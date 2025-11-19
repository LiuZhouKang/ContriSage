set +e
umask 022

TOTAL_CONTAINERS=${1:-40}         # 总容器数
ANOMALY_RATIO=${2:-0.2}           # 异常比例
DURATION=${3:-600}                # 运行时长（秒）
CLEANUP=${4:-true}                # 结束是否清理
# 可选：设为 true 时尝试包含 DB（需资源较多，且会设置必要环境变量以避免退出）
INCLUDE_DB=${5:-false}

if ! command -v docker >/dev/null 2>&1; then
  echo "错误: 未检测到 docker，请先安装并启动 docker 服务。"
  exit 1
fi

if (( $(echo "$ANOMALY_RATIO > 1 || $ANOMALY_RATIO < 0" | bc -l) )); then
  echo "错误: 异常比例必须在 0~1 之间"
  exit 1
fi

NUM_ANOMALY=$(echo "$TOTAL_CONTAINERS * $ANOMALY_RATIO" | bc | awk '{print int($1+0.5)}')
NUM_NORMAL=$((TOTAL_CONTAINERS - NUM_ANOMALY))
TS=$(date +%Y%m%d_%H%M%S)

mkdir -p injection_logs
LOG_FILE="injection_logs/container_injector_${TS}.log"
touch "$LOG_FILE"

log() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') - $*" | tee -a "$LOG_FILE"
}

# 镜像列表（仅基础服务，稳定不易退出）
IMAGES_BASIC=(
  "nginx:latest"
  "redis:latest"
  "httpd:latest"
  "python:3.11"
  "node:18"
)

# DB 镜像（默认关闭，开启时会注入必要环境变量以保证存活）
IMAGES_DB=(
  "mysql:8.0"
  "postgres:16"
  "mongo:6"
)

choose_image() {
  if [ "$INCLUDE_DB" = "true" ]; then
    printf "%s\n" "${IMAGES_BASIC[@]}" "${IMAGES_DB[@]}" | shuf -n 1
  else
    printf "%s\n" "${IMAGES_BASIC[@]}" | shuf -n 1
  fi
}

# 对不同镜像，尽量使用默认入口；仅在需要时提供命令
# 返回两值：RUN_MODE 和 CMD
# RUN_MODE: default 或 with_cmd
get_normal_cmd() {
  local image="$1"
  case "$image" in
    python:*)
      echo "with_cmd" "python -m http.server 8000"
      ;;
    node:*)
      echo "with_cmd" "node -e 'setInterval(() => console.log(\"Container running\"), 5000)'"
      ;;
    # nginx/redis/httpd/mongo/mysql/postgres 都使用默认入口，避免退出
    *)
      echo "default" ""
      ;;
  esac
}

# DB 环境变量，避免因缺失密码等直接退出
get_db_envs() {
  local image="$1"
  case "$image" in
    mysql:*)
      echo "-e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=test"
      ;;
    postgres:*)
      echo "-e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=test"
      ;;
    mongo:*)
      # mongo 默认即可启动
      echo ""
      ;;
    *)
      echo ""
      ;;
  esac
}

pre_pull_images() {
  local images=("${IMAGES_BASIC[@]}")
  if [ "$INCLUDE_DB" = "true" ]; then
    images+=("${IMAGES_DB[@]}")
  fi
  log "预拉取镜像以减少运行时等待..."
  for img in "${images[@]}"; do
    docker pull -q "$img" >/dev/null 2>&1 || true
  done
}

container_status() {
  docker inspect -f '{{.State.Status}}' "$1" 2>/dev/null
}

# 运行容器（normal/anomaly）
run_container() {
  local ctype="$1"    # normal/anomaly
  local name="$2"
  local image="$3"

  # 默认不覆盖入口；仅在 python/node 使用 with_cmd
  local mode cmd
  read -r mode cmd < <(get_normal_cmd "$image")

  local db_envs=""
  if [ "$INCLUDE_DB" = "true" ]; then
    db_envs="$(get_db_envs "$image")"
  fi

  # 异常容器用 root，确保后续 apt/注入权限足够
  local user_arg=""
  if [ "$ctype" = "anomaly" ]; then
    user_arg="--user root"
  fi

  if [ "$mode" = "default" ]; then
    docker run -d --name "$name" --label type="$ctype" $user_arg $db_envs "$image" >/dev/null 2>&1
  else
    docker run -d --name "$name" --label type="$ctype" $user_arg $db_envs "$image" sh -c "$cmd" >/dev/null 2>&1
  fi
}

# 将注入脚本写入容器并后台运行
start_injection() {
  local cname="$1"
  docker exec "$cname" sh -c 'cat > /tmp/inject.sh << "EOF"
#!/bin/sh
set +e

log() { echo "[INJECT] $(date "+%F %T") - $*"; }

# 轻量依赖检查
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# 尝试安装工具（在 Debian/Ubuntu 基础镜像上可用）
ensure_tool() {
  tool="$1"
  if has_cmd "$tool"; then return 0; fi
  if has_cmd apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$tool" >/dev/null 2>&1 || true
    has_cmd "$tool"
  else
    return 1
  fi
}

# 端口探测（尽量不用 bash /dev/tcp），优先 nc，其次 curl，最后超时 connect
scan_ports() {
  target="$1"
  # 优先 nc
  if ensure_tool netcat || ensure_tool nc; then
    ncbin="$(command -v nc || command -v netcat)"
    for p in $(seq 1 1024); do
      $ncbin -z -w 1 "$target" "$p" 2>/dev/null && echo "open:$p" || true
    done
    return
  fi
  # 其次 curl
  if ensure_tool curl; then
    for p in $(seq 1 1024); do
      curl --max-time 1 "http://$target:$p" >/dev/null 2>&1 && echo "open:$p" || true
    done
    return
  fi
  # 最后原生超时连接（大多数镜像有 timeout）
  if ensure_tool timeout && ensure_tool bash; then
    for p in $(seq 1 1024); do
      timeout 1 bash -lc "echo >/dev/tcp/$target/$p" 2>/dev/null && echo "open:$p" || true
    done
  fi
}

ANOMALY_TYPE=$(shuf -e crypto_miner port_scanner data_exfil process_injector file_anomaly network_flood -n 1 2>/dev/null || echo crypto_miner)
log "开始注入: $ANOMALY_TYPE"

case "$ANOMALY_TYPE" in
  crypto_miner)
    # CPU 密集
    while :; do
      dd if=/dev/zero bs=1M count=16 2>/dev/null | sha256sum >/dev/null 2>&1
    done &
    ;;

  port_scanner)
    # 使用容器默认路由网关作为目标
    GW="$(ip route | awk "/default/ {print \$3}" 2>/dev/null)"
    [ -z "$GW" ] && GW="127.0.0.1"
    while :; do
      scan_ports "$GW"
      sleep 15
    done &
    ;;

  data_exfil)
    mkdir -p /data/secrets
    i=1
    while [ $i -le 20 ]; do
      head -c 512K /dev/urandom > "/data/secrets/secret_$i.bin" 2>/dev/null || true
      i=$((i+1))
    done
    while :; do
      find /data/secrets -type f -name "secret_*.bin" -print 2>/dev/null | while read -r f; do
        echo "exfil:$f" >/dev/null
      done
      sleep 20
    done &
    ;;

  process_injector)
    # 反复产生短生命周期子进程
    while :; do
      (sleep 5) >/dev/null 2>&1 &
      (sleep 7) >/dev/null 2>&1 &
      (sleep 9) >/dev/null 2>&1 &
      sleep 5
    done &
    ;;

  file_anomaly)
    mkdir -p /tmp/malicious
    while :; do
      dd if=/dev/urandom of=/tmp/malicious/file_$(date +%s).bin bs=256K count=4 >/dev/null 2>&1 || true
      chmod 600 /etc/hosts 2>/dev/null || true
      sleep 5
    done &
    ;;

  network_flood)
    # 优先 hping3，不行则使用 ping/curl 回退
    if ensure_tool hping3; then
      TARGET="8.8.8.8"
      while :; do
        timeout 15 hping3 --flood -S -p 80 "$TARGET" >/dev/null 2>&1 || true
        sleep 10
      done &
    elif ensure_tool ping; then
      TARGET="1.1.1.1"
      while :; do
        ping -f -c 100 "$TARGET" >/dev/null 2>&1 || true
        sleep 10
      done &
    else
      # 最后回退：对常用端口快速连接
      while :; do
        for p in 80 443 53; do
          timeout 1 sh -c "exec 3<>/dev/tcp/8.8.8.8/$p" 2>/dev/null || true
        done
        sleep 5
      done &
    fi
    ;;
esac

log "注入启动完成"
EOF
chmod +x /tmp/inject.sh
nohup sh /tmp/inject.sh >/tmp/inject.log 2>&1 &
' >/dev/null 2>&1
}

deploy_containers() {
  log "预拉取镜像..."
  pre_pull_images

  log "部署正常容器: $NUM_NORMAL 个"
  for i in $(seq 1 "$NUM_NORMAL"); do
    img="$(choose_image)"
    name="normal-${i}-${TS}"
    log "部署正常容器 [$i/$NUM_NORMAL]: $name ($img)"
    run_container "normal" "$name" "$img"
  done

  log "部署异常容器: $NUM_ANOMALY 个"
  for i in $(seq 1 "$NUM_ANOMALY"); do
    img="$(choose_image)"
    name="anomaly-${i}-${TS}"
    log "部署异常容器 [$i/$NUM_ANOMALY]: $name ($img)"
    run_container "anomaly" "$name" "$img"
    # 等待容器就绪后注入
    sleep 2
    start_injection "$name"
  done

  log "等待容器启动..."
  sleep 8

  log "容器状态检查:"
  docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Image}}" | tee -a "$LOG_FILE"
}

monitor_containers() {
  local start=$(date +%s)
  local elapsed=0
  log "开始监控容器 ($DURATION 秒)..."
  while [ "$elapsed" -lt "$DURATION" ]; do
    for cname in $(docker ps -a --filter "label=type=normal" --format "{{.Names}}"); do
      st=$(container_status "$cname")
      if [ "$st" != "running" ] && [ "$st" != "restarting" ]; then
        log "警告: 正常容器 $cname 状态: $st，尝试重启一次"
        docker restart "$cname" >/dev/null 2>&1 || true
      fi
    done
    sleep 5
    elapsed=$(( $(date +%s) - start ))
  done
  log "监控完成"
}

cleanup_containers() {
  log "清理容器..."
  for t in normal anomaly; do
    for cname in $(docker ps -a --filter "label=type=$t" --format "{{.Names}}"); do
      docker rm -f "$cname" >/dev/null 2>&1 || true
    done
  done
  log "容器清理完成"
}

generate_report() {
  local report="injection_logs/report_${TS}.json"
  docker ps -a --format '{{json .}}' | jq -s '.' > "$report" 2>/dev/null || true
  log "报告已生成: $report"
}

main() {
  echo "============================================="
  echo "容器异常注入脚本"
  echo "总容器数: $TOTAL_CONTAINERS"
  echo "正常容器: $NUM_NORMAL"
  echo "异常容器: $NUM_ANOMALY"
  echo "持续时间: $DURATION 秒"
  echo "包含数据库: $INCLUDE_DB"
  echo "清理容器: $CLEANUP"
  echo "日志: $LOG_FILE"
  echo "============================================="

  log "脚本启动"
  deploy_containers
  monitor_containers
  generate_report
  if [ "$CLEANUP" = "true" ]; then
    cleanup_containers
  else
    log "已保留容器，normal/anomaly 可继续采集"
  fi
  log "脚本完成"
}

main