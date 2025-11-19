# 容器异常注入器（container_injector）

面向容器安全与行为分析的可控异常流量生成工具集，用于端到端验证“采集 → 特征 → AI 检测 → 告警”闭环，并为模型训练与回归提供带标签数据。本目录提供三种注入器：

- Python 高级注入器：`container_anomaly_injector.py`（场景化、可生成报告与标签、可并发调度）
- Shell 批量注入器：`container_injector.sh`（快速批量拉起 normal/anomaly 容器并注入行为，易于脚本化）
- Python 简易注入器：`injector.py`（按比例随机注入，适合快速产生日志/数据）

---

## 目录结构

```
container_injector/
├── container_anomaly_injector.py   # 高级注入器（多场景、调度、报告）
├── container_injector.sh           # 批量注入脚本（Bash）
├── injector.py                     # 简易注入器（Python）
├── injection_config.ini            # 注入配置样例（权重、资源、日志路径等）
├── container_injector.log          # 运行日志（injector.py 默认）
└── injection_logs/                 # 注入运行产出目录（日志/报告/历史）
    ├── injection_history.json
    ├── anomaly_injection.log
    ├── injection_report_*.json     # 高级注入器生成的报告
    └── container_injector_*.log    # Shell 注入器运行日志
```

---

## 支持的异常类型

高级/简易注入器覆盖多类常见攻击与异常模式（不同脚本的实现细节略有差别）：

- CPU_INTENSIVE / CRYPTO_MINING：CPU 密集、伪挖矿
- MEMORY_LEAK：内存泄漏/占用异常
- NETWORK_SCANNING / PORT_SCANNER：端口/主机扫描
- PRIVILEGE_ESCALATION：权限提升尝试、敏感文件访问
- FILE_SYSTEM_ABUSE / FILE_ANOMALY：异常文件读写/权限修改
- DNS_TUNNELING：DNS 隧道特征流量
- DDOS_ATTACK / NETWORK_FLOOD：网络洪泛/拒绝服务
- DATA_EXFILTRATION / DATA_EXFIL：数据外泄行为
- PROCESS_INJECTION：进程注入/频繁子进程
- SUSPICIOUS_NETWORK：可疑外联模式
- RESOURCE_EXHAUSTION：资源耗尽（进程/文件/存储）

所有注入均带时间维度、可控强度/频率，并尽量提供“轻量级依赖 + 回退路径”，以提高在不同基础镜像上的成功率。

---

## 先决条件

- Linux 主机，已安装 Docker 并处于运行状态
- 当前用户具备运行 Docker 权限（加入 docker 组或使用 sudo）
- 网络访问：部分注入使用 `host` 网络模式或访问外部地址（例如 DNS、公共 IP），请确认安全边界
- 可选工具：`jq`（Shell 脚本生成报告时使用），`bc`、`shuf`

---

## 快速开始

### A. 高级注入器（container_anomaly_injector.py）

特性：
- 创建一组“正常容器”（Nginx/Redis/HTTP 等）作为背景流量
- 定时随机注入多种异常，自动记录注入历史（带时间戳/类型/严重度）
- 结束时生成结构化注入报告（`injection_logs/injection_report_*.json`）
- 支持清理策略与交互式确认

运行示例：

```bash
# 在本目录下运行
python3 container_anomaly_injector.py --normal-containers 8 --duration 30

# 仅清理容器
python3 container_anomaly_injector.py --cleanup-only

# 不创建正常容器，仅注入异常
python3 container_anomaly_injector.py --no-normal --duration 10
```

主要参数：
- `--normal-containers <int>`：正常容器数量（默认 8）
- `--duration <minutes>`：注入持续时间（默认 30 分钟）
- `--cleanup-only`：仅执行清理，不做注入
- `--no-normal`：不创建正常容器，仅进行异常注入

运行产出：
- `injection_logs/injection_history.json`：注入事件流水
- `injection_logs/anomaly_injection.log`：运行日志
- `injection_logs/injection_report_*.json`：聚合统计报告（类型计数、严重度分布、时间线）

实现要点：
- 使用 Docker SDK（`docker` Python 包）拉起容器与注入命令
- 部分场景设置 `mem_limit`、`cpu_count` 等资源限制，防止对宿主机造成过大影响
- 网络扫描使用 Alpine + nmap（容器内安装），为保证可观测性部分场景使用 `--network host`

安全边界：
- 某些行为可能触发入侵检测/防火墙规则；请在隔离环境执行
- 使用 `--network host` 的场景具备更高权限和风险，谨慎开启

---

### B. 批量注入脚本（container_injector.sh）

特性：
- 一次性批量部署 normal/anomaly 容器，按镜像稳定性优先（nginx/redis/httpd/python/node 等）
- 对异常容器注入后台脚本（`docker exec` 写入 `/tmp/inject.sh` 并运行），带依赖探测与多级回退
- 支持（可选）包含数据库镜像，并自动注入最小化环境变量确保能持续运行
- 全流程日志与简单报告产出

用法：

```bash
# 参数: TOTAL ANOMALY_RATIO DURATION CLEANUP INCLUDE_DB
# TOTAL: 总容器数，ANOMALY_RATIO: 异常比例(0~1)，DURATION: 运行秒数
# CLEANUP: true/false 结束是否清理，INCLUDE_DB: true/false 是否包含 DB 镜像

# 例1：40 个容器，20% 异常，运行 600 秒，结束清理，不包含 DB
./container_injector.sh 40 0.2 600 true false

# 例2：80 个容器，15% 异常，运行 900 秒，保留容器，包含 DB
./container_injector.sh 80 0.15 900 false true
```

脚本行为：
- 预拉取镜像，减少运行时等待
- 正常容器默认使用镜像自带入口；Python/Node 镜像提供轻量命令以保持常驻
- 异常容器以 root 运行，确保后续 `apt-get`/工具注入权限足够
- 注入器优先使用现有工具（nc/curl/hping3），若无则尝试 `apt-get` 安装；仍不可用时采用内置“原生命令”回退

产出：
- 日志：`injection_logs/container_injector_<timestamp>.log`
- 报告：`injection_logs/report_<timestamp>.json`（基于 `docker ps -a` 的快照，需要宿主机安装 `jq`）

依赖：宿主机建议安装 `jq`、`bc`、`shuf`。脚本会尽量在容器内部安装所需工具；对非 Debian/Ubuntu 基础镜像将采用回退路径。

---

### C. 简易注入器（injector.py）

特性：
- 按比例部署正常/异常容器，随机选择异常类型
- 监控容器运行状态，周期性注入额外异常（工具安装与命令通过 `docker exec` 触发）
- 结束后可选择清理

运行示例：

```bash
python3 injector.py --total 50 --anomaly-ratio 0.15 --duration 600

# 运行结束后保留容器
python3 injector.py --total 30 --anomaly-ratio 0.3 --duration 300 --no-cleanup
```

主要参数：
- `--total <int>`：总容器数（默认 50）
- `--anomaly-ratio <float>`：异常容器比例（默认 0.15）
- `--duration <seconds>`：监控/运行时长（默认 600 秒）
- `--no-cleanup`：结束后不清理容器

产出：
- 运行日志：`container_injector.log`

---

## 注入实现与回退机制（关键逻辑）

为兼容多种基础镜像（alpine、debian/ubuntu、language runtimes），脚本在注入时采取“优先依赖 → 安装 → 回退”的策略：

- 端口扫描：优先 `nc`/`netcat`，其次 `curl`，最后 `bash /dev/tcp` + `timeout` 回退
- 网络洪泛：优先 `hping3`，回退 `ping -f`，再回退为快速 TCP 连接尝试
- 文件/进程异常：尽量使用 POSIX 基础命令（dd、chmod、sleep）以提升成功率
- 工具安装：若容器具备 `apt-get`，会尝试静默安装所需工具（不可用则跳过）

---

## 日志与报告

- 高级注入器（Python）：
  - `injection_logs/anomaly_injection.log`：运行日志（stdout 同步输出）
  - `injection_logs/injection_history.json`：每次注入的结构化记录
  - `injection_logs/injection_report_*.json`：汇总报告（异常类型计数、严重度分布、时间线）

- 批量注入器（Shell）：
  - `injection_logs/container_injector_*.log`：全流程运行日志
  - `injection_logs/report_*.json`：容器状态快照（需宿主机 `jq`）

- 简易注入器（Python）：
  - `container_injector.log`：运行日志

---

## 配置文件说明（injection_config.ini）

此文件提供一份注入配置样例，包含：
- 基础设置：正常容器数、注入时长、注入间隔范围
- 各异常类型的权重与严重度分布建议
- 容器资源限制（默认/高资源场景）
- 日志与报告路径

注意：当前 `container_anomaly_injector.py` 与 `injector.py` 未直接解析该 INI 文件（参数通过命令行传入/代码内置）。如需启用统一配置，可在后续版本中将该 INI 接入解析（如 `configparser`），并覆盖默认参数。

---

## 与 AI 检测系统的对齐

- 标签字段：高级注入器会为每次注入记录 `{timestamp, container_name, anomaly_type, severity, description}`，便于与采集数据按容器名/时间段对齐
- 建议对齐策略：
  - 以注入 `timestamp` 为中心窗口（±Δt），在 AI 检测输出中查询对应容器的异常事件
  - 计算 P/R/F1，并统计延迟（注入→检出）
  - 基于 `injection_report_*.json` 的类型/严重度分布进行分层评估

---

## 常见问题（FAQ）

1) 运行提示无 Docker 权限/找不到命令
- 将当前用户加入 docker 组，或以 `sudo` 运行
- 确认 Docker 服务已启动：`systemctl status docker`

2) 容器镜像拉取慢/失败
- 先手动 `docker pull` 关键镜像（如 `nginx`, `redis`, `python:3.11` 等）
- 脚本内置预拉取逻辑，但受网络影响较大

3) 网络相关异常（nmap/hping3 不存在）
- Shell 注入脚本会尝试在容器内安装工具；若基础镜像非 Debian/Ubuntu，将回退为 `ping/curl/bash` 等原生命令
- 某些镜像受权限/能力限制，可能无法产生完全理想的网络特征，属预期

4) 扫描/洪泛与安全边界
- 可能触发 IDS/IPS 或防火墙策略，请在隔离测试环境执行
- `--network host` 场景风险更高，务必谨慎

5) 运行结束是否自动清理？
- 高级注入器：运行结束会询问是否清理；也可用 `--cleanup-only` 主动清理
- Shell 注入器：通过第 4 个参数控制（`true/false`）
- 简易注入器：默认清理，传 `--no-cleanup` 可保留

---

## 开发与扩展

- 将 `injection_config.ini` 对接到 Python 注入器（`configparser`）以实现统一配置中心
- 补充更多异常场景（如容器逃逸尝试、内核接口滥用、可疑 seccomp/bpf/ptrace 操作）
- 为注入事件附加容器/镜像元数据（ID、镜像、标签、网络/资源限制），提升评估可解释性
- 输出与 AI 检测系统的对接插件（将注入标签直接写入监测目录，或通过 HTTP/消息队列推送）

---
