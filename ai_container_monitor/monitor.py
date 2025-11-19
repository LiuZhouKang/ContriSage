import os
import sys
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List
import pandas as pd
import numpy as np
from pathlib import Path

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

from data_processor import DataProcessor
from anomaly_detector import AnomalyDetector, AnomalyAnalyzer
from time_series_optimizer import TimeSeriesOptimizer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ContainerMonitor:
    """容器异常监测主服务"""
    
    def __init__(self, data_path: str = "/home/lzk/agent3/build/bin/Debug/agent_data"):
        self.data_path = data_path
        self.processor = DataProcessor(data_path)
        self.detector = AnomalyDetector(contamination=0.1, use_corrected=True, anomaly_threshold=0.58)
        self.analyzer = AnomalyAnalyzer()

        self.model_path = current_dir / "anomaly_model.pkl"
        self.results_path = current_dir / "monitoring_results"
        self.results_path.mkdir(exist_ok=True)
        self.history_path = current_dir / "monitoring_results" / "feature_history.csv"
        self.ts_optimizer = TimeSeriesOptimizer(self.history_path, degree=6, min_points=24)

        self.monitoring_history = []
        
    def initialize(self):
        """初始化监测系统"""
        try:
            logger.info("初始化容器异常监测系统...")
            
            # 加载数据
            process_data, syscall_data = self.processor.load_latest_data()
            logger.info(f"加载数据 - 进程: {len(process_data)} 行, 系统调用: {len(syscall_data)} 行")
            
            # 提取特征
            features = self.processor.extract_features()
            if features.empty:
                raise ValueError("无法提取特征数据")
                
            # 更新历史并生成校正特征
            self.ts_optimizer.update_history(features)
            features_corr = self.ts_optimizer.correct_features(features)

            logger.info(f"提取特征: {len(features)} 个容器")
            
            # 训练或加载模型
            if self.model_path.exists():
                try:
                    self.detector.load_model(str(self.model_path))
                    logger.info("加载现有模型")
                except Exception as e:
                    logger.warning(f"加载模型失败: {e}，重新训练...")
                    self._train_model(features_corr)
            else:
                self._train_model(features_corr)
                
            logger.info("系统初始化完成")
            return True
            
        except Exception as e:
            logger.error(f"系统初始化失败: {e}")
            return False
            
    def _train_model(self, features: pd.DataFrame):
        """训练模型"""
        training_results = self.detector.train(features)
        self.detector.save_model(str(self.model_path))
        logger.info(f"模型训练完成: {training_results}")
        
    def run_detection(self) -> Dict:
        """运行异常检测"""
        try:
            # 加载最新数据
            self.processor.load_latest_data()
            features = self.processor.extract_features()
            # 更新历史并应用校正
            self.ts_optimizer.update_history(features)
            features = self.ts_optimizer.correct_features(features)
            
            if features.empty:
                logger.warning("没有可用的特征数据")
                return {"error": "没有可用数据"}
                
            # 预测异常
            predictions = self.detector.predict(features)
            
            # 分析每个异常容器
            results = {
                "timestamp": datetime.now().isoformat(),
                "total_containers": len(features),
                "anomaly_count": int(predictions['combined_anomaly'].sum()),
                "anomaly_rate": float(predictions['combined_anomaly'].mean()),
                "containers": [],
                "summary": {}
            }
            
            # 严重程度统计
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            
            for i, (_, container) in enumerate(features.iterrows()):
                container_result = {
                    "container_id": container['container_id'],
                    "container_name": container['container_name'],
                    "is_anomaly": bool(predictions['combined_anomaly'][i]),
                    "confidence": float(predictions['anomaly_confidence'][i])
                }
                
                if container_result['is_anomaly']:
                    # 详细分析异常
                    pred_slice = {k: v[i:i+1] if isinstance(v, np.ndarray) else v 
                                 for k, v in predictions.items()}
                    analysis = self.analyzer.analyze_anomaly(container, pred_slice)
                    
                    container_result.update({
                        "severity": analysis['severity'],
                        "anomaly_reasons": analysis['anomaly_reasons'],
                        "recommendations": analysis['recommendations']
                    })
                    
                    severity_counts[analysis['severity']] += 1
                    
                results["containers"].append(container_result)
            
            # 添加汇总信息
            results["summary"] = {
                "severity_distribution": severity_counts,
                "top_anomaly_reasons": self._get_top_anomaly_reasons(results["containers"]),
                "feature_importance": self.detector.get_feature_importance()
            }
            
            # 保存结果
            self._save_results(results)
            
            # 添加到历史记录
            self.monitoring_history.append(results)
            if len(self.monitoring_history) > 100:  # 保留最近100次结果
                self.monitoring_history.pop(0)
                
            logger.info(f"检测完成 - 发现 {results['anomaly_count']} 个异常容器")
            return results
            
        except Exception as e:
            logger.error(f"异常检测失败: {e}")
            return {"error": str(e)}
            
    def _get_top_anomaly_reasons(self, containers: List[Dict]) -> List[Dict]:
        """获取最常见的异常原因"""
        reason_counts = {}
        
        for container in containers:
            if container.get('is_anomaly') and container.get('anomaly_reasons'):
                for reason in container['anomaly_reasons']:
                    desc = reason['description']
                    if desc not in reason_counts:
                        reason_counts[desc] = 0
                    reason_counts[desc] += 1
                    
        # 排序并返回前5个
        top_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        return [{"reason": reason, "count": count} for reason, count in top_reasons]
        
    def _save_results(self, results: Dict):
        """保存检测结果"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            result_file = self.results_path / f"detection_results_{timestamp}.json"
            
            import json
            with open(result_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
                
            logger.info(f"结果已保存到: {result_file}")
            
        except Exception as e:
            logger.error(f"保存结果失败: {e}")
            
    def generate_report(self) -> str:
        """生成检测报告"""
        try:
            if not self.monitoring_history:
                return "暂无检测历史"
                
            latest_result = self.monitoring_history[-1]
            
            report = f"""
# 容器异常监测报告

## 检测时间
{latest_result['timestamp']}

## 总体概况
- 总容器数: {latest_result['total_containers']}
- 异常容器数: {latest_result['anomaly_count']}
- 异常率: {latest_result['anomaly_rate']:.2%}

## 严重程度分布
"""
            
            for severity, count in latest_result['summary']['severity_distribution'].items():
                if count > 0:
                    report += f"- {severity.title()}: {count} 个\n"
                    
            report += "\n## 主要异常原因\n"
            for reason in latest_result['summary']['top_anomaly_reasons']:
                report += f"- {reason['reason']}: {reason['count']} 次\n"
                
            report += "\n## 异常容器详情\n"
            anomaly_containers = [c for c in latest_result['containers'] if c['is_anomaly']]
            
            for container in anomaly_containers[:5]:  # 显示前5个
                report += f"""
### 容器: {container['container_name']}
- ID: {container['container_id'][:12]}...
- 严重程度: {container['severity']}
- 置信度: {container['confidence']:.3f}
- 异常原因数: {len(container.get('anomaly_reasons', []))}
"""
                
            if len(self.monitoring_history) > 1:
                report += self._generate_trend_analysis()
                
            return report
            
        except Exception as e:
            logger.error(f"报告生成失败: {e}")
            return f"报告生成失败: {str(e)}"
            
    def _generate_trend_analysis(self) -> str:
        """生成趋势分析"""
        try:
            # 分析最近的检测历史
            recent_results = self.monitoring_history[-10:]  # 最近10次
            
            anomaly_counts = [r['anomaly_count'] for r in recent_results]
            anomaly_rates = [r['anomaly_rate'] for r in recent_results]
            
            avg_anomaly_count = np.mean(anomaly_counts)
            avg_anomaly_rate = np.mean(anomaly_rates)
            
            trend = ""
            if len(anomaly_counts) >= 2:
                if anomaly_counts[-1] > anomaly_counts[-2]:
                    trend = "上升"
                elif anomaly_counts[-1] < anomaly_counts[-2]:
                    trend = "下降"
                else:
                    trend = "稳定"
                    
            report = f"""
## 趋势分析

### 最近趋势
- 异常数量趋势: {trend}
- 平均异常数量: {avg_anomaly_count:.1f}
- 平均异常率: {avg_anomaly_rate:.2%}

### 历史统计
- 最高异常数: {max(anomaly_counts)}
- 最低异常数: {min(anomaly_counts)}
- 标准差: {np.std(anomaly_counts):.1f}
"""
            return report
            
        except Exception as e:
            logger.error(f"趋势分析失败: {e}")
            return ""
            
    def start_monitoring(self, interval_seconds: int = 30):
        """启动持续监测"""
        logger.info(f"启动持续监测，间隔: {interval_seconds} 秒")
        
        try:
            while True:
                logger.info("=" * 50)
                logger.info("开始新一轮检测...")
                
                results = self.run_detection()
                
                if "error" not in results:
                    anomaly_count = results['anomaly_count']
                    total_count = results['total_containers']
                    
                    if anomaly_count > 0:
                        logger.warning(f"发现 {anomaly_count}/{total_count} 个异常容器!")
                        
                        # 输出异常容器信息
                        for container in results['containers']:
                            if container['is_anomaly']:
                                logger.warning(
                                    f"异常容器: {container['container_name']} "
                                    f"(严重程度: {container.get('severity', 'unknown')}, "
                                    f"置信度: {container['confidence']:.3f})"
                                )
                    else:
                        logger.info("所有容器运行正常")
                        
                else:
                    logger.error(f"检测失败: {results['error']}")
                    
                logger.info(f"下次检测将在 {interval_seconds} 秒后进行...")
                time.sleep(interval_seconds)
                
        except KeyboardInterrupt:
            logger.info("监测已停止")
        except Exception as e:
            logger.error(f"监测过程中发生错误: {e}")

def main():
    """主函数"""
    monitor = ContainerMonitor()
    
    # 初始化系统
    if not monitor.initialize():
        logger.error("系统初始化失败")
        return
        
    print("\n" + "="*60)
    print("AI容器异常监测系统")
    print("="*60)
    print("1. 运行单次检测")
    print("2. 启动持续监测")  
    print("3. 生成检测报告")
    print("4. 重新训练模型")
    print("5. 退出")
    print("="*60)
    
    while True:
        try:
            choice = input("\n请选择操作 (1-5): ").strip()
            
            if choice == "1":
                print("\n运行单次检测...")
                results = monitor.run_detection()
                
                if "error" not in results:
                    print(f"\n检测结果:")
                    print(f"总容器数: {results['total_containers']}")
                    print(f"异常容器数: {results['anomaly_count']}")
                    print(f"异常率: {results['anomaly_rate']:.2%}")
                    
                    if results['anomaly_count'] > 0:
                        print(f"\n异常容器列表:")
                        for container in results['containers']:
                            if container['is_anomaly']:
                                print(f"- {container['container_name']} "
                                      f"(严重程度: {container.get('severity', 'unknown')}, "
                                      f"置信度: {container['confidence']:.3f})")
                else:
                    print(f"检测失败: {results['error']}")
                    
            elif choice == "2":
                interval = input("请输入监测间隔（秒，默认30）: ").strip()
                interval = int(interval) if interval.isdigit() else 30
                print(f"\n启动持续监测（间隔 {interval} 秒）...")
                print("按 Ctrl+C 停止监测")
                monitor.start_monitoring(interval)
                
            elif choice == "3":
                print("\n生成检测报告...")
                report = monitor.generate_report()
                print(report)
                
                # 保存报告到文件
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_file = monitor.results_path / f"report_{timestamp}.md"
                with open(report_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                print(f"\n报告已保存到: {report_file}")
                
            elif choice == "4":
                print("\n重新训练模型...")
                monitor.processor.load_latest_data()
                features = monitor.processor.extract_features()
                monitor.ts_optimizer.update_history(features)
                features = monitor.ts_optimizer.correct_features(features)
                if not features.empty:
                    monitor._train_model(features)
                    print("模型训练完成")
                else:
                    print("没有可用数据进行训练")
                    
            elif choice == "5":
                print("\n感谢使用，再见！")
                break
                
            else:
                print("无效选择，请输入 1-5")
                
        except KeyboardInterrupt:
            print("\n\n程序已退出")
            break
        except Exception as e:
            print(f"操作失败: {e}")

if __name__ == "__main__":
    main()
