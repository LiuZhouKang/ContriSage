import argparse
import sys
import subprocess
from pathlib import Path
import logging
import numpy as np

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

from monitor import ContainerMonitor
from visualizer import VisualizationGenerator
from data_processor import DataProcessor
from anomaly_detector import AnomalyDetector, AnomalyAnalyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def check_dependencies():
    """检查依赖包是否安装"""
    required_packages = [
        'pandas', 'numpy', 'matplotlib', 
        'seaborn', 'joblib'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"缺少以下依赖包: {', '.join(missing_packages)}")
        print("请运行以下命令安装依赖:")
        print(f"pip install {' '.join(missing_packages)}")
        return False
    
    return True

def install_dependencies():
    """安装依赖包"""
    requirements_file = current_dir / "requirements.txt"
    if requirements_file.exists():
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(requirements_file)])
            print("依赖包安装完成")
            return True
        except subprocess.CalledProcessError as e:
            print(f"依赖包安装失败: {e}")
            return False
    else:
        print("找不到 requirements.txt 文件")
        return False

def run_web_dashboard():
    """启动Web仪表板"""
    try:
        # 检查dash是否可用
        import dash
        import dash_bootstrap_components
        
        # 启动dashboard
        from dashboard import app
        print("启动Web仪表板...")
        print("访问地址: http://localhost:8050")
        app.run(debug=False, host='0.0.0.0', port=8050)
        
    except ImportError:
        print("Web仪表板需要安装以下包:")
        print("pip install dash dash-bootstrap-components plotly")
        print("或者运行: python main.py --install-deps")
        return False
    except Exception as e:
        logger.error(f"Web仪表板启动失败: {e}")
        return False

def run_cli_monitor():
    """运行命令行监测器"""
    monitor = ContainerMonitor()
    
    if not monitor.initialize():
        print("系统初始化失败")
        return False
        
    print("\n启动命令行监测器...")
    
    try:
        monitor.start_monitoring(interval_seconds=30)
    except KeyboardInterrupt:
        print("\n监测已停止")
    except Exception as e:
        print(f"监测失败: {e}")
        return False
        
    return True

def generate_report():
    """生成可视化报告"""
    try:
        print("开始生成可视化报告...")
        
        # 加载数据
        processor = DataProcessor()
        processor.load_latest_data()
        features = processor.extract_features()
        
        if features.empty:
            print("没有可用数据")
            return False
        
        print(f"加载数据: {len(features)} 个容器")
        
        # 训练模型并预测
        detector = AnomalyDetector()
        detector.train(features)
        predictions = detector.predict(features)
        
        print(f"模型预测完成: 发现 {predictions['combined_anomaly'].sum()} 个异常容器")
        
        # 分析异常
        analyzer = AnomalyAnalyzer()
        analysis_results = []
        
        for i, (_, container) in enumerate(features.iterrows()):
            pred_slice = {k: v[i:i+1] if isinstance(v, np.ndarray) else v 
                         for k, v in predictions.items()}
            analysis = analyzer.analyze_anomaly(container, pred_slice)
            analysis_results.append(analysis)
        
        print("异常分析完成")
        
        # 生成可视化
        visualizer = VisualizationGenerator()
        visualizations = visualizer.generate_all_visualizations(
            features, predictions, analysis_results)
        
        # 生成仪表板
        dashboard_path = visualizer.generate_summary_dashboard(visualizations)
        
        print(f"可视化报告生成完成!")
        print(f"生成了 {len(visualizations)} 个图表")
        print(f"仪表板路径: {dashboard_path}")
        print(f"图片保存在: {visualizer.output_dir}")
        
        return True
        
    except Exception as e:
        print(f"报告生成失败: {e}")
        return False

def run_single_detection():
    """运行单次检测"""
    try:
        print("开始单次异常检测...")
        
        monitor = ContainerMonitor()
        
        if not monitor.initialize():
            print("系统初始化失败")
            return False
            
        results = monitor.run_detection()
        
        if "error" in results:
            print(f"检测失败: {results['error']}")
            return False
        
        # 显示结果
        print(f"\n检测结果:")
        print(f"总容器数: {results['total_containers']}")
        print(f"异常容器数: {results['anomaly_count']}")
        print(f"异常率: {results['anomaly_rate']:.2%}")
        
        # 显示严重程度分布
        severity_dist = results['summary']['severity_distribution']
        print(f"\n异常严重程度分布:")
        for severity, count in severity_dist.items():
            if count > 0:
                print(f"  {severity.title()}: {count} 个")
        
        # 显示异常容器
        if results['anomaly_count'] > 0:
            print(f"\n异常容器详情:")
            for container in results['containers']:
                if container['is_anomaly']:
                    print(f"  - {container['container_name']}")
                    print(f"    严重程度: {container['severity']}")
                    print(f"    置信度: {container['confidence']:.3f}")
                    print(f"    异常原因: {len(container.get('anomaly_reasons', []))} 个")
        else:
            print("\n所有容器运行正常!")
        
        return True
        
    except Exception as e:
        print(f"检测失败: {e}")
        return False

def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="AI容器异常监测系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:
  python main.py --web                 # 启动Web仪表板
  python main.py --cli                 # 启动命令行监测
  python main.py --detect              # 运行单次检测
  python main.py --report              # 生成可视化报告
  python main.py --install-deps        # 安装依赖包
        """
    )
    
    parser.add_argument('--web', action='store_true', help='启动Web仪表板')
    parser.add_argument('--cli', action='store_true', help='启动命令行监测')
    parser.add_argument('--detect', action='store_true', help='运行单次检测')
    parser.add_argument('--report', action='store_true', help='生成可视化报告')
    parser.add_argument('--install-deps', action='store_true', help='安装依赖包')
    parser.add_argument('--check-deps', action='store_true', help='检查依赖包')
    
    args = parser.parse_args()
    
    print("="*60)
    print("AI容器异常监测系统")
    print("Container Anomaly Detection System")
    print("="*60)
    
    # 处理参数
    if args.install_deps:
        install_dependencies()
        return
    
    if args.check_deps:
        if check_dependencies():
            print("所有依赖包已安装")
        return
    
    # 检查基本依赖
    if not check_dependencies():
        print("\n请先安装依赖包:")
        print("python main.py --install-deps")
        return
    
    if args.web:
        run_web_dashboard()
    elif args.cli:
        run_cli_monitor()
    elif args.detect:
        run_single_detection()
    elif args.report:
        generate_report()
    else:
        # 写一个死循环实现终端交互式菜单
        while True:
            print("\n" + "="*40)
            print("请选择操作:")
            print("1. 启动Web仪表板")
            print("2. 启动命令行监测")
            print("3. 运行单次检测")
            print("4. 生成可视化报告")
            print("5. 检查依赖包")
            print("6. 安装依赖包")
            print("7. 退出")
            print("="*40)
            
            try:
                choice = input("请输入选择 (1-7): ").strip()
                
                if choice == "1":
                    run_web_dashboard()
                elif choice == "2":
                    run_cli_monitor()
                elif choice == "3":
                    run_single_detection()
                elif choice == "4":
                    generate_report()
                elif choice == "5":
                    if check_dependencies():
                        print("所有依赖包已安装")
                    else:
                        print("缺少必要的依赖包")
                elif choice == "6":
                    install_dependencies()
                elif choice == "7":
                    print("感谢使用，再见！")
                    break
                else:
                    print("无效选择，请输入 1-7")
                    
            except KeyboardInterrupt:
                print("\n\n程序已退出")
                break
            except Exception as e:
                print(f"操作失败: {e}")

if __name__ == "__main__":
    main()
