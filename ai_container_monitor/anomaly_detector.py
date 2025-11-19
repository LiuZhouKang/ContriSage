import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
import logging
from typing import Dict, List, Tuple, Optional, Any
import warnings
warnings.filterwarnings('ignore')

logger = logging.getLogger(__name__)

class AnomalyDetector:
    """
    容器异常检测器 - 集成多种优化技术
    - 集成多个 IsolationForest 模型
    - Holt-Winters 时序预处理
    """
    
    def __init__(self, 
                 contamination: float = 0.1,
                 contamination_levels: Optional[List[float]] = None,
                 n_estimators_list: Optional[List[int]] = None,
                 ensemble_weights: Optional[List[float]] = None,
                 hw_params: Optional[Dict[str, float]] = None,
                 anomaly_threshold: float = 0.7,
                 use_corrected: bool = True):
        """
        初始化异常检测器
        
        Args:
            contamination: 基础污染率（向后兼容参数）
            contamination_levels: 不同污染率设置
            n_estimators_list: 不同估计器数量
            ensemble_weights: 集成权重，如果为None则使用均等权重
            hw_params: Holt-Winters参数
            anomaly_threshold: 异常判定阈值
            use_corrected: 是否优先使用校正后特征
        """
        # 处理向后兼容：如果只提供了contamination，则自动生成集成参数
        if contamination_levels is None:
            self.contamination_levels = [contamination * 0.5, contamination, contamination * 1.5]
        else:
            self.contamination_levels = contamination_levels
            
        if n_estimators_list is None:
            self.n_estimators_list = [50, 100, 150]
        else:
            self.n_estimators_list = n_estimators_list
            
        if ensemble_weights is None:
            self.ensemble_weights = [0.1, 0.3, 0.6]
        else:
            self.ensemble_weights = ensemble_weights
            
        self.anomaly_threshold = anomaly_threshold
        self.use_corrected = use_corrected
        
        # Holt-Winters 参数
        self.hw_params = hw_params or {
            'alpha': 0.15,
            'beta': 0.005, 
            'gamma': 0.35,
            'factor': 0.15
        }
        
        # 模型组件
        self.scaler = RobustScaler()
        self.models = []
        self.pca = None
        self.feature_names = None
        self.is_trained = False
        
        # 性能指标
        self.training_metrics = {}
        
    def _apply_holt_winters_preprocessing(self, X: np.ndarray) -> np.ndarray:
        """
        应用 Holt-Winters 时序预处理
        对特征进行平滑处理，减少噪声影响
        """
        try:
            X_processed = X.copy()
            
            # 对每个特征独立应用平滑
            for i in range(X.shape[1]):
                feature_data = X[:, i]
                
                # 跳过常数特征
                if np.std(feature_data) < 1e-6:
                    continue
                
                # 如果数据点足够多，应用指数平滑
                if len(feature_data) >= 10:
                    try:
                        # 使用简单指数平滑
                        alpha = self.hw_params['alpha']
                        smoothed = np.zeros_like(feature_data)
                        smoothed[0] = feature_data[0]
                        
                        for j in range(1, len(feature_data)):
                            smoothed[j] = alpha * feature_data[j] + (1 - alpha) * smoothed[j-1]
                        
                        X_processed[:, i] = smoothed
                    except:
                        # 如果平滑失败，保持原数据
                        pass
            
            return X_processed
            
        except Exception as e:
            logger.warning(f"Holt-Winters预处理失败，使用原始数据: {e}")
            return X

    def prepare_features(self, features_df: pd.DataFrame) -> np.ndarray:
        """准备用于模型的特征数据"""
        try:
            # 选择数值特征，优先使用校正后的列 *_corr
            all_numeric = features_df.select_dtypes(include=[np.number]).columns.tolist()
            corr_cols = [c for c in all_numeric if c.endswith('_corr')]
            base_cols = [c for c in all_numeric if not c.endswith('_corr')]
            
            # 排除标识列
            exclude_cols = ['container_id', 'timestamp', 'minute_of_day']
            corr_cols = [col for col in corr_cols if all(x not in col for x in exclude_cols)]
            base_cols = [col for col in base_cols if col not in exclude_cols]

            numeric_cols = corr_cols if (self.use_corrected and len(corr_cols) > 0) else base_cols
            
            if not numeric_cols:
                raise ValueError("没有找到可用的数值特征")
                
            self.feature_names = numeric_cols
            features_array = features_df[numeric_cols].values
            
            # 处理无穷大和NaN值
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=1e6, neginf=-1e6)
            
            return features_array
            
        except Exception as e:
            logger.error(f"特征准备失败: {e}")
            raise

    def train(self, features_df: pd.DataFrame) -> Dict[str, Any]:
        """训练异常检测器"""
        try:
            print("开始训练异常检测器...")
            
            if len(features_df) < 2:
                raise ValueError("训练数据太少，至少需要2个样本")
                
            # 准备特征
            X = self.prepare_features(features_df)
            print(f"训练数据: {X.shape[0]} 样本, {X.shape[1]} 维特征")
            
            # 应用Holt-Winters时序预处理
            print("应用Holt-Winters时序预处理...")
            X_processed = self._apply_holt_winters_preprocessing(X)
            
            # 特征标准化
            X_scaled = self.scaler.fit_transform(X_processed)
            
            # 训练集成IForest模型
            print("训练IForest集成模型...")
            self.models = []
            
            for i, (contamination, n_estimators) in enumerate(zip(self.contamination_levels, self.n_estimators_list)):
                print(f"   训练模型 {i+1}/{len(self.contamination_levels)}: contamination={contamination}, n_estimators={n_estimators}")
                
                model = IsolationForest(
                    contamination=contamination,
                    n_estimators=n_estimators,
                    random_state=42 + i,
                    n_jobs=-1
                )
                model.fit(X_scaled)
                self.models.append(model)
            
            # PCA降维（用于可视化和特征重要性）
            n_components = min(2, X_scaled.shape[1])
            self.pca = PCA(n_components=n_components)
            X_pca = self.pca.fit_transform(X_scaled)
            
            self.is_trained = True
            
            # 模型评估
            predictions = self.predict(features_df)
            
            training_results = {
                'n_samples': len(X_scaled),
                'n_features': len(self.feature_names),
                'feature_names': self.feature_names,
                'n_models': len(self.models),
                'contamination_levels': self.contamination_levels,
                'n_estimators_list': self.n_estimators_list,
                'ensemble_weights': self.ensemble_weights,
                'anomaly_threshold': self.anomaly_threshold,
                'hw_params': self.hw_params,
                'pca_explained_variance': self.pca.explained_variance_ratio_.tolist() if hasattr(self.pca, 'explained_variance_ratio_') else [],
                'anomaly_count': int(predictions['combined_anomaly'].sum()),
                'anomaly_rate': float(predictions['combined_anomaly'].mean())
            }
            
            self.training_metrics = training_results
            print("异常检测器训练完成！")
            return training_results
            
        except Exception as e:
            logger.error(f"模型训练失败: {e}")
            raise

    def predict(self, features_df: pd.DataFrame) -> Dict[str, np.ndarray]:
        """异常预测"""
        try:
            if not self.is_trained:
                raise ValueError("模型尚未训练，请先调用train方法")
                
            # 准备特征
            X = self.prepare_features(features_df)
            
            # 应用Holt-Winters时序预处理
            X_processed = self._apply_holt_winters_preprocessing(X)
            X_scaled = self.scaler.transform(X_processed)
            
            # 集成预测
            ensemble_scores = np.zeros(X_scaled.shape[0])
            model_predictions = []
            
            for i, model in enumerate(self.models):
                # 获取异常分数
                scores = model.decision_function(X_scaled)
                # 标准化分数到[0,1]，越大越异常
                normalized_scores = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
                
                model_predictions.append(normalized_scores)
                # 加权融合
                ensemble_scores += self.ensemble_weights[i] * normalized_scores
            
            # 应用阈值
            combined_anomaly = (ensemble_scores >= self.anomaly_threshold).astype(int)
            
            # PCA变换（用于可视化）
            X_pca = self.pca.transform(X_scaled) if self.pca else X_scaled[:, :2]
            
            predictions = {
                'combined_anomaly': combined_anomaly,
                'anomaly_scores': ensemble_scores,
                'anomaly_confidence': ensemble_scores,  # 为了向后兼容，添加这个字段
                'model_predictions': np.array(model_predictions).T,  # 转置以便每行是一个样本
                'pca_features': X_pca,
                'scaled_features': X_scaled
            }
            
            return predictions
            
        except Exception as e:
            logger.error(f"异常预测失败: {e}")
            raise

    def decision_function(self, features_df: pd.DataFrame) -> np.ndarray:
        """返回异常分数"""
        predictions = self.predict(features_df)
        return predictions['anomaly_scores']

    def get_feature_importance(self) -> Optional[Dict[str, float]]:
        """获取特征重要性（基于PCA）"""
        try:
            if not self.is_trained or self.pca is None:
                return None
                
            # 基于PCA成分的特征重要性
            if hasattr(self.pca, 'components_'):
                importance = np.abs(self.pca.components_).mean(axis=0)
                feature_importance = dict(zip(self.feature_names, importance))
                
                # 归一化到0-1
                max_importance = max(feature_importance.values())
                if max_importance > 0:
                    feature_importance = {k: v/max_importance for k, v in feature_importance.items()}
                    
                return dict(sorted(feature_importance.items(), key=lambda x: x[1], reverse=True))
            
            return None
            
        except Exception as e:
            logger.error(f"特征重要性计算失败: {e}")
            return None

    def save_model(self, filepath: str):
        """保存模型"""
        try:
            model_data = {
                'scaler': self.scaler,
                'models': self.models,
                'pca': self.pca,
                'feature_names': self.feature_names,
                'contamination_levels': self.contamination_levels,
                'n_estimators_list': self.n_estimators_list,
                'ensemble_weights': self.ensemble_weights,
                'hw_params': self.hw_params,
                'anomaly_threshold': self.anomaly_threshold,
                'use_corrected': self.use_corrected,
                'is_trained': self.is_trained,
                'training_metrics': self.training_metrics
            }
            joblib.dump(model_data, filepath)
            logger.info(f"模型已保存到: {filepath}")
            
        except Exception as e:
            logger.error(f"模型保存失败: {e}")
            raise

    def load_model(self, filepath: str):
        """加载模型"""
        try:
            model_data = joblib.load(filepath)
            
            self.scaler = model_data['scaler']
            self.models = model_data['models']
            self.pca = model_data['pca']
            self.feature_names = model_data['feature_names']
            self.contamination_levels = model_data['contamination_levels']
            self.n_estimators_list = model_data['n_estimators_list']
            self.ensemble_weights = model_data['ensemble_weights']
            self.hw_params = model_data['hw_params']
            self.anomaly_threshold = model_data['anomaly_threshold']
            self.use_corrected = model_data['use_corrected']
            self.is_trained = model_data['is_trained']
            self.training_metrics = model_data.get('training_metrics', {})
            
            logger.info(f"模型已从 {filepath} 加载")
            
        except Exception as e:
            logger.error(f"模型加载失败: {e}")
            raise


class AnomalyAnalyzer:
    """异常分析器 - 提供异常解释和建议"""
    
    def __init__(self):
        self.threshold_rules = self._initialize_threshold_rules()
        
    def _initialize_threshold_rules(self) -> Dict[str, Dict]:
        """初始化阈值规则"""
        return {
            'process_start_count': {'high': 50, 'description': '进程启动次数过多'},
            'process_exit_count': {'high': 50, 'description': '进程退出次数过多'},
            'non_zero_exit_count': {'high': 5, 'description': '异常退出次数过多'},
            'total_syscalls': {'high': 1000, 'description': '系统调用次数异常高'},
            'network_syscall_count': {'high': 200, 'description': '网络系统调用过多'},
            'file_syscall_count': {'high': 500, 'description': '文件系统调用过多'},
            'syscall_entropy': {'low': 1.0, 'description': '系统调用模式过于单一'},
            'top_syscall_ratio': {'high': 0.8, 'description': '单一系统调用占比过高'},
            'unique_processes': {'high': 20, 'description': '运行进程种类过多'},
        }
        
    def analyze_anomaly(self, container_features: pd.Series, predictions: Dict) -> Dict[str, Any]:
        """分析单个容器的异常情况"""
        try:
            container_id = container_features.get('container_id', 'unknown')
            container_name = container_features.get('container_name', f'Container-{container_id[:8]}')
            
            # 获取异常预测结果
            is_anomaly = predictions.get('combined_anomaly', [False])[0] if len(predictions.get('combined_anomaly', [])) > 0 else False
            confidence = predictions.get('anomaly_scores', [0.0])[0] if len(predictions.get('anomaly_scores', [])) > 0 else 0.0
            
            # 识别异常原因
            anomaly_reasons = self._identify_anomaly_reasons(container_features)
            
            # 计算严重程度
            severity = self._calculate_severity(container_features, confidence)
            
            # 生成建议
            recommendations = self._generate_recommendations(anomaly_reasons)
            
            analysis = {
                'container_id': container_id,
                'container_name': container_name,
                'is_anomaly': bool(is_anomaly),
                'confidence': float(confidence),
                'severity': severity,
                'anomaly_reasons': anomaly_reasons,
                'recommendations': recommendations,
                'feature_summary': self._summarize_features(container_features)
            }
            
            return analysis
            
        except Exception as e:
            logger.error(f"异常分析失败: {e}")
            return {
                'container_id': 'unknown',
                'container_name': 'unknown',
                'is_anomaly': False,
                'confidence': 0.0,
                'severity': 'low',
                'anomaly_reasons': [],
                'recommendations': [],
                'feature_summary': {}
            }
            
    def _identify_anomaly_reasons(self, features: pd.Series) -> List[Dict[str, Any]]:
        """识别异常原因"""
        reasons = []
        
        for feature_name, rule in self.threshold_rules.items():
            if feature_name in features:
                value = features[feature_name]
                
                if 'high' in rule and value > rule['high']:
                    reasons.append({
                        'feature': feature_name,
                        'value': float(value),
                        'threshold': rule['high'],
                        'type': 'high',
                        'description': rule['description']
                    })
                elif 'low' in rule and value < rule['low']:
                    reasons.append({
                        'feature': feature_name,
                        'value': float(value),
                        'threshold': rule['low'],
                        'type': 'low',
                        'description': rule['description']
                    })
                    
        return reasons
        
    def _calculate_severity(self, features: pd.Series, confidence: float) -> str:
        """计算异常严重程度"""
        # 基于置信度和异常特征数量
        anomaly_count = len(self._identify_anomaly_reasons(features))
        
        if confidence > 0.8 and anomaly_count >= 3:
            return 'critical'
        elif confidence > 0.6 or anomaly_count >= 2:
            return 'high'
        elif confidence > 0.4 or anomaly_count >= 1:
            return 'medium'
        else:
            return 'low'
            
    def _generate_recommendations(self, anomaly_reasons: List[Dict]) -> List[str]:
        """生成异常处理建议"""
        recommendations = []
        
        for reason in anomaly_reasons:
            feature = reason['feature']
            
            if 'process' in feature and 'start' in feature:
                recommendations.append("检查是否有异常进程大量启动，可能存在恶意软件")
            elif 'syscall' in feature:
                recommendations.append("监控系统调用模式，排查可能的异常行为")
            elif 'network' in feature:
                recommendations.append("检查网络连接，可能存在异常网络活动")
            elif 'file' in feature:
                recommendations.append("检查文件操作，可能存在异常文件访问")
            elif 'exit' in feature:
                recommendations.append("检查进程退出状态，可能存在程序崩溃或异常终止")
                
        # 去重
        recommendations = list(set(recommendations))
        
        if not recommendations:
            recommendations.append("进行全面的系统检查，确认容器状态")
            
        return recommendations
    
    def _summarize_features(self, features: pd.Series) -> Dict[str, Any]:
        """总结特征信息"""
        summary = {}
        
        # 选择关键特征进行总结
        key_features = [
            'total_syscalls', 'process_start_count', 'process_exit_count',
            'network_syscall_count', 'file_syscall_count', 'unique_processes'
        ]
        
        for feature in key_features:
            if feature in features:
                summary[feature] = float(features[feature])
                
        return summary

if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent))
    from data_processor import DataProcessor
    from time_series_optimizer import TimeSeriesOptimizer
    
    try:
        # 加载数据
        processor = DataProcessor()
        processor.load_latest_data()
        features = processor.extract_features()
        
        if not features.empty:
            print(f"加载数据: {len(features)} 个容器")
            
            # 创建AnomalyDetector
            detector = AnomalyDetector(
                contamination_levels=[0.05, 0.1, 0.15],
                n_estimators_list=[50, 100, 150],
                ensemble_weights=[0.1, 0.3, 0.6],
                anomaly_threshold=0.7
            )
            
            # 训练模型
            training_results = detector.train(features)
            print(f"训练完成: {training_results}")
            
            # 预测异常
            predictions = detector.predict(features)
            print(f"发现 {predictions['combined_anomaly'].sum()} 个异常容器")
            
            # 分析异常
            analyzer = AnomalyAnalyzer()
            for i, (_, container) in enumerate(features.iterrows()):
                if predictions['combined_anomaly'][i]:
                    analysis = analyzer.analyze_anomaly(container, {
                        'combined_anomaly': [predictions['combined_anomaly'][i]],
                        'anomaly_scores': [predictions['anomaly_scores'][i]]
                    })
                    print(f"异常容器分析: {analysis}")
            
        else:
            print("没有找到有效的特征数据")
            
    except Exception as e:
        print(f"错误: {e}")
