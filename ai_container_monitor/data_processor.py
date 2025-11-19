import pandas as pd
import numpy as np
import glob
import os
from datetime import datetime, timedelta
import logging
from typing import Dict, List, Tuple, Optional
import sys
from pathlib import Path

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

from syscall_classifier import SyscallClassifier

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DataProcessor:
    """数据处理和特征工程类"""
    
    def __init__(self, data_path: str = "/home/lzk/agent3/build/bin/Debug/agent_data"):
        self.data_path = data_path
        self.process_data = None
        self.syscall_data = None
        self.features = None
        self.syscall_classifier = SyscallClassifier()  # 添加系统调用分类器
        
    def load_latest_data(self) -> Tuple[pd.DataFrame, pd.DataFrame]:
        """加载最新的进程和系统调用数据"""
        try:
            # 获取最新的数据文件
            process_files = glob.glob(os.path.join(self.data_path, "process_*.csv"))
            syscall_files = glob.glob(os.path.join(self.data_path, "syscall_*.csv"))
            
            if not process_files or not syscall_files:
                raise FileNotFoundError("没有找到数据文件")
                
            latest_process_file = max(process_files, key=os.path.getctime)
            latest_syscall_file = max(syscall_files, key=os.path.getctime)
            
            logger.info(f"加载进程数据: {latest_process_file}")
            logger.info(f"加载系统调用数据: {latest_syscall_file}")
            
            # 读取数据，处理编码问题
            self.process_data = self._read_csv_with_encoding(latest_process_file)
            self.syscall_data = self._read_csv_with_encoding(latest_syscall_file)
            
            # 数据清洗
            self._clean_data()
            
            return self.process_data, self.syscall_data
            
        except Exception as e:
            logger.error(f"数据加载失败: {e}")
            raise
    
    def _read_csv_with_encoding(self, filepath: str) -> pd.DataFrame:
        """安全读取CSV文件，处理编码问题"""
        encodings = ['utf-8', 'latin-1', 'gb2312', 'gbk', 'utf-16']
        
        for encoding in encodings:
            try:
                logger.info(f"尝试使用 {encoding} 编码读取文件: {filepath}")
                df = pd.read_csv(filepath, encoding=encoding, on_bad_lines='skip')
                logger.info(f"成功使用 {encoding} 编码读取文件")
                return df
            except UnicodeDecodeError:
                continue
            except Exception as e:
                logger.warning(f"使用 {encoding} 编码读取失败: {e}")
                continue
        
        # 如果所有编码都失败，尝试忽略错误
        try:
            logger.warning("所有编码尝试失败，使用错误忽略模式")
            df = pd.read_csv(filepath, encoding='utf-8', errors='ignore', on_bad_lines='skip')
            return df
        except Exception as e:
            logger.error(f"文件读取完全失败: {e}")
            raise
            
    def _clean_data(self):
        """数据清洗"""
        # 清理损坏的字符
        if self.process_data is not None:
            self.process_data = self._clean_corrupted_data(self.process_data)
        if self.syscall_data is not None:
            self.syscall_data = self._clean_corrupted_data(self.syscall_data)
            
        # 处理时间戳
        if self.process_data is not None and 'timestamp' in self.process_data.columns:
            self.process_data['timestamp'] = pd.to_datetime(self.process_data['timestamp'], errors='coerce')
        if self.syscall_data is not None and 'timestamp' in self.syscall_data.columns:
            self.syscall_data['timestamp'] = pd.to_datetime(self.syscall_data['timestamp'], errors='coerce')
            
        # 删除空值行
        if self.process_data is not None:
            self.process_data = self.process_data.dropna(subset=['pid', 'container_id'])
            # 处理缺失的容器名称
            self.process_data['container_name'] = self.process_data['container_name'].fillna('unknown')
            
        if self.syscall_data is not None:
            self.syscall_data = self.syscall_data.dropna(subset=['pid', 'container_id'])
            # 处理缺失的容器名称
            self.syscall_data['container_name'] = self.syscall_data['container_name'].fillna('unknown')

        # 去重：相同容器/系统调用/时间戳的重复记录仅保留最后一条
        if self.syscall_data is not None and not self.syscall_data.empty:
            dedup_cols = [c for c in ['container_id', 'syscall_id', 'syscall_name', 'timestamp'] if c in self.syscall_data.columns]
            if dedup_cols:
                before = len(self.syscall_data)
                self.syscall_data = self.syscall_data.drop_duplicates(subset=dedup_cols, keep='last')
                after = len(self.syscall_data)
                logger.info(f"系统调用数据去重: {before} -> {after}")

        if self.process_data is not None and not self.process_data.empty:
            dedup_cols_p = [c for c in ['container_id', 'pid', 'event', 'timestamp'] if c in self.process_data.columns]
            if dedup_cols_p:
                before = len(self.process_data)
                self.process_data = self.process_data.drop_duplicates(subset=dedup_cols_p, keep='last')
                after = len(self.process_data)
                logger.info(f"进程数据去重: {before} -> {after}")

        # 数值列异常值修正与裁剪
        def _clip_numeric(df: pd.DataFrame, exclude: List[str] = None):
            exclude = exclude or []
            if df is None or df.empty:
                return
            for col in df.select_dtypes(include=[np.number]).columns:
                if col in exclude:
                    continue
                s = pd.to_numeric(df[col], errors='coerce')
                s = s.replace([np.inf, -np.inf], np.nan)
                if s.notna().sum() >= 20:
                    lo, hi = s.quantile([0.01, 0.99])
                    s = s.clip(lower=lo, upper=hi)
                df[col] = s.fillna(0)

        _clip_numeric(self.syscall_data, exclude=['pid'])
        _clip_numeric(self.process_data, exclude=['pid'])
            
    def _clean_corrupted_data(self, df: pd.DataFrame) -> pd.DataFrame:
        """清理损坏的数据"""
        # 替换或删除包含无效字符的行
        for col in df.select_dtypes(include=[object]).columns:
            # 替换非法字符
            df[col] = df[col].astype(str).str.replace('��', '', regex=False)
            df[col] = df[col].str.replace('[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]', '', regex=True)
            # 清理空字符串
            df[col] = df[col].replace('', np.nan)
        
        return df
        
    def extract_features(self, time_window_minutes: int = 5) -> pd.DataFrame:
        """提取容器级别的特征"""
        try:
            if self.process_data is None or self.syscall_data is None:
                raise ValueError("请先加载数据")
                
            # 按容器分组提取特征
            container_features = []
            
            for container_id in self.process_data['container_id'].unique():
                if pd.isna(container_id) or container_id == '':
                    continue
                    
                features = self._extract_container_features(container_id, time_window_minutes)
                if features:
                    container_features.append(features)
                    
            if not container_features:
                logger.warning("没有提取到任何特征")
                return pd.DataFrame()
                
            self.features = pd.DataFrame(container_features)
            # 处理特征中的无穷和NaN
            for col in self.features.select_dtypes(include=[np.number]).columns:
                s = pd.to_numeric(self.features[col], errors='coerce')
                s = s.replace([np.inf, -np.inf], np.nan)
                self.features[col] = s.fillna(0)
            logger.info(f"成功提取 {len(self.features)} 个容器的特征")
            
            return self.features
            
        except Exception as e:
            logger.error(f"特征提取失败: {e}")
            raise
            
    def _extract_container_features(self, container_id: str, time_window_minutes: int) -> Dict:
        """为单个容器提取特征"""
        try:
            # 过滤容器数据
            container_process = self.process_data[self.process_data['container_id'] == container_id]
            container_syscall = self.syscall_data[self.syscall_data['container_id'] == container_id]
            
            if container_process.empty and container_syscall.empty:
                return None
                
            container_name = container_process['container_name'].iloc[0] if not container_process.empty else \
                           container_syscall['container_name'].iloc[0] if not container_syscall.empty else 'unknown'
            
            features = {
                'container_id': container_id,
                'container_name': container_name,
                'timestamp': datetime.now()
            }
            
            # 进程相关特征
            if not container_process.empty:
                features.update(self._extract_process_features(container_process))
            else:
                features.update(self._get_default_process_features())
                
            # 系统调用相关特征
            if not container_syscall.empty:
                features.update(self._extract_syscall_features(container_syscall))
            else:
                features.update(self._get_default_syscall_features())
                
            return features
            
        except Exception as e:
            logger.error(f"容器 {container_id} 特征提取失败: {e}")
            return None
            
    def _extract_process_features(self, process_df: pd.DataFrame) -> Dict:
        """提取进程相关特征"""
        features = {}
        
        # 进程启动和退出统计
        start_events = process_df[process_df['event'] == 'start']
        exit_events = process_df[process_df['event'] == 'exit']
        
        features['process_start_count'] = len(start_events)
        features['process_exit_count'] = len(exit_events)
        features['process_net_count'] = features['process_start_count'] - features['process_exit_count']
        
        # 进程多样性
        features['unique_processes'] = process_df['comm'].nunique()
        features['unique_pids'] = process_df['pid'].nunique()
        
        # 进程层次结构
        features['max_ppid'] = process_df['ppid'].max() if 'ppid' in process_df.columns else 0
        features['unique_ppids'] = process_df['ppid'].nunique() if 'ppid' in process_df.columns else 0
        
        # 命名空间特征
        for ns_col in ['user_ns', 'pid_ns', 'mount_ns']:
            if ns_col in process_df.columns:
                features[f'{ns_col}_unique_count'] = process_df[ns_col].nunique()
            else:
                features[f'{ns_col}_unique_count'] = 0
                
        # 异常退出码
        if 'exit_code' in process_df.columns:
            exit_codes = exit_events['exit_code'].dropna()
            features['non_zero_exit_count'] = (exit_codes != 0).sum()
            features['avg_exit_code'] = exit_codes.mean() if len(exit_codes) > 0 else 0
        else:
            features['non_zero_exit_count'] = 0
            features['avg_exit_code'] = 0
            
        return features
        
    def _extract_syscall_features(self, syscall_df: pd.DataFrame) -> Dict:
        """提取系统调用相关特征 - 使用智能分类器"""
        features = {}
        
        if len(syscall_df) == 0:
            return self._get_default_syscall_features()
        
        # 基本统计
        features['total_syscalls'] = syscall_df['occur_times'].sum()
        features['unique_syscall_types'] = syscall_df['syscall_name'].nunique()
        features['unique_syscall_ids'] = syscall_df['syscall_id'].nunique()
        
        # 使用智能分类器获取分类特征
        category_features = self.syscall_classifier.get_category_features(syscall_df)
        features.update(category_features)
        
        # 高频系统调用分析
        syscall_counts = syscall_df.groupby('syscall_name')['occur_times'].sum().sort_values(ascending=False)
        
        if len(syscall_counts) > 0:
            total_calls = features['total_syscalls']
            
            # TOP系统调用比例
            features['top_syscall_ratio'] = syscall_counts.iloc[0] / total_calls
            features['top3_syscall_ratio'] = syscall_counts.head(3).sum() / total_calls
            features['top5_syscall_ratio'] = syscall_counts.head(5).sum() / total_calls
            features['top10_syscall_ratio'] = syscall_counts.head(10).sum() / total_calls
            
            # 系统调用集中度（基尼系数）
            sorted_counts = syscall_counts.values
            n = len(sorted_counts)
            index = np.arange(1, n + 1)
            features['syscall_gini_coefficient'] = (2 * np.sum(index * sorted_counts)) / (n * np.sum(sorted_counts)) - (n + 1) / n
            
            # 系统调用多样性（香农熵）
            proportions = syscall_counts / total_calls
            features['syscall_entropy'] = -np.sum(proportions * np.log2(proportions + 1e-10))
            
            # 系统调用多样性（辛普森指数）
            features['syscall_simpson_index'] = np.sum(proportions ** 2)
            features['syscall_simpson_diversity'] = 1 - features['syscall_simpson_index']
            
        else:
            features.update({
                'top_syscall_ratio': 0,
                'top3_syscall_ratio': 0,
                'top5_syscall_ratio': 0,
                'top10_syscall_ratio': 0,
                'syscall_gini_coefficient': 0,
                'syscall_entropy': 0,
                'syscall_simpson_index': 0,
                'syscall_simpson_diversity': 0
            })
        
        # 系统调用时间模式分析（如果有时间戳信息）
        if 'timestamp' in syscall_df.columns:
            features.update(self._extract_temporal_syscall_features(syscall_df))
        
        # 异常系统调用检测
        features.update(self._detect_anomalous_syscalls(syscall_df, syscall_counts))
        
        return features
    
    def _extract_temporal_syscall_features(self, syscall_df: pd.DataFrame) -> Dict:
        """提取时间相关的系统调用特征"""
        features = {}
        
        try:
            # 如果有时间戳，分析时间模式
            if 'timestamp' in syscall_df.columns:
                timestamps = pd.to_datetime(syscall_df['timestamp'])
                time_diffs = timestamps.diff().dropna()
                
                if len(time_diffs) > 0:
                    # 时间间隔统计
                    features['avg_syscall_interval'] = time_diffs.mean().total_seconds()
                    features['std_syscall_interval'] = time_diffs.std().total_seconds()
                    features['max_syscall_interval'] = time_diffs.max().total_seconds()
                    features['min_syscall_interval'] = time_diffs.min().total_seconds()
                else:
                    features.update({
                        'avg_syscall_interval': 0,
                        'std_syscall_interval': 0,
                        'max_syscall_interval': 0,
                        'min_syscall_interval': 0
                    })
            else:
                features.update({
                    'avg_syscall_interval': 0,
                    'std_syscall_interval': 0,
                    'max_syscall_interval': 0,
                    'min_syscall_interval': 0
                })
        except Exception as e:
            logger.warning(f"时间特征提取失败: {e}")
            features.update({
                'avg_syscall_interval': 0,
                'std_syscall_interval': 0,
                'max_syscall_interval': 0,
                'min_syscall_interval': 0
            })
        
        return features
    
    def _detect_anomalous_syscalls(self, syscall_df: pd.DataFrame, syscall_counts: pd.Series) -> Dict:
        """检测异常系统调用"""
        features = {}
        
        try:
            # 定义一些可能的异常系统调用--后续我们可以添加更多的异常系统调用以此来进一步提高我们模型的准确率以及减少误报
            suspicious_syscalls = {
                'ptrace', 'personality', 'modify_ldt', 'create_module', 'delete_module',
                'init_module', 'finit_module', 'kexec_load', 'kexec_file_load',
                'bpf', 'seccomp', 'setns', 'unshare'
            }
            
            # 计算可疑系统调用
            suspicious_count = 0
            for syscall_name in syscall_counts.index:
                if syscall_name.lower() in suspicious_syscalls:
                    suspicious_count += syscall_counts[syscall_name]
            
            features['suspicious_syscall_count'] = suspicious_count
            
            # 计算高频异常（调用次数超过平均值3倍的系统调用）　－－基于统计的检测，超出３esp调用次数的系统调用被认为是异常
            if len(syscall_counts) > 0:
                avg_count = syscall_counts.mean()
                high_freq_threshold = avg_count * 3
                features['high_frequency_syscall_count'] = (syscall_counts > high_freq_threshold).sum()
                features['max_single_syscall_count'] = syscall_counts.max()
            else:
                features['high_frequency_syscall_count'] = 0
                features['max_single_syscall_count'] = 0
                
        except Exception as e:
            logger.warning(f"异常系统调用检测失败: {e}")
            features.update({
                'suspicious_syscall_count': 0,
                'high_frequency_syscall_count': 0,
                'max_single_syscall_count': 0
            })
        
        return features
        
    def _get_default_process_features(self) -> Dict:
        """返回默认的进程特征（当没有进程数据时）"""
        return {
            'process_start_count': 0,
            'process_exit_count': 0,
            'process_net_count': 0,
            'unique_processes': 0,
            'unique_pids': 0,
            'max_ppid': 0,
            'unique_ppids': 0,
            'user_ns_unique_count': 0,
            'pid_ns_unique_count': 0,
            'mount_ns_unique_count': 0,
            'non_zero_exit_count': 0,
            'avg_exit_code': 0
        }
        
    def _get_default_syscall_features(self) -> Dict:
        """返回默认的系统调用特征（当没有系统调用数据时）"""
        # 获取分类器的默认特征
        default_features = self.syscall_classifier.get_category_features(pd.DataFrame())
        
        # 添加其他基本特征
        default_features.update({
            'total_syscalls': 0,
            'unique_syscall_types': 0,
            'unique_syscall_ids': 0,
            'top_syscall_ratio': 0,
            'top3_syscall_ratio': 0,
            'top5_syscall_ratio': 0,
            'top10_syscall_ratio': 0,
            'syscall_gini_coefficient': 0,
            'syscall_entropy': 0,
            'syscall_simpson_index': 0,
            'syscall_simpson_diversity': 0,
            'avg_syscall_interval': 0,
            'std_syscall_interval': 0,
            'max_syscall_interval': 0,
            'min_syscall_interval': 0,
            'suspicious_syscall_count': 0,
            'high_frequency_syscall_count': 0,
            'max_single_syscall_count': 0
        })
        
        return default_features
    
    def print_syscall_analysis(self, syscall_df: pd.DataFrame):
        """打印系统调用分析报告"""
        if len(syscall_df) > 0:
            print("\n" + "="*60)
            print("系统调用分析报告")
            print("="*60)
            self.syscall_classifier.print_classification_report(syscall_df)
        else:
            print("没有系统调用数据可分析")
        
    def get_feature_summary(self) -> Dict:
        """获取特征摘要信息"""
        if self.features is None:
            return {}
            
        summary = {
            'total_containers': len(self.features),
            'feature_count': len(self.features.columns) - 3,  # 排除id, name, timestamp
            'features': list(self.features.columns),
            'numeric_features': list(self.features.select_dtypes(include=[np.number]).columns)
        }
        
        return summary

if __name__ == "__main__":
    # 测试数据处理器
    processor = DataProcessor()
    
    try:
        # 加载数据
        process_data, syscall_data = processor.load_latest_data()
        print(f"加载进程数据: {len(process_data)} 行")
        print(f"加载系统调用数据: {len(syscall_data)} 行")
        
        # 提取特征
        features = processor.extract_features()
        print(f"提取特征: {len(features)} 个容器")
        
        # 显示特征摘要
        summary = processor.get_feature_summary()
        print(f"特征摘要: {summary}")
        
        # 保存特征数据
        if not features.empty:
            features.to_csv('/home/lzk/agent3/ai_container_monitor/container_features.csv', index=False)
            print("特征数据已保存到 container_features.csv")
            
    except Exception as e:
        print(f"错误: {e}")
