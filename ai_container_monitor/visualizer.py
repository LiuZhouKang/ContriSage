import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path
import json
import logging
from datetime import datetime
import sys
from matplotlib import font_manager as fm

# 添加项目路径
current_dir = Path(__file__).parent
sys.path.append(str(current_dir))

from data_processor import DataProcessor
from anomaly_detector import AnomalyDetector, AnomalyAnalyzer

# 设置字体和样式
import matplotlib
matplotlib.use('Agg')  # 使用非交互式后端
# 扩展中文字体候选，后续会动态检测是否存在
plt.rcParams['font.family'] = ['DejaVu Sans', 'Arial', 'Liberation Sans']
plt.rcParams['font.sans-serif'] = [
    'Noto Sans CJK SC', 'WenQuanYi Micro Hei', 'Source Han Sans SC', 'Microsoft YaHei',
    'PingFang SC', 'SimHei', 'DejaVu Sans', 'Arial', 'Liberation Sans'
]
plt.rcParams['axes.unicode_minus'] = False
plt.rcParams['figure.max_open_warning'] = 50
sns.set_style("whitegrid")
sns.set_palette("husl")

logger = logging.getLogger(__name__)

class VisualizationGenerator:
    """可视化图表生成器"""
    
    def __init__(self, output_dir: str = None):
        self.output_dir = Path(output_dir) if output_dir else current_dir / "visualizations"
        self.output_dir.mkdir(exist_ok=True)
    
    def _translate_description(self, text: str) -> str:
        return str(text)

    def _apply_cjk_font(self, ax=None) -> str | None:
        """寻找并应用可用的 CJK 字体，解决中文显示为方框的问题。
        返回选中的字体名，找不到则返回 None。
        """
        candidates = [
            'Noto Sans CJK SC', 'Source Han Sans SC', 'WenQuanYi Micro Hei',
            'Microsoft YaHei', 'PingFang SC', 'SimHei', 'Arial Unicode MS'
        ]
        available = {f.name for f in fm.fontManager.ttflist}
        chosen = None
        for name in candidates:
            if name in available:
                chosen = name
                break
        if chosen:
            # 设为首选 sans-serif 字体
            current = list(plt.rcParams.get('font.sans-serif', []))
            plt.rcParams['font.sans-serif'] = [chosen] + [f for f in current if f != chosen]
            if ax is not None:
                for lab in list(ax.get_xticklabels()) + list(ax.get_yticklabels()):
                    lab.set_fontfamily(chosen)
        else:
            logger.warning("未找到可用的中文字体，中文可能显示为方框。建议安装 Noto Sans CJK 或 WenQuanYi Micro Hei。")
        return chosen
        
    def generate_all_visualizations(self, features_df: pd.DataFrame, predictions: dict, 
                                  analysis_results: list) -> dict:
        """生成所有可视化图表"""
        try:
            visualizations = {}
            
            # 1. 异常分布图
            visualizations['anomaly_distribution'] = self.plot_anomaly_distribution(
                features_df, predictions)
            
            # 2. 特征重要性图
            detector = AnomalyDetector()
            if hasattr(detector, 'get_feature_importance'):
                visualizations['feature_importance'] = self.plot_feature_importance(
                    detector.get_feature_importance())
            
            # 3. 系统调用分析图
            visualizations['syscall_analysis'] = self.plot_syscall_analysis(features_df)
            
            # 4. 进程行为分析图
            visualizations['process_analysis'] = self.plot_process_analysis(features_df)
            
            # 5. 异常严重程度分布
            visualizations['severity_distribution'] = self.plot_severity_distribution(
                analysis_results)
            
            # 6. 容器资源使用热力图
            visualizations['resource_heatmap'] = self.plot_resource_heatmap(features_df)
            
            # 7. 异常原因分析
            visualizations['anomaly_reasons'] = self.plot_anomaly_reasons(analysis_results)
            
            # 8. 特征相关性热力图（加入异常分数）
            features_with_score = features_df.copy()
            try:
                if predictions and 'anomaly_confidence' in predictions:
                    # 将 0-1 的异常置信度作为异常分数
                    anomaly_score = np.asarray(predictions['anomaly_confidence']).reshape(-1)
                    if len(anomaly_score) == len(features_with_score):
                        features_with_score['anomaly_score'] = anomaly_score
            except Exception as _:
                pass
            visualizations['feature_correlation'] = self.plot_feature_correlation(features_with_score)
            
            logger.info(f"生成了 {len(visualizations)} 个可视化图表")
            return visualizations
            
        except Exception as e:
            logger.error(f"可视化生成失败: {e}")
            return {}
    
    def plot_anomaly_distribution(self, features_df: pd.DataFrame, predictions: dict) -> str:
        """异常分布散点图"""
        try:
            self._apply_cjk_font()
            # 创建更大的图形，左右各一个子图
            fig = plt.figure(figsize=(20, 8))
            
            # 创建子图，给颜色条留出空间
            ax1 = plt.subplot(1, 2, 1)
            ax2 = plt.subplot(1, 2, 2)
            
            # PCA降维可视化
            if len(features_df) > 0:
                from sklearn.decomposition import PCA
                from sklearn.preprocessing import StandardScaler

                # 选择数值特征
                numeric_features = features_df.select_dtypes(include=[np.number]).columns.tolist()
                numeric_features = [col for col in numeric_features if col not in ['container_id', 'timestamp']]

                if len(numeric_features) >= 2:
                    # 标准化数据
                    scaler = StandardScaler()
                    scaled_data = scaler.fit_transform(features_df[numeric_features].fillna(0))

                    # PCA降维
                    pca = PCA(n_components=2)
                    pca_data = pca.fit_transform(scaled_data)

                    # 获取异常标签
                    anomaly_labels = predictions.get('combined_anomaly', np.zeros(len(features_df)))

                    # 绘制散点图
                    normal_mask = anomaly_labels == 0
                    anomaly_mask = anomaly_labels == 1

                    if np.any(normal_mask):
                        ax1.scatter(
                            pca_data[normal_mask, 0], pca_data[normal_mask, 1],
                            c='blue', alpha=0.6, s=60, label='Normal Containers',
                            edgecolors='navy', linewidths=0.5
                        )
                    if np.any(anomaly_mask):
                        ax1.scatter(
                            pca_data[anomaly_mask, 0], pca_data[anomaly_mask, 1],
                            c='red', alpha=0.8, s=100, label='Anomaly Containers',
                            marker='x', linewidths=2
                        )
                ax1.set_xlabel('Principal Component 1', fontsize=13)
                ax1.set_ylabel('Principal Component 2', fontsize=13)
                ax1.set_title('Container Anomaly Distribution (PCA)', fontsize=15, fontweight='bold', pad=20)
                
                # 将图例放在左上角，避免与数据重叠
                ax1.legend(fontsize=11, loc='upper left', frameon=True, fancybox=True, shadow=True)
                ax1.grid(True, alpha=0.3)
            
            # 异常置信度分布
            if 'anomaly_confidence' in predictions:
                confidence_scores = predictions['anomaly_confidence']
                anomaly_labels = predictions['combined_anomaly']
                
                # 使用不同的透明度和边缘颜色来区分
                ax2.hist(confidence_scores[anomaly_labels == 0], bins=20, alpha=0.6, 
                        label='Normal Confidence', color='skyblue', density=True, 
                        edgecolor='blue', linewidth=1)
                ax2.hist(confidence_scores[anomaly_labels == 1], bins=20, alpha=0.6, 
                        label='Anomaly Confidence', color='lightcoral', density=True,
                        edgecolor='red', linewidth=1)
                
                ax2.set_xlabel('Anomaly Confidence Score', fontsize=13)
                ax2.set_ylabel('Density', fontsize=13)
                ax2.set_title('Anomaly Confidence Distribution', fontsize=15, fontweight='bold', pad=20)
                
                # 将图例放在左上角
                ax2.legend(fontsize=11, loc='upper left', frameon=True, fancybox=True, shadow=True)
                ax2.grid(True, alpha=0.3)
            
            # 调整整体布局，确保有足够的空间
            plt.tight_layout(pad=3.0)
            
            output_path = self.output_dir / "anomaly_distribution.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight', facecolor='white', pad_inches=0.2)
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"异常分布图生成失败: {e}")
            return ""
    
    def plot_feature_importance(self, feature_importance: dict) -> str:
        """特征重要性图"""
        try:
            self._apply_cjk_font()
            if not feature_importance:
                return ""
                
            # 取前15个最重要的特征
            top_features = dict(list(feature_importance.items())[:15])
            
            fig, ax = plt.subplots(figsize=(12, 8))
            
            features = list(top_features.keys())
            importance_scores = list(top_features.values())
            
            # 创建水平条形图
            bars = ax.barh(range(len(features)), importance_scores, color='steelblue')
            
            # 添加数值标签
            for i, (bar, score) in enumerate(zip(bars, importance_scores)):
                ax.text(score + 0.01, i, f'{score:.3f}', 
                       va='center', fontsize=10)
            
            ax.set_yticks(range(len(features)))
            ax.set_yticklabels([f.replace('_', ' ').title() for f in features])
            ax.set_xlabel('Importance Score')
            ax.set_title('Feature Importance Ranking', fontsize=14, fontweight='bold')
            ax.grid(True, axis='x', alpha=0.3)
            
            plt.tight_layout()
            
            output_path = self.output_dir / "feature_importance.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"特征重要性图生成失败: {e}")
            return ""
    
    def plot_syscall_analysis(self, features_df: pd.DataFrame) -> str:
        """系统调用分析图"""
        try:
            self._apply_cjk_font()
            syscall_features = [
                'total_syscalls', 'network_syscall_count', 
                'file_syscall_count', 'process_mgmt_syscall_count', 
                'memory_syscall_count'
            ]
            
            available_features = [f for f in syscall_features if f in features_df.columns]
            
            if not available_features:
                return ""
            
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            
            # 1. 系统调用类型分布
            syscall_totals = features_df[available_features].sum()
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7'][:len(available_features)]
            
            bars = ax1.bar(range(len(available_features)), syscall_totals.values, color=colors)
            ax1.set_xticks(range(len(available_features)))
            ax1.set_xticklabels([f.replace('_', ' ').title() for f in available_features], 
                               rotation=45, ha='right')
            ax1.set_ylabel('Total System Calls')
            ax1.set_title('System Call Type Distribution')
            ax1.grid(True, alpha=0.3)
            
            # 添加数值标签
            for bar, value in zip(bars, syscall_totals.values):
                ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + value*0.01,
                        f'{int(value):,}', ha='center', va='bottom')
            
            # 2. 系统调用箱线图
            if len(available_features) > 1:
                data_for_box = [features_df[f].values for f in available_features]
                # 截断特征名称以避免重叠
                feature_labels = []
                for f in available_features:
                    label = f.replace('_', ' ').title()
                    if len(label) > 15:
                        label = label[:12] + "..."
                    feature_labels.append(label)
                
                bp = ax2.boxplot(data_for_box, patch_artist=True, labels=feature_labels)
                for patch, color in zip(bp['boxes'], colors):
                    patch.set_facecolor(color)
                    patch.set_alpha(0.7)
                
                ax2.set_ylabel('System Call Count')
                ax2.set_title('System Call Distribution by Type')
                ax2.tick_params(axis='x', rotation=45, labelsize=9)
                ax2.grid(True, alpha=0.3)
            
            # 3. 系统调用相关性
            if 'syscall_entropy' in features_df.columns and 'total_syscalls' in features_df.columns:
                ax3.scatter(features_df['total_syscalls'], features_df['syscall_entropy'], 
                           alpha=0.6, s=50, color='purple')
                ax3.set_xlabel('Total System Calls')
                ax3.set_ylabel('System Call Entropy')
                ax3.set_title('System Call Diversity vs Volume')
                ax3.grid(True, alpha=0.3)
                
                # 添加回归线
                z = np.polyfit(features_df['total_syscalls'], features_df['syscall_entropy'], 1)
                p = np.poly1d(z)
                ax3.plot(features_df['total_syscalls'], p(features_df['total_syscalls']), 
                        "r--", alpha=0.8)
            
            # 4. 网络 vs 文件系统调用
            if 'network_syscall_count' in features_df.columns and 'file_syscall_count' in features_df.columns:
                ax4.scatter(features_df['network_syscall_count'], features_df['file_syscall_count'],
                           alpha=0.6, s=50, color='orange')
                ax4.set_xlabel('Network System Calls')
                ax4.set_ylabel('File System Calls')
                ax4.set_title('Network vs File System Call Pattern')
                ax4.grid(True, alpha=0.3)
            
            plt.tight_layout()
            
            output_path = self.output_dir / "syscall_analysis.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"系统调用分析图生成失败: {e}")
            return ""
    
    def plot_process_analysis(self, features_df: pd.DataFrame) -> str:
        """进程行为分析图"""
        try:
            self._apply_cjk_font()
            process_features = [
                'process_start_count', 'process_exit_count', 
                'unique_processes', 'non_zero_exit_count'
            ]
            
            available_features = [f for f in process_features if f in features_df.columns]
            
            if not available_features:
                return ""
            
            fig, axes = plt.subplots(2, 2, figsize=(15, 12))
            axes = axes.flatten()
            
            colors = ['#E74C3C', '#3498DB', '#2ECC71', '#F39C12']
            
            for i, feature in enumerate(available_features):
                if i < len(axes):
                    ax = axes[i]
                    
                    # 直方图
                    ax.hist(features_df[feature], bins=20, alpha=0.7, color=colors[i % len(colors)],
                           edgecolor='black', linewidth=0.5)
                    
                    # 添加统计信息
                    mean_val = features_df[feature].mean()
                    median_val = features_df[feature].median()
                    
                    ax.axvline(mean_val, color='red', linestyle='--', alpha=0.8, 
                              label=f'Mean: {mean_val:.1f}')
                    ax.axvline(median_val, color='green', linestyle='--', alpha=0.8,
                              label=f'Median: {median_val:.1f}')
                    
                    ax.set_xlabel(feature.replace('_', ' ').title())
                    ax.set_ylabel('Frequency')
                    ax.set_title(f'Distribution of {feature.replace("_", " ").title()}')
                    ax.legend()
                    ax.grid(True, alpha=0.3)
            
            # 隐藏多余的子图
            for i in range(len(available_features), len(axes)):
                axes[i].set_visible(False)
            
            plt.tight_layout()
            
            output_path = self.output_dir / "process_analysis.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"进程分析图生成失败: {e}")
            return ""
    
    def plot_severity_distribution(self, analysis_results: list) -> str:
        """异常严重程度分布图"""
        try:
            self._apply_cjk_font()
            if not analysis_results:
                return ""
            
            # 统计严重程度
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            
            for result in analysis_results:
                if result.get('is_anomaly'):
                    severity = result.get('severity', 'low')
                    severity_counts[severity] += 1
            
            if sum(severity_counts.values()) == 0:
                return ""
            
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
            
            # 饼图
            labels = [k.title() for k, v in severity_counts.items() if v > 0]
            sizes = [v for v in severity_counts.values() if v > 0]
            colors = ['#dc3545', '#fd7e14', '#ffc107', '#28a745']  # critical, high, medium, low
            actual_colors = [colors[i] for i, (k, v) in enumerate(severity_counts.items()) if v > 0]
            
            wedges, texts, autotexts = ax1.pie(sizes, labels=labels, colors=actual_colors, 
                                              autopct='%1.1f%%', startangle=90)
            ax1.set_title('Anomaly Severity Distribution', fontsize=14, fontweight='bold')
            
            # 条形图
            bars = ax2.bar(labels, sizes, color=actual_colors, alpha=0.8, edgecolor='black')
            ax2.set_ylabel('Number of Containers')
            ax2.set_title('Anomaly Count by Severity', fontsize=14, fontweight='bold')
            ax2.grid(True, alpha=0.3)
            
            # 添加数值标签
            for bar, value in zip(bars, sizes):
                ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                        str(value), ha='center', va='bottom', fontweight='bold')
            
            plt.tight_layout()
            
            output_path = self.output_dir / "severity_distribution.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"严重程度分布图生成失败: {e}")
            return ""
    
    def plot_resource_heatmap(self, features_df: pd.DataFrame) -> str:
        """容器资源使用热力图"""
        try:
            self._apply_cjk_font()
            # 选择数值特征
            numeric_features = features_df.select_dtypes(include=[np.number]).columns.tolist()
            
            # 排除标识列
            exclude_cols = ['container_id', 'timestamp', 'anomaly_score']
            numeric_features = [col for col in numeric_features if col not in exclude_cols]
            
            if len(numeric_features) < 2:
                return ""
            
            # 选择前10个容器和前10个特征
            data_subset = features_df[numeric_features].head(10).iloc[:, :10]
            # 移除在当前选择的样本中为常量的特征（会在标准化后变成全 0.00 的行）
            nunique = data_subset.nunique(dropna=True)
            constant_cols = nunique[nunique <= 1].index.tolist()
            if constant_cols:
                data_subset = data_subset.drop(columns=constant_cols)
            # 若全部被移除，则不绘制
            if data_subset.shape[1] == 0:
                return ""
            
            # 标准化数据
            from sklearn.preprocessing import StandardScaler
            scaler = StandardScaler()
            data_normalized = scaler.fit_transform(data_subset)
            
            # 创建热力图
            fig, ax = plt.subplots(figsize=(12, 8))

            # 使用实际容器名称作为 X 轴标签（与 data_subset 的行索引对齐）
            try:
                if 'container_name' in features_df.columns:
                    container_labels = features_df.loc[data_subset.index, 'container_name'].astype(str).tolist()
                elif 'container_id' in features_df.columns:
                    container_labels = (
                        features_df.loc[data_subset.index, 'container_id']
                        .astype(str)
                        .str.slice(0, 12)
                        .tolist()
                    )
                else:
                    container_labels = [f"Container {i+1}" for i in range(data_subset.shape[0])]
            except Exception:
                container_labels = [f"Container {i+1}" for i in range(data_subset.shape[0])]
            
            sns.heatmap(data_normalized.T, 
                       xticklabels=container_labels,
                       yticklabels=[col.replace('_', ' ').title() for col in data_subset.columns],
                       cmap='RdYlBu_r', center=0, annot=True, fmt='.2f',
                       cbar_kws={'label': 'Normalized Value'})
            
            ax.set_title('Container Resource Usage Heatmap (Normalized)', 
                        fontsize=14, fontweight='bold')
            ax.set_xlabel('Containers')
            ax.set_ylabel('Features')
            
            plt.tight_layout()
            
            output_path = self.output_dir / "resource_heatmap.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"资源热力图生成失败: {e}")
            return ""
    
    def plot_anomaly_reasons(self, analysis_results: list) -> str:
        """异常原因分析图"""
        try:
            if not analysis_results:
                return ""
            
            # 统计异常原因
            reason_counts = {}
            
            for result in analysis_results:
                if result.get('is_anomaly') and result.get('anomaly_reasons'):
                    for reason in result['anomaly_reasons']:
                        # 兼容多种结构：dict 或 直接字符串
                        if isinstance(reason, dict):
                            desc = reason.get('description') or reason.get('desc') or reason.get('message')
                        else:
                            desc = str(reason)
                        if not desc:
                            continue
                        english_desc = self._translate_description(desc)
                        if english_desc not in reason_counts:
                            reason_counts[english_desc] = 0
                        reason_counts[english_desc] += 1
            
            if not reason_counts:
                return ""
            
            # 排序并取前8个（减少数量避免重叠）
            sorted_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:8]
            
            fig, ax = plt.subplots(figsize=(14, 10))  # 增加图表大小
            chosen_font = self._apply_cjk_font(ax)
            
            reasons = [r[0] for r in sorted_reasons]
            counts = [r[1] for r in sorted_reasons]
            
            # 截断过长的标签
            truncated_reasons = []
            for reason in reasons:
                if len(reason) > 50:
                    truncated_reasons.append(reason[:47] + "...")
                else:
                    truncated_reasons.append(reason)
            
            # 水平条形图
            bars = ax.barh(range(len(truncated_reasons)), counts, color='coral', alpha=0.8)
            
            # 添加数值标签
            for bar, count in zip(bars, counts):
                ax.text(bar.get_width() + max(counts)*0.02, bar.get_y() + bar.get_height()/2,
                       str(count), va='center', fontweight='bold', fontsize=10)
            
            ax.set_yticks(range(len(truncated_reasons)))
            ax.set_yticklabels(truncated_reasons, fontsize=11, fontfamily=chosen_font or plt.rcParams['font.sans-serif'][0])
            ax.set_xlabel('Number of Occurrences', fontsize=12)
            ax.set_title('Top Anomaly Reasons', fontsize=16, fontweight='bold', pad=20)
            ax.grid(True, axis='x', alpha=0.3)
            
            # 调整边距以防止标签被截断
            plt.subplots_adjust(left=0.32, right=0.96, top=0.9, bottom=0.12)
            
            output_path = self.output_dir / "anomaly_reasons.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"异常原因图生成失败: {e}")
            return ""
    
    def plot_feature_correlation(self, features_df: pd.DataFrame) -> str:
        """特征相关性热力图"""
        try:
            self._apply_cjk_font()
            # 选择数值特征
            numeric_features = features_df.select_dtypes(include=[np.number]).columns.tolist()
            
            # 排除标识列
            exclude_cols = ['container_id', 'timestamp']
            numeric_features = [col for col in numeric_features if col not in exclude_cols]
            
            if len(numeric_features) < 2:
                return ""
            
            # 先移除无变化（常量/唯一值）导致无颜色的特征
            nunique = features_df[numeric_features].nunique(dropna=True)
            constant_cols = nunique[nunique <= 1].index.tolist()
            numeric_features = [c for c in numeric_features if c not in constant_cols]
            if len(numeric_features) < 2:
                return ""

            # 计算相关性矩阵
            corr_matrix = features_df[numeric_features].corr()
            # 丢弃整行/整列均为 NaN 的特征（仍然没有颜色）
            corr_matrix = corr_matrix.dropna(axis=0, how='all').dropna(axis=1, how='all')
            if corr_matrix.shape[0] < 2:
                return ""
            # 对角线设为 1，避免 NaN 留白
            np.fill_diagonal(corr_matrix.values, 1.0)
            
            # 自适应图尺寸，确保所有数字可读且不重叠
            n = corr_matrix.shape[0]
            # 随特征数放大单元格尺寸；在大矩阵上也提供足够空间
            cell_size = 0.55 if n <= 25 else (0.50 if n <= 35 else 0.48)
            fig_w = max(12, min(48, n * cell_size))
            fig_h = max(12, min(48, n * cell_size))
            
            # 展示所有数字（保留两位小数），不做阈值过滤
            annot_data = corr_matrix.round(2)
            
            # 适度截断过长的特征名称
            def _shorten(name: str, limit: int = 28) -> str:
                if len(name) <= limit:
                    return name
                return name[:limit-1] + '…'
            xticklabels = [ _shorten(c.replace('_', ' ')) for c in corr_matrix.columns ]
            yticklabels = [ _shorten(c.replace('_', ' ')) for c in corr_matrix.index ]
            
            # 创建热力图（显示完整矩阵以去除上三角空白）
            fig, ax = plt.subplots(figsize=(fig_w, fig_h), constrained_layout=True)
            hm = sns.heatmap(
                corr_matrix,
                annot=annot_data,
                fmt='.2f',
                annot_kws={'size': 10 if n <= 20 else (9 if n <= 28 else (8 if n <= 38 else 7))},
                cmap='coolwarm',
                center=0,
                square=True,
                xticklabels=xticklabels,
                yticklabels=yticklabels,
                cbar_kws={'label': 'Correlation Coefficient', 'shrink': 0.85, 'pad': 0.02}
            )
            
            # 轴与标题样式
            ax.set_title('Feature Correlation Matrix', fontsize=14, fontweight='bold', pad=14)
            tick_size = 9 if n <= 28 else (8 if n <= 38 else 7)
            ax.tick_params(axis='x', labelrotation=90, labelsize=tick_size, labelright=False)
            ax.tick_params(axis='y', labelrotation=0, labelsize=tick_size)
            
            # 去除多余边距与空白
            plt.subplots_adjust(left=0.18 if n > 20 else 0.14,
                                right=0.98, top=0.94, bottom=0.18 if n > 20 else 0.14)
            
            output_path = self.output_dir / "feature_correlation.png"
            plt.savefig(output_path, dpi=300, bbox_inches='tight', pad_inches=0.02, facecolor='white')
            plt.close()
            
            return str(output_path)
            
        except Exception as e:
            logger.error(f"特征相关性图生成失败: {e}")
            return ""
    
    def generate_summary_dashboard(self, visualizations: dict) -> str:
        """生成汇总仪表板"""
        try:
            # 创建HTML仪表板
            html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Container Anomaly Detection Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { text-align: center; background-color: #2c3e50; color: white; padding: 20px; border-radius: 10px; }
        .container { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        .card h3 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .card img { width: 100%; height: auto; border-radius: 5px; }
        .footer { text-align: center; margin-top: 40px; color: #7f8c8d; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🤖 AI容器异常监测系统</h1>
        <p>Container Anomaly Detection Dashboard</p>
    </div>
    
    <div class="container">
"""
            
            # 添加每个可视化图表
            chart_titles = {
                'anomaly_distribution': '异常分布分析',
                'feature_importance': '特征重要性排序',
                'syscall_analysis': '系统调用分析',
                'process_analysis': '进程行为分析',
                'severity_distribution': '异常严重程度分布',
                'resource_heatmap': '资源使用热力图',
                'anomaly_reasons': '异常原因统计',
                'feature_correlation': '特征相关性分析'
            }
            
            for key, path in visualizations.items():
                if path and Path(path).exists():
                    title = chart_titles.get(key, key.replace('_', ' ').title())
                    html_content += f"""
        <div class="card">
            <h3>{title}</h3>
            <img src="{Path(path).name}" alt="{title}">
        </div>
"""
            
            html_content += """
    </div>
    
    <div class="footer">
        <p>Generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
    </div>
</body>
</html>
"""
            
            # 保存HTML文件
            dashboard_path = self.output_dir / "dashboard.html"
            with open(dashboard_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"仪表板已生成: {dashboard_path}")
            return str(dashboard_path)
            
        except Exception as e:
            logger.error(f"仪表板生成失败: {e}")
            return ""

def main():
    """测试可视化生成器"""
    try:
        # 加载数据
        processor = DataProcessor()
        processor.load_latest_data()
        features = processor.extract_features()
        
        if features.empty:
            print("没有可用数据")
            return
        
        # 训练模型并预测
        detector = AnomalyDetector()
        detector.train(features)
        predictions = detector.predict(features)
        
        # 分析异常
        analyzer = AnomalyAnalyzer()
        analysis_results = []
        
        for i, (_, container) in enumerate(features.iterrows()):
            pred_slice = {k: v[i:i+1] if isinstance(v, np.ndarray) else v 
                         for k, v in predictions.items()}
            analysis = analyzer.analyze_anomaly(container, pred_slice)
            analysis_results.append(analysis)
        
        # 生成可视化
        visualizer = VisualizationGenerator()
        visualizations = visualizer.generate_all_visualizations(
            features, predictions, analysis_results)
        
        # 生成仪表板
        dashboard_path = visualizer.generate_summary_dashboard(visualizations)
        
        print(f"可视化生成完成!")
        print(f"生成了 {len(visualizations)} 个图表")
        print(f"仪表板路径: {dashboard_path}")
        print(f"图片保存在: {visualizer.output_dir}")
        
        # 打印所有生成的文件
        for name, path in visualizations.items():
            if path:
                print(f"   - {name}: {Path(path).name}")
        
    except Exception as e:
        print(f"可视化生成失败: {e}")

if __name__ == "__main__":
    main()
