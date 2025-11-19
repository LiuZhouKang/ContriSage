import dash
from dash import dcc, html, Input, Output, State, dash_table, callback
import plotly.graph_objs as go
import plotly.express as px
import pandas as pd
import numpy as np
import dash_bootstrap_components as dbc
import json
from datetime import datetime, timedelta
import logging
import os
import sys

# 添加项目路径
sys.path.append('/home/lzk/agent3/ai_container_monitor')

from data_processor import DataProcessor
from anomaly_detector import AnomalyDetector, AnomalyAnalyzer

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 初始化Dash应用
app = dash.Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "AI容器异常监测系统"

# 全局变量
processor = DataProcessor()
detector = AnomalyDetector()
analyzer = AnomalyAnalyzer()
current_features = pd.DataFrame()
current_predictions = {}

# 样式定义
CARD_STYLE = {
    "box-shadow": "0 4px 8px 0 rgba(0,0,0,0.2)",
    "margin": "10px",
    "padding": "15px",
}

SEVERITY_COLORS = {
    'critical': '#dc3545',  # 红色
    'high': '#fd7e14',      # 橙色  
    'medium': '#ffc107',    # 黄色
    'low': '#28a745'        # 绿色
}

# 应用布局
def create_layout():
    return dbc.Container([
        # 标题和控制面板
        dbc.Row([
            dbc.Col([
                html.H1("🤖 AI容器异常监测系统", 
                       className="text-center mb-4",
                       style={"color": "#2c3e50", "font-weight": "bold"}),
            ], width=12)
        ]),
        
        # 控制面板
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        dbc.Row([
                            dbc.Col([
                                dbc.Button("刷新数据", id="refresh-btn", color="primary", className="me-2"),
                                dbc.Button("重新训练", id="retrain-btn", color="warning", className="me-2"),
                                dbc.Button("保存模型", id="save-model-btn", color="success"),
                            ], width=8),
                            dbc.Col([
                                html.Div(id="status-indicator", style={"text-align": "right"})
                            ], width=4)
                        ])
                    ])
                ], style=CARD_STYLE)
            ], width=12)
        ], className="mb-3"),
        
        # 统计概览
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("系统概览", className="card-title"),
                        html.Div(id="system-overview")
                    ])
                ], style=CARD_STYLE)
            ], width=12)
        ], className="mb-3"),
        
        # 异常容器列表和详情
        dbc.Row([
            # 异常容器列表
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("异常容器", className="card-title"),
                        html.Div(id="anomaly-list")
                    ])
                ], style=CARD_STYLE)
            ], width=6),
            
            # 容器详情
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("容器详情", className="card-title"),
                        html.Div(id="container-detail")
                    ])
                ], style=CARD_STYLE)
            ], width=6)
        ], className="mb-3"),
        
        # 可视化图表
        dbc.Row([
            # 异常分布图
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("异常分布图", className="card-title"),
                        dcc.Graph(id="anomaly-scatter-plot")
                    ])
                ], style=CARD_STYLE)
            ], width=6),
            
            # 特征重要性
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("特征重要性", className="card-title"),
                        dcc.Graph(id="feature-importance-plot")
                    ])
                ], style=CARD_STYLE)
            ], width=6)
        ], className="mb-3"),
        
        # 系统调用和进程分析
        dbc.Row([
            # 系统调用分析
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("系统调用分析", className="card-title"),
                        dcc.Graph(id="syscall-analysis-plot")
                    ])
                ], style=CARD_STYLE)
            ], width=6),
            
            # 进程行为分析
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("进程行为分析", className="card-title"),
                        dcc.Graph(id="process-analysis-plot")
                    ])
                ], style=CARD_STYLE)
            ], width=6)
        ], className="mb-3"),
        
        # 时间序列趋势
        dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H4("异常趋势分析", className="card-title"),
                        dcc.Graph(id="trend-analysis-plot")
                    ])
                ], style=CARD_STYLE)
            ], width=12)
        ]),
        
        # 隐藏的数据存储
        dcc.Store(id="features-store"),
        dcc.Store(id="predictions-store"),
        dcc.Store(id="selected-container-store"),
        
        # 定时器
        dcc.Interval(
            id='interval-component',
            interval=30*1000,  # 30秒更新一次
            n_intervals=0
        )
        
    ], fluid=True)

app.layout = create_layout()

# 回调函数

@app.callback(
    [Output("features-store", "data"),
     Output("predictions-store", "data"),
     Output("status-indicator", "children")],
    [Input("refresh-btn", "n_clicks"),
     Input("interval-component", "n_intervals"),
     Input("retrain-btn", "n_clicks")],
    prevent_initial_call=False
)
def update_data(refresh_clicks, n_intervals, retrain_clicks):
    """更新数据和模型预测"""
    try:
        ctx = dash.callback_context
        
        # 加载数据
        processor.load_latest_data()
        features = processor.extract_features()
        
        if features.empty:
            return {}, {}, dbc.Alert("没有可用数据", color="warning")
            
        # 训练或加载模型
        model_path = '/home/lzk/agent3/ai_container_monitor/anomaly_model.pkl'
        
        if (ctx.triggered and ctx.triggered[0]['prop_id'] == 'retrain-btn.n_clicks') or not os.path.exists(model_path):
            # 重新训练
            training_results = detector.train(features)
            detector.save_model(model_path)
            status_msg = f"模型已训练 ({training_results['n_samples']} 样本)"
        else:
            # 加载现有模型
            try:
                detector.load_model(model_path)
                status_msg = "模型已加载"
            except:
                # 如果加载失败，重新训练
                training_results = detector.train(features)
                detector.save_model(model_path)
                status_msg = "模型已重新训练"
        
        # 预测异常
        predictions = detector.predict(features)
        
        # 添加时间戳
        features['update_time'] = datetime.now().isoformat()
        
        status_indicator = dbc.Badge(
            status_msg,
            color="success",
            className="ms-1"
        )
        
        return features.to_json(orient='records'), predictions, status_indicator
        
    except Exception as e:
        logger.error(f"数据更新失败: {e}")
        error_indicator = dbc.Alert(f"错误: {str(e)}", color="danger")
        return {}, {}, error_indicator

@app.callback(
    Output("system-overview", "children"),
    [Input("features-store", "data"),
     Input("predictions-store", "data")]
)
def update_system_overview(features_data, predictions_data):
    """更新系统概览"""
    try:
        if not features_data or not predictions_data:
            return html.P("暂无数据")
            
        features = pd.read_json(features_data, orient='records')
        
        # 解析预测结果
        predictions = {}
        for key, value in predictions_data.items():
            if isinstance(value, list):
                predictions[key] = np.array(value)
            else:
                predictions[key] = value
                
        total_containers = len(features)
        anomaly_count = int(predictions['combined_anomaly'].sum()) if 'combined_anomaly' in predictions else 0
        anomaly_rate = (anomaly_count / total_containers * 100) if total_containers > 0 else 0
        
        # 计算严重程度分布
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for i, (_, container) in enumerate(features.iterrows()):
            if predictions['combined_anomaly'][i] == 1:
                pred_slice = {k: v[i:i+1] if isinstance(v, np.ndarray) else v for k, v in predictions.items()}
                analysis = analyzer.analyze_anomaly(container, pred_slice)
                severity_counts[analysis['severity']] += 1
        
        # 创建概览卡片
        overview_cards = dbc.Row([
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(total_containers, className="text-primary"),
                        html.P("总容器数", className="mb-0")
                    ])
                ], color="light", outline=True)
            ], width=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(anomaly_count, className="text-danger"),
                        html.P("异常容器", className="mb-0")
                    ])
                ], color="light", outline=True)
            ], width=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(f"{anomaly_rate:.1f}%", className="text-warning"),
                        html.P("异常率", className="mb-0")
                    ])
                ], color="light", outline=True)
            ], width=3),
            
            dbc.Col([
                dbc.Card([
                    dbc.CardBody([
                        html.H3(features['unique_processes'].sum(), className="text-info"),
                        html.P("活跃进程", className="mb-0")
                    ])
                ], color="light", outline=True)
            ], width=3)
        ])
        
        # 严重程度统计
        severity_badges = []
        for severity, count in severity_counts.items():
            if count > 0:
                severity_badges.append(
                    dbc.Badge(
                        f"{severity.title()}: {count}",
                        color=SEVERITY_COLORS[severity][1:],  # 去掉#号
                        className="me-2"
                    )
                )
        
        if severity_badges:
            severity_section = html.Div([
                html.H6("异常严重程度分布:", className="mt-3 mb-2"),
                html.Div(severity_badges)
            ])
        else:
            severity_section = html.Div()
            
        return html.Div([overview_cards, severity_section])
        
    except Exception as e:
        logger.error(f"系统概览更新失败: {e}")
        return dbc.Alert(f"更新失败: {str(e)}", color="danger")

@app.callback(
    Output("anomaly-list", "children"),
    [Input("features-store", "data"),
     Input("predictions-store", "data")]
)
def update_anomaly_list(features_data, predictions_data):
    """更新异常容器列表"""
    try:
        if not features_data or not predictions_data:
            return html.P("暂无数据")
            
        features = pd.read_json(features_data, orient='records')
        
        # 解析预测结果
        predictions = {}
        for key, value in predictions_data.items():
            if isinstance(value, list):
                predictions[key] = np.array(value)
            else:
                predictions[key] = value
        
        anomaly_containers = []
        
        for i, (_, container) in enumerate(features.iterrows()):
            if predictions['combined_anomaly'][i] == 1:
                pred_slice = {k: v[i:i+1] if isinstance(v, np.ndarray) else v for k, v in predictions.items()}
                analysis = analyzer.analyze_anomaly(container, pred_slice)
                
                # 创建容器卡片
                container_card = dbc.Card([
                    dbc.CardBody([
                        html.H6(analysis['container_name'], className="card-title"),
                        html.P(f"ID: {analysis['container_id'][:12]}...", className="card-text small"),
                        dbc.Row([
                            dbc.Col([
                                dbc.Badge(
                                    analysis['severity'].title(),
                                    color=SEVERITY_COLORS[analysis['severity']][1:],
                                    className="me-2"
                                ),
                                dbc.Badge(f"{analysis['confidence']:.2f}", color="secondary")
                            ], width=8),
                            dbc.Col([
                                dbc.Button(
                                    "详情",
                                    id={"type": "container-detail-btn", "index": i},
                                    size="sm",
                                    color="outline-primary"
                                )
                            ], width=4)
                        ])
                    ])
                ], style={"margin-bottom": "10px"})
                
                anomaly_containers.append(container_card)
        
        if not anomaly_containers:
            return dbc.Alert("🎉 暂无异常容器！", color="success")
            
        return html.Div(anomaly_containers)
        
    except Exception as e:
        logger.error(f"异常列表更新失败: {e}")
        return dbc.Alert(f"更新失败: {str(e)}", color="danger")

@app.callback(
    Output("selected-container-store", "data"),
    Input({"type": "container-detail-btn", "index": dash.dependencies.ALL}, "n_clicks"),
    prevent_initial_call=True
)
def select_container(n_clicks_list):
    """选择容器进行详细分析"""
    ctx = dash.callback_context
    if not ctx.triggered:
        return None
        
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    if button_id:
        container_index = json.loads(button_id)['index']
        return container_index
    
    return None

@app.callback(
    Output("container-detail", "children"),
    [Input("selected-container-store", "data")],
    [State("features-store", "data"),
     State("predictions-store", "data")]
)
def update_container_detail(selected_index, features_data, predictions_data):
    """更新容器详情"""
    try:
        if selected_index is None or not features_data or not predictions_data:
            return html.P("请选择一个容器查看详情")
            
        features = pd.read_json(features_data, orient='records')
        
        # 解析预测结果
        predictions = {}
        for key, value in predictions_data.items():
            if isinstance(value, list):
                predictions[key] = np.array(value)
            else:
                predictions[key] = value
        
        container = features.iloc[selected_index]
        pred_slice = {k: v[selected_index:selected_index+1] if isinstance(v, np.ndarray) else v 
                     for k, v in predictions.items()}
        
        analysis = analyzer.analyze_anomaly(container, pred_slice)
        
        # 容器基本信息
        basic_info = dbc.Card([
            dbc.CardBody([
                html.H6("基本信息", className="card-title"),
                html.P(f"容器名称: {analysis['container_name']}"),
                html.P(f"容器ID: {analysis['container_id']}"),
                html.P(f"异常置信度: {analysis['confidence']:.3f}"),
                html.P([
                    "严重程度: ",
                    dbc.Badge(
                        analysis['severity'].title(),
                        color=SEVERITY_COLORS[analysis['severity']][1:]
                    )
                ])
            ])
        ], className="mb-3")
        
        # 异常原因
        if analysis['anomaly_reasons']:
            reason_items = []
            for reason in analysis['anomaly_reasons']:
                reason_items.append(
                    html.Li([
                        html.Strong(reason['description']),
                        html.Br(),
                        html.Small(f"特征: {reason['feature']}, 值: {reason['value']:.2f}, 阈值: {reason['threshold']}")
                    ])
                )
            
            reasons_card = dbc.Card([
                dbc.CardBody([
                    html.H6("异常原因", className="card-title"),
                    html.Ul(reason_items)
                ])
            ], className="mb-3")
        else:
            reasons_card = dbc.Card([
                dbc.CardBody([
                    html.H6("异常原因", className="card-title"),
                    html.P("未发现明确的异常模式")
                ])
            ], className="mb-3")
        
        # 处理建议
        if analysis['recommendations']:
            rec_items = [html.Li(rec) for rec in analysis['recommendations']]
            recommendations_card = dbc.Card([
                dbc.CardBody([
                    html.H6("处理建议", className="card-title"),
                    html.Ul(rec_items)
                ])
            ])
        else:
            recommendations_card = dbc.Card([
                dbc.CardBody([
                    html.H6("处理建议", className="card-title"),
                    html.P("继续监控容器行为")
                ])
            ])
        
        return html.Div([basic_info, reasons_card, recommendations_card])
        
    except Exception as e:
        logger.error(f"容器详情更新失败: {e}")
        return dbc.Alert(f"更新失败: {str(e)}", color="danger")

@app.callback(
    Output("anomaly-scatter-plot", "figure"),
    [Input("features-store", "data"),
     Input("predictions-store", "data")]
)
def update_anomaly_scatter_plot(features_data, predictions_data):
    """更新异常分布散点图"""
    try:
        if not features_data or not predictions_data:
            return go.Figure()
            
        features = pd.read_json(features_data, orient='records')
        
        # 解析预测结果
        predictions = {}
        for key, value in predictions_data.items():
            if isinstance(value, list):
                predictions[key] = np.array(value)
            else:
                predictions[key] = value
        
        if 'pca_features' not in predictions:
            return go.Figure()
            
        pca_features = predictions['pca_features']
        anomaly_labels = predictions['combined_anomaly']
        confidence_scores = predictions['anomaly_confidence']
        
        # 创建散点图
        fig = go.Figure()
        
        # 正常点
        normal_mask = anomaly_labels == 0
        if normal_mask.any():
            # 安全获取容器名称
            normal_names = []
            for i in range(len(features)):
                if normal_mask[i]:
                    container_name = features.iloc[i].get('container_name', 
                                                        f"Container-{features.iloc[i].get('container_id', 'unknown')[:8]}")
                    normal_names.append(container_name)
            
            fig.add_trace(go.Scatter(
                x=pca_features[normal_mask, 0],
                y=pca_features[normal_mask, 1] if pca_features.shape[1] > 1 else np.zeros(normal_mask.sum()),
                mode='markers',
                marker=dict(
                    color='blue',
                    size=8,
                    opacity=0.6
                ),
                name='正常容器',
                text=normal_names,
                hovertemplate='%{text}<br>PC1: %{x:.2f}<br>PC2: %{y:.2f}<extra></extra>'
            ))
        
        # 异常点
        anomaly_mask = anomaly_labels == 1
        if anomaly_mask.any():
            # 安全获取容器名称
            anomaly_names = []
            for i in range(len(features)):
                if anomaly_mask[i]:
                    container_name = features.iloc[i].get('container_name', 
                                                        f"Container-{features.iloc[i].get('container_id', 'unknown')[:8]}")
                    anomaly_names.append(container_name)
            
            fig.add_trace(go.Scatter(
                x=pca_features[anomaly_mask, 0],
                y=pca_features[anomaly_mask, 1] if pca_features.shape[1] > 1 else np.zeros(anomaly_mask.sum()),
                mode='markers',
                marker=dict(
                    color=confidence_scores[anomaly_mask],
                    colorscale='Reds',
                    size=12,
                    opacity=0.8,
                    colorbar=dict(
                        title="异常置信度",
                        x=1.02,  # 将颜色条移到右侧
                        xanchor='left',
                        len=0.6,  # 缩短颜色条长度
                        y=0.5,    # 垂直居中
                        yanchor='middle'
                    )
                ),
                name='异常容器',
                text=anomaly_names,
                hovertemplate='%{text}<br>PC1: %{x:.2f}<br>PC2: %{y:.2f}<br>置信度: %{marker.color:.3f}<extra></extra>'
            ))
        
        fig.update_layout(
            title="容器异常分布图 (PCA降维)",
            xaxis_title="主成分1",
            yaxis_title="主成分2",
            height=400,
            showlegend=True,
            legend=dict(
                x=0.91,
                y=0.98,
                xanchor='left',
                yanchor='top',
                bgcolor='rgba(255,255,255,0.8)',
                bordercolor='rgba(0,0,0,0.2)',
                borderwidth=1
            ),
            margin=dict(r=120)  # 为颜色条留出右边距
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"异常散点图更新失败: {e}")
        return go.Figure()

@app.callback(
    Output("feature-importance-plot", "figure"),
    Input("predictions-store", "data")
)
def update_feature_importance_plot(predictions_data):
    """更新特征重要性图"""
    try:
        if not detector.is_trained:
            return go.Figure()
            
        importance = detector.get_feature_importance()
        if not importance:
            return go.Figure()
            
        # 取前10个最重要的特征
        top_features = dict(list(importance.items())[:10])
        
        fig = go.Figure([
            go.Bar(
                x=list(top_features.values()),
                y=list(top_features.keys()),
                orientation='h',
                marker_color='steelblue'
            )
        ])
        
        fig.update_layout(
            title="特征重要性排序",
            xaxis_title="重要性分数",
            yaxis_title="特征名称",
            height=400,
            margin=dict(l=150)
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"特征重要性图更新失败: {e}")
        return go.Figure()

@app.callback(
    Output("syscall-analysis-plot", "figure"),
    Input("features-store", "data")
)
def update_syscall_analysis_plot(features_data):
    """更新系统调用分析图"""
    try:
        if not features_data:
            return go.Figure()
            
        features = pd.read_json(features_data, orient='records')
        
        # 系统调用相关特征
        syscall_features = [
            'total_syscalls', 'network_syscall_count', 
            'file_syscall_count', 'process_mgmt_syscall_count', 
            'memory_syscall_count'
        ]
        
        # 检查哪些特征存在
        available_features = [f for f in syscall_features if f in features.columns]
        
        if not available_features:
            return go.Figure()
        
        # 计算每种系统调用的总数
        syscall_totals = features[available_features].sum()
        
        fig = go.Figure([
            go.Bar(
                x=available_features,
                y=syscall_totals.values,
                marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']
            )
        ])
        
        fig.update_layout(
            title="系统调用类型分布",
            xaxis_title="系统调用类型",
            yaxis_title="总调用次数",
            height=400
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"系统调用分析图更新失败: {e}")
        return go.Figure()

@app.callback(
    Output("process-analysis-plot", "figure"),
    Input("features-store", "data")
)
def update_process_analysis_plot(features_data):
    """更新进程行为分析图"""
    try:
        if not features_data:
            return go.Figure()
            
        features = pd.read_json(features_data, orient='records')
        
        # 进程相关特征
        process_features = [
            'process_start_count', 'process_exit_count', 
            'unique_processes', 'non_zero_exit_count'
        ]
        
        # 检查哪些特征存在
        available_features = [f for f in process_features if f in features.columns]
        
        if not available_features:
            return go.Figure()
        
        # 创建子图
        fig = go.Figure()
        
        for feature in available_features:
            fig.add_trace(go.Box(
                y=features[feature],
                name=feature.replace('_', ' ').title(),
                boxpoints='outliers'
            ))
        
        fig.update_layout(
            title="进程行为特征分布",
            yaxis_title="特征值",
            height=400,
            showlegend=True
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"进程分析图更新失败: {e}")
        return go.Figure()

@app.callback(
    Output("trend-analysis-plot", "figure"),
    Input("features-store", "data")
)
def update_trend_analysis_plot(features_data):
    """更新趋势分析图"""
    try:
        if not features_data:
            return go.Figure()
            
        # 这里可以实现时间序列分析
        # 由于当前数据是静态的，我们创建一个模拟的趋势图
        
        # 生成模拟的时间序列数据
        dates = pd.date_range(start=datetime.now() - timedelta(hours=24), 
                             end=datetime.now(), 
                             freq='H')
        
        # 模拟异常检测数量的变化
        np.random.seed(42)
        anomaly_counts = np.random.poisson(2, len(dates))
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=dates,
            y=anomaly_counts,
            mode='lines+markers',
            name='异常容器数量',
            line=dict(color='red', width=2),
            marker=dict(size=6)
        ))
        
        fig.update_layout(
            title="24小时异常趋势（模拟数据）",
            xaxis_title="时间",
            yaxis_title="异常容器数量",
            height=400,
            xaxis=dict(tickformat='%H:%M')
        )
        
        return fig
        
    except Exception as e:
        logger.error(f"趋势分析图更新失败: {e}")
        return go.Figure()

@app.callback(
    Output("save-model-btn", "children"),
    Input("save-model-btn", "n_clicks"),
    prevent_initial_call=True
)
def save_model(n_clicks):
    """保存模型"""
    try:
        if detector.is_trained:
            model_path = '/home/lzk/agent3/ai_container_monitor/anomaly_model.pkl'
            detector.save_model(model_path)
            return "已保存"
        else:
            return "未训练"
    except Exception as e:
        logger.error(f"模型保存失败: {e}")
        return "保存失败"

if __name__ == "__main__":
    print("启动AI容器异常监测系统...")
    print("访问地址: http://localhost:8050")
    app.run(debug=True, host='0.0.0.0', port=8050)
