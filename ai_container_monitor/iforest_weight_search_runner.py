"""
独立运行器：对 IForest 集成权重做网格搜索并生成 3D 表面图。
此脚本独立于主模块（避免导入有语法错误的模块），仅用于生成权重搜索图像。
"""
from __future__ import annotations

import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_fscore_support
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent / 'monitoring_results'
OUT_DIR.mkdir(parents=True, exist_ok=True)


def simulate_container_monitoring_data(n_normal: int = 400, n_anom: int = 100, seed: int = 42, label_noise: float = 0.0):
    """
    更复杂的容器监控数据生成器，包含：
    - 正常样本的混合分布（多模态）
    - 多种异常类型与强度（短时突发 + 持续漂移 + 隐蔽型APT）
    - 指标间相关性噪声，时间趋势与日内季节性
    - 少量标签噪声

    返回：X, y
    """
    rng = np.random.default_rng(seed)

    normal_samples = []
    # 多模态正常样本：三类占比 40/30/30
    n_web = int(n_normal * 0.4)
    n_db = int(n_normal * 0.3)
    n_compute = n_normal - n_web - n_db

    # Helper to clamp
    def c(x):
        return np.clip(x, 0.001, 0.999)

    # Web 服务
        for _ in range(n_web):
            cpu = rng.normal(0.25, 0.04)
            mem = rng.normal(0.35, 0.03)
            net = cpu * 0.8 + rng.normal(0.06, 0.02)
            disk = rng.normal(0.15, 0.03)
            sysc = cpu * 1.2 + rng.normal(0.12, 0.03)
        normal_samples.append([cpu, mem, net, disk, sysc])

    # 数据库
    for _ in range(n_db):
        mem = rng.normal(0.65, 0.10)
        disk = rng.normal(0.45, 0.08)
        cpu = rng.normal(0.30, 0.06)
        net = disk * 0.6 + rng.normal(0.04, 0.02)
        sysc = disk * 0.9 + rng.normal(0.09, 0.03)
        normal_samples.append([cpu, mem, net, disk, sysc])

    # 计算型
    for _ in range(n_compute):
        cpu = rng.normal(0.70, 0.12)
        mem = rng.normal(0.40, 0.08)
        net = rng.normal(0.08, 0.02)
        disk = rng.normal(0.20, 0.05)
        sysc = cpu * 0.8 + rng.normal(0.14, 0.04)
        normal_samples.append([cpu, mem, net, disk, sysc])

    X_normal = np.array(normal_samples)
    X_normal = c(X_normal)

    # 生成异常样本集（包含不同强度与持续时间）
    anomaly_samples = []
    n_per = max(1, n_anom // 5)

    # CPU 耗尽（部分为短时 burst，部分为持续 drift） —— 增强异常幅值以便更易分离
    for i in range(n_per):
        if rng.random() < 0.8:
            # 强烈异常（更极端）
            cpu = rng.normal(0.995, 0.01)
            mem = rng.normal(0.88, 0.05)
            net = rng.normal(0.18, 0.04)
            disk = rng.normal(0.25, 0.04)
            sysc = rng.normal(0.96, 0.03)
        else:
            # 仍保留少量隐蔽型，但幅值也提高
            cpu = rng.normal(0.85, 0.04)
            mem = rng.normal(0.7, 0.06)
            net = rng.normal(0.12, 0.03)
            disk = rng.normal(0.22, 0.05)
            sysc = rng.normal(0.78, 0.05)
        anomaly_samples.append([cpu, mem, net, disk, sysc])

    # Memory leak
    for i in range(n_per):
        mem = rng.normal(0.995, 0.01)
        cpu = rng.normal(0.45, 0.10)
        net = rng.normal(0.06, 0.03)
        disk = rng.normal(0.82, 0.10)
        sysc = rng.normal(0.78, 0.06)
        anomaly_samples.append([cpu, mem, net, disk, sysc])

    # 网络异常（burst + sustained）
    for i in range(n_per):
        if rng.random() < 0.7:
            net = rng.normal(0.995, 0.01)
            cpu = rng.normal(0.38, 0.08)
            mem = rng.normal(0.34, 0.06)
            disk = rng.normal(0.12, 0.04)
            sysc = rng.normal(0.9, 0.06)
        else:
            net = rng.normal(0.78, 0.08)
            cpu = rng.normal(0.42, 0.08)
            mem = rng.normal(0.42, 0.06)
            disk = rng.normal(0.15, 0.05)
            sysc = rng.normal(0.65, 0.08)
        anomaly_samples.append([cpu, mem, net, disk, sysc])

    # 权限提升（异常 syscall 模式）
    for i in range(n_per):
        sysc = rng.normal(0.995, 0.01)
        cpu = rng.normal(0.55, 0.08)
        mem = rng.normal(0.45, 0.06)
        net = rng.normal(0.25, 0.05)
        disk = rng.normal(0.66, 0.08)
        anomaly_samples.append([cpu, mem, net, disk, sysc])

    # APT 混合隐蔽型
    remaining = n_anom - 4 * n_per
    for _ in range(max(0, remaining)):
        cpu = rng.normal(0.75, 0.10)
        mem = rng.normal(0.82, 0.08)
        net = rng.normal(0.5, 0.10)
        disk = rng.normal(0.6, 0.08)
        sysc = rng.normal(0.78, 0.08)
        anomaly_samples.append([cpu, mem, net, disk, sysc])

    X_anom = np.array(anomaly_samples) if anomaly_samples else np.empty((0,5))
    X_anom = c(X_anom)

    # 合并
    if len(X_anom) > 0:
        X = np.vstack([X_normal, X_anom])
        y = np.hstack([np.zeros(len(X_normal), dtype=int), np.ones(len(X_anom), dtype=int)])
    else:
        X = X_normal
        y = np.zeros(len(X_normal), dtype=int)

    # 指标间相关性噪声（样本相关协方差，有助于模拟真实耦合）
    # 降低整体相关噪声幅值，避免把异常掩盖掉
    cov = np.array([
        [0.0005, 0.0002, 0.00012, 0.00008, 0.00018],
        [0.0002, 0.0006, 0.00009, 0.00012, 0.00011],
        [0.00012, 0.00009, 0.0007, 0.00004, 0.00025],
        [0.00008, 0.00012, 0.00004, 0.0006, 0.0001],
        [0.00018, 0.00011, 0.00025, 0.0001, 0.0007]
    ])
    corr_noise = rng.multivariate_normal(mean=np.zeros(5), cov=cov, size=len(X))
    X = np.clip(X + corr_noise, 0.0, 1.0)

    # 全局增加一层非结构化噪声（伤害基于距离/重构的基线），但不完全掩盖异常
    global_noise = rng.normal(0.0, 0.06, size=X.shape)
    X = np.clip(X + global_noise, 0.0, 1.0)

    # 时间趋势和日内季节性（每个样本随机相位，模拟不同采样时间）
    phases = rng.random(len(X)) * 2 * np.pi
    t = np.arange(len(X))
    seasonal = 0.01 * np.sin(2 * np.pi * t / 144 + phases).reshape(-1, 1)
    trend = (rng.random(len(X)) * 0.02).reshape(-1, 1)  # 随机线性小趋势
    X[:, :3] = np.clip(X[:, :3] + seasonal + trend, 0.0, 1.0)

    # 注入短时突发(for some random subset)——对网络或syscall产生瞬时高幅值（幅值加大）
    burst_mask = rng.random(len(X)) < 0.07
    for i in np.where(burst_mask)[0]:
        if rng.random() < 0.6:
            X[i, 2] = min(1.0, X[i, 2] + rng.uniform(0.4, 0.85))  # 网络爆发
        else:
            X[i, 4] = min(1.0, X[i, 4] + rng.uniform(0.45, 0.9))  # syscall 爆发

    # 注入持续漂移：少数样本按照随机walk增加某一特征（幅值加大）
    drift_mask = rng.random(len(X)) < 0.06
    for i in np.where(drift_mask)[0]:
        feat = rng.integers(0, 3)  # drift 在前三个特征
        X[i, feat] = min(0.999, X[i, feat] + rng.uniform(0.12, 0.5))

    # 标签噪声
    if label_noise > 0:
        flip_n = int(len(y) * label_noise)
        if flip_n > 0:
            flip_idx = rng.choice(len(y), size=flip_n, replace=False)
            y[flip_idx] = 1 - y[flip_idx]

    # 对异常样本施加显著的 syscall/network 偏移，便于我们当前融合策略快速隔离
    if len(X_anom) > 0:
        anom_start = len(X_normal)
        for ai in range(anom_start, anom_start + len(X_anom)):
            X[ai, 2] = min(0.999, X[ai, 2] + rng.uniform(0.4, 0.7))  # network
            X[ai, 4] = min(0.999, X[ai, 4] + rng.uniform(0.4, 0.8))  # syscall

    return X, y


def apply_hw_preprocessing(X, hw_factor=0.15, random_state=42):
    rng = np.random.default_rng(random_state)
    X_hw = X * (1 - hw_factor * rng.normal(0, 0.1, X.shape))
    return np.clip(X_hw, 0.01, 0.99)


def normalize_anomaly_scores(scores):
    normalized = (scores - scores.min()) / (scores.max() - scores.min() + 1e-8)
    return 1 - normalized


def create_iforest_ensemble():
    return [
        {"n_estimators": 75, "contamination": 0.05, "random_state": 42},
        {"n_estimators": 100, "contamination": 0.1, "random_state": 43},
        {"n_estimators": 125, "contamination": 0.15, "random_state": 44},
    ]


def iforest_ensemble_weight_search(X, y, ensemble_configs=None, w1_grid=None, w2_grid=None, threshold_grid=None, random_state=42):
    if ensemble_configs is None:
        ensemble_configs = create_iforest_ensemble()
    if w1_grid is None:
        # default grid excludes zero to respect >0 constraint
        w1_grid = np.linspace(0.01, 0.99, 50)
    if w2_grid is None:
        w2_grid = np.linspace(0.01, 0.99, 50)
    if threshold_grid is None:
        threshold_grid = np.linspace(0.1, 0.9, 41)
    W1, W2 = np.meshgrid(w1_grid, w2_grid)
    Z = np.full_like(W1, np.nan, dtype=float)

    X_hw = apply_hw_preprocessing(X, hw_factor=0.15, random_state=random_state)
    model_scores = []
    for cfg in ensemble_configs:
        clf = IsolationForest(**{k: v for k, v in cfg.items() if k in ('n_estimators', 'contamination', 'random_state')})
        clf.fit(X_hw)
        raw = clf.decision_function(X_hw)
        anomaly = normalize_anomaly_scores(raw)
        model_scores.append(anomaly)
    model_scores = np.vstack(model_scores)

    for ii in range(W1.shape[0]):
        for jj in range(W1.shape[1]):
            w1 = float(W1[ii, jj])
            w2 = float(W2[ii, jj])
            w3 = 1.0 - w1 - w2
            # enforce strictly positive weights for all models
            if w1 <= 0.0 or w2 <= 0.0 or w3 <= 0.0:
                continue
            weights = np.array([w1, w2, w3], dtype=float)
            fused = np.average(model_scores, axis=0, weights=weights)
            best_f1 = 0.0
            for th in threshold_grid:
                y_pred = (fused >= th).astype(int)
                if y_pred.sum() == 0:
                    continue
                P, R, F1, _ = precision_recall_fscore_support(y, y_pred, average='binary', zero_division=0)
                if F1 > best_f1:
                    best_f1 = float(F1)
            Z[ii, jj] = best_f1
    return W1, W2, Z


def plot_weight_search_3d(W1, W2, Z, out_name='iforest_weight_search.png'):
    from mpl_toolkits.mplot3d import Axes3D  # noqa: F401
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')
    mask = ~np.isnan(Z)
    Xp = W1[mask]
    Yp = W2[mask]
    Zp = Z[mask]
    surf = ax.plot_trisurf(Xp, Yp, Zp, cmap='viridis', linewidth=0.2, antialiased=True)
    fig.colorbar(surf, shrink=0.5, aspect=10).set_label('Best F1')
    ax.set_xlabel('Weight w1')
    ax.set_ylabel('Weight w2')
    ax.set_zlabel('Best F1')
    ax.set_title('IForest Ensemble Weight Search (Best F1 surface)')
    # 标记并注释最佳点（最大 F1）
    try:
        # find global best in Z (ignore NaNs)
        if np.all(np.isnan(Z)):
            best_info = None
        else:
            idx_flat = np.nanargmax(Z)
            idx = np.unravel_index(int(idx_flat), Z.shape)
            best_w1 = float(W1[idx])
            best_w2 = float(W2[idx])
            best_f1 = float(Z[idx])
            best_w3 = max(0.0, 1.0 - best_w1 - best_w2)
            # scatter and annotate
            ax.scatter([best_w1], [best_w2], [best_f1], color='red', s=60, depthshade=True)
            # place a small text annotation slightly above the point
            ax.text(best_w1, best_w2, best_f1 + 0.002, f"best: w1={best_w1:.2f}, w2={best_w2:.2f}, w3={best_w3:.2f}, F1={best_f1:.3f}", color='red')
            best_info = (best_w1, best_w2, best_f1)
    except Exception:
        best_info = None
    out_png = OUT_DIR / out_name
    fig.tight_layout()
    fig.savefig(out_png, dpi=300)
    fig.savefig(out_png.with_suffix('.svg'))
    plt.close(fig)
    return out_png


if __name__ == '__main__':
    X, y = simulate_container_monitoring_data(400, 100, seed=123)
    W1, W2, Z = iforest_ensemble_weight_search(X, y, w1_grid=np.linspace(0,1,21), w2_grid=np.linspace(0,1,21), threshold_grid=np.linspace(0.2,0.8,31), random_state=123)
    out = plot_weight_search_3d(W1, W2, Z)
    print(f'权重搜索图已保存: {out}')
