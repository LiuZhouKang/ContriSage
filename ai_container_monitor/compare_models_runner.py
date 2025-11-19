from __future__ import annotations

import numpy as np
import pandas as pd
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor, NearestNeighbors
from sklearn.covariance import EllipticEnvelope
from sklearn.decomposition import PCA
from sklearn.metrics import precision_recall_fscore_support
from sklearn.preprocessing import MinMaxScaler
import glob
import os
from typing import Tuple
import pandas as _pd


def load_real_agent_data(data_dir: os.PathLike) -> Tuple[np.ndarray, np.ndarray]:
    data_dir = Path(data_dir)
    # find files
    proc_files = sorted(glob.glob(str(data_dir / 'process_*.csv')))
    sys_files = sorted(glob.glob(str(data_dir / 'syscall_*.csv')))
    if not proc_files or not sys_files:
        raise FileNotFoundError('process_*.csv or syscall_*.csv not found in ' + str(data_dir))

    # read process file(s) and count processes per container as a proxy for cpu/mem
    df_proc = _pd.concat([_pd.read_csv(p) for p in proc_files], ignore_index=True)
    df_sys = _pd.concat([_pd.read_csv(p) for p in sys_files], ignore_index=True)

    # basic aggregates per container_name
    # cpu proxy: count of active processes
    proc_counts = df_proc.groupby('container_name').size().rename('proc_count')
    # memory proxy: unique pids count (as a rough proxy)
    mem_counts = df_proc.groupby('container_name')['pid'].nunique().rename('mem_count')
    # netio/diskio proxies are not present; use counts of network-related syscalls as netio proxy
    # syscall_rate: total syscall occurrences per container
    sys_counts = df_sys.groupby('container_name')['occur_times'].sum().rename('sys_calls')

    # approximate netio by counting connect/listen/accept syscalls
    net_like = df_sys[df_sys['syscall_name'].isin(['connect', 'listen', 'accept', 'sendto', 'recvfrom'])]
    net_counts = net_like.groupby('container_name').size().rename('net_count')

    # merge
    merged = _pd.concat([proc_counts, mem_counts, sys_counts, net_counts], axis=1).fillna(0)
    merged['diskio'] = 0.0

    # labels: container_name contains 'anomaly' -> 1 else 0
    merged['label'] = merged.index.to_series().apply(lambda s: 1 if 'anomaly' in str(s) else 0)

    # features order: cpu(proc_count), mem(mem_count), net(net_count), diskio, syscall_rate
    X = merged[['proc_count', 'mem_count', 'net_count', 'diskio', 'sys_calls']].values.astype(float)
    y = merged['label'].values.astype(int)

    # scale to [0,1]
    scaler = MinMaxScaler()
    X = scaler.fit_transform(X)

    return X, y


# reuse simulate function from iforest runner
from iforest_weight_search_runner import simulate_container_monitoring_data, apply_hw_preprocessing, normalize_anomaly_scores, create_iforest_ensemble

OUT_DIR = Path(__file__).resolve().parent / 'monitoring_results'
OUT_DIR.mkdir(parents=True, exist_ok=True)


def select_threshold_by_f1(scores, y_true, thresholds=None):
    if thresholds is None:
        thresholds = np.linspace(0.05, 0.95, 91)
    best_th = thresholds[0]
    best_f1 = -1.0
    for th in thresholds:
        y_pred = (scores >= th).astype(int)
        if y_pred.sum() == 0:
            continue
        P, R, F1, _ = precision_recall_fscore_support(y_true, y_pred, average='binary', zero_division=0)
        if F1 > best_f1:
            best_f1 = float(F1)
            best_th = float(th)
    return best_th, best_f1


def evaluate_model_on_splits(model_name, score_vals_val, y_val, score_vals_test, y_test, auto_threshold=True):
    # score_vals are anomaly degrees (higher -> more anomalous, in [0,1])
    if auto_threshold:
        th, f1_val = select_threshold_by_f1(score_vals_val, y_val)
    else:
        th = 0.5
    # evaluate on test
    y_pred_test = (score_vals_test >= th).astype(int)
    P, R, F1, _ = precision_recall_fscore_support(y_test, y_pred_test, average='binary', zero_division=0)
    return {
        'Method': model_name,
        'Precision': float(P),
        'Recall': float(R),
        'F1': float(F1)
    }


def build_superfusion_scores(X_train, X_val, X_test, w_best=(0.0, 0.55, 0.45), hw_factor=0.15, random_state=42):
    # train on X_train (only normals) -> prepare HW processed X
    X_train_hw = apply_hw_preprocessing(X_train, hw_factor=hw_factor, random_state=random_state)
    X_val_hw = apply_hw_preprocessing(X_val, hw_factor=hw_factor, random_state=random_state)
    X_test_hw = apply_hw_preprocessing(X_test, hw_factor=hw_factor, random_state=random_state)

    ensemble_configs = create_iforest_ensemble()
    models = []
    for cfg in ensemble_configs:
        clf = IsolationForest(**{k: v for k, v in cfg.items() if k in ('n_estimators', 'contamination', 'random_state')})
        clf.fit(X_train_hw)
        s_val = clf.decision_function(X_val_hw)
        s_test = clf.decision_function(X_test_hw)
        # normalize separately per model using its val+test span to stabilize
        combined = np.concatenate([s_val, s_test])
        normalized = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
        anomaly_combined = 1 - normalized
        s_val_a = anomaly_combined[:len(s_val)]
        s_test_a = anomaly_combined[len(s_val):]
        models.append((s_val_a, s_test_a))

    # stack models
    s_val_stack = np.vstack([m[0] for m in models])
    s_test_stack = np.vstack([m[1] for m in models])

    w = np.array(w_best, dtype=float)
    fused_val = np.average(s_val_stack, axis=0, weights=w)
    fused_test = np.average(s_test_stack, axis=0, weights=w)
    return fused_val, fused_test


def run_comparison(seed=123):
    # by default use simulated dataset; if a real data folder exists next to repo, prefer it
    data_dir = Path(__file__).resolve().parent.parent / 'build' / 'bin' / 'Debug' / 'agent_data'
    if data_dir.exists():
        try:
            X, y = load_real_agent_data(data_dir)
        except Exception:
            # fallback to simulation on any error
            X, y = simulate_container_monitoring_data(n_normal=1000, n_anom=250, seed=seed)
    else:
        X, y = simulate_container_monitoring_data(n_normal=1000, n_anom=250, seed=seed)

    # split into train/val/test = 60/20/20
    n = len(X)
    idx = np.arange(n)
    rng = np.random.default_rng(seed)
    rng.shuffle(idx)
    tr_end = int(0.6 * n)
    val_end = int(0.8 * n)
    tr_idx = idx[:tr_end]
    val_idx = idx[tr_end:val_end]
    te_idx = idx[val_end:]

    X_tr_all, y_tr_all = X[tr_idx], y[tr_idx]
    X_val_all, y_val_all = X[val_idx], y[val_idx]
    X_te_all, y_te_all = X[te_idx], y[te_idx]

    # for unsupervised training, train only on normal samples in train set
    X_tr = X_tr_all[y_tr_all == 0]

    results = []

    # Our final model (Agent) - use previously found best weights
    w_best = (0.05, 0.55, 0.4)
    fused_val, fused_test = build_superfusion_scores(X_tr, X_val_all, X_te_all, w_best=w_best, random_state=seed)
    res = evaluate_model_on_splits('Agent(our)', fused_val, y_val_all, fused_test, y_te_all)
    results.append(res)

    # Baseline 1: Classical IsolationForest
    clf_if = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    clf_if.fit(X_tr)
    s_val = clf_if.decision_function(X_val_all)
    s_test = clf_if.decision_function(X_te_all)
    # normalize
    combined = np.concatenate([s_val, s_test])
    norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
    a_val = 1 - norm[:len(s_val)]
    a_test = 1 - norm[len(s_val):]
    results.append(evaluate_model_on_splits('IsolationForest (baseline)', a_val, y_val_all, a_test, y_te_all))

    # Baseline 2: One-Class SVM
    clf_ocsvm = OneClassSVM(nu=0.1, kernel='rbf', gamma='scale')
    clf_ocsvm.fit(X_tr)
    s_val = clf_ocsvm.decision_function(X_val_all)
    s_test = clf_ocsvm.decision_function(X_te_all)
    combined = np.concatenate([s_val, s_test])
    norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
    a_val = 1 - norm[:len(s_val)]
    a_test = 1 - norm[len(s_val):]
    results.append(evaluate_model_on_splits('OneClassSVM', a_val, y_val_all, a_test, y_te_all))

    # Baseline 3: Local Outlier Factor (novelty)
    clf_lof = LocalOutlierFactor(n_neighbors=20, novelty=True)
    clf_lof.fit(X_tr)
    s_val = clf_lof.decision_function(X_val_all)
    s_test = clf_lof.decision_function(X_te_all)
    combined = np.concatenate([s_val, s_test])
    norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
    a_val = 1 - norm[:len(s_val)]
    a_test = 1 - norm[len(s_val):]
    results.append(evaluate_model_on_splits('LocalOutlierFactor', a_val, y_val_all, a_test, y_te_all))

    # Baseline 4: EllipticEnvelope
    clf_ee = EllipticEnvelope(contamination=0.1, support_fraction=None, random_state=42)
    clf_ee.fit(X_tr)
    s_val = clf_ee.decision_function(X_val_all)
    s_test = clf_ee.decision_function(X_te_all)
    combined = np.concatenate([s_val, s_test])
    norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
    a_val = 1 - norm[:len(s_val)]
    a_test = 1 - norm[len(s_val):]
    results.append(evaluate_model_on_splits('EllipticEnvelope', a_val, y_val_all, a_test, y_te_all))

    # Baseline 5: KNN-distance anomaly score (avg distance to k nearest neighbors)
    k = 5
    nbrs = NearestNeighbors(n_neighbors=k+1).fit(X_tr)
    # compute distance of each validation/test point to its k nearest in training
    dist_val, _ = nbrs.kneighbors(X_val_all)
    dist_test, _ = nbrs.kneighbors(X_te_all)
    # drop first column (self) if present; here nbrs fitted on X_tr so no self; keep mean distance
    a_val = dist_val.mean(axis=1)
    a_test = dist_test.mean(axis=1)
    combined = np.concatenate([a_val, a_test])
    norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
    a_val = norm[:len(a_val)]  # here larger distance -> more anomalous already
    a_test = norm[len(a_val):]
    results.append(evaluate_model_on_splits('KNN-distance', a_val, y_val_all, a_test, y_te_all))

    # Baseline 6: PCA reconstruction error
    pca = PCA(n_components=min(3, X_tr.shape[1]))
    pca.fit(X_tr)
    rec_val = pca.inverse_transform(pca.transform(X_val_all))
    rec_test = pca.inverse_transform(pca.transform(X_te_all))
    err_val = np.linalg.norm(X_val_all - rec_val, axis=1)
    err_test = np.linalg.norm(X_te_all - rec_test, axis=1)
    combined = np.concatenate([err_val, err_test])
    norm = (combined - combined.min()) / (combined.max() - combined.min() + 1e-8)
    a_val = norm[:len(err_val)]
    a_test = norm[len(err_val):]
    results.append(evaluate_model_on_splits('PCA-reconstruction', a_val, y_val_all, a_test, y_te_all))

    # compile results
    df = pd.DataFrame(results)
    df = df[['Method', 'Precision', 'Recall', 'F1']]
    # control numeric precision to 3 decimal places for CSV/MD/PNG
    df[['Precision', 'Recall', 'F1']] = df[['Precision', 'Recall', 'F1']].round(3)

    # save CSV
    csv_path = OUT_DIR / 'compare_results.csv'
    df.to_csv(csv_path, index=False)

    # save markdown table
    md_path = OUT_DIR / 'compare_results.md'
    with md_path.open('w', encoding='utf-8') as f:
        f.write('# 模型对比实验结果\n\n')
        # 避免依赖 tabulate，使用简单的表格文本输出
        f.write(df.to_string(index=False))
    
    # render as image (simple table rendering)
    fig, ax = plt.subplots(figsize=(8.5, 1.2 + 0.5 * len(df)))
    ax.axis('off')
    tbl = ax.table(cellText=df.values, colLabels=df.columns, cellLoc='center', loc='center')
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1, 1.8)
    out_png = OUT_DIR / 'compare_results.png'
    fig.tight_layout()
    fig.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close(fig)

    print('对比实验完成，结果已保存:')
    print('CSV:', csv_path)
    print('MD :', md_path)
    print('PNG :', out_png)
    return df


if __name__ == '__main__':
    # if user provided real data path via env var AGENT_DATA_DIR, prefer it
    agent_data_dir = os.environ.get('AGENT_DATA_DIR')
    if agent_data_dir:
        # run with real data
        Xy = None
        try:
            X, y = load_real_agent_data(Path(agent_data_dir))
            run_comparison(seed=123)
        except Exception as e:
            print('加载真实数据出错，回退到模拟数据：', e)
            run_comparison(seed=123)
    else:
        run_comparison(seed=123)

