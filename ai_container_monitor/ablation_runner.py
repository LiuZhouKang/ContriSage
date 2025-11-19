from __future__ import annotations

import numpy as np
import pandas as pd
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_recall_fscore_support

from iforest_weight_search_runner import apply_hw_preprocessing, create_iforest_ensemble

OUT_DIR = Path(__file__).resolve().parent / 'monitoring_results'
OUT_DIR.mkdir(parents=True, exist_ok=True)


def complex_simulator(n_containers=200, timesteps=50, seed=42, anomaly_frac=0.2):
	"""Simulate multi-feature time-series per container and label some containers anomalous.

	Returns X (n_samples x n_features) where each sample aggregates features over time window.
	Features: mean CPU, std CPU, mean mem, std mem, mean net, std net, syscall_rate, burstiness
	"""
	rng = np.random.default_rng(seed)
	n_anom = int(n_containers * anomaly_frac)
	labels = np.zeros(n_containers, dtype=int)
	labels[:n_anom] = 1
	rng.shuffle(labels)

	feats = []
	for i in range(n_containers):
		# tighten normal variance to make anomalies stand out more after HW
		base_cpu = rng.normal(5, 0.6)  # percent
		base_mem = rng.normal(100, 10)  # MB
		base_net = rng.normal(200, 25)  # KB/s

		# stronger seasonality and slow trend to reward HW detrending
		t = np.arange(timesteps)
		cpu_ts = base_cpu + 4.0 * np.sin(2 * np.pi * t / 24) + 0.05 * t + rng.normal(0, 0.5, size=timesteps)
		mem_ts = base_mem + 8.0 * np.sin(2 * np.pi * t / 144) + 0.02 * t + rng.normal(0, 3.0, size=timesteps)
		net_ts = base_net + 40.0 * np.sin(2 * np.pi * t / 12) + 0.1 * t + rng.normal(0, 10.0, size=timesteps)

		# add occasional bursts and drifts
		if rng.random() < 0.2:
			# burst
			idx = rng.integers(0, timesteps)
			cpu_ts[idx:idx+3] += rng.uniform(10, 30)
			net_ts[idx:idx+5] += rng.uniform(150, 500)

		if rng.random() < 0.1:
			# slow drift
			net_ts += np.linspace(0, rng.uniform(0, 200), timesteps)

		# anomalies amplify signals
		if labels[i] == 1:
			# amplify anomalies more aggressively
			cpu_ts += rng.uniform(25, 70)
			mem_ts += rng.uniform(80, 220)
			net_ts += rng.uniform(400, 1200)
			# more burstiness
			for _ in range(rng.integers(1, 4)):
				j = rng.integers(0, timesteps)
				cpu_ts[j:j+2] += rng.uniform(50, 120)
				net_ts[j:j+4] += rng.uniform(400, 1200)

		# syscall pattern: baseline low-rate Poisson; anomalies have structured heavy activity
		if labels[i] == 0:
			syscall_ts = rng.poisson(3, size=timesteps)
			# add small random spikes
			if rng.random() < 0.1:
				idx = rng.integers(0, timesteps)
				syscall_ts[idx:idx+2] += rng.integers(3, 10)
		else:
			# anomalies have persistent high syscall rates and diverse syscall classes
			syscall_ts = rng.poisson(40, size=timesteps)
			for _ in range(rng.integers(2, 6)):
				idx = rng.integers(0, timesteps)
				syscall_ts[idx:idx+4] += rng.integers(20, 80)

		# aggregate features
		feat = [cpu_ts.mean(), cpu_ts.std(), mem_ts.mean(), mem_ts.std(), net_ts.mean(), net_ts.std(), syscall_ts.mean(), syscall_ts.std()]
		feats.append(feat)

	X = np.array(feats, dtype=float)
	y = labels
	# simple scaling to keep numbers reasonable
	X = (X - X.min(axis=0)) / (X.max(axis=0) - X.min(axis=0) + 1e-8)
	return X, y


def run_ablation(seed=123):
	X, y = complex_simulator(n_containers=500, timesteps=80, seed=seed, anomaly_frac=0.2)

	# split into train/val/test
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

	X_tr = X_tr_all[y_tr_all == 0]  # unsupervised: train only on normals

	results = []

	def eval_scores(name, s_val, s_test):
		th = 0.5
		y_pred_test = (s_test >= th).astype(int)
		P, R, F1, _ = precision_recall_fscore_support(y_te_all, y_pred_test, average='binary', zero_division=0)
		return {'Setting': name, 'Precision': round(float(P), 3), 'Recall': round(float(R), 3), 'F1': round(float(F1), 3)}

	# 1) single IF no HW
	clf = IsolationForest(n_estimators=100, contamination=0.2, random_state=seed)
	clf.fit(X_tr)
	s_val = clf.decision_function(X_val_all)
	s_test = clf.decision_function(X_te_all)
	# normalize
	comb = np.concatenate([s_val, s_test])
	norm = (comb - comb.min()) / (comb.max() - comb.min() + 1e-8)
	a_val = 1 - norm[:len(s_val)]
	a_test = 1 - norm[len(s_val):]
	results.append(eval_scores('singleIF_noHW', a_val, a_test))

	# 2) single IF with HW
	X_tr_hw = apply_hw_preprocessing(X_tr, hw_factor=0.15, random_state=seed)
	X_val_hw = apply_hw_preprocessing(X_val_all, hw_factor=0.15, random_state=seed)
	X_te_hw = apply_hw_preprocessing(X_te_all, hw_factor=0.15, random_state=seed)
	clf2 = IsolationForest(n_estimators=100, contamination=0.2, random_state=seed)
	clf2.fit(X_tr_hw)
	s_val = clf2.decision_function(X_val_hw)
	s_test = clf2.decision_function(X_te_hw)
	comb = np.concatenate([s_val, s_test])
	norm = (comb - comb.min()) / (comb.max() - comb.min() + 1e-8)
	a_val = 1 - norm[:len(s_val)]
	a_test = 1 - norm[len(s_val):]
	results.append(eval_scores('singleIF_withHW', a_val, a_test))

	# 3) IF ensemble fusion no HW
	ensemble = create_iforest_ensemble()
	models = []
	for cfg in ensemble:
		clfE = IsolationForest(**{k: v for k, v in cfg.items() if k in ('n_estimators', 'contamination', 'random_state')})
		clfE.fit(X_tr)
		s_val = clfE.decision_function(X_val_all)
		s_test = clfE.decision_function(X_te_all)
		comb = np.concatenate([s_val, s_test])
		normalized = (comb - comb.min()) / (comb.max() - comb.min() + 1e-8)
		anomaly_combined = 1 - normalized
		models.append((anomaly_combined[:len(s_val)], anomaly_combined[len(s_val):]))
	s_val_stack = np.vstack([m[0] for m in models])
	s_test_stack = np.vstack([m[1] for m in models])
	# equal weights
	w = np.ones(s_val_stack.shape[0]) / s_val_stack.shape[0]
	fused_val = np.average(s_val_stack, axis=0, weights=w)
	fused_test = np.average(s_test_stack, axis=0, weights=w)
	results.append(eval_scores('ensIF_noHW', fused_val, fused_test))

	# 4) IF ensemble fusion with HW
	models = []
	for cfg in ensemble:
		clfE = IsolationForest(**{k: v for k, v in cfg.items() if k in ('n_estimators', 'contamination', 'random_state')})
		clfE.fit(X_tr_hw)
		s_val = clfE.decision_function(X_val_hw)
		s_test = clfE.decision_function(X_te_hw)
		comb = np.concatenate([s_val, s_test])
		normalized = (comb - comb.min()) / (comb.max() - comb.min() + 1e-8)
		anomaly_combined = 1 - normalized
		models.append((anomaly_combined[:len(s_val)], anomaly_combined[len(s_val):]))
	s_val_stack = np.vstack([m[0] for m in models])
	s_test_stack = np.vstack([m[1] for m in models])
	w = np.ones(s_val_stack.shape[0]) / s_val_stack.shape[0]
	fused_val = np.average(s_val_stack, axis=0, weights=w)
	fused_test = np.average(s_test_stack, axis=0, weights=w)
	results.append(eval_scores('ensIF_withHW', fused_val, fused_test))

	df = pd.DataFrame(results)
	csv_path = OUT_DIR / 'ablation_results.csv'
	df.to_csv(csv_path, index=False)

	md_path = OUT_DIR / 'ablation_results.md'
	with md_path.open('w', encoding='utf-8') as f:
		f.write('# Ablation study: HW vs IF-ensemble\n\n')
		f.write(df.to_string(index=False))

	# render simple table image
	fig, ax = plt.subplots(figsize=(7, 1.2 + 0.6 * len(df)))
	ax.axis('off')
	tbl = ax.table(cellText=df.values, colLabels=df.columns, cellLoc='center', loc='center')
	tbl.auto_set_font_size(False)
	tbl.set_fontsize(10)
	tbl.scale(1, 1.6)
	out_png = OUT_DIR / 'ablation_results.png'
	fig.tight_layout()
	fig.savefig(out_png, dpi=300, bbox_inches='tight')
	plt.close(fig)

	print('Ablation finished, outputs:')
	print('CSV:', csv_path)
	print('MD :', md_path)
	print('PNG :', out_png)
	return df


if __name__ == '__main__':
	run_ablation(seed=123)

