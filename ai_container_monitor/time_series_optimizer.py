import pandas as pd
import numpy as np
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Tuple, Dict


class TimeSeriesOptimizer:
    """
    使用 Holt‑Winters 三重指数平滑对随时间波动的指标进行校正：x_corr = x_real - x_pred
    - 针对“趋势 + 周期（日内分钟）”的容器指标设计（multiplicative seasonality）
    - 仅依赖历史数据的上一状态，O(1) 在线更新，低开销
    - 历史按CSV维护并自动截断
    """

    def __init__(self,
                 history_path: Path,
                 degree: int = 6,
                 min_points: int = 24,
                 max_history_rows: int = 100_000,
                 alpha: float = 0.2,
                 beta: float = 0.1,
                 gamma: float = 0.4,
                 season_length: int = 144,
                 delta_ratio: float = 0.05):
        # 兼容旧签名：保留 degree/min_points 参数，但不再用于多项式
        self.history_path = Path(history_path)
        self.history_path.parent.mkdir(parents=True, exist_ok=True)
        self.min_points = int(min_points)
        self.max_history_rows = int(max_history_rows)
        # Holt‑Winters 参数
        self.alpha = float(alpha)
        self.beta = float(beta)
        self.gamma = float(gamma)
        self.season_length = int(season_length)  # 默认 10 分钟采样 -> 144
        self.delta_ratio = float(delta_ratio)    # 小波动阈值过滤（相对预测值）

    @staticmethod
    def _minute_of_day(ts: pd.Timestamp) -> int:
        ts = pd.to_datetime(ts) if not isinstance(ts, pd.Timestamp) else ts
        return ts.hour * 60 + ts.minute

    def load_history(self) -> pd.DataFrame:
        if self.history_path.exists():
            try:
                return pd.read_csv(self.history_path)
            except Exception:
                return pd.DataFrame()
        return pd.DataFrame()

    def _truncate_history(self, df: pd.DataFrame) -> pd.DataFrame:
        if len(df) > self.max_history_rows:
            return df.tail(self.max_history_rows).reset_index(drop=True)
        return df

    def update_history(self, features_df: pd.DataFrame) -> None:
        if features_df is None or features_df.empty:
            return
        numeric_cols = features_df.select_dtypes(include=[np.number]).columns.tolist()
        # 保留关键标识列和数值列
        keep_cols = [c for c in ['timestamp', 'container_id', 'container_name'] if c in features_df.columns]
        keep_cols += numeric_cols

        to_save = features_df[keep_cols].copy()
        # 统一时间列
        if 'timestamp' not in to_save.columns:
            to_save['timestamp'] = datetime.now()
        to_save['timestamp'] = pd.to_datetime(to_save['timestamp'])
        to_save['minute_of_day'] = to_save['timestamp'].apply(self._minute_of_day)

        history = self.load_history()
        history = pd.concat([history, to_save], ignore_index=True)
        history = self._truncate_history(history)
        try:
            history.to_csv(self.history_path, index=False)
        except Exception:
            pass

    # ---------- Holt‑Winters 实现辅助 ----------
    def _resolve_season_length(self, history: pd.DataFrame) -> int:
        if 'minute_of_day' in history.columns:
            u = pd.Series(pd.to_numeric(history['minute_of_day'], errors='coerce').dropna().astype(int).unique())
            # 若覆盖了大部分 0..143，则采用 144
            if len(u) >= 100:
                return 144
        return max(2, self.season_length)

    def _init_hw(self, y: pd.Series, minutes: pd.Series, s: int) -> Tuple[float, float, Dict[int, float]]:
        """
        初始化 L0, T0, S 季节索引（按分钟 0..s-1 映射）。
        采用乘性季节：S[m] 近似为 y / 水平均值 的跨日均值。
        """
        df = pd.DataFrame({
            'y': pd.to_numeric(y, errors='coerce'),
            'm': pd.to_numeric(minutes, errors='coerce').astype('Int64')
        }).dropna()
        if df.empty:
            return 0.0, 0.0, {i: 1.0 for i in range(s)}

        # 按时间顺序（如果历史文件本身是时间顺序则无需额外排序，这里稳妥起见）
        df = df.reset_index(drop=True)

        # 估计 L0, T0
        # 使用前一季与后一季的均值估计趋势；数据不足两季时，T0=0
        if len(df) >= 2 * s:
            first_season = df.iloc[:s]['y']
            second_season = df.iloc[s:2*s]['y']
            L0 = float(first_season.mean()) if first_season.notna().any() else float(df['y'].mean())
            Ls = float(second_season.mean()) if second_season.notna().any() else L0
            T0 = (Ls - L0) / s
        else:
            L0 = float(df['y'].mean())
            T0 = 0.0

        # 季节索引：对齐到 0..s-1，聚合跨日均值比
        S_map: Dict[int, float] = {i: 1.0 for i in range(s)}
        try:
            seasonal = df.groupby((df['m'] % s).astype(int))['y'].mean()
            base = L0 if L0 != 0 else (float(df['y'].mean()) or 1.0)
            for idx, val in seasonal.items():
                S_map[int(idx)] = float(val) / (base if base != 0 else 1.0)
            # 归一化到平均 1.0，避免整体偏移
            mean_S = np.mean(list(S_map.values()))
            if mean_S and np.isfinite(mean_S) and mean_S != 0:
                for k in S_map:
                    S_map[k] = max(1e-6, float(S_map[k]) / mean_S)
        except Exception:
            pass

        # 边界保护
        for k in S_map:
            if not np.isfinite(S_map[k]) or S_map[k] <= 0:
                S_map[k] = 1.0

        return L0, T0, S_map

    def _run_hw_over_history(self, y: pd.Series, minutes: pd.Series, s: int,
                              alpha: float, beta: float, gamma: float) -> Tuple[float, float, Dict[int, float]]:
        """
        在历史序列上运行一次 Holt‑Winters，返回最后的 L, T 以及每个分钟位置的 S 值。
        """
        L, T, S_map = self._init_hw(y, minutes, s)
        if len(y) == 0:
            return L, T, S_map

        # 时间顺序迭代
        df = pd.DataFrame({
            'y': pd.to_numeric(y, errors='coerce'),
            'm': pd.to_numeric(minutes, errors='coerce').astype('Int64')
        }).dropna()
        if df.empty:
            return L, T, S_map

        for _, r in df.iterrows():
            x_t = float(r['y'])
            m = int(r['m']) % s
            S_prev = S_map.get(m, 1.0)
            # 更新水平与趋势（乘性季节）
            denom = S_prev if S_prev != 0 else 1.0
            L_t = alpha * (x_t / denom) + (1 - alpha) * (L + T)
            T_t = beta * (L_t - L) + (1 - beta) * T
            # 更新当期季节分量
            denom_L = L_t if L_t != 0 else 1.0
            S_t = gamma * (x_t / denom_L) + (1 - gamma) * S_prev

            # 边界保护
            if not np.isfinite(L_t):
                L_t = L
            if not np.isfinite(T_t):
                T_t = T
            if not np.isfinite(S_t) or S_t <= 0:
                S_t = S_prev if np.isfinite(S_prev) and S_prev > 0 else 1.0

            L, T, S_map[m] = L_t, T_t, S_t

        return L, T, S_map

    def correct_features(self, features_df: pd.DataFrame) -> pd.DataFrame:
        """
        为输入的特征DataFrame追加校正后的列：<feature>_corr
        仅对数值列进行校正，且对每个容器独立进行 Holt‑Winters 预测与校正。
        """
        if features_df is None or features_df.empty:
            return features_df

        df = features_df.copy()
        history = self.load_history()
        if history.empty:
            return df

        # 准备列
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        exclude_cols = {'minute_of_day'}
        numeric_cols = [c for c in numeric_cols if c not in exclude_cols]

        # 当前分钟
        if 'timestamp' in df.columns:
            cur_minutes = df['timestamp'].apply(self._minute_of_day)
        else:
            cur_minutes = pd.Series([self._minute_of_day(datetime.now())] * len(df))

        # 解析季节长度
        season_len = self._resolve_season_length(history)

        # 逐容器逐特征平滑
        corr_values = {f"{col}_corr": [] for col in numeric_cols}
        for i, row in df.iterrows():
            cid = row.get('container_id', None)
            if cid is None:
                # 无container_id时不校正
                for col in numeric_cols:
                    corr_values[f"{col}_corr"].append(row[col])
                continue

            hist_c = history[history.get('container_id', pd.Series(dtype=str)) == cid]
            if hist_c.empty or len(hist_c) < max(10, self.min_points):
                for col in numeric_cols:
                    corr_values[f"{col}_corr"].append(row[col])
                continue

            # 使用时间顺序数据（不按分钟去重，保留跨日季节信息）
            if 'timestamp' in hist_c.columns:
                hist_c = hist_c.sort_values('timestamp')

            cur_minute = int(cur_minutes.iloc[i]) % season_len

            for col in numeric_cols:
                series = pd.to_numeric(hist_c.get(col, pd.Series(dtype=float)), errors='coerce')
                mins = pd.to_numeric(hist_c.get('minute_of_day', pd.Series(dtype=float)), errors='coerce')
                mask = series.notna() & mins.notna()
                y_hist = series[mask]
                m_hist = mins[mask].astype(int)

                # 数据不足或方差为0时跳过
                if len(y_hist) < max(season_len, self.min_points) or (y_hist.std() == 0 and y_hist.mean() == 0):
                    corr_values[f"{col}_corr"].append(row[col])
                    continue

                try:
                    # 运行一次 HW，获取最新 L、T、S
                    L, T, S_map = self._run_hw_over_history(
                        y_hist.values, m_hist.values, season_len,
                        self.alpha, self.beta, self.gamma
                    )
                    S_use = S_map.get(cur_minute, 1.0)
                    pred = (L + T) * (S_use if S_use > 0 else 1.0)
                    x_real = float(row[col]) if np.isfinite(row[col]) else float('nan')

                    if not np.isfinite(pred) or not np.isfinite(x_real):
                        corr_val = row[col]
                    else:
                        corr_val = x_real - float(pred)
                        # 小阈值过滤，避免把正常轻微波动当异常信号
                        if abs(corr_val) < self.delta_ratio * (abs(pred) + 1e-9):
                            corr_val = 0.0
                except Exception:
                    corr_val = row[col]

                if not np.isfinite(corr_val):
                    corr_val = row[col]
                corr_values[f"{col}_corr"].append(float(corr_val))

        # 合并校正列
        for col, vals in corr_values.items():
            df[col] = pd.to_numeric(pd.Series(vals), errors='coerce')
            # 将极端值裁剪到合理范围（基于1/99分位）
            series = df[col]
            if series.notna().sum() >= 10:
                lo, hi = series.quantile([0.01, 0.99])
                df[col] = series.clip(lower=lo, upper=hi)

        return df
