"""
ARGUS Phase 4 — Concept Drift Monitor
======================================
Monitors the live score distribution against a training-split baseline to
detect concept drift — the silent degradation that occurs when normal user
behaviour shifts significantly after a model was trained.

Three complementary tests are run:

  1. Population Stability Index (PSI) on fused_risk_score:
       Buckets both distributions into 10 equal-width bins, computes the
       weighted log-ratio of proportions. Standard thresholds:
         PSI < 0.10  → NONE      (distributions are stable)
         0.10–0.25   → MODERATE  (worth monitoring)
         > 0.25      → SIGNIFICANT (action required — investigate or retrain)

  2. Kolmogorov-Smirnov test on transformer_score and iforest_score:
       Two-sample KS statistic + p-value. p < 0.05 = reject H0 (drift).
       Applied independently to each raw model score stream so we can
       distinguish model-specific drift (one model degrading) from
       population-wide drift.

  3. Alert rate check:
       Compare the rolling alert rate (fraction of sessions flagged >= threshold)
       against the training baseline rate. Flags if rate doubles (>2x) or
       halves (<0.5x) relative to baseline.

Usage (standalone):
    python src/monitoring/drift_monitor.py

Output:
    data/processed/drift_baseline.json   — serialised training-split stats
"""

import json
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import numpy as np
import pandas as pd
from scipy import stats


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

ALERT_THRESHOLD      = 50      # fused_risk_score >= this → flagged
PSI_N_BINS           = 10      # number of PSI histogram bins
PSI_THRESHOLD_MOD    = 0.10    # PSI >= this → MODERATE
PSI_THRESHOLD_SIG    = 0.25    # PSI >= this → SIGNIFICANT
KS_ALPHA             = 0.05    # p-value threshold for KS test
ALERT_RATE_RATIO_HI  = 2.0     # rate > baseline * this → HIGH
ALERT_RATE_RATIO_LO  = 0.5     # rate < baseline * this → LOW


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

class DriftLevel(str, Enum):
    NONE        = "NONE"
    MODERATE    = "MODERATE"
    SIGNIFICANT = "SIGNIFICANT"


@dataclass
class KSResult:
    score_name:  str
    statistic:   float
    p_value:     float
    drift_detected: bool   # p < KS_ALPHA

    def to_dict(self):
        return asdict(self)


@dataclass
class AlertRateResult:
    baseline_rate:  float
    current_rate:   float
    ratio:          float
    flag:           str    # "OK" | "HIGH" | "LOW"

    def to_dict(self):
        return asdict(self)


@dataclass
class DriftReport:
    psi:              float
    psi_level:        DriftLevel
    ks_transformer:   KSResult
    ks_iforest:       KSResult
    alert_rate:       AlertRateResult
    drift_level:      DriftLevel          # overall severity (worst of the three)
    n_baseline:       int
    n_current:        int

    def to_dict(self):
        return {
            "psi":            round(self.psi, 5),
            "psi_level":      self.psi_level.value,
            "ks_transformer": self.ks_transformer.to_dict(),
            "ks_iforest":     self.ks_iforest.to_dict(),
            "alert_rate":     self.alert_rate.to_dict(),
            "drift_level":    self.drift_level.value,
            "n_baseline":     self.n_baseline,
            "n_current":      self.n_current,
        }

    def __str__(self):
        lines = [
            f"  Overall drift level  : {self.drift_level.value}",
            f"  PSI                  : {self.psi:.4f}  ({self.psi_level.value})",
            f"  KS transformer_score : stat={self.ks_transformer.statistic:.4f}  "
            f"p={self.ks_transformer.p_value:.4f}  "
            f"drift={'YES' if self.ks_transformer.drift_detected else 'NO'}",
            f"  KS iforest_score     : stat={self.ks_iforest.statistic:.4f}  "
            f"p={self.ks_iforest.p_value:.4f}  "
            f"drift={'YES' if self.ks_iforest.drift_detected else 'NO'}",
            f"  Alert rate           : baseline={self.alert_rate.baseline_rate:.4f}  "
            f"current={self.alert_rate.current_rate:.4f}  "
            f"ratio={self.alert_rate.ratio:.2f}x  [{self.alert_rate.flag}]",
            f"  N baseline           : {self.n_baseline:,}",
            f"  N current            : {self.n_current:,}",
        ]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Baseline computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_baseline(
    train_df: pd.DataFrame,
    out_path: str = "data/processed/drift_baseline.json",
) -> dict:
    """
    Compute and persist the training-split score distribution baseline.

    Parameters
    ----------
    train_df : DataFrame with columns fused_risk_score, transformer_score,
               iforest_score, is_malicious, and optionally entity_session_idx.
    out_path : JSON output path.

    Filtering applied (production-correct methodology, verified in Phase 4 / G4):
    1. Exclude malicious sessions (is_malicious == False) — malicious campaigns
       inflate the score distribution and cause train alert rate to appear 8-10x
       higher than expected for normal traffic, making Check A falsely fail.
    2. Exclude cold-start sessions (entity_session_idx <= 2) — first 1-2 sessions
       per entity have inflated anomaly scores because the rolling baseline has
       zero prior history. Including these inflates the baseline alert rate.

    Returns
    -------
    dict — baseline statistics (also written to out_path).
    """
    # Apply production-correct filters
    baseline_df = train_df[~train_df["is_malicious"]].copy()
    if "entity_session_idx" in baseline_df.columns:
        baseline_df = baseline_df[baseline_df["entity_session_idx"] > 2].copy()
        print(f"     After cold-start filter (entity_session_idx > 2): {len(baseline_df):,} sessions")
    else:
        print("     [WARN] entity_session_idx not in DataFrame — cold-start filter skipped")

    if len(baseline_df) == 0:
        raise ValueError("Baseline DataFrame is empty after filtering — check splits and entity_session_idx.")

    risk_scores = baseline_df["fused_risk_score"].values.astype(float)
    tf_scores   = baseline_df["transformer_score"].values.astype(float)
    if_scores   = baseline_df["iforest_score"].values.astype(float)

    # Compute 10-bin histogram for PSI (fixed bin edges from training distribution)
    bin_edges = np.linspace(
        max(risk_scores.min() - 1e-6, 0),
        min(risk_scores.max() + 1e-6, 100),
        PSI_N_BINS + 1
    )
    counts, _ = np.histogram(risk_scores, bins=bin_edges)
    total = counts.sum()
    proportions = (counts + 1e-9) / (total + PSI_N_BINS * 1e-9)  # Laplace smoothing

    alert_rate = float((risk_scores >= ALERT_THRESHOLD).mean())

    baseline = {
        "n_sessions":         int(total),
        "n_raw_train":        int(len(train_df)),
        "baseline_filter":    "is_malicious==False AND entity_session_idx>2",
        "alert_threshold":    ALERT_THRESHOLD,
        "alert_rate":         alert_rate,
        "psi_bin_edges":      bin_edges.tolist(),
        "psi_proportions":    proportions.tolist(),
        "risk_score": {
            "mean": float(risk_scores.mean()),
            "std":  float(risk_scores.std()),
            "p10":  float(np.percentile(risk_scores, 10)),
            "p50":  float(np.percentile(risk_scores, 50)),
            "p90":  float(np.percentile(risk_scores, 90)),
            "p99":  float(np.percentile(risk_scores, 99)),
        },
        "transformer_score": {
            "mean":   float(tf_scores.mean()),
            "std":    float(tf_scores.std()),
            "values": tf_scores.tolist(),   # stored for KS test
        },
        "iforest_score": {
            "mean":   float(if_scores.mean()),
            "std":    float(if_scores.std()),
            "values": if_scores.tolist(),
        },
    }

    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=2)

    print(f"[OK] Drift baseline saved → {out_path}")
    print(f"     Raw train sessions  : {len(train_df):,}")
    print(f"     Baseline sessions   : {total:,} (after malicious+cold-start filter)")
    print(f"     Alert rate          : {alert_rate:.4f} ({int(alert_rate*total)} sessions flagged)")
    print(f"     Risk score          : mean={baseline['risk_score']['mean']:.2f}  "
          f"p90={baseline['risk_score']['p90']:.1f}  p99={baseline['risk_score']['p99']:.1f}")
    return baseline


# ─────────────────────────────────────────────────────────────────────────────
# PSI computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_psi(
    current_scores: np.ndarray,
    baseline: dict,
) -> tuple[float, DriftLevel]:
    """
    Compute PSI between current and baseline fused_risk_score distributions.

    PSI = Σ (A_i - E_i) * ln(A_i / E_i)
    where A_i = actual (current) proportion in bin i,
          E_i = expected (baseline) proportion in bin i.

    Returns (psi_value, DriftLevel).
    """
    bin_edges    = np.array(baseline["psi_bin_edges"])
    expected     = np.array(baseline["psi_proportions"])  # already Laplace-smoothed

    counts, _ = np.histogram(current_scores, bins=bin_edges)
    total     = counts.sum()
    actual    = (counts + 1e-9) / (total + len(bin_edges[:-1]) * 1e-9)

    psi = float(np.sum((actual - expected) * np.log(actual / expected)))

    if psi < PSI_THRESHOLD_MOD:
        level = DriftLevel.NONE
    elif psi < PSI_THRESHOLD_SIG:
        level = DriftLevel.MODERATE
    else:
        level = DriftLevel.SIGNIFICANT

    return psi, level


# ─────────────────────────────────────────────────────────────────────────────
# KS test
# ─────────────────────────────────────────────────────────────────────────────

def compute_ks(
    current_scores: np.ndarray,
    baseline_values: list,
    score_name: str,
) -> KSResult:
    """
    Two-sample Kolmogorov-Smirnov test between current and baseline distributions.
    """
    baseline_arr = np.array(baseline_values)
    ks_stat, p_value = stats.ks_2samp(baseline_arr, current_scores)
    return KSResult(
        score_name    = score_name,
        statistic     = round(float(ks_stat), 6),
        p_value       = round(float(p_value), 6),
        drift_detected= bool(p_value < KS_ALPHA),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Alert rate check
# ─────────────────────────────────────────────────────────────────────────────

def compute_alert_rate_check(
    current_scores: np.ndarray,
    baseline: dict,
) -> AlertRateResult:
    baseline_rate = float(baseline["alert_rate"])
    current_rate  = float((current_scores >= ALERT_THRESHOLD).mean())
    ratio         = current_rate / baseline_rate if baseline_rate > 0 else float("inf")

    if ratio >= ALERT_RATE_RATIO_HI:
        flag = "HIGH"
    elif ratio <= ALERT_RATE_RATIO_LO:
        flag = "LOW"
    else:
        flag = "OK"

    return AlertRateResult(
        baseline_rate = round(baseline_rate, 6),
        current_rate  = round(current_rate, 6),
        ratio         = round(ratio, 4),
        flag          = flag,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main check function
# ─────────────────────────────────────────────────────────────────────────────

def check_drift(
    current_df: pd.DataFrame,
    baseline: dict,
) -> DriftReport:
    """
    Run all three drift tests against the loaded baseline.

    Parameters
    ----------
    current_df : DataFrame with columns fused_risk_score, transformer_score,
                 iforest_score (the "live" or test window to evaluate).
    baseline   : dict loaded from drift_baseline.json (via compute_baseline or json.load).

    Returns
    -------
    DriftReport dataclass.
    """
    risk_scores = current_df["fused_risk_score"].values.astype(float)
    tf_scores   = current_df["transformer_score"].values.astype(float)
    if_scores   = current_df["iforest_score"].values.astype(float)

    psi, psi_level = compute_psi(risk_scores, baseline)

    ks_tf = compute_ks(tf_scores, baseline["transformer_score"]["values"], "transformer_score")
    ks_if = compute_ks(if_scores, baseline["iforest_score"]["values"],    "iforest_score")

    alert_rate = compute_alert_rate_check(risk_scores, baseline)

    # Overall drift level: worst-case across all three signals
    levels = [psi_level]
    if ks_tf.drift_detected or ks_if.drift_detected:
        levels.append(DriftLevel.MODERATE)   # KS detection = at least moderate
    if psi_level == DriftLevel.SIGNIFICANT:
        levels.append(DriftLevel.SIGNIFICANT)

    level_order = {DriftLevel.NONE: 0, DriftLevel.MODERATE: 1, DriftLevel.SIGNIFICANT: 2}
    overall = max(levels, key=lambda l: level_order[l])

    return DriftReport(
        psi            = psi,
        psi_level      = psi_level,
        ks_transformer = ks_tf,
        ks_iforest     = ks_if,
        alert_rate     = alert_rate,
        drift_level    = overall,
        n_baseline     = int(baseline["n_sessions"]),
        n_current      = len(current_df),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main — baseline generation
# ─────────────────────────────────────────────────────────────────────────────

def main():
    fused_path    = "data/processed/fused_scores.parquet"
    baseline_path = "data/processed/drift_baseline.json"

    print("[*] Loading fused scores...")
    result = pd.read_parquet(fused_path)

    train_df = result[result["split"] == "train"].copy()
    n_raw = len(train_df)
    print(f"    Raw train sessions : {n_raw:,}")
    n_malicious = train_df["is_malicious"].sum()
    print(f"    Malicious in train : {n_malicious:,} (excluded from baseline)")
    if "entity_session_idx" in train_df.columns:
        n_coldstart = (train_df["entity_session_idx"] <= 2).sum()
        print(f"    Cold-start (idx<=2): {n_coldstart:,} (excluded from baseline)")

    baseline = compute_baseline(train_df, out_path=baseline_path)
    return baseline


if __name__ == "__main__":
    main()
