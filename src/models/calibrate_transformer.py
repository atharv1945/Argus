"""
ARGUS Phase 4 — Transformer Score Calibration
===============================================
Fits Platt scaling (logistic regression on transformer_score → calibrated
probability) using the held-out test split.

The held-out test split is itself split 50/50 into:
  • calibration set  (50%) — used to fit the Platt sigmoid a, b
  • validation set   (50%) — used to evaluate ECE before vs after

This double-split avoids overfitting the calibration curve onto the same
data that will be used to measure improvement.

Outputs
-------
  src/models/calibration_params.json   — Platt a, b + optimal threshold + ECE metrics
  Console report:
    - ECE before calibration
    - ECE after Platt scaling
    - Precision-recall sweep (threshold 0.10 → 0.90, step 0.05)
    - Max-F1 operating point and whether 0.50 is optimal

IMPORTANT: This phase's imbalance handling means calibration + threshold
selection ONLY. No retraining of the Isolation Forest or Transformer.
Both frozen model files remain read-only throughout.

Usage:
    python src/models/calibrate_transformer.py
"""

import json
import os
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import calibration_curve
from sklearn.metrics import precision_score, recall_score, f1_score


# ─────────────────────────────────────────────────────────────────────────────
# Expected Calibration Error
# ─────────────────────────────────────────────────────────────────────────────

def expected_calibration_error(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    n_bins: int = 10,
) -> float:
    """
    Compute ECE: weighted average gap between predicted probability and
    observed fraction positive across n_bins confidence buckets.

    ECE = Σ_b  |B_b| / N * |mean_prob(B_b) - mean_label(B_b)|

    Lower is better. A perfectly calibrated model has ECE = 0.
    """
    bin_edges = np.linspace(0, 1, n_bins + 1)
    ece = 0.0
    n   = len(y_true)
    for lo, hi in zip(bin_edges[:-1], bin_edges[1:]):
        mask = (y_prob >= lo) & (y_prob < hi)
        if mask.sum() == 0:
            continue
        bin_mean_prob  = y_prob[mask].mean()
        bin_mean_label = y_true[mask].mean()
        ece += (mask.sum() / n) * abs(bin_mean_prob - bin_mean_label)
    return float(ece)


# ─────────────────────────────────────────────────────────────────────────────
# Platt scaling
# ─────────────────────────────────────────────────────────────────────────────

def fit_platt(
    scores: np.ndarray,
    labels: np.ndarray,
) -> tuple[float, float]:
    """
    Fit Platt scaling: logistic regression on scalar scores.
    Returns (a, b) such that P(y=1|s) = sigmoid(a*s + b) = 1 / (1 + exp(-(a*s + b))).
    sklearn's LogisticRegression uses the sign convention: coef_[0][0]=a, intercept_[0]=b.
    """
    lr = LogisticRegression(
        solver    = "lbfgs",
        max_iter  = 1000,
        C         = 1e10,    # effectively no regularisation — Platt scaling uses full MLE
        random_state = 42,
    )
    lr.fit(scores.reshape(-1, 1), labels)
    a = float(lr.coef_[0][0])
    b = float(lr.intercept_[0])
    return a, b


def apply_platt(scores: np.ndarray, a: float, b: float) -> np.ndarray:
    """Apply Platt scaling: sigmoid(a*score + b)."""
    logit = a * scores + b
    return 1.0 / (1.0 + np.exp(-logit))


# ─────────────────────────────────────────────────────────────────────────────
# Precision-recall threshold sweep
# ─────────────────────────────────────────────────────────────────────────────

def threshold_sweep(
    y_true: np.ndarray,
    y_prob: np.ndarray,
    lo: float = 0.10,
    hi: float = 0.90,
    step: float = 0.05,
) -> list[dict]:
    """
    Sweep classification threshold and return P/R/F1 at each point.
    y_prob can be raw transformer_score OR calibrated probability.
    """
    thresholds = np.arange(lo, hi + step / 2, step)
    rows = []
    for t in thresholds:
        y_pred = (y_prob >= t).astype(int)
        rows.append({
            "threshold": round(float(t), 2),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall":    round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1":        round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "n_flagged": int(y_pred.sum()),
        })
    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    fused_path  = "data/processed/fused_scores.parquet"
    out_path    = "src/models/calibration_params.json"

    print("[*] Loading fused scores...")
    result = pd.read_parquet(fused_path)
    test   = result[result["split"] == "test"].copy()
    print(f"    Test sessions total : {len(test):,}")

    # ── 50/50 split of test set ───────────────────────────────────────────────
    rng     = np.random.default_rng(42)
    idx     = rng.permutation(len(test))
    mid     = len(idx) // 2
    cal_idx = idx[:mid]
    val_idx = idx[mid:]

    cal = test.iloc[cal_idx].copy()
    val = test.iloc[val_idx].copy()
    print(f"    Calibration subset  : {len(cal):,}")
    print(f"    Validation subset   : {len(val):,}")
    print(f"    Malicious in cal    : {cal['is_malicious'].sum()}")
    print(f"    Malicious in val    : {val['is_malicious'].sum()}")
    print()

    # ── Fit Platt scaling on calibration subset ───────────────────────────────
    cal_scores = cal["transformer_score"].values.astype(float)
    cal_labels = cal["is_malicious"].astype(int).values
    a, b = fit_platt(cal_scores, cal_labels)
    print(f"[OK] Platt scaling fitted: a={a:.4f}, b={b:.4f}")
    print()

    # ── Evaluate on validation subset ─────────────────────────────────────────
    val_scores   = val["transformer_score"].values.astype(float)
    val_labels   = val["is_malicious"].astype(int).values
    val_cal_prob = apply_platt(val_scores, a, b)

    ece_before = expected_calibration_error(val_labels, val_scores)
    ece_after  = expected_calibration_error(val_labels, val_cal_prob)
    print(f"  ECE before calibration : {ece_before:.5f}")
    print(f"  ECE after  calibration : {ece_after:.5f}")
    ece_delta = ece_before - ece_after
    if ece_delta > 0:
        print(f"  Improvement            : -{ece_delta:.5f}  ({100*ece_delta/ece_before:.1f}% reduction)")
    else:
        print(f"  Note: ECE did not improve ({ece_delta:+.5f}) — see interpretation below.")
    print()

    # ── Calibration bin analysis ───────────────────────────────────────────────
    print("  Calibration bins (val set, raw transformer_score):")
    print(f"  {'Bin':>14}  {'N':>5}  {'mean_score':>10}  {'frac_malicious':>14}")
    n_bins = 10
    for lo_b, hi_b in zip(np.linspace(0, 1, n_bins + 1)[:-1], np.linspace(0, 1, n_bins + 1)[1:]):
        mask = (val_scores >= lo_b) & (val_scores < hi_b)
        if mask.sum() == 0:
            continue
        print(f"  [{lo_b:.1f} – {hi_b:.1f}]     "
              f"{mask.sum():>5}  "
              f"{val_scores[mask].mean():>10.3f}  "
              f"{val_labels[mask].mean():>14.3f}")
    print()

    # ── Threshold sweep — raw transformer_score ───────────────────────────────
    sweep_raw = threshold_sweep(val_labels, val_scores)
    print("  PR sweep — raw transformer_score (validation):")
    print(f"  {'threshold':>9}  {'precision':>9}  {'recall':>7}  {'f1':>7}  {'flagged':>8}")
    for row in sweep_raw:
        marker = " ←" if row["f1"] == max(r["f1"] for r in sweep_raw) else ""
        print(f"  {row['threshold']:>9.2f}  {row['precision']:>9.4f}  "
              f"{row['recall']:>7.4f}  {row['f1']:>7.4f}  {row['n_flagged']:>8}{marker}")
    print()

    best_raw = max(sweep_raw, key=lambda r: r["f1"])
    print(f"  Best raw threshold   : {best_raw['threshold']:.2f}  "
          f"(F1={best_raw['f1']:.4f}, P={best_raw['precision']:.4f}, R={best_raw['recall']:.4f})")

    row_50 = next((r for r in sweep_raw if r["threshold"] == 0.50), None)
    if row_50:
        if best_raw["threshold"] == 0.50:
            print(f"  Default threshold=0.50 IS optimal (max F1={best_raw['f1']:.4f}).")
        else:
            f1_gain = best_raw["f1"] - row_50["f1"]
            print(f"  Default threshold=0.50 is NOT optimal.")
            print(f"  Optimal threshold={best_raw['threshold']:.2f} improves F1 by {f1_gain:+.4f} "
                  f"({row_50['f1']:.4f} → {best_raw['f1']:.4f}) on the validation subset.")
    print()

    # ── Threshold sweep — calibrated probability ──────────────────────────────
    sweep_cal = threshold_sweep(val_labels, val_cal_prob)
    best_cal  = max(sweep_cal, key=lambda r: r["f1"])
    print(f"  Best calibrated threshold: {best_cal['threshold']:.2f}  "
          f"(F1={best_cal['f1']:.4f}, P={best_cal['precision']:.4f}, R={best_cal['recall']:.4f})")
    print()

    # ── Save parameters ───────────────────────────────────────────────────────
    params = {
        "platt": {"a": round(a, 6), "b": round(b, 6)},
        "ece": {
            "before": round(ece_before, 6),
            "after":  round(ece_after, 6),
            "delta":  round(ece_before - ece_after, 6),
        },
        "threshold_sweep_raw": sweep_raw,
        "threshold_sweep_calibrated": sweep_cal,
        "optimal_raw_threshold": best_raw["threshold"],
        "optimal_calibrated_threshold": best_cal["threshold"],
        "default_threshold_is_optimal": bool(best_raw["threshold"] == 0.50),
        "f1_at_default_050": row_50["f1"] if row_50 else None,
        "f1_at_optimal":     best_raw["f1"],
        "calibration_note": (
            "Imbalance handling in Phase 4 = calibration + threshold selection ONLY. "
            "No retraining of the Isolation Forest or Transformer was performed. "
            "Both frozen model files (.pkl, .pt) remain read-only."
        ),
    }

    os.makedirs(os.path.dirname(out_path) if os.path.dirname(out_path) else ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(params, f, indent=2)
    print(f"[OK] Calibration params saved → {out_path}")


if __name__ == "__main__":
    main()
