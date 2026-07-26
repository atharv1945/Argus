"""
ARGUS Phase 4 — Drift Check CLI
=================================
Runs two checks:

  (A) SANITY CHECK — current test split vs. training baseline.
      Expectation: PSI < 0.10, KS p > 0.05, alert rate OK.
      Both splits come from the same synthetic distribution, so the detector
      should report NONE. If it reports MODERATE/SIGNIFICANT, the baseline
      or the test split has a structural anomaly worth investigating.

  (B) SYNTHETIC DRIFT CHECK — score-shifted population.
      We simulate a drifted distribution by shifting transformer_score by +0.25
      and fused_risk_score by +20 for all sessions, mimicking a scenario where
      all entities have become more anomalous (e.g. a security incident, a new
      pentest wave, or a model trained on stale normal behaviour).
      Expectation: PSI > 0.25, KS p < 0.05 → SIGNIFICANT.
      If NOT detected, the drift monitor itself is broken and must be fixed
      before it can be used in production.

Usage:
    python src/monitoring/run_drift_check.py

Outputs:
    Console report only. Does not overwrite drift_baseline.json.
"""

import json
import os
import sys
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
from src.monitoring.drift_monitor import (
    compute_baseline,
    check_drift,
    DriftLevel,
)

FUSED_PATH    = "data/processed/fused_scores.parquet"
BASELINE_PATH = "data/processed/drift_baseline.json"
SHIFT_RISK    = 20.0    # add this to fused_risk_score in synthetic drift
SHIFT_TF      = 0.25    # add this to transformer_score
SHIFT_IF      = 0.10    # add this to iforest_score (smaller — IF is less sensitive)


def _separator(title: str = "", width: int = 66):
    if title:
        pad = (width - len(title) - 2) // 2
        print("─" * pad + f" {title} " + "─" * pad)
    else:
        print("─" * width)


def run_sanity_check(fused_df: pd.DataFrame, baseline: dict) -> bool:
    """
    Check A: test split vs training baseline.
    Returns True if the check passes (PSI < threshold_moderate, KS not detected).
    """
    _separator("CHECK A — Sanity (test split vs train baseline)")
    test_df = fused_df[(fused_df["split"] == "test") & (~fused_df["is_malicious"]) & (fused_df.get("entity_session_idx", 3) > 2)].copy()
    print(f"  Test sessions (normal-only) : {len(test_df):,}")
    print()

    report = check_drift(test_df, baseline)
    print(report)
    print()

    passed = (
        report.psi_level == DriftLevel.NONE
        and not report.ks_transformer.drift_detected
        and not report.ks_iforest.drift_detected
        and report.alert_rate.flag == "OK"
    )
    status = "✓ PASS" if passed else "✗ FAIL — unexpected drift between train and test splits"
    print(f"  Result: {status}")
    _separator()
    return passed


def run_shifted_drift_check(fused_df: pd.DataFrame, baseline: dict) -> bool:
    """
    Check B: synthetically shifted distribution.
    Returns True if drift is correctly SIGNIFICANT (confirming the detector works).
    """
    _separator("CHECK B — Synthetic Drift (shifted scores, expect SIGNIFICANT)")
    # Use the full dataset as the "live" population, then shift it
    shifted = fused_df.copy()
    shifted["fused_risk_score"] = (shifted["fused_risk_score"] + SHIFT_RISK).clip(0, 100)
    shifted["transformer_score"] = (shifted["transformer_score"] + SHIFT_TF).clip(0, 1)
    shifted["iforest_score"] = shifted["iforest_score"] + SHIFT_IF  # can go above 1, KS handles it

    print(f"  Simulation: all scores shifted by +{SHIFT_RISK} risk / +{SHIFT_TF} transformer / +{SHIFT_IF} iforest")
    print(f"  Sessions  : {len(shifted):,}")
    print()

    report = check_drift(shifted, baseline)
    print(report)
    print()

    passed = report.drift_level == DriftLevel.SIGNIFICANT
    status = "✓ PASS" if passed else "✗ FAIL — detector did NOT flag significant drift (detector broken)"
    print(f"  Result: {status}")
    _separator()
    return passed


def main():
    _separator("ARGUS CONCEPT DRIFT CHECK")
    print()

    # ── Step 1: Load baseline (generate if missing) ───────────────────────────
    if not os.path.exists(BASELINE_PATH):
        print(f"[!] Baseline not found at {BASELINE_PATH} — generating now.")
        fused_df = pd.read_parquet(FUSED_PATH)
        train_df = fused_df[fused_df["split"] == "train"].copy()
        baseline = compute_baseline(train_df, out_path=BASELINE_PATH)
    else:
        print(f"[*] Loading baseline from {BASELINE_PATH}")
        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            baseline = json.load(f)
        fused_df = pd.read_parquet(FUSED_PATH)
        print(f"    Baseline sessions: {baseline['n_sessions']:,}")
        print(f"    Baseline alert rate: {baseline['alert_rate']:.4f}")

    print()

    # ── Step 2: Sanity check ──────────────────────────────────────────────────
    sanity_ok = run_sanity_check(fused_df, baseline)
    print()

    # ── Step 3: Synthetic drift check ─────────────────────────────────────────
    shifted_ok = run_shifted_drift_check(fused_df, baseline)
    print()

    # ── Step 4: Overall verdict ───────────────────────────────────────────────
    _separator("OVERALL")
    print(f"  Sanity check (test ≈ train)     : {'PASS' if sanity_ok else 'FAIL'}")
    print(f"  Shifted drift detection         : {'PASS' if shifted_ok else 'FAIL'}")
    print()
    if sanity_ok and shifted_ok:
        print("  ✓ Drift monitor is correctly calibrated and production-ready.")
    elif not sanity_ok:
        print("  ✗ Sanity check failed — investigate score distribution asymmetry between train/test.")
    elif not shifted_ok:
        print("  ✗ Shifted drift check failed — the detector is insensitive. Check PSI bins or KS threshold.")
    _separator()


if __name__ == "__main__":
    main()
