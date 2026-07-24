"""
ARGUS Phase 4 — Alert Deduplication Layer
==========================================
Collapses per-session alert firings into enriched case records to suppress
repeat-alert noise from sustained campaigns.

Without deduplication, a credential stuffing campaign targeting 8 entities
over 2 hours produces 52 separate Tier-1 alerts in the queue. A SOC analyst
sees 52 identical tickets. With dedup, they see one enriched case record that
says: "8 entities targeted, 52 sessions, max score 93, first seen 04:21,
last seen 06:19."

Dedup key
---------
(entity_id, predicted_attack_type, UTC date window)

The window is configurable (default 24 hours). Sessions sharing the same
entity, attack type, and falling within the same window boundary are collapsed
into one case. The first-fired session becomes the case record; all subsequent
sessions within the window are "suppressed" (stored in the case record's
suppressed_sessions list but not re-alerted).

Outputs
-------
  data/processed/alert_cases.parquet
    One row per case. Columns include:
      case_id, entity_id, predicted_attack_type, window_start, window_end,
      first_seen, last_seen, session_count, suppressed_count,
      max_fused_risk_score, tier_distribution, all_session_ids,
      suppressed_session_ids.

Usage:
    python src/fusion/alert_dedup.py [--window-hours N]
"""

import argparse
import os
import numpy as np
import pandas as pd
from collections import Counter


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

ALERT_THRESHOLD  = 50       # fused_risk_score >= this is an "alert"
DEFAULT_WINDOW_H = 24       # default dedup window in hours


# ─────────────────────────────────────────────────────────────────────────────
# Core deduplication logic
# ─────────────────────────────────────────────────────────────────────────────

def dedup_alerts(
    fused_df: pd.DataFrame,
    window_hours: int = DEFAULT_WINDOW_H,
    alert_threshold: int = ALERT_THRESHOLD,
) -> pd.DataFrame:
    """
    Collapse repeated per-session alerts into enriched case records.

    Parameters
    ----------
    fused_df       : DataFrame with fused risk scores (output of compute_fused_risk).
                     Required columns: session_id, entity_id, predicted_attack_type,
                     fused_risk_score, fusion_tier, session_start (datetime or str).
    window_hours   : Dedup window length in hours. Sessions from the same entity
                     with the same predicted_attack_type within the same window
                     are collapsed into one case.
    alert_threshold: Minimum fused_risk_score to consider a session an alert.

    Returns
    -------
    DataFrame of case records (one row per case).
    """
    # ── Filter to alerts only ──────────────────────────────────────────────────
    alerts = fused_df[fused_df["fused_risk_score"] >= alert_threshold].copy()

    if len(alerts) == 0:
        print("[!] No alerts found — returning empty case frame.")
        return pd.DataFrame()

    # ── Parse session_start ────────────────────────────────────────────────────
    if "session_start" not in alerts.columns:
        # Fall back to timestamp column if available
        if "timestamp" in alerts.columns:
            alerts = alerts.copy()
            alerts["session_start"] = pd.to_datetime(alerts["timestamp"])
        else:
            raise ValueError("fused_df must have a 'session_start' or 'timestamp' column.")

    alerts["session_start"] = pd.to_datetime(alerts["session_start"])
    alerts = alerts.sort_values(["entity_id", "predicted_attack_type", "session_start"])

    # ── Assign each alert to a window bucket ───────────────────────────────────
    # Window: floor session_start to the nearest window_hours boundary (UTC).
    window_td = pd.Timedelta(hours=window_hours)
    epoch     = pd.Timestamp("1970-01-01", tz=None)  # naive anchor
    alerts["window_start"] = (
        ((alerts["session_start"] - epoch) // window_td) * window_td + epoch
    )
    alerts["window_end"]   = alerts["window_start"] + window_td

    # ── Group by dedup key ─────────────────────────────────────────────────────
    dedup_key  = ["entity_id", "predicted_attack_type", "window_start"]
    cases = []

    for key, group in alerts.groupby(dedup_key):
        entity_id, attack_type, window_start = key
        group = group.sort_values("session_start")

        session_ids = group["session_id"].tolist()
        first_row   = group.iloc[0]
        suppressed  = session_ids[1:]  # all except first

        # Tier distribution: {tier_int: count}
        tier_dist = dict(Counter(group["fusion_tier"].astype(int).tolist()))

        case = {
            "case_id":               f"CASE_{entity_id}_{attack_type}_{window_start.date()}",
            "entity_id":             entity_id,
            "predicted_attack_type": attack_type,
            "window_start":          window_start,
            "window_end":            first_row["window_end"],
            "first_seen":            group["session_start"].min(),
            "last_seen":             group["session_start"].max(),
            "session_count":         len(session_ids),
            "suppressed_count":      len(suppressed),
            "max_fused_risk_score":  float(group["fused_risk_score"].max()),
            "mean_fused_risk_score": float(group["fused_risk_score"].mean()),
            "tier_1_count":          int(tier_dist.get(1, 0)),
            "tier_2_count":          int(tier_dist.get(2, 0)),
            "tier_3_count":          int(tier_dist.get(3, 0)),
            "all_session_ids":       session_ids,
            "suppressed_session_ids": suppressed,
            # passthrough useful fields from first-seen session
            "entity_type":           first_row.get("entity_type", ""),
            "entity_dept":           first_row.get("entity_dept", ""),
            "split":                 first_row.get("split", ""),
            "is_malicious":          bool(group["is_malicious"].any()),
            "attack_type_true":      first_row.get("attack_type", ""),
        }
        cases.append(case)

    case_df = pd.DataFrame(cases)
    return case_df


# ─────────────────────────────────────────────────────────────────────────────
# Reporting
# ─────────────────────────────────────────────────────────────────────────────

def print_dedup_report(case_df: pd.DataFrame, fused_df: pd.DataFrame, window_hours: int):
    """Print a formatted case-level dedup summary."""
    alerts = fused_df[fused_df["fused_risk_score"] >= ALERT_THRESHOLD]
    total_alert_sessions = len(alerts)
    total_cases          = len(case_df)
    suppressed           = case_df["suppressed_count"].sum()

    print("=" * 66)
    print("ALERT DEDUPLICATION REPORT")
    print("=" * 66)
    print(f"  Window length        : {window_hours}h")
    print(f"  Alert sessions total : {total_alert_sessions}")
    print(f"  Cases after dedup    : {total_cases}")
    print(f"  Suppressed sessions  : {suppressed}  "
          f"({100*suppressed/max(total_alert_sessions,1):.1f}% suppression)")
    print()

    # Per-attack-type breakdown
    print(f"  {'Attack type':<35} {'sessions':>8}  {'cases':>6}  {'dedup ratio':>11}")
    print("  " + "-" * 63)
    at_sessions = alerts.groupby("predicted_attack_type").size()
    at_cases    = case_df.groupby("predicted_attack_type").size()
    for at in sorted(at_sessions.index):
        ns = at_sessions.get(at, 0)
        nc = at_cases.get(at, 0)
        ratio = f"{ns/nc:.1f}x" if nc > 0 else "—"
        print(f"  {at:<35} {ns:>8}  {nc:>6}  {ratio:>11}")
    print()

    # Test split only
    test_cases = case_df[case_df["split"] == "test"]
    mal_cases  = test_cases[test_cases["is_malicious"]]
    norm_cases = test_cases[~test_cases["is_malicious"]]
    print(f"  Test split cases     : {len(test_cases)}")
    print(f"    Malicious cases    : {len(mal_cases)}")
    print(f"    Normal cases (FPs) : {len(norm_cases)}")
    print()

    # Case-level precision on test split
    if len(test_cases) > 0:
        case_precision = len(mal_cases) / len(test_cases) if len(test_cases) > 0 else 0
        print(f"  Case-level precision (test): {case_precision:.4f}")
        print(f"  Session-level precision had: "
              f"{alerts[alerts['split']=='test']['is_malicious'].mean():.4f}")
    print()

    # Multi-session cases (where dedup actually fired)
    multi = case_df[case_df["session_count"] > 1]
    print(f"  Multi-session cases (dedup saved ≥1 alert): {len(multi)}")
    if len(multi) > 0 and len(multi) <= 30:
        print()
        disp = multi[["case_id","predicted_attack_type","session_count",
                      "suppressed_count","max_fused_risk_score","is_malicious"]].copy()
        disp = disp.sort_values("session_count", ascending=False)
        print(disp.to_string(index=False))
    print("=" * 66)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main(window_hours: int = DEFAULT_WINDOW_H):
    fused_path  = "data/processed/fused_scores.parquet"
    sess_path   = "data/processed/session_features.parquet"
    out_path    = "data/processed/alert_cases.parquet"

    print("[*] Loading fused scores...")
    fused_df = pd.read_parquet(fused_path)

    # Merge in session_start if not already present
    if "session_start" not in fused_df.columns:
        print("[*] Merging session_start from session_features...")
        sess_df = pd.read_parquet(sess_path)
        fused_df = fused_df.merge(
            sess_df[["session_id", "session_start", "entity_type", "entity_dept"]],
            on="session_id", how="left"
        )

    print(f"[*] Running deduplication (window={window_hours}h)...")
    case_df = dedup_alerts(fused_df, window_hours=window_hours)

    # Save
    case_df.to_parquet(out_path, index=False)
    print(f"[OK] Alert cases saved → {out_path}")
    print(f"     {len(case_df):,} cases from "
          f"{(fused_df['fused_risk_score'] >= ALERT_THRESHOLD).sum():,} alert sessions")
    print()

    print_dedup_report(case_df, fused_df, window_hours)

    return case_df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARGUS Alert Deduplication")
    parser.add_argument(
        "--window-hours", type=int, default=DEFAULT_WINDOW_H,
        help=f"Dedup window length in hours (default: {DEFAULT_WINDOW_H})"
    )
    args = parser.parse_args()
    main(window_hours=args.window_hours)
