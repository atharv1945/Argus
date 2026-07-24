"""
ARGUS Phase 2 — Detection Core v1: Feature Engineering
=====================================================
Builds per-entity session-level features, rolling baselines, and peer-group
baselines from the raw event stream. Outputs session_features.parquet and
split_manifest.json.

Usage:
    python src/ingest/build_features.py
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import timedelta

# ─────────────────────────────────────────────────────────────────────────────
# Campaign-level train/test split manifest
# ─────────────────────────────────────────────────────────────────────────────

# Campaigns per attack type (from Phase 1 generation, seed=42, 7% ratio)
# Holding out ~1-2 latest campaigns per type for test (temporal honesty)
SPLIT_MANIFEST = {
    "split_strategy": {
        "malicious": "Campaign-level hold-out — latest 1-2 campaigns per attack_type go to test. No event-level leakage.",
        "normal": "Chronological split — events before 2026-06-14 00:00 UTC go to train, remainder to test (approx 65/35 by day count).",
        "seed": 42
    },
    "train_campaigns": {
        "brute_force": [
            "ATK_BF_20260605_005",
            "ATK_BF_20260608_004",
            "ATK_BF_20260608_006",
            "ATK_BF_20260611_002"
        ],
        "credential_misuse": [
            "ATK_CM_20260603_006",
            "ATK_CM_20260607_001",
            "ATK_CM_20260612_003",
            "ATK_CM_20260614_004"
        ],
        "device_spoofing": [
            "ATK_DS_20260606_003",
            "ATK_DS_20260615_004",
            "ATK_DS_20260616_005"
        ],
        "impossible_travel": [
            "ATK_IT_20260604_005",
            "ATK_IT_20260609_003",
            "ATK_IT_20260612_001"
        ],
        "lateral_movement": [
            "ATK_LM_20260607_002",
            "ATK_LM_20260607_005",
            "ATK_LM_20260608_001",
            "ATK_LM_20260614_003"
        ]
    },
    "test_campaigns": {
        "brute_force": [
            "ATK_BF_20260613_003",
            "ATK_BF_20260617_001"
        ],
        "credential_misuse": [
            "ATK_CM_20260615_005",
            "ATK_CM_20260616_002"
        ],
        "device_spoofing": [
            "ATK_DS_20260619_001",
            "ATK_DS_20260620_002"
        ],
        "impossible_travel": [
            "ATK_IT_20260612_004",
            "ATK_IT_20260620_002"
        ],
        "lateral_movement": [
            "ATK_LM_20260616_004",
            "ATK_LM_20260620_006"
        ]
    },
    "normal_cutoff_date": "2026-06-14T00:00:00"
}

ALL_TRAIN_CAMPAIGNS = set(
    cid for cids in SPLIT_MANIFEST["train_campaigns"].values() for cid in cids
)
ALL_TEST_CAMPAIGNS = set(
    cid for cids in SPLIT_MANIFEST["test_campaigns"].values() for cid in cids
)

# ─────────────────────────────────────────────────────────────────────────────
# Session-level feature extraction
# ─────────────────────────────────────────────────────────────────────────────

EVENT_TYPES = ["logon", "logoff", "file_access", "http", "email", "device_connect"]

def build_session_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group raw events by session_id and compute session-level features.
    Each output row = one session.
    """
    rows = []

    for sess_id, grp in df.groupby("session_id"):
        grp = grp.sort_values("timestamp")
        entity_id    = grp["entity_id"].iloc[0]
        entity_role  = grp["entity_role"].iloc[0]
        entity_dept  = grp["entity_dept"].iloc[0]
        t_start      = grp["timestamp"].min()
        t_end        = grp["timestamp"].max()
        duration_min = (t_end - t_start).total_seconds() / 60.0

        # Event-type counts
        etype_counts = grp["event_type"].value_counts()
        event_count  = len(grp)

        logon_count        = int(etype_counts.get("logon",         0))
        logoff_count       = int(etype_counts.get("logoff",        0))
        file_access_count  = int(etype_counts.get("file_access",   0))
        http_count         = int(etype_counts.get("http",          0))
        email_count        = int(etype_counts.get("email",         0))
        device_connect_cnt = int(etype_counts.get("device_connect",0))

        failure_count = int((grp["status"] == "FAILURE").sum())
        failure_ratio = failure_count / max(event_count, 1)

        # Resource diversity
        distinct_resources = grp["resource_id"].nunique()
        distinct_resource_depts = grp["resource_dept"].nunique()
        distinct_devices   = grp["device_id"].nunique()

        # Foreign resource access (resource dept != entity dept)
        foreign_access_count = int((grp["resource_dept"] != entity_dept).sum())

        # Byte volume
        bytes_total = int(grp["bytes_transferred"].sum())
        bytes_max   = int(grp["bytes_transferred"].max())
        bytes_mean  = float(grp["bytes_transferred"].mean())

        # Geo diversity
        distinct_countries = grp["geo_country"].nunique()
        distinct_ips       = grp["geo_ip"].nunique()

        # Off-hours flag: any event between 22:00 and 06:00
        hours = grp["timestamp"].dt.hour
        off_hours_flag = int(((hours >= 22) | (hours < 6)).any())

        # Labels
        is_malicious = bool(grp["is_malicious"].any())
        attack_type  = grp.loc[grp["is_malicious"], "attack_type"].values[0] if is_malicious else "none"
        attack_instance_id = grp.loc[grp["is_malicious"], "attack_instance_id"].values[0] if is_malicious else "none"

        rows.append({
            "session_id":             sess_id,
            "entity_id":              entity_id,
            "entity_role":            entity_role,
            "entity_dept":            entity_dept,
            "session_start":          t_start,
            "session_end":            t_end,
            "duration_min":           round(duration_min, 2),
            "event_count":            event_count,
            "logon_count":            logon_count,
            "logoff_count":           logoff_count,
            "file_access_count":      file_access_count,
            "http_count":             http_count,
            "email_count":            email_count,
            "device_connect_count":   device_connect_cnt,
            "failure_count":          failure_count,
            "failure_ratio":          round(failure_ratio, 4),
            "distinct_resources":     distinct_resources,
            "distinct_resource_depts":distinct_resource_depts,
            "distinct_devices":       distinct_devices,
            "foreign_access_count":   foreign_access_count,
            "bytes_total":            bytes_total,
            "bytes_max":              bytes_max,
            "bytes_mean":             round(bytes_mean, 2),
            "distinct_countries":     distinct_countries,
            "distinct_ips":           distinct_ips,
            "off_hours_flag":         off_hours_flag,
            "is_malicious":           is_malicious,
            "attack_type":            attack_type,
            "attack_instance_id":     attack_instance_id,
        })

    return pd.DataFrame(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Rolling entity-level baseline (7-day trailing window)
# ─────────────────────────────────────────────────────────────────────────────

NUMERIC_FEATURES = [
    "duration_min", "event_count", "file_access_count", "http_count",
    "email_count", "device_connect_count", "failure_ratio",
    "distinct_resources", "distinct_resource_depts", "distinct_devices",
    "foreign_access_count", "bytes_total", "bytes_max", "bytes_mean",
    "distinct_countries", "distinct_ips", "off_hours_flag",
]

def add_rolling_baseline(sf: pd.DataFrame, window_days: int = 7) -> pd.DataFrame:
    """
    For each session, compute trailing mean/std of each numeric feature
    over that entity's prior sessions within the rolling window.
    Deviation = (session_value - rolling_mean) / (rolling_std + 1e-6).
    """
    sf = sf.sort_values(["entity_id", "session_start"]).copy()
    sf["session_start"] = pd.to_datetime(sf["session_start"])

    for feat in NUMERIC_FEATURES:
        sf[f"roll_mean_{feat}"] = np.nan
        sf[f"roll_std_{feat}"]  = np.nan
        sf[f"dev_{feat}"]       = np.nan

    for entity, grp in sf.groupby("entity_id"):
        idx = grp.index.tolist()
        times = grp["session_start"].values

        for i, ridx in enumerate(idx):
            t_curr = pd.Timestamp(times[i])
            t_lo   = t_curr - timedelta(days=window_days)
            # Preceding sessions only (exclude current)
            prior_mask = (grp["session_start"] >= t_lo) & (grp["session_start"] < t_curr)
            prior = grp[prior_mask]

            if len(prior) >= 2:
                for feat in NUMERIC_FEATURES:
                    m = prior[feat].mean()
                    s = prior[feat].std()
                    v = sf.at[ridx, feat]
                    sf.at[ridx, f"roll_mean_{feat}"] = m
                    sf.at[ridx, f"roll_std_{feat}"]  = s
                    sf.at[ridx, f"dev_{feat}"]        = (v - m) / (s + 1e-6)

    return sf


# ─────────────────────────────────────────────────────────────────────────────
# Peer-group baseline (department + role aggregates over training data)
# ─────────────────────────────────────────────────────────────────────────────

def add_peer_group_baseline(sf: pd.DataFrame, train_mask: pd.Series) -> pd.DataFrame:
    """
    Compute dept-level mean/std from training sessions only, then attach
    as peer_mean_*/peer_std_* and peer_dev_* to all sessions.
    """
    train_sf = sf[train_mask & ~sf["is_malicious"]]

    peer_stats = train_sf.groupby("entity_dept")[NUMERIC_FEATURES].agg(["mean", "std"])
    peer_stats.columns = [f"{agg}_{feat}" for feat, agg in peer_stats.columns]

    for feat in NUMERIC_FEATURES:
        sf[f"peer_mean_{feat}"] = sf["entity_dept"].map(
            peer_stats.get(f"mean_{feat}", pd.Series(dtype=float))
        )
        sf[f"peer_std_{feat}"]  = sf["entity_dept"].map(
            peer_stats.get(f"std_{feat}", pd.Series(dtype=float))
        )
        sf[f"peer_dev_{feat}"]  = (
            (sf[feat] - sf[f"peer_mean_{feat}"]) /
            (sf[f"peer_std_{feat}"].fillna(1e-6) + 1e-6)
        )

    return sf


# ─────────────────────────────────────────────────────────────────────────────
# Split assignment
# ─────────────────────────────────────────────────────────────────────────────

def assign_split(sf: pd.DataFrame) -> pd.DataFrame:
    cutoff = pd.Timestamp(SPLIT_MANIFEST["normal_cutoff_date"])

    def _split(row):
        if row["is_malicious"]:
            aid = row["attack_instance_id"]
            if aid in ALL_TRAIN_CAMPAIGNS:
                return "train"
            elif aid in ALL_TEST_CAMPAIGNS:
                return "test"
            else:
                return "unknown"
        else:
            return "train" if row["session_start"] < cutoff else "test"

    sf["split"] = sf.apply(_split, axis=1)
    return sf


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("[*] Loading raw event stream...")
    df = pd.read_parquet("data/processed/full_dataset.parquet")
    print(f"    {len(df):,} events, {df['session_id'].nunique():,} unique sessions.")

    print("[*] Building session-level features...")
    sf = build_session_features(df)
    print(f"    {len(sf):,} sessions extracted.")

    print("[*] Assigning train/test splits...")
    sf = assign_split(sf)
    print(f"    Train sessions: {(sf['split']=='train').sum():,} | Test sessions: {(sf['split']=='test').sum():,}")

    train_mask = sf["split"] == "train"

    print("[*] Computing rolling entity baselines (7-day window)...")
    sf = add_rolling_baseline(sf, window_days=7)
    print("    Rolling baseline columns added.")

    print("[*] Computing peer-group (dept-level) baselines...")
    sf = add_peer_group_baseline(sf, train_mask)
    print("    Peer-group baseline columns added.")

    # Save
    os.makedirs("data/processed", exist_ok=True)
    out_path = "data/processed/session_features.parquet"
    sf.to_parquet(out_path, index=False)
    print(f"[OK] Saved {len(sf):,} session feature rows to {out_path}.")
    print(f"     Total columns: {len(sf.columns)}")

    # Save split manifest
    manifest_path = "data/processed/split_manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(SPLIT_MANIFEST, f, indent=2)
    print(f"[OK] Saved split manifest to {manifest_path}.")

    # Quick class balance report
    test_df = sf[sf["split"] == "test"]
    print(f"\n--- Test Split Class Balance ---")
    print(f"  Total test sessions : {len(test_df):,}")
    print(f"  Malicious test      : {test_df['is_malicious'].sum()}")
    print(f"  Normal test         : {(~test_df['is_malicious']).sum():,}")
    print(f"\n  Malicious test breakdown:")
    print(test_df[test_df["is_malicious"]].groupby("attack_type")["attack_instance_id"].nunique().to_string())


if __name__ == "__main__":
    main()
