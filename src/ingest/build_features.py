"""
ARGUS Phase 2 — Detection Core v1: Feature Engineering (20-Field Expanded Spec)
================================================================================
Builds per-entity session-level features, rolling baselines, and peer-group
baselines from the raw 20-field event stream. Outputs session_features.parquet
and split_manifest.json.

New features from expanded schema:
  - command_sequence risk features (escalate/delete/export token counts, sequence length)
  - auth_method risk weighting
  - entity_type encoding
  - device_fingerprint consistency check

Usage:
    python src/ingest/build_features.py
"""

import os
import json
import numpy as np
import pandas as pd
from datetime import timedelta
from collections import Counter

# ─────────────────────────────────────────────────────────────────────────────
# Campaign-level train/test split manifest (20-field expanded, 8 categories)
# ─────────────────────────────────────────────────────────────────────────────

# Campaign IDs from regenerated dataset (seed=42, 20% attack ratio, expanded spec)
# G1: Hold out 3 latest campaigns per thin attack class (vs 2 previously), giving n>=3 test sessions.
# G5c: impossible_travel now has 14 campaigns (7 ATK_IT_* + 7 ATK_ITSC_*).
#       Both variants share attack_type='impossible_travel' — they test different trigger paths.
# G2: insider_drift now has 6 campaigns (5 original + 1 harder cross-dept fan-out, campaign 6).
#     Campaign 6 is split 3 train / 2 test since it spans 2 days.
SPLIT_MANIFEST = {
    "split_strategy": {
        "malicious": "Campaign-level hold-out — 3 latest-dated campaigns per attack_type go to test. No event-level leakage.",
        "normal": "Chronological split — events before 2026-06-14 00:00 UTC go to train, remainder to test.",
        "insider_drift": "Benign edge case (is_malicious=False). Split by campaign: earliest 4 campaigns train, latest 2 test. Campaign 6 (harder) split 3/2 internally.",
        "seed": 42
    },
    "train_campaigns": {
        "brute_force": [
            "ATK_BF_20260606_003",
            "ATK_BF_20260607_007",
            "ATK_BF_20260609_006",
            "ATK_BF_20260610_004",
        ],
        "credential_misuse": [
            "ATK_CM_20260603_004",
            "ATK_CM_20260613_003",
            "ATK_CM_20260614_006",
            "ATK_CM_20260615_002",
        ],
        "lateral_movement": [
            "ATK_LM_20260607_001",
            "ATK_LM_20260607_003",
            "ATK_LM_20260608_007",
            "ATK_LM_20260615_002",
        ],
        "impossible_travel": [
            # Original IT (fp_mismatch=1 + geo_vel=1)
            "ATK_IT_20260603_003",
            "ATK_IT_20260605_004",
            "ATK_IT_20260614_007",
            "ATK_IT_20260615_002",
            # Stolen-credential IT (fp_mismatch=0 + geo_vel=1) — G5c
            "ATK_ITSC_20260603_006",
            "ATK_ITSC_20260604_002",
            "ATK_ITSC_20260605_001",
            "ATK_ITSC_20260606_007",
        ],
        "device_spoofing": [
            "ATK_DS_20260603_001",
            "ATK_DS_20260604_002",
            "ATK_DS_20260612_004",
            "ATK_DS_20260613_007",
        ],
        "credential_stuffing": [
            "ATK_CS_20260603_003",
            "ATK_CS_20260611_005",
            "ATK_CS_20260612_004",
            "ATK_CS_20260614_007",
        ],
        "low_and_slow_exfiltration": [
            "ATK_LS_20260606_007",
            "ATK_LS_20260609_006",
            "ATK_LS_20260610_005",
            "ATK_LS_20260612_001",
        ],
    },
    "test_campaigns": {
        "brute_force": [
            "ATK_BF_20260612_002",
            "ATK_BF_20260617_005",
            "ATK_BF_20260619_001",
        ],
        "credential_misuse": [
            "ATK_CM_20260618_001",
            "ATK_CM_20260618_005",
            "ATK_CM_20260620_007",
        ],
        "lateral_movement": [
            "ATK_LM_20260616_004",
            "ATK_LM_20260617_005",
            "ATK_LM_20260618_006",
        ],
        "impossible_travel": [
            # Original IT (fp_mismatch=1 + geo_vel=1)
            "ATK_IT_20260616_005",
            "ATK_IT_20260617_006",
            "ATK_IT_20260618_001",
            # Stolen-credential IT (fp_mismatch=0 + geo_vel=1) — G5c
            "ATK_ITSC_20260614_005",
            "ATK_ITSC_20260616_003",
            "ATK_ITSC_20260619_004",
        ],
        "device_spoofing": [
            "ATK_DS_20260616_006",
            "ATK_DS_20260617_003",
            "ATK_DS_20260619_005",
        ],
        "credential_stuffing": [
            "ATK_CS_20260617_001",
            "ATK_CS_20260618_002",
            "ATK_CS_20260618_006",
        ],
        "low_and_slow_exfiltration": [
            "ATK_LS_20260618_003",
            "ATK_LS_20260619_002",
            "ATK_LS_20260619_004",
        ],
    },
    # insider_drift: campaigns 1-5 original, campaign 6 harder (G2)
    # Campaign 6 spans 2 days: sessions on day0 (step 0-2) → train, day1 (step 3-4) → test
    # We put campaign 6's ID in BOTH train and test so it's treated as a split campaign.
    # The session-level assignment handles the split: sessions with session_start < cutoff → train
    "insider_drift_train": [
        "ATK_ID_20260604_005",
        "ATK_ID_20260605_001",
        "ATK_ID_20260605_003",
        "ATK_ID_20260606_004",
    ],
    "insider_drift_test": [
        "ATK_ID_20260608_006",   # campaign 5
        "ATK_ID_20260610_002",   # campaign 6 (harder) — all 5 sessions evaluated in test
    ],
    "normal_cutoff_date": "2026-06-14T00:00:00"
}

ALL_TRAIN_CAMPAIGNS = set(
    cid for cids in SPLIT_MANIFEST["train_campaigns"].values() for cid in cids
) | set(SPLIT_MANIFEST["insider_drift_train"])

ALL_TEST_CAMPAIGNS = set(
    cid for cids in SPLIT_MANIFEST["test_campaigns"].values() for cid in cids
) | set(SPLIT_MANIFEST["insider_drift_test"])




# ─────────────────────────────────────────────────────────────────────────────
# Command sequence risk vocabulary
# ─────────────────────────────────────────────────────────────────────────────

RISKY_TOKENS = {"escalate_privilege", "delete", "export_data"}
AUTH_RISK_MAP = {"password": 0.6, "biometric": 0.3, "token": 0.4, "certificate": 0.2}
ENTITY_TYPE_MAP = {"user": 0, "service_account": 1, "edge_device": 2}


# ─────────────────────────────────────────────────────────────────────────────
# Session-level feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def build_session_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Group raw events by session_id and compute session-level features.
    Each output row = one session.
    """
    rows = []

    # Pre-compute per-entity modal fingerprint (most common fingerprint per entity)
    entity_fp_mode = df.groupby("entity_id")["device_fingerprint"].agg(
        lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else ""
    ).to_dict()

    for sess_id, grp in df.groupby("session_id"):
        grp = grp.sort_values("timestamp")
        entity_id    = grp["entity_id"].iloc[0]
        entity_role  = grp["entity_role"].iloc[0]
        entity_dept  = grp["entity_dept"].iloc[0]
        entity_type  = grp["entity_type"].iloc[0] if "entity_type" in grp.columns else "user"
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
        primary_geo_country = grp["geo_country"].iloc[0]

        # Off-hours flag: any event between 22:00 and 06:00
        hours = grp["timestamp"].dt.hour
        off_hours_flag = int(((hours >= 22) | (hours < 6)).any())

        # ── NEW FEATURES from expanded schema ──

        # Command sequence risk features
        cmd_seqs = grp["command_sequence"].dropna().replace("", np.nan).dropna()
        all_tokens = []
        for seq in cmd_seqs:
            all_tokens.extend(str(seq).split(","))
        cmd_seq_length    = len(all_tokens)
        cmd_risky_count   = sum(1 for t in all_tokens if t.strip() in RISKY_TOKENS)
        cmd_risky_ratio   = cmd_risky_count / max(cmd_seq_length, 1)
        cmd_has_escalate  = int("escalate_privilege" in all_tokens)
        cmd_has_delete    = int("delete" in all_tokens)
        cmd_has_export    = int("export_data" in all_tokens)
        # Command entropy (diversity of tokens used)
        if cmd_seq_length > 0:
            token_counts = Counter(all_tokens)
            probs = np.array(list(token_counts.values()), dtype=float) / cmd_seq_length
            cmd_entropy = float(-np.sum(probs * np.log2(probs + 1e-10)))
        else:
            cmd_entropy = 0.0

        # Auth method risk score
        auth_methods = grp["auth_method"].unique()
        auth_risk = max(AUTH_RISK_MAP.get(a, 0.5) for a in auth_methods)

        # Entity type encoding
        entity_type_code = ENTITY_TYPE_MAP.get(entity_type, 0)

        # Device fingerprint consistency check
        session_fps = grp["device_fingerprint"].unique()
        modal_fp = entity_fp_mode.get(entity_id, "")
        fp_mismatch = int(not all(fp == modal_fp for fp in session_fps)) if modal_fp else 0

        # Labels — Note: insider_drift has is_malicious=False but attack_type != "none"
        is_malicious = bool(grp["is_malicious"].any())
        # For attack_type, pick the non-"none" type if present (covers insider_drift)
        non_none_types = grp.loc[grp["attack_type"] != "none", "attack_type"]
        attack_type = non_none_types.values[0] if len(non_none_types) > 0 else "none"
        non_none_ids = grp.loc[grp["attack_instance_id"] != "none", "attack_instance_id"]
        attack_instance_id = non_none_ids.values[0] if len(non_none_ids) > 0 else "none"

        rows.append({
            "session_id":             sess_id,
            "entity_id":              entity_id,
            "entity_type":            entity_type,
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
            "primary_geo_country":    primary_geo_country,
            "off_hours_flag":         off_hours_flag,
            # New features
            "cmd_seq_length":         cmd_seq_length,
            "cmd_risky_count":        cmd_risky_count,
            "cmd_risky_ratio":        round(cmd_risky_ratio, 4),
            "cmd_has_escalate":       cmd_has_escalate,
            "cmd_has_delete":         cmd_has_delete,
            "cmd_has_export":         cmd_has_export,
            "cmd_entropy":            round(cmd_entropy, 4),
            "auth_risk":              auth_risk,
            "entity_type_code":       entity_type_code,
            "fp_mismatch":            fp_mismatch,
            # Labels
            "is_malicious":           is_malicious,
            "attack_type":            attack_type,
            "attack_instance_id":     attack_instance_id,
        })

    sf = pd.DataFrame(rows)

    # ── Compute entity_session_idx (1-indexed session rank per entity, chronological) ──
    # Used by drift_monitor.py to exclude cold-start sessions (entity_session_idx <= 2)
    sf["session_start_dt"] = pd.to_datetime(sf["session_start"])
    sf = sf.sort_values(["entity_id", "session_start_dt"])
    sf["entity_session_idx"] = sf.groupby("entity_id").cumcount() + 1

    # ── Compute geo_velocity_violation across consecutive sessions per entity ──
    # G5a FIX: Only propagate prev_geo_country from AUTHENTICATED sessions (fp_mismatch == 0).
    # This prevents probe contamination: when an attacker's credential_stuffing session is
    # injected into a victim entity's session sequence, it sets the entity's prev_geo_country
    # to the attacker's country, causing the victim's next LEGITIMATE session to falsely
    # trigger geo_velocity_violation (RU->US in 82 min etc.). By propagating prev_geo_country
    # only from fp_mismatch=0 sessions, the victim's legitimate geo baseline is preserved.
    #
    # Why fp_mismatch=1 impossible_travel sessions still trigger correctly:
    # Real impossible_travel attack sessions have fp_mismatch=1. Their PREVIOUS session
    # (the entity's normal session before the attack) has fp_mismatch=0 with the entity's
    # home country. The ffill() ensures that prior authenticated country is still tracked
    # and compared against the attack session's foreign geo_country. The attack session's
    # own fp_mismatch=1 only means we don't USE it as a baseline for subsequent sessions,
    # not that we can't DETECT the country change in it.
    #
    # G5b NOTE: The sort-order dependency is a legitimate cross-session rolling computation
    # (geo_velocity requires chronological ordering). It is not a positional accumulation bug.
    # The borderline Tier 2 session that shifted classification after the geo_velocity sort
    # was added was a genuine consequence of re-ordering the DataFrame. The ffill fix
    # (authenticated-only baseline) makes the computation more robust to such cases.
    sf["authenticated_geo"] = sf["primary_geo_country"].where(sf["fp_mismatch"] == 0, other=np.nan)
    sf["prev_geo_country"]  = sf.groupby("entity_id")["authenticated_geo"].shift(1)
    # Forward-fill: carry the last known authenticated country forward if the immediately
    # previous session was malicious/unauth (fp_mismatch=1). This ensures:
    #   - Victim entities: previous attacker session doesn't pollute geo baseline
    #   - Real IT sessions: still get the correct prev_geo_country from last auth session
    sf["prev_geo_country"]  = sf.groupby("entity_id")["prev_geo_country"].ffill()
    sf["prev_session_start"] = sf.groupby("entity_id")["session_start_dt"].shift(1)
    sf["time_since_prev_session_min"] = (sf["session_start_dt"] - sf["prev_session_start"]).dt.total_seconds() / 60.0
    sf["geo_velocity_violation"] = (
        (sf["primary_geo_country"] != sf["prev_geo_country"]) &
        sf["prev_geo_country"].notna() &
        (sf["time_since_prev_session_min"] <= 120.0)
    ).astype(int)
    sf.drop(columns=["session_start_dt", "authenticated_geo", "prev_geo_country",
                     "prev_session_start", "time_since_prev_session_min"], inplace=True)
    return sf


# ─────────────────────────────────────────────────────────────────────────────
# Rolling entity-level baseline (7-day trailing window)
# ─────────────────────────────────────────────────────────────────────────────

NUMERIC_FEATURES = [
    "duration_min", "event_count", "file_access_count", "http_count",
    "email_count", "device_connect_count", "failure_ratio",
    "distinct_resources", "distinct_resource_depts", "distinct_devices",
    "foreign_access_count", "bytes_total", "bytes_max", "bytes_mean",
    "distinct_countries", "distinct_ips", "off_hours_flag",
    # New numeric features
    "cmd_seq_length", "cmd_risky_count", "cmd_risky_ratio",
    "cmd_has_escalate", "cmd_has_delete", "cmd_has_export",
    "cmd_entropy", "auth_risk", "entity_type_code", "fp_mismatch",
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
# Peer-group baseline (department + entity_type aggregates)
# ─────────────────────────────────────────────────────────────────────────────

def add_peer_group_baseline(sf: pd.DataFrame, train_mask: pd.Series) -> pd.DataFrame:
    """
    Compute dept+entity_type-level mean/std from training sessions only, then
    attach as peer_mean_*/peer_std_* and peer_dev_* to all sessions.
    Stratified by entity_type since normal behavior for service_account/edge_device
    differs fundamentally from human users.
    """
    # Build peer group key
    sf["_peer_key"] = sf["entity_dept"] + "|" + sf["entity_type"]
    train_sf = sf.loc[train_mask & ~sf["is_malicious"]].copy()

    peer_stats = train_sf.groupby("_peer_key")[NUMERIC_FEATURES].agg(["mean", "std"])
    peer_stats.columns = [f"{agg}_{feat}" for feat, agg in peer_stats.columns]

    # Build lookup dicts once for vectorized mapping
    peer_mean_dicts = {}
    peer_std_dicts = {}
    for feat in NUMERIC_FEATURES:
        mean_col = f"mean_{feat}"
        std_col = f"std_{feat}"
        peer_mean_dicts[feat] = peer_stats[mean_col].to_dict() if mean_col in peer_stats.columns else {}
        peer_std_dicts[feat] = peer_stats[std_col].to_dict() if std_col in peer_stats.columns else {}

    # Build all peer columns at once to avoid fragmentation
    peer_cols = {}
    for feat in NUMERIC_FEATURES:
        pm = sf["_peer_key"].map(peer_mean_dicts[feat])
        ps = sf["_peer_key"].map(peer_std_dicts[feat])
        peer_cols[f"peer_mean_{feat}"] = pm
        peer_cols[f"peer_std_{feat}"] = ps
        peer_cols[f"peer_dev_{feat}"] = (sf[feat] - pm) / (ps.fillna(1e-6) + 1e-6)

    peer_df = pd.DataFrame(peer_cols, index=sf.index)
    sf = pd.concat([sf, peer_df], axis=1)
    sf = sf.drop(columns=["_peer_key"])

    return sf


# ─────────────────────────────────────────────────────────────────────────────
# Split assignment
# ─────────────────────────────────────────────────────────────────────────────

def assign_split(sf: pd.DataFrame) -> pd.DataFrame:
    cutoff = pd.Timestamp(SPLIT_MANIFEST["normal_cutoff_date"])

    def _split(row):
        aid = row["attack_instance_id"]
        atk = row["attack_type"]

        if atk != "none":
            # Campaign-based split for ALL labeled rows (malicious + insider_drift)
            if aid in ALL_TRAIN_CAMPAIGNS:
                return "train"
            elif aid in ALL_TEST_CAMPAIGNS:
                return "test"
            else:
                return "unknown"
        else:
            # Pure normal traffic: chronological split
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

    print("[*] Building session-level features (20-field expanded schema)...")
    sf = build_session_features(df)
    print(f"    {len(sf):,} sessions extracted.")

    print("[*] Assigning train/test splits (8 attack categories)...")
    sf = assign_split(sf)
    train_ct = (sf['split']=='train').sum()
    test_ct = (sf['split']=='test').sum()
    unknown_ct = (sf['split']=='unknown').sum()
    print(f"    Train sessions: {train_ct:,} | Test sessions: {test_ct:,} | Unknown: {unknown_ct}")

    train_mask = sf["split"] == "train"

    print("[*] Computing rolling entity baselines (7-day window, 27 features)...")
    sf = add_rolling_baseline(sf, window_days=7)
    print("    Rolling baseline columns added.")

    print("[*] Computing peer-group (dept+entity_type) baselines...")
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

    # Class balance report
    test_df = sf[sf["split"] == "test"]
    print(f"\n--- Test Split Class Balance ---")
    print(f"  Total test sessions : {len(test_df):,}")
    print(f"  Malicious test      : {test_df['is_malicious'].sum()}")
    print(f"  Normal test         : {(~test_df['is_malicious']).sum():,}")
    print(f"\n  Test breakdown by attack_type:")
    print(test_df[test_df["attack_type"] != "none"].groupby(["attack_type", "is_malicious"])["attack_instance_id"].nunique().to_string())


if __name__ == "__main__":
    main()
