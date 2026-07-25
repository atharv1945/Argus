"""
ARGUS Phase 3 — Anomaly-First Fusion Engine
============================================
Combines three signal streams into a single fused risk score [0–100] using
an explicit priority hierarchy:

  Tier 1 (Hard Rules, score band 90–100):
      Sessions with fp_mismatch == 1 OR geo_velocity_violation == True OR
      ip_entity_fan_in >= 3 + failure_ratio >= 0.5 fire deterministic
      hard-rule triggers. These bypass model weights entirely and are
      assigned a fixed score in [90, 100].

  Tier 2 (Graph-Boosted, score band 55–89):
      Sessions where graph heuristics (lateral_hop_score > 0, new_device_edge,
      high entity_fan_out, ip_entity_fan_in) provide structural evidence of
      suspicious lateral or relational behaviour.

  Tier 3 (Model-Driven, score band 0–54):
      Sessions with no hard-rule triggers and weak graph signals.

Scoring formula
---------------
  IF score  (iforest_score): sklearn raw score. More negative = more anomalous.
                             Normalised to [0,1] by min-max over test window.
  Transformer score (transformer_score): model output probability [0,1].
                             Used directly.

  base_score = w_if * if_norm + w_tf * transformer_score
             (weights: IF=0.45, Transformer=0.55)

  graph_boost = clip(lateral_hop_score * 0.25
                     + entity_fan_out_norm * 0.15
                     + new_device_edge * 0.10
                     + ip_fan_in_norm * 0.10, 0, 0.60)

  Tier 3 fused = base_score * 54
  Tier 2 fused = clip(base_score + graph_boost, 0.55, 1.0) * 89
  Tier 1 fused = 90 + min(hard_rule_count * 3, 10)

Output columns added per session:
  - if_norm              : normalised IF anomaly score [0,1]
  - base_score           : weighted blend pre-tier [0,1]
  - graph_boost          : graph uplift applied [0,1]
  - hard_rule_fired      : int — number of hard rules triggered (0/1/2)
  - hard_rule_detail     : str — comma-separated list of triggered rules
  - fused_risk_score     : final score [0–100]
  - fusion_tier          : 1, 2, or 3
  - predicted_attack_type: rule-chain label from attack_classifier

Usage (standalone):
    python src/fusion/anomaly_first_fusion.py
"""

import json
import os
import numpy as np
import pandas as pd

from src.fusion.attack_classifier import classify_dataframe


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

W_IF = 0.45
W_TF = 0.55

GRAPH_BOOST_WEIGHTS = {
    "lateral_hop_score":  0.25,
    "entity_fan_out_norm": 0.15,
    "new_device_edge":    0.10,
    "ip_fan_in_norm":     0.10,
}

# Hard-rule thresholds
HARD_RULE_FP_MISMATCH        = 1
HARD_RULE_GEO_VEL_COL        = "geo_velocity_violation"   # bool or int
HARD_RULE_DISTINCT_COUNTRIES  = 3    # alternative geo trigger if col missing
HARD_RULE_NEW_DEV_FLAT        = 2    # Global fallback flat threshold for new_device_edge_count
                                     # Used only if entity cohort threshold cannot be looked up.
                                     # Role-aware: IT/SVC cohorts get higher thresholds (G3 fix).

# Tier band boundaries (inclusive upper)
TIER3_MAX = 54
TIER2_MAX = 89
TIER1_MIN = 90


# ─────────────────────────────────────────────────────────────────────────────
# G3: Peer-group cohort device threshold computation
# ─────────────────────────────────────────────────────────────────────────────

def compute_cohort_device_thresholds(
    train_df: pd.DataFrame,
    percentile: float = 95.0,
    min_threshold: int = 2,
    save_path: str = "data/processed/cohort_device_thresholds.json",
) -> dict:
    """
    Compute peer-group 95th-percentile of new_device_edge_count by
    (entity_type, entity_dept) from training sessions. Returns a dict
    keyed by (entity_type, entity_dept) tuples with integer threshold values.

    Why this matters (G3): A flat threshold of new_device_edge_count >= 2
    flags IT-department service accounts and IT users as suspicious simply
    because their role requires connecting to many distinct hosts. An IT
    service account's p95 of new_device_edge_count may be 8, so a count of
    2 is completely normal for that cohort. This fix prevents the
    fp_mismatch+corroborated hard rule from triggering on SVC_1115,
    U1128, U1295 and similar entities.

    Parameters
    ----------
    train_df     : Training-split sessions (must have entity_type, entity_dept,
                   new_device_edge_count, is_malicious).
    percentile   : Percentile to use as threshold (default: 95th).
    min_threshold: Floor threshold — even if p95=0, the threshold is at least
                   this value so we don't flag every entity.
    save_path    : JSON file to persist thresholds for auditability.

    Returns
    -------
    dict[(entity_type, entity_dept)] -> int threshold
    """
    if "new_device_edge_count" not in train_df.columns:
        print("    [!] new_device_edge_count not in train_df — using flat threshold everywhere")
        return {}

    # Only use normal (non-malicious) train sessions to avoid attack campaigns
    # inflating the upper tail of the device-count distribution.
    normal_train = train_df[~train_df["is_malicious"]]

    thresholds = {}
    for (etype, dept), grp in normal_train.groupby(["entity_type", "entity_dept"]):
        p95_val = grp["new_device_edge_count"].quantile(percentile / 100.0)
        # Add 1 so threshold is exclusive of the 95th percentile itself.
        # This means sessions at exactly p95 are NOT flagged — only those beyond.
        thresh = max(min_threshold, int(np.ceil(p95_val)) + 1)
        thresholds[(etype, dept)] = thresh

    # Persist for auditability
    os.makedirs(os.path.dirname(save_path) if os.path.dirname(save_path) else ".", exist_ok=True)
    serialisable = {f"{k[0]}:{k[1]}": v for k, v in thresholds.items()}
    with open(save_path, "w", encoding="utf-8") as f:
        json.dump(serialisable, f, indent=2, sort_keys=True)
    print(f"    [G3] Cohort device thresholds saved → {save_path}")
    for (etype, dept), thr in sorted(thresholds.items()):
        print(f"         {etype:15s} / {dept:12s} : new_device_edge_count >= {thr}")

    return thresholds


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _normalise_if_score(if_scores: pd.Series) -> pd.Series:
    """
    IsolationForest raw scores: higher = more normal, lower = more anomalous.
    Flip and min-max normalise to [0, 1] where 1 = most anomalous.
    """
    inverted = -if_scores  # now higher = more anomalous
    lo, hi = inverted.min(), inverted.max()
    if hi == lo:
        return pd.Series(np.zeros(len(if_scores)), index=if_scores.index)
    return (inverted - lo) / (hi - lo)


def _check_hard_rules(row: pd.Series, cohort_dev_threshold: int = 2) -> tuple:
    """
    Returns (hard_rule_count: int, hard_rule_detail: str).

    fp_mismatch corroboration rules
    --------------------------------
    fp_mismatch alone fires for legitimate device-rotating users (Campaign 4,
    133 normal FPs observed in diagnostic). Require corroboration from ANY of:
      - new_device_edge_count >= cohort_dev_threshold : brand-new devices above the
                                    peer-group 95th percentile. G3 fix: IT/SVC
                                    cohorts have higher thresholds (8-12) so their
                                    normal device rotation does not trigger this rule.
      - distinct_countries > 1      : cross-geo device jump.
      - event_count == 1            : single-event flash session typical of spoofing,
                                      credential stuffing, or impossible_travel
                                      (Campaign 4 has event_count=2).

    ip_fan_in_stuffing rule
    -----------------------
    ip_entity_fan_in >= 3 AND failure_ratio >= 0.5: many distinct entities
    failing authentication from the same IP in a 1-hour window. This is the
    primary behaviorally-correct signal for credential_stuffing, independent
    of fp_mismatch (which can be absent if the attacker spoofs the device ID
    correctly).
    """
    rules_fired = []

    fp_mm     = int(row.get("fp_mismatch", 0))
    new_dev   = int(row.get("new_device_edge_count", 0))
    countries = int(row.get("distinct_countries", 0))
    event_ct  = int(row.get("event_count", 2))

    # fp_mismatch hard-rule: corroborated if ANY of:
    #   - new_device_edge_count >= cohort_dev_threshold (peer-group normalised, G3)
    #   - distinct_countries > 1  (geo jump)
    #   - event_count == 1        (single-event flash session)
    if fp_mm >= HARD_RULE_FP_MISMATCH:
        if new_dev >= cohort_dev_threshold or countries > 1 or event_ct == 1:
            rules_fired.append("fp_mismatch+corroborated")

    # Check geo_velocity_violation (may or may not exist in merged frame)
    if HARD_RULE_GEO_VEL_COL in row.index:
        if bool(row[HARD_RULE_GEO_VEL_COL]):
            rules_fired.append("geo_velocity_violation")
    else:
        # Fallback: distinct_countries >= 3 acts as geo-anomaly proxy
        if countries >= HARD_RULE_DISTINCT_COUNTRIES:
            rules_fired.append("distinct_countries_proxy")

    # IP fan-in credential stuffing: many distinct entities from same IP + failures
    ip_fan_in  = int(row.get("ip_entity_fan_in", 0))
    fail_ratio = float(row.get("failure_ratio", 0.0))
    if ip_fan_in >= 3 and fail_ratio >= 0.5:
        rules_fired.append("ip_fan_in_stuffing")

    # Rule A — Single-entity brute force volume: high failure count & high failure ratio
    fail_cnt = int(row.get("failure_count", 0))
    if fail_cnt >= 10 and fail_ratio >= 0.80:
        rules_fired.append("brute_force_volume")

    # Rule B — Credential misuse: high risky-command ratio in sustained off-hours session
    cmd_r_ratio = float(row.get("cmd_risky_ratio", 0.0))
    cmd_len     = int(row.get("cmd_seq_length", 0))
    off_hours   = int(row.get("off_hours_flag", 0))
    if cmd_r_ratio >= 0.45 and cmd_len >= 10 and off_hours == 1:
        rules_fired.append("credential_misuse_risk")

    return len(rules_fired), ",".join(rules_fired) if rules_fired else ""



# ─────────────────────────────────────────────────────────────────────────────
# Core fusion function
# ─────────────────────────────────────────────────────────────────────────────

def compute_fused_risk(merged_df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute fused risk scores for all sessions in merged_df.

    Expected columns in merged_df:
      - session_id, entity_id, split, is_malicious, attack_type
      - iforest_score
      - transformer_score
      - fp_mismatch, off_hours_flag, failure_ratio, failure_count,
        distinct_countries, foreign_access_count, bytes_total, event_count,
        logon_count, distinct_ips, distinct_devices
      - cmd_has_escalate, cmd_has_export, cmd_has_delete
      - lateral_hop_score, new_device_edge, entity_fan_out, lateral_new_device_edges

    Returns
    -------
    DataFrame with all original columns plus fusion output columns.
    """
    df = merged_df.copy()

    # ── Step 1: Normalise IF scores ───────────────────────────────────────────
    df["if_norm"] = _normalise_if_score(df["iforest_score"])

    # ── Step 2: Base score (weighted blend) ───────────────────────────────────
    df["base_score"] = (W_IF * df["if_norm"] + W_TF * df["transformer_score"]).clip(0, 1)

    # ── Step 3: Graph boost ───────────────────────────────────────────────────
    # Normalise entity_fan_out to [0, 1] using 99th percentile cap
    fan_out_cap = df["entity_fan_out"].quantile(0.99) + 1e-6
    df["entity_fan_out_norm"] = (df["entity_fan_out"] / fan_out_cap).clip(0, 1)

    # Normalise ip_entity_fan_in to [0, 1] (cap at 99th percentile).
    # FIX: ip_entity_fan_in=1 = "only self from this IP" = no cohort signal.
    # Floor to 0 for fan_in < 2 to avoid leaking 0.0125 residual uplift onto
    # every single-entity session (which was causing 3 spurious Tier-2 FPs).
    ip_fan_cap = df["ip_entity_fan_in"].quantile(0.99) + 1e-6
    df["ip_fan_in_norm"] = ((df["ip_entity_fan_in"] >= 2).astype(float)
                            * (df["ip_entity_fan_in"] / ip_fan_cap)).clip(0, 1)

    df["graph_boost"] = (
        df["lateral_hop_score"].fillna(0)  * GRAPH_BOOST_WEIGHTS["lateral_hop_score"]
        + df["entity_fan_out_norm"]         * GRAPH_BOOST_WEIGHTS["entity_fan_out_norm"]
        + df["new_device_edge"].fillna(0)   * GRAPH_BOOST_WEIGHTS["new_device_edge"]
        + df["ip_fan_in_norm"].fillna(0)    * GRAPH_BOOST_WEIGHTS["ip_fan_in_norm"]
    ).clip(0, 0.60)

    # ── Step 4: Hard rules (G3: peer-group cohort device thresholds) ──────────
    # Compute per-cohort new_device_edge_count thresholds from training sessions.
    # This prevents IT/SVC entities from triggering fp_mismatch+corroborated solely
    # on new_device_edge_count, which is structurally high for those cohorts.
    if "split" in df.columns:
        train_mask = df["split"] == "train"
    else:
        train_mask = pd.Series([True] * len(df), index=df.index)
    cohort_thresholds = compute_cohort_device_thresholds(df[train_mask])

    # Build per-session cohort threshold lookup
    def _get_cohort_threshold(row: pd.Series) -> int:
        etype = str(row.get("entity_type", "user"))
        dept  = str(row.get("entity_dept",  "Engineering"))
        return cohort_thresholds.get((etype, dept), HARD_RULE_NEW_DEV_FLAT)

    df["_cohort_dev_thr"] = df.apply(_get_cohort_threshold, axis=1)

    hard_results = df.apply(
        lambda row: _check_hard_rules(row, cohort_dev_threshold=int(row["_cohort_dev_thr"])),
        axis=1
    )
    df.drop(columns=["_cohort_dev_thr"], inplace=True)
    df["hard_rule_fired"]  = hard_results.apply(lambda x: x[0])
    df["hard_rule_detail"] = hard_results.apply(lambda x: x[1])

    # ── Step 5: Tier assignment + final score ─────────────────────────────────
    scores = []
    tiers  = []

    for _, row in df.iterrows():
        hrf = int(row["hard_rule_fired"])

        if hrf > 0:
            # Tier 1: hard rules → fixed high band
            score = TIER1_MIN + min(hrf * 3, 10)
            tier  = 1
        else:
            boosted = float(row["base_score"]) + float(row["graph_boost"])
            if boosted >= 0.55:
                # Tier 2: graph-boosted
                score = int(min(boosted, 1.0) * TIER2_MAX)
                score = max(score, 55)       # floor at tier boundary
                tier  = 2
            else:
                # Tier 3: model-driven
                score = int(float(row["base_score"]) * TIER3_MAX)
                tier  = 3

        scores.append(score)
        tiers.append(tier)

    df["fused_risk_score"] = scores
    df["fusion_tier"]      = tiers

    # ── Step 6: Rule-based attack type label ──────────────────────────────────
    df["predicted_attack_type"] = classify_dataframe(df)

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Data loader helper
# ─────────────────────────────────────────────────────────────────────────────

def load_and_merge(
    session_path: str  = "data/processed/session_features.parquet",
    iforest_path: str  = "data/processed/iforest_scores.parquet",
    xformer_path: str  = "data/processed/transformer_scores.parquet",
    graph_path:   str  = "data/processed/graph_features.parquet",
    cohort_path:  str  = "data/processed/cohort_features.parquet",
) -> pd.DataFrame:
    """
    Load and merge all signal streams into a single per-session DataFrame.
    """
    print("[*] Loading signal streams...")
    sf  = pd.read_parquet(session_path)
    ifs = pd.read_parquet(iforest_path)[["session_id", "iforest_score"]]
    tfs = pd.read_parquet(xformer_path)[["session_id", "transformer_score"]]
    gf  = pd.read_parquet(graph_path)

    # Keep only graph-specific signal columns + session_id merge key
    # Exclude all columns already present in session_features to avoid duplication
    sf_cols_set = set(sf.columns)
    graph_only_cols = [c for c in gf.columns if c not in sf_cols_set]
    gf = gf[["session_id"] + graph_only_cols]
    # De-duplicate session_id column if somehow present twice
    gf = gf.loc[:, ~gf.columns.duplicated()]

    merged = (
        sf
        .merge(ifs, on="session_id", how="left")
        .merge(tfs, on="session_id", how="left")
        .merge(gf,  on="session_id", how="left")
    )

    # Cohort features (ip_entity_fan_in)
    if os.path.exists(cohort_path):
        cf = pd.read_parquet(cohort_path)[["session_id", "ip_entity_fan_in"]]
        merged = merged.merge(cf, on="session_id", how="left")
    else:
        print(f"    [!] Cohort features not found at {cohort_path} — defaulting to 0.")
        merged["ip_entity_fan_in"] = 0

    # Fill missing scores (sessions the Transformer skipped — event_count=1)
    # with a neutral score of 0.479 (the known constant for those sessions)
    merged["transformer_score"] = merged["transformer_score"].fillna(0.479)
    merged["iforest_score"]     = merged["iforest_score"].fillna(-0.05)

    # Fill graph features for sessions without graph data
    graph_feat_cols = [
        "new_device_edge", "new_device_edge_count", "new_resource_edge",
        "new_resource_edge_count", "entity_fan_out", "lateral_hop_score",
        "lateral_new_device_edges", "resource_fan_out_raw",
        "graph_edge_count", "resource_fan_out_dev", "entity_fan_out_norm",
        "ip_entity_fan_in", "ip_fan_in_norm",
    ]
    for col in graph_feat_cols:
        if col in merged.columns:
            merged[col] = merged[col].fillna(0)

    print(f"    Merged: {len(merged):,} sessions, {len(merged.columns)} columns")
    return merged


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    merged = load_and_merge()

    print("[*] Computing fused risk scores...")
    result = compute_fused_risk(merged)

    out_path = "data/processed/fused_scores.parquet"
    result.to_parquet(out_path, index=False)
    print(f"[OK] Saved fused scores → {out_path}")
    print(f"     Columns: {[c for c in result.columns if c in ['fused_risk_score','fusion_tier','hard_rule_fired','predicted_attack_type','base_score','graph_boost','if_norm']]}")

    # Quick peek
    test = result[result["split"] == "test"]
    print(f"\n--- Test set fused score stats ---")
    print(f"  Malicious sessions  : {test['is_malicious'].sum()}")
    print(f"  Normal sessions     : {(~test['is_malicious']).sum():,}")
    print(f"  Tier distribution   :")
    print(test["fusion_tier"].value_counts().to_string())
    print(f"\n  Mean fused score by attack_type:")
    print(test[test["attack_type"] != "none"].groupby("attack_type")["fused_risk_score"].mean().round(1).to_string())


if __name__ == "__main__":
    main()
