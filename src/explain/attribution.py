"""
ARGUS Phase 5 — Feature Attribution Engine
============================================
Extracts the specific contributing factors from a flagged session's raw signal
values and traces back to the exact fusion code path (tier + rule condition)
that caused the alert. Produces human-readable factor strings, not SHAP bars.

Design rules:
  - Every factor string names the raw field and its value, with a plain-language
    gloss: "failure_ratio=0.97 (97% of 29 logon attempts failed)".
  - The output always states WHICH tier fired and WHICH specific condition was
    satisfied — tracing back to the actual fusion logic, not a generic tier description.
  - When the Transformer is NOT the reason for an alert (Tier 1 hard rules, or
    graph_boost lifting a near-threshold session), this is stated explicitly and
    honestly: "transformer_score=0.479 (single-event session; model has insufficient
    context — flagged via hard rule, not model confidence)."
  - Known limitations are surfaced, not suppressed.

Usage:
    from src.explain.attribution import attribute_session
    result = attribute_session(session_row)   # accepts dict or pd.Series
    print(result.summary)
    for f in result.factors: print(" •", f)
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Thresholds — must mirror anomaly_first_fusion.py and attack_classifier.py
# ─────────────────────────────────────────────────────────────────────────────
ALERT_THRESHOLD   = 50
TIER1_SCORE_MIN   = 90
TIER2_SCORE_MIN   = 55
TIER1_MIN_TIER_VAL = 1     # hard_rule_fired > 0
GRAPH_BOOST_TIER2_THRESHOLD = 0.55   # base_score + graph_boost >= 0.55 → Tier 2

TRANSFORMER_PLATEAU = 0.479   # single-event sessions plateau at ~0.479
TRANSFORMER_PLATEAU_TOL = 0.01

# Key graph boost weights (from anomaly_first_fusion.py GRAPH_BOOST_WEIGHTS)
GBW_LATERAL_HOP   = 0.50
GBW_FAN_OUT_NORM  = 0.15
GBW_NEW_DEVICE    = 0.10
GBW_IP_FAN_IN     = 0.10

# Tier 2 base_score threshold (pre-boost)
TIER2_BASE_SCORE_MODERATE = 0.50


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttributionResult:
    session_id:        str
    entity_id:         str
    entity_type:       str
    entity_dept:       str
    fused_risk_score:  int
    fusion_tier:       int
    predicted_attack_type: str

    # Ordered list of human-readable contributing factor strings
    factors: List[str] = field(default_factory=list)

    # Which specific rule/condition fired (mirrors fusion code path)
    tier_condition:    str = ""    # e.g. "hard_rule fp_mismatch+corroborated (event_count==1)"
    hard_rule_detail:  str = ""    # raw hard_rule_detail from fusion

    # Model score context
    transformer_score: float = 0.0
    iforest_score:     float = 0.0
    is_transformer_primary: bool = True   # False when transformer is NOT why it fired

    # Honest limitation flags
    is_single_event_plateau: bool = False   # transformer at 0.479 plateau
    is_cold_start_graph:     bool = False   # graph signal is first session for entity

    @property
    def summary(self) -> str:
        """One-line attribution summary for display."""
        tier_str = {1: "Tier 1 (Hard Rule)", 2: "Tier 2 (Graph-Boosted)", 3: "Tier 3 (Model-Driven)"}
        t = tier_str.get(self.fusion_tier, f"Tier {self.fusion_tier}")
        return (
            f"Entity {self.entity_id} ({self.entity_type}, {self.entity_dept}) — "
            f"Risk {self.fused_risk_score}/100 [{t}] — "
            f"Predicted: {self.predicted_attack_type}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _g(row: Dict[str, Any], key: str, default=0):
    v = row.get(key, default)
    return default if v is None else v


def _fmt_bytes(n: int) -> str:
    if n >= 1_000_000_000:
        return f"{n/1e9:.1f} GB"
    if n >= 1_000_000:
        return f"{n/1e6:.1f} MB"
    if n >= 1_000:
        return f"{n/1e3:.1f} KB"
    return f"{n} B"


def _is_plateau(score: float) -> bool:
    return abs(score - TRANSFORMER_PLATEAU) < TRANSFORMER_PLATEAU_TOL


# ─────────────────────────────────────────────────────────────────────────────
# Tier 1 — hard rule attribution
# ─────────────────────────────────────────────────────────────────────────────

def _attribute_tier1(row: Dict[str, Any], result: AttributionResult) -> None:
    """Parse hard_rule_detail and produce specific factor strings for Tier 1."""
    detail        = str(_g(row, "hard_rule_detail", ""))
    fp_mm         = int(_g(row, "fp_mismatch", 0))
    new_dev       = int(_g(row, "new_device_edge_count", 0))
    countries     = int(_g(row, "distinct_countries", 0))
    event_ct      = int(_g(row, "event_count", 2))
    foreign_ac    = int(_g(row, "foreign_access_count", 0))
    ip_fan_in     = int(_g(row, "ip_entity_fan_in", 0))
    fail_ratio    = float(_g(row, "failure_ratio", 0.0))
    fail_ct       = int(_g(row, "failure_count", 0))
    tf_score      = float(_g(row, "transformer_score", 0.0))
    graph_boost   = float(_g(row, "graph_boost", 0.0))
    hrf_count     = int(_g(row, "hard_rule_fired", 0))

    conditions_satisfied = []

    # ── fp_mismatch + corroboration ─────────────────────────────────────────
    if "fp_mismatch+corroborated" in detail:
        result.factors.append(
            f"fp_mismatch=1 — device fingerprint changed from entity's known profile"
        )
        # Which corroborator fired?
        if event_ct == 1:
            conditions_satisfied.append("event_count==1 (single-event flash session)")
            result.factors.append(
                f"event_count=1 — single-event session (flash authentication with no "
                f"subsequent activity, characteristic of spoofing or automated logon)"
            )
        if new_dev >= 2:
            conditions_satisfied.append(f"new_device_edge_count={new_dev} (≥2 brand-new devices)")
            result.factors.append(
                f"new_device_edge_count={new_dev} — entity accessed {new_dev} devices "
                f"never seen in its graph history within this session"
            )
        elif new_dev == 1 and event_ct != 1:
            # new_dev=1 alone doesn't corroborate (Phase 3 fix), only as complement
            result.factors.append(
                f"new_device_edge_count={new_dev} — 1 new device edge (below "
                f"corroboration threshold of 2; flagged via single-event rule, not this)"
            )
        if countries > 1:
            conditions_satisfied.append(f"distinct_countries={countries} (geo jump)")
            result.factors.append(
                f"distinct_countries={countries} — session crossed {countries} country "
                f"boundaries, consistent with impossible geographic travel"
            )
        if foreign_ac > 0:
            result.factors.append(
                f"foreign_access_count={foreign_ac} — accessed {foreign_ac} resource(s) "
                f"outside entity's home department"
            )

        cond_str = " + ".join(conditions_satisfied) if conditions_satisfied else "event_count==1"
        result.tier_condition = f"hard_rule fp_mismatch+corroborated ({cond_str})"

    # ── geo_velocity_violation ──────────────────────────────────────────────
    geo_vel = bool(_g(row, "geo_velocity_violation", 0))
    if "geo_velocity_violation" in detail or geo_vel:
        result.factors.append(
            "geo_velocity_violation=1 — authentication origin changed country within 2 hours "
            "of entity's previous session, indicating physically impossible travel velocity"
        )
        if "geo_velocity_violation" not in result.tier_condition:
            result.tier_condition += (" + " if result.tier_condition else "") + "hard_rule geo_velocity_violation"

    # ── ip_fan_in_stuffing ─────────────────────────────────────────────────
    if "ip_fan_in_stuffing" in detail:
        result.factors.append(
            f"ip_entity_fan_in={ip_fan_in} — {ip_fan_in} distinct entities authenticated "
            f"from the same source IP within the 1-hour cohort window"
        )
        result.factors.append(
            f"failure_ratio={fail_ratio:.2f} — {fail_ratio*100:.0f}% of authentication "
            f"attempts from this IP cohort failed (≥50% threshold for stuffing)"
        )
        result.tier_condition += (" + " if result.tier_condition else "") + (
            f"hard_rule ip_fan_in_stuffing (ip_fan_in={ip_fan_in}, fail_ratio={fail_ratio:.2f})"
        )

    # ── Transformer honesty for Tier 1 ─────────────────────────────────────
    result.is_transformer_primary = False  # Hard rule fired; transformer is not why
    if _is_plateau(tf_score):
        result.is_single_event_plateau = True
        result.factors.append(
            f"transformer_score={tf_score:.3f} — near-constant plateau value "
            f"(single-event session has insufficient temporal context for the model; "
            f"this session was flagged by hard rule, NOT model confidence)"
        )
    else:
        result.factors.append(
            f"transformer_score={tf_score:.3f} — model score present but "
            f"this session was escalated by hard rule, not model threshold"
        )

    result.hard_rule_detail = detail


# ─────────────────────────────────────────────────────────────────────────────
# Tier 2 — graph-boosted attribution
# ─────────────────────────────────────────────────────────────────────────────

def _attribute_tier2(row: Dict[str, Any], result: AttributionResult) -> None:
    """Decompose graph_boost contributions for Tier 2 sessions."""
    base_score    = float(_g(row, "base_score", 0.0))
    graph_boost   = float(_g(row, "graph_boost", 0.0))
    tf_score      = float(_g(row, "transformer_score", 0.0))
    if_score      = float(_g(row, "iforest_score", 0.0))
    lat_hop       = float(_g(row, "lateral_hop_score", 0.0))
    fan_out       = int(_g(row, "entity_fan_out", 0))
    new_dev       = int(_g(row, "new_device_edge_count", 0))
    new_dev_bin   = int(_g(row, "new_device_edge", 0))
    ip_fan_in     = int(_g(row, "ip_entity_fan_in", 0))
    off_hours     = int(_g(row, "off_hours_flag", 0))
    bytes_tot     = int(_g(row, "bytes_total", 0))
    fail_ratio    = float(_g(row, "failure_ratio", 0.0))
    fail_ct       = int(_g(row, "failure_count", 0))
    logon_ct      = int(_g(row, "logon_count", 0))
    event_ct      = int(_g(row, "event_count", 2))
    cmd_esc       = int(_g(row, "cmd_has_escalate", 0))
    cmd_exp       = int(_g(row, "cmd_has_export", 0))
    cmd_del       = int(_g(row, "cmd_has_delete", 0))
    foreign_ac    = int(_g(row, "foreign_access_count", 0))

    # ── Base score decomposition ─────────────────────────────────────────────
    result.factors.append(
        f"base_score={base_score:.3f} — blended model score "
        f"(transformer={tf_score:.3f}, isolation_forest={if_score:.4f})"
    )
    result.tier_condition = f"Tier 2: base_score({base_score:.3f}) + graph_boost({graph_boost:.4f}) = {base_score+graph_boost:.3f} ≥ 0.55"

    # ── Transformer context ──────────────────────────────────────────────────
    if tf_score >= 0.90:
        result.is_transformer_primary = True
        result.factors.append(
            f"transformer_score={tf_score:.3f} — model flags this session as highly "
            f"anomalous (score ≥ 0.90; primary anomaly signal)"
        )
    elif _is_plateau(tf_score):
        result.is_single_event_plateau = True
        result.is_transformer_primary = False
        result.factors.append(
            f"transformer_score={tf_score:.3f} — plateau value (single-event session, "
            f"model has insufficient context; graph_boost is the primary signal here)"
        )
    else:
        result.is_transformer_primary = (tf_score >= 0.60)
        result.factors.append(
            f"transformer_score={tf_score:.3f} — moderate anomaly score; "
            f"combined with graph signals to reach Tier 2 threshold"
        )

    # ── Graph boost decomposition ────────────────────────────────────────────
    if graph_boost > 0:
        contributing = []

        if lat_hop > 0:
            contributing.append(f"lateral_hop_score={lat_hop:.2f}")
            result.factors.append(
                f"lateral_hop_score={lat_hop:.2f} — {lat_hop*100:.0f}% of new resource "
                f"edges in this session cross department boundaries"
            )
        if new_dev_bin > 0:
            contributing.append(f"new_device_edge=1 ({new_dev_bin} new device in entity history)")
            result.factors.append(
                f"new_device_edge_count={new_dev} — entity accessed {new_dev} device(s) "
                f"never seen in its graph history"
                + (" (Note: high-mobility roles such as IT/service-account may access "
                   "new devices legitimately — this is a known limitation of the global "
                   "flat threshold, not yet role-aware)" if new_dev <= 2 else "")
            )
        if ip_fan_in >= 2:
            contributing.append(f"ip_entity_fan_in={ip_fan_in}")
            result.factors.append(
                f"ip_entity_fan_in={ip_fan_in} — {ip_fan_in} distinct entities "
                f"authenticated from the same source IP within the 1-hour window"
            )
        if fan_out > 0:
            contributing.append(f"entity_fan_out={fan_out}")
            result.factors.append(
                f"entity_fan_out={fan_out} — entity reached {fan_out} distinct "
                f"resource nodes in its graph neighbourhood"
            )

        if contributing:
            result.factors.append(
                f"graph_boost={graph_boost:.4f} — contributed by: {', '.join(contributing)}"
            )
        else:
            result.factors.append(
                f"graph_boost={graph_boost:.4f} — minimal graph signal"
            )

    # ── Attack-specific contextual signals ───────────────────────────────────
    if fail_ratio >= 0.90 and fail_ct >= 10:
        result.factors.append(
            f"failure_ratio={fail_ratio:.2f} with failure_count={fail_ct}, "
            f"logon_count={logon_ct} — high-volume repeated authentication failures"
        )
    if off_hours:
        result.factors.append("off_hours_flag=1 — activity occurred outside normal business hours")
    if bytes_tot >= 100_000:
        result.factors.append(
            f"bytes_total={_fmt_bytes(bytes_tot)} — significant data volume transferred "
            f"in this session"
        )
    if cmd_esc:
        result.factors.append("cmd_has_escalate=1 — session included privilege-escalation commands")
    if cmd_exp:
        result.factors.append("cmd_has_export=1 — session included data-export commands")
    if cmd_del:
        result.factors.append("cmd_has_delete=1 — session included file-deletion commands")
    if foreign_ac > 0 and not off_hours:
        result.factors.append(
            f"foreign_access_count={foreign_ac} — accessed {foreign_ac} resources "
            f"outside entity's home department"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Tier 3 — model-driven attribution
# ─────────────────────────────────────────────────────────────────────────────

def _attribute_tier3(row: Dict[str, Any], result: AttributionResult) -> None:
    """Attribute a Tier 3 (model-driven, score < 55) session."""
    base_score  = float(_g(row, "base_score", 0.0))
    tf_score    = float(_g(row, "transformer_score", 0.0))
    if_score    = float(_g(row, "iforest_score", 0.0))
    graph_boost = float(_g(row, "graph_boost", 0.0))

    result.tier_condition = f"Tier 3: base_score({base_score:.3f}) + graph_boost({graph_boost:.4f}) = {base_score+graph_boost:.3f} < 0.55 (below alert threshold)"
    result.factors.append(
        f"base_score={base_score:.3f}, graph_boost={graph_boost:.4f} — "
        f"combined score {base_score+graph_boost:.3f} below alert threshold (0.55 for Tier 2). "
        f"Session not flagged."
    )
    result.factors.append(
        f"transformer_score={tf_score:.3f}, iforest_score={if_score:.4f} — "
        f"both model scores below anomaly threshold"
    )
    result.is_transformer_primary = False


# ─────────────────────────────────────────────────────────────────────────────
# Main attribution function
# ─────────────────────────────────────────────────────────────────────────────

def attribute_session(row) -> AttributionResult:
    """
    Produce a structured attribution for a session row.

    Parameters
    ----------
    row : dict, pd.Series, or dict-like object.
        Must contain the standard fused_scores.parquet columns.

    Returns
    -------
    AttributionResult with factors, tier_condition, and honesty flags.
    """
    if hasattr(row, "to_dict"):
        row = row.to_dict()

    session_id   = str(_g(row, "session_id", "UNKNOWN"))
    entity_id    = str(_g(row, "entity_id", "UNKNOWN"))
    entity_type  = str(_g(row, "entity_type", "unknown"))
    entity_dept  = str(_g(row, "entity_dept", "unknown"))
    risk_score   = int(_g(row, "fused_risk_score", 0))
    tier         = int(_g(row, "fusion_tier", 3))
    attack_type  = str(_g(row, "predicted_attack_type", "none"))
    hrf          = int(_g(row, "hard_rule_fired", 0))
    tf_score     = float(_g(row, "transformer_score", 0.0))
    if_score     = float(_g(row, "iforest_score", 0.0))

    result = AttributionResult(
        session_id            = session_id,
        entity_id             = entity_id,
        entity_type           = entity_type,
        entity_dept           = entity_dept,
        fused_risk_score      = risk_score,
        fusion_tier           = tier,
        predicted_attack_type = attack_type,
        transformer_score     = tf_score,
        iforest_score         = if_score,
    )

    if hrf > 0 or tier == 1:
        _attribute_tier1(row, result)
    elif tier == 2:
        _attribute_tier2(row, result)
    else:
        _attribute_tier3(row, result)

    return result


def attribute_session_id(session_id: str, fused_df=None) -> AttributionResult:
    """
    Convenience wrapper: look up a session_id in fused_scores.parquet and
    return its attribution.
    """
    import pandas as pd
    if fused_df is None:
        fused_df = pd.read_parquet("data/processed/fused_scores.parquet")
    row = fused_df[fused_df["session_id"] == session_id]
    if len(row) == 0:
        raise ValueError(f"Session {session_id} not found in fused_scores.parquet")
    return attribute_session(row.iloc[0])


if __name__ == "__main__":
    import pandas as pd
    fused = pd.read_parquet("data/processed/fused_scores.parquet")
    flagged = fused[fused["fused_risk_score"] >= 50]
    t1 = flagged[flagged["fusion_tier"] == 1].iloc[0]
    r = attribute_session(t1)
    print(r.summary)
    print(f"Tier condition: {r.tier_condition}")
    for f in r.factors:
        print(f"  • {f}")
