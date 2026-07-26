"""
ARGUS Phase 3 — Attack Classifier (Rule-Based Tagger)
======================================================
Given a fused session record (containing model scores + graph features +
raw session stats), applies a deterministic, priority-ordered rule chain
to assign a predicted_attack_type label.

Rule priority (highest -> lowest):
  0. credential_stuffing -- ip_entity_fan_in >= 3 AND failure_ratio >= 0.5
                             (behaviorally correct: many distinct entities failing
                              from same IP within 1h = shared-IP stuffing campaign)
  1. credential_stuffing -- fp_mismatch AND event_count<=1 AND failure_ratio > 0
                             (proxy: failed logon under a mismatched fingerprint)
  2. impossible_travel   -- fp_mismatch AND event_count<=1 AND failure_ratio==0
                             AND entity_fan_out >= 2
  3. device_spoofing     -- fp_mismatch AND event_count<=1 AND failure_ratio==0
  4. lateral_movement    -- fp_mismatch AND new_device_edge_count >= 5
                             (multi-event session touching >=5 new foreign devices)
  5. brute_force         -- failure_ratio >= 0.90 AND failure_count >= 10
                             AND logon_count >= 10
  6. low_and_slow_exfil  -- off_hours AND bytes_total >= 100_000 AND foreign_access > 0
  7. credential_misuse   -- off_hours AND foreign_access > 0 AND failure_ratio < 0.20
  8. insider_drift       -- cmd_has_escalate OR cmd_has_export (benign edge case)
  9. none                -- no rule matched

Thresholds are calibrated to the synthetic data generator's actual output
(credential_stuffing uses single-event failed logons, brute_force generates
15-30 rapid failures, low_and_slow_exfil uses bytes_total 200K-12M).

Note: The rule chain is evaluated independently of the hard-rule tier
assignment in the fusion engine. It provides a human-readable explanation
for every session -- alerting is governed by fused_risk_score >= threshold.

Usage:
    from src.fusion.attack_classifier import classify_attack_type
    predicted = classify_attack_type(session_row_dict)
"""

from typing import Dict, Any


# ---------------------------------------------------------------------------
# Thresholds (calibrated to synthetic data generator output)
# ---------------------------------------------------------------------------

THRESH = {
    # credential_stuffing: shared-IP fan-in (Priority 0, behaviorally correct)
    "CS_ip_fan_in_min":    3,    # distinct entities from same IP in ±1h
    "CS_fan_in_fail_min":  0.5,  # failure_ratio >= 0.5 required
    # credential_stuffing proxy: failed logon with fp mismatch (single-event)
    "CS_failure_ratio_min": 0.01,   # > 0 (any failure)
    # impossible_travel: successful logon with fp mismatch, shared credential
    "IT_fan_out_min":       2,
    # lateral_movement: fp_mismatch + multiple new foreign device edges
    "LM_new_dev_min":       5,    # graph signal: new devices never in entity history
    "LM_foreign_min":       5,    # fallback: heavy foreign traversal (legacy)
    # brute_force: many rapid failed logons
    "BF_failure_ratio":     0.90,
    "BF_failure_count":     10,
    "BF_logon_count":       10,
    # low_and_slow_exfiltration (stepped byte growth over off-hours)
    "LS_bytes_min":         100_000,
    "LS_foreign_min":       1,
    # credential_misuse (valid creds, off-hours, foreign resources)
    "CM_foreign_min":       1,
    "CM_failure_ratio_max": 0.20,
    # insider_drift
    "ID_cmd_escalate":      1,
    "ID_cmd_export":        1,
}


def _g(row: Dict[str, Any], key: str, default=0):
    """Safe getter with fallback for None."""
    v = row.get(key, default)
    return default if v is None else v


# ---------------------------------------------------------------------------
# Main classifier
# ---------------------------------------------------------------------------

def classify_attack_type(row: Dict[str, Any]) -> str:
    """
    Apply rule chain and return predicted attack type string.

    Parameters
    ----------
    row : dict-like row containing session features + graph features.

    Returns
    -------
    str -- one of: credential_stuffing, impossible_travel, device_spoofing,
                   lateral_movement, brute_force, low_and_slow_exfiltration,
                   credential_misuse, insider_drift, none
    """
    fp_mm      = int(_g(row, "fp_mismatch"))
    event_ct   = int(_g(row, "event_count", 1))
    fan_out    = float(_g(row, "entity_fan_out", 0))
    foreign_ac = int(_g(row, "foreign_access_count", 0))
    fail_ratio = float(_g(row, "failure_ratio", 0.0))
    fail_ct    = int(_g(row, "failure_count", 0))
    logon_ct   = int(_g(row, "logon_count", 0))
    bytes_tot  = int(_g(row, "bytes_total", 0))
    off_hours  = int(_g(row, "off_hours_flag", 0))
    ip_fan_in  = int(_g(row, "ip_entity_fan_in", 0))
    new_dev_ct = int(_g(row, "new_device_edge_count", 0))

    # -- Priority 0: credential_stuffing (shared-IP fan-in) -------------------
    # Behaviorally correct detection: many distinct entities failing logon from
    # the same IP in a 1-hour window. Catches stuffing even without fp_mismatch.
    if ip_fan_in >= THRESH["CS_ip_fan_in_min"] and fail_ratio >= THRESH["CS_fan_in_fail_min"]:
        return "credential_stuffing"

    # -- Priority 1: credential_stuffing (fp_mismatch proxy) ------------------
    # Single-event logon with fp mismatch AND a failure.
    if fp_mm and event_ct <= 1 and fail_ratio >= THRESH["CS_failure_ratio_min"]:
        return "credential_stuffing"

    # -- Priority 2: impossible_travel ----------------------------------------
    # Genuine behavioral signal: geo_velocity_violation=True (country change within 2h).
    # Fallback: fan_out >= IT_fan_out_min if geo_velocity_violation absent.
    geo_vel = bool(_g(row, "geo_velocity_violation", False))
    if fp_mm and event_ct <= 1 and fail_ratio == 0 and (geo_vel or fan_out >= THRESH["IT_fan_out_min"]):
        return "impossible_travel"

    # -- Priority 3: device_spoofing ------------------------------------------
    # Single-event successful login with fp mismatch, low/zero fan-out (and no geo_velocity_violation).
    if fp_mm and event_ct <= 1 and fail_ratio == 0:
        return "device_spoofing"

    # -- Priority 4: lateral_movement -----------------------------------------
    # Multi-event session with fp_mismatch + multiple new device edges (graph).
    # Prefer graph signal (new_device_edge_count) over proxy (foreign_access).
    if fp_mm and (new_dev_ct >= THRESH["LM_new_dev_min"] or foreign_ac >= THRESH["LM_foreign_min"]):
        return "lateral_movement"

    # -- Priority 5: brute_force ----------------------------------------------
    # Rapid succession of failed logons (failure_ratio may not be exactly 1.0
    # if the final attempt succeeded). Requires many failures AND many logons.
    if (
        fail_ratio >= THRESH["BF_failure_ratio"]
        and fail_ct >= THRESH["BF_failure_count"]
        and logon_ct >= THRESH["BF_logon_count"]
    ):
        return "brute_force"

    # -- Priority 6: low_and_slow_exfiltration --------------------------------
    # Off-hours activity, significant byte volume, foreign resource access.
    if (
        off_hours
        and bytes_tot >= THRESH["LS_bytes_min"]
        and foreign_ac >= THRESH["LS_foreign_min"]
    ):
        return "low_and_slow_exfiltration"

    # -- Priority 7: credential_misuse ----------------------------------------
    # Valid credentials used off-hours to access foreign department resources.
    if (
        off_hours
        and foreign_ac >= THRESH["CM_foreign_min"]
        and fail_ratio < THRESH["CM_failure_ratio_max"]
    ):
        return "credential_misuse"

    # -- Priority 8: insider_drift (benign edge case, low-confidence label) ---
    if (
        _g(row, "cmd_has_escalate") >= THRESH["ID_cmd_escalate"]
        or _g(row, "cmd_has_export") >= THRESH["ID_cmd_export"]
    ):
        return "insider_drift"

    return "none"


# ---------------------------------------------------------------------------
# Batch helper
# ---------------------------------------------------------------------------

def classify_dataframe(df) -> "pd.Series":
    """Apply classify_attack_type row-wise to a DataFrame. Returns Series."""
    import pandas as pd
    return df.apply(lambda r: classify_attack_type(r.to_dict()), axis=1)
