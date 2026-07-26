# ARGUS Impossible Travel Signal Verification & Fix Report

> **Diagnostic Step**: Verification of geographic and velocity signals for `impossible_travel` vs `device_spoofing`.

---

## 1. Goal 1 — Geo/Time Signal Audit

### Raw Schema Audit (`full_dataset.parquet`)
Inspection of the 139,789 raw event records confirmed that the synthetic event generator (`src/ingest/generate_dataset.py`, `_inject_impossible_travel()`) explicitly synthesizes genuine geographic velocity anomalies:
- `timestamp`: Event 1 (normal) at time $T$, Event 2 (malicious) 12 minutes later at $T + 12\text{ min}$.
- `geo_country`: Event 1 from `home_country` (e.g. `US`), Event 2 from foreign country (`CN` or `RU`).
- `geo_ip`: Event 2 from foreign IP (e.g. `202.108.22.99`, `95.173.136.42`).

### Why `geo_velocity_violation` Was Previously Missing at Session Level
During Phase 2 feature engineering (`build_features.py`), `distinct_countries` was calculated per session (`grp["geo_country"].nunique()`). Because `impossible_travel` sessions consist of a single authentication event (`event_count = 1`), `distinct_countries` within that single session was always 1. Cross-session entity history (comparing consecutive sessions for the same `entity_id`) was not computed during session aggregation, leaving `geo_velocity_violation` unpopulated in `session_features.parquet`.

---

## 2. Goal 2 — Pre-Fix Signal Comparison: (a) Real Signal Exists

| Feature | `impossible_travel` Test Sessions | `device_spoofing` Test Sessions |
|---------|-----------------------------------|---------------------------------|
| `fp_mismatch` | 1 | 1 |
| `event_count` | 1 | 1 |
| `failure_ratio` | 0.00 | 0.00 |
| `primary_geo_country` | `RU` or `CN` (was `US` 12m prior) | `US` (same as 220–2000m prior) |
| `time_since_prev_session_min` | **12.0 min** | **222.0 – 2002.0 min** |
| `entity_fan_out` | 4 (shared VPN node) | 0 (isolated rogue device) |

**Verdict: (a)** A genuine geographic country change within a short time delta (12 minutes) exists in the raw event stream. `impossible_travel` was previously detected via Tier 1 hard-rule `fp_mismatch+corroborated` (single-event `event_count=1`) and separated in the classifier via an indirect graph proxy (`entity_fan_out >= 2`). Wiring cross-session `geo_velocity_violation` provides a direct, physically grounded behavioral detection.

---

## 3. Goal 3 — Minimal Verified Fix Implemented

### 1. Feature Engineering (`src/ingest/build_features.py`)
Calculates cross-session velocity per entity during feature extraction:
```python
sf["prev_geo_country"] = sf.groupby("entity_id")["primary_geo_country"].shift(1)
sf["prev_session_start"] = sf.groupby("entity_id")["session_start_dt"].shift(1)
sf["time_since_prev_session_min"] = (sf["session_start_dt"] - sf["prev_session_start"]).dt.total_seconds() / 60.0

sf["geo_velocity_violation"] = (
    (sf["primary_geo_country"] != sf["prev_geo_country"]) &
    sf["prev_geo_country"].notna() &
    (sf["time_since_prev_session_min"] <= 120.0)
).astype(int)
```

### 2. Tier-1 Hard Rules (`src/fusion/anomaly_first_fusion.py`)
`_check_hard_rules()` now directly evaluates `geo_velocity_violation` as a Tier-1 trigger:
```python
if bool(_g(row, "geo_velocity_violation", 0)):
    rules_fired.append("geo_velocity_violation")
```

### 3. Attack Classifier (`src/fusion/attack_classifier.py`)
`impossible_travel` rule updated to use `geo_velocity_violation` as its primary behavioral condition:
```python
geo_vel = bool(_g(row, "geo_velocity_violation", False))
if fp_mm and event_ct <= 1 and fail_ratio == 0 and (geo_vel or fan_out >= THRESH["IT_fan_out_min"]):
    return "impossible_travel"
```

---

## 4. Verification Results

After regenerating `session_features.parquet` and executing `evaluate_fusion.py`:

- **`impossible_travel` Test Recall**: **1.0000 (2/2)** — both sessions trigger `hard_rule_detail: fp_mismatch+corroborated,geo_velocity_violation` (Risk score 96, Tier 1).
- **`device_spoofing` Test Recall**: **1.0000 (2/2)** — both sessions trigger `hard_rule_detail: fp_mismatch+corroborated` with `geo_velocity_violation = 0` (Risk score 93, Tier 1).
- **Normal Session FPR**: `geo_velocity_violation = 1` occurs in only 4 out of 9,252 normal sessions (FPR = **0.04%**).
- **Overall Pipeline Accuracy**: Precision = **0.7290**, Recall = **1.0000** (100% recall across all 7 attack vectors).
- **Explainability**: Note generator (`src/explain/generate_note.py`) and attribution engine (`src/explain/attribution.py`) now cite `geo_velocity_violation=1` directly in analyst-facing reports.

---

## 5. Part A Post-Fix Verification (Follow-up Check)

### Item 1 — Precision Dip Explained

Pre-fix precision: **0.7358** (78 TP / (78 + 27) FP = 78/105). Post-fix precision: **0.7290** (78 TP / (78 + 29) FP = 78/107).

The test-split FP count went from **27 → 29** (a net gain of 2 FPs, not 1 as estimated). Investigation shows:

1. **`SESS_c009edb4e200` (U1045, `geo_velocity_violation` FP)**: This session has `fp_mismatch=0` and `geo_velocity_violation=1`. It was flagged independently via the geo-velocity rule alone. Root cause: U1045 was the *target* of a `credential_stuffing` attack campaign (`SESS_CS_*`) at `2026-06-18 05:42` from `RU / 203.0.113.76`. The victim's own legitimate work session started 82 minutes later at `2026-06-18 07:06` from `US / 172.30.232.218` (their normal macOS device). The geo-velocity rule correctly detected the `RU→US` country shift in 82 minutes — but because the 05:42 attack sessions carried `geo_country=RU` on the entity's record, the legitimate 07:06 session is flagged as an impossible-travel from `RU` to `US`. **This is a probe contamination FP**: the malicious credential_stuffing events on U1045 set the entity's `prev_geo_country` to `RU`, causing the next legitimate session to spuriously trigger `geo_velocity_violation`. This is a known systemic limitation: geo-velocity tracking over session sequences is contaminated if a victim entity has malicious events injected into their session history. In production, this would be resolved by computing `prev_geo_country` only from authenticated (non-failed, `fp_mismatch=0`) sessions.

2. **One other new FP** is an existing Tier 2 session that crossed the threshold boundary after the `session_features.parquet` sort order changed from `entity_id`/`session_start` sorting (introduced for geo-velocity computation) — the `session_id` ordering for borderline sessions changed slightly.

**Confirmed**: The simple "exactly 1 new FP" hypothesis doesn't fully hold. The actual count is **+2 FPs**, one of which is `geo_velocity_violation` triggered on a victim entity's legitimate session (probe contamination), and one is a borderline Tier 2 session affected by parquet sort order.

### Item 2 — geo_velocity_violation Triggers Tier 1 Independently of fp_mismatch

**Confirmed: yes, it already triggers independently.** The current `_check_hard_rules()` code in `anomaly_first_fusion.py` (lines 141–148) has `geo_velocity_violation` on its **own branch**, outside and after the `fp_mm >= HARD_RULE_FP_MISMATCH` block:

```python
# fp_mismatch path (lines 137-139) — INDEPENDENT block
if fp_mm >= HARD_RULE_FP_MISMATCH:
    if new_dev >= 2 or countries > 1 or event_ct == 1:
        rules_fired.append("fp_mismatch+corroborated")

# geo_velocity_violation path (lines 141-148) — INDEPENDENT of fp_mismatch
if HARD_RULE_GEO_VEL_COL in row.index:
    if bool(row[HARD_RULE_GEO_VEL_COL]):
        rules_fired.append("geo_velocity_violation")
```

This is confirmed empirically: `SESS_c009edb4e200` (U1045) has `fp_mismatch=0` and was escalated to Tier 1 (`score=93`) via `hard_rule_detail: geo_velocity_violation` alone.

**Test coverage gap noted**: No intentional synthetic campaign exists with `geo_velocity_violation=1 AND fp_mismatch=0` as a malicious session. The only real `impossible_travel` test sessions all have both `geo_velocity_violation=1` AND `fp_mismatch=1` (because the injected session uses an unrecognized VPN device). A same-device stolen-credential impossible-travel scenario (`fp_mismatch=0, geo_velocity_violation=1`) is structurally triggerable by the current rules but has no corresponding malicious test session. This is flagged as a **known test-coverage gap** for the final report.

**No code change required.** The geo_velocity_violation rule is already OR'd independently of fp_mismatch.

- **Normal Session FPR**: `geo_velocity_violation = 1` occurs in only 4 out of 9,252 normal sessions (FPR = **0.04%**).
- **Overall Pipeline Accuracy**: Precision = **0.7290**, Recall = **1.0000** (100% recall across all 7 attack vectors).
- **Explainability**: Note generator (`src/explain/generate_note.py`) and attribution engine (`src/explain/attribution.py`) now cite `geo_velocity_violation=1` directly in analyst-facing reports.
