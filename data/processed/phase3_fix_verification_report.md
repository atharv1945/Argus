# ARGUS Phase 3 Fix — Precision Drop Verification Report

> Produced by post-diagnostic analysis. Covers the precision drop from 0.772 (pre-fix,
> graph layer dead) to the post-fix value, and the subsequent targeted correction.

---

## 1. FPR Before vs. After the Graph Fix

| State | FP Count | Normal Test Sessions | FPR |
|-------|---------|---------------------|-----|
| **Pre-fix** (graph layer dead, simulated) | 23 | 3,152 | **0.0073 (0.73%)** |
| **Post-fix v1** (graph active, ip_fan_in bug present) | 31 | 3,152 | **0.0098 (0.98%)** |
| **Post-fix v2** (graph active + ip_fan_in floor fixed) | 28 | 3,152 | **0.0089 (0.89%)** |

Corresponding precision:

| State | Precision | Recall | F1 |
|-------|-----------|--------|-----|
| Pre-fix | 0.7723 | 1.0000 | 0.8715 |
| Post-fix v1 | 0.7156 | 1.0000 | 0.8342 |
| **Post-fix v2 (final)** | **0.7358** | **1.0000** | **0.8478** |

---

## 2. What Drove the 8 Newly-Added FPs in Post-fix v1

The graph becoming active added 8 new FPs over the pre-fix baseline. Detailed breakdown:

### 2a. 3 New Tier-1 FPs — Hard-rule promotion via `new_device_edge_count >= 2`

| Entity | Type | Dept | new_device_edge_count | event_count | fp_mismatch | Score |
|--------|------|------|-----------------------|-------------|-------------|-------|
| SVC_1115 | service_account | Engineering | 2 | 17 | 1 | 93 |
| U1128 | user | Engineering | 2 | 11 | 1 | 93 |
| U1295 | user | IT | 2 | 22 | 1 | 93 |

**Cause:** These are high-activity entities (event_count 11–22, far above the typical 2-event session for attacks) who legitimately used two distinct devices never before in their graph history during this test-period session. With the graph now active, `new_device_edge_count` correctly measures 2 brand-new device edges, which satisfies the hard-rule corroboration condition `fp_mismatch AND new_dev >= 2`, escalating them to Tier 1 (score 93).

**Root cause:** The `fp_mismatch=1` flag on normal sessions is real — these entities genuinely logged in from a fingerprint slightly different from their historical device profile (e.g. a new browser version, OS update, or temporary corporate laptop). The `new_device_edge_count >= 2` threshold was set to guard against Campaign 4's single-swap (count=1), but does not exclude entities who legitimately rotate through two devices in the same session.

**This is NOT role-aware:** IT admins and service accounts are structurally expected to access multiple devices. A peer-group baseline (e.g. the 95th percentile `new_device_edge_count` for the IT department or service_account entity_type) would absorb this variation. The current global threshold of 2 does not.

### 2b. 3 New Tier-2 FPs — Spurious `ip_fan_in_norm` residual (fixable bug)

| Entity | Type | Dept | ip_entity_fan_in | graph_boost | base_score | base+boost |
|--------|------|------|-----------------|-------------|------------|-----------|
| SVC_1043 | service_account | Finance | 1 | 0.0125 | 0.5470 | 0.5595 |
| SVC_1191 | service_account | IT | 1 | 0.0125 | 0.5469 | 0.5594 |
| U1028 | user | Finance | 1 | 0.0125 | 0.5480 | 0.5605 |

**Cause:** `ip_entity_fan_in = 1` means only the entity itself logged in from its IP in the ±1h window — the baseline "self-only" state with zero cohort signal. Due to the 99th-percentile normalisation cap (cap=8, the credential stuffing campaign size), even `fan_in=1` produced `ip_fan_in_norm = 1/8 = 0.125`, contributing `0.10 × 0.125 = 0.0125` to `graph_boost`. For sessions with `base_score` just below 0.55 (e.g. 0.547), this 0.0125 residual was enough to cross the Tier-2 threshold.

**This is a formula bug, not a genuine signal.** `ip_fan_in=1` = no cross-entity cohort evidence. This was fixed (see Section 3).

### 2c. 2 New Tier-2 FPs — `new_device_edge=1` contributing 0.10 to graph_boost

| Entity | Type | Dept | new_device_edge | graph_boost | base_score |
|--------|------|------|-----------------|-------------|------------|
| U1236 | user | HR | 1 | 0.1125 | 0.5414 |
| U1286 | user | IT | 1 | 0.1125 | 0.5257 |

**Cause:** These sessions accessed one device never in the entity's history before. `new_device_edge=1` (binary flag) contributes `0.10` to `graph_boost`. Combined with a near-threshold `base_score` (0.54–0.52), the total crosses 0.55. Both entities are in IT or HR departments with naturally higher device mobility.

**This is a genuine, working graph signal** (the entity really did access a novel device) but applied at a global flat threshold without accounting for the fact that IT/HR roles have structurally higher device mobility than e.g. Finance. A per-role peer-group baseline on `new_device_edge` frequency would calibrate this correctly.

---

## 3. The Targeted Fix Applied (Post-fix v2)

**Fix:** In `anomaly_first_fusion.py`, `compute_fused_risk()`:
```python
# Before (bug):
df["ip_fan_in_norm"] = (df["ip_entity_fan_in"] / ip_fan_cap).clip(0, 1)

# After (fixed):
df["ip_fan_in_norm"] = ((df["ip_entity_fan_in"] >= 2).astype(float)
                        * (df["ip_entity_fan_in"] / ip_fan_cap)).clip(0, 1)
```

`ip_fan_in_norm` is now zeroed for `fan_in < 2`. This eliminates the 3 spurious Tier-2 FPs from the self-only residual. The fix recovers 3 FPs at zero cost: `fan_in=1` carries no cohort information, so removing it from graph_boost is unambiguously correct.

**Result after fix:** FPR 0.0073 → 0.0098 → **0.0089**. Precision: 0.7723 → 0.7156 → **0.7358**.

---

## 4. Diagnosis: Acceptable Cost (a) vs. Fixable Problem (b)

### Remaining 5 new FPs (after the ip_fan_in floor fix)

- **3 Tier-1 FPs** (new_device_edge_count=2 + fp_mismatch): **Verdict (b) — fixable but not here.**
  These are high-connectivity entities (IT, service accounts) whose legitimate multi-device usage crosses a flat `>= 2` threshold. The correct fix is role-aware or peer-group-aware `new_device_edge_count` normalisation: compare against the 95th percentile of `new_device_edge_count` within the entity's `entity_type + entity_dept` cohort, not a global absolute count. This was part of ARGUS's original design intent (peer-group baselining in `build_features.py`). However, this requires re-running feature engineering and would change the interface to the models — **not applied in this step to avoid scope creep**. Carried forward as a **known limitation for Phase 5**.

- **2 Tier-2 FPs** (new_device_edge=1 pushing near-threshold sessions over 0.55): **Verdict (a) — acceptable SOC cost.**
  The graph signal is real (they did access a novel device). At 2 extra FPs across 3,152 normal sessions, a SOC analyst investigating 28 alerts per test period would encounter these 2 sessions in their queue. Given the context (fp_mismatch=1, novel device, near-threshold model scores), these are reasonable candidates for a 30-second analyst triage step. Suppressing them would require either raising the Tier-2 base_score threshold (which risks missing low-model-score lateral movement) or applying role-aware new_device_edge normalisation (same fix as above). Neither is applied here.

### Summary

| FP Category | Count | Verdict | Action |
|-------------|-------|---------|--------|
| ip_fan_in=1 residual (self-only) | 3 | (b) Bug | ✅ Fixed in Post-fix v2 |
| new_device_edge_count=2, high-connectivity roles | 3 | (b) Fixable, non-trivial | ⚠️ Known limitation, Phase 5 (role-aware graph normalisation) |
| new_device_edge=1, near-threshold base_score | 2 | (a) Acceptable | ✅ Tolerated |
| Pre-existing FPs (survived both fixes) | 23 | (a) Acceptable | ✅ No change |
| **Total post-fix v2** | **28** | — | FPR = **0.89%** |

> [!NOTE]
> The pre-fix precision of 0.772 was built on a dead graph layer. The graph was not contributing to detection — it was also not contributing any false positives. A precision of 0.772 with a broken graph is not a meaningful baseline. The honest post-fix precision is **0.7358** (28 FPs), and 3 of those FPs are directly attributable to the role-aware baselining gap that was always in the design scope for Phase 5.
