# ARGUS Phase 3 Verification Report

This report documents the verification of the Graph Layer and Anomaly-First Fusion Engine implemented in Phase 3. It addresses two critical goals:
1. Verifying the separation between `insider_drift` Campaign 1 ("cross-department resource expansion") and `lateral_movement` sessions.
2. Assessing the credential stuffing detection mechanism compared to its behavioral definition in the specification.

---

## Goal 1: Insider Drift vs. Lateral Movement Collision Risk

### 1. Side-by-Side Session-Level Heuristics

The table below contrasts all sessions of **insider_drift Campaign 1** (ATK_ID_*_001) against all **lateral_movement** test sessions.

| Session ID | Campaign / Instance ID | Class | Lateral Hop Score | Entity Fan Out | New Resource Edge | Resource Fan Out Dev | Fused Risk Score | Fusion Tier |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **SESS_LM_1172164c53** | ATK_LM_20260617_004 | Lateral Movement (Test) | 0.0 | 0 | 0 | -3.3659 | 56 | 2 |
| **SESS_LM_f8a404b9ad** | ATK_LM_20260619_002 | Lateral Movement (Test) | 0.0 | 0 | 0 | -3.3659 | 55 | 2 |
| **SESS_ID_1e9cb00b** | ATK_ID_20260607_001 | Insider Drift C1 (Train) | 0.0 | 0 | 0 | -2.8295 | 12 | 3 |
| **SESS_ID_a3f92c88** | ATK_ID_20260607_001 | Insider Drift C1 (Train) | 0.0 | 0 | 0 | -2.8295 | 13 | 3 |
| **SESS_ID_d497db8c** | ATK_ID_20260607_001 | Insider Drift C1 (Train) | 0.0 | 0 | 0 | -2.8295 | 11 | 3 |
| **SESS_ID_0a8425ce** | ATK_ID_20260607_001 | Insider Drift C1 (Train) | 0.0 | 0 | 0 | -2.8295 | 12 | 3 |
| **SESS_ID_5d7f5c61** | ATK_ID_20260607_001 | Insider Drift C1 (Train) | 0.0 | 0 | 0 | -2.8295 | 11 | 3 |

### 2. Diagnosis and Findings

#### Crucial Pipeline Bug Discovered: Dead Graph Features
The side-by-side comparison reveals that **all temporal and relational new-edge features (`lateral_hop_score`, `new_resource_edge`, and `new_device_edge`) are exactly 0.0 for both classes**.

Investigation of the graph feature builder (`src/graph/entity_graph.py`) identified a **timestamp scaling mismatch**:
- The event logs' timestamp column is stored as `datetime64[us]` (microseconds).
- `raw_df["timestamp"].astype("int64") // 10**9` yields integer timestamps scaled in **microseconds** divided by $10^9$ (giving value ranges around $1.78 \times 10^6$).
- The lookup session start time in the evaluation script is generated using `pd.Timestamp(t_start).value // 10**9`, which returns **seconds** (value ranges around $1.78 \times 10^9$).
- Because of this 1000x scaling mismatch, the lookup timestamp is always much larger than the edge timestamps stored in the graph. As a result, the binary search function `_had_edge_before` **always returns `True`**, falsely indicating that every single edge already existed in the baseline history.
- Consequently, all new-edge metrics (`new_device_edge`, `new_resource_edge`, `lateral_hop_score`, and `graph_boost`) **evaluated to flat zeros for all 9,476 sessions in the dataset**.

#### Separation State: Coincidental / Not Genuinely Resolved
1. **Collision Risk Status**: The separation is **not genuinely resolved by the graph layer**, as both classes have identical graph feature signatures (0.0). The graph layer is currently inactive (dead).
2. **True Source of Separation**: The separation is achieved **solely by the Transformer model**. The Transformer scored the lateral movement sessions very high ($\approx 0.996$), bringing their `base_score` above the Tier 2 threshold of 0.55. Meanwhile, the Transformer scored the insider drift sessions close to zero ($\approx 0.001$), keeping them in Tier 3 (score 11–13) and avoiding alerts.
3. **Hidden Vulnerability**: If the timestamp bug is fixed, a new vulnerability appears: `insider_drift` Campaign 4 (benign hardware upgrade) will evaluate to `new_device_edge_count = 1`. Under the current Tier 1 hard-rule corroboration logic (`fp_mismatch == 1 AND (new_device_edge_count >= 1 OR ...)`), Campaign 4 sessions would satisfy the condition and get **falsely flagged as Tier 1 alerts (score 93)**.

---

## Goal 2: Credential Stuffing Detection Mechanism

### 1. Cohort Analysis vs. Active Rules

1. **Shared-IP Fan-in Signal**: No cohort-level shared-IP fan-in feature was computed or used. The pipeline does not possess a feature tracking multiple entity logons sharing a single IP.
2. **Current Classifier Logic**: Detection relies entirely on the proxy path:
   `fp_mismatch AND event_count == 1 AND failure_ratio > 0`
   (Mismatched device fingerprint + single-event session + failed logon).

### 2. Campaign Data Check: Is the Signature Present?

We verified the raw telemetry in the test split for the two credential stuffing campaigns:

- **Campaign `ATK_CS_20260618_002`**:
  - Distinct Entities (`entity_id`): **8**
  - Distinct Source IPs (`geo_ip`): **1**
- **Campaign `ATK_CS_20260608_004`**:
  - Distinct Entities (`entity_id`): **8**
  - Distinct Source IPs (`geo_ip`): **1**

The "many entities, single IP" signature is **highly prominent and present** in the raw synthetic data, but the current detection logic does not inspect it.

### 3. Diagnosis and Findings

The credential stuffing detection is **coincidentally correct (proxy-based)**, not behaviorally correct:
- It succeeds because the synthetic data generator injects a mismatched fingerprint (`fp_mismatch = 1`) and a failed logon (`failure_ratio = 1.0`) on a single-event session (`event_count = 1`) for every credential stuffing attempt.
- This would fail to generalize in production:
  1. An attacker using standard user-agent rotation (or a proxy matching the user's OS/device) would not trigger the `fp_mismatch` proxy.
  2. The classifier would fail to flag credential stuffing attempts that successfully logged in (which is the goal of credential stuffing), or attempts that did not exhibit a device fingerprint change.
  3. A true credential stuffing detection must track cross-entity IP cohort fan-in (e.g. multiple distinct entities failing logins from the same source IP in a short window).

---

## Key Recommendations for Phase 4 / Next Actions

1. **Fix the Graph Time Scale**: Correct the division in `build_from_events` to match the query scale in `evaluate_fusion.py` (scale both to standard Unix epoch seconds).
2. **Refine Hard Rule Corroboration**: Adjust the `fp_mismatch` corroboration threshold to require `new_device_edge_count >= 2` (rather than $\ge 1$) to prevent hardware upgrades (which generate exactly 1 new edge) from triggering Tier 1 false alarms.
3. **Engineer a Cohort Shared-IP Feature**: Introduce a windowed count of distinct entities per IP to build a behaviorally correct credential stuffing detection rather than relying on the device mismatch proxy.
