# ARGUS Benchmark Comparison Report: XGBoost vs. Transformer Sequence Model

**Date:** July 25, 2026  
**Status:** Completed (Isolated Read-Only Evaluation)  
**Target Artifact:** `data/processed/xgb_comparison_scores.parquet`  
**Dataset Version:** ARGUS Pre-Phase-7 Verified Benchmark (9,575 sessions: 6,293 train / 3,282 test)

---

## 1. Executive Summary

This report presents an isolated, empirical comparison between a **Gradient Boosted Decision Tree (XGBoost)** classifier and the primary **Transformer Sequence Model** within the ARGUS Insider Threat Detection Pipeline.

The investigation was initiated to evaluate whether the recall deficit observed in the Transformer model on the `low_and_slow_exfiltration` attack vector (54.2% recall) stemmed from an inherent weakness in the dataset's feature representation or from architectural limitations of sequence-based deep learning on low-sample tabular sessions.

### Key Findings

1. **Superior Overall Benchmark Performance:**
   - **XGBoost** achieved an overall test **Precision of 0.9231**, **Recall of 1.0000**, and **F1 Score of 0.9600** (at decision threshold $t = 0.5$).
   - The **Transformer/Fusion Baseline** achieved an overall test Precision of 0.6987, Recall of 0.9083, and F1 Score of 0.7899.

2. **100% Low & Slow Exfiltration Recall:**
   - XGBoost successfully detected **24 out of 24 test sessions (100% recall)** for `low_and_slow_exfiltration`, completely eliminating the coverage gap on low-bytes campaigns (200 KB and 360 KB sessions).
   - In comparison, the Transformer sequence model caught only 13 of 24 test sessions (54.2% recall).

3. **Generalization via Feature Thresholds vs. Sequence Memorization:**
   - On the train-side gradient diagnostic (Spearman correlation between `bytes_total` and score across training campaigns), XGBoost exhibited output probability saturation ($r = +0.287$, $p = 0.11$, non-significant gradient).
   - However, unlike the Transformer (which memorized campaign identity tokens and failed on unseen test campaigns), XGBoost learned **explicit decision boundary splits** on structural session features (`duration_min`, `logoff_count`, `peer_dev_duration_min`, `bytes_total`). Consequently, XGBoost generalized perfectly to unseen test campaigns.

4. **Fusion Simulation Insights:**
   - Simulating the addition of XGBoost as an additive 4th signal to ARGUS's Anomaly-First Fusion Engine ($S_{\text{sim}} = S_{\text{fused}} + 40 \times S_{\text{xgb}}$ at threshold $t = 55$) converted **3 of 11 currently missed LS sessions** to caught status without adding any new normal false positives.
   - The remaining 8 missed LS sessions require a dedicated lower fusion threshold or higher weight because their baseline anomaly scores are extremely low (9–15 points out of 100).

---

## 2. Background & Motivation

During Phase 6 testing and verification of ARGUS, an in-depth audit of the `low_and_slow_exfiltration` attack class revealed a structural limitation in the sequence Transformer:
- The Transformer score tracked `bytes_total` on *unseen test campaigns* (caught mean 0.830 vs. missed mean 0.132).
- However, on *training campaigns*, all 32 sessions scored near $1.000$ regardless of session bytes or rank within the campaign.
- Diagnostic analysis proved that the Transformer was memorizing training campaign identity sequences via attention mechanisms rather than discovering robust feature-level boundary rules.

To determine whether this limitation was inherent to the dataset or specific to the neural sequence architecture, an isolated XGBoost model was trained on the exact same 81 tabular features and identical train/test splits.

---

## 3. Methodology & Experimental Setup

To guarantee strict experimental control and eliminate data leakage, the experiment adhered to rigid isolation boundaries:

- **Data Integrity:** Read-only access to `session_features.parquet` and `fused_scores.parquet`. Zero modifications were made to dataset generation, feature engineering, or active fusion engine code.
- **Feature Set:** Exactly 81 features (27 base session metrics + 27 individual entity deviation metrics `dev_*` + 27 peer-group deviation metrics `peer_dev_*`). Key features include `bytes_total`, `bytes_max`, `bytes_mean`, `duration_min`, `event_count`, `logoff_count`, `off_hours_flag`, `cmd_risky_ratio`, and `auth_risk`.
- **Model Configuration:**
  - Algorithm: `XGBClassifier` (`objective="binary:logistic"`, `eval_metric="aucpr"`)
  - Hyperparameters: `n_estimators=300`, `max_depth=4`, `learning_rate=0.05`, `subsample=0.8`, `colsample_bytree=0.8`, `random_state=42`
  - Class Imbalance Weighting: `scale_pos_weight = 38.33` ($\frac{N_{\text{normal}}}{N_{\text{malicious}}} = \frac{6,133}{160}$), matching the exact empirical train ratio.
- **Dataset Partitioning:**
  - **Train:** 6,293 sessions (160 malicious, 6,133 normal), containing 32 `low_and_slow` sessions across 4 campaigns.
  - **Test:** 3,282 sessions (120 malicious, 3,162 normal), containing 24 `low_and_slow` sessions across 3 unseen campaigns.

---

## 4. Quantitative Comparison

### 4.1 Overall Test Set Metrics

The performance of XGBoost evaluated on the held-out test set ($N = 3,282$) at threshold $t = 0.5$ is contrasted against the baseline ARGUS Transformer/Fusion system below:

| Metric | XGBoost (Isolated) | Transformer / Fusion Baseline | Absolute Delta |
| :--- | :---: | :---: | :---: |
| **Precision** | **0.9231** | 0.6987 | **+0.2244** |
| **Recall** | **1.0000** | 0.9083 | **+0.0917** |
| **F1 Score** | **0.9600** | 0.7899 | **+0.1701** |
| **ROC-AUC** | **0.9996** | 0.9140 | **+0.0856** |
| **PR-AUC** | **0.9900** | 0.8585 | **+0.1315** |
| **Normal False Positives** | **5 sessions** (0.16%) | 47 sessions (1.49%) | **-42 FPs (-89.4%)** |

---

### 4.2 Per-Class Recall Breakdown

The table below details test-set session recall ($N_{\text{caught}} / N_{\text{total}}$) across all 7 insider threat attack classes:

| Attack Category | Test Count ($N$) | XGBoost Recall | Transformer Recall | Delta |
| :--- | :---: | :---: | :---: | :---: |
| `brute_force` | 3 | **1.000** (3/3) | **1.000** (3/3) | 0.000 |
| `credential_misuse` | 3 | **1.000** (3/3) | **1.000** (3/3) | 0.000 |
| `credential_stuffing` | 78 | **1.000** (78/78) | 0.923 (72/78) | **+0.077** |
| `device_spoofing` | 3 | **1.000** (3/3) | **1.000** (3/3) | 0.000 |
| `impossible_travel` | 6 | **1.000** (6/6) | 0.833 (5/6) | **+0.167** |
| `lateral_movement` | 3 | **1.000** (3/3) | 0.667 (2/3) | **+0.333** |
| `low_and_slow_exfiltration` | 24 | **1.000** (24/24) | 0.542 (13/24) | **+0.458** |
| **Total Malicious** | **120** | **1.000 (120/120)** | **0.908 (109/120)** | **+0.092** |

---

## 5. Deep Dive: Low & Slow Exfiltration Diagnostic

### 5.1 Test Performance Across Thresholds

Threshold sensitivity analysis for `low_and_slow_exfiltration` test sessions ($N=24$) demonstrates stability across a broad operating range:

| Decision Threshold ($t$) | LS Test Recall | Caught / Total | Normal FPs |
| :---: | :---: | :---: | :---: |
| $t = 0.1$ | 1.000 | 24 / 24 | 5 |
| $t = 0.3$ | 1.000 | 24 / 24 | 5 |
| **$t = 0.5$ (Default)** | **1.000** | **24 / 24** | **5** |
| $t = 0.7$ | 1.000 | 24 / 24 | 5 |
| $t = 0.9$ | 1.000 | 24 / 24 | 5 |

Even at high confidence thresholds up to $t = 0.9$, XGBoost maintains 100% recall on all low-and-slow sessions, capturing both the high-volume sessions (3.78 MB – 12.24 MB) and the low-volume sessions (200 KB – 1.16 MB).

---

### 5.2 Train-Side Gradient Check

To assess whether XGBoost exhibited score-to-bytes sensitivity on training data, the 4 training campaigns (32 sessions) were evaluated using Spearman rank correlation ($r$) and split-half score diffs ($\Delta = \text{Mean}_{\text{top}} - \text{Mean}_{\text{bottom}}$):

| Training Campaign ID | $N_{\text{sess}}$ | Bottom Half Mean | Top Half Mean | Score Diff ($\Delta$) | Spearman $r$ | Diagnostic Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `ATK_LS_20260606_007` | 8 | 0.9998 | 0.9999 | +0.0000 | +0.6347 ($p=0.091$) | **FLAT (Ceiling)** |
| `ATK_LS_20260609_006` | 8 | 0.9994 | 0.9996 | +0.0002 | +0.8333 ($p=0.010$) | **FLAT (Ceiling)** |
| `ATK_LS_20260610_005` | 8 | 0.9996 | 0.9997 | +0.0001 | +0.9698 ($p<0.001$) | **FLAT (Ceiling)** |
| `ATK_LS_20260612_001` | 8 | 0.9998 | 0.9999 | +0.0000 | +0.2410 ($p=0.565$) | **FLAT (Ceiling)** |
| **Pooled Summary** | **32** | **0.9996** | **0.9998** | **+0.0001** | **+0.2868 ($p=0.112$)** | **FLAT (Ceiling)** |

#### Critical Insight on Generalization
While XGBoost output probabilities saturate near $1.000$ on training data (producing a flat gradient across byte steps), **its underlying mechanism of generalization is fundamentally distinct from the Transformer's:**
- The **Transformer** uses self-attention over sequence position tokens, which memorized specific campaign sequence signatures. When evaluated on unseen test campaigns, the sequence tokens no longer matched, forcing a fallback to weak byte linear projections.
- **XGBoost** constructs axis-aligned orthogonal decision boundaries on tabular features (`logoff_count`, `duration_min`, `bytes_total`). Because these physical boundaries are invariant to campaign identity, XGBoost classifies unseen test campaigns with equal precision.

---

## 6. Feature Importance Analysis

Gain-based feature importance extracted from the trained XGBoost model highlights the top structural drivers of threat identification:

| Rank | Feature | Importance (Gain) | Category / Description |
| :---: | :--- | :---: | :--- |
| 1 | `logoff_count` | **816.62** | Session termination frequency |
| 2 | `duration_min` | **624.13** | Overall session active duration |
| 3 | `peer_dev_duration_min` | **47.08** | Deviation in duration vs. peer group |
| 4 | `cmd_entropy` | **16.22** | Command complexity / randomness |
| 5 | `peer_dev_auth_risk` | **11.65** | Peer deviation in authentication risk |
| 6 | `event_count` | **10.10** | Total log entries in session |
| 7 | `file_access_count` | **5.52** | Count of distinct file interactions |
| 8 | `dev_distinct_resource_depts` | **3.67** | Individual baseline deviation in resource depts |
| 9 | `dev_auth_risk` | **3.58** | Individual baseline deviation in auth risk |
| 10 | `bytes_total` | **2.90** | Total raw bytes transmitted |

### Takeaway
`logoff_count` and `duration_min` provide the strongest non-linear signal for separating low-and-slow exfiltration sessions from normal background activity. Low-and-slow campaigns maintain lingering, multi-hour sessions with irregular logoff counts and elevated command entropy, allowing XGBoost to detect them even when total bytes transmitted are small ($200\text{ KB}$).

---

## 7. Fusion Engine Integration Simulation

To evaluate the feasibility of augmenting the active ARGUS Anomaly-First Fusion Engine without modifying live code, a read-only simulation was conducted.

### Simulation Protocol
- **Formula:** $S_{\text{sim}} = S_{\text{fused}} + (40 \times S_{\text{xgb}})$
- **Fusion Alert Threshold:** $S_{\text{target}} \ge 55$
- **Target Population:** The 11 `low_and_slow` test sessions currently missed by the baseline fusion engine ($S_{\text{fused}} < 55$).

### Simulation Results

| Session ID | $S_{\text{fused}}$ (Base) | $S_{\text{xgb}}$ (XGB Score) | $S_{\text{sim}}$ (Simulated) | Outcome |
| :--- | :---: | :---: | :---: | :---: |
| `SESS_LS_507a24b7` | 21.0 | 0.9997 | **61.0** | **WOULD CATCH (Flipped)** |
| `SESS_LS_f8f9dec5` | 17.0 | 0.9997 | **57.0** | **WOULD CATCH (Flipped)** |
| `SESS_LS_07988cad` | 17.0 | 0.9996 | **57.0** | **WOULD CATCH (Flipped)** |
| `SESS_LS_19b286c3` | 14.0 | 0.9996 | 54.0 | Still Missed ($54.0 < 55$) |
| `SESS_LS_3f19893f` | 15.0 | 0.9730 | 53.9 | Still Missed ($53.9 < 55$) |
| `SESS_LS_4257d271` | 13.0 | 0.9996 | 53.0 | Still Missed ($53.0 < 55$) |
| `SESS_LS_f22590cd` | 11.0 | 0.9997 | 51.0 | Still Missed ($51.0 < 55$) |
| `SESS_LS_e7683a7b` | 12.0 | 0.9669 | 50.7 | Still Missed ($50.7 < 55$) |
| `SESS_LS_cb5a7202` | 11.0 | 0.9737 | 49.9 | Still Missed ($49.9 < 55$) |
| `SESS_LS_fd556a13` | 11.0 | 0.9630 | 49.5 | Still Missed ($49.5 < 55$) |
| `SESS_LS_d704e97e` | 9.0 | 0.9995 | 49.0 | Still Missed ($49.0 < 55$) |

### Summary of Fusion Impact
- **Flipped Sessions:** 3 out of 11 missed sessions cross the threshold to caught.
- **Normal False Positives:** **0 new FPs** added.
- **Analysis:** Because baseline fusion scores for low-bytes exfiltration sessions are extremely low (9.0 – 17.0 points), an additive boost of $+40$ is insufficient for sessions scoring below 15.0. Complete recovery in fusion requires either increasing XGB boost weight to $+46$, or introducing an explicit Tier 2 rule for high-confidence tree classification ($S_{\text{xgb}} > 0.95$).

---

## 8. Summary & Strategic Recommendations

### Comparative Summary Matrix

| Metric / Dimension | Transformer Sequence Model | XGBoost Decision Trees | Strategic Advantage |
| :--- | :--- | :--- | :--- |
| **Tabular Data Efficiency** | Requires sequence padding & positional embeddings | Native handling of non-linear tabular features | **XGBoost (+17.0% F1)** |
| **Low-Sample Generalization** | Prone to sequence/campaign memorization ($N=32$) | Robust boundary splits invariant to campaign identity | **XGBoost (100% LS Recall)** |
| **False Positive Rate** | 1.49% (47 normal FPs) | 0.16% (5 normal FPs) | **XGBoost (-89.4% FPs)** |
| **Sequential Temporal Context** | Explicit multi-event sequence attention | Relies on aggregated duration & entropy features | **Transformer** |
| **Training & Inference Speed** | Multi-minute GPU/CPU epoch training | Sub-second fitting & inference | **XGBoost** |

---

### Key Takeaways

1. **The Limitation is Architectural, Not Data-Inherent:**
   The recall gap on `low_and_slow_exfiltration` is not caused by missing features in `session_features.parquet`. The signal is fully present and extractable via tree-based partitioning.

2. **Dual-Model Architecture Recommendation:**
   For Phase 7 packaging or future production deployment, ARGUS should adopt a **hybrid ensemble design**:
   - **Transformer:** Retained for sequence-level anomaly representation and temporal trajectory modeling.
   - **XGBoost:** Integrated as a high-precision, tree-based classifier operating directly on non-linear session feature deviations.

3. **No Retraining or Dataset Regeneration Required:**
   The current ARGUS system remains fully restored and baseline-verified. This experiment confirms a clear, well-documented optimization path for future iterations without risking system stability.

---
*Report compiled automatically by ARGUS Evaluation Engine.*



## Pre-Integration Verification of XGBoost Comparison Results
*Added 2026-07-25. Read-only diagnostic verification of XGBoost 100% recall / 92.3% precision results.*

---

### CHECK 1 — Leakage Audit on `dev_*` / `peer_dev_*` Features

**Code Inspection (`src/ingest/build_features.py`):**

1. **Per-Entity Rolling Baseline (`dev_*`):**
   ```python
   # Lines 404-407 of src/ingest/build_features.py
   t_curr = pd.Timestamp(times[i])
   t_lo   = t_curr - timedelta(days=window_days)
   prior_mask = (grp["session_start"] >= t_lo) & (grp["session_start"] < t_curr)
   prior = grp[prior_mask]
   ```
   - **Causal / Temporal Check:** Strictly uses prior sessions in time (`session_start < t_curr`).
   - **Self-Exclusion Check:** The session being scored (`session_start == t_curr`) is strictly excluded from `prior_mask`.

2. **Per-Peer-Group Baseline (`peer_dev_*`):**
   ```python
   # Line 435 of src/ingest/build_features.py
   train_sf = sf.loc[train_mask & ~sf["is_malicious"]].copy()
   peer_stats = train_sf.groupby("_peer_key")[NUMERIC_FEATURES].agg(["mean", "std"])
   ```
   - **Train/Test Separation Check:** Peer group baselines (`mean` and `std` by `department|entity_type`) are computed **exclusively from benign training-split sessions** (`train_mask & ~is_malicious`).
   - **Test Session Exclusion:** Test-split sessions are strictly excluded from the peer group baseline computation.

**Leakage Verdict:** **NO LEAKAGE.** All baseline and deviation features obey strict temporal causality, exclude self-session values, and compute peer group statistics strictly on benign training sessions.

---

### CHECK 2 — Duration / Logoff Count Artifact Check

**Injector Inspection (`src/ingest/generate_dataset.py`):**
In `_inject_low_and_slow_exfiltration()` (lines 709–769), sessions are generated with exactly two events:
- A `logon` event at `start_time`.
- A `file_access` event at `start_time + timedelta(minutes=15)`.
- **No `logoff` event is ever injected.**

Consequently, `duration_min` is hardcoded to $15.00$ minutes (`(t_end - t_start) = 15 min`) and `logoff_count` is hardcoded to $0$.

**Empirical Distribution across Benchmark ($N=9,575$ sessions):**

| Attack / Category | Count ($N$) | `duration_min` (Mean ± Std) | `duration_min` Range | `logoff_count` (Mean ± Std) | Unique Values (`dur` / `logoff`) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `low_and_slow_exfiltration` | **56** | **15.00 ± 0.00** | **[15.00, 15.00]** | **0.00 ± 0.00** | **1 / 1** |
| `none` (Normal) | 9,265 | 195.18 ± 43.92 | [0.00, 270.00] | 1.00 ± 0.03 | 153 / 2 |
| `brute_force` | 7 | 2.37 ± 0.49 | [1.87, 3.07] | 0.00 ± 0.00 | 6 / 1 |
| `credential_misuse` | 7 | 17.86 ± 4.49 | [11.00, 23.00] | 0.00 ± 0.00 | 5 / 1 |
| `credential_stuffing` | 182 | 0.00 ± 0.00 | [0.00, 0.00] | 0.00 ± 0.00 | 1 / 1 |
| `device_spoofing` | 7 | 0.00 ± 0.00 | [0.00, 0.00] | 0.00 ± 0.00 | 1 / 1 |
| `impossible_travel` | 14 | 0.00 ± 0.00 | [0.00, 0.00] | 0.00 ± 0.00 | 1 / 1 |
| `lateral_movement` | 7 | 13.00 ± 0.00 | [13.00, 13.00] | 0.00 ± 0.00 | 1 / 1 |

**Artifact Verdict:** **FIXED-SIGNATURE GENERATOR ARTIFACT.** The zero variance on `duration_min` (std = 0.00) and `logoff_count` (std = 0.00) confirms that XGBoost's top feature importances (`logoff_count` gain 816.62, `duration_min` gain 624.13) reflect a fixed structural artifact of the synthetic generator (session duration = 15 min with missing logoff event), NOT an organically varying behavioral signal.

---

### CHECK 3 — Spot-Check Decision Logic on Test Sessions

Individual prediction feature contributions (tree SHAP log-odds) were extracted for 4 real `low_and_slow_exfiltration` test sessions:

| Session ID | `bytes_total` | Fused Score (Transformer) | XGB Probability | Top SHAP Feature Drivers & Log-Odds Contributions |
| :--- | :---: | :---: | :---: | :--- |
| `SESS_LS_fd556a13` | 200,000 B | 11.0 (Missed) | **0.9630** | `duration_min=15.0` (+3.88), `off_hours_flag=1` (+1.33), `logoff_count=0` (+1.03) |
| `SESS_LS_d704e97e` | 200,000 B | 9.0 (Missed) | **0.9995** | `duration_min=15.0` (+4.69), `off_hours_flag=1` (+1.26), `logoff_count=0` (+1.14) |
| `SESS_LS_2d84cfc3` | 12,244,400 B | 61.0 (Caught) | **0.9646** | `duration_min=15.0` (+3.89), `off_hours_flag=1` (+1.27), `logoff_count=0` (+1.03) |
| `SESS_LS_05cd6e81` | 12,244,400 B | 55.0 (Caught) | **0.9995** | `duration_min=15.0` (+4.68), `off_hours_flag=1` (+1.27), `logoff_count=0` (+1.16) |

**Decision Rationale Evaluation:**
- Across all 4 test sessions (both 200 KB low-bytes and 12.24 MB high-bytes), `bytes_total` contribution is near zero (<0.01 log-odds).
- XGBoost predicts high threat probability strictly because it matches the static synthetic tuple: `(duration_min == 15.0, logoff_count == 0, off_hours_flag == 1)`.
- This is a **generator quirk**, not a real-world plausible attacker signature. In a realistic environment with variable session lengths and missing/incomplete logoffs, this decision rule would produce high false positive rates or fail under evasion.

---

### Final Verdict & Corrected Performance Claim

**FINAL VERDICT: THE XGBOOST RESULT NEEDS CAVEATING.**

1. **Feature Leakage:** **NONE.** Feature pipeline math in `src/ingest/build_features.py` is clean and correctly isolated across train/test splits.
2. **Corrected Performance Claim:** The headline claim of **100% recall (24/24)** and **92.3% precision** for XGBoost is **not** evidence that XGBoost learned to detect gradual byte exfiltration or subtle behavioral deviations. Rather, XGBoost exploited a static synthetic generator artifact: every `low_and_slow` session was generated without a `logoff` event (`logoff_count == 0`) and with a constant 15-minute duration (`duration_min == 15.00`, std = 0.00), whereas 99.7% of normal background sessions last ~195 minutes and include a `logoff` event (`logoff_count == 1`).
3. **Action Recommendation:** **DO NOT replace or promote XGBoost into the live ARGUS pipeline based on these headline numbers.** The existing baseline Transformer/Fusion pipeline remains the verified system. Future modeling experiments must update synthetic session generation to include realistic session duration distributions and standard logoff events before tree-based classifiers can be fairly evaluated.
