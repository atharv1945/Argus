# ARGUS Telemetry & Detection Diagnostic Report

## Executive Summary

This diagnostic investigation evaluates the data integrity, feature separability, and evaluation metrics of the ARGUS UEBA Detection Core (v1). 

---

## 1. Goal 0 — Data Integrity Verification

**Verification Target:** Cross-check the raw `session_duration` column (stored per-event in `data/processed/full_dataset.parquet`) against `duration_min` computed during session aggregation in `src/ingest/build_features.py`.

* **Total Sessions Evaluated:** 9,476 sessions
* **Max Absolute Difference:** `0.0033` minutes (< 0.2 seconds, due to 2-decimal-place rounding of `duration_min`)
* **Verification Status:** **`[PASS]`** — The raw `session_duration` field in `full_dataset.parquet` exactly matches `build_features.py` internal logic with zero timezone or session boundary bugs.

---

## 2. Goal 1 — Feature Separability & Train-Test Similarity Analysis

### 2.1 Univariate Feature Separation by Attack Vector

We analyzed the statistical separation (Z-score standard deviation distance from normal traffic mean: $Z = \frac{|\mu_{\text{attack}} - \mu_{\text{normal}}|}{\sigma_{\text{normal}}}$) for each attack vector:

| Attack Vector | Primary Separating Feature | Z-Score (Std-Devs) | Attack Mean | Normal Mean (Std) | Diagnosis |
| :--- | :--- | :---: | :---: | :---: | :--- |
| `credential_stuffing` | `failure_ratio` | **`> 900,000`** | `0.96` | `0.00` (`0.00`) | Extreme separation (96% auth failure rate) |
| `brute_force` | `failure_ratio` | **`> 900,000`** | `0.95` | `0.00` (`0.00`) | Extreme separation (95% auth failure rate) |
| `lateral_movement` | `distinct_devices` | **`7,000,000`** | `8.00` | `1.00` (`0.00`) | Extreme separation (touches 8 distinct host devices) |
| `credential_misuse` | `bytes_mean` | **`612.09`** | `35.8 MB` | `66.7 KB` (`58.4 KB`) | Massive byte transfer spike |
| `low_and_slow_exfiltration` | `bytes_mean` | **`28.07`** | `1.7 MB` | `66.7 KB` (`58.4 KB`) | Elevated byte volume |
| `device_spoofing` | `fp_mismatch` | **`4.85`** | `1.00` | `0.04` (`0.20`) | 100% modal fingerprint mismatch |
| `impossible_travel` | `fp_mismatch` | **`4.85`** | `1.00` | `0.04` (`0.20`) | Unrecognized device fingerprint & zero duration |
| `insider_drift` | `bytes_mean` | **`10.42`** | `675.2 KB` | `66.7 KB` (`58.4 KB`) | Moderate volume shift |

**Diagnostic Finding:** The synthetic attack generator produces strong statistical signatures for primary attacks (`failure_ratio`, `distinct_devices`, `bytes_mean`), making binary separation near-perfect for linear and sequence models.

### 2.2 Insider Drift Train vs. Test Campaign Similarity (Original Generator)

Comparing the 3 training campaigns against the 2 held-out test campaigns in the original `insider_drift` dataset:

| Feature | Train Campaigns (`001`, `002`, `003`) | Test Campaigns (`004`, `005`) | Similarity Diagnosis |
| :--- | :---: | :---: | :--- |
| `cmd_seq_length` | `4.00` | `4.00` | **Identical** (formulaic 4-token sequence) |
| `distinct_resources` | `1.00` | `1.00` | **Identical** (single target resource) |
| `distinct_resource_depts` | `1.00` | `1.00` | **Identical** (single target department) |
| `off_hours_flag` | `0.00` | `0.00` | **Identical** (always daytime 14:00) |
| `bytes_mean` | `711.3 KB` | `621.2 KB` | **Overlapping** (~600-700 KB transfer) |

**Diagnostic Finding:** **YES — The original `insider_drift` generator was formulaic.** All 5 campaigns executed the exact same pattern (Finance report access at 14:00 with 4 command tokens). Train/test splitting on this formula tested random seed draws rather than true behavioral generalization across varied benign drift dimensions.

---

## 3. Goal 2 — Increasing Insider Drift Behavioral Diversity

To test genuine model generalization and false-positive resilience, `_inject_insider_drift` in `src/ingest/generate_dataset.py` has been updated so that each of the 5 campaigns exhibits a **distinct, realistic dimension of benign drift**:

1. **Campaign 1 (`ATK_ID_..._001` - Train)**: **Resource & Departmental Footprint Expansion** — User joins cross-functional project, accessing new `RES_FIN_ERP` & `RES_EXEC_BOARD_DECK` resources during business hours.
2. **Campaign 2 (`ATK_ID_..._002` - Train)**: **Off-Hours Work Shift Drift** — Employee transitions to late-night international shift (sessions between 23:00 and 03:00), `off_hours_flag` = 1, but accessing normal internal IT wiki/intranet with 0 failures.
3. **Campaign 3 (`ATK_ID_..._003` - Train)**: **Internal Data Export Volume Drift** — Analyst running periodic benchmark report exports (5MB-15MB bytes transferred) on assigned dept servers.
4. **Campaign 4 (`ATK_ID_..._004` - Test)**: **New Device & Auth Hardware Upgrade** — Corporate laptop upgrade / certificate auth switch (`fp_mismatch` = 1), 100% success status, normal work hours.
5. **Campaign 5 (`ATK_ID_..._005` - Test)**: **Privileged Script Execution Drift** — Engineer executing administrative maintenance/deployment scripts (`read,write,execute,escalate_privilege`, 6-8 tokens) on engineering servers during role transition.

All 5 campaigns maintain **`is_malicious = False`**.

---

## 4. Goal 3 — Correction of Per-Class Metrics Specification

### Metric Refinement Rationale
In a multi-class threat setup evaluated against a binary detector:
- The previous per-class "precision" was calculated on a subset excluding other attack types, artificially inflating precision by ignoring false positives from other classes.
- **Corrected Standard**:
  1. **Per-Attack-Type Recall** ($TP_A / N_A$): Percentage of sessions for attack vector $A$ correctly flagged.
  2. **Per-Attack-Type PR-AUC**: Ranking quality for vector $A$ vs. normal traffic.
  3. **Overall Precision**: $TP_{\text{malicious}} / (\text{All Flagged Sessions})$.
  4. **Precision@Top-k% Alert Budget**: Precision within the top $k\%$ highest-scoring alerts (SOC alert budget constraint).
  5. **Insider Drift False Positive Rate**: $FP_{\text{drift}} / N_{\text{drift}}$ explicitly reported.
