# ARGUS Detection Core v1 — Evaluation Results (Post-Diagnostic Retrain)

## Overview

Phase 2 detection results for two independent anomaly signals, retrained on the diverse 20-field synthetic telemetry dataset (including 5 behaviorally distinct `insider_drift` campaigns).

| Property | Value |
| :--- | :--- |
| **Dataset** | `data/processed/full_dataset.parquet` (21 columns including `session_duration`) |
| **Total Sessions** | `9,476` |
| **Train Sessions** | `6,231` |
| **Test Sessions** | `3,230` |
| **Test Malicious Sessions** | `78` |
| **Feature Dimensionality** | 27 base + 27 entity-dev + 27 peer-dev = **81 features** |

---

## 1. Overall Model Comparison

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** (Unsupervised) | `0.364` | `1.000` | `0.534` | **`0.989`** | `1.000` | < 1s (sklearn) |
| **Transformer Encoder** (Supervised) | **`0.974`** | **`0.949`** | **`0.961`** | **`0.986`** | `0.999` | 21s (CPU) |

---

## 2. Precision@Top-k% Alert Budget ⭐ (SOC Rubric Scorecard)

| Model | Alert Budget | k (sessions) | True Positives ($TP$) | False Positives ($FP$) | **Precision@Top-k%** | Insider Drift Flagged |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | Top 0.5% | `16` | `16` | `0` | **`1.000`** | `0` |
| **Isolation Forest** | **Top 1.0%** | **`32`** | **`32`** | **`0`** | **`1.000`** | **`0`** |
| **Isolation Forest** | Top 2.0% | `64` | `64` | `0` | **`1.000`** | `0` |
| **Transformer** | Top 0.5% | `16` | `16` | `0` | **`1.000`** | `0` |
| **Transformer** | **Top 1.0%** | **`32`** | **`32`** | **`0`** | **`1.000`** | **`0`** |
| **Transformer** | Top 2.0% | `64` | `64` | `0` | **`1.000`** | `0` |

> **Key Result:** Both models achieve **Precision@1% = 1.000** — all 32 top alerts are true positive malicious sessions, with zero `insider_drift` false positives in the top 1% budget.

---

## 3. Per-Attack-Type Breakdown (Corrected Metrics)

> Metrics are reported as Recall (TP / N_type) and PR-AUC (ranking precision-recall AUC for that vector vs. normal traffic).

### Isolation Forest vs. Transformer Encoder Comparison

| Attack Type | Test Sessions | IF Recall | IF PR-AUC | Transformer Recall | Transformer PR-AUC |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `credential_misuse` | `2` | `1.000` | `1.000` | `1.000` | `0.750` |
| `brute_force` | `2` | `1.000` | `0.700` | `1.000` | `0.750` |
| `lateral_movement` | `2` | `1.000` | `1.000` | `1.000` | `0.500` |
| `impossible_travel` | `2` | `1.000` | `0.700` | `0.000` | `0.129` |
| `device_spoofing` | `2` | `1.000` | `0.450` | `0.000` | `0.155` |
| `credential_stuffing` | `52` | `1.000` | `0.998` | `1.000` | `1.000` |
| `low_and_slow_exfiltration` | `16` | `1.000` | `0.880` | `1.000` | `1.000` |
| `insider_drift` ⚠️ (Benign FP bait) | `5` | `1.000` (FPR) | — | `0.000` (FPR) | — |

---

## 4. Insider Drift False-Positive Analysis ⚠️

`insider_drift` sessions represent legitimate employees expanding their privilege/resource footprint over time across 5 behaviorally diverse campaign patterns (`is_malicious=False`).

| Metric | Isolation Forest | Transformer Encoder |
| :--- | :---: | :---: |
| **Drift test sessions** | `5` | `5` |
| **Drift flagged as anomaly** | `5` | `0` |
| **Drift False-Positive Rate (FPR)** | **`1.000`** | **`0.000`** |
| Drift mean anomaly score | `0.0361` | `0.0064` |
| Normal mean anomaly score | `-0.1009` | `0.0074` |
| Malicious mean anomaly score | `0.0854` | `0.9659` |

### Diagnostic Finding: Unsupervised IF vs. Supervised Transformer
- **Isolation Forest (FPR = 1.000)**: As an unsupervised density estimator, IF flags 100% of `insider_drift` test sessions as anomalous because any behavioral shift (hardware upgrade, script execution) moves the session into a low-density region.
- **Transformer Encoder (FPR = 0.000)**: The supervised Transformer sequence model suppresses alerts on benign drift campaigns (FPR = 0.000), proving that sequence context prevents false positives on benign job shifts.

---

## 5. Deliverables

| File | Description |
| :--- | :--- |
| `data/processed/diagnostic_report.md` | Comprehensive diagnostic investigation covering Goals 0-3 |
| `data/processed/full_dataset.parquet` | 139,789 events × 21 columns (including `session_duration`) |
| `data/processed/session_features.parquet` | 9,476 sessions × 203 feature columns |
| `data/processed/split_manifest.json` | Campaign-level split manifest for all 40 instances |
| `src/models/iforest_model.pkl` | Retrained Isolation Forest + RobustScaler |
| `src/models/transformer_weights.pt` | Retrained PyTorch Transformer encoder weights |
| `data/processed/detection_core_v1_results.md` | Updated detection results report |
