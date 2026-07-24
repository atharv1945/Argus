# ARGUS Detection Core v1 — Evaluation Results

## Overview

This document reports Phase 2 detection results for two independent anomaly signals trained and evaluated on the ARGUS synthetic telemetry dataset (Phase 1 output, seed=42).

| Property | Value |
| :--- | :--- |
| **Dataset** | `data/processed/full_dataset.parquet` |
| **Total Sessions** | `8,873` |
| **Train Sessions** | `5,882` (normal: `5,864` + malicious: `18`) |
| **Test Sessions** | `2,991` (normal: `2,981` + malicious: `10`) |
| **Test Malicious Rate** | `0.334%` (realistic class imbalance preserved) |

---

## 1. Train/Test Split Strategy

**Malicious campaigns** — campaign-level hold-out, no event-level leakage:

| Attack Type | Train Campaigns | Test Campaigns |
| :--- | :--- | :--- |
| `credential_misuse` | ATK_CM_20260603, ATK_CM_20260607, ATK_CM_20260612, ATK_CM_20260614 | **ATK_CM_20260615, ATK_CM_20260616** |
| `brute_force` | ATK_BF_20260605, ATK_BF_20260608×2, ATK_BF_20260611 | **ATK_BF_20260613, ATK_BF_20260617** |
| `lateral_movement` | ATK_LM_20260607×2, ATK_LM_20260608, ATK_LM_20260614 | **ATK_LM_20260616, ATK_LM_20260620** |
| `impossible_travel` | ATK_IT_20260604, ATK_IT_20260609, ATK_IT_20260612_001 | **ATK_IT_20260612_004, ATK_IT_20260620** |
| `device_spoofing` | ATK_DS_20260606, ATK_DS_20260615, ATK_DS_20260616 | **ATK_DS_20260619, ATK_DS_20260620** |

**Normal traffic** — chronological split: events before `2026-06-14 00:00 UTC` → train, remainder → test.

Full manifest: `data/processed/split_manifest.json`

---

## 2. Feature Engineering

**Session-level features (17 base features):**
`duration_min`, `event_count`, `file_access_count`, `http_count`, `email_count`,
`device_connect_count`, `failure_ratio`, `distinct_resources`, `distinct_resource_depts`,
`distinct_devices`, `foreign_access_count`, `bytes_total`, `bytes_max`, `bytes_mean`,
`distinct_countries`, `distinct_ips`, `off_hours_flag`

**Rolling entity baseline (7-day trailing window):**
`roll_mean_*`, `roll_std_*`, `dev_*` — deviation from that entity's own trailing norm.
Sessions without enough history get NaN → imputed to 0 (no deviation assumed).

**Peer-group baseline (dept-level, fit on train-normal only):**
`peer_mean_*`, `peer_std_*`, `peer_dev_*` — deviation from departmental cohort.

**Total feature dimensionality:** 17 base + 17 entity-dev + 17 peer-dev = **51 features**

Output: `data/processed/session_features.parquet` (132 columns total including metadata)

---

## 3. Model A — Isolation Forest (Cold-Start Baseline)

**Architecture:** scikit-learn `IsolationForest`, n_estimators=200, contamination=0.01
**Training data:** Normal-only training sessions (5,864 sessions)
**Scoring:** Raw decision_function score negated → higher = more anomalous
**Decision threshold:** p95 of normal training scores = `-0.0542`
**Rationale:** Distribution-free unsupervised baseline — best signal for entities
with little or no history (cold-start entities). No label dependency.

### Overall Test Results

| Metric | Value |
| :--- | :--- |
| **Precision** | `0.074` |
| **Recall** | `1.000` |
| **F1** | `0.138` |
| **PR-AUC** | `1.000` ← primary metric (class imbalance) |
| **ROC-AUC** | `1.000` |
| Test sessions | `2,991` |
| Malicious test | `10` |

> **Note:** Low precision at threshold is expected — Isolation Forest flags ~5% of
> all sessions as anomalies (p95 threshold design). PR-AUC=1.000 means the ranking
> is perfect: all 10 malicious sessions scored higher than all normal sessions.

### Per-Attack-Type Results ⚠️ Small-Sample Estimates

> These are small-sample estimates. Each type has only **1-2 held-out campaigns**
> (~2 malicious sessions). Do not treat individual type precision/recall as reliable
> standalone estimates — treat them as directional indicators only.

| Attack Type | Precision | Recall | F1 | PR-AUC | Malicious Sessions | Campaigns |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `credential_misuse` | `0.016` | `1.000` | `0.031` | `1.000` | `2` | `2` |
| `brute_force` | `0.016` | `1.000` | `0.031` | `1.000` | `2` | `2` |
| `lateral_movement` | `0.016` | `1.000` | `0.031` | `1.000` | `2` | `2` |
| `impossible_travel` | `0.016` | `1.000` | `0.031` | `1.000` | `2` | `2` |
| `device_spoofing` | `0.016` | `1.000` | `0.031` | `1.000` | `2` | `2` |

---

## 4. Model B — Transformer Encoder (Temporal Sequence Model)

**Architecture:** Small custom Transformer encoder (PyTorch CPU)
- Input projection: 51 features → d_model=32
- Learnable positional embeddings, seq_len=8
- Encoder: 2 layers, 4 heads, dim_ff=64, pre-norm, GELU
- Classification head: d_model → 16 → 1 (sigmoid anomaly probability)

**Training configuration:**
- Loss: BCEWithLogitsLoss with pos_weight=303.6 (handles severe class imbalance)
- Optimizer: Adam, lr=1e-3, weight_decay=1e-4
- LR schedule: CosineAnnealingLR
- Gradient clipping: max_norm=1.0
- Epochs: 20, batch_size=128

**Training time:** 23 seconds (CPU-only)
**Weights file:** `src/models/transformer_weights.pt` (88 KB)

**Scoring:** Raw sigmoid probability → higher = more anomalous

**Architecture choice rationale:**
Binary classification (not reconstruction/autoencoder) chosen because:
1. We have labeled training campaigns — supervised signal is stronger than reconstruction.
2. pos_weight handles imbalance without discarding any training examples.
3. Continuous sigmoid output preserved for Phase 3 fusion layer.
4. Pre-norm TransformerEncoderLayer ensures stable training from epoch 1.

### Overall Test Results

| Metric | Value |
| :--- | :--- |
| **Precision** | `0.909` |
| **Recall** | `1.000` |
| **F1** | `0.952` |
| **PR-AUC** | `1.000` ← primary metric (class imbalance) |
| **ROC-AUC** | `1.000` |
| Test sessions | `2,991` |
| Malicious test | `10` |

### Per-Attack-Type Results ⚠️ Small-Sample Estimates

> Same caveat as Isolation Forest — 1-2 campaigns per type, ~2 malicious sessions each.

| Attack Type | Precision | Recall | F1 | PR-AUC | Malicious Sessions | Campaigns |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `credential_misuse` | `0.667` | `1.000` | `0.800` | `1.000` | `2` | `2` |
| `brute_force` | `0.667` | `1.000` | `0.800` | `1.000` | `2` | `2` |
| `lateral_movement` | `0.667` | `1.000` | `0.800` | `1.000` | `2` | `2` |
| `impossible_travel` | `0.667` | `1.000` | `0.800` | `1.000` | `2` | `2` |
| `device_spoofing` | `0.667` | `1.000` | `0.800` | `1.000` | `2` | `2` |

---

## 5. Model Comparison Summary

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | `0.074` | `1.000` | `0.138` | **`1.000`** | `1.000` | < 1 min (sklearn) |
| **Transformer Encoder** | `0.909` | `1.000` | `0.952` | **`1.000`** | `1.000` | 23s (CPU) |

**Key observations:**
- Both models achieve **perfect PR-AUC = 1.000 and ROC-AUC = 1.000** on the test set,
  meaning they successfully rank all 10 malicious sessions above all 2,981 normal sessions.
- The Transformer achieves higher precision (0.909 vs 0.074) at the default threshold
  because its supervised training signal allows a much tighter decision boundary.
- The Isolation Forest's low precision at threshold is by design (p95 = 5% FP rate)
  but its perfect ranking makes it valuable as a cold-start fallback for entities
  without training history.
- Both models are complementary — exactly the design goal for Phase 3 fusion.

---

## 6. Deliverables

| File | Description |
| :--- | :--- |
| `data/processed/split_manifest.json` | Campaign-to-split assignment for all 28 campaigns |
| `data/processed/session_features.parquet` | 8,873 sessions × 132 feature columns |
| `src/models/iforest_model.pkl` | Isolation Forest + RobustScaler + threshold |
| `data/processed/iforest_scores.parquet` | Per-session raw IF anomaly scores |
| `src/models/transformer_weights.pt` | Transformer encoder state_dict |
| `src/models/transformer_meta.pkl` | Feature columns, scaler, model hyper-params |
| `data/processed/transformer_scores.parquet` | Per-session raw sigmoid anomaly scores |

---

*Phase 3 input: both raw score files feed directly into the fusion layer.*
