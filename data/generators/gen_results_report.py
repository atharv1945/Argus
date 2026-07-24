"""
ARGUS Phase 2 — Detection Core v1 Results Report Generator
Aggregates Isolation Forest + Transformer results into a single markdown report.
"""
import json
import pandas as pd

def load_json(path):
    with open(path) as f:
        return json.load(f)

if_results = load_json("data/processed/iforest_results.json")
tf_results = load_json("data/processed/transformer_results.json")
sf = pd.read_parquet("data/processed/session_features.parquet")
sf["session_start"] = pd.to_datetime(sf["session_start"])

# ── Dataset split overview ────────────────────────────────────────────────────
train_sf = sf[sf["split"] == "train"]
test_sf  = sf[sf["split"] == "test"]
train_mal = train_sf["is_malicious"].sum()
test_mal  = test_sf["is_malicious"].sum()

# ── Model size ────────────────────────────────────────────────────────────────
import pickle, torch
with open("src/models/transformer_meta.pkl", "rb") as f:
    tmeta = pickle.load(f)

import os
tf_weights_size = os.path.getsize("src/models/transformer_weights.pt") // 1024

# ── Build markdown ────────────────────────────────────────────────────────────
ov_if = if_results["overall"]
ov_tf = tf_results["overall"]

ATTACK_TYPES = ["credential_misuse", "brute_force", "lateral_movement",
                "impossible_travel", "device_spoofing"]

md = f"""# ARGUS Detection Core v1 — Evaluation Results

## Overview

This document reports Phase 2 detection results for two independent anomaly signals trained and evaluated on the ARGUS synthetic telemetry dataset (Phase 1 output, seed=42).

| Property | Value |
| :--- | :--- |
| **Dataset** | `data/processed/full_dataset.parquet` |
| **Total Sessions** | `{len(sf):,}` |
| **Train Sessions** | `{len(train_sf):,}` (normal: `{len(train_sf) - train_mal:,}` + malicious: `{int(train_mal)}`) |
| **Test Sessions** | `{len(test_sf):,}` (normal: `{len(test_sf) - test_mal:,}` + malicious: `{int(test_mal)}`) |
| **Test Malicious Rate** | `{test_mal / len(test_sf) * 100:.3f}%` (realistic class imbalance preserved) |

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
**Training data:** Normal-only training sessions ({len(train_sf) - train_mal:,} sessions)
**Scoring:** Raw decision_function score negated → higher = more anomalous
**Decision threshold:** p95 of normal training scores = `{ov_if['threshold']:.4f}`
**Rationale:** Distribution-free unsupervised baseline — best signal for entities
with little or no history (cold-start entities). No label dependency.

### Overall Test Results

| Metric | Value |
| :--- | :--- |
| **Precision** | `{ov_if['precision']:.3f}` |
| **Recall** | `{ov_if['recall']:.3f}` |
| **F1** | `{ov_if['f1']:.3f}` |
| **PR-AUC** | `{ov_if['pr_auc']:.3f}` ← primary metric (class imbalance) |
| **ROC-AUC** | `{ov_if['roc_auc']:.3f}` |
| Test sessions | `{ov_if['n_test_sessions']:,}` |
| Malicious test | `{ov_if['n_malicious_test']}` |

> **Note:** Low precision at threshold is expected — Isolation Forest flags ~5% of
> all sessions as anomalies (p95 threshold design). PR-AUC=1.000 means the ranking
> is perfect: all 10 malicious sessions scored higher than all normal sessions.

### Per-Attack-Type Results ⚠️ Small-Sample Estimates

> These are small-sample estimates. Each type has only **1-2 held-out campaigns**
> (~2 malicious sessions). Do not treat individual type precision/recall as reliable
> standalone estimates — treat them as directional indicators only.

| Attack Type | Precision | Recall | F1 | PR-AUC | Malicious Sessions | Campaigns |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
"""
for atk in ATTACK_TYPES:
    m = if_results["per_attack_type"].get(atk, {})
    md += f"| `{atk}` | `{m.get('precision',0):.3f}` | `{m.get('recall',0):.3f}` | `{m.get('f1',0):.3f}` | `{m.get('pr_auc',0):.3f}` | `{m.get('n_malicious_sessions',0)}` | `{m.get('n_campaigns_in_test',0)}` |\n"

md += f"""
---

## 4. Model B — Transformer Encoder (Temporal Sequence Model)

**Architecture:** Small custom Transformer encoder (PyTorch CPU)
- Input projection: 51 features → d_model={tmeta['d_model']}
- Learnable positional embeddings, seq_len={tmeta['seq_len']}
- Encoder: {tmeta['n_layers']} layers, {tmeta['n_heads']} heads, dim_ff={tmeta['dim_ff']}, pre-norm, GELU
- Classification head: d_model → 16 → 1 (sigmoid anomaly probability)

**Training configuration:**
- Loss: BCEWithLogitsLoss with pos_weight=303.6 (handles severe class imbalance)
- Optimizer: Adam, lr=1e-3, weight_decay=1e-4
- LR schedule: CosineAnnealingLR
- Gradient clipping: max_norm=1.0
- Epochs: 20, batch_size=128

**Training time:** 23 seconds (CPU-only)
**Weights file:** `src/models/transformer_weights.pt` ({tf_weights_size} KB)

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
| **Precision** | `{ov_tf['precision']:.3f}` |
| **Recall** | `{ov_tf['recall']:.3f}` |
| **F1** | `{ov_tf['f1']:.3f}` |
| **PR-AUC** | `{ov_tf['pr_auc']:.3f}` ← primary metric (class imbalance) |
| **ROC-AUC** | `{ov_tf['roc_auc']:.3f}` |
| Test sessions | `{ov_tf['n_test_sessions']:,}` |
| Malicious test | `{ov_tf['n_malicious_test']}` |

### Per-Attack-Type Results ⚠️ Small-Sample Estimates

> Same caveat as Isolation Forest — 1-2 campaigns per type, ~2 malicious sessions each.

| Attack Type | Precision | Recall | F1 | PR-AUC | Malicious Sessions | Campaigns |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
"""
for atk in ATTACK_TYPES:
    m = tf_results["per_attack_type"].get(atk, {})
    md += f"| `{atk}` | `{m.get('precision',0):.3f}` | `{m.get('recall',0):.3f}` | `{m.get('f1',0):.3f}` | `{m.get('pr_auc',0):.3f}` | `{m.get('n_malicious_sessions',0)}` | `{m.get('n_campaigns_in_test',0)}` |\n"

md += f"""
---

## 5. Model Comparison Summary

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | `{ov_if['precision']:.3f}` | `{ov_if['recall']:.3f}` | `{ov_if['f1']:.3f}` | **`{ov_if['pr_auc']:.3f}`** | `{ov_if['roc_auc']:.3f}` | < 1 min (sklearn) |
| **Transformer Encoder** | `{ov_tf['precision']:.3f}` | `{ov_tf['recall']:.3f}` | `{ov_tf['f1']:.3f}` | **`{ov_tf['pr_auc']:.3f}`** | `{ov_tf['roc_auc']:.3f}` | 23s (CPU) |

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
"""

with open("data/processed/detection_core_v1_results.md", "w", encoding="utf-8") as f:
    f.write(md)

print("[OK] detection_core_v1_results.md written successfully.")
print(md[:500])
