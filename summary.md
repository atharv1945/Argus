# ARGUS Project Summary & File Structure

This document provides a comprehensive map of the ARGUS repository structure, detailing the role of each file and the key results achieved during **Phase 1 (Setup + Synthetic Data Generation)**, **Phase 2 (Detection Core v1)**, and **Phase 3 (Graph Layer + Anomaly-First Fusion)**.

---

## 1. Directory Tree & File Registry

```
argus/
 ├── .gitignore
 ├── README.md
 ├── requirements.txt
 ├── summary.md                             <-- [This File]
 ├── data/
 │    ├── README.md                          <-- 21-Field Schema Documentation
 │    ├── generators/
 │    │    └── gen_results_report.py         <-- Post-training evaluation markdown generator
 │    └── processed/
 │         ├── full_dataset.parquet          <-- Raw event stream (139k events, 21 columns)
 │         ├── dataset_summary.md            <-- Dataset stats & attack breakdowns
 │         ├── session_features.parquet      <-- Session aggregation with baseline features
 │         ├── split_manifest.json           <-- Campaign train/test split manifest
 │         ├── iforest_scores.parquet        <-- Isolation Forest inference scores
 │         ├── iforest_results.json          <-- Isolation Forest evaluation metrics
 │         ├── transformer_scores.parquet    <-- Transformer inference scores
 │         ├── transformer_results.json      <-- Transformer evaluation metrics
 │         ├── detection_core_v1_results.md  <-- Phase 2 consolidated results report
 │         ├── graph_features.parquet        <-- Phase 3 per-session graph heuristic signals
 │         ├── entity_graph.pkl              <-- Serialised EntityGraph (NetworkX)
 │         ├── fused_scores.parquet          <-- Phase 3 fused risk scores (9,476 sessions)
 │         ├── fusion_results.json           <-- Phase 3 machine-readable evaluation metrics
 │         └── fusion_eval_report.md         <-- Phase 3 human-readable evaluation report
 ├── notebooks/
 │    └── .gitkeep
 └── src/
      ├── ingest/
      │    ├── build_features.py             <-- Session aggregation & baseline feature engineer
      │    ├── generate_dataset.py           <-- Synthetic event generator (8 threat patterns)
      │    └── mask_labels.py                <-- Label-hiding/masking utility for inference
      ├── models/
      │    ├── isolation_forest.py           <-- Isolation Forest training & evaluation
      │    ├── sequence_model.py             <-- Transformer Sequence training & evaluation
      │    ├── iforest_model.pkl             <-- Saved IF model object & scaler
      │    ├── transformer_weights.pt        <-- PyTorch Transformer weights state_dict
      │    └── transformer_meta.pkl          <-- Hyperparameters, scaler, & model features
      ├── graph/
      │    └── entity_graph.py               <-- NetworkX graph builder + graph heuristic signals
      └── fusion/
           ├── anomaly_first_fusion.py       <-- 3-tier fusion engine (hard-rule > graph > model)
           ├── attack_classifier.py          <-- Rule-based attack type tagger (9 categories)
           └── evaluate_fusion.py            <-- End-to-end Phase 3 evaluation pipeline
```

---

## 2. Detailed File Descriptions

### Core Files
- **[README.md](file:///d:/Desktop%20Data/ML/Projects/Argus/README.md)**: Main workspace README describing build activation instructions and overall architecture.
- **[requirements.txt](file:///d:/Desktop%20Data/ML/Projects/Argus/requirements.txt)**: Specifies CPU-only project requirements: `pandas`, `numpy`, `scikit-learn`, `torch`, `scipy`, `streamlit`, `faiss-cpu`, `networkx`, and `faker`.
- **[.gitignore](file:///d:/Desktop%20Data/ML/Projects/Argus/.gitignore)**: Configured to ignore large binary files (`*.pkl`, `*.pt`), data parquet files, and standard virtual environments.

### Ingestion & Feature Engineering (`src/ingest/`)
- **[generate_dataset.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/ingest/generate_dataset.py)**: Simulates a 21-day timeline for 400 entities generating ~139K events across 21 raw schema fields. Includes generators for 7 malicious threat categories and 5 behaviorally distinct insider_drift benign campaigns.
- **[build_features.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/ingest/build_features.py)**: Groups event logs into 9,476 distinct sessions and constructs 81 features (17 base + rolling entity deviations + peer-group deviations stratified by dept+entity_type).
- **[mask_labels.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/ingest/mask_labels.py)**: Implements `mask_labels(df)` and `strip_labels(df)` to prevent label leakage during inference.

### Detection Core Models (`src/models/`)
- **[isolation_forest.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/models/isolation_forest.py)**: Trains scikit-learn `IsolationForest` on normal training sessions as an unsupervised cold-start detector. Saved to `iforest_model.pkl`.
- **[sequence_model.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/models/sequence_model.py)**: PyTorch CPU Transformer Encoder (2 layers, 4 heads, d=32). Trained with class-weighted BCE (pos_weight=48.9). Saved to `transformer_weights.pt`.

### Graph Layer (`src/graph/`)
- **[entity_graph.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/graph/entity_graph.py)**: Builds a directed NetworkX graph of entity->device and entity->resource edges from the raw event stream. Computes per-session temporal new-edge signals (`new_device_edge_count`, `new_resource_edge`), relational signals (`entity_fan_out`, `lateral_hop_score`), and exports `graph_features.parquet`. Graph: 1,023 nodes, 5,322 edges.

### Fusion Layer (`src/fusion/`)
- **[anomaly_first_fusion.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/fusion/anomaly_first_fusion.py)**: 3-tier priority fusion engine. Tier 1 (90-100): corroborated hard rules (fp_mismatch + new_device OR geo OR single-event). Tier 2 (55-89): graph_boost (lateral_hop, fan_out, new_device) lifts base_score above 0.55. Tier 3 (0-54): pure IF+Transformer blend. Outputs `fused_scores.parquet`.
- **[attack_classifier.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/fusion/attack_classifier.py)**: Deterministic rule chain providing human-readable `predicted_attack_type` label for every session. Calibrated to the synthetic data generator's actual output patterns. Accuracy: 93.6% (73/78 correctly labeled malicious test sessions).
- **[evaluate_fusion.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/fusion/evaluate_fusion.py)**: Orchestrates the full Phase 3 pipeline: graph build -> merge -> fusion -> evaluation. Saves `fusion_results.json` and `fusion_eval_report.md`.

---

## 3. Key Results of the Completed Phases

### Phase 1: Setup & Synthetic Data Generation (Patched to 20-Field Spec)
- Simulated **400 monitored entities** (339 users, 43 service accounts, 18 edge devices).
- Generated **~139K raw events** across 21 schema fields including `command_sequence`, `device_fingerprint`, `auth_method`, `entity_type`, and `session_duration`.
- Injected **35 distinct malicious campaigns** (5 per attack type) + **5 behaviorally distinct insider_drift benign campaigns**.

### Phase 2: Detection Core v1

| Model | Precision | Recall | F1 | PR-AUC | ROC-AUC |
|:------|:---------:|:------:|:--:|:------:|:-------:|
| **Isolation Forest** (Unsupervised) | 0.359 | 1.000 | 0.529 | **0.968** | 0.999 |
| **Transformer Encoder** (Supervised) | **0.681** | **0.987** | **0.806** | **0.986** | 0.999 |

Known limitations entering Phase 3:
- IF flags all insider_drift sessions (FPR=1.0) -- unsupervised density model cannot separate benign shifts
- Transformer recall=0 on impossible_travel and device_spoofing (single-event sessions, score ~0.479)

### Phase 3: Graph Layer + Anomaly-First Fusion

| Metric | Phase 2 Best | Phase 3 Fusion |
|:-------|:------------:|:--------------:|
| Precision | 0.681 | **0.772** |
| Recall | 0.987 | **1.000** |
| F1 | 0.806 | **0.872** |
| PR-AUC | 0.986 | **0.987** |
| ROC-AUC | 0.999 | **0.9997** |
| P@top-1% | 1.000 | **1.000** |
| insider_drift FPR | 0.0 | **0.0** |
| impossible_travel Recall | 0.0 | **1.000** |
| device_spoofing Recall | 0.0 | **1.000** |

All 7 attack types: **Recall = 1.000**.
False positive rate: **0.73%** (23 / 3,152 normal test sessions flagged).
Rule classifier accuracy: **93.6%** (73/78 correct attack type labels on malicious sessions).

#### Alert Tier Distribution (test split)

| Tier | Sessions | Attack Types Covered |
|------|----------|---------------------|
| **1** (Hard Rules, score 90-100) | 56 | credential_stuffing (52), device_spoofing (2), impossible_travel (2) |
| **2** (Graph-Boosted, score 55-89) | 45 | brute_force, credential_misuse, lateral_movement, low_and_slow_exfiltration |
| **3** (Model-Driven, score 0-54) | 0 | None -- all malicious sessions captured by tiers 1/2 |
