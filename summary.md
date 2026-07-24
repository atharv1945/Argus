# ARGUS Project Summary & File Structure

This document provides a comprehensive map of the ARGUS repository structure, detailing the role of each file and the key results achieved during **Phase 1 (Setup + Synthetic Data Generation)** and **Phase 2 (Detection Core v1)**.

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
 │         └── detection_core_v1_results.md  <-- Consolidated results report
 ├── notebooks/
 │    └── .gitkeep
 └── src/
      ├── ingest/
      │    ├── build_features.py             <-- Session aggregation & baseline feature engineer
      │    ├── generate_dataset.py           <-- Synthetic event generator (8 threat patterns)
      │    └── mask_labels.py                <-- Label-hiding/masking utility for inference
      └── models/
           ├── isolation_forest.py           <-- Isolation Forest training & evaluation
           ├── sequence_model.py             <-- Transformer Sequence training & evaluation
           ├── iforest_model.pkl             <-- Saved IF model object & scaler
           ├── transformer_weights.pt        <-- PyTorch Transformer weights state_dict
           └── transformer_meta.pkl          <-- Hyperparameters, scaler, & model features
```

---

## 2. Detailed File Descriptions

### Core Files
- **[README.md](file:///d:/Desktop%20Data/ML/Projects/Argus/README.md)**: Main workspace README describing build activation instructions (`source venv/Scripts/activate`) and overall architecture.
- **[requirements.txt](file:///d:/Desktop%20Data/ML/Projects/Argus/requirements.txt)**: Specifies project requirements for CPU-only local execution: `pandas`, `numpy`, `scikit-learn`, `torch` (CPU build), `scipy`, `streamlit`, `faiss-cpu`, `networkx`, and `faker`.
- **[.gitignore](file:///d:/Desktop%20Data/ML/Projects/Argus/.gitignore)**: Configured to ignore large binary files (`*.pkl`, `*.pt`), data parquet files, and standard virtual environments.

### Ingestion & Feature Engineering (`src/ingest/`)
- **[generate_dataset.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/ingest/generate_dataset.py)**: Simulates a 21-day timeline for 400 entities generating 139,789 events across 21 raw schema fields. Includes generators for 7 malicious threat categories and 1 benign false-positive bait scenario.
- **[build_features.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/ingest/build_features.py)**: Groups event logs into 9,476 distinct sessions and constructs 81 features. Includes 17 base features, 7-day rolling entity baseline deviations (`dev_*`), and cohort-based peer-group baseline deviations (`peer_dev_*`) stratified by department and entity type.
- **[mask_labels.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/ingest/mask_labels.py)**: Implements `mask_labels(df)` and `strip_labels(df)` to support label-hiding discipline. Ensures evaluation is performed honestly by preventing label leakage into features.

### Detection Core Models (`src/models/`)
- **[isolation_forest.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/models/isolation_forest.py)**: Trains scikit-learn `IsolationForest` on normal training sessions as an unsupervised cold-start detector. Saves model binary to `iforest_model.pkl`.
- **[sequence_model.py](file:///d:/Desktop%20Data/ML/Projects/Argus/src/models/sequence_model.py)**: Implements a PyTorch CPU-friendly Transformer Encoder (2 layers, 4 attention heads, $d_{\text{model}}=32$) trained using sequence-length context and class-weighted BCE loss (`pos_weight = 48.9`) to handle telemetry imbalance. Saves state dict to `transformer_weights.pt`.

---

## 3. Key Results of the Completed Phases

### Phase 1: Setup & Synthetic Data Generation (Patch Retrained)
- Simulated **400 monitored entities** (339 users, 43 service accounts, 18 edge devices).
- Generated **139,789 raw logs** standardizing VPN, Active Directory, proxy, file server, and device connections.
- Mapped **21 schema fields** including new telemetry categories: `command_sequence` (privileged sessions), `device_fingerprint` (OS, MAC address, protocol), `auth_method`, and `session_duration`.
- Injected **35 distinct threat campaigns** (5 campaigns each for 7 malicious vectors) + **5 insider_drift benign drift campaigns**.

### Phase 2: Detection Core v1 & Retraining Results
The models were trained on training campaigns and evaluated on a held-out test split (**3,235 sessions**, containing 78 malicious sessions and 10 benign `insider_drift` false-positive bait sessions).

#### Overall Metrics

| Model | Precision | Recall | F1 Score | PR-AUC (Primary) | ROC-AUC | Training Time |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** (Unsupervised) | `0.359` | `1.000` | `0.529` | **`0.968`** | `0.999` | < 1 sec |
| **Transformer Encoder** (Supervised) | **`0.681`** | **`0.987`** | **`0.806`** | **`0.986`** | `0.999` | 15 sec (CPU) |

#### Precision@Top-k% Alert Budget (Rubric Score Card)

| Model | Alert Budget (k% of Test) | Budget Size ($k$ sessions) | True Positives ($TP$) | False Positives ($FP$) | **Precision@Top-k%** | Insider Drift Flagged |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Isolation Forest** | Top 0.5% | 16 | 16 | 0 | **`1.000`** | 0 |
| **Isolation Forest** | **Top 1.0%** | **32** | **32** | **0** | **`1.000`** | **0** |
| **Isolation Forest** | Top 2.0% | 64 | 60 | 4 | **`0.938`** | 2 |
| **Transformer** | Top 0.5% | 16 | 16 | 0 | **`1.000`** | 0 |
| **Transformer** | **Top 1.0%** | **32** | **32** | **0** | **`1.000`** | **0** |
| **Transformer** | Top 2.0% | 64 | 64 | 0 | **`1.000`** | 0 |

#### Insider Drift FP Bait Analysis

`insider_drift` represents normal users expanding their job footprint. They are labeled `is_malicious=False` but are highly anomalous relative to their historical peer cohorts.

* **Isolation Forest (FP Rate = 1.000)**: Flags **all 10** drift test sessions as anomalies. This is an expected limitation of unsupervised density models that cannot distinguish benign shifts from malicious ones.
* **Transformer Encoder (FP Rate = 0.000)**: Flags **0** drift sessions, successfully learning sequence context to suppress benign alerts.
* **Fusion Strategy**: This variance directly justifies Phase 3, where graph-based context and score fusion will be built to blend these complementary behaviors.
