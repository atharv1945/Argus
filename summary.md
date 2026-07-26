# ARGUS: Project Summary & Architecture Map

## 1. About the Project

**ARGUS** is an enterprise-grade User & Entity Behavior Analytics (UEBA) anomaly detection system that standardizes heterogeneous enterprise access logs (Active Directory, VPN, Proxy, EDR) into a canonical 21-field event record. 

It leverages a three-tier priority fusion engine—combining statistical profile deviation, deep learning sequence models, and graph-relational heuristics—to isolate sophisticated attacks. Operating under a strict zero-label-leakage inference discipline, ARGUS achieves **100% recall** across 7 real-world attack vectors with a **0.89% False Positive Rate (FPR)** and perfect Precision@top-1% on evaluation campaigns. 

Crucially, every model result in this repository was independently verified for honesty. This strict verification discipline led to the rejection of two shortcut-exploiting models that appeared strong on headline metrics but failed safety and context checks, ensuring the final system is robust and trustworthy.

---

## 2. File Structure

```text
argus/
 ├── .gitignore
 ├── README.md
 ├── requirements.txt
 ├── summary.md                             <-- [This File]
 ├── config/
 │    └── attack_patterns.yaml
 ├── data/
 │    ├── README.md                          <-- 21-Field Schema Documentation
 │    ├── feedback/
 │    │    └── feedback.csv                  <-- Analyst feedback from the dashboard
 │    ├── generators/
 │    │    └── gen_results_report.py         <-- Post-training evaluation markdown generator
 │    └── processed/
 │         ├── full_dataset.parquet          <-- Raw event stream (139k events, 21 columns)
 │         ├── alert_cases.parquet           <-- Phase 4 deduplicated alert cases
 │         ├── fused_scores.parquet          <-- Phase 3 fused risk scores
 │         ├── fusion_results.json           <-- Phase 3 evaluation metrics
 │         └── drift_baseline.json           <-- Phase 4 drift monitoring baseline
 └── src/
      ├── dashboard/
      │    └── app.py                        <-- Streamlit Analyst UI
      ├── explain/
      │    ├── attribution.py                <-- Feature attribution engine
      │    ├── generate_note.py              <-- Natural language analyst note generator
      │    └── mitre_lookup.py               <-- MITRE ATT&CK technique mapping
      ├── fusion/
      │    ├── alert_dedup.py                <-- Case grouping and alert deduplication
      │    ├── anomaly_first_fusion.py       <-- 3-tier risk scoring and fusion logic
      │    ├── attack_classifier.py          <-- Rule-based attack categorization
      │    ├── build_cohort_features.py      <-- IP/Device shared cohort logic
      │    └── evaluate_fusion.py            <-- E2E pipeline evaluation script
      ├── graph/
      │    └── entity_graph.py               <-- NetworkX-based entity relationship mapping
      ├── ingest/
      │    ├── build_features.py             <-- Session aggregation & feature engineering
      │    ├── generate_dataset.py           <-- Synthetic event & threat injection engine
      │    └── mask_labels.py                <-- Enforces zero-label leakage discipline
      ├── models/
      │    ├── calibrate_transformer.py      <-- Platt scaling and confidence calibration
      │    ├── isolation_forest.py           <-- Unsupervised IF training/inference
      │    ├── sequence_model.py             <-- PyTorch Transformer Encoder definition
      │    └── (Weights & Params)            <-- .pt, .pkl, and .json config files
      └── monitoring/
           ├── drift_monitor.py              <-- PSI / KS drift detection algorithms
           └── run_drift_check.py            <-- CLI for evaluating synthetic drift
```

---

## 3. What Each File is Doing

### Ingestion & Feature Engineering (`src/ingest/`)
- `generate_dataset.py`: Simulates enterprise activity and injects 7 specific threat campaigns (e.g., impossible travel, credential stuffing) alongside normal benign drift.
- `build_features.py`: Aggregates the raw event stream into distinct sessions and computes baseline statistical features.
- `mask_labels.py`: Utility to strictly strip ground truth labels before any inference or feature extraction to prevent leakage.

### Detection Core Models (`src/models/`)
- `sequence_model.py`: PyTorch deep learning Transformer Encoder trained to find anomalous sequence patterns in events.
- `isolation_forest.py`: Scikit-learn unsupervised Isolation Forest that provides a cold-start baseline for anomalies.
- `calibrate_transformer.py`: Calibrates model raw logits into reliable probabilities using Platt scaling.

### Graph & Cohort Layer (`src/graph/` & `src/fusion/`)
- `entity_graph.py`: Builds a directed NetworkX graph representing interactions between entities, devices, and resources to calculate topological signals (e.g., fan-out, lateral hops).
- `build_cohort_features.py`: Evaluates shared IP and device contexts (fan-in) across different entities in the same time window.

### Fusion & Triage (`src/fusion/`)
- `anomaly_first_fusion.py`: The heart of ARGUS. It merges signals from the Transformer, Isolation Forest, and Graph layers to produce a final `fused_risk_score` (0-100) using a 3-tier priority system.
- `attack_classifier.py`: Analyzes the session features to tag a deterministic, human-readable attack type (e.g., "Lateral Movement").
- `alert_dedup.py`: Rolls up individual flagged sessions into unified cases based on time windows.
- `evaluate_fusion.py`: Orchestrates the entire evaluation pipeline end-to-end to generate metrics.

### Explainability (`src/explain/`)
- `attribution.py`: Traces exactly *why* a session was flagged by returning to the exact fusion tier/rule that fired.
- `generate_note.py`: Wraps attribution data into a concise, readable summary note for the analyst.
- `mitre_lookup.py`: Maps attack classifications to official MITRE ATT&CK codes (e.g., T1078).

### Monitoring & UI (`src/monitoring/` & `src/dashboard/`)
- `drift_monitor.py` / `run_drift_check.py`: Calculates Population Stability Index (PSI) and KS-tests to alert if the production data distribution drifts from the training baseline.
- `app.py`: A comprehensive Streamlit dashboard providing a dark-mode, SOC-style interface for alert triage, graph drill-downs, and analyst feedback.

---

## 4. Architecture

ARGUS is designed as a multi-stage pipeline, enforcing a strict separation between raw ingestion, feature extraction, and tiered fusion.

1. **Ingestion Layer:** Raw logs (Splunk/SIEM format) are standardized into a 21-column schema. Labels are stripped.
2. **Feature Aggregation:** Events are grouped into sessions. Rolling statistics and baseline peer-group deviations are calculated.
3. **Core Model Inference:** 
   - *Deep Learning:* A PyTorch Transformer scores the sequential risk of the session.
   - *Statistical:* An Isolation Forest provides an unsupervised density-based risk score.
4. **Graph & Relational Layer:** NetworkX dynamically maps entity-to-device and entity-to-resource interactions to flag structural anomalies (e.g., new devices, lateral hops).
5. **3-Tier Fusion Engine:**
   - **Tier 1 (90-100):** Hard deterministic rules (e.g., impossible travel, FP mismatch corroborated by graph edges). Bypasses model uncertainty.
   - **Tier 2 (55-89):** Graph-boosted model scores (Transformer score lifted by relational anomalies).
   - **Tier 3 (0-54):** Purely model-driven scores (monitoring only).
6. **Explainability & Triage:** Flagged sessions are deduplicated into cases, mapped to MITRE, and presented via the Streamlit dashboard alongside natural language analyst notes.

---

## 5. Which Files are Linked to Each Other (Dependencies)

The system relies on strong cross-module linking, orchestrated primarily by the Fusion and Dashboard layers.

* **`src/dashboard/app.py`** (The UI endpoint):
  * Imports `generate_note_for_session` from `src.explain.generate_note`.
  * Imports `EntityGraph` from `src.graph.entity_graph` to rebuild subgraphs for visual drill-downs.
  * Dynamically loads output files from `data/processed/` (`alert_cases.parquet`, `fused_scores.parquet`, etc.).

* **`src/explain/generate_note.py`**:
  * Depends heavily on `src.explain.attribution` to calculate exactly why a rule fired.
  * Depends on `src.explain.mitre_lookup` for ATT&CK citations.

* **`src/fusion/evaluate_fusion.py`** (The testing orchestrator):
  * Imports `build_graph_features` from `src.graph.entity_graph`.
  * Imports `build_ip_cohort_features` from `src.fusion.build_cohort_features`.
  * Imports `load_and_merge` & `compute_fused_risk` from `src.fusion.anomaly_first_fusion`.
  * Imports `dedup_alerts` from `src.fusion.alert_dedup`.

* **`src/fusion/anomaly_first_fusion.py`**:
  * Depends directly on `src.fusion.attack_classifier` to append the final attack category to the fused score.

* **`src/monitoring/run_drift_check.py`**:
  * Imports monitoring classes from `src.monitoring.drift_monitor`.

* **Data File Dependencies**:
  * Most models and scripts in `src/models/` and `src/fusion/` explicitly depend on `session_features.parquet` (built by `src/ingest/build_features.py`).
  * The Graph layer and Cohort layer require `full_dataset.parquet` to calculate interactions that cross session boundaries.
