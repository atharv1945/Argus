# ARGUS: Adaptive Risk & Graph-based Unified Security

**Live Dashboard**: [https://arguskavachh.streamlit.app/](https://arguskavachh.streamlit.app/)

**ARGUS** is an enterprise-grade User & Entity Behavior Analytics (UEBA) anomaly detection system that standardizes heterogeneous enterprise access logs (Active Directory, VPN, Proxy, EDR) into a canonical 21-field event record. It leverages a three-tier priority fusion engine—combining statistical profile deviation, deep learning sequence models, and graph-relational heuristics—to isolate sophisticated attacks. 

Operating under a strict zero-label-leakage inference discipline, ARGUS achieves **100% recall** across 7 real-world attack vectors with a **0.89% False Positive Rate (FPR)** and perfect Precision@top-1% on evaluation campaigns. Crucially, every model result in this repository was independently verified, leading to the rejection of two shortcut-exploiting models that appeared strong on headline metrics but failed safety checks.

## System Architecture & File Structure

```text
argus/
 ├── config/            # Attack pattern specs
 ├── data/
 │    ├── feedback/     # Analyst UI feedback logs
 │    ├── generators/   # Synthetic dataset generators
 │    └── processed/    # Core data pipeline inputs & outputs (Streamlit assets)
 ├── experiments/       # Independent verification reports and experimental model comparisons
 ├── src/
 │    ├── dashboard/    # Streamlit Analyst Dashboard
 │    ├── explain/      # Natural language feature attribution & MITRE mapping
 │    ├── fusion/       # 3-Tier Fusion Engine (Hard Rules > Graph > ML)
 │    ├── graph/        # NetworkX entity relationship heuristics
 │    ├── ingest/       # Zero-label leakage data aggregation pipeline
 │    ├── models/       # PyTorch Sequence Models & Sklearn Statistical Baselines
 │    └── monitoring/   # Distribution drift testing (PSI / KS tests)
 └── notebooks/         # (Archived) Exploratory analysis
```

## Quick Start

### 1. Activate Virtual Environment & Install Dependencies
```bash
# Windows (Git Bash / Bash):
source venv/Scripts/activate

# PowerShell:
.\venv\Scripts\Activate.ps1

# Install requirements inside venv:
pip install -r requirements.txt
```

### 2. Generate Synthetic Telemetry & Injected Attacks
```bash
python src/ingest/generate_dataset.py
```

Outputs will be generated in `data/processed/`:
- `full_dataset.parquet`: Labeled security event stream containing normal behavior and **7 distinct attack vectors + 1 insider_drift edge case**.
- `dataset_summary.md`: Class balance statistics, entity profiles, and attack campaign metrics.

### 3. Launch Analyst Dashboard
```bash
streamlit run src/dashboard/app.py
```

## Unified Event Schema

ARGUS processes unified access logs modeled after enterprise SIEM datasets (Windows Event Logs, Active Directory, Proxy Logs, EDR, VPN). See [data/README.md](file:///d:/Desktop%20Data/ML/Projects/Argus/data/README.md) for full schema specifications.

## Core Detection Metrics (Phase 3 Fusion)

| Metric | Score |
|:-------|:-----:|
| **Precision** | 0.736 |
| **Recall**    | 1.000 |
| **F1 Score**  | 0.848 |
| **PR-AUC**    | 0.974 |
| **ROC-AUC**   | 0.999 |
| **FPR**       | 0.89% |

All metrics reflect rigorous post-diagnostic verification. For an in-depth breakdown of individual component testing and architectural linkage, see the [summary.md](file:///d:/Desktop%20Data/ML/Projects/Argus/summary.md) file.
