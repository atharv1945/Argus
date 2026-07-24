# ARGUS: User & Entity Behavior Analytics (UEBA) Anomaly Detection System

ARGUS is a real-time, multi-vector User and Entity Behavior Analytics (UEBA) cybersecurity anomaly detection system built for enterprise security telemetry.

## System Architecture

- **`data/`**: Synthetic security event generators, schema specifications, and processed parquet datasets.
- **`src/ingest/`**: Synthetic access log generation, attack injection engines, and data preprocessing pipelines.
- **`src/models/`**: Anomaly detection models (Statistical, ML, Deep Learning / Graph Neural Networks).
- **`src/api/`**: Streamlit dashboard and alert triage interface.
- **`notebooks/`**: Exploratory data analysis and model prototyping.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Synthetic Telemetry & Injected Attacks
```bash
python src/ingest/generate_dataset.py
```

Outputs will be generated in `data/processed/`:
- `full_dataset.parquet`: Labeled security event stream containing normal behavior and 5 distinct attack vectors.
- `dataset_summary.md`: Class balance statistics, entity profiles, and attack campaign metrics.

## Unified Event Schema

ARGUS processes unified access logs modeled after enterprise SIEM datasets (Windows Event Logs, Active Directory, Proxy Logs, EDR, VPN). See [data/README.md](file:///d:/Desktop%20Data/ML/Projects/Argus/data/README.md) for full schema specifications.
