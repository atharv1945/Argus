# ARGUS Phase 6 — Analyst Dashboard Build Notes

**Deliverable**: `src/dashboard/app.py` (Streamlit entry point)  
**Run**: `streamlit run src/dashboard/app.py`  
**URL**: http://localhost:8501

---

## What Was Built

### 1. Drift Status Banner (top of every page)
Computes current drift by comparing test split alert rate to the train baseline stored in `drift_baseline.json`. Displays `NONE / MODERATE / SIGNIFICANT` with colour coding (green/amber/red). Current status: **NONE** (test alert rate 3.31% vs train 9.53%, ratio 0.35x — explained by the test/train split having proportionally fewer malicious campaigns).

### 2. Alert Queue (primary view)
- Reads from `alert_cases.parquet`, sorted by `max_fused_risk_score` descending.
- Split filter (test / train / all), attack type filter, tier filter.
- 73 test cases loaded, showing entity, dept, attack type, risk score, session count, first/last seen.
- `✅` badge on cases already reviewed via feedback buttons.
- **Quick Drill-In** selectbox below the table triggers the full drill-down panel inline.

### 3. Entity Drill-Down (full view)
- Entity selector over all entities in `alert_cases.parquet`.
- **Session risk timeline**: matplotlib scatter of risk scores over date, with 50-point alert threshold line.
- **Case selector** → full drill-down panel with:
  - Case summary table (entity, type, dept, risk, session count, first/last seen).
  - **Analyst note**: generated live by `generate_note_for_session()` from Phase 5.
  - **Subgraph visualization**: NetworkX DiGraph drawn with matplotlib; entity (red), co-using entities (orange), devices (blue), resources (green).
  - **Session details table**: all signals from `fused_scores.parquet` for this case's sessions.
  - **TP/FP feedback buttons** with optional text comment → appends to `data/feedback/feedback.csv`.

### 4. Analyst Feedback Log (view)
- Reads `data/feedback/feedback.csv`.
- Shows all submitted verdicts.
- Computes analyst-estimated precision from TP/FP counts.
- Download button for CSV export.

---

## Simplifications Made for Time Budget

| Item | Decision | Reason |
|------|----------|---------|
| Graph visualization library | matplotlib + NetworkX (not D3/Pyvis) | Avoids additional JS dependencies; sufficient for demo |
| Drift computation | Simple alert-rate ratio vs baseline | Full PSI computation would need real-time score stream |
| Feedback store | Flat CSV | No retraining hookup needed at this phase; concept demonstrated |
| Entity timeline | scatter plot vs interactive chart | Altair/Plotly would be nicer but adds dep complexity |
| No auth / multi-user | Single user | Out of scope for this phase |
| Subgraph cache | `@st.cache_resource` on EntityGraph | Avoids rebuilding the full graph on every interaction (graph build takes ~10s) |

---

## Goal 2 — Sanity Check Results

All three required data paths verified:

### Tier 1 Case: `CASE_SVC_1203_credential_stuffing_2026-06-18`
- Anchor session: `SESS_CS_d39b8d0a` (SVC_1203, Engineering)
- Note risk score: **96** ✅ matches raw `fused_risk_score = 96`
- Attack type: **Credential Stuffing** ✅ matches `attack_type = credential_stuffing`
- Detection path: `hard_rule fp_mismatch+corroborated + hard_rule ip_fan_in_stuffing`
- Key signals cited: `fp_mismatch=1`, `event_count=1`, `ip_entity_fan_in=8`, `failure_ratio=1.00` — all verified against raw parquet row.

### Tier 2 Case: `EDGE_1011 / credential_misuse`
- Note risk score matches raw ✅
- Tier 2 path (graph-boosted, no hard rule) correctly shown.

### Benign Insider Drift (correctly not-flagged): `U1024`
- Note contains `NOT FLAGGED` label ✅
- Score: 10/100 ✅
- Attribution: `base_score=0.192, graph_boost=0.1000 → 0.292 < 0.55`

No hallucinated factors found in any note.

---

## Screenshots

Dashboard loads at http://localhost:8501:
- **Drift banner**: ✅ NONE (green)
- **Alert Queue**: 73 test cases shown with real entity/attack data
- **Metrics**: Precision 0.729, Recall 1.000, Tier 1: 28, Tier 2: 45

To run: `cd d:\Desktop Data\ML\Projects\Argus && streamlit run src/dashboard/app.py`
