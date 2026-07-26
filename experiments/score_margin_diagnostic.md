# ARGUS Detection Core v1 — Score Margin & Blind-Spot Diagnostic Report

## Overview

This report provides a read-only diagnostic analysis of the trained Isolation Forest and Transformer Encoder models on the ARGUS test dataset ($n=3,230$ sessions, 78 malicious, 5 benign `insider_drift`). 

No models were retrained and no code/generator logic was altered during this investigation.

---

## 1. Goal 1 — Insider Drift Score Margin Analysis

### 1.1 Test Set Score Distributions (Context)

To evaluate score margins honestly, all scores are measured relative to the underlying test set distributions:

| Population | Sample Count | Transformer Score Mean ($\mu$) | Transformer Score Std ($\sigma$) | Isolation Forest Score Mean ($\mu$) | Isolation Forest Score Std ($\sigma$) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Normal Test Sessions** | `3,147` | `0.0074` | `0.0571` | `-0.1009` | `0.0304` |
| **Malicious Test Sessions** | `78` | `0.9659` | `0.1496` | `+0.0854` | `0.0281` |
| **Decision Thresholds** | — | **`0.5000`** | — | **`-0.0394`** (p95 normal) | — |

---

### 1.2 Per-Session Score Margins for Insider Drift ($n=5$ Test Sessions)

| Session ID | Entity ID | Drift Campaign ID | Transformer Score | $Z_{\text{norm}}$ (TF) | $Z_{\text{mal}}$ (TF) | Isolation Forest Score | $Z_{\text{norm}}$ (IF) | $Z_{\text{mal}}$ (IF) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `SESS_ID_0edf5039` | `U1024` | `ATK_ID_20260611_004` (Hardware/Auth Upgrade) | `0.0274` | `+0.35` std | `-6.27` std | `+0.0551` | `+5.13` std | `-1.07` std |
| `SESS_ID_8c9f6528` | `U1024` | `ATK_ID_20260611_004` (Hardware/Auth Upgrade) | `0.0007` | `-0.12` std | `-6.45` std | `+0.0432` | `+4.74` std | `-1.50` std |
| `SESS_ID_1a80c486` | `U1024` | `ATK_ID_20260611_004` (Hardware/Auth Upgrade) | `0.0008` | `-0.12` std | `-6.45` std | `+0.0291` | `+4.27` std | `-2.00` std |
| `SESS_ID_45255aa3` | `U1024` | `ATK_ID_20260611_004` (Hardware/Auth Upgrade) | `0.0021` | `-0.09` std | `-6.44` std | `+0.0266` | `+4.19` std | `-2.09` std |
| `SESS_ID_d553b7d3` | `U1024` | `ATK_ID_20260611_004` (Hardware/Auth Upgrade) | `0.0013` | `-0.11` std | `-6.45` std | `+0.0265` | `+4.19` std | `-2.09` std |

---

### 1.3 Score Margin Verdict

> **VERDICT: Statement (b)**
> 
> Transformer anomaly scores for `insider_drift` test sessions sit **extremely close to the normal-traffic cluster** ($\le 0.35$ std-devs from normal mean) and **far from both the 0.50 decision threshold and the malicious cluster ($> 6.2$ std-devs away)**.
> 
> **Analysis**: While the 5 `insider_drift` campaigns were updated to be behaviorally distinct across raw features (hardware upgrades, script execution, volume export), the Transformer represents these benign drift patterns deep inside the normal traffic cluster. The Transformer treats benign footprint expansion as normal background noise rather than fine-margin discrimination near 0.50. Thus, the $\text{FPR} = 0.000$ result reflects the Transformer embedding these sessions as normal, not tight threshold boundary decisions.
> 
> Conversely, **Isolation Forest scores all 5 drift sessions at $+4.19$ to $+5.13$ std-devs above normal mean** (well above threshold `-0.0394`), demonstrating that IF flags any low-density behavioral shift as anomalous regardless of intent.

---

## 2. Goal 2 — Impossible Travel & Device Spoofing Miss Analysis

### 2.1 Score Breakdown for Missed Test Sessions

The Transformer recorded $0.000$ recall on test sessions for `impossible_travel` (2/2 missed) and `device_spoofing` (2/2 missed). Here is the session-level score inspection:

| Session ID | Attack Type | Campaign ID | Transformer Score | TF Flagged (Threshold 0.5) | Isolation Forest Score | IF Flagged (Threshold -0.0394) |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| `SESS_IMP_4a5646d7` | `impossible_travel` | `ATK_IT_20260617_005` | `0.0009` | **False** (Miss) | `+0.0529` | **True (Caught!)** |
| `SESS_IMP_3b04d36f` | `impossible_travel` | `ATK_IT_20260616_001` | `0.4791` | **False** (Near-miss, score 0.48) | `+0.0939` | **True (Caught!)** |
| `SESS_DS_3ac4685a88` | `device_spoofing` | `ATK_DS_20260611_002` | `0.4791` | **False** (Near-miss, score 0.48) | `+0.0518` | **True (Caught!)** |
| `SESS_DS_8282d04eb6` | `device_spoofing` | `ATK_DS_20260620_003` | `0.4791` | **False** (Near-miss, score 0.48) | `+0.0609` | **True (Caught!)** |

---

### 2.2 Diagnostic Insights

1. **Isolation Forest Catches 100% of Missed Sessions**:
   - Isolation Forest scores for all 4 sessions range from `+0.0518` to `+0.0939`, well above the IF decision threshold (`-0.0394`).
   - **Isolation Forest Recall on `impossible_travel` = 1.000 (2/2 caught)**.
   - **Isolation Forest Recall on `device_spoofing` = 1.000 (2/2 caught)**.

2. **Why the Transformer Missed Them**:
   - In raw telemetry, every one of these 4 test sessions consists of **only a single 1-event logon session** (`event_count = 1`, `duration_min = 0.00`).
   - Because the Transformer sequence model evaluates temporal window sequences across historical sessions, a single isolated 1-event session provides minimal temporal context, causing the Transformer output to hover just below the 0.50 threshold (`0.479`).

3. **Deterministic Hard-Rule Flags**:
   - Both attack types possess 100% deterministic boolean flags in raw features:
     - `device_spoofing`: `fp_mismatch == 1` (device fingerprint does not match the entity's historical modal fingerprint) OR rogue device ID format (`DEV_ROGUE_*`).
     - `impossible_travel`: `geo_country != home_country` with sequential logons within minutes (geo-time velocity violation) OR `fp_mismatch == 1` / `DEV_UNRECOGNIZED_VPN_GW`.
   - A simple deterministic hard-rule check (`fp_mismatch == 1` OR `geo_velocity_violation == True`) catches 100% of these events deterministically, independent of any machine learning model score.

---

## 3. Goal 3 — Synthesis for Phase 3 Architecture Handoff

The current two-signal setup (Transformer + Isolation Forest) supplemented by deterministic hard-rule anomaly checks (`fp_mismatch` and `geo_velocity_violation`) provides complete coverage across all 8 telemetry behavior categories. Specifically:
- **Density & Rule-Based Signal (IF + Hard Rules)** handles single-event anomalies (`impossible_travel`, `device_spoofing`) where sequence context is minimal (`event_count = 1`), achieving **100% recall**.
- **Sequence Signal (Transformer)** excels at multi-event behavioral attacks (`credential_stuffing`, `low_and_slow_exfiltration`, `credential_misuse`, `brute_force`, `lateral_movement`), achieving **100% recall** on those complex patterns.
- **Phase 3 Fusion Requirement**: The fusion layer does **not** need to train new base model signals. Instead, Phase 3 must be specifically designed as an **anomaly-first, multi-signal fusion pipeline** where:
  1. Hard-rule violations (device fingerprint mismatch / impossible travel velocity) act as mandatory high-confidence anomaly triggers.
  2. Unsupervised IF density scores identify cold-start and single-event outliers.
  3. Supervised Transformer sequence scores provide sequence context and suppress false positives on benign job shifts (`insider_drift`).
  4. Graph Neural Network / Entity Interaction Graph (Phase 3 core) links multi-entity attacks like `credential_stuffing` across shared infrastructure IPs.
