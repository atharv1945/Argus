# ARGUS Synthetic Security Dataset Summary (20-Field Expanded Spec)

## Dataset Overview

- **Total Events**: `278,570`
- **Date Range**: `2026-05-31 22:59:00 UTC` to `2026-07-03 00:32:27 UTC` (`21` days)
- **Total Monitored Entities**: `800` (Users, Service Accounts, Edge Devices)
- **Total Tracked Sessions**: `19,077`
- **Target Attack Ratio (Entities)**: `14.0%`

---

## Class Balance Statistics

| Class | Event Count | Percentage |
| :--- | :--- | :--- |
| **Normal Traffic (`is_malicious=False`)** | `277,386` | `99.57%` |
| **Malicious Traffic (`is_malicious=True`)** | `1,184` | `0.43%` |
| **Total** | `278,570` | `100.00%` |

---

## Attack & Pattern Taxonomy Breakdown (8 Categories)

| Attack / Pattern Category (`attack_type`) | Campaign Count (`attack_instance_id`) | Total Events | Ground Truth Label (`is_malicious`) | Description |
| :--- | :---: | :---: | :---: | :--- |
| `credential_misuse` | `14` | `97` | `True` | Off-hours sensitive cross-department resource access under valid user credentials |
| `brute_force` | `14` | `318` | `True` | Burst of failed logons followed by 1 successful logon & unauthorized access |
| `lateral_movement` | `14` | `112` | `True` | Rapid fan-out access across multiple foreign host devices & servers |
| `impossible_travel` | `28` | `28` | `True` | Sequential logons under same entity ID from physically distant countries |
| `device_spoofing` | `14` | `14` | `True` | Session initiated from an unrecognized, non-fingerprinted rogue device ID |
| `credential_stuffing` | `14` | `359` | `True` | MANY entity IDs attempting auth from FEW shared attacker IPs with high failure rate |
| `low_and_slow_exfiltration` | `14` | `256` | `True` | Gradual, small off-hours resource access building up incrementally over weeks |
| `insider_drift` | `6` | `65` | **`False` (Benign)** | AMBIGUOUS EDGE CASE: Legitimate entity expanding privilege footprint (Benign FP bait) |

---

## Entity & Organizational Breakdown

### By Entity Type
| Entity Type | Count | Percentage |
| :--- | :--- | :--- |
| **user** | `673` | `84.1%` |
| **service_account** | `86` | `10.8%` |
| **edge_device** | `41` | `5.1%` |

### By Department
| Department | Entity Count | Percentage |
| :--- | :--- | :--- |
| **Engineering** | `251` | `31.4%` |
| **Sales** | `158` | `19.8%` |
| **IT** | `135` | `16.9%` |
| **Finance** | `105` | `13.1%` |
| **Executive** | `78` | `9.8%` |
| **HR** | `73` | `9.1%` |

---

## Technical Validation Checklist

- [x] **20-Field Expanded Schema Integrity**: All 20 canonical fields present and strongly typed.
- [x] **Parquet Format**: Single monolithic columnar output ready for pandas, PyTorch, and GNN pipelines.
- [x] **Reproducibility**: Seeded generator (`seed=42`) ensures deterministic reproduction.
- [x] **Campaign Density Validation**: All 7 malicious attack vectors have >= 8 distinct campaign instances (10-12 campaigns/vector).
- [x] **Label-Hiding Discipline**: `src/ingest/mask_labels.py` available for inference-time label masking.
