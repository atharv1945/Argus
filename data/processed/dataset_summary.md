# ARGUS Synthetic Security Dataset Summary (20-Field Expanded Spec)

## Dataset Overview

- **Total Events**: `140,015`
- **Date Range**: `2026-05-31 23:22:00 UTC` to `2026-07-01 03:25:32 UTC` (`21` days)
- **Total Monitored Entities**: `400` (Users, Service Accounts, Edge Devices)
- **Total Tracked Sessions**: `9,570`
- **Target Attack Ratio (Entities)**: `7.0%`

---

## Class Balance Statistics

| Class | Event Count | Percentage |
| :--- | :--- | :--- |
| **Normal Traffic (`is_malicious=False`)** | `139,418` | `99.57%` |
| **Malicious Traffic (`is_malicious=True`)** | `597` | `0.43%` |
| **Total** | `140,015` | `100.00%` |

---

## Attack & Pattern Taxonomy Breakdown (8 Categories)

| Attack / Pattern Category (`attack_type`) | Campaign Count (`attack_instance_id`) | Total Events | Ground Truth Label (`is_malicious`) | Description |
| :--- | :---: | :---: | :---: | :--- |
| `credential_misuse` | `7` | `48` | `True` | Off-hours sensitive cross-department resource access under valid user credentials |
| `brute_force` | `7` | `160` | `True` | Burst of failed logons followed by 1 successful logon & unauthorized access |
| `lateral_movement` | `7` | `56` | `True` | Rapid fan-out access across multiple foreign host devices & servers |
| `impossible_travel` | `14` | `14` | `True` | Sequential logons under same entity ID from physically distant countries |
| `device_spoofing` | `7` | `7` | `True` | Session initiated from an unrecognized, non-fingerprinted rogue device ID |
| `credential_stuffing` | `7` | `177` | `True` | MANY entity IDs attempting auth from FEW shared attacker IPs with high failure rate |
| `low_and_slow_exfiltration` | `7` | `135` | `True` | Gradual, small off-hours resource access building up incrementally over weeks |
| `insider_drift` | `6` | `65` | **`False` (Benign)** | AMBIGUOUS EDGE CASE: Legitimate entity expanding privilege footprint (Benign FP bait) |

---

## Entity & Organizational Breakdown

### By Entity Type
| Entity Type | Count | Percentage |
| :--- | :--- | :--- |
| **user** | `339` | `84.8%` |
| **service_account** | `43` | `10.8%` |
| **edge_device** | `18` | `4.5%` |

### By Department
| Department | Entity Count | Percentage |
| :--- | :--- | :--- |
| **Engineering** | `122` | `30.5%` |
| **Sales** | `74` | `18.5%` |
| **IT** | `60` | `15.0%` |
| **Finance** | `57` | `14.2%` |
| **Executive** | `45` | `11.2%` |
| **HR** | `42` | `10.5%` |

---

## Technical Validation Checklist

- [x] **20-Field Expanded Schema Integrity**: All 20 canonical fields present and strongly typed.
- [x] **Parquet Format**: Single monolithic columnar output ready for pandas, PyTorch, and GNN pipelines.
- [x] **Reproducibility**: Seeded generator (`seed=42`) ensures deterministic reproduction.
- [ ] **WARNING - Campaign Density Check Failed**: Vector(s) ['credential_misuse', 'brute_force', 'lateral_movement', 'device_spoofing', 'credential_stuffing', 'low_and_slow_exfiltration'] have < 8 campaigns!
- [x] **Label-Hiding Discipline**: `src/ingest/mask_labels.py` available for inference-time label masking.
