# ARGUS Synthetic Security Dataset Summary

## Dataset Overview

- **Total Events**: `132,637`
- **Date Range**: `2026-05-31 23:41:00 UTC` to `2026-06-21 19:50:00 UTC` (`21` days)
- **Total Monitored Entities**: `400`
- **Total Tracked Sessions**: `8,847`
- **Target Attack Ratio (Entities)**: `1.5%`

---

## Class Balance Statistics

| Class | Event Count | Percentage |
| :--- | :--- | :--- |
| **Normal Traffic (`is_malicious=False`)** | `132,566` | `99.95%` |
| **Malicious Traffic (`is_malicious=True`)** | `71` | `0.05%` |
| **Total** | `132,637` | `100.00%` |

---

## Attack Vector Breakdown

| Attack Vector (`attack_type`) | Campaign Count (`attack_instance_id`) | Malicious Events | Description |
| :--- | :--- | :--- | :--- |
| `credential_misuse` | `2` | `16` | Off-hours sensitive cross-department resource access under valid user credentials |
| `brute_force` | `1` | `27` | Burst of failed logons followed by 1 successful logon & unauthorized access |
| `lateral_movement` | `1` | `17` | Rapid fan-out access across multiple foreign host devices & servers |
| `impossible_travel` | `1` | `5` | Sequential logons under same entity ID from physically distant countries |
| `device_spoofing` | `1` | `6` | Session initiated from an unrecognized, non-fingerprinted rogue device ID |

---

## Entity & Organizational Breakdown

| Department | Entity Count | Percentage |
| :--- | :--- | :--- |
| **Engineering** | `125` | `31.2%` |
| **Sales** | `82` | `20.5%` |
| **IT** | `60` | `15.0%` |
| **Finance** | `56` | `14.0%` |
| **HR** | `39` | `9.8%` |
| **Executive** | `38` | `9.5%` |

---

## Technical Validation Checklist

- [x] **Schema Integrity**: All 16 fields present and strongly typed according to canonical specification.
- [x] **Parquet Format**: Optimized columnar output ready for pandas, PyTorch, and GNN pipelines.
- [x] **Reproducibility**: Seeded generator (`seed=42`) ensures deterministic reproduction.
