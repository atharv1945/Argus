# ARGUS Unified Security Event Telemetry Schema (Expanded Spec)

## Overview

The ARGUS Unified Security Telemetry Schema standardizes heterogeneous enterprise access logs (Active Directory authentications, VPN connections, web proxy traffic, file server accesses, EDR endpoint events, service account tokens, and IoT edge device telemetry) into a single canonical 21-field event record. 

This schema represents real-world enterprise log pipelines (Splunk CIM, Elastic Common Schema / ECS, Microsoft Sentinel, and EDR agents) supporting multi-dimensional User and Entity Behavior Analytics (UEBA).

---

## 21-Field Canonical Specifications

| Field Name | Type | Description | Example Values |
| :--- | :--- | :--- | :--- |
| `entity_id` | `String` | Unique identifier for user, service account, or edge device | `U1042`, `SVC_1002`, `EDGE_1001` |
| `entity_type` | `String` | Entity classification (`user`, `service_account`, `edge_device`) | `user`, `service_account`, `edge_device` |
| `entity_role` | `String` | Functional job title, service role, or hardware category | `Software Engineer`, `ETL Runner`, `IoT Gateway` |
| `entity_dept` | `String` | Organizational unit or operating department | `Engineering`, `Finance`, `HR`, `IT`, `Sales`, `Executive` |
| `timestamp` | `Timestamp (UTC)` | ISO 8601 event timestamp (millisecond precision) | `2026-06-15T08:34:12.104Z` |
| `event_type` | `String` | Standardized telemetry event category | `logon`, `logoff`, `file_access`, `http`, `email`, `device_connect` |
| `auth_method` | `String` | Authentication protocol / credential type | `password`, `token`, `certificate`, `biometric` |
| `resource_id` | `String` | Identifier of target server, database, service, or URL | `RES_ENG_SRV_02`, `DB_FIN_PAYROLL`, `GW_PROXY_01` |
| `resource_dept` | `String` | Departmental ownership of target resource | `Engineering`, `Finance`, `HR`, `IT`, `General` |
| `command_sequence` | `String` | Ordered action tokens for privileged sessions (comma-separated, or empty) | `read,execute,export_data`, `read,write` |
| `device_id` | `String` | Endpoint hardware / workstation identifier | `DEV_U1042_LAPTOP`, `DEV_IT_JUMPBOX_01` |
| `device_fingerprint` | `String` | Hardware fingerprint (`OS \| MAC Address \| Protocol`) | `Windows 11 23H2 \| 00:1A:2B:3C:4D:5E \| TLS1.3` |
| `geo_country` | `String` | ISO 3166-1 alpha-2 country code of origin IP | `US`, `CA`, `UK`, `DE`, `CN`, `RU` |
| `geo_ip` | `String` | Source IPv4 address | `192.168.1.104`, `10.0.4.12`, `198.51.100.44` |
| `session_id` | `String` | Correlation token tracking an active session | `SESS_8f3a12b4-9c01` |
| `session_duration` | `Float64` | Total duration of the active session in seconds | `0.0`, `7200.0`, `14280.0` |
| `bytes_transferred` | `Int64` | Volume of data transferred in bytes | `0`, `4520`, `104857600` |
| `status` | `String` | Authentication / execution outcome | `SUCCESS`, `FAILURE` |
| `is_malicious` | `Boolean` | Ground truth label (`True` for attacks, `False` for normal/drift) | `False`, `True` |
| `attack_type` | `String` | Categorized attack vector or pattern | `none`, `credential_misuse`, `brute_force`, `lateral_movement`, `impossible_travel`, `device_spoofing`, `credential_stuffing`, `low_and_slow_exfiltration`, `insider_drift` |
| `attack_instance_id` | `String` | Campaign tracking ID linking multi-event sequences | `none`, `ATK_BF_20260615_001` |

---

## Attack Taxonomy (8 Categories)

ARGUS explicitly models 7 attack vectors and 1 non-malicious edge case (`insider_drift`):

```text
[Attack & Pattern Taxonomy]
  ├── 1. Credential Misuse       --> Off-hours access to sensitive cross-dept resources under valid user credentials
  ├── 2. Brute Force             --> Rapid succession of failed logons for 1 user followed by 1 successful compromise
  ├── 3. Lateral Movement        --> High-fanout access across multiple foreign host devices & servers in minutes
  ├── 4. Impossible Travel       --> Sequential logons under same entity from physically distant countries within minutes
  │                                  └── Includes Stolen Credential variant (ATK_ITSC): valid fingerprint + foreign geo
  ├── 5. Device Spoofing         --> Valid session initiated from an unrecognized, non-fingerprinted rogue device ID
  ├── 6. Credential Stuffing     --> MANY entity IDs attempting auth from a FEW shared attacker IPs with high failure rates
  ├── 7. Low & Slow Exfiltration --> Gradual, small off-hours resource access building up incrementally over weeks
  └── 8. Insider Drift (Benign)  --> Legitimate entity expanding privilege/resource footprint (is_malicious=False, FP bait)
                                     └── Includes Harder variant: cross-department resource fan-out
```

---

## Label-Hiding Discipline

> [!IMPORTANT]
> **Strict Inference Discipline**:
> To ensure honest and unbiased evaluation:
> 1. All feature extraction scripts, rolling entity baselines, peer group aggregations, and model inference pipelines **MUST** run on un-labeled or masked telemetry streams (`src/ingest/mask_labels.py`).
> 2. Ground truth labels (`is_malicious`, `attack_type`, `attack_instance_id`) are accessed **ONLY** during metric calculation (Precision, Recall, F1, PR-AUC).
> 3. Zero label leakage into features is enforced.
