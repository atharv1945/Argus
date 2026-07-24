# ARGUS Unified Security Event Telemetry Schema

## Overview

The ARGUS Unified Security Telemetry Schema standardizes heterogeneous enterprise access logs (Active Directory authentications, VPN connections, web proxy traffic, file server accesses, and EDR endpoint events) into a single canonical event record. 

This schema is designed to represent real-world enterprise log pipelines (such as Splunk CIM, Elastic Common Schema / ECS, and Microsoft Sentinel) to support multi-dimensional User and Entity Behavior Analytics (UEBA).

---

## Field Specifications

| Field Name | Type | Description | Example Values |
| :--- | :--- | :--- | :--- |
| `entity_id` | `String` | Unique identifier for the user account / identity | `U1042`, `U1089` |
| `entity_role` | `String` | Functional job title / privilege tier of the entity | `Software Engineer`, `HR Specialist`, `Systems Admin`, `Finance Analyst` |
| `entity_dept` | `String` | Organizational unit / department | `Engineering`, `HR`, `Finance`, `IT`, `Sales`, `Executive` |
| `timestamp` | `Timestamp (UTC)` | ISO 8601 event timestamp (millisecond precision) | `2026-06-15T08:34:12.104Z` |
| `event_type` | `String` | Standardized access telemetry event category | `logon`, `logoff`, `file_access`, `http`, `email`, `device_connect` |
| `resource_id` | `String` | Unique identifier of target host, database, service, or URL | `RES_ENG_SRV_02`, `DB_FIN_PAYROLL`, `GW_PROXY_01` |
| `resource_dept` | `String` | Departmental ownership of the target resource | `Engineering`, `Finance`, `HR`, `IT`, `General` |
| `device_id` | `String` | Endpoint hardware identifier / workstation assigned to entity | `DEV_U1042_LAPTOP`, `DEV_IT_JUMPBOX_01` |
| `geo_country` | `String` | ISO 3166-1 alpha-2 country code of source origin IP | `US`, `CA`, `UK`, `DE`, `CN`, `RU` |
| `geo_ip` | `String` | Source IPv4 address | `192.168.1.104`, `10.0.4.12`, `198.51.100.44` |
| `session_id` | `String` | Correlation token tracking an active user session | `SESS_8f3a12b4-9c01` |
| `bytes_transferred` | `Int64` | Volume of data transferred in bytes (network / file I/O) | `0`, `4520`, `104857600` |
| `status` | `String` | Event authentication / execution outcome | `SUCCESS`, `FAILURE` |
| `is_malicious` | `Boolean` | Ground truth label indicating whether event is part of an attack | `False`, `True` |
| `attack_type` | `String` | Categorized attack vector (or `none` for normal traffic) | `none`, `credential_misuse`, `brute_force`, `lateral_movement`, `impossible_travel`, `device_spoofing` |
| `attack_instance_id` | `String` | Unique campaign ID linking multi-event attack sequences | `none`, `ATK_BF_20260615_001` |

---

## Event Types & Characteristics

1. **`logon`**: Authentication request (interactive desktop, VPN, or SSH).
   - Key attributes: `status` (`SUCCESS`/`FAILURE`), `geo_ip`, `geo_country`, `device_id`.
2. **`logoff`**: Session termination signal.
   - Marks end of active `session_id`.
3. **`file_access`**: File read, write, or download from file servers / share drives.
   - Key attributes: `bytes_transferred`, `resource_id`, `resource_dept`.
4. **`http`**: Web proxy request / external endpoint connection.
   - Key attributes: `bytes_transferred`, `resource_id`.
5. **`email`**: Internal or external email exchange telemetry.
   - Key attributes: `bytes_transferred`.
6. **`device_connect`**: Peripheral device insertion or remote terminal connection to endpoint.
   - Key attributes: `device_id`.

---

## Modeled Threat Vectors (Ground Truth Labels)

ARGUS explicitly models 5 realistic insider threat and compromise scenarios:

```
[Threat Landscape]
  ├── 1. Credential Misuse   --> Off-hours access to sensitive cross-dept resources under valid user credentials
  ├── 2. Brute Force         --> Rapid succession of failed logons followed by a successful compromise
  ├── 3. Lateral Movement    --> High-fanout access across foreign devices & servers in a narrow time window
  ├── 4. Impossible Travel   --> Logons under same entity from physically distant geographies within minutes
  └── 5. Device Spoofing     --> Valid session initiated from a non-fingerprinted, unauthorized device ID
```

---

## Ingestion Pipeline Output Specification

The data generation pipeline outputs a unified columnar dataset saved in **Apache Parquet format**:
- File location: `data/processed/full_dataset.parquet`
- Partitioning: Single monolithic file for fast in-memory analytics and GPU/CPU model training.
- Accompanying summary: `data/processed/dataset_summary.md` detailing dataset distributions, entity metrics, and attack campaign counts.
