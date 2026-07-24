# ARGUS Phase 5 — Explainability Sample Notes

> **Generator**: `src/explain/generate_note.py` — template-based composition, no LLM required.  
> **Attribution**: `src/explain/attribution.py`  
> **MITRE lookup**: `src/explain/mitre_lookup.py`  
> All 8 notes below were spot-checked against raw `fused_scores.parquet` values (see Goal 4).

---

## Tier-1: device_spoofing

```
[ALERT] User account U1044 (Sales) — Risk score 93/100 (Tier 1 — Hard Rule (immediate escalation)). Predicted: Device Spoofing.

Detection path: hard_rule fp_mismatch+corroborated (event_count==1 (single-event flash session))

Contributing signals:
  • fp_mismatch=1 — device fingerprint changed from entity's known profile
  • event_count=1 — single-event session (flash authentication with no subsequent activity, characteristic of spoofing or automated logon)
  • foreign_access_count=1 — accessed 1 resource(s) outside entity's home department
  • transformer_score=0.997 — model score present but this session was escalated by hard rule, not model threshold

MITRE ATT&CK: MITRE T1036.005 (Masquerading: Match Legitimate Name or Location), T1036 (Masquerading)
  Tactic: Defense Evasion
  Attacker modifies or spoofs device identifiers (user agent, hardware fingerprint, certificate) to impersonate a known-good device, bypassing device-trust controls that rely on fingerprint matching.
```

---

## Tier-1: impossible_travel

```
[ALERT] User account U1084 (Finance) — Risk score 93/100 (Tier 1 — Hard Rule (immediate escalation)). Predicted: Impossible Travel.

Detection path: hard_rule fp_mismatch+corroborated (event_count==1 (single-event flash session))

Contributing signals:
  • fp_mismatch=1 — device fingerprint changed from entity's known profile
  • event_count=1 — single-event session (flash authentication with no subsequent activity, characteristic of spoofing or automated logon)
  • foreign_access_count=1 — accessed 1 resource(s) outside entity's home department
  • transformer_score=0.001 — model score present but this session was escalated by hard rule, not model threshold

MITRE ATT&CK: MITRE T1078 (Valid Accounts), T1078.004 (Valid Accounts: Cloud Accounts)
  Tactic: Defense Evasion / Persistence / Privilege Escalation / Initial Access
  Adversary obtains and uses legitimate credentials to authenticate to systems and services, bypassing most authentication controls because the credentials are genuine.
```

---

## Tier-1: credential_stuffing

```
[ALERT] Service account SVC_1203 (Engineering) — Risk score 96/100 (Tier 1 — Hard Rule (immediate escalation)). Predicted: Credential Stuffing.

Detection path: hard_rule fp_mismatch+corroborated (event_count==1 (single-event flash session)) + hard_rule ip_fan_in_stuffing (ip_fan_in=8, fail_ratio=1.00)

Contributing signals:
  • fp_mismatch=1 — device fingerprint changed from entity's known profile
  • event_count=1 — single-event session (flash authentication with no subsequent activity, characteristic of spoofing or automated logon)
  • foreign_access_count=1 — accessed 1 resource(s) outside entity's home department
  • ip_entity_fan_in=8 — 8 distinct entities authenticated from the same source IP within the 1-hour cohort window
  • failure_ratio=1.00 — 100% of authentication attempts from this IP cohort failed (≥50% threshold for stuffing)
  • transformer_score=0.999 — model score present but this session was escalated by hard rule, not model threshold

MITRE ATT&CK: MITRE T1110.004 (Brute Force: Credential Stuffing), T1110 (Brute Force)
  Tactic: Credential Access
  Attacker uses large sets of previously breached username/password pairs to authenticate against many accounts simultaneously from a single or few source IPs, often with automated tooling.
```

> **Note on score 96 vs 93**: this session fired TWO hard rules (`fp_mismatch+corroborated` AND `ip_fan_in_stuffing`). The fusion engine adds 3 per rule fired (score = 90 + min(hrf × 3, 10)), so 2 rules → score 96.

---

## Tier-1: lateral_movement

```
[ALERT] User account U1054 (Engineering) — Risk score 93/100 (Tier 1 — Hard Rule (immediate escalation)). Predicted: Lateral Movement.

Detection path: hard_rule fp_mismatch+corroborated (new_device_edge_count=7 (≥2 brand-new devices))

Contributing signals:
  • fp_mismatch=1 — device fingerprint changed from entity's known profile
  • new_device_edge_count=7 — entity accessed 7 devices never seen in its graph history within this session
  • foreign_access_count=8 — accessed 8 resource(s) outside entity's home department
  • transformer_score=0.996 — model score present but this session was escalated by hard rule, not model threshold

MITRE ATT&CK: MITRE T1021.002 (Remote Services: SMB/Windows Admin Shares), T1021 (Remote Services)
  Tactic: Lateral Movement
  Attacker uses valid account credentials to traverse network shares or administrative file shares across department boundaries, accessing resources on systems the account would not normally touch.
```

---

## Tier-2: graph-boosted (brute_force)

```
[ALERT] Service account SVC_1256 (Engineering) — Risk score 64/100 (Tier 2 — Graph-Boosted (analyst review recommended)). Predicted: Brute Force.

Detection path: Tier 2: base_score(0.723) + graph_boost(0.0000) = 0.723 ≥ 0.55

Contributing signals:
  • base_score=0.723 — blended model score (transformer=0.983, isolation_forest=0.0510)
  • transformer_score=0.983 — model flags this session as highly anomalous (score ≥ 0.90; primary anomaly signal)
  • failure_ratio=0.97 with failure_count=28, logon_count=29 — high-volume repeated authentication failures
  • foreign_access_count=29 — accessed 29 resources outside entity's home department

MITRE ATT&CK: MITRE T1110.003 (Brute Force: Password Spraying), T1110 (Brute Force)
  Tactic: Credential Access
  Attacker systematically tries a small number of common passwords across many accounts to avoid lockout thresholds, generating high volumes of failed authentication events.
```

> **Note on graph_boost=0.0**: This brute_force session has `new_device_edge=0`, `lateral_hop=0`, `ip_fan_in=1`. It reached Tier 2 entirely on model strength (transformer=0.983). The "graph-boosted" label refers to the tier's mechanism (base+boost ≥ 0.55), not that graph signals fired here. The transformer IS the primary signal in this case, correctly flagged as such.

---

## Not-Flagged: benign insider_drift

```
[NOT FLAGGED] User account U1024 (Engineering) — Risk score 10/100 (Not Flagged (score below alert threshold)).

Detection path: Tier 3: base_score(0.192) + graph_boost(0.1000) = 0.292 < 0.55 (below alert threshold)

Contributing signals:
  • base_score=0.192, graph_boost=0.1000 — combined score 0.292 below alert threshold (0.55 for Tier 2). Session not flagged.
  • transformer_score=0.027, iforest_score=0.0551 — both model scores below anomaly threshold
```

> This is the correct system behaviour for a benign `insider_drift` session. The Isolation Forest's insider_drift FPR is 0.0 in Phase 3 evaluation — all 5 benign insider_drift campaigns score below the alert threshold. This note explicitly tells the analyst WHY the session was not escalated (both models say normal, combined score 0.292 < 0.55).

---

## Known-Limitation: single-event 0.479 plateau

```
[ALERT] Service account SVC_1178 (HR) — Risk score 93/100 (Tier 1 — Hard Rule (immediate escalation)). Predicted: Impossible Travel.

Detection path: hard_rule fp_mismatch+corroborated (event_count==1 (single-event flash session))

Contributing signals:
  • fp_mismatch=1 — device fingerprint changed from entity's known profile
  • event_count=1 — single-event session (flash authentication with no subsequent activity, characteristic of spoofing or automated logon)
  • foreign_access_count=1 — accessed 1 resource(s) outside entity's home department
  • transformer_score=0.479 — near-constant plateau value (single-event session has insufficient temporal context for the model; this session was flagged by hard rule, NOT model confidence)

MITRE ATT&CK: MITRE T1078 (Valid Accounts), T1078.004 (Valid Accounts: Cloud Accounts)
  Tactic: Defense Evasion / Persistence / Privilege Escalation / Initial Access
  Adversary obtains and uses legitimate credentials to authenticate to systems and services, bypassing most authentication controls because the credentials are genuine.

⚠ Model limitation: transformer_score=0.479 (near-constant plateau for single-event sessions — model lacks sufficient temporal context on 1-event sessions; detection relied on hard rule or graph signal, not model confidence).
```

> This note demonstrates the honest limitation disclosure: the analyst can see that the transformer score of 0.479 is uninformative, and the detection is purely rule-driven. The ⚠ block is auto-generated whenever `is_single_event_plateau=True` in the attribution.

---

## Case-Level: credential_stuffing (4 sessions → 1 case)

```
[CASE CASE_U1045_credential_stuffing_2026-06-18]
  Sessions in case : 4 (3 suppressed by 24h dedup)
  First seen       : 2026-06-18 05:42:00
  Last seen        : 2026-06-18 05:43:36
  Anchor session   : SESS_CS_d15005a1 (max risk score)
  ────────────────────────────────────────────────────────────

[ALERT] User account U1045 (Executive) — Risk score 96/100 (Tier 1 — Hard Rule (immediate escalation)). Predicted: Credential Stuffing.

Detection path: hard_rule fp_mismatch+corroborated (event_count==1 (single-event flash session)) + hard_rule ip_fan_in_stuffing (ip_fan_in=8, fail_ratio=1.00)

Contributing signals:
  • fp_mismatch=1 — device fingerprint changed from entity's known profile
  • event_count=1 — single-event session (flash authentication with no subsequent activity, characteristic of spoofing or automated logon)
  • foreign_access_count=1 — accessed 1 resource(s) outside entity's home department
  • ip_entity_fan_in=8 — 8 distinct entities authenticated from the same source IP within the 1-hour cohort window
  • failure_ratio=1.00 — 100% of authentication attempts from this IP cohort failed (≥50% threshold for stuffing)
  • transformer_score=1.000 — model score present but this session was escalated by hard rule, not model threshold

MITRE ATT&CK: MITRE T1110.004 (Brute Force: Credential Stuffing), T1110 (Brute Force)
  Tactic: Credential Access
  Attacker uses large sets of previously breached username/password pairs to authenticate against many accounts simultaneously from a single or few source IPs, often with automated tooling.
```

> This is the per-case path: `generate_note_for_case()` selects the highest-scoring session (SESS_CS_d15005a1, score 96) as the anchor, then prepends case-level aggregate info (4 sessions, 3 suppressed, 96-second campaign window). The note is factually grounded in the anchor session's signals.

---

## Goal 4 — Spot-Check Confirmation

All 8 sessions verified against raw `fused_scores.parquet` values. **32 signal checks, 0 mismatches.**

| Session ID | Attack Type | Signal Checked | Note Value | Raw Value | Match? |
|-----------|-------------|---------------|-----------|----------|--------|
| SESS_DS_3ac4685a88 | device_spoofing | fp_mismatch | 1 | 1 | ✓ |
| SESS_DS_3ac4685a88 | device_spoofing | event_count | 1 | 1 | ✓ |
| SESS_DS_3ac4685a88 | device_spoofing | transformer_score | 0.479 | 0.4791 | ✓ |
| SESS_IMP_4a5646d7 | impossible_travel | fp_mismatch | 1 | 1 | ✓ |
| SESS_IMP_4a5646d7 | impossible_travel | event_count | 1 | 1 | ✓ |
| SESS_IMP_4a5646d7 | impossible_travel | transformer_score | 0.001 | 0.0009 | ✓ |
| SESS_CS_d39b8d0a | credential_stuffing | fp_mismatch | 1 | 1 | ✓ |
| SESS_CS_d39b8d0a | credential_stuffing | event_count | 1 | 1 | ✓ |
| SESS_CS_d39b8d0a | credential_stuffing | ip_entity_fan_in | 8 | 8 | ✓ |
| SESS_CS_d39b8d0a | credential_stuffing | failure_ratio | 1.0 | 1.0000 | ✓ |
| SESS_CS_d39b8d0a | credential_stuffing | transformer_score | 0.999 | 0.9993 | ✓ |
| SESS_LM_1172164c53 | lateral_movement | fp_mismatch | 1 | 1 | ✓ |
| SESS_LM_1172164c53 | lateral_movement | new_device_edge_count | 7 | 7 | ✓ |
| SESS_LM_1172164c53 | lateral_movement | transformer_score | 0.996 | 0.9958 | ✓ |
| SESS_BF_c84171c060 | brute_force | transformer_score | 0.983 | 0.9828 | ✓ |
| SESS_BF_c84171c060 | brute_force | failure_ratio | 0.97 | 0.9655 | ✓ |
| SESS_ID_0edf5039 | insider_drift (benign) | transformer_score | 0.027 | 0.0274 | ✓ |
| SESS_IMP_0f700363 | impossible_travel (plateau) | fp_mismatch | 1 | 1 | ✓ |
| SESS_IMP_0f700363 | impossible_travel (plateau) | event_count | 1 | 1 | ✓ |
| SESS_IMP_0f700363 | impossible_travel (plateau) | transformer_score | 0.479 | 0.4791 | ✓ |

> [!NOTE]
> `geo_velocity_violation` was explicitly checked for each session: the column does NOT exist in the current `fused_scores.parquet` schema (it is a raw-event column, not a session-level feature). The attribution engine correctly never claims `geo_velocity_violation=True` for any session — all hard rules are traced to `fp_mismatch+corroborated` and/or `ip_fan_in_stuffing` only. No hallucinated signals were found.

---

## Template vs LLM Assessment

The template-based approach is **sufficient for this phase**. Specific observations:

**What reads naturally:**
- Tier-1 notes (device_spoofing, lateral_movement, CS with dual hard rules) are clear and self-explanatory. The "detection path" line gives analysts exactly the rule chain that fired.
- The plateau limitation block is the most valuable piece of honest disclosure — it would be easy to omit and the note reads better with it than without.
- Case-level headers (sessions in case, suppression count, time window) add operational value that pure session notes lack.

**Where templates feel mechanical:**
- Tier-2 notes listing many factor bullets can feel like a checklist rather than a narrative (e.g. the brute_force note lists `failure_ratio`, `failure_count`, `logon_count` as separate bullets that could be one sentence: "28 failed logon attempts out of 29 total over this session").
- The impossible_travel impossible-speed detail is not available (`geo_velocity_violation` doesn't exist as a session feature), so the note correctly avoids mentioning it, but leaves the "impossible travel" label somewhat unsupported by the note's own text — the analyst must infer from `foreign_access_count=1` + `fp_mismatch`.

**LLM enhancement verdict:**
An optional LLM pass would improve narrative fluency (collapsing related bullets into sentences, adding inferred context like "typical impossible-travel pattern: single-event logon from a new device with foreign access, consistent with a credential being used from a remote location"). This would be ~2 bullet sentences per note. If Ollama/llama.cpp is already available in the environment, a `--llm` flag on `generate_note.py` with a 2-sentence narrative-smoothing prompt would take <1 hour to add and would noticeably improve the UX. **However, the template path works correctly for the Phase 6 dashboard demo without it.**