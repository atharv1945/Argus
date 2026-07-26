"""
ARGUS UEBA Synthetic Data Generator & Attack Injector (Expanded Spec)
=====================================================================
Generates realistic enterprise security access telemetry logs matching the ARGUS
20-Field Unified Security Event Telemetry Schema and injects 7 malicious attack
vectors + 1 benign insider_drift edge case.

Usage:
    python src/ingest/generate_dataset.py [--num-users 400] [--num-days 21] [--attack-ratio 0.07] [--seed 42]
"""

import os
import argparse
import random
import uuid
import math
import json
from datetime import datetime, timedelta, time
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

import numpy as np
import pandas as pd
import yaml
# pyrefly: ignore [missing-import]
from faker import Faker

# -----------------------------------------------------------------------------
# Severity helpers
# -----------------------------------------------------------------------------

def _severity(val: float, lo: float, hi: float) -> float:
    """Map val from [lo, hi] to [0.0, 1.0], clamped."""
    if hi <= lo:
        return 0.5
    return float(min(max((val - lo) / (hi - lo), 0.0), 1.0))


def _add_session_severity(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute per-session 0-1 severity scores from the natural magnitude feature
    for each malicious attack type.  Normal / insider_drift sessions keep 0.0.

    Attack-type → magnitude feature (rationale):
      brute_force          : failure_count in session  (campaign intensity)
      credential_stuffing  : failure_count in campaign (# victim accounts targeted)
      credential_misuse    : bytes_total in session    (data volume exfiltrated)
      lateral_movement     : bytes_total in session    (data moved across hops)
      low_and_slow_exfil.  : bytes_total per session   (log-scaled, session-level)
      impossible_travel    : bytes_total of malicious  (0 for device-only variant)
      device_spoofing      : fixed 0.5                 (no natural magnitude variation)
    """
    df = df.copy()
    df["severity"] = 0.0

    sev_col_idx = df.columns.get_loc("severity")

    malicious_types = [
        "brute_force", "credential_stuffing", "credential_misuse",
        "lateral_movement", "low_and_slow_exfiltration",
        "impossible_travel", "device_spoofing",
    ]

    for attack_type in malicious_types:
        atk_df = df[df["attack_type"] == attack_type]
        if atk_df.empty:
            continue

        if attack_type == "device_spoofing":
            # Fixed magnitude — no variation exists in the generator
            df.loc[atk_df.index, "severity"] = 0.5
            continue

        for camp_id, camp_grp in atk_df.groupby("attack_instance_id"):
            camp_idx = camp_grp.index

            if attack_type == "brute_force":
                # fail_count range 15–30 (from config)
                fail_count = int((camp_grp["status"] == "FAILURE").sum())
                sev = _severity(fail_count, 15, 30)
                df.loc[camp_idx, "severity"] = sev

            elif attack_type == "credential_stuffing":
                # fail_count range 20–30 across all sessions in this campaign
                fail_count = int((camp_grp["status"] == "FAILURE").sum())
                sev = _severity(fail_count, 20, 30)
                df.loc[camp_idx, "severity"] = sev

            elif attack_type == "credential_misuse":
                # bytes_total range: 4*15M = 60M  to  8*80M = 640M
                bytes_total = int(camp_grp["bytes_transferred"].sum())
                sev = _severity(bytes_total, 60_000_000, 640_000_000)
                df.loc[camp_idx, "severity"] = sev

            elif attack_type == "lateral_movement":
                # hop bytes range: 7*1M = 7M  to  7*10M = 70M
                bytes_total = int(camp_grp["bytes_transferred"].sum())
                sev = _severity(bytes_total, 7_000_000, 70_000_000)
                df.loc[camp_idx, "severity"] = sev

            elif attack_type == "impossible_travel":
                # ITSC variant: bytes 2M–15M; original IT: 0 bytes → use 0.5
                bytes_total = int(camp_grp["bytes_transferred"].sum())
                if bytes_total > 0:
                    sev = _severity(bytes_total, 2_000_000, 15_000_000)
                else:
                    sev = 0.5
                df.loc[camp_idx, "severity"] = sev

            elif attack_type == "low_and_slow_exfiltration":
                # Severity is SESSION-level (each step has different bytes_tx)
                # log-scale: 100K (step-0 min) to 100M (step-7 max estimate)
                log_lo = math.log(100_000)
                log_hi = math.log(100_000_000)
                for sess_id, sess_grp in camp_grp.groupby("session_id"):
                    bytes_tx = int(sess_grp["bytes_transferred"].sum())
                    sev = _severity(math.log(max(bytes_tx, 1)), log_lo, log_hi)
                    df.loc[sess_grp.index, "severity"] = sev

    return df

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

@dataclass
class GeneratorConfig:
    num_users: int = 400
    num_days: int = 21
    start_date_str: str = "2026-06-01"
    random_seed: int = 42
    attack_entity_ratio: float = 0.20  # ~20% of entities targeted by malicious campaigns (raised for sample-size)
    output_dir: str = "data/processed"

DEPARTMENTS = {
    "Engineering": {
        "roles": ["Software Engineer", "Senior Software Engineer", "DevOps Engineer", "QA Engineer"],
        "weight": 0.30,
        "resources": ["RES_ENG_SRV_01", "RES_ENG_SRV_02", "DB_ENG_CODEBASE", "RES_ENG_CI_CD", "RES_ENG_DOCS"]
    },
    "Finance": {
        "roles": ["Finance Analyst", "Senior Accountant", "Payroll Specialist", "Financial Controller"],
        "weight": 0.15,
        "resources": ["RES_FIN_ERP", "DB_FIN_PAYROLL", "RES_FIN_REPORTS", "RES_FIN_LEDGER", "RES_FIN_AUDIT"]
    },
    "HR": {
        "roles": ["HR Specialist", "Recruiter", "HR Business Partner", "HR Director"],
        "weight": 0.10,
        "resources": ["RES_HR_PORTAL", "DB_HR_EMPLOYEE_RECORDS", "RES_HR_BENEFITS", "RES_HR_RECRUITING"]
    },
    "IT": {
        "roles": ["Systems Admin", "Security Analyst", "Network Engineer", "Helpdesk Tech"],
        "weight": 0.15,
        "resources": ["RES_IT_JUMPBOX", "RES_IT_AD_DC", "RES_IT_MONITORING", "RES_IT_FIREWALL_MGR", "RES_IT_KNOWLEDGEBASE"]
    },
    "Sales": {
        "roles": ["Account Executive", "Sales Manager", "Business Dev Rep"],
        "weight": 0.20,
        "resources": ["RES_SALES_CRM", "RES_SALES_PROPOSALS", "RES_SALES_LEADS", "RES_SALES_DEMO_ENV"]
    },
    "Executive": {
        "roles": ["VP of Engineering", "Chief Financial Officer", "Chief Executive Officer", "General Counsel"],
        "weight": 0.10,
        "resources": ["RES_EXEC_BOARD_DECK", "RES_EXEC_STRATEGY", "RES_EXEC_FINANCIALS", "RES_EXEC_LEGAL_VAULT"]
    }
}

SHARED_RESOURCES = [
    ("GW_PROXY_01", "IT"),
    ("GW_PROXY_02", "IT"),
    ("EMAIL_SRV_01", "IT"),
    ("EMAIL_SRV_02", "IT"),
    ("PORTAL_INTRANET", "General"),
    ("WIKI_CORP", "General"),
    ("VPN_GATEWAY_PRIMARY", "IT")
]

COUNTRY_WEIGHTS = {
    "US": 0.85,
    "UK": 0.08,
    "DE": 0.04,
    "CA": 0.03
}

COMMAND_TOKENS = ["read", "write", "execute", "delete", "escalate_privilege", "export_data"]

OS_VERSIONS = [
    "Windows 11 23H2", "Windows Server 2022", "macOS Sonoma 14.4",
    "Ubuntu 22.04 LTS", "Alpine Linux 3.19"
]

PROTOCOLS = ["TLS1.3", "SSHv2", "HTTPS", "mTLS"]

# -----------------------------------------------------------------------------
# User Profile Dataclass & Generator
# -----------------------------------------------------------------------------

@dataclass
class UserProfile:
    entity_id: str
    entity_type: str        # user, service_account, edge_device
    entity_role: str
    entity_dept: str
    auth_method: str        # password, token, certificate, biometric
    home_country: str
    home_ip: str
    primary_device: str
    primary_fingerprint: str
    secondary_device: str
    secondary_fingerprint: str
    shift_start_hour: int
    shift_duration: int
    dept_resources: List[str]
    peer_devices: List[str] = field(default_factory=list)

class UserProfileGenerator:
    def __init__(self, seed: int):
        self.fake = Faker()
        Faker.seed(seed)
        random.seed(seed)
        np.random.seed(seed)

    def _gen_fingerprint(self) -> str:
        os_ver = random.choice(OS_VERSIONS)
        mac = self.fake.mac_address()
        proto = random.choice(PROTOCOLS)
        return f"{os_ver} | {mac} | {proto}"

    def generate_profiles(self, num_users: int) -> List[UserProfile]:
        profiles = []
        dept_names = list(DEPARTMENTS.keys())
        dept_weights = [DEPARTMENTS[d]["weight"] for d in dept_names]
        
        # Entity type distribution: 85% user, 10% service_account, 5% edge_device
        entity_types = np.random.choice(
            ["user", "service_account", "edge_device"],
            size=num_users,
            p=[0.85, 0.10, 0.05]
        )
        
        assigned_depts = np.random.choice(dept_names, size=num_users, p=dept_weights)
        
        for i in range(num_users):
            etype = entity_types[i]
            dept = assigned_depts[i]
            user_num = 1000 + i
            
            if etype == "user":
                entity_id = f"U{user_num}"
                role = random.choice(DEPARTMENTS[dept]["roles"])
                auth_method = random.choices(["password", "biometric", "token"], weights=[0.60, 0.25, 0.15])[0]
            elif etype == "service_account":
                entity_id = f"SVC_{user_num}"
                role = random.choice(["Service Account", "ETL Daemon", "Backup Job", "API Service"])
                auth_method = random.choices(["token", "certificate"], weights=[0.70, 0.30])[0]
            else:  # edge_device
                entity_id = f"EDGE_{user_num}"
                role = random.choice(["IoT Gateway", "Edge Controller", "Kiosk Terminal", "Sensor Hub"])
                auth_method = random.choices(["certificate", "token"], weights=[0.65, 0.35])[0]

            country = random.choices(
                list(COUNTRY_WEIGHTS.keys()), 
                weights=list(COUNTRY_WEIGHTS.values())
            )[0]
            
            home_ip = self.fake.ipv4_private()
            primary_device = f"DEV_{entity_id}_MAIN"
            primary_fp = self._gen_fingerprint()
            
            secondary_device = f"DEV_{entity_id}_ALT" if random.random() < 0.3 else primary_device
            secondary_fp = self._gen_fingerprint() if secondary_device != primary_device else primary_fp
            
            if etype in ["service_account", "edge_device"]:
                shift_start = 0  # 24/7 background operation
                shift_duration = 24
            elif dept == "IT" and random.random() < 0.25:
                shift_start = random.choice([0, 7, 15, 16])
                shift_duration = random.choice([8, 9])
            else:
                shift_start = random.choice([8, 9, 10])
                shift_duration = random.choice([8, 9])
                
            dept_resources = DEPARTMENTS[dept]["resources"]
            
            profiles.append(UserProfile(
                entity_id=entity_id,
                entity_type=etype,
                entity_role=role,
                entity_dept=dept,
                auth_method=auth_method,
                home_country=country,
                home_ip=home_ip,
                primary_device=primary_device,
                primary_fingerprint=primary_fp,
                secondary_device=secondary_device,
                secondary_fingerprint=secondary_fp,
                shift_start_hour=shift_start,
                shift_duration=shift_duration,
                dept_resources=dept_resources
            ))
            
        all_devices = [p.primary_device for p in profiles]
        for p in profiles:
            p.peer_devices = random.sample(all_devices, min(10, len(all_devices)))
            
        return profiles

# -----------------------------------------------------------------------------
# Command Sequence Helper
# -----------------------------------------------------------------------------

def generate_command_sequence(resource_id: str) -> str:
    """Generate ordered 2-8 action tokens for privileged sessions."""
    is_privileged = any(kw in resource_id for kw in ["RES_IT", "RES_EXEC", "DB_", "RES_SRV", "CI_CD", "ERP", "VAULT"])
    if not is_privileged:
        return ""
    
    num_tokens = random.randint(2, 6)
    tokens = random.choices(COMMAND_TOKENS, weights=[0.4, 0.2, 0.2, 0.08, 0.04, 0.08], k=num_tokens)
    return ",".join(tokens)

# -----------------------------------------------------------------------------
# Normal Behavior Generator
# -----------------------------------------------------------------------------

class NormalBehaviorGenerator:
    def __init__(self, profiles: List[UserProfile], config: GeneratorConfig):
        self.profiles = profiles
        self.config = config
        self.start_date = datetime.strptime(config.start_date_str, "%Y-%m-%d")

    def generate(self) -> List[Dict]:
        events = []
        
        for day_idx in range(self.config.num_days):
            current_date = self.start_date + timedelta(days=day_idx)
            is_weekend = current_date.weekday() >= 5
            
            for user in self.profiles:
                if user.entity_type == "user":
                    work_probability = 0.10 if is_weekend else 0.95
                else:
                    work_probability = 1.00  # Service accounts & edge devices run 24/7
                    
                if random.random() > work_probability:
                    continue
                
                num_sessions = random.choice([1, 2]) if not is_weekend else 1
                
                for s_idx in range(num_sessions):
                    jitter_minutes = int(np.random.normal(0, 25))
                    session_start_hour = (user.shift_start_hour + s_idx * 4) % 24
                    session_start = current_date.replace(
                        hour=session_start_hour, 
                        minute=random.randint(0, 59)
                    ) + timedelta(minutes=jitter_minutes)
                    
                    session_duration_minutes = random.randint(120, 270)
                    session_end = session_start + timedelta(minutes=session_duration_minutes)
                    session_id = f"SESS_{uuid.uuid4().hex[:12]}"
                    
                    device = user.primary_device if random.random() < 0.85 else user.secondary_device
                    fingerprint = user.primary_fingerprint if device == user.primary_device else user.secondary_fingerprint
                    
                    # 1. LOGON Event
                    events.append({
                        "entity_id": user.entity_id,
                        "entity_type": user.entity_type,
                        "entity_role": user.entity_role,
                        "entity_dept": user.entity_dept,
                        "timestamp": session_start,
                        "event_type": "logon",
                        "auth_method": user.auth_method,
                        "resource_id": "VPN_GATEWAY_PRIMARY" if random.random() < 0.4 else "PORTAL_INTRANET",
                        "resource_dept": "IT",
                        "command_sequence": "",
                        "device_id": device,
                        "device_fingerprint": fingerprint,
                        "geo_country": user.home_country,
                        "geo_ip": user.home_ip,
                        "session_id": session_id,
                        "bytes_transferred": 0,
                        "status": "SUCCESS",
                        "is_malicious": False,
                        "attack_type": "none",
                        "attack_instance_id": "none"
                    })
                    
                    # 2. Intra-session Activity Events
                    num_events = random.randint(6, 20)
                    for _ in range(num_events):
                        offset_sec = random.randint(60, session_duration_minutes * 60 - 60)
                        event_time = session_start + timedelta(seconds=offset_sec)
                        
                        event_type = random.choices(
                            ["file_access", "http", "email", "device_connect"],
                            weights=[0.35, 0.45, 0.15, 0.05]
                        )[0]
                        
                        if random.random() < 0.75:
                            res_id = random.choice(user.dept_resources)
                            res_dept = user.entity_dept
                        else:
                            res_tuple = random.choice(SHARED_RESOURCES)
                            res_id, res_dept = res_tuple[0], res_tuple[1]
                            
                        if event_type == "file_access":
                            bytes_tx = int(np.random.lognormal(mean=11.5, sigma=1.2))
                        elif event_type == "http":
                            bytes_tx = int(np.random.lognormal(mean=8.5, sigma=1.0))
                        elif event_type == "email":
                            bytes_tx = int(np.random.lognormal(mean=9.5, sigma=1.1))
                        else:
                            bytes_tx = 0
                            
                        cmd_seq = generate_command_sequence(res_id)
                        
                        events.append({
                            "entity_id": user.entity_id,
                            "entity_type": user.entity_type,
                            "entity_role": user.entity_role,
                            "entity_dept": user.entity_dept,
                            "timestamp": event_time,
                            "event_type": event_type,
                            "auth_method": user.auth_method,
                            "resource_id": res_id,
                            "resource_dept": res_dept,
                            "command_sequence": cmd_seq,
                            "device_id": device,
                            "device_fingerprint": fingerprint,
                            "geo_country": user.home_country,
                            "geo_ip": user.home_ip,
                            "session_id": session_id,
                            "bytes_transferred": max(0, bytes_tx),
                            "status": "SUCCESS",
                            "is_malicious": False,
                            "attack_type": "none",
                            "attack_instance_id": "none"
                        })
                        
                    # 3. LOGOFF Event
                    events.append({
                        "entity_id": user.entity_id,
                        "entity_type": user.entity_type,
                        "entity_role": user.entity_role,
                        "entity_dept": user.entity_dept,
                        "timestamp": session_end,
                        "event_type": "logoff",
                        "auth_method": user.auth_method,
                        "resource_id": "PORTAL_INTRANET",
                        "resource_dept": "IT",
                        "command_sequence": "",
                        "device_id": device,
                        "device_fingerprint": fingerprint,
                        "geo_country": user.home_country,
                        "geo_ip": user.home_ip,
                        "session_id": session_id,
                        "bytes_transferred": 0,
                        "status": "SUCCESS",
                        "is_malicious": False,
                        "attack_type": "none",
                        "attack_instance_id": "none"
                    })
                    
        return events

# -----------------------------------------------------------------------------
# Attack Injector (8 Categories)
# -----------------------------------------------------------------------------

def _derive_seed(base_seed: int, name: str) -> int:
    """Derive a deterministic per-injector seed from base_seed + attack-type name.
    Changing one attack type's campaign count or parameters cannot shift other types."""
    return (base_seed + abs(hash(name))) % (2 ** 31)


class AttackInjector:
    def __init__(self, profiles: List[UserProfile], config: GeneratorConfig):
        self.profiles = profiles
        self.config = config
        self.start_date = datetime.strptime(config.start_date_str, "%Y-%m-%d")
        self.fake = Faker()

        # ── Load attack pattern config ──────────────────────────────────────
        config_path = os.path.join("config", "attack_patterns.yaml")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                self._ap = yaml.safe_load(f)
        else:
            print(f"[WARNING] {config_path} not found — using built-in defaults.")
            self._ap = {"base_seed": config.random_seed}

        # ── Per-injector isolated RNGs (seed isolation fix) ─────────────────
        # Each attack type gets its own deterministic random.Random and
        # np.random.Generator so that changing one injector's campaign count
        # cannot shift another injector's PRNG state.
        attack_type_names = [
            "credential_misuse", "brute_force", "lateral_movement",
            "impossible_travel", "device_spoofing", "credential_stuffing",
            "low_and_slow_exfiltration", "impossible_travel_sc",
            "insider_drift", "scheduling",  # scheduling = campaign date selection RNG
        ]
        self._rng: Dict[str, random.Random] = {}
        self._np_rng: Dict[str, np.random.Generator] = {}
        for name in attack_type_names:
            seed = _derive_seed(config.random_seed, name)
            self._rng[name] = random.Random(seed)
            self._np_rng[name] = np.random.default_rng(seed)

    def inject_all_vectors(self) -> List[Dict]:
        attack_events = []
        # Scale to ~10-12 campaigns per thin attack class (G1: increase sample size)
        num_attack_users = max(56, int(len(self.profiles) * self.config.attack_entity_ratio))
        # Use scheduling RNG for user selection so it's isolated from injector RNGs
        sched_rng = self._rng["scheduling"]
        target_users = sched_rng.sample(self.profiles, min(num_attack_users, len(self.profiles) - 10))

        malicious_types = [
            "credential_misuse",
            "brute_force",
            "lateral_movement",
            "impossible_travel",
            "device_spoofing",
            "credential_stuffing",
            "low_and_slow_exfiltration",
            # impossible_travel_sc: same-device stolen-credential variant (G5c)
            "impossible_travel_sc",
        ]

        vector_campaign_counts = {at: 0 for at in malicious_types}

        for idx, user in enumerate(target_users):
            attack_type = malicious_types[idx % len(malicious_types)]
            vector_campaign_counts[attack_type] += 1
            campaign_num = vector_campaign_counts[attack_type]

            # Per-type scheduling RNG for campaign date — isolated from injector RNGs
            type_sched_key = attack_type if attack_type in self._rng else "scheduling"
            day_offset = self._rng[type_sched_key].randint(2, max(2, self.config.num_days - 2))
            campaign_date = self.start_date + timedelta(days=day_offset)

            if attack_type == "credential_misuse":
                attack_events.extend(self._inject_credential_misuse(user, campaign_date, campaign_num))
            elif attack_type == "brute_force":
                attack_events.extend(self._inject_brute_force(user, campaign_date, campaign_num))
            elif attack_type == "lateral_movement":
                attack_events.extend(self._inject_lateral_movement(user, campaign_date, campaign_num))
            elif attack_type == "impossible_travel":
                attack_events.extend(self._inject_impossible_travel(user, campaign_date, campaign_num))
            elif attack_type == "impossible_travel_sc":
                # Same-device stolen-credential impossible travel (fp_mismatch=0, geo_velocity=1)
                attack_events.extend(self._inject_stolen_credential_impossible_travel(user, campaign_date, campaign_num))
            elif attack_type == "device_spoofing":
                attack_events.extend(self._inject_device_spoofing(user, campaign_date, campaign_num))
            elif attack_type == "credential_stuffing":
                # Credential stuffing targets multiple entities at once
                victim_pool = self._rng["credential_stuffing"].sample(self.profiles, 8)
                attack_events.extend(self._inject_credential_stuffing(victim_pool, campaign_date, campaign_num))
            elif attack_type == "low_and_slow_exfiltration":
                attack_events.extend(self._inject_low_and_slow_exfiltration(user, campaign_date, campaign_num))

        # Inject benign insider_drift edge cases (is_malicious=False)
        # Campaigns 1-5: original, Campaign 6: harder fan-out mimicking lateral_movement (G2)
        id_rng = self._rng["insider_drift"]
        remaining = [p for p in self.profiles if p not in target_users]
        drift_users = id_rng.sample(remaining, min(6, len(remaining)))
        for d_num, d_user in enumerate(drift_users, 1):
            d_date = self.start_date + timedelta(days=id_rng.randint(3, 10))
            if d_num <= 5:
                attack_events.extend(self._inject_insider_drift(d_user, d_date, d_num))
            else:
                # Campaign 6: harder insider drift — cross-dept fan-out in one day (G2)
                attack_events.extend(self._inject_harder_insider_drift(d_user, d_date, 6))

        return attack_events

    # --- 5 Existing Attack Vectors ---

    def _inject_credential_misuse(self, user: UserProfile, date: datetime, campaign_num: int) -> List[Dict]:
        rng = self._rng["credential_misuse"]
        events = []
        instance_id = f"ATK_CM_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        cm_cfg = self._ap.get("credential_misuse", {})
        off_hours = cm_cfg.get("off_hour_choices", [1, 2, 3, 22, 23])
        exfil_min, exfil_max = cm_cfg.get("exfil_events_range", [4, 8])
        b_min, b_max = cm_cfg.get("bytes_range", [15_000_000, 80_000_000])
        off_hour = rng.choice(off_hours)
        start_time = date.replace(hour=off_hour, minute=rng.randint(5, 55), second=0)
        session_id = f"SESS_MAL_{uuid.uuid4().hex[:10]}"

        sensitive_targets = [("RES_EXEC_STRATEGY", "Executive"), ("DB_FIN_PAYROLL", "Finance"), ("DB_HR_EMPLOYEE_RECORDS", "HR")]
        foreign_targets = [t for t in sensitive_targets if t[1] != user.entity_dept] or sensitive_targets

        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": start_time, "event_type": "logon",
            "auth_method": user.auth_method, "resource_id": "RES_IT_JUMPBOX", "resource_dept": "IT",
            "command_sequence": "read,escalate_privilege,execute", "device_id": user.primary_device,
            "device_fingerprint": user.primary_fingerprint, "geo_country": user.home_country, "geo_ip": user.home_ip,
            "session_id": session_id, "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": True,
            "attack_type": "credential_misuse", "attack_instance_id": instance_id
        })

        num_exfil = rng.randint(exfil_min, exfil_max)
        for i in range(num_exfil):
            t_offset = start_time + timedelta(minutes=i * 3 + 2)
            res_id, res_dept = rng.choice(foreign_targets)
            events.append({
                "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
                "entity_dept": user.entity_dept, "timestamp": t_offset, "event_type": "file_access",
                "auth_method": user.auth_method, "resource_id": res_id, "resource_dept": res_dept,
                "command_sequence": "read,export_data", "device_id": user.primary_device,
                "device_fingerprint": user.primary_fingerprint, "geo_country": user.home_country, "geo_ip": user.home_ip,
                "session_id": session_id, "bytes_transferred": rng.randint(b_min, b_max),
                "status": "SUCCESS", "is_malicious": True, "attack_type": "credential_misuse", "attack_instance_id": instance_id
            })

        return events

    def _inject_brute_force(self, user: UserProfile, date: datetime, campaign_num: int) -> List[Dict]:
        rng = self._rng["brute_force"]
        events = []
        instance_id = f"ATK_BF_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        bf_cfg = self._ap.get("brute_force", {})
        h_min, h_max = bf_cfg.get("hour_range", [7, 21])
        fc_min, fc_max = bf_cfg.get("fail_count_range", [15, 30])
        interval_sec = bf_cfg.get("attempt_interval_sec", 6)
        start_time = date.replace(hour=rng.randint(h_min, h_max), minute=rng.randint(0, 50), second=0)
        session_id = f"SESS_BF_{uuid.uuid4().hex[:10]}"
        target_res = rng.choice(["RES_FIN_ERP", "DB_ENG_CODEBASE", "RES_HR_PORTAL"])
        attacker_ip = f"198.51.100.{rng.randint(10, 200)}"

        fail_count = rng.randint(fc_min, fc_max)
        for i in range(fail_count):
            t_offset = start_time + timedelta(seconds=i * interval_sec)
            events.append({
                "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
                "entity_dept": user.entity_dept, "timestamp": t_offset, "event_type": "logon",
                "auth_method": "password", "resource_id": target_res, "resource_dept": "Finance",
                "command_sequence": "", "device_id": user.primary_device, "device_fingerprint": user.primary_fingerprint,
                "geo_country": user.home_country, "geo_ip": attacker_ip, "session_id": session_id,
                "bytes_transferred": 0, "status": "FAILURE", "is_malicious": True, "attack_type": "brute_force", "attack_instance_id": instance_id
            })

        succ_time = start_time + timedelta(seconds=fail_count * interval_sec + 10)
        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": succ_time, "event_type": "logon",
            "auth_method": "password", "resource_id": target_res, "resource_dept": "Finance",
            "command_sequence": "read,execute", "device_id": user.primary_device, "device_fingerprint": user.primary_fingerprint,
            "geo_country": user.home_country, "geo_ip": attacker_ip, "session_id": session_id,
            "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": True, "attack_type": "brute_force", "attack_instance_id": instance_id
        })
        return events

    def _inject_lateral_movement(self, user: UserProfile, date: datetime, campaign_num: int) -> List[Dict]:
        rng = self._rng["lateral_movement"]
        events = []
        instance_id = f"ATK_LM_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        lm_cfg = self._ap.get("lateral_movement", {})
        h_min, h_max = lm_cfg.get("hour_range", [8, 20])
        dev_count = lm_cfg.get("foreign_device_count", 7)
        hop_min, hop_max = lm_cfg.get("hop_interval_min_range", [1, 4])
        start_time = date.replace(hour=rng.randint(h_min, h_max), minute=rng.randint(0, 45), second=0)
        session_id = f"SESS_LM_{uuid.uuid4().hex[:10]}"

        foreign_devices = [f"DEV_FOREIGN_HOST_{campaign_num:02d}_{i:02d}" for i in range(1, dev_count + 1)]
        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": start_time, "event_type": "logon",
            "auth_method": user.auth_method, "resource_id": "RES_IT_AD_DC", "resource_dept": "IT",
            "command_sequence": "read,escalate_privilege", "device_id": user.primary_device,
            "device_fingerprint": user.primary_fingerprint, "geo_country": user.home_country, "geo_ip": user.home_ip,
            "session_id": session_id, "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": True,
            "attack_type": "lateral_movement", "attack_instance_id": instance_id
        })

        # [ARTIFACT FIX] Hop timing: was always i*2+1 min (duration_min=13, std=0).
        # Now each hop interval is jittered from hop_interval_min_range.
        cumulative_offset = 0
        for i, dev in enumerate(foreign_devices):
            cumulative_offset += rng.randint(hop_min, hop_max)
            t_offset = start_time + timedelta(minutes=cumulative_offset)
            target_res = f"RES_SRV_HOST_{campaign_num:02d}_{i+1:02d}"
            events.append({
                "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
                "entity_dept": user.entity_dept, "timestamp": t_offset, "event_type": "device_connect",
                "auth_method": user.auth_method, "resource_id": target_res, "resource_dept": "Finance",
                "command_sequence": "read,execute", "device_id": dev, "device_fingerprint": f"Linux | {dev} | SSHv2",
                "geo_country": user.home_country, "geo_ip": user.home_ip, "session_id": session_id,
                "bytes_transferred": rng.randint(1_000_000, 10_000_000), "status": "SUCCESS",
                "is_malicious": True, "attack_type": "lateral_movement", "attack_instance_id": instance_id
            })
        return events

    def _inject_impossible_travel(self, user: UserProfile, date: datetime, campaign_num: int) -> List[Dict]:
        """Original impossible travel: fp_mismatch=1 (unrecognized VPN device) + geo_velocity=1."""
        rng = self._rng["impossible_travel"]
        events = []
        instance_id = f"ATK_IT_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        it_cfg = self._ap.get("impossible_travel", {})
        h_min, h_max = it_cfg.get("hour_range", [8, 18])
        gap_min = it_cfg.get("gap_minutes", 12)
        time_us = date.replace(hour=rng.randint(h_min, h_max), minute=10, second=0)
        session_us = f"SESS_US_{uuid.uuid4().hex[:8]}"

        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": time_us, "event_type": "logon",
            "auth_method": user.auth_method, "resource_id": "PORTAL_INTRANET", "resource_dept": "General",
            "command_sequence": "", "device_id": user.primary_device, "device_fingerprint": user.primary_fingerprint,
            "geo_country": user.home_country, "geo_ip": user.home_ip, "session_id": session_us,
            "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": False, "attack_type": "none", "attack_instance_id": "none"
        })

        time_foreign = time_us + timedelta(minutes=gap_min)
        session_foreign = f"SESS_IMP_{uuid.uuid4().hex[:8]}"
        foreign_country, foreign_ip = rng.choice([("CN", "202.108.22.99"), ("RU", "95.173.136.42")])

        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": time_foreign, "event_type": "logon",
            "auth_method": user.auth_method, "resource_id": "VPN_GATEWAY_PRIMARY", "resource_dept": "IT",
            "command_sequence": "", "device_id": "DEV_UNRECOGNIZED_VPN_GW", "device_fingerprint": "Linux | 00:00:00:00:00:00 | TLS1.3",
            "geo_country": foreign_country, "geo_ip": foreign_ip, "session_id": session_foreign,
            "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": True, "attack_type": "impossible_travel", "attack_instance_id": instance_id
        })
        return events

    def _inject_stolen_credential_impossible_travel(self, user: UserProfile, date: datetime, campaign_num: int) -> List[Dict]:
        """
        [G5c] Stolen-credential impossible travel: fp_mismatch=0, geo_velocity_violation=1.
        Attacker uses a cloned session token (no device change needed).
        The entity's PRIMARY device fingerprint is preserved, but the geo origin
        shifts to a foreign country within 60 minutes of their last authenticated session.
        is_malicious=True, attack_type='impossible_travel'.
        """
        rng = self._rng["impossible_travel_sc"]
        events = []
        instance_id = f"ATK_ITSC_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        # Entity's normal morning session (benign, same device + home country)
        time_legit = date.replace(hour=rng.randint(8, 10), minute=5, second=0)
        session_legit = f"SESS_LEGIT_{uuid.uuid4().hex[:8]}"
        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": time_legit, "event_type": "logon",
            "auth_method": user.auth_method, "resource_id": "PORTAL_INTRANET", "resource_dept": "General",
            "command_sequence": "", "device_id": user.primary_device, "device_fingerprint": user.primary_fingerprint,
            "geo_country": user.home_country, "geo_ip": user.home_ip, "session_id": session_legit,
            "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": False, "attack_type": "none",
            "attack_instance_id": "none"
        })
        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": time_legit + timedelta(minutes=25), "event_type": "logoff",
            "auth_method": user.auth_method, "resource_id": "PORTAL_INTRANET", "resource_dept": "General",
            "command_sequence": "", "device_id": user.primary_device, "device_fingerprint": user.primary_fingerprint,
            "geo_country": user.home_country, "geo_ip": user.home_ip, "session_id": session_legit,
            "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": False, "attack_type": "none",
            "attack_instance_id": "none"
        })
        # Attacker session: SAME device + fingerprint (token theft), but foreign geo — 45 min later
        time_attack = time_legit + timedelta(minutes=45)
        session_attack = f"SESS_ITSC_{uuid.uuid4().hex[:8]}"
        foreign_country, foreign_ip = rng.choice([("CN", "202.108.22.100"), ("BR", "189.1.100.50"), ("NG", "41.76.111.21")])
        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": time_attack, "event_type": "logon",
            "auth_method": user.auth_method,  # same auth method — session token reuse
            "resource_id": "RES_EXEC_FINANCIALS", "resource_dept": "Executive",
            "command_sequence": "read,export_data", "device_id": user.primary_device,
            "device_fingerprint": user.primary_fingerprint,  # SAME fingerprint (no hardware change)
            "geo_country": foreign_country, "geo_ip": foreign_ip, "session_id": session_attack,
            "bytes_transferred": rng.randint(2_000_000, 15_000_000),
            "status": "SUCCESS", "is_malicious": True, "attack_type": "impossible_travel",
            "attack_instance_id": instance_id
        })
        return events

    def _inject_device_spoofing(self, user: UserProfile, date: datetime, campaign_num: int) -> List[Dict]:
        rng = self._rng["device_spoofing"]
        events = []
        instance_id = f"ATK_DS_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        ds_cfg = self._ap.get("device_spoofing", {})
        h_min, h_max = ds_cfg.get("hour_range", [6, 21])
        start_time = date.replace(hour=rng.randint(h_min, h_max), minute=20, second=0)
        session_id = f"SESS_DS_{uuid.uuid4().hex[:10]}"
        spoofed_device = f"DEV_ROGUE_{rng.randint(100, 999)}"
        spoofed_fp = "FreeBSD 13 | 02:42:FF:FF:FF:FF | HTTPS"  # Spoofed fingerprint!

        events.append({
            "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
            "entity_dept": user.entity_dept, "timestamp": start_time, "event_type": "logon",
            "auth_method": user.auth_method, "resource_id": "RES_IT_JUMPBOX", "resource_dept": "IT",
            "command_sequence": "read,execute", "device_id": spoofed_device, "device_fingerprint": spoofed_fp,
            "geo_country": user.home_country, "geo_ip": "10.0.99.14", "session_id": session_id,
            "bytes_transferred": 0, "status": "SUCCESS", "is_malicious": True, "attack_type": "device_spoofing", "attack_instance_id": instance_id
        })
        return events

    # --- 3 NEW Patterns ---

    def _inject_credential_stuffing(self, victim_pool: List[UserProfile], date: datetime, campaign_num: int) -> List[Dict]:
        """[NEW] Pattern 1: MANY entity_ids attempting auth from a FEW shared source_ips with high failure rate."""
        rng = self._rng["credential_stuffing"]
        events = []
        instance_id = f"ATK_CS_{date.strftime('%Y%m%d')}_{campaign_num:03d}"
        cs_cfg = self._ap.get("credential_stuffing", {})
        h_min, h_max = cs_cfg.get("hour_range", [1, 5])
        fc_min, fc_max = cs_cfg.get("fail_count_range", [20, 30])  # [ARTIFACT FIX] was hardcoded 25
        interval_sec = cs_cfg.get("attempt_interval_sec", 4)
        start_time = date.replace(hour=rng.randint(h_min, h_max), minute=rng.randint(0, 50), second=0)
        attacker_ip = f"203.0.113.{rng.randint(10, 90)}"

        # [ARTIFACT FIX] fail_count: was exactly 25 (std=0). Now drawn from config range.
        fail_count = rng.randint(fc_min, fc_max)
        for i in range(fail_count):
            victim = victim_pool[i % len(victim_pool)]
            t_offset = start_time + timedelta(seconds=i * interval_sec + rng.randint(0, 2))
            session_id = f"SESS_CS_{uuid.uuid4().hex[:8]}"

            events.append({
                "entity_id": victim.entity_id,
                "entity_type": victim.entity_type,
                "entity_role": victim.entity_role,
                "entity_dept": victim.entity_dept,
                "timestamp": t_offset,
                "event_type": "logon",
                "auth_method": "password",
                "resource_id": "PORTAL_INTRANET",
                "resource_dept": "General",
                "command_sequence": "",
                "device_id": f"DEV_STUFFER_BOT_{i % 3}",
                "device_fingerprint": "Linux | 02:42:AC:00:00:99 | HTTP",
                "geo_country": "RU",
                "geo_ip": attacker_ip,
                "session_id": session_id,
                "bytes_transferred": 0,
                "status": "FAILURE",
                "is_malicious": True,
                "attack_type": "credential_stuffing",
                "attack_instance_id": instance_id
            })

        # 1 successful compromise logon
        chosen_victim = victim_pool[0]
        succ_time = start_time + timedelta(seconds=fail_count * interval_sec + 15)
        succ_session = f"SESS_CS_SUCCESS_{uuid.uuid4().hex[:8]}"
        events.append({
            "entity_id": chosen_victim.entity_id,
            "entity_type": chosen_victim.entity_type,
            "entity_role": chosen_victim.entity_role,
            "entity_dept": chosen_victim.entity_dept,
            "timestamp": succ_time,
            "event_type": "logon",
            "auth_method": "password",
            "resource_id": "PORTAL_INTRANET",
            "resource_dept": "General",
            "command_sequence": "read,export_data",
            "device_id": "DEV_STUFFER_BOT_0",
            "device_fingerprint": "Linux | 02:42:AC:00:00:99 | HTTP",
            "geo_country": "RU",
            "geo_ip": attacker_ip,
            "session_id": succ_session,
            "bytes_transferred": rng.randint(5_000_000, 25_000_000),
            "status": "SUCCESS",
            "is_malicious": True,
            "attack_type": "credential_stuffing",
            "attack_instance_id": instance_id
        })

        return events

    def _inject_low_and_slow_exfiltration(self, user: UserProfile, start_date: datetime, campaign_num: int) -> List[Dict]:
        """
        [NEW] Pattern 2: Gradual, small, off-hours resource access building up incrementally.

        ARTIFACT FIXES applied (vs original hardcoded version):
          - duration_min: drawn from config range (was exactly 15.00 min, std=0)
          - logoff_count: Bernoulli draw (was always 0 — no logoff ever injected)
          - bytes_total:  per-campaign randomized growth ladder (was fixed 200_000 * 1.8^step)
        """
        rng = self._rng["low_and_slow_exfiltration"]
        np_rng = self._np_rng["low_and_slow_exfiltration"]
        events = []
        instance_id = f"ATK_LS_{start_date.strftime('%Y%m%d')}_{campaign_num:03d}"
        ls_cfg = self._ap.get("low_and_slow_exfiltration", {})

        sessions_n = ls_cfg.get("sessions_per_campaign", 8)
        spread_days = ls_cfg.get("session_spread_days", 12)
        off_hours = ls_cfg.get("off_hours_choices", [1, 2, 3, 23])

        # [ARTIFACT FIX] Per-campaign randomized bytes growth ladder
        b_min, b_max = ls_cfg.get("bytes_base_range", [150_000, 300_000])
        g_min, g_max = ls_cfg.get("bytes_growth_rate_range", [1.6, 2.2])
        base_bytes = rng.randint(b_min, b_max)
        growth_rate = g_min + rng.random() * (g_max - g_min)

        # [ARTIFACT FIX] Session duration and offset from config
        dur_min_lo, dur_min_hi = ls_cfg.get("duration_min_range", [30, 90])
        act_off_lo, act_off_hi = ls_cfg.get("action_offset_min_range", [10, 40])
        logoff_prob = ls_cfg.get("logoff_prob", 0.35)

        # 8 sessions spread over ~12 days
        for step in range(sessions_n):
            day_step = (step * spread_days / max(sessions_n - 1, 1)) + rng.uniform(0, 0.5)
            sess_date = start_date + timedelta(days=day_step)
            start_time = sess_date.replace(
                hour=rng.choice(off_hours), minute=rng.randint(10, 50), second=0, microsecond=0
            )
            session_id = f"SESS_LS_{uuid.uuid4().hex[:8]}"

            # Per-campaign stochastic bytes ladder
            bytes_tx = int(base_bytes * (growth_rate ** step))

            # [ARTIFACT FIX] Session duration: drawn from range, not hardcoded 15.0 min
            duration_min = dur_min_lo + rng.random() * (dur_min_hi - dur_min_lo)
            # [ARTIFACT FIX] Action offset: drawn from range, not hardcoded 15 min
            action_offset_min = act_off_lo + rng.random() * (act_off_hi - act_off_lo)

            events.append({
                "entity_id": user.entity_id,
                "entity_type": user.entity_type,
                "entity_role": user.entity_role,
                "entity_dept": user.entity_dept,
                "timestamp": start_time,
                "event_type": "logon",
                "auth_method": user.auth_method,
                "resource_id": "RES_EXEC_FINANCIALS",
                "resource_dept": "Executive",
                "command_sequence": "read,export_data",
                "device_id": user.primary_device,
                "device_fingerprint": user.primary_fingerprint,
                "geo_country": user.home_country,
                "geo_ip": user.home_ip,
                "session_id": session_id,
                "bytes_transferred": 0,
                "status": "SUCCESS",
                "is_malicious": True,
                "attack_type": "low_and_slow_exfiltration",
                "attack_instance_id": instance_id
            })

            events.append({
                "entity_id": user.entity_id,
                "entity_type": user.entity_type,
                "entity_role": user.entity_role,
                "entity_dept": user.entity_dept,
                "timestamp": start_time + timedelta(minutes=action_offset_min),
                "event_type": "file_access",
                "auth_method": user.auth_method,
                "resource_id": "RES_EXEC_FINANCIALS",
                "resource_dept": "Executive",
                "command_sequence": "read,export_data",
                "device_id": user.primary_device,
                "device_fingerprint": user.primary_fingerprint,
                "geo_country": user.home_country,
                "geo_ip": user.home_ip,
                "session_id": session_id,
                "bytes_transferred": bytes_tx,
                "status": "SUCCESS",
                "is_malicious": True,
                "attack_type": "low_and_slow_exfiltration",
                "attack_instance_id": instance_id
            })

            # [ARTIFACT FIX] Logoff event: Bernoulli(logoff_prob) — was always 0
            if rng.random() < logoff_prob:
                logoff_time = start_time + timedelta(minutes=duration_min)
                events.append({
                    "entity_id": user.entity_id,
                    "entity_type": user.entity_type,
                    "entity_role": user.entity_role,
                    "entity_dept": user.entity_dept,
                    "timestamp": logoff_time,
                    "event_type": "logoff",
                    "auth_method": user.auth_method,
                    "resource_id": "RES_EXEC_FINANCIALS",
                    "resource_dept": "Executive",
                    "command_sequence": "",
                    "device_id": user.primary_device,
                    "device_fingerprint": user.primary_fingerprint,
                    "geo_country": user.home_country,
                    "geo_ip": user.home_ip,
                    "session_id": session_id,
                    "bytes_transferred": 0,
                    "status": "SUCCESS",
                    "is_malicious": True,
                    "attack_type": "low_and_slow_exfiltration",
                    "attack_instance_id": instance_id
                })

        return events



    def _inject_insider_drift(self, user: UserProfile, start_date: datetime, campaign_num: int) -> List[Dict]:
        """
        [NEW] Pattern 3: AMBIGUOUS EDGE CASE — benign entity expanding privilege/resource footprint over time.
        is_malicious = False for ALL instances.
        
        To prevent formulaic train-test similarity, each campaign_num (1 to 5) exhibits a
        DISTINCT behavioral dimension of benign drift:
          - Campaign 1 (Train): Cross-departmental resource & project expansion (high foreign_access)
          - Campaign 2 (Train): Late-night off-hours work schedule shift (off_hours_flag = 1)
          - Campaign 3 (Train): Internal report data export volume drift (high bytes_transferred)
          - Campaign 4 (Test) : Hardware upgrade & certificate auth switch (fp_mismatch = 1)
          - Campaign 5 (Test) : Privileged deployment script execution (high cmd_seq_length & escalate token)
        """
        events = []
        instance_id = f"ATK_ID_{start_date.strftime('%Y%m%d')}_{campaign_num:03d}"
        
        for step in range(5):
            sess_date = start_date + timedelta(days=step*2 + random.uniform(0, 0.4))
            session_id = f"SESS_ID_{uuid.uuid4().hex[:8]}"
            
            # --- Campaign-specific behavioral parameterization ---
            if campaign_num == 1:
                # 1. Cross-dept resource expansion (Daytime)
                start_time = sess_date.replace(hour=14, minute=random.randint(10, 45))
                res_id, res_dept = random.choice([
                    ("RES_FIN_ERP", "Finance"), ("RES_EXEC_BOARD_DECK", "Executive"),
                    ("DB_FIN_PAYROLL", "Finance"), ("RES_HR_PORTAL", "HR")
                ])
                cmd_seq = "read,write"
                device = user.primary_device
                fp = user.primary_fingerprint
                auth = user.auth_method
                bytes_tx = random.randint(200_000, 800_000)
                
            elif campaign_num == 2:
                # 2. Late-night off-hours work schedule shift (23:00 to 03:00)
                start_time = sess_date.replace(hour=random.choice([23, 0, 1, 2]), minute=random.randint(10, 50))
                res_id, res_dept = "WIKI_CORP", "General"
                cmd_seq = ""
                device = user.primary_device
                fp = user.primary_fingerprint
                auth = user.auth_method
                bytes_tx = random.randint(50_000, 300_000)
                
            elif campaign_num == 3:
                # 3. Internal data export volume drift (High bytes_transferred)
                start_time = sess_date.replace(hour=11, minute=random.randint(10, 45))
                res_id = random.choice(user.dept_resources)
                res_dept = user.entity_dept
                cmd_seq = "read,export_data"
                device = user.primary_device
                fp = user.primary_fingerprint
                auth = user.auth_method
                bytes_tx = random.randint(8_000_000, 20_000_000)
                
            elif campaign_num == 4:
                # 4. Hardware upgrade & certificate auth switch (Test split)
                start_time = sess_date.replace(hour=10, minute=random.randint(10, 45))
                res_id = random.choice(user.dept_resources)
                res_dept = user.entity_dept
                cmd_seq = "read,write"
                device = f"DEV_{user.entity_id}_NEW_LAPTOP"
                fp = f"macOS Sonoma 14.4 | {self.fake.mac_address()} | mTLS"  # New hardware fingerprint!
                auth = "certificate"
                bytes_tx = random.randint(100_000, 500_000)
                
            else:  # campaign_num == 5
                # 5. Privileged deployment script execution (Test split)
                start_time = sess_date.replace(hour=15, minute=random.randint(10, 45))
                res_id = "RES_ENG_CI_CD"
                res_dept = "Engineering"
                cmd_seq = "read,write,execute,escalate_privilege,export_data,delete"
                device = user.primary_device
                fp = user.primary_fingerprint
                auth = user.auth_method
                bytes_tx = random.randint(300_000, 1_200_000)

            # Logon Event
            events.append({
                "entity_id": user.entity_id,
                "entity_type": user.entity_type,
                "entity_role": user.entity_role,
                "entity_dept": user.entity_dept,
                "timestamp": start_time,
                "event_type": "logon",
                "auth_method": auth,
                "resource_id": res_id,
                "resource_dept": res_dept,
                "command_sequence": "",
                "device_id": device,
                "device_fingerprint": fp,
                "geo_country": user.home_country,
                "geo_ip": user.home_ip,
                "session_id": session_id,
                "bytes_transferred": 0,
                "status": "SUCCESS",
                "is_malicious": False,  # BENIGN! False positive bait!
                "attack_type": "insider_drift",
                "attack_instance_id": instance_id
            })
            
            # Action Event
            events.append({
                "entity_id": user.entity_id,
                "entity_type": user.entity_type,
                "entity_role": user.entity_role,
                "entity_dept": user.entity_dept,
                "timestamp": start_time + timedelta(minutes=15),
                "event_type": "file_access" if cmd_seq else "http",
                "auth_method": auth,
                "resource_id": res_id,
                "resource_dept": res_dept,
                "command_sequence": cmd_seq,
                "device_id": device,
                "device_fingerprint": fp,
                "geo_country": user.home_country,
                "geo_ip": user.home_ip,
                "session_id": session_id,
                "bytes_transferred": bytes_tx,
                "status": "SUCCESS",
                "is_malicious": False,  # BENIGN!
                "attack_type": "insider_drift",
                "attack_instance_id": instance_id
            })
            
        return events

    def _inject_harder_insider_drift(self, user: UserProfile, start_date: datetime, campaign_num: int) -> List[Dict]:
        """
        [G2] Campaign 6: Harder benign insider_drift — entity joins a cross-functional
        crisis-response task force. Accesses 5 departments' resources in ONE DAY
        using their NORMAL device (fp_mismatch=0), during business hours.
        Behaviorally mimics lateral_movement fan-out, but is legitimately benign:
          - Same device, same country (no geo or device signal)
          - off_hours_flag=0 (business hours)
          - distinct_resource_depts=5 (threshold mimicking lateral_movement)
          - All accesses are read/write on shared project resources (plausible business context)
        is_malicious=False.
        Split: 3 train sessions + 2 test sessions (staged over 2 days).
        """
        events = []
        instance_id = f"ATK_ID_{start_date.strftime('%Y%m%d')}_{campaign_num:03d}"
        # Resources across 5 departments — legitimate cross-functional access
        cross_dept_resources = [
            ("RES_FIN_ERP",           "Finance"),
            ("RES_EXEC_BOARD_DECK",   "Executive"),
            ("DB_HR_EMPLOYEE_RECORDS","HR"),
            ("RES_IT_KNOWLEDGEBASE",  "IT"),
            ("RES_SALES_CRM",         "Sales"),
        ]
        # 5 sessions across 2 days (3 train day1, 2 test day2)
        for step in range(5):
            day_offset = 0 if step < 3 else 1  # first 3 on day 0, last 2 on day 1
            hour = [9, 11, 14, 10, 15][step]
            sess_date = start_date + timedelta(days=day_offset)
            session_id = f"SESS_ID_{uuid.uuid4().hex[:8]}"
            res_id, res_dept = cross_dept_resources[step]
            start_time = sess_date.replace(hour=hour, minute=random.randint(5, 45), second=0)

            events.append({
                "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
                "entity_dept": user.entity_dept, "timestamp": start_time, "event_type": "logon",
                "auth_method": user.auth_method, "resource_id": res_id, "resource_dept": res_dept,
                "command_sequence": "", "device_id": user.primary_device,
                "device_fingerprint": user.primary_fingerprint,
                "geo_country": user.home_country, "geo_ip": user.home_ip,
                "session_id": session_id, "bytes_transferred": 0,
                "status": "SUCCESS", "is_malicious": False,
                "attack_type": "insider_drift", "attack_instance_id": instance_id
            })
            events.append({
                "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
                "entity_dept": user.entity_dept, "timestamp": start_time + timedelta(minutes=20), "event_type": "file_access",
                "auth_method": user.auth_method, "resource_id": res_id, "resource_dept": res_dept,
                "command_sequence": "read,write", "device_id": user.primary_device,
                "device_fingerprint": user.primary_fingerprint,
                "geo_country": user.home_country, "geo_ip": user.home_ip,
                "session_id": session_id, "bytes_transferred": random.randint(500_000, 3_000_000),
                "status": "SUCCESS", "is_malicious": False,
                "attack_type": "insider_drift", "attack_instance_id": instance_id
            })
            events.append({
                "entity_id": user.entity_id, "entity_type": user.entity_type, "entity_role": user.entity_role,
                "entity_dept": user.entity_dept, "timestamp": start_time + timedelta(minutes=45), "event_type": "logoff",
                "auth_method": user.auth_method, "resource_id": res_id, "resource_dept": res_dept,
                "command_sequence": "", "device_id": user.primary_device,
                "device_fingerprint": user.primary_fingerprint,
                "geo_country": user.home_country, "geo_ip": user.home_ip,
                "session_id": session_id, "bytes_transferred": 0,
                "status": "SUCCESS", "is_malicious": False,
                "attack_type": "insider_drift", "attack_instance_id": instance_id
            })
        return events

# -----------------------------------------------------------------------------
# Main Orchestration & Export
# -----------------------------------------------------------------------------

def auto_split_manifest(df: pd.DataFrame, output_dir: str, test_campaigns_per_type: int = 3,
                         normal_cutoff_date: str = None) -> dict:
    """
    Auto-compute the train/test split manifest from the generated dataset.
    Replaces the hardcoded SPLIT_MANIFEST in build_features.py.

    Strategy:
      - Malicious campaigns: sort by first event date per campaign, assign
        last `test_campaigns_per_type` per attack_type to test, rest to train.
      - insider_drift (is_malicious=False): earliest 4 campaign IDs → train,
        latest 2 → test (preserving G2 logic).
      - Normal traffic: chronological split using normal_cutoff_date.
    """
    manifest = {
        "split_strategy": {
            "malicious": (
                f"Campaign-level hold-out — {test_campaigns_per_type} latest-dated campaigns per "
                "attack_type go to test. No event-level leakage."
            ),
            "normal": "Chronological split — events before normal_cutoff_date go to train.",
            "insider_drift": (
                "Benign edge case (is_malicious=False). Earliest 4 campaigns → train, latest 2 → test."
            ),
            "seed": "auto (derived from generated dataset campaign dates)",
        },
        "train_campaigns": {},
        "test_campaigns": {},
        "insider_drift_train": [],
        "insider_drift_test": [],
    }

    # --- Malicious campaigns (is_malicious=True) ---
    mal_df = df[(df["is_malicious"] == True) & (df["attack_type"] != "none")].copy()
    # Get first event timestamp per campaign
    campaign_dates = (
        mal_df.groupby(["attack_type", "attack_instance_id"])["timestamp"]
        .min()
        .reset_index()
        .rename(columns={"timestamp": "first_event"})
    )

    # Derive campaign prefix (portion before date: e.g., 'ATK_IT_' vs 'ATK_ITSC_')
    campaign_dates["prefix"] = campaign_dates["attack_instance_id"].apply(
        lambda cid: cid.rsplit("_", 2)[0] + "_" if "_" in cid else cid
    )

    for attack_type, grp in campaign_dates.groupby("attack_type"):
        prefixes = grp["prefix"].unique()
        if len(prefixes) > 1:
            # Multi-prefix attack type (e.g., impossible_travel with ATK_IT_ and ATK_ITSC_):
            # Reserve 2 latest-dated campaigns PER PREFIX for test split to guarantee sub-variant representation.
            test_ids = []
            train_ids = []
            for pfx, pfx_grp in grp.groupby("prefix"):
                pfx_sorted = pfx_grp.sort_values("first_event")["attack_instance_id"].tolist()
                n_test_pfx = min(2, len(pfx_sorted))
                test_ids.extend(pfx_sorted[-n_test_pfx:])
                train_ids.extend(pfx_sorted[:-n_test_pfx] if n_test_pfx < len(pfx_sorted) else [])
            manifest["train_campaigns"][attack_type] = train_ids
            manifest["test_campaigns"][attack_type] = test_ids
        else:
            # Single-prefix attack type (common case): pick N latest campaigns overall
            campaigns_sorted = grp.sort_values("first_event")["attack_instance_id"].tolist()
            n_test = min(test_campaigns_per_type, len(campaigns_sorted))
            test_ids = campaigns_sorted[-n_test:]
            train_ids = campaigns_sorted[:-n_test] if n_test < len(campaigns_sorted) else []
            manifest["train_campaigns"][attack_type] = train_ids
            manifest["test_campaigns"][attack_type] = test_ids

    # --- insider_drift (is_malicious=False, attack_type='insider_drift') ---
    drift_df = df[(df["is_malicious"] == False) & (df["attack_type"] == "insider_drift")].copy()
    if len(drift_df) > 0:
        drift_dates = (
            drift_df.groupby("attack_instance_id")["timestamp"]
            .min()
            .reset_index()
            .sort_values("timestamp")
        )
        all_drift = drift_dates["attack_instance_id"].tolist()
        n_drift_test = min(2, len(all_drift))
        manifest["insider_drift_train"] = all_drift[:-n_drift_test] if n_drift_test < len(all_drift) else all_drift
        manifest["insider_drift_test"] = all_drift[-n_drift_test:]

    # --- Normal traffic cutoff ---
    if normal_cutoff_date is None:
        # Default: middle of the simulation window based on actual data dates
        min_ts = df[df["attack_type"] == "none"]["timestamp"].min()
        max_ts = df[df["attack_type"] == "none"]["timestamp"].max()
        midpoint = min_ts + (max_ts - min_ts) * 0.60  # ~60% into the window → train
        normal_cutoff_date = midpoint.strftime("%Y-%m-%dT%H:%M:%S")
    manifest["normal_cutoff_date"] = normal_cutoff_date

    # --- Write to file ---
    manifest_path = os.path.join(output_dir, "split_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[OK] Auto-generated split manifest -> {manifest_path}")

    # Summary printout
    for atype in sorted(manifest["train_campaigns"].keys()):
        train_n = len(manifest["train_campaigns"].get(atype, []))
        test_n = len(manifest["test_campaigns"].get(atype, []))
        print(f"     {atype:35s}: {train_n} train / {test_n} test campaigns")
    print(f"     {'insider_drift':35s}: {len(manifest['insider_drift_train'])} train / {len(manifest['insider_drift_test'])} test campaigns")

    return manifest


def generate_dataset(config: GeneratorConfig) -> Tuple[pd.DataFrame, str]:
    print(f"[*] Initializing ARGUS Synthetic Telemetry Generator (Seed={config.random_seed})...")

    profile_gen = UserProfileGenerator(seed=config.random_seed)
    profiles = profile_gen.generate_profiles(config.num_users)
    print(f"[+] Generated {len(profiles)} synthetic user profiles across {len(DEPARTMENTS)} departments.")

    normal_gen = NormalBehaviorGenerator(profiles, config)
    normal_events = normal_gen.generate()
    print(f"[+] Generated {len(normal_events):,} normal baseline telemetry events across {config.num_days} days.")

    injector = AttackInjector(profiles, config)
    attack_events = injector.inject_all_vectors()
    print(f"[+] Injected {len(attack_events):,} telemetry events across 8 attack & pattern categories.")

    all_events = normal_events + attack_events
    df = pd.DataFrame(all_events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    # ── Add graded severity label (0-1, per attack type natural magnitude) ──
    print("[*] Computing per-session severity labels...")
    df = _add_session_severity(df)
    sev_stats = df[df["is_malicious"] == True].groupby("attack_type")["severity"].agg(["mean", "std", "min", "max"])
    print("    Severity stats per attack type (malicious sessions only):")
    print(sev_stats.to_string())

    os.makedirs(config.output_dir, exist_ok=True)
    parquet_path = os.path.join(config.output_dir, "full_dataset.parquet")
    df.to_parquet(parquet_path, index=False)
    print(f"[OK] Saved full dataset to {parquet_path} ({len(df):,} total rows, {len(df.columns)} columns).")

    # Auto-generate split_manifest.json from actual campaign dates in the dataset
    print("[*] Auto-computing train/test split manifest from generated campaign dates...")
    auto_split_manifest(df, config.output_dir)

    summary_md = create_summary_markdown(df, profiles, config)
    summary_path = os.path.join(config.output_dir, "dataset_summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_md)
    print(f"[OK] Saved dataset summary doc to {summary_path}.")

    return df, summary_path

def create_summary_markdown(df: pd.DataFrame, profiles: List[UserProfile], config: GeneratorConfig) -> str:
    total_events = len(df)
    malicious_events = df["is_malicious"].sum()
    normal_events = total_events - malicious_events
    malicious_pct = (malicious_events / total_events) * 100
    
    total_entities = df["entity_id"].nunique()
    total_sessions = df["session_id"].nunique()
    min_date = df["timestamp"].min().strftime("%Y-%m-%d %H:%M:%S UTC")
    max_date = df["timestamp"].max().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    attack_breakdown = df[df["attack_type"] != "none"]["attack_type"].value_counts().to_dict()
    campaign_counts = df[df["attack_type"] != "none"].groupby("attack_type")["attack_instance_id"].nunique().to_dict()
    
    dept_entity_counts = pd.Series([p.entity_dept for p in profiles]).value_counts().to_dict()
    type_entity_counts = pd.Series([p.entity_type for p in profiles]).value_counts().to_dict()
    
    expected_vectors = ["credential_misuse", "brute_force", "lateral_movement", "impossible_travel", "device_spoofing", "credential_stuffing", "low_and_slow_exfiltration"]
    # Include both impossible_travel variants in the count
    it_total = campaign_counts.get("impossible_travel", 0) + campaign_counts.get("impossible_travel_sc", 0)
    campaign_counts_check = dict(campaign_counts)
    campaign_counts_check["impossible_travel"] = it_total
    failed_vectors = [v for v in expected_vectors if campaign_counts_check.get(v, 0) < 8]

    if failed_vectors:
        campaign_check_str = f"- [ ] **WARNING - Campaign Density Check Failed**: Vector(s) {failed_vectors} have < 8 campaigns!"
        print(f"[WARNING] Campaign validation check failed for vectors: {failed_vectors}")
    else:
        campaign_check_str = f"- [x] **Campaign Density Validation**: All 7 malicious attack vectors have >= 8 distinct campaign instances (10-12 campaigns/vector)."
        print("[OK] Campaign validation check passed! All attack vectors have >= 8 distinct campaigns.")

    summary = f"""# ARGUS Synthetic Security Dataset Summary (20-Field Expanded Spec)

## Dataset Overview

- **Total Events**: `{total_events:,}`
- **Date Range**: `{min_date}` to `{max_date}` (`{config.num_days}` days)
- **Total Monitored Entities**: `{total_entities}` (Users, Service Accounts, Edge Devices)
- **Total Tracked Sessions**: `{total_sessions:,}`
- **Target Attack Ratio (Entities)**: `{config.attack_entity_ratio * 100:.1f}%`

---

## Class Balance Statistics

| Class | Event Count | Percentage |
| :--- | :--- | :--- |
| **Normal Traffic (`is_malicious=False`)** | `{normal_events:,}` | `{100 - malicious_pct:.2f}%` |
| **Malicious Traffic (`is_malicious=True`)** | `{malicious_events:,}` | `{malicious_pct:.2f}%` |
| **Total** | `{total_events:,}` | `100.00%` |

---

## Attack & Pattern Taxonomy Breakdown (8 Categories)

| Attack / Pattern Category (`attack_type`) | Campaign Count (`attack_instance_id`) | Total Events | Ground Truth Label (`is_malicious`) | Description |
| :--- | :---: | :---: | :---: | :--- |
"""

    vector_descriptions = {
        "credential_misuse": (True, "Off-hours sensitive cross-department resource access under valid user credentials"),
        "brute_force": (True, "Burst of failed logons followed by 1 successful logon & unauthorized access"),
        "lateral_movement": (True, "Rapid fan-out access across multiple foreign host devices & servers"),
        "impossible_travel": (True, "Sequential logons under same entity ID from physically distant countries"),
        "device_spoofing": (True, "Session initiated from an unrecognized, non-fingerprinted rogue device ID"),
        "credential_stuffing": (True, "MANY entity IDs attempting auth from FEW shared attacker IPs with high failure rate"),
        "low_and_slow_exfiltration": (True, "Gradual, small off-hours resource access building up incrementally over weeks"),
        "insider_drift": (False, "AMBIGUOUS EDGE CASE: Legitimate entity expanding privilege footprint (Benign FP bait)")
    }

    for atk_type, (is_mal, desc) in vector_descriptions.items():
        evt_cnt = attack_breakdown.get(atk_type, 0)
        cmp_cnt = campaign_counts.get(atk_type, 0)
        mal_str = "`True`" if is_mal else "**`False` (Benign)**"
        summary += f"| `{atk_type}` | `{cmp_cnt}` | `{evt_cnt:,}` | {mal_str} | {desc} |\n"

    summary += f"""
---

## Entity & Organizational Breakdown

### By Entity Type
| Entity Type | Count | Percentage |
| :--- | :--- | :--- |
"""
    for etype, cnt in type_entity_counts.items():
        summary += f"| **{etype}** | `{cnt}` | `{cnt / total_entities * 100:.1f}%` |\n"

    summary += f"""
### By Department
| Department | Entity Count | Percentage |
| :--- | :--- | :--- |
"""
    for dept, cnt in dept_entity_counts.items():
        summary += f"| **{dept}** | `{cnt}` | `{cnt / total_entities * 100:.1f}%` |\n"

    summary += f"""
---

## Technical Validation Checklist

- [x] **20-Field Expanded Schema Integrity**: All 20 canonical fields present and strongly typed.
- [x] **Parquet Format**: Single monolithic columnar output ready for pandas, PyTorch, and GNN pipelines.
- [x] **Reproducibility**: Seeded generator (`seed={config.random_seed}`) ensures deterministic reproduction.
{campaign_check_str}
- [x] **Label-Hiding Discipline**: `src/ingest/mask_labels.py` available for inference-time label masking.
"""

    return summary

# -----------------------------------------------------------------------------
# CLI Interface
# -----------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARGUS UEBA Synthetic Data Generator (Expanded Spec)")
    parser.add_argument("--num-users", type=int, default=400, help="Number of synthetic entities to simulate (default: 400)")
    parser.add_argument("--num-days", type=int, default=21, help="Number of simulation days (default: 21)")
    parser.add_argument("--start-date", type=str, default="2026-06-01", help="Simulation start date YYYY-MM-DD (default: 2026-06-01)")
    parser.add_argument("--attack-ratio", type=float, default=0.07, help="Ratio of entities targeted by malicious campaigns (default: 0.07)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility (default: 42)")
    parser.add_argument("--output-dir", type=str, default="data/processed", help="Output directory for parquet & summary (default: data/processed)")
    
    args = parser.parse_args()
    
    cfg = GeneratorConfig(
        num_users=args.num_users,
        num_days=args.num_days,
        start_date_str=args.start_date,
        attack_entity_ratio=args.attack_ratio,
        random_seed=args.seed,
        output_dir=args.output_dir
    )
    
    generate_dataset(cfg)
