"""
ARGUS Phase 5 — MITRE ATT&CK Technique Lookup Table
=====================================================
Static, hardcoded local table mapping each ARGUS attack type to one or more
real MITRE ATT&CK Enterprise technique IDs, names, and a brief analyst-facing
description. This is NOT an API call or embedding lookup — it is a Python dict
for zero-latency, offline-capable access during note generation.

All technique IDs have been verified against the MITRE ATT&CK Enterprise matrix
(https://attack.mitre.org/). Where a sub-technique is the most precise mapping,
the parent technique is also listed for context. Where multiple techniques apply
equally, all are listed in priority order (most specific first).

Usage:
    from src.explain.mitre_lookup import get_techniques, ATTACK_TYPE_TO_MITRE
    techs = get_techniques("credential_stuffing")
    # → list of MitreTechnique objects
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class MitreTechnique:
    technique_id: str          # e.g. "T1110.004"
    name: str                  # e.g. "Brute Force: Credential Stuffing"
    tactic: str                # MITRE tactic (e.g. "Credential Access")
    description: str           # 1-2 sentence plain-language description for analyst notes
    is_subtechnique: bool = False  # True if ID contains a dot (T1110.004)
    parent_id: str = ""            # Parent technique ID if is_subtechnique


# ─────────────────────────────────────────────────────────────────────────────
# Technique definitions — verified against MITRE ATT&CK Enterprise v15
# ─────────────────────────────────────────────────────────────────────────────

_TECHNIQUES: dict[str, MitreTechnique] = {

    # ── T1110 Brute Force (parent) ─────────────────────────────────────────
    "T1110": MitreTechnique(
        technique_id  = "T1110",
        name          = "Brute Force",
        tactic        = "Credential Access",
        description   = (
            "Adversaries use automated tools to guess or crack account credentials "
            "via repeated authentication attempts. Distinguished from credential "
            "stuffing by the use of password-spraying or dictionary attacks rather "
            "than breached credential lists."
        ),
        is_subtechnique = False,
    ),

    # ── T1110.003 Brute Force: Password Spraying ───────────────────────────
    # Used for brute_force (rapid repeated failures on a single account or
    # across accounts). T1110.003 = Password Spraying is the closest sub-technique
    # for high failure-ratio / logon-count patterns. T1110.001 (Password Guessing)
    # would also apply but .003 is more precise for multi-attempt patterns.
    "T1110.003": MitreTechnique(
        technique_id  = "T1110.003",
        name          = "Brute Force: Password Spraying",
        tactic        = "Credential Access",
        description   = (
            "Attacker systematically tries a small number of common passwords across "
            "many accounts to avoid lockout thresholds, generating high volumes of "
            "failed authentication events."
        ),
        is_subtechnique = True,
        parent_id     = "T1110",
    ),

    # ── T1110.004 Brute Force: Credential Stuffing ────────────────────────
    "T1110.004": MitreTechnique(
        technique_id  = "T1110.004",
        name          = "Brute Force: Credential Stuffing",
        tactic        = "Credential Access",
        description   = (
            "Attacker uses large sets of previously breached username/password pairs "
            "to authenticate against many accounts simultaneously from a single or "
            "few source IPs, often with automated tooling."
        ),
        is_subtechnique = True,
        parent_id     = "T1110",
    ),

    # ── T1078 Valid Accounts (parent) ─────────────────────────────────────
    "T1078": MitreTechnique(
        technique_id  = "T1078",
        name          = "Valid Accounts",
        tactic        = "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        description   = (
            "Adversary obtains and uses legitimate credentials to authenticate to "
            "systems and services, bypassing most authentication controls because the "
            "credentials are genuine."
        ),
        is_subtechnique = False,
    ),

    # ── T1078.004 Valid Accounts: Cloud Accounts ──────────────────────────
    # Best sub-technique for impossible_travel and credential_misuse:
    # legitimate cloud/VPN credentials used from unexpected geographies or
    # outside normal working hours. T1078.003 (Local Accounts) is less applicable.
    "T1078.004": MitreTechnique(
        technique_id  = "T1078.004",
        name          = "Valid Accounts: Cloud Accounts",
        tactic        = "Defense Evasion / Persistence",
        description   = (
            "Legitimate cloud or SSO credentials accessed from unusual locations, "
            "times, or devices — often an indicator of account compromise where the "
            "attacker has obtained valid credentials but is operating from a different "
            "geographic location or device than the legitimate user."
        ),
        is_subtechnique = True,
        parent_id     = "T1078",
    ),

    # ── T1021 Remote Services (parent) ────────────────────────────────────
    "T1021": MitreTechnique(
        technique_id  = "T1021",
        name          = "Remote Services",
        tactic        = "Lateral Movement",
        description   = (
            "Adversary uses legitimate remote access services (RDP, SSH, VNC, SMB) "
            "to move laterally through a network after establishing initial access, "
            "accessing systems or resources that were not the original target."
        ),
        is_subtechnique = False,
    ),

    # ── T1021.002 Remote Services: SMB/Windows Admin Shares ──────────────
    # Most precise for ARGUS lateral_movement (network share/resource traversal
    # across departments via entity's credentials). T1021.001 (RDP) is also valid
    # but SMB shares are more typical in enterprise lateral movement patterns.
    "T1021.002": MitreTechnique(
        technique_id  = "T1021.002",
        name          = "Remote Services: SMB/Windows Admin Shares",
        tactic        = "Lateral Movement",
        description   = (
            "Attacker uses valid account credentials to traverse network shares or "
            "administrative file shares across department boundaries, accessing "
            "resources on systems the account would not normally touch."
        ),
        is_subtechnique = True,
        parent_id     = "T1021",
    ),

    # ── T1036 Masquerading (parent) ────────────────────────────────────────
    "T1036": MitreTechnique(
        technique_id  = "T1036",
        name          = "Masquerading",
        tactic        = "Defense Evasion",
        description   = (
            "Adversary disguises malicious activity by manipulating device identifiers, "
            "process names, or file attributes to appear legitimate and evade detection "
            "based on known-good signatures."
        ),
        is_subtechnique = False,
    ),

    # ── T1036.005 Masquerading: Match Legitimate Name or Location ─────────
    # Best mapping for device_spoofing (device fingerprint is falsified/changed
    # to match a known-good device profile). T1036 parent alone is also listed.
    "T1036.005": MitreTechnique(
        technique_id  = "T1036.005",
        name          = "Masquerading: Match Legitimate Name or Location",
        tactic        = "Defense Evasion",
        description   = (
            "Attacker modifies or spoofs device identifiers (user agent, hardware "
            "fingerprint, certificate) to impersonate a known-good device, bypassing "
            "device-trust controls that rely on fingerprint matching."
        ),
        is_subtechnique = True,
        parent_id     = "T1036",
    ),

    # ── T1030 Data Transfer Size Limits ───────────────────────────────────
    # Used for low_and_slow_exfiltration (deliberately staged, small-volume
    # transfers to stay below alert thresholds over extended time).
    "T1030": MitreTechnique(
        technique_id  = "T1030",
        name          = "Data Transfer Size Limits",
        tactic        = "Exfiltration",
        description   = (
            "Attacker limits the size of each data transfer to avoid triggering "
            "volume-based detection thresholds, exfiltrating data in small increments "
            "over an extended period (low-and-slow pattern)."
        ),
        is_subtechnique = False,
    ),

    # ── T1041 Exfiltration Over C2 Channel ────────────────────────────────
    "T1041": MitreTechnique(
        technique_id  = "T1041",
        name          = "Exfiltration Over C2 Channel",
        tactic        = "Exfiltration",
        description   = (
            "Attacker sends stolen data out of the environment through the same "
            "channel used for command-and-control, blending exfiltration traffic "
            "with legitimate communications to evade detection."
        ),
        is_subtechnique = False,
    ),

    # ── T1048 Exfiltration Over Alternative Protocol ──────────────────────
    # Also applicable to low_and_slow_exfil when data leaves via HTTP/email
    # channels that are not the primary C2 channel.
    "T1048": MitreTechnique(
        technique_id  = "T1048",
        name          = "Exfiltration Over Alternative Protocol",
        tactic        = "Exfiltration",
        description   = (
            "Attacker uses alternative network protocols (email, HTTP, DNS) to "
            "exfiltrate data, often during off-hours to reduce visibility among "
            "normal business traffic."
        ),
        is_subtechnique = False,
    ),

    # ── T1098 Account Manipulation ────────────────────────────────────────
    # Insider threat context: gradual privilege/access escalation
    "T1098": MitreTechnique(
        technique_id  = "T1098",
        name          = "Account Manipulation",
        tactic        = "Persistence / Privilege Escalation",
        description   = (
            "Adversary manipulates account credentials or permissions to maintain "
            "access or escalate privileges, often detectable as gradual drift in "
            "the account's access patterns relative to its peer group."
        ),
        is_subtechnique = False,
    ),

    # ── T1087 Account Discovery ────────────────────────────────────────────
    # Insider drift footprint expansion = discovery of new resources/departments
    "T1087": MitreTechnique(
        technique_id  = "T1087",
        name          = "Account Discovery",
        tactic        = "Discovery",
        description   = (
            "Adversary (or malicious insider) enumerates accounts, resources, or "
            "department access permissions beyond their normal scope, often as a "
            "precursor to data collection or privilege escalation."
        ),
        is_subtechnique = False,
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Attack type → technique mapping
# ─────────────────────────────────────────────────────────────────────────────

# Each entry: list of technique IDs in priority order (most specific first).
# The first entry is the primary technique shown in analyst notes.
ATTACK_TYPE_TO_MITRE: dict[str, List[str]] = {
    "credential_stuffing": [
        "T1110.004",   # Brute Force: Credential Stuffing (most specific)
        "T1110",       # Brute Force (parent, for broader context)
    ],
    "brute_force": [
        "T1110.003",   # Brute Force: Password Spraying (closest to rapid repeated failures)
        "T1110",       # Brute Force (parent)
    ],
    "impossible_travel": [
        "T1078",       # Valid Accounts (geo-implausible logon with valid credentials)
        "T1078.004",   # Valid Accounts: Cloud Accounts (most common vector)
    ],
    "device_spoofing": [
        "T1036.005",   # Masquerading: Match Legitimate Name or Location
        "T1036",       # Masquerading (parent)
    ],
    "lateral_movement": [
        "T1021.002",   # Remote Services: SMB/Windows Admin Shares
        "T1021",       # Remote Services (parent)
        "T1078",       # Valid Accounts (credentials used to facilitate movement)
    ],
    "low_and_slow_exfiltration": [
        "T1030",       # Data Transfer Size Limits (primary: staged small transfers)
        "T1048",       # Exfiltration Over Alternative Protocol (off-hours HTTP/email)
        "T1041",       # Exfiltration Over C2 Channel (also plausible)
    ],
    "credential_misuse": [
        "T1078",       # Valid Accounts (legitimate creds used outside normal context)
        "T1078.004",   # Valid Accounts: Cloud Accounts (off-hours/foreign-resource access)
    ],
    "insider_drift": [
        "T1098",       # Account Manipulation (gradual access pattern change)
        "T1087",       # Account Discovery (footprint expansion)
    ],
    # "none" is intentionally absent — no technique is mapped to an unclassified session
}


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def get_techniques(attack_type: str) -> List[MitreTechnique]:
    """
    Return a list of MitreTechnique objects for the given attack type.
    Returns an empty list if attack_type is "none" or unrecognised.

    Parameters
    ----------
    attack_type : str
        One of the 7 malicious ARGUS attack types or "none".

    Returns
    -------
    List[MitreTechnique] — ordered primary-first.
    """
    ids = ATTACK_TYPE_TO_MITRE.get(attack_type, [])
    return [_TECHNIQUES[tid] for tid in ids if tid in _TECHNIQUES]


def get_primary_technique(attack_type: str) -> MitreTechnique | None:
    """Return just the primary (first) technique for compact note generation."""
    techs = get_techniques(attack_type)
    return techs[0] if techs else None


def format_technique_citation(attack_type: str, max_ids: int = 2) -> str:
    """
    Return a formatted citation string for inline use in analyst notes.
    e.g. "MITRE T1110.004 (Brute Force: Credential Stuffing), T1110"
    """
    techs = get_techniques(attack_type)[:max_ids]
    if not techs:
        return ""
    parts = [f"{t.technique_id} ({t.name})" for t in techs]
    return "MITRE " + ", ".join(parts)


if __name__ == "__main__":
    print("ARGUS MITRE ATT&CK Lookup Table\n" + "=" * 50)
    for at in ATTACK_TYPE_TO_MITRE:
        techs = get_techniques(at)
        print(f"\n{at}")
        for t in techs:
            sub = " [sub]" if t.is_subtechnique else ""
            print(f"  {t.technique_id}{sub}  {t.name}  [{t.tactic}]")
