"""Local, rule-based MITRE ATT&CK mapping for the offline prototype."""

from __future__ import annotations

import pandas as pd


# This configuration can later be replaced by ATT&CK STIX/API data.
MITRE_RULES = {
    "Port Scan / Reconnaissance": ("T1046", "Network Service Discovery", "Discovery", 0.35),
    "Credential Attack": ("T1110", "Brute Force", "Credential Access", 0.70),
    "Credential Abuse": ("T1078", "Valid Accounts", "Defense Evasion", 0.85),
    "Suspicious Connection": ("T1071", "Application Layer Protocol", "Command and Control", 0.60),
    "Malware Activity": ("T1204", "User Execution", "Execution", 0.75),
    "Lateral Movement": ("T1021", "Remote Services", "Lateral Movement", 0.90),
    "Privilege Escalation": ("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", 0.95),
    "Data Exfiltration": ("T1041", "Exfiltration Over C2 Channel", "Exfiltration", 1.00),
}
EVENT_TYPE_RULES = {
    "port scan": "Port Scan / Reconnaissance", "failed login burst": "Credential Attack",
    "login failure": "Credential Attack", "credential abuse": "Credential Abuse",
    "suspicious connection": "Suspicious Connection", "malware activity": "Malware Activity",
    "lateral movement": "Lateral Movement", "privilege escalation": "Privilege Escalation",
    "data exfiltration": "Data Exfiltration",
}


def map_to_mitre(df: pd.DataFrame) -> pd.DataFrame:
    """Append MITRE ID, technique, tactic, and severity to each event."""
    df = df.copy()
    threat_types = df.get("threat_type", pd.Series("Normal", index=df.index)).fillna("Normal")
    event_types = df.get("event_type", pd.Series("", index=df.index)).astype(str).str.strip().str.lower().str.replace("_", " ", regex=False)
    resolved = threat_types.where(threat_types.isin(MITRE_RULES), event_types.map(EVENT_TYPE_RULES).fillna("Normal"))
    mapped = resolved.map(MITRE_RULES)
    def mapped_value(item: object, index: int, default: object) -> object:
        return item[index] if isinstance(item, tuple) else default

    df["mitre_id"] = mapped.map(lambda item: mapped_value(item, 0, "Unknown"))
    df["mitre_technique"] = mapped.map(lambda item: mapped_value(item, 1, "Unknown"))
    df["mitre_tactic"] = mapped.map(lambda item: mapped_value(item, 2, "Unknown"))
    df["mitre_severity"] = mapped.map(lambda item: mapped_value(item, 3, 0.0)).astype(float)
    return df
