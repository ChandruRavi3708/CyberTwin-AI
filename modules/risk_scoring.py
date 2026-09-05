"""Explainable 0--100 cyber-risk scoring."""

from __future__ import annotations

import pandas as pd


CRITICAL_HOSTS = {"db-01", "database", "domain-controller", "auth-01"}
SEVERITY_WEIGHTS = {"low": 0, "medium": 5, "high": 10, "critical": 15}
PROGRESSION_WEIGHTS = {"Port Scan / Reconnaissance": 3, "Credential Attack": 8, "Credential Abuse": 12, "Lateral Movement": 15, "Privilege Escalation": 16, "Data Exfiltration": 18}


def get_risk_level(score: float) -> str:
    """Return the Phase 2 risk band for a numeric score."""
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 35:
        return "Medium"
    return "Low"


def _number(row: pd.Series, field: str) -> float:
    value = pd.to_numeric(row.get(field, 0), errors="coerce")
    return float(value) if pd.notna(value) else 0.0


def calculate_risk(df: pd.DataFrame) -> pd.DataFrame:
    """Score events and retain factor-by-factor contributions for investigation."""
    df = df.copy()
    contributions: list[dict[str, float]] = []
    for _, row in df.iterrows():
        anomaly = min(max(_number(row, "anomaly_score"), 0), 1)
        failed_logins, connections = _number(row, "failed_logins"), _number(row, "connections")
        transfer = _number(row, "data_transfer") or _number(row, "bytes")
        severity = str(row.get("severity_hint", row.get("risk_level", "Low"))).lower()
        threat_type, host = str(row.get("threat_type", "Normal")), str(row.get("host", "")).lower()
        destination = str(row.get("destination_ip", "")).lower()
        factors = {
            "anomaly_score": round(anomaly * 28, 1),
            "authentication_risk": min(16.0, round(failed_logins * 1.6, 1)),
            "connection_volume": min(9.0, round(connections / 4, 1)),
            "data_transfer": min(10.0, round(transfer / 20_000, 1)),
            "event_severity": float(SEVERITY_WEIGHTS.get(severity, 0)),
            "attack_progression": float(PROGRESSION_WEIGHTS.get(threat_type, 0)),
            "mitre_severity": round(min(max(_number(row, "mitre_severity"), 0), 1) * 12, 1),
            "critical_asset_exposure": 10.0 if host in CRITICAL_HOSTS or destination.endswith(".60") else 0.0,
        }
        contributions.append(factors)
    df["risk_factor_contributions"] = contributions
    df["risk_score"] = [min(100.0, round(sum(item.values()), 1)) for item in contributions]
    df["ai_risk_level"] = df["risk_score"].map(get_risk_level)
    df["risk_level"] = df["ai_risk_level"]
    return df
