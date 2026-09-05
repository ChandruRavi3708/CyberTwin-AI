"""Structured, rule-based explanations for CyberTwin risk decisions."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pandas as pd


FACTOR_LABELS = {
    "anomaly_score": "High anomaly score",
    "authentication_risk": "Failed authentication activity",
    "connection_volume": "Unusual connection volume",
    "data_transfer": "Unusual data transfer",
    "event_severity": "Event severity",
    "attack_progression": "Attack progression evidence",
    "mitre_severity": "MITRE technique severity",
    "critical_asset_exposure": "Critical asset exposure",
}


def _event_dict(event: Mapping[str, Any] | pd.Series) -> dict[str, Any]:
    """Make a plain event dictionary from a dataframe row or mapping."""
    return event.to_dict() if isinstance(event, pd.Series) else dict(event)


def _number(event: Mapping[str, Any], field: str) -> float:
    value = pd.to_numeric(event.get(field, 0), errors="coerce")
    return float(value) if pd.notna(value) else 0.0


def explain_event(event: Mapping[str, Any] | pd.Series) -> dict[str, Any]:
    """Explain why one event was flagged, with investigation guidance."""
    record = _event_dict(event)
    raw_factors = record.get("risk_factor_contributions", {})
    factors = raw_factors if isinstance(raw_factors, Mapping) else {}
    ranked_factors = [
        {"factor": name, "label": FACTOR_LABELS.get(name, name.replace("_", " ").title()), "contribution": round(float(value), 1)}
        for name, value in factors.items() if float(value) > 0
    ]
    ranked_factors.sort(key=lambda item: item["contribution"], reverse=True)

    reasons = [item["label"] for item in ranked_factors[:4]]
    if _number(record, "failed_logins") >= 5:
        reasons.append(f"{int(_number(record, 'failed_logins'))} failed login attempts")
    if record.get("mitre_id", "Unknown") != "Unknown":
        reasons.append(f"MITRE {record.get('mitre_id')}: {record.get('mitre_technique')}")
    if not reasons:
        reasons.append("Telemetry is within the current baseline; no dominant risk factor was found")

    investigation_steps = [
        "Verify the source and destination asset ownership and expected business purpose.",
        "Review nearby authentication and network events for the same source account or IP.",
    ]
    if _number(record, "failed_logins") > 0:
        investigation_steps.append("Check account lockout, sign-in logs, and privileged account activity.")
    if _number(record, "data_transfer") > 50_000 or _number(record, "bytes") > 50_000:
        investigation_steps.append("Validate the destination, transferred data classification, and egress approval.")
    if record.get("mitre_id", "Unknown") != "Unknown":
        investigation_steps.append(f"Hunt for related {record.get('mitre_tactic')} activity using {record.get('mitre_id')} telemetry.")

    risk_score = _number(record, "risk_score")
    return {
        "event_summary": {
            "source_ip": record.get("source_ip", "Unknown"),
            "destination_ip": record.get("destination_ip", "Unknown"),
            "event_type": record.get("event_type", "Unknown"),
            "risk_score": risk_score,
            "risk_level": record.get("ai_risk_level", record.get("risk_level", "Unknown")),
        },
        "why_flagged": reasons,
        "top_contributing_factors": ranked_factors,
        "risk_contribution_breakdown": {item["factor"]: item["contribution"] for item in ranked_factors},
        "mitre": {
            "id": record.get("mitre_id", "Unknown"),
            "technique": record.get("mitre_technique", "Unknown"),
            "tactic": record.get("mitre_tactic", "Unknown"),
        },
        "recommended_investigation_steps": investigation_steps,
    }


def explain_high_risk_events(events: pd.DataFrame, limit: int = 10) -> list[dict[str, Any]]:
    """Return XAI records for the highest-risk events in a dataframe."""
    if events.empty or "risk_score" not in events:
        return []
    high_risk = events[events["risk_score"] >= 60].sort_values("risk_score", ascending=False).head(limit)
    return [explain_event(row) for _, row in high_risk.iterrows()]
