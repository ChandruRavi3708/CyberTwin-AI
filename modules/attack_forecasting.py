"""Explainable, rule-based multi-step attack forecasting."""

from __future__ import annotations

from typing import Any

import networkx as nx
import pandas as pd

from modules.attack_graph import get_critical_paths, get_neighbors


ATTACK_TRANSITIONS = {
    "Discovery": ("Credential Access", "Brute Force / credential attack", 0.58),
    "Credential Access": ("Defense Evasion", "Valid account abuse", 0.66),
    "Defense Evasion": ("Lateral Movement", "Remote-service lateral movement", 0.70),
    "Lateral Movement": ("Privilege Escalation", "Privilege escalation on a reachable host", 0.72),
    "Privilege Escalation": ("Exfiltration", "Collection and data exfiltration", 0.74),
    "Exfiltration": ("Impact", "Potential business impact", 0.48),
}


def get_attack_timeline(df: pd.DataFrame, source_ip: str | None = None) -> list[dict[str, Any]]:
    """Return chronologically ordered, MITRE-mapped threat events."""
    if df.empty:
        return []
    working = df.copy()
    if source_ip is not None:
        working = working[working["source_ip"] == source_ip]
    if "known_threat" in working:
        working = working[working["known_threat"]]
    if "mitre_tactic" in working:
        working = working[working["mitre_tactic"] != "Unknown"]
    if working.empty:
        return []
    columns = ["timestamp", "source_ip", "destination_ip", "threat_type", "mitre_tactic", "mitre_technique", "risk_score", "scenario_id"]
    available = [column for column in columns if column in working]
    return working.sort_values("timestamp", kind="stable")[available].to_dict("records")


def forecast_next_attack(
    df: pd.DataFrame,
    source_ip: str | None = None,
    graph: nx.DiGraph | None = None,
) -> dict[str, Any]:
    """Forecast a next ATT&CK stage from timeline, risk, and graph context."""
    timeline = get_attack_timeline(df, source_ip)
    if not timeline:
        return {"status": "No attack sequence detected", "prediction": None, "confidence": 0.0, "current_stage": None, "observed_stage": None, "predicted_next_stage": None, "next_stage": None, "reason": "No MITRE-mapped threat events are available."}

    # Synthetic data labels explicit attack chains.  Prefer the latest such
    # chain over unrelated activity that happens to share a source IP.
    labelled_events = [event for event in timeline if event.get("scenario_id") not in (None, "", "baseline")]
    if labelled_events:
        latest_scenario = labelled_events[-1]["scenario_id"]
        timeline = [event for event in labelled_events if event.get("scenario_id") == latest_scenario]

    latest = timeline[-1]
    current_stage = latest.get("mitre_tactic", "Unknown")
    transition = ATTACK_TRANSITIONS.get(current_stage)
    if transition is None:
        return {"status": "No prediction available", "prediction": None, "confidence": 0.0, "current_stage": current_stage, "observed_stage": current_stage, "predicted_next_stage": None, "next_stage": None, "reason": f"No transition rule exists for {current_stage}."}

    next_stage, prediction, base_confidence = transition
    risk = float(latest.get("risk_score", 0) or 0)
    sequence_bonus = min(0.12, max(0, len(timeline) - 1) * 0.04)
    risk_bonus = min(0.15, risk / 100 * 0.15)
    graph_bonus = 0.0
    graph_reason = ""
    if graph is not None and graph.number_of_nodes() > 0:
        source = source_ip or latest.get("source_ip")
        neighbours = get_neighbors(graph, str(source))
        if neighbours["successors"]:
            graph_bonus += 0.05
            graph_reason = "The source has observed outbound graph relationships."
        if any(path and path[0] == source for path in get_critical_paths(graph)):
            graph_bonus += 0.08
            graph_reason = "The source has an observed path toward a critical asset."
    confidence = min(0.99, base_confidence + sequence_bonus + risk_bonus + graph_bonus)
    reason = (
        f"Latest observed stage is {current_stage} ({latest.get('mitre_technique', 'Unknown')}); "
        f"risk is {risk:.1f}/100 and {len(timeline)} related stage(s) were observed. {graph_reason}"
    ).strip()
    return {
        "status": "Prediction Generated", "current_stage": current_stage, "observed_stage": current_stage,
        "predicted_next_stage": next_stage, "next_stage": next_stage, "prediction": prediction,
        "confidence": round(confidence * 100, 1), "reason": reason,
        "source_ip": latest.get("source_ip"), "target_ip": latest.get("destination_ip"),
    }
