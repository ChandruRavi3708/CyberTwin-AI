"""Rank defensive actions by simulated risk reduction, path disruption, and cost."""

from __future__ import annotations

import networkx as nx

from modules.attack_graph import get_critical_assets
from modules.defense_simulation import simulate_defense


OPERATIONAL_COST = {"Block IP": 8, "Isolate Host": 28, "Block Connection": 14, "Protect Critical Asset": 18}


def _candidate_actions(graph: nx.DiGraph) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for node, data in graph.nodes(data=True):
        if data.get("node_type") == "external_ip":
            candidates.append({"action": "Block IP", "target": node})
        elif data.get("node_type") != "critical_asset":
            candidates.append({"action": "Isolate Host", "target": node})
    for source, destination in graph.edges():
        candidates.append({"action": "Block Connection", "target": f"{source} -> {destination}", "source": source, "destination": destination})
    for asset in get_critical_assets(graph):
        candidates.append({"action": "Protect Critical Asset", "target": asset})
    return candidates


def rank_defense_recommendations(graph: nx.DiGraph, limit: int | None = None) -> list[dict[str, object]]:
    """Simulate viable controls and return ranked, explainable recommendations."""
    recommendations: list[dict[str, object]] = []
    for candidate in _candidate_actions(graph):
        result = simulate_defense(
            graph, candidate["action"], target=candidate.get("target"),
            source=candidate.get("source"), destination=candidate.get("destination"),
        )
        cost = OPERATIONAL_COST[candidate["action"]]
        disruption_bonus = 25.0 if result["attack_path_disrupted"] else result["path_reduction_percent"] * 0.25
        defense_score = round(float(result["risk_reduction_percent"]) + disruption_bonus - cost, 2)
        recommendations.append({
            **candidate,
            "risk_reduction": result["risk_reduction_percent"],
            "risk_reduction_percent": result["risk_reduction_percent"],
            "path_reduction_percent": result["path_reduction_percent"],
            "attack_path_disrupted": result["attack_path_disrupted"],
            "operational_cost": cost,
            "defense_score": defense_score,
        })
    recommendations.sort(key=lambda item: (item["defense_score"], item["risk_reduction_percent"]), reverse=True)
    return recommendations[:limit] if limit is not None else recommendations


def recommend_best_defense(graph: nx.DiGraph) -> dict[str, object] | None:
    """Return the highest-ranked recommendation for the existing dashboard."""
    recommendations = rank_defense_recommendations(graph, limit=1)
    return recommendations[0] if recommendations else None
