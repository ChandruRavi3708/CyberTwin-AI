"""Dynamic NetworkX attack graph construction and path intelligence."""

from __future__ import annotations

import ipaddress
from typing import Any, Iterable

import networkx as nx
import pandas as pd


CRITICAL_HOSTS = {"db-01", "database", "domain-controller", "auth-01"}


def _is_external_ip(value: str) -> bool:
    try:
        return not ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _node_details(node: str, row: pd.Series, is_destination: bool) -> dict[str, Any]:
    host = str(row.get("host", "")) if is_destination else ""
    critical = host.lower() in CRITICAL_HOSTS or node.endswith(".60")
    return {
        "node_type": "critical_asset" if critical else ("external_ip" if _is_external_ip(node) else "host"),
        "hostname": host or node,
        "criticality": 1.0 if critical else 0.3,
        "risk": 0.0,
        "anomaly_score": 0.0,
        "mitre_technique": "Unknown",
        "forecast": None,
    }


def _update_node(graph: nx.DiGraph, node: str, row: pd.Series, is_destination: bool) -> None:
    if not graph.has_node(node):
        graph.add_node(node, **_node_details(node, row, is_destination))
    data = graph.nodes[node]
    risk = float(row.get("risk_score", 0) or 0)
    anomaly = float(row.get("anomaly_score", 0) or 0)
    if risk >= data["risk"]:
        data["risk"] = risk
        data["mitre_technique"] = row.get("mitre_technique", "Unknown")
    data["anomaly_score"] = max(data["anomaly_score"], anomaly)
    if is_destination and str(row.get("host", "")):
        data["hostname"] = str(row["host"])


def build_attack_graph(df: pd.DataFrame) -> nx.DiGraph:
    """Build a directed graph whose edges are observed security events.

    Nodes aggregate maximum risk/anomaly evidence while edge counts preserve
    repeated communication.  The function safely returns an empty graph for
    empty input, enabling dashboard pages to render without special callers.
    """
    graph = nx.DiGraph()
    if df is None or df.empty:
        return graph
    required = {"source_ip", "destination_ip"}
    missing = required.difference(df.columns)
    if missing:
        raise ValueError(f"Missing graph columns: {', '.join(sorted(missing))}")

    events = df.sort_values("timestamp", kind="stable") if "timestamp" in df else df
    for _, row in events.iterrows():
        source, destination = str(row["source_ip"]), str(row["destination_ip"])
        _update_node(graph, source, row, is_destination=False)
        _update_node(graph, destination, row, is_destination=True)
        edge_values = {
            "event_type": row.get("event_type", "Unknown"),
            "risk": float(row.get("risk_score", 0) or 0),
            "timestamp": str(row.get("timestamp", "")),
            "relationship_type": "suspicious_communication" if bool(row.get("known_threat", False)) else "network_connection",
            "mitre_technique": row.get("mitre_technique", "Unknown"),
        }
        if graph.has_edge(source, destination):
            edge = graph[source][destination]
            edge["count"] += 1
            if edge_values["risk"] >= edge["risk"]:
                edge.update(edge_values)
        else:
            graph.add_edge(source, destination, count=1, **edge_values)
    return graph


def get_high_risk_nodes(graph: nx.DiGraph, threshold: float = 60.0) -> list[str]:
    """Return nodes at or above the supplied risk threshold."""
    return [node for node, data in graph.nodes(data=True) if float(data.get("risk", 0)) >= threshold]


def get_suspicious_nodes(graph: nx.DiGraph) -> list[str]:
    """Backward-compatible alias used by the existing dashboard."""
    return get_high_risk_nodes(graph)


def get_critical_assets(graph: nx.DiGraph) -> list[str]:
    """Return explicitly critical assets, with a risk fallback for legacy graphs."""
    return [
        node for node, data in graph.nodes(data=True)
        if data.get("node_type") == "critical_asset" or float(data.get("criticality", 0)) >= 0.9 or float(data.get("risk", 0)) >= 80
    ]


def get_neighbors(graph: nx.DiGraph, node: str) -> dict[str, list[str]]:
    """Return inbound and outbound neighbours without raising for missing nodes."""
    if not graph.has_node(node):
        return {"predecessors": [], "successors": []}
    return {"predecessors": list(graph.predecessors(node)), "successors": list(graph.successors(node))}


def find_attack_paths(
    graph: nx.DiGraph,
    sources: Iterable[str] | None = None,
    targets: Iterable[str] | None = None,
    cutoff: int = 6,
    limit: int = 10,
) -> list[list[str]]:
    """Find bounded simple paths from risky/external nodes to critical assets."""
    if graph.number_of_nodes() < 2:
        return []
    source_nodes = list(sources) if sources is not None else [
        node for node, data in graph.nodes(data=True)
        if data.get("node_type") == "external_ip" or node in get_high_risk_nodes(graph)
    ]
    target_nodes = list(targets) if targets is not None else get_critical_assets(graph)
    paths: list[list[str]] = []
    for source in source_nodes:
        for target in target_nodes:
            if source == target or not graph.has_node(source) or not graph.has_node(target):
                continue
            try:
                for path in nx.all_simple_paths(graph, source, target, cutoff=cutoff):
                    paths.append(path)
                    if len(paths) >= limit:
                        return paths
            except nx.NetworkXNoPath:
                continue
    return paths


def get_critical_paths(graph: nx.DiGraph, limit: int = 10) -> list[list[str]]:
    """Return attack paths which terminate at an identified critical asset."""
    return find_attack_paths(graph, targets=get_critical_assets(graph), limit=limit)


def get_graph_summary(graph: nx.DiGraph) -> dict[str, int]:
    """Provide stable graph metrics for the dashboard."""
    return {
        "total_nodes": graph.number_of_nodes(),
        "total_connections": graph.number_of_edges(),
        "suspicious_nodes": len(get_high_risk_nodes(graph)),
        "critical_assets": len(get_critical_assets(graph)),
        "critical_paths": len(get_critical_paths(graph)),
    }
