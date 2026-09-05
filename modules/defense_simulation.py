"""Risk and path-impact calculations for safe network defense simulations."""

from __future__ import annotations

import copy

import networkx as nx

from modules.attack_graph import get_critical_paths


def calculate_network_risk(graph: nx.DiGraph) -> float:
    """Return average node exposure, weighted for critical assets, on a 0--100 scale."""
    if graph.number_of_nodes() == 0:
        return 0.0
    exposure = sum(float(data.get("risk", 0)) * (1 + 0.5 * float(data.get("criticality", 0))) for _, data in graph.nodes(data=True))
    return round(min(100.0, exposure / graph.number_of_nodes()), 2)


def block_ip(graph: nx.DiGraph, ip: str | None) -> nx.DiGraph:
    simulated = copy.deepcopy(graph)
    if ip and simulated.has_node(ip):
        simulated.remove_node(ip)
    return simulated


def isolate_host(graph: nx.DiGraph, host: str | None) -> nx.DiGraph:
    simulated = copy.deepcopy(graph)
    if host and simulated.has_node(host):
        simulated.remove_edges_from(list(simulated.in_edges(host)) + list(simulated.out_edges(host)))
        simulated.nodes[host]["isolated"] = True
    return simulated


def block_connection(graph: nx.DiGraph, source: str | None, destination: str | None) -> nx.DiGraph:
    simulated = copy.deepcopy(graph)
    if source and destination and simulated.has_edge(source, destination):
        simulated.remove_edge(source, destination)
    return simulated


def protect_asset(graph: nx.DiGraph, asset: str | None) -> nx.DiGraph:
    simulated = copy.deepcopy(graph)
    if asset and simulated.has_node(asset):
        node = simulated.nodes[asset]
        node["risk"] = round(float(node.get("risk", 0)) * 0.30, 2)
        node["protected"] = True
        node["criticality"] = min(float(node.get("criticality", 0)), 0.4)
    return simulated


def check_attack_path(graph: nx.DiGraph, attacker: str | None, target: str | None) -> bool:
    """Safely test reachability between two assets."""
    return bool(attacker and target and graph.has_node(attacker) and graph.has_node(target) and nx.has_path(graph, attacker, target))


def _apply_action(graph: nx.DiGraph, action: str, target: str | None, source: str | None, destination: str | None) -> nx.DiGraph:
    if action == "Block IP":
        return block_ip(graph, target)
    if action == "Isolate Host":
        return isolate_host(graph, target)
    if action == "Block Connection":
        return block_connection(graph, source, destination)
    if action in {"Protect Asset", "Protect Critical Asset"}:
        return protect_asset(graph, target)
    raise ValueError(f"Unsupported defense action: {action}")


def simulate_defense(
    graph: nx.DiGraph,
    action: str,
    target: str | None = None,
    source: str | None = None,
    destination: str | None = None,
    attacker: str | None = None,
    critical_target: str | None = None,
) -> dict[str, object]:
    """Run one action against a copy and quantify risk and path changes."""
    before_risk = calculate_network_risk(graph)
    before_paths = get_critical_paths(graph)
    path_before = check_attack_path(graph, attacker, critical_target)
    simulated_graph = _apply_action(graph, action, target, source, destination)
    after_risk = calculate_network_risk(simulated_graph)
    after_paths = get_critical_paths(simulated_graph)
    path_after = check_attack_path(simulated_graph, attacker, critical_target)
    reduction = round(before_risk - after_risk, 2)
    reduction_percent = round(reduction / before_risk * 100, 2) if before_risk else 0.0
    path_reduction = round((len(before_paths) - len(after_paths)) / len(before_paths) * 100, 2) if before_paths else 0.0
    return {
        "before_risk": before_risk,
        "after_risk": after_risk,
        "risk_reduction": reduction,
        "risk_reduction_percent": reduction_percent,
        "attack_paths_before": before_paths,
        "attack_paths_after": after_paths,
        "path_reduction_percent": path_reduction,
        "attack_path_before": path_before,
        "attack_path_after": path_after,
        "attack_path_disrupted": path_before and not path_after if attacker and critical_target else len(after_paths) < len(before_paths),
        "graph": simulated_graph,
    }
