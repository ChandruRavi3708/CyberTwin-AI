"""Safe, isolated copies of the attack graph for defense what-if analysis."""

from __future__ import annotations

import copy

import networkx as nx

from modules.attack_graph import get_critical_assets, get_critical_paths


def create_digital_twin(attack_graph: nx.DiGraph) -> nx.DiGraph:
    """Create an independent graph copy that cannot mutate the live graph."""
    twin = copy.deepcopy(attack_graph)
    # Keep an internal baseline so a caller can reset a long-lived twin.
    twin.graph["_twin_baseline"] = copy.deepcopy(attack_graph)
    return twin


def reset_twin(twin: nx.DiGraph, original_graph: nx.DiGraph | None = None) -> nx.DiGraph:
    """Return a reset twin from an explicit source or the twin's baseline."""
    source = original_graph or twin.graph.get("_twin_baseline") or twin
    return create_digital_twin(source)


def get_twin_state(twin: nx.DiGraph) -> dict[str, object]:
    """Summarise network topology, risk, critical assets, and attack paths."""
    nodes = twin.number_of_nodes()
    average_risk = round(sum(float(data.get("risk", 0)) for _, data in twin.nodes(data=True)) / nodes, 2) if nodes else 0.0
    paths = get_critical_paths(twin)
    return {
        "nodes": nodes,
        "connections": twin.number_of_edges(),
        "average_risk": average_risk,
        "critical_nodes": get_critical_assets(twin),
        "active_attack_paths": paths,
        "active_attack_path_count": len(paths),
    }


def simulate_network_change(twin: nx.DiGraph, action: str, **targets: str | None) -> dict[str, object]:
    """Apply a defense action only to a copy of the supplied twin.

    The import is local to keep the twin model independent of simulation
    mechanics and avoid circular imports.
    """
    from modules.defense_simulation import simulate_defense

    return simulate_defense(twin, action, **targets)
