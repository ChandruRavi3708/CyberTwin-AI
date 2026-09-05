"""Offline security-copilot explanations with an optional provider interface."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol

import networkx as nx
import pandas as pd

from modules.xai_engine import explain_event


class SecurityExplanationProvider(Protocol):
    """Interface an API-backed provider may implement in a later deployment."""

    def generate(self, event: Mapping[str, Any], graph_context: Any | None = None) -> str:
        """Generate a security explanation without exposing credentials."""


def _event_dict(event: Mapping[str, Any] | pd.Series) -> dict[str, Any]:
    return event.to_dict() if isinstance(event, pd.Series) else dict(event)


def _graph_context_summary(graph_context: Any | None, source_ip: str) -> str:
    if not isinstance(graph_context, nx.Graph) or graph_context.number_of_nodes() == 0:
        return "No graph context is currently available."
    if not graph_context.has_node(source_ip):
        return "The source is not present in the current attack graph."
    successors = list(graph_context.successors(source_ip)) if graph_context.is_directed() else list(graph_context.neighbors(source_ip))
    critical_nodes = [node for node, data in graph_context.nodes(data=True) if data.get("node_type") == "critical_asset"]
    if successors and critical_nodes:
        return f"The source has {len(successors)} observed outbound relationship(s); the graph contains {len(critical_nodes)} critical asset(s)."
    return "The source has limited graph reachability in the current attack graph."


def generate_security_explanation(
    event: Mapping[str, Any] | pd.Series,
    graph_context: Any | None = None,
    provider: SecurityExplanationProvider | None = None,
) -> str:
    """Return an analyst-readable explanation, using an optional provider safely.

    The default is fully local and requires no API key. If an optional provider
    fails, the local template remains available rather than interrupting SOC use.
    """
    record = _event_dict(event)
    if provider is not None:
        try:
            return provider.generate(record, graph_context)
        except Exception:
            # A remote integration must never make the offline fallback unavailable.
            pass
    xai = explain_event(record)
    summary = xai["event_summary"]
    mitre = xai["mitre"]
    reasons = "; ".join(xai["why_flagged"][:3])
    next_step = xai["recommended_investigation_steps"][0]
    graph_summary = _graph_context_summary(graph_context, str(summary["source_ip"]))
    return (
        f"{summary['source_ip']} is assessed as {summary['risk_level']} risk ({summary['risk_score']:.1f}/100) "
        f"after {summary['event_type']} activity toward {summary['destination_ip']}. "
        f"It was flagged because of {reasons}. "
        f"The mapped MITRE behaviour is {mitre['id']} {mitre['technique']} ({mitre['tactic']}). "
        f"{graph_summary} Recommended analyst action: {next_step}"
    )


def answer_security_question(question: str, event: Mapping[str, Any] | pd.Series, graph_context: Any | None = None) -> str:
    """Answer common copilot questions using the offline explanation context."""
    record = _event_dict(event)
    xai = explain_event(record)
    question_text = question.lower()
    if "mitre" in question_text or "technique" in question_text:
        mitre = xai["mitre"]
        return f"This event maps to {mitre['id']} {mitre['technique']} in the {mitre['tactic']} tactic."
    if "investigate" in question_text or "what should" in question_text:
        return " ".join(xai["recommended_investigation_steps"])
    if "next" in question_text or "happen" in question_text:
        return "Review the attack forecast for the source; graph context indicates: " + _graph_context_summary(graph_context, str(record.get("source_ip", "")))
    if "defense" in question_text or "recommend" in question_text:
        return "Prioritise containment of the source path and protection of any reachable critical asset, then " + xai["recommended_investigation_steps"][0].lower()
    return generate_security_explanation(record, graph_context)
