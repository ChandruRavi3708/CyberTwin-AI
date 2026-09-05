"""Lightweight distribution-drift monitoring for security telemetry."""

from __future__ import annotations

import numpy as np
import pandas as pd


DRIFT_FEATURES = ["failed_logins", "connections", "data_transfer", "anomaly_score"]


def _values(df: pd.DataFrame, feature: str) -> np.ndarray:
    source = df.get(feature, df.get("bytes") if feature == "data_transfer" else None)
    if source is None:
        source = pd.Series(0, index=df.index)
    values = pd.to_numeric(source, errors="coerce").fillna(0).to_numpy(dtype=float)
    return values[np.isfinite(values)]


def _feature_drift(historical: np.ndarray, recent: np.ndarray) -> float:
    """Combine robust median movement and distribution-bin change (0--1)."""
    if len(historical) == 0 or len(recent) == 0:
        return 0.0
    baseline_median = float(np.median(historical))
    baseline_iqr = float(np.percentile(historical, 75) - np.percentile(historical, 25))
    median_shift = min(1.0, abs(float(np.median(recent)) - baseline_median) / max(baseline_iqr * 2, 1.0))
    # Quantile-derived bins provide a dependency-free distribution comparison.
    edges = np.unique(np.quantile(historical, np.linspace(0, 1, 6)))
    if len(edges) < 2:
        distribution_shift = min(1.0, abs(float(np.mean(recent)) - float(np.mean(historical))) / max(abs(float(np.mean(historical))), 1.0))
    else:
        edges[0], edges[-1] = -np.inf, np.inf
        baseline_hist = np.histogram(historical, bins=edges)[0] / len(historical)
        recent_hist = np.histogram(recent, bins=edges)[0] / len(recent)
        distribution_shift = min(1.0, float(np.abs(baseline_hist - recent_hist).sum() / 2))
    return round(0.55 * median_shift + 0.45 * distribution_shift, 3)


def get_drift_level(drift_score: float) -> str:
    """Convert a 0--1 drift score into the required operational band."""
    if drift_score < 0.10:
        return "NO DRIFT"
    if drift_score < 0.25:
        return "LOW DRIFT"
    if drift_score < 0.50:
        return "MODERATE DRIFT"
    return "HIGH DRIFT"


def calculate_concept_drift(historical_events: pd.DataFrame, recent_events: pd.DataFrame) -> dict[str, object]:
    """Compare historical and recent telemetry distributions feature by feature."""
    feature_scores = {
        feature: _feature_drift(_values(historical_events, feature), _values(recent_events, feature))
        for feature in DRIFT_FEATURES
    }
    score = round(float(np.mean(list(feature_scores.values()))) if feature_scores else 0.0, 3)
    return {
        "drift_score": score,
        "drift_level": get_drift_level(score),
        "feature_drift": feature_scores,
        "historical_events": len(historical_events),
        "recent_events": len(recent_events),
    }


def monitor_concept_drift(events: pd.DataFrame, recent_fraction: float = 0.20) -> dict[str, object]:
    """Split chronologically ordered events and calculate their drift summary."""
    if not 0 < recent_fraction < 1:
        raise ValueError("recent_fraction must be between 0 and 1")
    if events is None or len(events) < 2:
        return {"drift_score": 0.0, "drift_level": "NO DRIFT", "feature_drift": {feature: 0.0 for feature in DRIFT_FEATURES}, "historical_events": 0 if events is None else len(events), "recent_events": 0}
    ordered = events.sort_values("timestamp", kind="stable") if "timestamp" in events else events
    split_at = max(1, int(len(ordered) * (1 - recent_fraction)))
    return calculate_concept_drift(ordered.iloc[:split_at], ordered.iloc[split_at:])
