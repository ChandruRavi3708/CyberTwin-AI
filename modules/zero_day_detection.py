"""Novel-behaviour detection for unknown / zero-day-like suspicious activity.

This module does not claim to identify real zero-day exploits. It highlights
events that are statistically unusual while having little match to the local
known-attack rules, so an analyst can investigate them as novel behaviour.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


NOVELTY_FEATURES = ["failed_logins", "connections", "data_transfer", "packet_size", "request_frequency"]


def _numeric_series(df: pd.DataFrame, column: str) -> pd.Series:
    """Return a finite, non-negative feature series with a safe default."""
    source = df.get(column, df.get("bytes") if column == "data_transfer" else None)
    if source is None:
        source = pd.Series(0, index=df.index)
    return pd.to_numeric(source, errors="coerce").fillna(0).clip(lower=0)


def detect_unknown_behaviour(df: pd.DataFrame, alert_threshold: float = 0.70) -> pd.DataFrame:
    """Append novelty scores and alerts to an already processed event dataframe.

    ``known_attack_match`` is a 0--1 confidence that an event is covered by
    local rules. ``unknown_behavior_score`` combines anomaly evidence,
    feature rarity, and low known-pattern match. Alerts are deliberately named
    *Unknown / Novel Suspicious Behaviour* rather than zero-day detections.
    """
    if not 0 < alert_threshold <= 1:
        raise ValueError("alert_threshold must be in the range (0, 1]")
    df = df.copy()
    if df.empty:
        df["known_attack_match"] = pd.Series(dtype="float64")
        df["unknown_behavior_score"] = pd.Series(dtype="float64")
        df["zero_day_alert"] = pd.Series(dtype="bool")
        df["novelty_label"] = pd.Series(dtype="object")
        return df

    known_threat = df.get("known_threat", pd.Series(False, index=df.index)).fillna(False).astype(bool)
    mitre_match = df.get("mitre_id", pd.Series("Unknown", index=df.index)).fillna("Unknown").ne("Unknown")
    known_attack_match = np.where(known_threat | mitre_match, 1.0, 0.0)

    rarity_components = []
    for feature in NOVELTY_FEATURES:
        values = _numeric_series(df, feature)
        median = values.median()
        mad = (values - median).abs().median()
        scale = max(float(mad) * 1.4826, 1.0)
        # Only unusually elevated telemetry increases novelty for this demo.
        rarity_components.append(((values - median).clip(lower=0) / (3 * scale)).clip(upper=1.0))
    rarity = pd.concat(rarity_components, axis=1).mean(axis=1).to_numpy()
    anomaly = _numeric_series(df, "anomaly_score").clip(upper=1.0).to_numpy()
    scores = np.clip(anomaly * 0.60 + rarity * 0.25 + (1 - known_attack_match) * 0.15, 0, 1)
    alerts = (scores >= alert_threshold) & (known_attack_match <= 0.30)

    df["known_attack_match"] = known_attack_match
    df["unknown_behavior_score"] = np.round(scores, 3)
    df["zero_day_alert"] = alerts
    df["novelty_label"] = np.where(alerts, "Unknown / Novel Suspicious Behaviour", "No Novel Behaviour Alert")
    return df
