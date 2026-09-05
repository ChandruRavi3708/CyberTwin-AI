"""Known-threat rules and reusable Isolation Forest anomaly detection."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import RobustScaler


ANOMALY_FEATURES = ["port", "failed_logins", "connections", "data_transfer", "packet_size", "request_frequency"]


def _normalise_event_type(value: object) -> str:
    """Normalise legacy and Phase 1 event labels for rule matching."""
    return str(value).strip().lower().replace("_", " ")


def detect_anomalies(df: pd.DataFrame, contamination: float = 0.10, training_data: pd.DataFrame | None = None) -> pd.DataFrame:
    """Mark statistically unusual activity with Isolation Forest.

    The model is fitted to the supplied batch for the offline prototype. Raw
    decision values are inverted and normalised to a 0--1 anomaly score.
    """
    if not 0 < contamination < 0.5:
        raise ValueError("contamination must be between 0 and 0.5")
    df = df.copy()
    if df.empty:
        df["anomaly_prediction"] = pd.Series(dtype="int64")
        df["anomaly_score"] = pd.Series(dtype="float64")
        df["is_anomaly"] = pd.Series(dtype="bool")
        return df

    features = pd.DataFrame(index=df.index)
    for column in ANOMALY_FEATURES:
        source = df["bytes"] if column == "data_transfer" and "bytes" in df else df.get(column, 0)
        features[column] = pd.to_numeric(source, errors="coerce").fillna(0).clip(lower=0)

    if len(df) == 1:
        df["anomaly_prediction"] = 1
        df["anomaly_score"] = 0.0
        df["is_anomaly"] = False
        return df

    training_features = features
    if training_data is not None and not training_data.empty:
        training_features = pd.DataFrame(index=training_data.index)
        for column in ANOMALY_FEATURES:
            source = training_data["bytes"] if column == "data_transfer" and "bytes" in training_data else training_data.get(column, 0)
            training_features[column] = pd.to_numeric(source, errors="coerce").fillna(0).clip(lower=0)
    if len(training_features) < 2:
        raise ValueError("At least two training rows are required for anomaly detection.")
    scaler = RobustScaler().fit(training_features)
    scaled_features = scaler.transform(features)
    scaled_training_features = scaler.transform(training_features)
    model = IsolationForest(contamination=contamination, random_state=42, n_estimators=200)
    model.fit(scaled_training_features)
    predictions = model.predict(scaled_features)
    unusualness = -model.decision_function(scaled_features)
    score_range = unusualness.max() - unusualness.min()
    scores = np.zeros(len(df)) if score_range == 0 else (unusualness - unusualness.min()) / score_range
    df["anomaly_prediction"] = predictions
    df["anomaly_score"] = np.round(scores, 3)
    df["is_anomaly"] = predictions == -1
    return df


def detect_known_threats(df: pd.DataFrame) -> pd.DataFrame:
    """Apply transparent rules for recognised attack behaviours."""
    df = df.copy()
    event_types = df.get("event_type", pd.Series("", index=df.index)).map(_normalise_event_type)
    failed_logins = pd.to_numeric(df.get("failed_logins", 0), errors="coerce").fillna(0)
    data_transfer = pd.to_numeric(df.get("data_transfer", df.get("bytes", 0)), errors="coerce").fillna(0)
    df["known_threat"] = False
    df["threat_type"] = "Normal"
    rules = [
        (event_types.eq("port scan"), "Port Scan / Reconnaissance"),
        (event_types.eq("failed login burst") | event_types.eq("login failure") | failed_logins.ge(5), "Credential Attack"),
        (event_types.eq("credential abuse"), "Credential Abuse"),
        (event_types.eq("suspicious connection"), "Suspicious Connection"),
        (event_types.eq("malware activity"), "Malware Activity"),
        (event_types.eq("lateral movement"), "Lateral Movement"),
        (event_types.eq("privilege escalation"), "Privilege Escalation"),
        (event_types.eq("data exfiltration") | (event_types.eq("data transfer") & data_transfer.ge(50_000)), "Data Exfiltration"),
    ]
    for condition, threat_name in rules:
        df.loc[condition, "known_threat"] = True
        df.loc[condition, "threat_type"] = threat_name
    return df
