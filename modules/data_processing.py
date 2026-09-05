"""Reusable Phase 1 cleansing and feature engineering for network events."""

import numpy as np
import pandas as pd


REQUIRED_COLUMNS = {"timestamp", "source_ip", "destination_ip", "protocol", "port", "event_type"}
NUMERIC_DEFAULTS = {
    "failed_logins": 0,
    "connections": 1,
    "data_transfer": 0,
    "packet_size": 0,
    "request_frequency": 1,
}


def preprocess_data(df: pd.DataFrame) -> pd.DataFrame:
    """Validate, clean, and enrich event data without changing its input.

    Legacy ``bytes``-only CSVs are accepted for compatibility.  Phase 1's
    canonical traffic field is ``data_transfer``; ``bytes`` is retained as an
    alias because current later-phase modules still use it.
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas DataFrame")
    missing = REQUIRED_COLUMNS.difference(df.columns)
    if missing:
        raise ValueError(f"Missing required event columns: {', '.join(sorted(missing))}")

    df = df.copy()
    if "data_transfer" not in df.columns:
        df["data_transfer"] = df.get("bytes", 0)
    if "bytes" not in df.columns:
        df["bytes"] = df["data_transfer"]

    for column, default in NUMERIC_DEFAULTS.items():
        df[column] = pd.to_numeric(df.get(column, default), errors="coerce").fillna(default).clip(lower=0)
    df["port"] = pd.to_numeric(df["port"], errors="coerce").fillna(0).clip(lower=0, upper=65535).astype(int)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if df["timestamp"].isna().any():
        raise ValueError("All event timestamps must be valid datetime values")
    df["bytes"] = df["data_transfer"]

    # -----------------------------------
    # TIME FEATURES
    # -----------------------------------

    df["hour"] = df["timestamp"].dt.hour

    df["minute"] = df["timestamp"].dt.minute

    # -----------------------------------
    # NETWORK FEATURES
    # -----------------------------------

    # Logarithmic traffic feature reduces the influence of large transfers.
    df["log_bytes"] = np.log1p(df["data_transfer"])

    # Is this authentication related?
    df["is_auth_event"] = (
        df["event_type"]
        .isin([
            "login_failure", "Failed Login Burst", "Login Attempt", "Credential Abuse"
        ])
        .astype(int)
    )

    # Is this scanning?
    df["is_scan"] = (
        df["event_type"]
        .isin([
            "port_scan", "Port Scan"
        ])
        .astype(int)
    )

    # Is this lateral movement?
    df["is_lateral_movement"] = (
        df["event_type"]
        .isin([
            "lateral_movement", "Lateral Movement"
        ])
        .astype(int)
    )

    # Is this data exfiltration?
    df["is_exfiltration"] = (
        df["event_type"]
        .isin([
            "data_exfiltration"
        ])
        .astype(int)
    )

    # A compact feature used by later models without exposing raw strings.
    df["is_high_volume"] = (df["data_transfer"] >= 50_000).astype(int)
    return df.sort_values("timestamp", kind="stable").reset_index(drop=True)
