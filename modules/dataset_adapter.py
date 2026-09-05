"""CIC-style CSV adapter that produces CyberTwin's canonical event schema.

The adapter is intentionally independent of Streamlit and of the intelligence
pipeline. Labels are preserved for optional post-analysis evaluation, never as
an Isolation Forest feature.
"""

from __future__ import annotations

from datetime import datetime
import re

import numpy as np
import pandas as pd


COLUMN_ALIASES = {
    "source_ip": ("source ip", "src ip", "src_ip", "source_ip"),
    "destination_ip": ("destination ip", "dst ip", "dst_ip", "destination_ip"),
    "port": ("destination port", "dst port", "dst_port", "port"),
    "protocol": ("protocol",),
    "timestamp": ("timestamp", "time", "flow start time"),
    "original_label": ("label", "attack", "class", "category"),
    "connections": ("total fwd packets", "total backward packets", "total bwd packets", "flow packets/s", "total packets"),
    "data_transfer": ("flow bytes/s", "total length of fwd packets", "total length of bwd packets", "total length of forward packets", "total length of backward packets", "total bytes"),
    "packet_size": ("average packet size", "avg packet size", "packet length mean", "average packet size"),
    "request_frequency": ("flow packets/s", "packets/s", "flow iat mean"),
    "flow_duration": ("flow duration",),
}


def _canonical_name(name: object) -> str:
    return re.sub(r"\s+", " ", str(name).strip().replace("_", " ").lower())


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace and make duplicate source column names unambiguous."""
    cleaned = df.copy()
    counts: dict[str, int] = {}
    names: list[str] = []
    for name in cleaned.columns:
        base = _canonical_name(name)
        counts[base] = counts.get(base, 0) + 1
        names.append(base if counts[base] == 1 else f"{base}__{counts[base]}")
    cleaned.columns = names
    cleaned = cleaned.replace([np.inf, -np.inf], np.nan)
    return cleaned


def detect_dataset_schema(df: pd.DataFrame) -> dict[str, object]:
    """Detect common CIC/network-flow columns and report unavailable fields."""
    columns = {_canonical_name(column): column for column in df.columns}
    mapping: dict[str, str] = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        found = next((columns[alias] for alias in aliases if alias in columns), None)
        if found is not None:
            mapping[canonical] = found
    important = ("source_ip", "destination_ip", "port", "protocol", "timestamp")
    return {
        "mapping": mapping,
        "missing_important": [field for field in important if field not in mapping],
        "detected_columns": len(mapping),
        "has_labels": "original_label" in mapping,
    }


def sample_large_dataset(df: pd.DataFrame, max_rows: int = 10_000, method: str = "Random Sample", random_state: int = 42) -> pd.DataFrame:
    """Return a reproducible bounded sample without modifying the source data."""
    if max_rows < 1:
        raise ValueError("max_rows must be at least 1")
    if len(df) <= max_rows:
        return df.copy()
    if method == "First N Rows":
        return df.head(max_rows).copy()
    if method != "Random Sample":
        raise ValueError("method must be 'Random Sample' or 'First N Rows'")
    return df.sample(n=max_rows, random_state=random_state).copy()


def _numeric(df: pd.DataFrame, column: str | None, default: float = 0) -> pd.Series:
    if column is None:
        return pd.Series(default, index=df.index, dtype=float)
    return pd.to_numeric(df[column], errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(default).clip(lower=0)


def _text(df: pd.DataFrame, column: str | None, default: str = "Unknown") -> pd.Series:
    if column is None:
        return pd.Series(default, index=df.index, dtype="object")
    return df[column].fillna(default).astype(str).str.strip().replace("", default)


def _event_types(port: pd.Series, request_frequency: pd.Series, transfer: pd.Series) -> pd.Series:
    """Derive broad flow behaviour from telemetry, without using ground-truth labels."""
    event_type = pd.Series("Normal Traffic", index=port.index, dtype="object")
    event_type.loc[port.isin([21, 22, 23])] = "Login Attempt"
    event_type.loc[port.isin([445, 3389, 1433])] = "Suspicious Connection"
    event_type.loc[request_frequency >= request_frequency.quantile(0.98)] = "Port Scan"
    event_type.loc[transfer >= max(float(transfer.quantile(0.99)), 50_000)] = "Data Transfer"
    return event_type


def convert_cic_to_cybertwin(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, object]]:
    """Normalize a CIC-style flow dataframe into the CyberTwin event format.

    Missing IPs become ``Unknown``; missing timestamps become a deterministic
    per-row sequence from 2026-01-01; unavailable auth data becomes zero.
    """
    if not isinstance(df, pd.DataFrame):
        raise TypeError("df must be a pandas DataFrame")
    clean = clean_column_names(df)
    schema = detect_dataset_schema(clean)
    mapping = schema["mapping"]
    port = _numeric(clean, mapping.get("port")).clip(upper=65535).astype(int)
    connections = _numeric(clean, mapping.get("connections"), 1).clip(upper=1_000_000)
    transfer = _numeric(clean, mapping.get("data_transfer")).clip(upper=1e12)
    packet_size = _numeric(clean, mapping.get("packet_size"))
    frequency = _numeric(clean, mapping.get("request_frequency"), 1).clip(upper=1e9)
    timestamps = pd.to_datetime(clean[mapping["timestamp"]], errors="coerce") if "timestamp" in mapping else pd.Series(pd.NaT, index=clean.index)
    fallback_time = pd.Series(pd.date_range(datetime(2026, 1, 1), periods=len(clean), freq="s"), index=clean.index)
    timestamps = timestamps.fillna(fallback_time)
    protocol = _text(clean, mapping.get("protocol"), "Unknown").replace({"6": "TCP", "17": "UDP", "1": "ICMP"})
    result = pd.DataFrame({
        "timestamp": timestamps,
        "source_ip": _text(clean, mapping.get("source_ip")),
        "destination_ip": _text(clean, mapping.get("destination_ip")),
        "protocol": protocol,
        "port": port,
        "connections": connections,
        "data_transfer": transfer,
        "packet_size": packet_size,
        "request_frequency": frequency,
        "failed_logins": 0,
        "event_type": _event_types(port, frequency, transfer),
        "original_label": _text(clean, mapping.get("original_label"), "Unknown"),
        "host": _text(clean, mapping.get("destination_ip")),
        "authentication_status": "not_available",
        "user_account": "unknown",
        "severity_hint": "Low",
        "anomaly_hint": False,
        "scenario_id": "uploaded_dataset",
    })
    result["bytes"] = result["data_transfer"]
    result["risk_level"] = "Low"
    schema["fallbacks"] = {
        "failed_logins": "Set to 0 because CIC flow data does not reliably contain authentication failures.",
        "timestamp": "Sequential timestamps used where source timestamps were missing or malformed.",
        "ip_addresses": "Unknown used where source or destination IP was unavailable.",
        "event_type": "Derived from flow telemetry only; labels are retained for post-analysis evaluation.",
    }
    return result, schema


def validate_cybertwin_schema(df: pd.DataFrame) -> dict[str, object]:
    """Validate the minimum event fields expected by CyberTwin preprocessing."""
    required = {"timestamp", "source_ip", "destination_ip", "protocol", "port", "event_type", "connections", "data_transfer", "packet_size", "request_frequency", "failed_logins", "original_label", "host"}
    missing = sorted(required.difference(df.columns))
    return {"is_valid": not missing and not df.empty, "missing_columns": missing, "rows": len(df)}
