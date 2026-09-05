"""Deterministic synthetic network telemetry for the CyberTwin AI demo.

The generator deliberately combines ordinary activity with ordered attack
scenarios.  That makes later detection, graph, and forecasting phases
demonstrable without needing a live network or an external data source.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


DEFAULT_SEED = 42
DEFAULT_EVENT_COUNT = 1_000
DEFAULT_START_TIME = datetime(2026, 9, 1, 8, 0, 0)

INTERNAL_HOSTS = {
    "web-01": "192.168.1.20",
    "auth-01": "192.168.1.30",
    "workstation-07": "192.168.1.50",
    "db-01": "192.168.1.60",
}
USER_ACCOUNTS = ["alex.chen", "priya.shah", "morgan.lee", "svc-backup"]
EXTERNAL_ATTACKERS = ["185.220.101.10", "45.142.212.55", "91.108.4.100"]


def _event(
    timestamp: datetime,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    port: int,
    event_type: str,
    *,
    failed_logins: int = 0,
    connections: int = 1,
    data_transfer: int = 0,
    packet_size: int = 0,
    request_frequency: int = 1,
    authentication_status: str = "not_applicable",
    user_account: str = "system",
    host: str = "unknown",
    severity_hint: str = "Low",
    anomaly_hint: bool = False,
    scenario_id: str = "baseline",
) -> dict[str, Any]:
    """Return one consistently shaped event record.

    ``bytes`` remains as a compatibility alias for the current dashboard.
    It is derived from the Phase 1 ``data_transfer`` field rather than stored
    independently, so future phases have one authoritative traffic measure.
    """
    return {
        "timestamp": timestamp.isoformat(sep=" "),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "port": port,
        "event_type": event_type,
        "failed_logins": failed_logins,
        "connections": connections,
        "data_transfer": data_transfer,
        "packet_size": packet_size,
        "request_frequency": request_frequency,
        "authentication_status": authentication_status,
        "user_account": user_account,
        "host": host,
        "severity_hint": severity_hint,
        "anomaly_hint": anomaly_hint,
        "scenario_id": scenario_id,
        # Backward-compatible fields consumed by the existing dashboard.
        "bytes": data_transfer,
        "risk_level": severity_hint,
    }


def _baseline_event(timestamp: datetime, rng: np.random.Generator) -> dict[str, Any]:
    """Create one benign event with realistic, bounded network values."""
    host, source_ip = list(INTERNAL_HOSTS.items())[rng.integers(len(INTERNAL_HOSTS))]
    event_kind = rng.choice(
        [
            "Normal Traffic", "Normal Traffic", "Normal Traffic", "Login Attempt",
            "Data Transfer", "Suspicious Connection", "Malware Activity",
        ]
    )
    if event_kind == "Login Attempt":
        destination_host, destination_ip = "auth-01", INTERNAL_HOSTS["auth-01"]
        return _event(
            timestamp, source_ip, destination_ip, "TCP", 443, event_kind,
            data_transfer=int(rng.integers(400, 1_500)), packet_size=int(rng.integers(200, 800)),
            request_frequency=int(rng.integers(1, 6)), authentication_status="success",
            user_account=str(rng.choice(USER_ACCOUNTS[:-1])), host=destination_host,
        )
    if event_kind == "Data Transfer":
        destination_host, destination_ip = "web-01", INTERNAL_HOSTS["web-01"]
        return _event(
            timestamp, source_ip, destination_ip, "TCP", 443, event_kind,
            connections=int(rng.integers(1, 5)), data_transfer=int(rng.integers(2_000, 12_000)),
            packet_size=int(rng.integers(700, 1_400)), request_frequency=int(rng.integers(2, 10)),
            host=destination_host,
        )
    if event_kind == "Suspicious Connection":
        destination_host, destination_ip = "web-01", INTERNAL_HOSTS["web-01"]
        return _event(
            timestamp, str(rng.choice(EXTERNAL_ATTACKERS)), destination_ip, "TCP", 3389, event_kind,
            connections=int(rng.integers(5, 12)), data_transfer=int(rng.integers(5_000, 18_000)),
            packet_size=int(rng.integers(400, 1_100)), request_frequency=int(rng.integers(10, 25)),
            host=destination_host, severity_hint="High", anomaly_hint=True,
        )
    if event_kind == "Malware Activity":
        destination_host, destination_ip = "workstation-07", INTERNAL_HOSTS["workstation-07"]
        return _event(
            timestamp, str(rng.choice(EXTERNAL_ATTACKERS)), destination_ip, "TCP", 445, event_kind,
            connections=int(rng.integers(4, 10)), data_transfer=int(rng.integers(8_000, 30_000)),
            packet_size=int(rng.integers(700, 1_400)), request_frequency=int(rng.integers(8, 18)),
            host=destination_host, severity_hint="High", anomaly_hint=True,
        )
    destination_host, destination_ip = "web-01", INTERNAL_HOSTS["web-01"]
    return _event(
        timestamp, source_ip, destination_ip, str(rng.choice(["TCP", "UDP"])),
        int(rng.choice([53, 80, 443])), event_kind, connections=int(rng.integers(1, 4)),
        data_transfer=int(rng.integers(300, 5_000)), packet_size=int(rng.integers(100, 1_200)),
        request_frequency=int(rng.integers(1, 8)), host=destination_host,
    )


def _attack_sequence(start: datetime, attacker: str, scenario_number: int) -> list[dict[str, Any]]:
    """Create an ordered recon-to-critical-asset compromise sequence."""
    scenario_id = f"attack-{scenario_number:02d}"
    web_ip, auth_ip, workstation_ip, db_ip = (INTERNAL_HOSTS[name] for name in ("web-01", "auth-01", "workstation-07", "db-01"))
    return [
        _event(start, attacker, web_ip, "TCP", 80, "Port Scan", connections=24,
               data_transfer=180, packet_size=72, request_frequency=36, host="web-01",
               severity_hint="Medium", anomaly_hint=True, scenario_id=scenario_id),
        _event(start + timedelta(minutes=1), attacker, auth_ip, "TCP", 22, "Failed Login Burst",
               failed_logins=14, connections=16, data_transfer=900, packet_size=120,
               request_frequency=28, authentication_status="failed", user_account="admin",
               host="auth-01", severity_hint="High", anomaly_hint=True, scenario_id=scenario_id),
        _event(start + timedelta(minutes=2), attacker, auth_ip, "TCP", 443, "Credential Abuse",
               connections=5, data_transfer=2_400, packet_size=480, request_frequency=12,
               authentication_status="success", user_account="svc-backup", host="auth-01",
               severity_hint="Critical", anomaly_hint=True, scenario_id=scenario_id),
        _event(start + timedelta(minutes=3), auth_ip, workstation_ip, "TCP", 445, "Lateral Movement",
               connections=9, data_transfer=18_000, packet_size=1_200, request_frequency=18,
               authentication_status="success", user_account="svc-backup", host="workstation-07",
               severity_hint="Critical", anomaly_hint=True, scenario_id=scenario_id),
        _event(start + timedelta(minutes=4), workstation_ip, db_ip, "TCP", 1433, "Privilege Escalation",
               connections=4, data_transfer=7_000, packet_size=1_000, request_frequency=10,
               authentication_status="success", user_account="svc-backup", host="db-01",
               severity_hint="Critical", anomaly_hint=True, scenario_id=scenario_id),
        _event(start + timedelta(minutes=5), db_ip, attacker, "TCP", 443, "Data Transfer",
               connections=3, data_transfer=190_000, packet_size=1_450, request_frequency=20,
               user_account="svc-backup", host="db-01", severity_hint="Critical",
               anomaly_hint=True, scenario_id=scenario_id),
    ]


def generate_network_events(
    event_count: int = DEFAULT_EVENT_COUNT,
    seed: int = DEFAULT_SEED,
    start_time: datetime = DEFAULT_START_TIME,
) -> pd.DataFrame:
    """Generate a reproducible blend of baseline telemetry and attack chains.

    At least one complete attack chain is included when ``event_count`` is six
    or greater.  The returned dataframe is chronologically ordered.
    """
    if event_count < 1:
        raise ValueError("event_count must be at least 1")

    rng = np.random.default_rng(seed)
    events: list[dict[str, Any]] = []
    attack_events = min(event_count, 18)
    baseline_count = event_count - attack_events
    current_time = start_time
    for _ in range(baseline_count):
        current_time += timedelta(seconds=int(rng.integers(8, 55)))
        events.append(_baseline_event(current_time, rng))

    for scenario_number, offset in enumerate(range(0, attack_events, 6), start=1):
        sequence = _attack_sequence(
            current_time + timedelta(minutes=10 + scenario_number * 8),
            EXTERNAL_ATTACKERS[(scenario_number - 1) % len(EXTERNAL_ATTACKERS)],
            scenario_number,
        )
        events.extend(sequence[: attack_events - offset])

    return pd.DataFrame(events).sort_values("timestamp", kind="stable").reset_index(drop=True)


def save_network_events(output_path: str | Path, **generator_options: Any) -> pd.DataFrame:
    """Generate and write the offline demo dataset, returning the dataframe."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    events = generate_network_events(**generator_options)
    events.to_csv(output, index=False)
    return events
