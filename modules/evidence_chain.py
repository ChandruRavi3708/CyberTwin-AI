"""Lightweight SHA-256 tamper-evident evidence chains for security events."""

from __future__ import annotations

from datetime import date, datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd


GENESIS_HASH = "0" * 64


def _json_safe(value: Any) -> Any:
    """Convert dataframe and NumPy values to stable, JSON-safe primitives."""
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (pd.Timestamp, datetime, date)):
        return value.isoformat()
    if isinstance(value, np.generic):
        return _json_safe(value.item())
    if isinstance(value, float) and not np.isfinite(value):
        return None
    return value


def _record_payload(index: int, timestamp: str, event_data: Mapping[str, Any], previous_hash: str) -> dict[str, Any]:
    return {"index": index, "timestamp": timestamp, "event_data": _json_safe(event_data), "previous_hash": previous_hash}


def _hash_payload(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(canonical.encode("utf-8")).hexdigest()


def create_evidence(
    event_data: Mapping[str, Any] | pd.Series,
    chain: Sequence[Mapping[str, Any]] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Create the next signed evidence record without mutating the chain."""
    records = list(chain or [])
    data = event_data.to_dict() if isinstance(event_data, pd.Series) else dict(event_data)
    record_timestamp = timestamp or str(data.get("timestamp") or datetime.now(timezone.utc).isoformat())
    previous_hash = str(records[-1].get("current_hash", GENESIS_HASH)) if records else GENESIS_HASH
    payload = _record_payload(len(records), record_timestamp, data, previous_hash)
    current_hash = _hash_payload(payload)
    return {**payload, "current_hash": current_hash, "event_hash": current_hash}


def build_evidence_chain(events: pd.DataFrame | Sequence[Mapping[str, Any]], critical_only: bool = False) -> list[dict[str, Any]]:
    """Build an in-memory chain from event records, optionally only Critical ones."""
    if isinstance(events, pd.DataFrame):
        records: Sequence[Mapping[str, Any]] = events.to_dict("records")
    else:
        records = events
    chain: list[dict[str, Any]] = []
    for event in records:
        if critical_only and str(event.get("ai_risk_level", event.get("risk_level", ""))).lower() != "critical":
            continue
        chain.append(create_evidence(event, chain))
    return chain


def verify_evidence_chain_details(chain: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Return integrity status and the first invalid record, if any."""
    previous_hash = GENESIS_HASH
    for expected_index, record in enumerate(chain):
        try:
            payload = _record_payload(
                int(record["index"]), str(record["timestamp"]), dict(record["event_data"]), str(record["previous_hash"])
            )
        except (KeyError, TypeError, ValueError):
            return {"is_valid": False, "invalid_index": expected_index, "reason": "Record structure is invalid."}
        if payload["index"] != expected_index:
            return {"is_valid": False, "invalid_index": expected_index, "reason": "Record index is out of sequence."}
        if payload["previous_hash"] != previous_hash:
            return {"is_valid": False, "invalid_index": expected_index, "reason": "Previous-hash link is broken."}
        calculated_hash = _hash_payload(payload)
        if record.get("current_hash") != calculated_hash or record.get("event_hash") != calculated_hash:
            return {"is_valid": False, "invalid_index": expected_index, "reason": "Evidence payload or hash was modified."}
        previous_hash = calculated_hash
    return {"is_valid": True, "invalid_index": None, "reason": "Chain integrity verified."}


def verify_evidence_chain(chain: Sequence[Mapping[str, Any]]) -> bool:
    """Return True only when every record and hash link is intact."""
    return bool(verify_evidence_chain_details(chain)["is_valid"])


def load_evidence_chain(path: str | Path) -> list[dict[str, Any]]:
    """Load a JSON chain, returning an empty chain when no file exists yet."""
    file_path = Path(path)
    if not file_path.exists():
        return []
    loaded = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, list):
        raise ValueError("Evidence chain file must contain a JSON list.")
    return loaded


def save_evidence_chain(chain: Sequence[Mapping[str, Any]], path: str | Path) -> None:
    """Persist an evidence chain atomically after validating its integrity."""
    if not verify_evidence_chain(chain):
        raise ValueError("Refusing to save an evidence chain that failed integrity verification.")
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = file_path.with_suffix(f"{file_path.suffix}.tmp")
    temporary_path.write_text(json.dumps(_json_safe(list(chain)), indent=2, ensure_ascii=False), encoding="utf-8")
    temporary_path.replace(file_path)


def get_evidence_summary(chain: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Provide record count, integrity state, and latest hash for a dashboard."""
    details = verify_evidence_chain_details(chain)
    return {
        "evidence_records": len(chain),
        "chain_integrity": "VALID" if details["is_valid"] else "INVALID",
        "latest_hash": chain[-1].get("current_hash", GENESIS_HASH) if chain else GENESIS_HASH,
        **details,
    }
