"""Persistent, explicitly trusted-aware Wi-Fi AP fingerprints."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime_config import load_runtime_config

ROOT = Path(__file__).resolve().parent
DEFAULT_PATH = ROOT / "wifi_fingerprint_baseline.json"
_LOCK = threading.RLock()
_VENDOR_OUIS = {
    "00:E0:4C": "Realtek",
    "00:50:F2": "Microsoft",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def canonical_bssid(value: Any) -> str:
    text = str(value or "").upper().replace("-", ":")
    parts = text.split(":")
    if len(parts) != 6 or any(len(part) != 2 or any(ch not in "0123456789ABCDEF" for ch in part) for part in parts):
        return ""
    return ":".join(parts)


def vendor_for_bssid(value: Any) -> str | None:
    bssid = canonical_bssid(value)
    if not bssid:
        return None
    return _VENDOR_OUIS.get(bssid[:8])


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        aps = payload.get("aps", {}) if isinstance(payload, dict) else {}
        return aps if isinstance(aps, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _atomic_save(path: Path, aps: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": 1, "updated_at": utc_now(), "aps": aps}
    fd, temp_name = tempfile.mkstemp(prefix="wifi-baseline-", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


class WiFiFingerprintStore:
    """Track observations while never enrolling an AP as trusted automatically."""

    def __init__(self, path: str | Path = DEFAULT_PATH, config: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        self.config = config or load_runtime_config()
        self.history_limit = int(self.config["fingerprints"]["history_limit"])
        self.established_count = int(self.config["fingerprints"]["established_observations"])

    def all_records(self) -> list[dict[str, Any]]:
        with _LOCK:
            return [dict(record) for record in _load(self.path).values()]

    def get(self, bssid: Any) -> dict[str, Any] | None:
        key = canonical_bssid(bssid)
        if not key:
            return None
        with _LOCK:
            record = _load(self.path).get(key)
            return dict(record) if record else None

    def candidates_for_ssid(self, ssid: str) -> list[dict[str, Any]]:
        target = str(ssid or "").strip().casefold()
        with _LOCK:
            return [dict(item) for item in _load(self.path).values() if str(item.get("ssid", "")).strip().casefold() == target]

    def set_trusted(self, bssid: Any, trusted: bool = True) -> bool:
        key = canonical_bssid(bssid)
        if not key:
            return False
        with _LOCK:
            aps = _load(self.path)
            record = aps.get(key)
            if not record:
                return False
            record["trusted"] = bool(trusted)
            record["confidence"] = "TRUSTED" if trusted else ("ESTABLISHED" if record.get("observation_count", 0) >= self.established_count else "OBSERVED")
            record["updated_at"] = utc_now()
            aps[key] = record
            _atomic_save(self.path, aps)
        return True

    def mark_suspicious(self, bssid: Any, suspicious: bool = True) -> None:
        key = canonical_bssid(bssid)
        if not key:
            return
        with _LOCK:
            aps = _load(self.path)
            if key not in aps:
                return
            record = aps[key]
            record["last_assessment"] = "SUSPICIOUS" if suspicious else "OBSERVED"
            if suspicious and not record.get("trusted"):
                record["confidence"] = "SUSPICIOUS"
            elif not record.get("trusted"):
                record["confidence"] = "ESTABLISHED" if record.get("observation_count", 0) >= self.established_count else "OBSERVED"
            aps[key] = record
            _atomic_save(self.path, aps)

    def observe(self, observation: dict[str, Any]) -> dict[str, Any] | None:
        key = canonical_bssid(observation.get("bssid"))
        if not key:
            return None
        timestamp = str(observation.get("timestamp") or utc_now())
        rssi = observation.get("rssi_dbm")
        channel = observation.get("channel")
        security = str(observation.get("security") or "UNKNOWN").upper()
        ssid = str(observation.get("ssid") or "")
        vendor = observation.get("vendor") or vendor_for_bssid(key)
        with _LOCK:
            aps = _load(self.path)
            record = aps.get(key, {
                "ssid": ssid,
                "bssid": key,
                "vendor": vendor,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "observation_count": 0,
                "confidence": "UNKNOWN",
                "trusted": False,
                "channels": [],
                "security_history": [],
                "channel_history": [],
                "rssi_history": [],
            })
            record.setdefault("channels", [])
            record.setdefault("security_history", [])
            record.setdefault("channel_history", [])
            record.setdefault("rssi_history", [])
            record["ssid"] = ssid or record.get("ssid", "")
            record["vendor"] = vendor or record.get("vendor")
            record["last_seen"] = timestamp
            record["observation_count"] = int(record.get("observation_count", 0)) + 1
            if channel is not None:
                record["channels"] = sorted(set(record["channels"] + [int(channel)]))
                record["channel_history"].append({"timestamp": timestamp, "channel": int(channel)})
                record["channel_history"] = record["channel_history"][-self.history_limit:]
            if security and security != "UNKNOWN":
                record["security_history"] = list(dict.fromkeys(record["security_history"] + [security]))[-self.history_limit:]
            if rssi is not None:
                try:
                    rssi_value = float(rssi)
                    if -127 <= rssi_value <= 0:
                        record["rssi_history"].append({"timestamp": timestamp, "rssi_dbm": rssi_value})
                except (TypeError, ValueError):
                    pass
            record["rssi_history"] = record["rssi_history"][-self.history_limit:]
            values = [float(item["rssi_dbm"]) for item in record["rssi_history"]]
            record["rssi_mean"] = sum(values) / len(values) if values else None
            record["rssi_variance"] = sum((x - record["rssi_mean"]) ** 2 for x in values) / len(values) if values else None
            record["rssi_min"] = min(values) if values else None
            record["rssi_max"] = max(values) if values else None
            record["signal_stability"] = "unknown" if len(values) < 3 else "stable" if (record["rssi_variance"] or 0) <= 25 else "variable"
            record["observation_frequency_per_hour"] = round(record["observation_count"] * 3600 / max(1, _elapsed_seconds(record["first_seen"], timestamp)), 3)
            record["confidence"] = "TRUSTED" if record.get("trusted") else "ESTABLISHED" if record["observation_count"] >= self.established_count else "OBSERVED"
            record["fingerprint_hash"] = fingerprint_hash(record)
            record["updated_at"] = utc_now()
            aps[key] = record
            _atomic_save(self.path, aps)
            return dict(record)


def _elapsed_seconds(start: str, end: str) -> float:
    try:
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        last = datetime.fromisoformat(end.replace("Z", "+00:00"))
        return max(1.0, (last - first).total_seconds())
    except (ValueError, TypeError):
        return 1.0


def fingerprint_hash(record: dict[str, Any]) -> str:
    parts = [
        str(record.get("ssid", "")).casefold(),
        canonical_bssid(record.get("bssid")),
        ",".join(map(str, sorted(set(record.get("channels", []))))),
        ",".join(map(str, sorted(set(record.get("security_history", []))))),
        str(record.get("vendor") or ""),
    ]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
