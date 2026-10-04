"""Compare a live access point with explicitly stored trusted fingerprints."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

DEFAULT_FINGERPRINT_FILE = Path(__file__).resolve().parents[1] / "fingerprints.json"


def _bssid_key(value: Any) -> str:
    return re.sub(r"[^0-9A-F]", "", str(value or "").upper())


def _channel_key(value: Any) -> int | None:
    try:
        number = int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None

    if 2412 <= number <= 2484:
        return 14 if number == 2484 else round((number - 2407) / 5)
    if 5000 <= number <= 5900:
        return round((number - 5000) / 5)
    return number if number > 0 else None


def _security_key(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    if not text or text in {"N/A", "UNKNOWN", "NONE"}:
        return None
    if "OPEN" in text or text == "UNSECURED":
        return "OPEN"
    return "SECURED"


def _valid_signal(value: Any) -> float | None:
    try:
        signal = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(signal) or signal == 0:
        return None
    return signal


def _score(current: dict[str, Any], baseline: dict[str, Any]) -> int:
    points = 40.0  # Candidate selection guarantees the BSSID matches.
    weight = 40.0

    current_ssid = str(current.get("SSID") or "").strip()
    baseline_ssid = str(baseline.get("SSID") or "").strip()
    if current_ssid and baseline_ssid:
        weight += 25
        if current_ssid.casefold() == baseline_ssid.casefold():
            points += 25

    current_channel = _channel_key(current.get("Channel", current.get("Frequency")))
    baseline_channel = _channel_key(baseline.get("Channel", baseline.get("Frequency")))
    if current_channel is not None and baseline_channel is not None:
        weight += 15
        if current_channel == baseline_channel:
            points += 15

    current_security = _security_key(current.get("Security"))
    baseline_security = _security_key(baseline.get("Security"))
    if current_security is not None and baseline_security is not None:
        weight += 15
        if current_security == baseline_security:
            points += 15

    current_signal = _valid_signal(current.get("RSSI", current.get("Signal")))
    baseline_signal = _valid_signal(baseline.get("RSSI", baseline.get("Signal")))
    if current_signal is not None and baseline_signal is not None:
        weight += 5
        delta = abs(current_signal - baseline_signal)
        points += 5 if delta <= 5 else 3 if delta <= 15 else 1 if delta <= 25 else 0

    return round(points / weight * 100)


def compare_fingerprint(
    current_network: dict[str, Any],
    fingerprints_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return similarity for a live AP, or ``None`` when no trusted baseline exists.

    Only records with the same BSSID are compared. A new BSSID is not treated as a
    mismatch because it may be a legitimate additional access point.
    """
    path = Path(fingerprints_path) if fingerprints_path else DEFAULT_FINGERPRINT_FILE
    current_bssid = _bssid_key(current_network.get("BSSID"))
    if not current_bssid or not path.exists():
        return {"similarity": None, "matched": False, "baseline_found": False}

    try:
        records = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        records = []

    if isinstance(records, dict):
        records = records.get("fingerprints", [])
    if not isinstance(records, list):
        records = []

    candidates = [
        record for record in records
        if isinstance(record, dict)
        and _bssid_key(record.get("BSSID")) == current_bssid
    ]
    if not candidates:
        return {"similarity": None, "matched": False, "baseline_found": False}

    best = max(candidates, key=lambda record: _score(current_network, record))
    similarity = _score(current_network, best)
    return {
        "similarity": similarity,
        "matched": similarity >= 90,
        "baseline_found": True,
        "baseline": best,
    }
