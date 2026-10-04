"""Utilities for explicitly saving trusted Wi-Fi fingerprints."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .fingerprint_matcher import DEFAULT_FINGERPRINT_FILE, _bssid_key


def create_fingerprint(
    network: dict[str, Any],
    fingerprints_path: str | Path | None = None,
    *,
    trusted: bool = False,
) -> dict[str, Any]:
    """Save/update one known-good AP fingerprint.

    Call this only after verifying that the network is trusted. The scanner does
    not enroll every newly discovered AP automatically, preventing an unknown or
    rogue AP from silently becoming a trusted baseline.
    """
    if not trusted:
        raise ValueError(
            "Confirm the access point is trusted before saving its fingerprint."
        )

    path = Path(fingerprints_path) if fingerprints_path else DEFAULT_FINGERPRINT_FILE
    bssid = str(network.get("BSSID") or "").strip()
    bssid_key = _bssid_key(bssid)
    if not bssid_key:
        raise ValueError("A valid BSSID is required to save a fingerprint.")

    if path.exists():
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Could not read fingerprint file: {exc}") from exc
    else:
        records = []

    if not isinstance(records, list):
        raise ValueError("The fingerprint file must contain a JSON list.")

    now = datetime.now().isoformat(timespec="seconds")
    entry = {
        "SSID": str(network.get("SSID") or "").strip(),
        "BSSID": bssid,
        "Channel": network.get("Channel", network.get("Frequency")),
        "Signal": network.get("RSSI", network.get("Signal")),
        "Security": str(network.get("Security") or "UNKNOWN").strip(),
        "Updated_At": now,
    }

    replaced = False
    for index, record in enumerate(records):
        if isinstance(record, dict) and _bssid_key(record.get("BSSID")) == bssid_key:
            entry["First_Seen"] = record.get("First_Seen", record.get("Updated_At", now))
            records[index] = entry
            replaced = True
            break
    if not replaced:
        entry["First_Seen"] = now
        records.append(entry)

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_suffix(path.suffix + ".tmp")
    temporary_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    temporary_path.replace(path)
    return entry
