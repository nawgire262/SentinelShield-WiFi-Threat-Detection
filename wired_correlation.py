"""Read-only correlation with an explicitly exported wired inventory.

The module never probes switches or endpoints.  Administrators may export an
authorized DHCP/ARP/NAC inventory as JSON, keeping deployment credentials out
of SentinelShield and making the evidence source auditable.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from wifi_fingerprint import canonical_bssid


def correlate(observation: dict[str, Any], inventory_file: str | Path) -> dict[str, Any]:
    path = Path(inventory_file)
    empty = {"available": False, "matched": False, "score": 0.0, "reasons": []}
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(records, list):
            raise ValueError("inventory root must be a list")
    except (OSError, ValueError, json.JSONDecodeError):
        return {**empty, "reasons": ["Authorized wired inventory is unavailable"]}
    bssid = canonical_bssid(observation.get("bssid"))
    ssid = str(observation.get("ssid") or "").casefold()
    for record in records:
        if not isinstance(record, dict):
            continue
        record_bssid = canonical_bssid(record.get("bssid") or record.get("mac"))
        record_ssid = str(record.get("ssid") or "").casefold()
        if bssid and bssid == record_bssid or ssid and record_ssid == ssid:
            allowed = bool(record.get("authorized", False))
            return {
                "available": True, "matched": True, "authorized": allowed,
                "score": 0.0 if allowed else 70.0,
                "reasons": (["AP matches authorized wired inventory"] if allowed
                            else ["AP is present in wired inventory but is not authorized"]),
                "source": str(path),
            }
    return {"available": True, "matched": False, "authorized": False, "score": 0.0,
            "reasons": ["No wired-inventory match; this alone is not proof of a rogue AP"], "source": str(path)}
