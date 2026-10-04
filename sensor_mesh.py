"""Offline inbox aggregation for authorized SentinelShield sensor exports."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wifi_fingerprint import canonical_bssid


def mesh_context(observation: dict[str, Any], inbox_dir: str | Path, max_age_seconds: int = 300) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    bssid = canonical_bssid(observation.get("bssid"))
    sensors: set[str] = set()
    try:
        paths = list(Path(inbox_dir).glob("*.json"))
    except OSError:
        paths = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            stamp = datetime.fromisoformat(str(payload.get("timestamp", "")).replace("Z", "+00:00"))
            if (now - stamp.astimezone(timezone.utc)).total_seconds() > max_age_seconds:
                continue
            for item in payload.get("observations", []):
                if canonical_bssid(item.get("bssid")) == bssid:
                    sensors.add(str(payload.get("sensor_id") or path.stem))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            continue
    return {"available": bool(paths), "sensor_count": len(sensors), "sensors": sorted(sensors),
            "score": 0.0, "reasons": ([f"Observed by {len(sensors)} authorized sensor(s)"] if sensors else [])}
