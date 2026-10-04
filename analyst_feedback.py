"""Append-only analyst verdicts; feedback is never used for automatic trust."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
DEFAULT_PATH = ROOT / "analyst_feedback.jsonl"


def record_feedback(bssid: str, verdict: str, analyst: str = "local", note: str = "", path: Path = DEFAULT_PATH) -> dict[str, Any]:
    verdict = str(verdict).upper()
    if verdict not in {"LEGITIMATE", "ROGUE", "INVESTIGATE"}:
        raise ValueError("verdict must be LEGITIMATE, ROGUE, or INVESTIGATE")
    item = {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "bssid": bssid, "verdict": verdict, "analyst": analyst[:100], "note": note[:1000]}
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, sort_keys=True) + "\n")
    return item
