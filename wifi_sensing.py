"""Opt-in storage for consented sensing metrics, never identity tracking or RF capture."""
from __future__ import annotations
from typing import Any


def summarize(metrics: list[dict[str, Any]], enabled: bool, consent: bool) -> dict[str, Any]:
    if not enabled or not consent:
        return {"enabled": False, "available": False, "score": 0.0, "reasons": []}
    usable = [row for row in metrics if isinstance(row, dict) and isinstance(row.get("variance"), (int, float))]
    return {"enabled": True, "available": bool(usable), "samples": len(usable), "score": 0.0,
            "reasons": ["Consent-based sensing is contextual only; it is not used to identify people or AP intent"]}
