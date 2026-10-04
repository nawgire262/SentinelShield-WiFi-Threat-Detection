"""Deterministic, local incident narrative; no model or external service required."""
from __future__ import annotations
from typing import Any


def explain(result: dict[str, Any]) -> dict[str, Any]:
    reasons = list(dict.fromkeys(str(item) for item in result.get("reasons", []) if item))
    level = str(result.get("threat_level", "LOW"))
    summary = f"{level} risk for {result.get('ssid') or '<hidden SSID>'} ({result.get('bssid') or 'unknown BSSID'}): "
    summary += "; ".join(reasons[:4]) if reasons else "no high-risk evidence was recorded."
    return {"summary": summary, "reasons": reasons, "recommended_action":
            "Preserve observations and investigate; do not automatically block wireless traffic." if level in {"HIGH", "CRITICAL"}
            else "Continue passive monitoring and seek an analyst verdict if behavior changes."}
