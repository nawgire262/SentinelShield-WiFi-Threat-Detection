"""Generate a compact, dependency-free software inventory (SBOM-style) for releases."""
from __future__ import annotations
import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any


def generate(output: str | Path = "sentinelshield_sbom.json") -> dict[str, Any]:
    root = Path(__file__).resolve().parent
    files = []
    for path in sorted(root.glob("*.py")):
        files.append({"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    payload: dict[str, Any] = {"format": "SentinelShield software inventory v1", "components":
        sorted({dist.metadata["Name"]: dist.version for dist in importlib.metadata.distributions() if dist.metadata.get("Name")}.items()),
        "source_files": files}
    Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload
