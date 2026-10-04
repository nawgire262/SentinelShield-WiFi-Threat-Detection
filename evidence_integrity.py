"""Crypto-agile integrity receipts for local evidence, with safe hash-only fallback."""
from __future__ import annotations
import hashlib
import hmac
import json
import os
from typing import Any


def receipt(payload: dict[str, Any], key_env: str = "SENTINELSHIELD_EVIDENCE_KEY") -> dict[str, str]:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    secret = os.environ.get(key_env)
    if secret:
        return {"algorithm": "HMAC-SHA-256", "digest": digest,
                "signature": hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()}
    return {"algorithm": "SHA-256", "digest": digest, "signature": ""}
