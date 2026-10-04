"""Cloud threat-intelligence support for SentinelShield.

Firebase is deliberately optional: without the Admin SDK or a service-account
file, all methods return safe local values and the scanner continues normally.
"""

from __future__ import annotations

import os
import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import firebase_admin
    from firebase_admin import credentials, firestore
except ImportError:  # Makes Firebase an optional deployment dependency.
    firebase_admin = credentials = firestore = None


class CloudThreatIntelligence:
    """Firestore-backed shared BSSID reputation feed with a timed local cache."""

    COLLECTION = "global_threat_intel"

    def __init__(
        self,
        credential_path: Optional[str] = None,
        sync_interval_seconds: int = 300,
        feed_limit: int = 100,
    ) -> None:
        self.credential_path = Path(
            credential_path or os.getenv("FIREBASE_CREDENTIALS", "firebase_credentials.json")
        )
        self.sync_interval_seconds = max(30, int(sync_interval_seconds))
        self.feed_limit = max(1, int(feed_limit))
        self._db = None
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._last_sync: Optional[datetime] = None
        self._last_error: Optional[str] = None
        self._reputation_hits = 0
        self._lock = threading.RLock()
        self.cache_path = Path(os.getenv("THREAT_INTEL_CACHE", "threat_intelligence_cache.json"))
        self._external_cache = self._load_external_cache()

    def _load_external_cache(self) -> Dict[str, Any]:
        try:
            payload = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def cache_external_result(self, bssid: str, provider: str, result: Dict[str, Any]) -> None:
        """Persist normalized results supplied by VirusTotal, AbuseIPDB, or OpenPhish adapters.

        Network calls are intentionally kept outside the scanner; deployments can
        call this method from their credentialed provider adapter without making
        a Wi-Fi scan depend on a third-party API.
        """
        mac = self.normalize_bssid(bssid)
        if not mac or provider not in {"VirusTotal", "AbuseIPDB", "OpenPhish"}:
            return
        with self._lock:
            item = self._external_cache.setdefault(mac, {})
            item[provider] = {"checked_at": datetime.now(timezone.utc).isoformat(), **result}
            self.cache_path.write_text(json.dumps(self._external_cache, indent=2), encoding="utf-8")

    @staticmethod
    def normalize_bssid(bssid: str) -> str:
        return (bssid or "").strip().upper()

    def _client(self):
        with self._lock:
            if self._db is not None:
                return self._db
            if firebase_admin is None:
                self._last_error = "firebase-admin is not installed"
                return None
            if not self.credential_path.exists():
                self._last_error = f"Firebase credentials not found: {self.credential_path}"
                return None
            try:
                # Reuse an app created elsewhere in the process if present.
                app = firebase_admin.get_app() if firebase_admin._apps else firebase_admin.initialize_app(
                    credentials.Certificate(str(self.credential_path))
                )
                self._db = firestore.client(app=app)
                self._last_error = None
            except Exception as exc:
                self._last_error = str(exc)
                return None
            return self._db

    def sync_feed(self, force: bool = False) -> List[Dict[str, Any]]:
        """Refresh the shared feed no more often than the configured interval."""
        with self._lock:
            due = self._last_sync is None or (time.time() - self._last_sync.timestamp()) >= self.sync_interval_seconds
            if not force and not due:
                return self.shared_feed()
        db = self._client()
        if db is None:
            return self.shared_feed()
        try:
            docs = db.collection(self.COLLECTION).order_by(
                "risk_score", direction=firestore.Query.DESCENDING
            ).limit(self.feed_limit).stream()
            cache = {}
            for document in docs:
                entry = document.to_dict() or {}
                bssid = self.normalize_bssid(entry.get("bssid", document.id))
                if bssid:
                    entry["bssid"] = bssid
                    cache[bssid] = entry
            with self._lock:
                self._cache = cache
                self._last_sync = datetime.now(timezone.utc)
                self._last_error = None
            return self.shared_feed()
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
            return self.shared_feed()

    def lookup(self, bssid: str) -> Dict[str, Any]:
        """Return normalized cloud reputation metadata without raising errors."""
        mac = self.normalize_bssid(bssid)
        self.sync_feed()
        with self._lock:
            entry = self._cache.get(mac)
            if entry:
                self._reputation_hits += 1
                return {
                    "hit": True,
                    "risk_score": float(entry.get("risk_score", 75.0)),
                    "threat_type": entry.get("threat_type", "Unknown"),
                    "detection_time": entry.get("detection_time"),
                }
            external = self._external_cache.get(mac, {})
            if external:
                scores = [float(value.get("risk_score", 0)) for value in external.values() if isinstance(value, dict)]
                return {"hit": bool(max(scores, default=0)), "risk_score": max(scores, default=0), "threat_type": "External provider reputation", "detection_time": None}
        return {"hit": False, "risk_score": 0.0, "threat_type": None, "detection_time": None}

    def upload_rogue_ap(self, ssid: str, bssid: str, risk_score: float, threat_type: str, node_id: str = "NODE_OM007") -> bool:
        """Publish a verified rogue AP. A merge preserves existing observation data."""
        mac = self.normalize_bssid(bssid)
        if not mac or mac == "UNKNOWN":
            return False
        db = self._client()
        if db is None:
            return False
        try:
            now = datetime.now(timezone.utc).isoformat()
            payload = {
                "ssid": ssid or "<hidden>", "bssid": mac,
                "risk_score": round(float(risk_score), 2),
                "threat_type": threat_type or "Rogue Access Point",
                "detection_time": now, "last_seen": now,
                "detected_by_node": node_id,
            }
            db.collection(self.COLLECTION).document(mac).set(payload, merge=True)
            with self._lock:
                self._cache[mac] = {**self._cache.get(mac, {}), **payload}
            return True
        except Exception as exc:
            with self._lock:
                self._last_error = str(exc)
            return False

    def shared_feed(self) -> List[Dict[str, Any]]:
        with self._lock:
            return sorted(self._cache.values(), key=lambda x: float(x.get("risk_score", 0)), reverse=True)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "enabled": self._client() is not None,
                "total_cloud_threats": len(self._cache),
                "reputation_hits": self._reputation_hits,
                "last_sync_time": self._last_sync.isoformat() if self._last_sync else None,
                "last_error": self._last_error,
                "sync_interval_seconds": self.sync_interval_seconds,
                "shared_threat_feed": self.shared_feed(),
                "external_provider_adapters": {
                    "VirusTotal": bool(os.getenv("VIRUSTOTAL_API_KEY")),
                    "AbuseIPDB": bool(os.getenv("ABUSEIPDB_API_KEY")),
                    "OpenPhish": bool(os.getenv("OPENPHISH_API_KEY")),
                },
                "local_external_cache_entries": len(self._external_cache),
            }


_intel = CloudThreatIntelligence()

def get_threat_intelligence() -> CloudThreatIntelligence:
    return _intel

# Compatibility functions for earlier integration drafts.
def check_bssid_reputation(bssid: str):
    result = _intel.lookup(bssid)
    return result["hit"], result["risk_score"], result["threat_type"] or "None"

def upload_rogue_ap(ssid: str, bssid: str, risk_score: float, threat_type: str, node_id: str = "NODE_OM007") -> bool:
    return _intel.upload_rogue_ap(ssid, bssid, risk_score, threat_type, node_id)

def download_threat_feed() -> List[Dict[str, Any]]:
    return _intel.sync_feed(force=True)
