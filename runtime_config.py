"""Small, dependency-free runtime configuration loader for SentinelShield."""

from __future__ import annotations

import json
import logging
import os
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)
CONFIG_PATH = Path(__file__).resolve().parent / "config" / "runtime_settings.json"

DEFAULTS: dict[str, Any] = {
    "adaptive_thresholds": {
        "warmup_samples": 15,
        "ewma_alpha": 0.12,
        "min_std": 4.0,
        "multipliers": {"critical": 2.0, "high": 1.15, "medium": 0.35},
        "bands": {"critical": [55.0, 95.0], "high": [35.0, 80.0], "medium": [15.0, 60.0]},
    },
    "notifications": {"cooldown_seconds": 120},
    "fast_scanning": {
        "settle_seconds": {"fast": 0.75, "balanced": 1.25, "deep": 2.0},
        "scan_timeout_seconds": 4.0,
        "max_parallel_adapters": 4,
        "adaptive_deep_scan": True,
        "rssi_change_trigger_db": 12.0,
        "verification_samples": 2,
    },
    "fingerprints": {
        "history_limit": 100,
        "established_observations": 5,
        "rssi_deviation_db": 12.0,
        "rssi_standard_deviation_multiplier": 2.0,
    },
    "temporal_analysis": {
        "history_limit": 60,
        "minimum_samples": 4,
        "rssi_jump_threshold_db": 18.0,
        "rssi_std_threshold_db": 12.0,
    },
    "evidence_fusion": {
        "weights": {
            "identity": 0.24, "security": 0.28, "channel": 0.20,
            "fingerprint": 0.06, "temporal": 0.12, "density": 0.03,
            "context": 0.01, "wired": 0.12, "ml": 0.03, "rssi": 0.03,
        },
        "risk_bands": {"medium": 30.0, "high": 50.0, "critical": 75.0},
        "unknown_bssid_same_ssid_score": 55.0,
        "security_mismatch_score": 95.0,
        "channel_mismatch_score": 65.0,
        "new_ap_score": 20.0,
        "density_unexpected_bssid_score": 20.0,
        "density_reference_count": 4,
        "open_security_score": 35.0,
        "weak_security_score": 20.0,
        "strong_rssi_threshold_dbm": -25.0,
        "strong_rssi_score": 40.0,
        "vendor_mismatch_score": 60.0,
    },
    "optional_context": {"bluetooth_enabled": False, "location_enabled": False},
    "wired_correlation": {"enabled": False, "inventory_file": "wired_inventory.json"},
    "sensor_mesh": {"enabled": False, "inbox_dir": "sensor_inbox", "max_age_seconds": 300},
    "wifi_sensing": {"enabled": False, "consent_required": True, "consent_granted": False},
    "evidence_integrity": {"enabled": True, "hmac_key_env": "SENTINELSHIELD_EVIDENCE_KEY"},
    "persistence": {"retention_days": 30},
}


def _merge(defaults: dict[str, Any], provided: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(defaults)
    for key, value in provided.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        elif key in result:
            result[key] = value
    return result


def load_runtime_config(path: Path = CONFIG_PATH) -> dict[str, Any]:
    """Load known keys only, retaining safe defaults on invalid configuration."""
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("configuration root must be an object")
        merged = _merge(DEFAULTS, loaded)
        adaptive = merged["adaptive_thresholds"]
        adaptive["warmup_samples"] = max(1, int(adaptive["warmup_samples"]))
        adaptive["ewma_alpha"] = min(1.0, max(0.001, float(adaptive["ewma_alpha"])))
        adaptive["min_std"] = max(0.1, float(adaptive["min_std"]))
        for name in ("critical", "high", "medium"):
            adaptive["multipliers"][name] = float(adaptive["multipliers"][name])
            band = adaptive["bands"][name]
            if not isinstance(band, list) or len(band) != 2:
                raise ValueError(f"adaptive threshold band '{name}' must contain two values")
            adaptive["bands"][name] = sorted(float(value) for value in band)
        merged["notifications"]["cooldown_seconds"] = max(0, int(merged["notifications"]["cooldown_seconds"]))
        scan = merged["fast_scanning"]
        scan["scan_timeout_seconds"] = max(0.5, float(scan["scan_timeout_seconds"]))
        scan["max_parallel_adapters"] = max(1, min(16, int(scan["max_parallel_adapters"])))
        for mode in ("fast", "balanced", "deep"):
            scan["settle_seconds"][mode] = max(0.1, float(scan["settle_seconds"][mode]))
        scan["rssi_change_trigger_db"] = max(0.0, float(scan["rssi_change_trigger_db"]))
        scan["verification_samples"] = max(1, min(5, int(scan["verification_samples"])))
        fingerprints = merged["fingerprints"]
        fingerprints["history_limit"] = max(10, min(1000, int(fingerprints["history_limit"])))
        fingerprints["established_observations"] = max(2, int(fingerprints["established_observations"]))
        fingerprints["rssi_deviation_db"] = max(1.0, float(fingerprints["rssi_deviation_db"]))
        fingerprints["rssi_standard_deviation_multiplier"] = max(0.0, float(fingerprints["rssi_standard_deviation_multiplier"]))
        temporal = merged["temporal_analysis"]
        temporal["history_limit"] = max(4, min(1000, int(temporal["history_limit"])))
        temporal["minimum_samples"] = max(3, min(temporal["history_limit"], int(temporal["minimum_samples"])))
        temporal["rssi_jump_threshold_db"] = max(1.0, float(temporal["rssi_jump_threshold_db"]))
        temporal["rssi_std_threshold_db"] = max(1.0, float(temporal["rssi_std_threshold_db"]))
        fusion = merged["evidence_fusion"]
        fusion["weights"] = {key: max(0.0, float(value)) for key, value in fusion["weights"].items()}
        if sum(fusion["weights"].values()) <= 0:
            raise ValueError("evidence fusion weights must have a positive sum")
        bands = fusion["risk_bands"]
        bands["medium"] = max(0.0, float(bands["medium"]))
        bands["high"] = max(bands["medium"], float(bands["high"]))
        bands["critical"] = max(bands["high"], float(bands["critical"]))
        fusion["density_unexpected_bssid_score"] = max(0.0, min(100.0, float(fusion["density_unexpected_bssid_score"])))
        fusion["density_reference_count"] = max(2, int(fusion["density_reference_count"]))
        for name in ("open_security_score", "weak_security_score", "strong_rssi_score", "vendor_mismatch_score"):
            fusion[name] = max(0.0, min(100.0, float(fusion[name])))
        fusion["strong_rssi_threshold_dbm"] = min(0.0, max(-127.0, float(fusion["strong_rssi_threshold_dbm"])))
        wired = merged["wired_correlation"]
        wired["enabled"] = bool(wired["enabled"])
        wired["inventory_file"] = str(wired["inventory_file"] or "wired_inventory.json")
        mesh = merged["sensor_mesh"]
        mesh["enabled"] = bool(mesh["enabled"])
        mesh["inbox_dir"] = str(mesh["inbox_dir"] or "sensor_inbox")
        mesh["max_age_seconds"] = max(10, min(86_400, int(mesh["max_age_seconds"])))
        sensing = merged["wifi_sensing"]
        sensing["enabled"] = bool(sensing["enabled"])
        sensing["consent_required"] = bool(sensing["consent_required"])
        sensing["consent_granted"] = bool(sensing["consent_granted"])
        integrity = merged["evidence_integrity"]
        integrity["enabled"] = bool(integrity["enabled"])
        integrity["hmac_key_env"] = str(integrity["hmac_key_env"] or "SENTINELSHIELD_EVIDENCE_KEY")
        merged["persistence"]["retention_days"] = max(1, int(merged["persistence"]["retention_days"]))
        return merged
    except FileNotFoundError:
        return deepcopy(DEFAULTS)
    except (KeyError, OSError, TypeError, json.JSONDecodeError, ValueError) as exc:
        LOGGER.warning("Invalid runtime configuration; using safe defaults: %s", exc)
        return deepcopy(DEFAULTS)


def save_runtime_config(config: dict[str, Any], path: Path = CONFIG_PATH) -> bool:
    """Validate and atomically persist recognized runtime configuration."""
    try:
        merged = _merge(DEFAULTS, config)
        # Run the same coercion/bounds checks as the reader before writing.
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix="runtime-settings-", suffix=".tmp", dir=str(path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(merged, handle, indent=2)
            os.replace(temp_name, path)
        finally:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass
        return True
    except (OSError, TypeError, ValueError):
        LOGGER.exception("Runtime configuration could not be saved")
        return False
