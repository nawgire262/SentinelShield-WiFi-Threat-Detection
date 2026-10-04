"""Windows-compatible, per-radio Wi-Fi discovery and fast single-pass scanning.

PyWiFi/Windows owns radio scans. Independent adapters may be scanned concurrently,
but each physical adapter is serialized by a stable adapter-ID lock.
"""
from __future__ import annotations

import csv
import logging
import os
import re
import subprocess
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from runtime_config import load_runtime_config

LOGGER = logging.getLogger(__name__)

try:
    import pywifi
except ImportError:
    pywifi = None

_STATE_NAMES = {0: "disconnected", 1: "scanning", 2: "inactive", 3: "connecting", 4: "connected"}
_LOCKS_GUARD = threading.Lock()
_ADAPTER_LOCKS: dict[str, threading.Lock] = {}


def _value(obj: Any, name: str, default: Any = None) -> Any:
    value = getattr(obj, name, default)
    try:
        return value() if callable(value) else value
    except Exception:
        return default


def _normalise_mac(value: Any) -> str:
    text = str(value or "").strip().upper().replace("-", ":")
    octets = re.findall(r"[0-9A-F]{2}", text)
    return ":".join(octets[:6]) if len(octets) >= 6 else ""


def _windows_adapter_macs() -> dict[str, str]:
    """Best-effort mapping of Windows connection names to physical addresses."""
    if os.name != "nt":
        return {}
    try:
        result = subprocess.run(
            ["getmac", "/fo", "csv", "/v"], capture_output=True, text=True,
            timeout=3, check=False,
        )
        rows = csv.DictReader((result.stdout or "").splitlines())
        mapped: dict[str, str] = {}
        for row in rows:
            name = (row.get("Connection Name") or "").strip().casefold()
            address = _normalise_mac(row.get("Physical Address"))
            if name and address:
                mapped[name] = address
        return mapped
    except (OSError, subprocess.TimeoutExpired, csv.Error):
        return {}


def frequency_to_mhz(value: Any) -> float | None:
    """Normalize PyWiFi frequency values (MHz, kHz, or Hz) to MHz."""
    try:
        frequency = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 2000 <= frequency <= 7_200_000_000:
        return None
    if frequency > 1_000_000_000:
        frequency /= 1_000_000
    elif frequency > 100_000:
        frequency /= 1000
    return frequency if 2000 <= frequency <= 7200 else None


def frequency_to_channel(value: Any) -> int | None:
    frequency = frequency_to_mhz(value)
    if frequency is None:
        return None
    if 2412 <= frequency <= 2472:
        return int(round((frequency - 2407) / 5))
    if abs(frequency - 2484) <= 1:
        return 14
    if 5000 <= frequency <= 5895:
        return int(round((frequency - 5000) / 5))
    if 5955 <= frequency <= 7115:
        return int(round((frequency - 5950) / 5))
    if abs(frequency - 5935) <= 1:
        return 2
    return None


def _security_name(network: Any) -> str:
    akm = _value(network, "akm", None)
    if not akm:
        return "OPEN"
    text = " ".join(str(value) for value in akm).upper()
    if "SAE" in text or "WPA3" in text:
        return "WPA3"
    if "WPA" in text:
        return "WPA/WPA2"
    return "SECURED"


def normalize_observation(network: Any, adapter: "RadioAdapter", observed_at: str | None = None) -> dict[str, Any]:
    raw_frequency = _value(network, "freq", None)
    frequency_mhz = frequency_to_mhz(raw_frequency)
    channel_raw = _value(network, "channel", None)
    try:
        channel = int(channel_raw) if channel_raw not in (None, "", 0, "0") else frequency_to_channel(raw_frequency)
    except (TypeError, ValueError):
        channel = frequency_to_channel(raw_frequency)
    ssid = str(_value(network, "ssid", "") or "").strip()
    bssid = _normalise_mac(_value(network, "bssid", ""))
    rssi_raw = _value(network, "signal", None)
    try:
        rssi = float(rssi_raw)
    except (TypeError, ValueError, OverflowError):
        rssi = None
    if rssi is not None and not -127 <= rssi <= 0:
        # Some PyWiFi backends return percentage instead of dBm. Preserve the
        # measurement but make its unit explicit rather than mislabel it RSSI.
        rssi = None
    now = observed_at or datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    return {
        "timestamp": now,
        "adapter_id": adapter.adapter_id,
        "adapter_name": adapter.name,
        "adapter_mac": adapter.mac_address or None,
        "ssid": ssid,
        "bssid": bssid,
        "rssi_dbm": rssi,
        "channel": channel,
        "frequency_mhz": round(frequency_mhz, 2) if frequency_mhz is not None else None,
        "security": _security_name(network),
        "encryption": _security_name(network),
        "vendor": None,
        # Opportunistic Wi-Fi 6E/7 fields.  Classic PyWiFi backends return
        # None, while richer Windows backends can populate them safely.
        "wireless_standard": _value(network, "wireless_standard", None) or _value(network, "standard", None),
        "channel_width_mhz": _value(network, "channel_width", None),
        "pmf_capable": _value(network, "pmf_capable", None),
        "mlo_link_id": _value(network, "mlo_link_id", None),
        "bss_color": _value(network, "bss_color", None),
        "scan_duration_ms": None,
    }


@dataclass
class RadioAdapter:
    adapter_id: str
    name: str
    description: str
    mac_address: str | None
    interface_state: str
    capabilities: list[str]
    backend: str
    interface: Any = field(repr=False, compare=False)

    def public_dict(self) -> dict[str, Any]:
        # Do not dataclasses.asdict() here: it deep-copies PyWiFi/COM handles.
        return {
            "adapter_id": self.adapter_id,
            "name": self.name,
            "description": self.description,
            "mac_address": self.mac_address,
            "interface_state": self.interface_state,
            "capabilities": list(self.capabilities),
            "backend": self.backend,
        }


@dataclass
class AdapterScan:
    adapter: dict[str, Any]
    observations: list[dict[str, Any]]
    started_at: str
    completed_at: str
    scan_duration_ms: float
    error: str | None = None


@dataclass
class ScanBatch:
    scan_id: str
    started_at: str
    completed_at: str
    scan_duration_ms: float
    processing_time_ms: float
    scan_mode: str
    adapters: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    errors: list[str]
    adapter_scans: list[AdapterScan]

    @property
    def unique_bssids(self) -> int:
        return len({item["bssid"] for item in self.observations if item.get("bssid")})

    def public_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "scan_duration_ms": self.scan_duration_ms,
            "processing_time_ms": self.processing_time_ms,
            "detection_latency_ms": self.scan_duration_ms + self.processing_time_ms,
            "scan_mode": self.scan_mode,
            "adapter_mode": "multi-adapter" if len(self.adapters) > 1 else "single-adapter" if self.adapters else "unavailable",
            "adapter_count": len(self.adapters),
            "aps_discovered": len(self.observations),
            "unique_bssids": self.unique_bssids,
            "adapters": self.adapters,
            "observations": self.observations,
            "errors": self.errors,
        }


class FastWiFiScanner:
    """Discovers Wi-Fi radios and scans each adapter at most once concurrently."""

    def __init__(
        self,
        interface_provider: Callable[[], Iterable[Any]] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.interface_provider = interface_provider or self._pywifi_interfaces
        self.sleep = sleep
        self.config = config or load_runtime_config()

    @staticmethod
    def _pywifi_interfaces() -> Iterable[Any]:
        if pywifi is None:
            return []
        return pywifi.PyWiFi().interfaces()

    def discover_adapters(self) -> list[RadioAdapter]:
        macs = _windows_adapter_macs()
        adapters: list[RadioAdapter] = []
        try:
            interfaces = list(self.interface_provider() or [])
        except Exception as exc:
            LOGGER.warning("Wi-Fi interface enumeration failed: %s", exc)
            return []
        for interface in interfaces:
            name_value = _value(interface, "name", "")
            desc_value = _value(interface, "description", "")
            name = str(name_value or desc_value or "Wi-Fi adapter").strip()
            description = str(desc_value or name).strip()
            lowered = f"{name} {description}".casefold()
            if any(marker in lowered for marker in ("wi-fi direct", "wifi direct", "virtual", "bluetooth", "ethernet", "loopback", "vpn")):
                continue
            status = _value(interface, "status", None)
            try:
                state = _STATE_NAMES.get(int(status), f"unknown:{status}")
            except (TypeError, ValueError):
                state = "unknown"
            capabilities = [method for method in ("scan", "scan_results") if callable(getattr(interface, method, None))]
            adapter_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{name.casefold()}|{description.casefold()}"))
            adapters.append(RadioAdapter(
                adapter_id=adapter_id,
                name=name,
                description=description,
                mac_address=macs.get(name.casefold()),
                interface_state=state,
                capabilities=capabilities,
                backend="pywifi",
                interface=interface,
            ))
        return adapters

    @staticmethod
    def _adapter_lock(adapter_id: str) -> threading.Lock:
        with _LOCKS_GUARD:
            return _ADAPTER_LOCKS.setdefault(adapter_id, threading.Lock())

    def _scan_one(self, adapter: RadioAdapter, mode: str) -> AdapterScan:
        started_clock = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        observations: list[dict[str, Any]] = []
        error = None
        settle = self.config["fast_scanning"]["settle_seconds"].get(mode, self.config["fast_scanning"]["settle_seconds"]["balanced"])
        timeout = self.config["fast_scanning"]["scan_timeout_seconds"]
        try:
            with self._adapter_lock(adapter.adapter_id):
                adapter.interface.scan()
                self.sleep(min(settle, timeout))
                results = list(adapter.interface.scan_results() or [])
            observed_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            observations = [normalize_observation(item, adapter, observed_at) for item in results]
        except Exception as exc:
            error = f"{adapter.name}: {type(exc).__name__}: {exc}"
            LOGGER.warning("Wi-Fi scan failed for %s: %s", adapter.name, exc)
        duration_ms = (time.perf_counter() - started_clock) * 1000.0
        ended_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        for observation in observations:
            observation["scan_duration_ms"] = round(duration_ms, 2)
        return AdapterScan(adapter.public_dict(), observations, started_at, ended_at, round(duration_ms, 2), error)

    def scan(self, mode: str = "balanced", cancel_event: threading.Event | None = None, adapters: list[RadioAdapter] | None = None) -> ScanBatch:
        mode = mode.casefold()
        if mode not in {"fast", "balanced", "deep"}:
            raise ValueError("mode must be fast, balanced, or deep")
        scan_clock = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        adapters = adapters if adapters is not None else self.discover_adapters()
        errors: list[str] = []
        completed: list[AdapterScan] = []
        if not adapters:
            errors.append("No supported PyWiFi wireless adapters were detected.")
        elif cancel_event is not None and cancel_event.is_set():
            errors.append("Scan cancelled before radio work started.")
        else:
            workers = max(1, min(len(adapters), int(self.config["fast_scanning"]["max_parallel_adapters"])))
            if workers == 1:
                completed = [self._scan_one(adapters[0], mode)]
            else:
                with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="wifi-radio") as pool:
                    futures = {pool.submit(self._scan_one, adapter, mode): adapter for adapter in adapters}
                    for future in as_completed(futures):
                        if cancel_event is not None and cancel_event.is_set():
                            # In-flight driver calls cannot be forcibly interrupted safely.
                            errors.append("Cancellation requested; in-flight adapter scans were allowed to finish safely.")
                        try:
                            completed.append(future.result())
                        except Exception as exc:
                            errors.append(f"{futures[future].name}: {exc}")
        observations = [item for result in completed for item in result.observations]
        errors.extend(result.error for result in completed if result.error)
        processing_start = time.perf_counter()
        # Merge repeated views of the same physical BSSID, retaining strongest RSSI
        # but preserving all adapter IDs as provenance.
        merged: dict[tuple[str, str], dict[str, Any]] = {}
        for item in observations:
            key = (item["bssid"], item["ssid"])
            if key not in merged:
                merged[key] = dict(item)
                merged[key]["adapter_ids"] = [item["adapter_id"]]
            else:
                previous = merged[key]
                if item.get("rssi_dbm") is not None and (previous.get("rssi_dbm") is None or item["rssi_dbm"] > previous["rssi_dbm"]):
                    for field_name in ("rssi_dbm", "channel", "frequency_mhz", "security", "timestamp"):
                        previous[field_name] = item.get(field_name)
                if item["adapter_id"] not in previous["adapter_ids"]:
                    previous["adapter_ids"].append(item["adapter_id"])
        observations = list(merged.values())
        processing_ms = (time.perf_counter() - processing_start) * 1000.0
        elapsed_ms = (time.perf_counter() - scan_clock) * 1000.0
        ended = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
        return ScanBatch(
            scan_id=str(uuid.uuid4()), started_at=started_at, completed_at=ended,
            scan_duration_ms=round(elapsed_ms, 2), processing_time_ms=round(processing_ms, 2),
            scan_mode=mode, adapters=[adapter.public_dict() for adapter in adapters],
            observations=observations, errors=errors, adapter_scans=completed,
        )


def discover_wifi_adapters() -> list[RadioAdapter]:
    return FastWiFiScanner().discover_adapters()


def scan_wifi_fast(mode: str = "balanced") -> ScanBatch:
    return FastWiFiScanner().scan(mode=mode)
