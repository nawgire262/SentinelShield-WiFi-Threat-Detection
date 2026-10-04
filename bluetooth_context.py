"""Optional BLE presence context. BLE is never treated as a Wi-Fi scanner."""
from __future__ import annotations

import asyncio
from typing import Any


class BluetoothContext:
    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    async def collect_async(self, duration_seconds: float = 2.0) -> dict[str, Any]:
        if not self.enabled:
            return {"available": False, "enabled": False, "device_count": 0, "devices": [], "score": 0.0, "reasons": []}
        try:
            from bleak import BleakScanner
        except ImportError:
            return {"available": False, "enabled": True, "device_count": 0, "devices": [], "score": 0.0, "reasons": ["BLE context unavailable: optional bleak package is not installed"]}
        try:
            found = await BleakScanner.discover(timeout=max(0.5, min(10.0, duration_seconds)), return_adv=True)
            devices = []
            for address, item in found.items():
                device, advertisement = item
                devices.append({
                    "address": address,
                    "name": device.name or advertisement.local_name,
                    "rssi_dbm": getattr(advertisement, "rssi", None),
                    "service_uuids": list(getattr(advertisement, "service_uuids", []) or []),
                })
            return {"available": True, "enabled": True, "device_count": len(devices), "devices": devices, "score": 0.0, "reasons": ["BLE observations provide proximity context only; they are not attributed to Wi-Fi APs"] if devices else []}
        except Exception as exc:
            return {"available": False, "enabled": True, "device_count": 0, "devices": [], "score": 0.0, "reasons": [f"BLE context scan failed: {type(exc).__name__}: {exc}"]}

    def collect(self, duration_seconds: float = 2.0) -> dict[str, Any]:
        try:
            return asyncio.run(self.collect_async(duration_seconds))
        except RuntimeError:
            # An existing event loop may be owned by an embedding host.
            return {"available": False, "enabled": self.enabled, "device_count": 0, "devices": [], "score": 0.0, "reasons": ["BLE context cannot start a nested event loop"]}
