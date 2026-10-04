"""Optional Windows location context; GPS/location is never needed for Wi-Fi scans."""
from __future__ import annotations

import asyncio
from typing import Any


class LocationContext:
    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    async def collect_async(self) -> dict[str, Any]:
        if not self.enabled:
            return {"available": False, "enabled": False, "position": None, "movement": "unknown", "score": 0.0, "reasons": []}
        try:
            from winrt.windows.devices.geolocation import Geolocator
        except ImportError:
            return {"available": False, "enabled": True, "position": None, "movement": "unknown", "score": 0.0, "reasons": ["Location context unavailable: Windows geolocation APIs are not installed"]}
        try:
            locator = Geolocator()
            position = await locator.get_geoposition_async()
            coord = position.coordinate.point.position
            return {
                "available": True,
                "enabled": True,
                "position": {"latitude": float(coord.latitude), "longitude": float(coord.longitude), "accuracy_m": float(position.coordinate.accuracy)},
                "movement": "unknown",
                "score": 0.0,
                "reasons": ["Approximate location is contextual only and is not direct Wi-Fi evidence"],
            }
        except Exception as exc:
            return {"available": False, "enabled": True, "position": None, "movement": "unknown", "score": 0.0, "reasons": [f"Location unavailable or permission denied: {type(exc).__name__}: {exc}"]}

    def collect(self) -> dict[str, Any]:
        try:
            return asyncio.run(self.collect_async())
        except RuntimeError:
            return {"available": False, "enabled": self.enabled, "position": None, "movement": "unknown", "score": 0.0, "reasons": ["Location context cannot start a nested event loop"]}
