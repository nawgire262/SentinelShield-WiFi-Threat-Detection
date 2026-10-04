"""Fusion of observations from independent physical Wi-Fi adapters."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev


def fuse_sensor_records(records):
    """Merge per-adapter records by SSID/BSSID while retaining sensor provenance."""
    grouped = {}
    for record in records:
        key = (record["SSID"], record["BSSID"])
        entry = grouped.setdefault(key, {"SSID": key[0], "BSSID": key[1], "RSSI_values": [], "Channels": [], "Securities": [], "Sensor_Observations": []})
        values = [float(value) for value in record.get("RSSI_values", [])]
        entry["RSSI_values"].extend(values)
        entry["Channels"].extend(record.get("Channels", []))
        entry["Securities"].extend(record.get("Securities", []))
        entry["Sensor_Observations"].append({
            "sensor_id": record.get("Sensor_ID", "unknown"),
            "rssi": round(mean(values), 2) if values else 0.0,
            "channel": record.get("Channels", [None])[-1],
        })
    fused = []
    for entry in grouped.values():
        readings = [item["rssi"] for item in entry["Sensor_Observations"]]
        entry["Sensor_IDs"] = [item["sensor_id"] for item in entry["Sensor_Observations"]]
        entry["Sensor_Count"] = len(entry["Sensor_IDs"])
        entry["Sensor_Agreement_dBm"] = round(pstdev(readings), 2) if len(readings) > 1 else 0.0
        fused.append(entry)
    return fused
