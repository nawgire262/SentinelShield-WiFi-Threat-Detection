"""
SentinelShield background scanner adapter.

Connects dashboard.py with the working scanner.py module.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from scanner import scan_wifi


class BackgroundScanner:
    """Background Wi-Fi scanner used by the Streamlit dashboard."""

    def __init__(self) -> None:
        self.lock = threading.Lock()

        self.status: str = "idle"
        self.progress: int = 0
        self.networks: list[dict[str, Any]] = []
        self.error: str | None = None
        self.last_scan_time: str | None = None

        self.scan_thread: threading.Thread | None = None

        self.active_response = False

        self.adaptive_thresholds = {
            "enabled": True,
            "method": "static",
            "status": "Using scanner.py risk thresholds",
        }

    # ============================================================
    # DASHBOARD STATUS
    # ============================================================

    def get_status(self) -> dict[str, Any]:
        with self.lock:
            return {
                "status": self.status,
                "progress": self.progress,
                "networks_found": len(self.networks),
                "error": self.error,
                "last_scan_time": self.last_scan_time,
                "scan_mode": "live",
            }

    # ============================================================
    # DASHBOARD RESULTS
    # ============================================================

    def get_results(self) -> dict[str, Any]:
        with self.lock:
            return {
                "networks": list(self.networks),
                "scan_mode": "live",
                "adaptive_thresholds": self.adaptive_thresholds,
            }

    # ============================================================
    # START SCAN
    # ============================================================

    def start_scan_async(self) -> bool:
        """
        Start a background Wi-Fi scan.

        Returns False if a scan is already running.
        """

        with self.lock:
            if self.status in ("scanning", "analyzing"):
                return False

            self.status = "scanning"
            self.progress = 5
            self.error = None

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            daemon=True,
        )

        self.scan_thread.start()

        return True

    # ============================================================
    # WORKER
    # ============================================================

    def _scan_worker(self) -> None:
        try:
            with self.lock:
                self.status = "scanning"
                self.progress = 10

            # scanner.py performs multiple scan rounds.
            findings = scan_wifi(rounds=3)

            with self.lock:
                self.progress = 85
                self.status = "analyzing"

            converted = []

            for finding in findings:

                ssid = finding.get("ssid", "Unknown")
                risk = float(finding.get("risk", 0))
                reasons = finding.get("reasons", [])
                signals = finding.get("signals", [])

                # Latest RSSI
                rssi = 0

                if signals:
                    try:
                        rssi = float(signals[-1])
                    except (ValueError, TypeError):
                        rssi = 0

                # Threat level
                if risk >= 70:
                    threat_level = "CRITICAL"
                elif risk >= 50:
                    threat_level = "MEDIUM"
                elif risk >= 30:
                    threat_level = "LOW"
                else:
                    threat_level = "SAFE"

                # Convert reason list into readable text
                reason_text = ", ".join(reasons) if reasons else "No major anomaly"

                converted.append(
                    {
                        "SSID": ssid,

                        "BSSID": row.get("bssid", "N/A"),

                        "RSSI": rssi,

                        "Channel": row.get("channel", "N/A"),

                        "Security": row.get("security", "Unknown"),

                        # Dashboard compatibility fields
                        "Threat_Score": risk,
                        "Combined_Risk": risk,
                        "ML_Risk": risk,

                        "Threat_Level": threat_level,

                        "Risk_Factors": reason_text,
                        "Threat_Vectors": reason_text,

                        "Signal_History": str(signals),

                        "Fingerprint_Similarity": (
                            row.get("fingerprint_similarity")
                            if row.get("fingerprint_similarity") is not None
                            else "N/A"
                        ),
                        "Cloud_Risk": "N/A",
                        "BSSID_Reputation": "N/A",

                        "RF_Prediction": "N/A",
                        "KNN_Prediction": "N/A",
                        "Isolation_Forest": "N/A",
                        "Anomaly_Detection": "N/A",
                        "Anomaly_Score": 0,
                    }
                )

            with self.lock:
                self.networks = converted
                self.progress = 100
                self.status = "completed"

                self.last_scan_time = time.strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

        except Exception as exc:

            with self.lock:
                self.error = str(exc)
                self.status = "error"
                self.progress = 0

    # ============================================================
    # ADAPTIVE THRESHOLDS
    # ============================================================

    def get_adaptive_threshold_info(self) -> dict[str, Any]:
        return self.adaptive_thresholds

    def reset_adaptive_thresholds(self) -> None:
        self.adaptive_thresholds = {
            "enabled": True,
            "method": "static",
            "status": "Baseline reset",
        }

    # ============================================================
    # ACTIVE RESPONSE
    # ============================================================

    def set_active_response(self, enabled: bool) -> None:
        self.active_response = bool(enabled)


# ================================================================
# SINGLETON SCANNER
# ================================================================

_scanner: BackgroundScanner | None = None


def get_scanner() -> BackgroundScanner:
    """
    Return the single scanner instance used by Streamlit.
    """

    global _scanner

    if _scanner is None:
        _scanner = BackgroundScanner()

    return _scanner