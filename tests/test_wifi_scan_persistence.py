import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database_manager


class WiFiScanPersistenceTests(unittest.TestCase):
    def test_enriched_scan_and_observations_are_persisted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "test.db"
            payload = {
                "scan_id": "scan-test-001",
                "started_at": "2026-10-04T10:00:00+00:00",
                "completed_at": "2026-10-04T10:00:01+00:00",
                "scan_duration_ms": 400.0,
                "processing_time_ms": 80.0,
                "detection_latency_ms": 480.0,
                "scan_mode": "fast",
                "adapter_count": 1,
                "aps_discovered": 1,
                "unique_bssids": 1,
                "results": [{
                    "timestamp": "2026-10-04T10:00:00+00:00",
                    "adapter_id": "radio-1",
                    "adapter_name": "Wi-Fi",
                    "ssid": "AuthorizedNetwork",
                    "bssid": "00:11:22:33:44:55",
                    "channel": 6,
                    "frequency_mhz": 2437,
                    "rssi_dbm": -51,
                    "security": "WPA2",
                    "vendor": "Realtek",
                    "fingerprint_hash": "abc123",
                    "risk_score": 12.5,
                    "threat_level": "LOW",
                    "detection_reason": "known baseline",
                    "scan_duration_ms": 400.0,
                }],
            }
            with patch.object(database_manager, "DB_PATH", database_path):
                self.assertTrue(database_manager.save_wifi_scan(payload))
                runs = database_manager.get_recent_scan_runs()
                observations = database_manager.get_recent_wifi_observations()

        run = next(item for item in runs if item["scan_id"] == "scan-test-001")
        observation = next(item for item in observations if item["scan_id"] == "scan-test-001")
        self.assertEqual(run["detection_latency_ms"], 480.0)
        self.assertEqual(observation["bssid"], "00:11:22:33:44:55")
        self.assertEqual(observation["frequency_mhz"], 2437.0)
        self.assertEqual(observation["risk_score"], 12.5)


if __name__ == "__main__":
    unittest.main()
