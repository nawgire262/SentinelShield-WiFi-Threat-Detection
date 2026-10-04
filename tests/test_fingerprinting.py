import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scanner
from fingerprinting.fingerprint_generator import create_fingerprint
from fingerprinting.fingerprint_matcher import compare_fingerprint


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.path = Path(self.temp_dir.name) / "fingerprints.json"
        self.baseline = {
            "SSID": "OfficeWiFi",
            "BSSID": "00:11:22:33:44:55:",
            "Channel": 2412,
            "Signal": 0,
            "Security": "WPA2",
        }
        self.path.write_text(json.dumps([self.baseline]), encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_matches_known_bssid_and_normalizes_channel_frequency(self):
        result = compare_fingerprint(
            {
                "SSID": "OfficeWiFi",
                "BSSID": "00:11:22:33:44:55",
                "Channel": 1,
                "Frequency": 2412,
                "RSSI": -58,
                "Security": "WPA/WPA2",
            },
            self.path,
        )

        self.assertEqual(result["similarity"], 100)
        self.assertTrue(result["matched"])

    def test_new_bssid_has_no_score_not_a_false_mismatch(self):
        result = compare_fingerprint(
            {
                "SSID": "OfficeWiFi",
                "BSSID": "AA:BB:CC:DD:EE:FF",
                "Channel": 2412,
                "Security": "WPA2",
            },
            self.path,
        )

        self.assertIsNone(result["similarity"])
        self.assertFalse(result["baseline_found"])

    def test_changed_security_reduces_match_score(self):
        result = compare_fingerprint(
            {
                "SSID": "OfficeWiFi",
                "BSSID": "00:11:22:33:44:55",
                "Channel": 2412,
                "Security": "OPEN",
            },
            self.path,
        )

        self.assertTrue(result["baseline_found"])
        self.assertLess(result["similarity"], 100)

    def test_baseline_must_be_explicitly_trusted(self):
        with self.assertRaises(ValueError):
            create_fingerprint(
                {"SSID": "Guest", "BSSID": "AA:BB:CC:DD:EE:FF"},
                self.path,
            )

        create_fingerprint(
            {
                "SSID": "Guest",
                "BSSID": "AA:BB:CC:DD:EE:FF",
                "Channel": 6,
                "RSSI": -60,
                "Security": "WPA2",
            },
            self.path,
            trusted=True,
        )
        records = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(len(records), 2)

    def test_scanner_includes_similarity_for_known_access_point(self):
        class FakeNetwork:
            ssid = "OfficeWiFi"
            bssid = "00:11:22:33:44:55"
            signal = -58
            freq = 2412
            akm = [1]

        with (
            patch.object(scanner, "_wireless_interface", return_value=object()),
            patch.object(scanner, "_scan_round", return_value=[FakeNetwork()]),
            patch(
                "fingerprinting.fingerprint_matcher.DEFAULT_FINGERPRINT_FILE",
                self.path,
            ),
        ):
            findings = scanner.scan_wifi(rounds=1)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["fingerprint_similarity"], 100)


if __name__ == "__main__":
    unittest.main()
