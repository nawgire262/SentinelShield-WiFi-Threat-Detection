import copy
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from evidence_fusion import EvidenceFusion
from fast_wifi_scanner import FastWiFiScanner, RadioAdapter, ScanBatch, frequency_to_channel, frequency_to_mhz
from scan_controller import ScanController
from temporal_analyzer import TemporalAnalyzer
from wifi_fingerprint import WiFiFingerprintStore


class FakeNetwork:
    def __init__(self, ssid="Campus", bssid="00:11:22:33:44:55", signal=-55, freq=2437, akm=(1,)):
        self.ssid = ssid
        self.bssid = bssid
        self.signal = signal
        self.freq = freq
        self.akm = akm


class FakeInterface:
    def __init__(self, name, results):
        self._name = name
        self._results = results
        self.active = 0
        self.max_active = 0
        self.guard = threading.Lock()

    def name(self):
        return self._name

    def description(self):
        return f"Test {self._name} Wi-Fi Adapter"

    def status(self):
        return 4

    def scan(self):
        with self.guard:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        return True

    def scan_results(self):
        with self.guard:
            self.active -= 1
        return self._results


class FakeBatchScanner:
    def __init__(self, observations):
        self.observations = observations
        self.modes = []

    def discover_adapters(self):
        return []

    def scan(self, mode="balanced", cancel_event=None, adapters=None):
        self.modes.append(mode)
        now = "2026-10-04T12:00:00+00:00"
        adapter = {"adapter_id": "radio-a", "name": "Wi-Fi A", "mac_address": None, "interface_state": "connected", "capabilities": ["scan", "scan_results"], "backend": "fake"}
        rows = [dict(row, timestamp=now, adapter_id="radio-a", adapter_name="Wi-Fi A", scan_duration_ms=5.0) for row in self.observations]
        return ScanBatch("test-scan", now, now, 5.0, 0.1, mode, [adapter], rows, [], [])


class NoML:
    available = False


class FastScannerTests(unittest.TestCase):
    def test_frequency_units_normalize_to_channel(self):
        self.assertEqual(frequency_to_mhz(2412), 2412)
        self.assertEqual(frequency_to_mhz(2412000), 2412)
        self.assertEqual(frequency_to_mhz(2412000000), 2412)
        self.assertEqual(frequency_to_channel(2412000), 1)
        self.assertEqual(frequency_to_channel(5180000), 36)

    def test_single_radio_discovery_and_normalized_result(self):
        interface = FakeInterface("Wi-Fi", [FakeNetwork()])
        scanner = FastWiFiScanner(interface_provider=lambda: [interface], sleep=lambda _: None)
        batch = scanner.scan(mode="fast")
        self.assertEqual(len(batch.adapters), 1)
        self.assertEqual(batch.public_dict()["adapter_mode"], "single-adapter")
        item = batch.observations[0]
        self.assertEqual(item["channel"], 6)
        self.assertEqual(item["frequency_mhz"], 2437)
        self.assertEqual(item["rssi_dbm"], -55)
        self.assertEqual(item["adapter_name"], "Wi-Fi")

    def test_parallel_distinct_radios_and_fallback_metadata(self):
        first = FakeInterface("Wi-Fi A", [FakeNetwork(bssid="00:11:22:33:44:55")])
        second = FakeInterface("Wi-Fi B", [FakeNetwork(bssid="00:11:22:33:44:66")])
        scanner = FastWiFiScanner(interface_provider=lambda: [first, second], sleep=lambda _: None)
        batch = scanner.scan(mode="fast")
        self.assertEqual(len(batch.adapters), 2)
        self.assertEqual(batch.public_dict()["adapter_mode"], "multi-adapter")
        self.assertEqual(batch.unique_bssids, 2)
        self.assertLessEqual(first.max_active, 1)
        self.assertLessEqual(second.max_active, 1)

    def test_virtual_interfaces_are_excluded(self):
        physical = FakeInterface("Wi-Fi", [FakeNetwork()])
        virtual = FakeInterface("Microsoft Wi-Fi Direct Virtual Adapter", [FakeNetwork(bssid="AA:BB:CC:DD:EE:FF")])
        scanner = FastWiFiScanner(interface_provider=lambda: [virtual, physical], sleep=lambda _: None)
        adapters = scanner.discover_adapters()
        self.assertEqual([item.name for item in adapters], ["Wi-Fi"])


class FingerprintAndTemporalTests(unittest.TestCase):
    def test_baseline_is_observed_not_trusted_until_explicit_action(self):
        with tempfile.TemporaryDirectory() as directory:
            store = WiFiFingerprintStore(Path(directory) / "baseline.json")
            record = store.observe({"ssid": "Campus", "bssid": "00:11:22:33:44:55", "rssi_dbm": -55, "channel": 6, "security": "WPA2"})
            self.assertEqual(record["confidence"], "OBSERVED")
            self.assertFalse(record["trusted"])
            self.assertTrue(store.set_trusted("00:11:22:33:44:55", True))
            self.assertEqual(store.get("00:11:22:33:44:55")["confidence"], "TRUSTED")

    def test_temporal_rssi_statistics_and_preview_are_bounded(self):
        config = copy.deepcopy(__import__("runtime_config").DEFAULTS)
        config["temporal_analysis"].update({"minimum_samples": 3, "rssi_jump_threshold_db": 10, "rssi_std_threshold_db": 8})
        analyzer = TemporalAnalyzer(config=config)
        values = [-50, -51, -49]
        for value in values:
            result = analyzer.observe({"bssid": "00:11:22:33:44:55", "rssi_dbm": value, "timestamp": "2026-10-04T12:00:00+00:00"})
        before = result["sample_count"]
        preview = analyzer.preview({"bssid": "00:11:22:33:44:55", "rssi_dbm": -20, "timestamp": "2026-10-04T12:00:01+00:00"})
        self.assertEqual(preview["sample_count"], before + 1)
        self.assertEqual(analyzer.observe({"bssid": "00:11:22:33:44:55", "rssi_dbm": -20})["rssi_delta"], 29)
        self.assertGreater(preview["temporal_score"], 0)


class FusionAndControllerTests(unittest.TestCase):
    def test_baseline_rssi_deviation_uses_configured_fingerprint_thresholds(self):
        fusion = EvidenceFusion()
        result = fusion.score_observation(
            {"ssid": "Campus", "bssid": "00:11:22:33:44:55", "security": "WPA2", "channel": 6, "rssi_dbm": -30},
            {"channels": [6], "security_history": ["WPA2"], "rssi_mean": -60, "rssi_variance": 4.0, "vendor": ""},
            [], {"temporal_score": 0, "reasons": []},
        )
        self.assertGreater(result["scores"]["fingerprint"], 0)

    def test_new_bssid_is_not_rogue_by_identity_alone_but_mismatches_fuse_high(self):
        fusion = EvidenceFusion()
        trusted = [{"ssid": "Campus", "bssid": "00:11:22:33:44:55", "trusted": True, "channels": [6], "security_history": ["WPA2"]}]
        base_obs = {"ssid": "Campus", "bssid": "00:11:22:33:44:66", "security": "WPA2", "channel": 6, "rssi_dbm": -55}
        no_mismatch = fusion.score_observation(base_obs, None, trusted, {"temporal_score": 0, "reasons": []})
        mismatch = fusion.score_observation({**base_obs, "security": "OPEN", "channel": 11}, None, trusted, {"temporal_score": 0, "reasons": []})
        self.assertNotEqual(no_mismatch["threat_level"], "CRITICAL")
        self.assertGreater(mismatch["risk_score"], no_mismatch["risk_score"])
        self.assertIn(mismatch["threat_level"], {"HIGH", "CRITICAL"})

    def test_auto_mode_deep_verifies_new_bssid_and_returns_findings(self):
        observation = {"ssid": "Campus", "bssid": "00:11:22:33:44:55", "rssi_dbm": -55, "channel": 6, "frequency_mhz": 2437, "security": "WPA2"}
        fake_scanner = FakeBatchScanner([observation])
        with tempfile.TemporaryDirectory() as directory:
            store = WiFiFingerprintStore(Path(directory) / "baseline.json")
            controller = ScanController(scanner=fake_scanner, fingerprint_store=store, ml_models=NoML(), database=False)
            self.assertEqual(controller.fingerprints.path, store.path)
            self.assertTrue(controller.start("auto"))
            controller._thread.join(timeout=3)
            status = controller.status()
            result = controller.latest()
            stored = store.get(observation["bssid"])
        self.assertEqual(status["status"], "completed")
        self.assertEqual(fake_scanner.modes, ["balanced", "deep"])
        self.assertTrue(result["verification_performed"])
        self.assertEqual(len(result["results"]), 1)
        self.assertEqual(result["results"][0]["confidence"], "OBSERVED")
        self.assertIsNotNone(stored)
        self.assertFalse(stored["trusted"])


if __name__ == "__main__":
    unittest.main()
