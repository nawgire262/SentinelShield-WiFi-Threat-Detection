import json
import ast
import tempfile
import unittest
from pathlib import Path

from analyst_feedback import record_feedback
from evidence_integrity import receipt
from incident_assistant import explain
from sensor_mesh import mesh_context
from wifi_sensing import summarize
from wired_correlation import correlate
from supply_chain import generate


class InnovationPhaseTests(unittest.TestCase):
    def test_wired_inventory_requires_explicit_authorization(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "inventory.json"
            path.write_text(json.dumps([{"bssid": "00:11:22:33:44:55", "authorized": False}]), encoding="utf-8")
            result = correlate({"ssid": "Campus", "bssid": "00:11:22:33:44:55"}, path)
        self.assertTrue(result["matched"])
        self.assertEqual(result["score"], 70.0)

    def test_mesh_only_accepts_recent_matching_sensor_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "sensor-a.json").write_text(json.dumps({"sensor_id": "A", "timestamp": "2099-01-01T00:00:00+00:00", "observations": [{"bssid": "00:11:22:33:44:55"}]}), encoding="utf-8")
            result = mesh_context({"bssid": "00:11:22:33:44:55"}, directory)
        self.assertIn("A", result["sensors"])

    def test_integrity_and_feedback_are_local_and_deterministic(self):
        self.assertEqual(receipt({"a": 1})["algorithm"], "SHA-256")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feedback.jsonl"
            item = record_feedback("00:11:22:33:44:55", "investigate", path=path)
            self.assertEqual(item["verdict"], "INVESTIGATE")
            self.assertEqual(len(path.read_text(encoding="utf-8").splitlines()), 1)

    def test_explanation_and_sensing_do_not_claim_attribution(self):
        result = explain({"ssid": "Campus", "bssid": "00:11:22:33:44:55", "threat_level": "HIGH", "reasons": ["security changed"]})
        self.assertIn("investigate", result["recommended_action"].lower())
        self.assertFalse(summarize([], enabled=True, consent=False)["enabled"])

    def test_dashboard_parses_and_supply_inventory_is_generated(self):
        root = Path(__file__).resolve().parents[1]
        ast.parse((root / "dashboard.py").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            payload = generate(Path(directory) / "inventory.json")
        self.assertTrue(payload["source_files"])


if __name__ == "__main__":
    unittest.main()
