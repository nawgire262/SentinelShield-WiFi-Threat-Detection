import re
import subprocess
import sys
import unittest
from pathlib import Path

import pandas as pd

from dataset_prep import load_clean_dataset, prepare_dataset, quality_gate
from evaluation import WITHHELD, held_out_scores

ROOT = Path(__file__).resolve().parents[1]


class DatasetCleaningTests(unittest.TestCase):
    def test_channel_units_and_justified_label_corrections(self):
        rows = []
        for index in range(4):
            rows.append({
                "SSID": "Pillai",
                "BSSID": f"70:a7:41:82:d3:9{index}:",
                "RSSI": -82,
                "Channel": 5765000,
                "Security": "WPA2",
                "AP_Count": 8,
                "Signal_Var": 19,
                "Label": "Fake",
            })
        rows.append({
            "SSID": "Raj",
            "BSSID": "AA:BB:CC:11:22:34",
            "RSSI": -32,
            "Channel": 2412,
            "Security": "OPEN",
            "AP_Count": 2,
            "Signal_Var": 28,
            "Label": "Fake",
        })
        rows.append({
            "SSID": "OfficeWiFi",
            "BSSID": "AA:BB:CC:11:22:33",
            "RSSI": -41.8,
            "Channel": 2412,
            "Security": "OPEN",
            "AP_Count": 2,
            "Signal_Var": 27,
            "Label": "Legit",
        })
        frame, audit = prepare_dataset(pd.DataFrame(rows))
        campus = frame[frame["SSID"] == "Pillai"]
        self.assertTrue((campus["Channel"] == 5765).all())
        self.assertTrue((campus["Label"] == "Legit").all())
        self.assertTrue(campus["BSSID"].str.fullmatch(r"([0-9A-F]{2}:){5}[0-9A-F]{2}").all())
        self.assertEqual(int(audit["campus_rows_relabeled_legit"]), 4)
        placeholder = frame[frame["BSSID"] == "AA:BB:CC:11:22:34"].iloc[0]
        self.assertTrue(bool(placeholder["synthetic_placeholder"]))
        self.assertEqual(placeholder["Label"], "Fake")
        self.assertEqual(float(placeholder["Channel"]), 2412.0)
        corrected = frame[frame["BSSID"] == "AA:BB:CC:11:22:33"].iloc[0]
        self.assertEqual(corrected["Label"], "Fake")
        self.assertEqual(corrected["label_action"], "relabeled_fake_open_placeholder")

    def test_shipped_labels_are_too_dirty_for_a_detection_score(self):
        frame, audit = load_clean_dataset(ROOT / "training_dataset.csv")
        self.assertEqual(audit["pillai_rows_relabeled_legit"], 18)
        self.assertGreaterEqual(audit["campus_rows_relabeled_legit"], 40)
        self.assertEqual(audit["real_fake_rows"], 0)
        self.assertGreater(audit["channel_khz_converted"], 100)
        allowed, reason = quality_gate(frame)
        self.assertFalse(allowed)
        self.assertIn("placeholder", reason)

    def test_evaluation_script_fails_closed_without_a_score(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "evaluation.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(WITHHELD, result.stdout)
        self.assertIn("own hotspot", result.stdout)
        self.assertNotIn("Held-out precision", result.stdout)
        self.assertIsNone(re.search(r"(Precision|Recall|F1|Accuracy)\s*[:=]", result.stdout))
        self.assertNotIn("accuracy_score", (ROOT / "evaluation.py").read_text(encoding="utf-8"))

    def test_held_out_helper_scores_only_the_test_split(self):
        import sklearn.metrics as metrics

        def _refuse_accuracy(*_args, **_kwargs):
            raise AssertionError("accuracy was requested")

        original = metrics.accuracy_score
        metrics.accuracy_score = _refuse_accuracy
        try:
            rows = []
            for index in range(40):
                rows.append({
                    "RSSI": -75, "Channel": 2412, "Security": "WPA2",
                    "AP_Count": 1, "Signal_Var": 2, "Label": "Legit",
                })
                rows.append({
                    "RSSI": -25, "Channel": 2412, "Security": "OPEN",
                    "AP_Count": 1, "Signal_Var": 30, "Label": "Fake",
                })
            scores = held_out_scores(pd.DataFrame(rows), n_estimators=20, random_state=42)
        finally:
            metrics.accuracy_score = original
        self.assertEqual(scores["split"], "held_out")
        self.assertEqual(scores["test_rows"], 24)
        self.assertNotIn("training_accuracy", scores)
        for name in ("precision", "recall", "f1", "false_positive_rate"):
            self.assertGreaterEqual(scores[name], 0.0)
            self.assertLessEqual(scores[name], 1.0)


if __name__ == "__main__":
    unittest.main()
