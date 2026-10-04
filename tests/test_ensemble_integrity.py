import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pandas as pd

import ml_ensemble
from ml_evidence import ExistingModelEvidence
from ml_ensemble import HybridEnsembleDetector
from sklearn.ensemble import IsolationForest
from xai_explain import local_occlusion


def _toy_frame(legit_rows: int = 36, fake_rows: int = 12) -> pd.DataFrame:
    rows = []
    for index in range(legit_rows):
        rows.append({
            "RSSI": -70 - (index % 3),
            "Channel": 2412,
            "Security": "WPA2",
            "AP_Count": 2,
            "Signal_Var": 3,
            "Label": "Legit",
        })
    for index in range(fake_rows):
        rows.append({
            "RSSI": -28,
            "Channel": 2462,
            "Security": "OPEN",
            "AP_Count": 2,
            "Signal_Var": 31,
            "Label": "Fake",
        })
    return pd.DataFrame(rows)


class OcclusionTests(unittest.TestCase):
    def test_only_the_changed_feature_gets_credit(self):
        def score_fn(matrix):
            return np.asarray(matrix, dtype=float)[:, 0]

        effects = local_occlusion(score_fn, np.array([0.8, 5.0, 9.0]), np.zeros(3), ["A", "B", "C"])
        by_name = {item["feature"]: item["delta"] for item in effects}
        self.assertAlmostEqual(by_name["A"], 0.8)
        self.assertAlmostEqual(by_name["B"], 0.0)
        self.assertAlmostEqual(by_name["C"], 0.0)
        from xai_explain import explanation_payload
        self.assertIn("A raises P(Fake)", explanation_payload(effects)["summary"])


class EnsembleTrainingTests(unittest.TestCase):
    def test_isolation_forest_never_fits_fake_rows_and_prediction_uses_meta_scaler(self):
        fitted = []
        original = IsolationForest.fit

        def _record(self, X, y=None, sample_weight=None):
            fitted.append(np.asarray(X, dtype=float).copy())
            return original(self, X, y=y, sample_weight=sample_weight)

        detector = HybridEnsembleDetector(n_estimators=15, random_state=42)
        with patch.object(ml_ensemble.IsolationForest, "fit", _record):
            self.assertTrue(detector.train_frame(_toy_frame(), compute_importance=False))
        legit = detector.training_matrix_[detector.training_labels_ != detector.fake_label_]
        self.assertGreaterEqual(len(fitted), 2)
        for block in fitted:
            self.assertLess(len(block), len(detector.training_matrix_))
            for row in block:
                distance = np.linalg.norm(legit - row, axis=1).min()
                self.assertLess(distance, 1e-6)

        calls = []
        original_transform = detector.meta_scaler.transform

        def _spy(matrix):
            calls.append(np.asarray(matrix, dtype=float).copy())
            return original_transform(matrix)

        detector.meta_scaler.transform = _spy
        prediction = detector.predict({
            "RSSI": -28, "Channel": 2462, "Security": "OPEN", "AP_Count": 2, "Signal_Var": 31,
        })
        self.assertIsNotNone(prediction)
        self.assertGreaterEqual(len(calls), 1)
        self.assertTrue(all(call.shape[1] == 3 for call in calls))
        self.assertIn("explanation", prediction)
        self.assertEqual(len(prediction["explanation"]["effects"]), 5)
        self.assertFalse(prediction["explanation"]["is_detection_accuracy"])

    def test_saved_artifacts_round_trip_through_the_live_loader(self):
        detector = HybridEnsembleDetector(n_estimators=15, random_state=42)
        self.assertTrue(detector.train_frame(_toy_frame(), compute_importance=True))
        with tempfile.TemporaryDirectory() as directory:
            detector.save_models(directory)
            evidence = ExistingModelEvidence(directory)
            self.assertTrue(evidence.available)
            result = evidence.predict(
                {"rssi_dbm": -28, "frequency_mhz": 2462, "security": "OPEN"},
                ap_count=2,
                signal_variance=31,
            )
            self.assertTrue((Path(directory) / "meta_scaler.pkl").is_file())
        self.assertIsNotNone(result)
        self.assertIn("fake_probability", result)
        self.assertEqual(result["explanation"]["method"], "occlusion")
        self.assertEqual(len(result["explanation"]["effects"]), 5)


if __name__ == "__main__":
    unittest.main()
