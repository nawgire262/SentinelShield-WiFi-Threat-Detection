"""Integration checks for the RF + KNN + Isolation Forest + meta-model path."""
import tempfile
import unittest

import numpy as np
import pandas as pd

from ml_ensemble import HybridEnsembleDetector
from ml_evidence import ExistingModelEvidence


def labelled_observations():
    rows = []
    for i in range(40):
        rows.append({"RSSI": -72 + (i % 4), "Channel": 2412 + (i % 2) * 5,
                     "Security": "WPA2", "AP_Count": 3 + (i % 2),
                     "Signal_Var": float(i % 4), "Label": "Legit"})
    for i in range(20):
        rows.append({"RSSI": -32 + (i % 3), "Channel": 2462,
                     "Security": "OPEN", "AP_Count": 1 + (i % 2),
                     "Signal_Var": 20.0 + (i % 5), "Label": "Fake"})
    return pd.DataFrame(rows)


class HybridPipelineIntegrationTests(unittest.TestCase):
    def test_each_base_model_and_meta_model_produce_compatible_outputs(self):
        detector = HybridEnsembleDetector(n_estimators=20, n_neighbors=3, random_state=7)
        self.assertTrue(detector.train_frame(labelled_observations(), compute_importance=False))
        raw = np.array([[-35.0, 2462.0, float(detector._security_code("OPEN")), 1.0, 22.0]])
        scaled = detector.scaler.transform(raw)
        self.assertEqual(scaled.shape, (1, 5))
        self.assertEqual(detector.rf_model.predict_proba(scaled).shape, (1, 2))
        self.assertEqual(detector.knn_model.predict_proba(scaled).shape, (1, 2))
        self.assertEqual(detector.iso_model.decision_function(scaled).shape, (1,))
        prediction = detector.predict({"RSSI": -35, "Channel": 2462, "Security": "OPEN",
                                       "AP_Count": 1, "Signal_Var": 22})
        self.assertIsNotNone(prediction)
        self.assertIn(prediction["rf_prediction"], {"Fake", "Legit"})
        self.assertIn(prediction["knn_prediction"], {"Fake", "Legit"})
        self.assertIn(prediction["iso_prediction"], {"Anomaly", "Normal"})
        self.assertIn(prediction["meta_prediction"], {"Fake", "Legit"})
        self.assertGreaterEqual(prediction["ensemble_risk"], 0)
        self.assertLessEqual(prediction["ensemble_risk"], 100)

    def test_saved_pipeline_contract_matches_live_evidence_adapter(self):
        detector = HybridEnsembleDetector(n_estimators=20, n_neighbors=3, random_state=7)
        self.assertTrue(detector.train_frame(labelled_observations(), compute_importance=False))
        with tempfile.TemporaryDirectory() as directory:
            detector.save_models(directory)
            adapter = ExistingModelEvidence(directory)
            self.assertTrue(adapter.available, adapter.load_error)
            result = adapter.predict(
                {"rssi_dbm": -35, "frequency_mhz": 2462, "security": "OPEN"},
                ap_count=1, signal_variance=22.0,
            )
            self.assertIsNotNone(result)
            for key in ("rf_fake_probability", "knn_fake_probability", "isolation_anomaly_score",
                        "fake_probability", "risk_score", "explanation"):
                self.assertIn(key, result)
            self.assertGreaterEqual(result["risk_score"], 0)
            self.assertLessEqual(result["risk_score"], 100)


if __name__ == "__main__":
    unittest.main()
