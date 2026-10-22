import unittest
from novelty_alert_engine import evaluate_novelty


class NoveltyAlertEngineTests(unittest.TestCase):
    def test_cloud_reputation_triggers_high_alert(self):
        result = evaluate_novelty({"Cloud_Reputation_Hit": True, "Combined_Risk": 30})
        self.assertTrue(result.should_alert)
        self.assertIn(result.level, {"HIGH", "CRITICAL"})
        self.assertIn("cloud_reputation", result.strong_evidence)

    def test_layer2_and_raim_can_raise_critical(self):
        result = evaluate_novelty({"Layer2_Deauth_Detected": True, "RAIM_Flagged": True, "Combined_Risk": 55})
        self.assertTrue(result.should_alert)
        self.assertEqual(result.level, "CRITICAL")

    def test_temporal_and_density_need_corroboration(self):
        result = evaluate_novelty({"Observation_Count": 5, "Signal_Fluctuation": 22, "AP_Count": 4, "Combined_Risk": 55})
        self.assertTrue(result.should_alert)
        self.assertEqual(result.level, "HIGH")
        self.assertGreaterEqual(len(result.evidence), 2)

    def test_one_weak_signal_does_not_alert(self):
        result = evaluate_novelty({"AP_Count": 4, "Combined_Risk": 20})
        self.assertFalse(result.should_alert)

    def test_safe_observation_stays_safe(self):
        result = evaluate_novelty({"Combined_Risk": 12, "Observation_Count": 2, "AP_Count": 1})
        self.assertFalse(result.should_alert)
        self.assertEqual(result.level, "SAFE")

    def test_high_risk_alone_triggers(self):
        result = evaluate_novelty({"Combined_Risk": 70})
        self.assertTrue(result.should_alert)
        self.assertEqual(result.level, "HIGH")


if __name__ == "__main__":
    unittest.main()
