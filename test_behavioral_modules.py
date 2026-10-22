"""test_behavioral_modules.py – Unit tests for the 5 behavioral cloud & log intelligence modules."""
import unittest

from adaptive_access_control import AdaptiveAccessControlEngine
from behavioral_biometrics import BehavioralBiometricsEngine, BiometricProfile, KeystrokeEvent
from behavioral_ml_engine import BehavioralHybridMLEngine
from over_efficiency_detector import OverEfficiencyDetector


class BehavioralModulesTestCase(unittest.TestCase):
    def setUp(self):
        self.bio_engine = BehavioralBiometricsEngine()
        self.eff_detector = OverEfficiencyDetector()
        self.ml_engine = BehavioralHybridMLEngine()
        self.ac_engine = AdaptiveAccessControlEngine()

    def test_behavioral_biometrics_human_nominal(self):
        """Authentic human typing within profile parameters should produce high similarity and low risk."""
        events = []
        t = 0.0
        # 30 keys with natural human jitter (flight ~100-130ms, dwell ~75-85ms)
        import math
        for i in range(30):
            dwell = 80.0 + (5.0 * math.sin(i))
            flight = 115.0 + (15.0 * math.cos(i))
            events.append(KeystrokeEvent(key=f"k{i}", press_time_ms=t, release_time_ms=t + dwell))
            t += (dwell + flight)

        assessment = self.bio_engine.evaluate_session("admin_user", events, total_duration_ms=t, backspace_count=2)
        self.assertFalse(assessment.is_anomaly)
        self.assertLess(assessment.risk_score, 30.0)
        self.assertGreater(assessment.similarity_score, 70.0)

    def test_behavioral_biometrics_robotic_anomaly(self):
        """Microsecond robotic typing should be flagged as an anomaly."""
        events = []
        t = 0.0
        # 30 keys, 5ms flight, 5ms dwell -> 1000+ WPM
        for i in range(30):
            events.append(KeystrokeEvent(key=f"k{i}", press_time_ms=t, release_time_ms=t + 5.0))
            t += 10.0

        assessment = self.bio_engine.evaluate_session("admin_user", events, total_duration_ms=t, backspace_count=0)
        self.assertTrue(assessment.is_anomaly)
        self.assertGreater(assessment.risk_score, 50.0)

    def test_over_efficiency_human_typing(self):
        """Natural human speed (~5 char/sec) should be classified as HUMAN_TYPICAL."""
        result = self.eff_detector.analyze_interaction(
            char_count=50,
            duration_ms=10000.0,  # 5 char/sec
            interval_history_ms=[120.0, 95.0, 140.0, 80.0, 110.0],
            backspace_count=3,
        )
        self.assertFalse(result.is_automated)
        self.assertEqual(result.classification, "HUMAN_TYPICAL")
        self.assertLess(result.efficiency_score, 30.0)

    def test_over_efficiency_bot_injection(self):
        """Massive throughput and clockwork intervals should trigger BOT_AUTOMATION."""
        result = self.eff_detector.analyze_interaction(
            char_count=60,
            duration_ms=300.0,   # 200 char/sec
            interval_history_ms=[5.0, 5.0, 5.0, 5.0, 5.0, 5.0],
            backspace_count=0,
        )
        self.assertTrue(result.is_automated)
        self.assertEqual(result.classification, "BOT_AUTOMATION")
        self.assertGreaterEqual(result.efficiency_score, 70.0)

    def test_hybrid_ml_prediction(self):
        """Hybrid ensemble (RF + Isolation Forest) should distinguish human from bot features."""
        human_features = {
            "typing_speed_wpm": 60.0,
            "mean_flight_time_ms": 115.0,
            "std_flight_time_ms": 32.0,
            "mean_dwell_time_ms": 82.0,
            "char_per_sec": 5.0,
            "error_rate": 0.05,
            "uniformity_index": 0.15,
        }
        human_pred = self.ml_engine.predict(human_features)
        self.assertEqual(human_pred.rf_prediction, "HUMAN_LEGIT")
        self.assertLess(human_pred.hybrid_threat_score, 45.0)

        bot_features = {
            "typing_speed_wpm": 850.0,
            "mean_flight_time_ms": 5.0,
            "std_flight_time_ms": 0.8,
            "mean_dwell_time_ms": 6.0,
            "char_per_sec": 70.0,
            "error_rate": 0.0,
            "uniformity_index": 0.95,
        }
        bot_pred = self.ml_engine.predict(bot_features)
        self.assertEqual(bot_pred.rf_prediction, "AUTOMATED_ANOMALOUS")
        self.assertGreater(bot_pred.hybrid_threat_score, 65.0)

    def test_adaptive_access_control_policies(self):
        """Risk thresholds trigger correct adaptive security actions."""
        # Low risk -> ALLOW
        d_low = self.ac_engine.evaluate_policy("user1", "s1", biometric_risk=10, over_efficiency_score=10, hybrid_ml_risk=10)
        self.assertEqual(d_low.action, "ALLOW")

        # Medium risk -> STEP_UP_MFA
        d_med = self.ac_engine.evaluate_policy("user1", "s2", biometric_risk=45, over_efficiency_score=40, hybrid_ml_risk=40)
        self.assertEqual(d_med.action, "STEP_UP_MFA")

        # Critical risk -> TERMINATE_QUARANTINE
        d_crit = self.ac_engine.evaluate_policy("user1", "s3", biometric_risk=90, over_efficiency_score=95, hybrid_ml_risk=90)
        self.assertEqual(d_crit.action, "TERMINATE_QUARANTINE")


if __name__ == "__main__":
    unittest.main()
