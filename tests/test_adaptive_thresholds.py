import tempfile
import unittest
from pathlib import Path

from adaptive_thresholds import (
    BAND,
    AdaptiveThresholdEngine,
    FALLBACK_THRESHOLDS,
    WARMUP_SAMPLES,
    scan_crowding,
)


class AdaptiveThresholdEngineTests(unittest.TestCase):
    def test_uses_fallback_until_warmup_then_persists_adaptive_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "threshold-state.json"
            engine = AdaptiveThresholdEngine(state_path=state_path)

            thresholds, mode = engine.get_thresholds()
            self.assertEqual(mode, "warming_up")
            self.assertEqual(thresholds, FALLBACK_THRESHOLDS)

            engine.update([10] * WARMUP_SAMPLES)
            thresholds, mode = engine.get_thresholds()
            self.assertEqual(mode, "adaptive")
            self.assertTrue(thresholds["critical"] > thresholds["high"])
            self.assertTrue(thresholds["high"] > thresholds["medium"])

            reloaded = AdaptiveThresholdEngine(state_path=state_path)
            self.assertEqual(reloaded.summary()["samples_seen"], WARMUP_SAMPLES)
            self.assertEqual(reloaded.summary()["mode"], "adaptive")

    def test_reset_returns_engine_to_warmup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = AdaptiveThresholdEngine(
                state_path=Path(temp_dir) / "threshold-state.json"
            )
            engine.update([20] * WARMUP_SAMPLES)
            engine.reset()

            self.assertEqual(engine.get_thresholds()[1], "warming_up")
            self.assertEqual(engine.summary()["samples_seen"], 0)
            self.assertEqual(engine.summary()["density_samples"], 0)
            self.assertEqual(engine.summary()["noise_mean"], 0)

    def test_warmup_ignores_crowding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = AdaptiveThresholdEngine(state_path=Path(temp_dir) / "threshold-state.json")
            thresholds, mode = engine.get_thresholds(ap_count=80, interference=40)
            self.assertEqual(mode, "warming_up")
            self.assertEqual(thresholds, FALLBACK_THRESHOLDS)

    def test_density_and_interference_move_cutoffs_after_warmup(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            engine = AdaptiveThresholdEngine(state_path=Path(temp_dir) / "threshold-state.json")
            engine.update([50] * WARMUP_SAMPLES)
            base, mode = engine.get_thresholds()
            dense, dense_mode = engine.get_thresholds(ap_count=40, interference=30)
            quiet, _mode = engine.get_thresholds(ap_count=1, interference=1)
            noisy, _mode = engine.get_thresholds(interference=36)
            self.assertEqual(mode, "adaptive")
            self.assertEqual(dense_mode, "adaptive")
            self.assertGreater(dense["critical"], base["critical"])
            self.assertGreater(dense["high"], base["high"])
            self.assertLess(quiet["critical"], base["critical"])
            self.assertGreater(noisy["high"], base["high"])
            for cuts in (dense, quiet, noisy):
                self.assertGreater(cuts["critical"], cuts["high"])
                self.assertGreater(cuts["high"], cuts["medium"])
                for level, value in cuts.items():
                    self.assertGreaterEqual(value, BAND[level][0])
                    self.assertLessEqual(value, BAND[level][1])

    def test_learned_density_is_the_reference_and_persists_once_per_scan(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "threshold-state.json"
            engine = AdaptiveThresholdEngine(state_path=state_path)
            engine.update([50] * WARMUP_SAMPLES, ap_count=10, interference=12)
            self.assertEqual(engine.summary()["density_samples"], 1)
            self.assertAlmostEqual(engine.summary()["density_mean"], 10)
            self.assertAlmostEqual(engine.summary()["noise_mean"], 12)
            base, _mode = engine.get_thresholds()
            matched, _mode = engine.get_thresholds(ap_count=10, interference=12)
            higher, _mode = engine.get_thresholds(ap_count=30, interference=12)
            self.assertAlmostEqual(matched["critical"], base["critical"], places=4)
            self.assertGreater(higher["critical"], matched["critical"])
            reloaded = AdaptiveThresholdEngine(state_path=state_path)
            self.assertEqual(reloaded.summary()["density_samples"], 1)
            self.assertAlmostEqual(reloaded.summary()["density_mean"], 10)
            self.assertAlmostEqual(reloaded.summary()["noise_mean"], 12)

    def test_scan_crowding_uses_rssi_standard_deviation(self):
        crowd = scan_crowding(3, [-40, -60, "nope", None])
        self.assertEqual(crowd["ap_count"], 3)
        self.assertAlmostEqual(crowd["interference"], 14.142135, places=3)
        self.assertEqual(scan_crowding(1, [-50])["interference"], 0.0)


if __name__ == "__main__":
    unittest.main()
