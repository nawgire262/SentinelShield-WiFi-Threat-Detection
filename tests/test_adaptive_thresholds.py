import tempfile
import unittest
from pathlib import Path

from adaptive_thresholds import AdaptiveThresholdEngine, FALLBACK_THRESHOLDS, WARMUP_SAMPLES


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


if __name__ == "__main__":
    unittest.main()
