import tempfile
import unittest
from pathlib import Path

import pandas as pd

from dataset_prep import prepare_dataset
from research_eval import group_column, run, session_gate, simulated_frame


def _clone_rows():
    return pd.DataFrame([
        dict(SSID="MyHotspot", BSSID=f"DA:11:22:33:44:{i:02X}", RSSI=-62, Channel=2437,
             Security="WPA2", AP_Count=5, Signal_Var=6, Label="Fake")
        for i in range(6)
    ])


class LabelSourceGuard(unittest.TestCase):
    def test_unverified_clone_is_relabelled_by_legacy_rule(self):
        frame, _ = prepare_dataset(_clone_rows())
        self.assertEqual(set(frame["Label"]), {"Legit"})  # documents the risk

    def test_field_verified_rows_keep_their_label(self):
        df = _clone_rows()
        df["label_source"] = "field_verified"
        frame, audit = prepare_dataset(df)
        self.assertEqual(set(frame["Label"]), {"Fake"})
        self.assertEqual(audit["campus_rows_relabeled_legit"], 0)


class SessionGate(unittest.TestCase):
    def test_missing_session_id_is_refused(self):
        frame = simulated_frame().drop(columns=["session_id"])
        group, is_session = group_column(frame)
        ok, why = session_gate(frame, group, is_session)
        self.assertFalse(ok)
        self.assertIn("session_id", why)

    def test_too_few_fake_sessions_is_refused(self):
        frame = simulated_frame()
        frame = frame[(frame["Label"] == "Legit") | (frame["session_id"].isin(["F0", "F1"]))]
        group, is_session = group_column(frame)
        ok, why = session_gate(frame, group, is_session)
        self.assertFalse(ok)
        self.assertIn("Fake sessions", why)


class HarnessSmoke(unittest.TestCase):
    def test_runs_and_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            code = run(simulated_frame(), Path(tmp), seeds=[0], n_splits=3)
            self.assertEqual(code, 0)
            for name in ("results.md", "cv_per_fold.csv", "zero_day.csv", "run_config.json"):
                self.assertTrue((Path(tmp) / name).is_file(), name)
            folds = pd.read_csv(Path(tmp) / "cv_per_fold.csv")
            self.assertEqual(set(folds["model"]), {"RF", "KNN", "IsolationForest", "RF+KNN (no IF)", "Hybrid stacked"})


if __name__ == "__main__":
    unittest.main()
