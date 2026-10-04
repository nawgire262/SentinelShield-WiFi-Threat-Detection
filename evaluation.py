"""Held-out evaluation for the Wi-Fi ensemble.

The script reports precision, recall, F1, and false-positive rate on a
stratified holdout only when the cleaned labels are large enough to support
that claim. It never scores the training split.

The current labeled file does not meet that bar: after unit fixes and the
campus-label correction, the remaining Fake rows are hand-typed placeholders.
In that case the script exits 2 and prints no detection score.
"""

from __future__ import annotations

import sys

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from dataset_prep import REAL_SCAN_REQUIREMENT, load_clean_dataset, quality_gate
from ml_ensemble import HybridEnsembleDetector

WITHHELD = "METRICS_WITHHELD"


def held_out_scores(frame: pd.DataFrame, test_size: float = 0.3, n_estimators: int = 200, random_state: int = 42) -> dict:
    """Train on the training split and score only the holdout."""
    labels = frame["Label"].astype(str)
    if labels.nunique() < 2:
        raise ValueError("held-out evaluation needs both labels")
    train_frame, test_frame = train_test_split(
        frame, test_size=test_size, random_state=random_state, stratify=labels
    )
    detector = HybridEnsembleDetector(n_estimators=n_estimators, random_state=random_state)
    if not detector.train_frame(train_frame.reset_index(drop=True), compute_importance=False):
        raise RuntimeError("held-out training split could not be fit")
    probabilities = detector.predict_frame(test_frame.reset_index(drop=True))
    y_true = (test_frame["Label"].astype(str) == "Fake").to_numpy(dtype=int)
    y_pred = (np.asarray(probabilities) >= 0.5).astype(int)
    true_negative, false_positive, _false_negative, _true_positive = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    negatives = false_positive + true_negative
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "false_positive_rate": float(false_positive / negatives) if negatives else 0.0,
        "test_rows": int(len(test_frame)),
        "test_fake": int(y_true.sum()),
        "test_legit": int(len(y_true) - y_true.sum()),
        "split": "held_out",
    }


def _print_audit(audit: dict) -> None:
    print(f"Source file: {audit.get('source', 'unknown')}")
    print(f"Rows read: {int(audit.get('rows_in', 0))}")
    print(f"Channel values converted from kHz to MHz: {int(audit.get('channel_khz_converted', 0))}")
    print(
        "Campus multi-AP rows relabeled Legit: "
        f"{int(audit.get('campus_rows_relabeled_legit', 0))} "
        f"(Pillai: {int(audit.get('pillai_rows_relabeled_legit', 0))})"
    )
    print(f"Hand-typed OPEN placeholders relabeled Fake: {int(audit.get('open_placeholder_relabeled_fake', 0))}")
    print(f"Fake rows that are not placeholders: {int(audit.get('real_fake_rows', 0))}")
    print("wifi_dataset.csv is header-only and is not used as a labeled evaluation set.")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    requested = args[0] if args else "training_dataset.csv"
    frame, audit = load_clean_dataset(requested)
    _print_audit(audit)
    allowed, reason = quality_gate(frame)
    if not allowed:
        print(WITHHELD)
        print("No held-out detection score is printed. The labeled file is too small and too dirty for an honest one.")
        print(reason)
        print(REAL_SCAN_REQUIREMENT)
        return 2
    scores = held_out_scores(frame)
    print(f"Held-out precision: {scores['precision']:.4f}")
    print(f"Held-out recall: {scores['recall']:.4f}")
    print(f"Held-out F1: {scores['f1']:.4f}")
    print(f"Held-out false-positive rate: {scores['false_positive_rate']:.4f}")
    print(f"Holdout rows: {scores['test_rows']} (Fake {scores['test_fake']}, Legit {scores['test_legit']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
