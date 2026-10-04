"""
train_model.py
================
Fit the hybrid stack and save the artifacts ml_evidence.py loads.

Isolation Forest is fit on Legit rows only, including inside each
out-of-fold split. The meta-classifier sees scaled out-of-fold scores, and
the same meta scaler is saved for prediction.

This script does not print a detection score. Run evaluation.py for that.
The shipped labeled file currently fails that check, so the saved model card
says metrics are withheld.
"""

import json
import sys

import sklearn

from dataset_prep import REAL_SCAN_REQUIREMENT
from ml_ensemble import HybridEnsembleDetector

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    dataset = sys.argv[1] if len(sys.argv) > 1 else "training_dataset.csv"
    detector = HybridEnsembleDetector()
    if not detector.train(dataset):
        print("Training did not produce a model.")
        return 1
    detector.save_models()
    audit = getattr(detector, "data_audit_", {})
    withheld = bool(getattr(detector, "metrics_withheld_", True))
    card = {
        "artifacts": [
            "rf_model.pkl", "knn_model.pkl", "iso_model.pkl", "meta_model.pkl",
            "le_security.pkl", "le_label.pkl", "scaler.pkl", "meta_scaler.pkl",
            "explanation_baseline.pkl",
        ],
        "sklearn_version": sklearn.__version__,
        "channel_unit": "MHz",
        "isolation_forest": "fit on Legit rows only, including every out-of-fold split",
        "meta_features": ["rf_fake_probability", "knn_fake_probability", "isolation_anomaly"],
        "meta_scaler": "StandardScaler saved as meta_scaler.pkl and applied at prediction",
        "feature_scaler": "StandardScaler saved as scaler.pkl and applied at prediction",
        "label_audit": {key: audit.get(key) for key in (
            "rows_in", "channel_khz_converted", "campus_rows_relabeled_legit",
            "pillai_rows_relabeled_legit", "open_placeholder_relabeled_fake",
            "real_legit_rows", "real_fake_rows",
        )},
        "metrics_withheld": withheld,
        "reason": getattr(detector, "metrics_reason_", ""),
        "real_scans_required": REAL_SCAN_REQUIREMENT,
        "supervised_labels": (
            "Remaining Fake rows are hand-typed placeholder MACs. "
            "The supervised models can learn that synthetic pattern. "
            "They have not been shown a captured evil twin that clones a real AP."
        ),
    }
    with open("model_card.json", "w", encoding="utf-8") as handle:
        json.dump(card, handle, indent=2)
    print("Saved model_card.json")
    if withheld:
        print("Detection metrics withheld. Run evaluation.py for the quality check.")
        print(REAL_SCAN_REQUIREMENT)
    else:
        print("Labeled file passed the quality gate. Run evaluation.py for held-out scores.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
