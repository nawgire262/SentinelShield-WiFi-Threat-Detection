"""Train SentinelShield's unsupervised Wi-Fi anomaly detector.

Usage: python train_isolation_forest.py [historical_csv]
"""
import sys
import pandas as pd

from ai_models.isolation_forest_detector import IsolationForestDetector

def main() -> None:
    dataset = sys.argv[1] if len(sys.argv) > 1 else "wifi_dataset.csv"
    # The Python parser honours on_bad_lines for mixed historical exports;
    # malformed legacy rows must not prevent model refreshes.
    data = pd.read_csv(dataset, on_bad_lines="skip", engine="python")
    if data.empty:
        raise ValueError(f"No valid training records found in {dataset}.")
    detector = IsolationForestDetector().train(data)
    path = detector.save()
    print(f"Trained Isolation Forest on {len(data)} historical rows using {detector.feature_names}.")
    print(f"Saved model to {path}")


if __name__ == "__main__":
    main()
