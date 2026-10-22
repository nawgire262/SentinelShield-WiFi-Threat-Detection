"""Create leakage-resistant train/validation/test splits from verified captures.

Requires field-verified, non-placeholder labels and groups records by Session_ID
and BSSID. It intentionally refuses to split the unverified legacy dataset.
"""
from pathlib import Path
import json
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "data" / "processed" / "clean_wifi_dataset.csv"
OUT = ROOT / "data" / "processed" / "splits"
MIN_PER_CLASS = 15


def main():
    if not INPUT.exists():
        raise SystemExit("Run clean_research_dataset.py first.")
    df = pd.read_csv(INPUT)
    if df.empty:
        raise SystemExit(
            "SPLIT_BLOCKED: no verified field-captured rows are eligible. "
            "Collect and label authorized real observations first."
        )
    required = {"Label", "BSSID", "Session_ID", "label_source", "synthetic_placeholder"}
    missing = sorted(required - set(df.columns))
    if missing:
        raise SystemExit(f"SPLIT_BLOCKED: missing columns: {missing}")
    if not df["label_source"].astype(str).str.lower().eq("field_verified").all():
        raise SystemExit("SPLIT_BLOCKED: every row must be field_verified.")
    if df["synthetic_placeholder"].astype(bool).any():
        raise SystemExit("SPLIT_BLOCKED: placeholder BSSIDs are present.")
    counts = df["Label"].value_counts()
    if any(int(counts.get(label, 0)) < MIN_PER_CLASS for label in ("Legit", "Fake")):
        raise SystemExit(f"SPLIT_BLOCKED: need at least {MIN_PER_CLASS} rows per class; got {counts.to_dict()}.")
    if df["Session_ID"].astype(str).str.strip().eq("").any():
        raise SystemExit("SPLIT_BLOCKED: Session_ID is missing; label collection sessions first.")

    groups = df["Session_ID"].astype(str) + "::" + df["BSSID"].astype(str)
    first = GroupShuffleSplit(n_splits=1, test_size=0.30, random_state=42)
    train_idx, hold_idx = next(first.split(df, df["Label"], groups))
    train = df.iloc[train_idx].copy()
    hold = df.iloc[hold_idx].copy()
    second = GroupShuffleSplit(n_splits=1, test_size=0.50, random_state=43)
    val_rel, test_rel = next(second.split(hold, hold["Label"], (hold["Session_ID"].astype(str) + "::" + hold["BSSID"].astype(str))))
    val = hold.iloc[val_rel].copy()
    test = hold.iloc[test_rel].copy()

    OUT.mkdir(parents=True, exist_ok=True)
    for name, part in (("train.csv", train), ("validation.csv", val), ("test.csv", test)):
        part.to_csv(OUT / name, index=False)
    report = {"split_method": "grouped by Session_ID + BSSID; 70/15/15 approximate", "random_state": 42,
              "rows": {"train": len(train), "validation": len(val), "test": len(test)},
              "labels": {name: part["Label"].value_counts().to_dict() for name, part in (("train", train), ("validation", val), ("test", test))},
              "warning": "Inspect each partition for both classes; grouped splitting can produce imbalanced partitions on small datasets."}
    (OUT / "split_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
