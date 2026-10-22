"""Create a separate, manually verified label file from a raw observation CSV.

Never infers labels from SSID/BSSID/signal/model output. Review every distinct
(session, SSID, BSSID) group and supply evidence notes. Raw input is unchanged.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd

REQUIRED = {"SSID", "BSSID", "Session_ID"}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input", help="Raw observation CSV; will not be modified")
    ap.add_argument("--output", default="data/raw/wifi_observations_annotated.csv")
    args = ap.parse_args()
    source = Path(args.input)
    df = pd.read_csv(source, dtype=str, keep_default_na=False)
    missing = REQUIRED - set(df.columns)
    if missing:
        raise SystemExit(f"Missing required columns: {sorted(missing)}")
    if "Label" not in df: df["Label"] = ""
    if "label_source" not in df: df["label_source"] = "unverified"
    for col in ("experiment_id", "ground_truth_notes", "session_id"):
        if col not in df: df[col] = ""
    keys = ["Session_ID", "SSID", "BSSID"]
    groups = df.groupby(keys, dropna=False, sort=True).groups
    print(f"Input rows: {len(df)}; distinct session/AP groups: {len(groups)}")
    print("Labels must be based on your own documented experiment/authorization, never model predictions.")
    for key, indices in groups.items():
        idx = list(indices)
        old = str(df.loc[idx[0], "Label"]).strip()
        print(f"\nSession={key[0]!r} SSID={key[1]!r} BSSID={key[2]!r} rows={len(idx)} current={old or '(blank)'}")
        print("Choose [l] Legit / [f] Fake (controlled, verified attack only) / [u] Uncertain / [s] skip:")
        choice = input("> ").strip().lower()
        if choice == "s": continue
        mapping = {"l": "Legit", "f": "Fake", "u": "Uncertain"}
        if choice not in mapping:
            print("Invalid choice; left unchanged."); continue
        label = mapping[choice]
        experiment = input("Experiment ID (required): ").strip()
        notes = input("Ground-truth evidence/notes (required): ").strip()
        if not experiment or not notes:
            print("Missing evidence; left unverified."); continue
        df.loc[idx, "Label"] = label
        df.loc[idx, "label_source"] = "field_verified"
        df.loc[idx, "experiment_id"] = experiment
        df.loc[idx, "ground_truth_notes"] = notes
        # Research evaluator expects lowercase session_id.
        df.loc[idx, "session_id"] = str(key[0]).strip()
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False)
    print(f"Saved annotated copy to {out}; raw source was not changed.")
    print("Review all labels and evidence before training. Uncertain rows must not enter binary evaluation.")

if __name__ == "__main__": main()
