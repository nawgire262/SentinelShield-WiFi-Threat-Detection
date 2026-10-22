"""Conservative SentinelShield dataset migration and quality gate.

Does not infer or rewrite ground-truth labels. Legacy rows are retained for
review, while only explicitly field-verified rows are eligible for research.
"""
from pathlib import Path
import json
import re
import pandas as pd

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "training_dataset.csv"
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
REPORT_DIR = ROOT / "data" / "reports"
LEGACY_REVIEW = PROCESSED_DIR / "legacy_dataset_for_review.csv"
CLEAN_FILE = PROCESSED_DIR / "clean_wifi_dataset.csv"
REPORT_FILE = REPORT_DIR / "dataset_quality_report.json"

MAC_RE = re.compile(r"^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$")
PLACEHOLDER_PREFIXES = ("AA:BB:CC:", "DD:EE:FF:", "11:22:33:", "22:33:44:",
                        "33:44:55:", "44:55:66:", "00:11:22:", "66:77:88:")


def frequency_to_channel(freq):
    """Convert a known Wi-Fi center frequency in MHz to a channel; else NA."""
    if pd.isna(freq):
        return pd.NA
    f = float(freq)
    if abs(f - 2484) < 2:
        return 14
    if 2412 <= f <= 2472 and abs((f - 2407) / 5 - round((f - 2407) / 5)) < 0.2:
        return int(round((f - 2407) / 5))
    if 5000 <= f < 5925 and abs((f - 5000) / 5 - round((f - 5000) / 5)) < 0.2:
        return int(round((f - 5000) / 5))
    if 5925 <= f <= 7125 and abs((f - 5950) / 5 - round((f - 5950) / 5)) < 0.2:
        return int(round((f - 5950) / 5))
    return pd.NA


def main():
    for folder in (RAW_DIR, PROCESSED_DIR, REPORT_DIR):
        folder.mkdir(parents=True, exist_ok=True)
    if not SOURCE.exists():
        raise FileNotFoundError(f"Expected dataset not found: {SOURCE}")
    backup = ROOT / "training_dataset_backup.csv"
    if not backup.exists():
        backup.write_bytes(SOURCE.read_bytes())

    df = pd.read_csv(SOURCE, dtype={"BSSID": "string"})
    original_rows = len(df)
    capture_file = RAW_DIR / "wifi_observations.csv"
    if capture_file.exists() and capture_file.stat().st_size > 0:
        captured = pd.read_csv(capture_file, dtype={"BSSID": "string"})
        captured["source_file"] = capture_file.name
        df["source_file"] = SOURCE.name
        df = pd.concat([df, captured], ignore_index=True, sort=False)
    required = ["SSID", "BSSID", "RSSI", "Channel", "Security", "AP_Count", "Signal_Var", "Label"]
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in source: {missing}")

    legacy = df.copy()
    if "source_file" not in legacy.columns:
        legacy["source_file"] = SOURCE.name
    legacy["BSSID"] = legacy["BSSID"].fillna("").astype(str).str.strip().str.upper().str.rstrip(":")
    legacy["SSID"] = legacy["SSID"].fillna("").astype(str).str.strip()
    legacy["Security"] = legacy["Security"].fillna("").astype(str).str.strip().str.upper()
    legacy["Label"] = legacy["Label"].fillna("").astype(str).str.strip().str.title()
    for col in ("RSSI", "Channel", "AP_Count", "Signal_Var"):
        legacy[col] = pd.to_numeric(legacy[col], errors="coerce")

    # New captures have an explicit Frequency_MHz field. Legacy files stored
    # frequency under Channel (sometimes MHz, sometimes kHz); migrate only
    # values that clearly look like frequencies and do not guess a band for
    # channel-only values.
    raw_channel = legacy["Channel"].copy()
    if "Frequency_MHz" in legacy.columns:
        legacy["Frequency_MHz"] = pd.to_numeric(legacy["Frequency_MHz"], errors="coerce")
        freq_missing = legacy["Frequency_MHz"].isna()
        legacy.loc[freq_missing & raw_channel.ge(1000), "Frequency_MHz"] = raw_channel[freq_missing & raw_channel.ge(1000)].where(raw_channel[freq_missing & raw_channel.ge(1000)] < 10000, raw_channel[freq_missing & raw_channel.ge(1000)] / 1000.0)
        known_freq = legacy["Frequency_MHz"].notna()
        legacy.loc[known_freq, "Channel"] = legacy.loc[known_freq, "Frequency_MHz"].map(frequency_to_channel)
    else:
        legacy["Frequency_MHz"] = raw_channel.copy()
        legacy.loc[legacy["Frequency_MHz"].ge(10000), "Frequency_MHz"] = legacy.loc[legacy["Frequency_MHz"].ge(10000), "Frequency_MHz"] / 1000.0
        legacy.loc[~legacy["Frequency_MHz"].between(1000, 10000), "Frequency_MHz"] = pd.NA
        known_freq = legacy["Frequency_MHz"].notna()
        legacy.loc[known_freq, "Channel"] = legacy.loc[known_freq, "Frequency_MHz"].map(frequency_to_channel)
        legacy.loc[~known_freq, "Channel"] = pd.NA
    legacy["Channel"] = pd.to_numeric(legacy["Channel"], errors="coerce").astype("Int64")
    legacy["Timestamp"] = legacy.get("Timestamp", pd.Series([""] * len(legacy))).fillna("").astype(str)
    legacy["Session_ID"] = legacy.get("Session_ID", pd.Series([""] * len(legacy))).fillna("").astype(str)
    # Legacy rows lack capture provenance; never silently upgrade them.
    if "label_source" not in legacy.columns:
        legacy["label_source"] = "legacy_unverified"
    else:
        legacy["label_source"] = legacy["label_source"].fillna("legacy_unverified").astype(str)
    legacy["synthetic_placeholder"] = legacy["BSSID"].apply(
        lambda x: any(x.startswith(p) for p in PLACEHOLDER_PREFIXES)
    )
    legacy["label_verified"] = legacy["label_source"].str.lower().eq("field_verified")

    # Preserve the complete migrated legacy data for manual review.
    legacy.to_csv(LEGACY_REVIEW, index=False)

    valid_structure = (
        legacy["SSID"].ne("")
        & legacy["BSSID"].str.match(MAC_RE, na=False)
        & legacy["RSSI"].between(-110, 0)
        & legacy["Frequency_MHz"].between(2000, 8000)
        & legacy["AP_Count"].ge(1)
        & legacy["Signal_Var"].ge(0)
        & legacy["Label"].isin(["Legit", "Fake"])
        & legacy["Channel"].notna()
    )
    verified = legacy["label_verified"] & ~legacy["synthetic_placeholder"]
    clean = legacy.loc[valid_structure & verified].copy()
    clean = clean.drop_duplicates().reset_index(drop=True)
    clean.to_csv(CLEAN_FILE, index=False)

    counts = clean["Label"].value_counts().to_dict() if not clean.empty else {}
    report = {
        "source_file": SOURCE.name,
        "capture_file_included": capture_file.exists() and capture_file.stat().st_size > 0,
        "backup_file": backup.name,
        "input_rows": int(original_rows),
        "legacy_review_rows": int(len(legacy)),
        "structurally_valid_rows": int(valid_structure.sum()),
        "verified_non_placeholder_rows_eligible_for_training": int(len(clean)),
        "verified_label_counts": {str(k): int(v) for k, v in counts.items()},
        "unverified_legacy_rows": int((~legacy["label_verified"]).sum()),
        "placeholder_bssid_rows": int(legacy["synthetic_placeholder"].sum()),
        "rows_with_unknown_channel_mapping": int(legacy["Channel"].isna().sum()),
        "legacy_review_file": str(LEGACY_REVIEW.relative_to(ROOT)),
        "clean_training_file": str(CLEAN_FILE.relative_to(ROOT)),
        "status": "BLOCKED_NO_VERIFIED_DATA" if clean.empty else "REVIEW_CLASS_COUNTS_AND_SPLIT",
        "warning": "No ground-truth labels were inferred or changed. Legacy rows are not considered field-verified.",
    }
    REPORT_FILE.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
