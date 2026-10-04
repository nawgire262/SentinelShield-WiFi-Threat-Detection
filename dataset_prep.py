"""Clean the labeled Wi-Fi table before training or evaluation.

`wifi_dataset.csv` has a header and no rows. The labeled rows live in
`training_dataset.csv`. This module does not invent scans. It only
normalizes units and corrects labels that the rows themselves contradict.

Channel: values at or above 10000 are kHz (2412000 -> 2412 MHz). Live
inference already feeds frequency in MHz.

Labels:
- Secured multi-AP rows (WPA2/WPA3, RSSI no stronger than -55 dBm,
  AP_Count >= 4, four or more rows for that SSID, real MAC) labeled
  Fake are treated as a normal campus deployment and relabeled Legit.
  That covers the Pillai rows and the same pattern on Guest and PHCET.
- Hand-typed placeholder MACs (AA:BB:CC:..., 11:22:33:..., and the
  same textbook sequences) are marked synthetic. An OPEN placeholder
  with a strong signal and high Signal_Var that was labeled Legit is
  relabeled Fake so it matches the other hand-typed OPEN rows.
- Placeholder rows are not field-captured evil twins. Evaluation must
  not turn them into a detection score.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

LABELED_DATASET = "training_dataset.csv"
MIN_REAL_PER_CLASS = 15
REAL_SCAN_REQUIREMENT = (
    "Real scans are still required before any detection score is meaningful: "
    "capture your own hotspot cloned as an evil twin and label those BSSIDs Fake, "
    "and capture ordinary campus or office scans, including dense multi-AP SSIDs, and label those Legit. "
    "Append the rows to training_dataset.csv and run evaluation.py again."
)

_PLACEHOLDER_PREFIXES = (
    "AA:BB:CC:",
    "DD:EE:FF:",
    "11:22:33:",
    "22:33:44:",
    "33:44:55:",
    "44:55:66:",
    "00:11:22:",
    "66:77:88:",
)


def canonical_bssid(value: object) -> str:
    text = str(value or "").strip().upper().rstrip(":")
    parts = [part for part in text.split(":") if part]
    if len(parts) == 6 and all(len(part) == 2 and all(ch in "0123456789ABCDEF" for ch in part) for part in parts):
        return ":".join(parts)
    return text


def is_placeholder_mac(value: object) -> bool:
    mac = canonical_bssid(value)
    return any(mac.startswith(prefix) for prefix in _PLACEHOLDER_PREFIXES)


def canonical_security(value: object) -> str:
    text = str(value or "OPEN").strip().upper()
    if text in {"OPEN", "NONE", "OPN", ""}:
        return "OPEN"
    if "WPA3" in text:
        return "WPA3"
    if "WPA" in text:
        return "WPA2"
    if "WEP" in text:
        return "WEP"
    return text


def channel_to_mhz(value: float) -> float:
    """Return a Wi-Fi frequency in MHz. kHz exports are divided by 1000."""
    frequency = float(value)
    if frequency >= 10000:
        frequency = frequency / 1000.0
    return round(frequency, 3)


def _usable_labeled_file(path: Path) -> bool:
    if not path.is_file() or path.stat().st_size == 0:
        return False
    try:
        frame = pd.read_csv(path, on_bad_lines="skip")
    except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError):
        return False
    return not frame.empty and "Label" in frame.columns and frame["Label"].notna().any()


def resolve_dataset(path: str | Path | None = None) -> Path:
    """Use the requested file when it has labels, otherwise the labeled CSV."""
    requested = Path(path) if path else Path(LABELED_DATASET)
    if _usable_labeled_file(requested):
        return requested
    fallback = Path(LABELED_DATASET)
    if requested.resolve() != fallback.resolve() and _usable_labeled_file(fallback):
        return fallback
    return requested


def prepare_dataset(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    data = frame.copy()
    rows_in = int(len(data))
    for column in ("SSID", "BSSID", "Security", "Label"):
        if column not in data.columns:
            data[column] = ""
    data["SSID"] = data["SSID"].fillna("").astype(str)
    data["BSSID"] = data["BSSID"].map(canonical_bssid)
    data["Security"] = data["Security"].map(canonical_security)
    data["label_original"] = data["Label"].fillna("").astype(str).str.strip()
    data["Label"] = data["label_original"].replace({"SAFE": "Legit", "ROGUE": "Fake"})
    data = data[data["Label"].isin(["Legit", "Fake"])].copy()
    for column in ("RSSI", "Channel", "AP_Count", "Signal_Var"):
        data[column] = pd.to_numeric(data[column], errors="coerce")
    data = data.dropna(subset=["RSSI", "Channel", "AP_Count", "Signal_Var"]).copy()
    data["channel_was_khz"] = data["Channel"] >= 10000
    data.loc[data["channel_was_khz"], "Channel"] = data.loc[data["channel_was_khz"], "Channel"] / 1000.0
    data["Channel"] = data["Channel"].round(3)
    data["synthetic_placeholder"] = data["BSSID"].map(is_placeholder_mac)
    data["label_action"] = "kept"
    ssid_key = data["SSID"].str.strip().str.casefold()
    ssid_counts = ssid_key.value_counts()
    campus = (
        (data["Label"] == "Fake")
        & (data["Security"] != "OPEN")
        & (data["RSSI"] <= -55)
        & (data["AP_Count"] >= 4)
        & ssid_key.map(ssid_counts).ge(4)
        & ~data["synthetic_placeholder"]
    )
    data.loc[campus, "Label"] = "Legit"
    data.loc[campus, "label_action"] = "relabeled_legit_campus"
    inconsistent = (
        (data["Label"] == "Legit")
        & data["synthetic_placeholder"]
        & (data["Security"] == "OPEN")
        & (data["Signal_Var"] >= 15)
        & (data["RSSI"] >= -50)
    )
    data.loc[inconsistent, "Label"] = "Fake"
    data.loc[inconsistent, "label_action"] = "relabeled_fake_open_placeholder"
    data = data.reset_index(drop=True)
    real = data.loc[~data["synthetic_placeholder"]]
    audit = {
        "rows_in": rows_in,
        "rows_out": int(len(data)),
        "channel_khz_converted": int(data["channel_was_khz"].sum()),
        "campus_rows_relabeled_legit": int((data["label_action"] == "relabeled_legit_campus").sum()),
        "pillai_rows_relabeled_legit": int(
            ((data["SSID"].str.strip().str.casefold() == "pillai") & (data["label_action"] == "relabeled_legit_campus")).sum()
        ),
        "open_placeholder_relabeled_fake": int((data["label_action"] == "relabeled_fake_open_placeholder").sum()),
        "synthetic_placeholder_rows": int(data["synthetic_placeholder"].sum()),
        "real_legit_rows": int((real["Label"] == "Legit").sum()),
        "real_fake_rows": int((real["Label"] == "Fake").sum()),
        "labels_after": {str(label): int(count) for label, count in data["Label"].value_counts().items()},
    }
    return data, audit


def training_rows(frame: pd.DataFrame) -> pd.DataFrame:
    """Drop placeholder MACs labeled Legit. They are not real normal scans."""
    placeholder = frame["synthetic_placeholder"].astype(bool) if "synthetic_placeholder" in frame.columns else False
    drop = placeholder & (frame["Label"] == "Legit")
    return frame.loc[~drop].reset_index(drop=True)


def quality_gate(frame: pd.DataFrame) -> tuple[bool, str]:
    """Refuse a detection score when the positive class is synthetic or tiny."""
    work = frame.copy()
    if "synthetic_placeholder" not in work.columns:
        work["synthetic_placeholder"] = False
    work["synthetic_placeholder"] = work["synthetic_placeholder"].astype(bool)
    real = work.loc[~work["synthetic_placeholder"]]
    real_fake = int((real["Label"] == "Fake").sum())
    real_legit = int((real["Label"] == "Legit").sum())
    fake_rows = work.loc[work["Label"] == "Fake"]
    placeholder_fake = int(fake_rows["synthetic_placeholder"].sum()) if len(fake_rows) else 0
    reasons = []
    if real_fake < MIN_REAL_PER_CLASS or real_legit < MIN_REAL_PER_CLASS:
        reasons.append(
            f"field-captured class counts are Legit={real_legit} and Fake={real_fake}; "
            f"at least {MIN_REAL_PER_CLASS} non-placeholder rows are required in each class."
        )
    if len(fake_rows) and placeholder_fake / len(fake_rows) > 0.5:
        reasons.append(
            f"{placeholder_fake} of {len(fake_rows)} Fake rows are hand-typed placeholder MACs, not captured evil twins."
        )
    if reasons:
        return False, " ".join(reasons)
    return True, ""


def load_clean_dataset(path: str | Path | None = None) -> tuple[pd.DataFrame, dict]:
    requested = Path(path) if path else Path(LABELED_DATASET)
    source = resolve_dataset(requested)
    if not _usable_labeled_file(source):
        empty = pd.DataFrame(columns=["SSID", "BSSID", "RSSI", "Channel", "Security", "AP_Count", "Signal_Var", "Label"])
        return empty, {"rows_in": 0, "requested": str(requested), "source": str(source), "real_fake_rows": 0, "real_legit_rows": 0}
    frame, audit = prepare_dataset(pd.read_csv(source, on_bad_lines="skip"))
    audit["requested"] = str(requested)
    audit["source"] = str(source)
    return frame, audit
