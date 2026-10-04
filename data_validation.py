"""Repair and normalize SentinelShield CSV stores before they are consumed."""

from pathlib import Path
import pandas as pd

ALERT_COLUMNS = ["Time", "SSID", "BSSID", "Risk", "Reason"]
SCAN_COLUMNS = ["SSID", "BSSID", "RSSI", "Channel", "Security", "Threat_Score", "Signal_Pattern_Score", "ML_Risk", "Combined_Risk", "Threat_Level"]
TRAINING_COLUMNS = ["SSID", "BSSID", "RSSI", "Channel", "Security", "AP_Count", "Signal_Var", "Label"]


def _read(path):
    try:
        return pd.read_csv(path, on_bad_lines="skip", engine="python") if Path(path).exists() else pd.DataFrame()
    except (OSError, UnicodeDecodeError, pd.errors.ParserError, pd.errors.EmptyDataError):
        return pd.DataFrame()


def _write(frame, path):
    frame.to_csv(path, index=False)


def repair_project_data(base_path="."):
    """Repair schemas, invalid numeric values, and duplicate CSV records."""
    base = Path(base_path)
    report = {}
    alerts = _read(base / "alert_history.csv")
    alerts = alerts.reindex(columns=ALERT_COLUMNS)
    alerts["Risk"] = pd.to_numeric(alerts["Risk"], errors="coerce").clip(0, 100)
    alerts = alerts.dropna(subset=["Time", "SSID", "BSSID", "Risk"]).drop_duplicates().sort_values("Time")
    _write(alerts, base / "alert_history.csv")
    report["alert_history"] = len(alerts)

    scan = _read(base / "current_scan.csv")
    if not scan.empty:
        for column in SCAN_COLUMNS:
            if column not in scan:
                scan[column] = "" if column not in {"RSSI", "Channel", "Threat_Score", "Signal_Pattern_Score", "ML_Risk", "Combined_Risk"} else 0
        for column in ["Threat_Score", "Signal_Pattern_Score", "ML_Risk", "Combined_Risk"]:
            scan[column] = pd.to_numeric(scan[column], errors="coerce").fillna(0).clip(0, 100)
        scan = scan.dropna(subset=["SSID", "BSSID"]).drop_duplicates(subset=["BSSID"], keep="last")
        _write(scan, base / "current_scan.csv")
    report["current_scan"] = len(scan)

    source = _read(base / "training_dataset.csv")
    if source.empty:
        source = _read(base / "wifi_dataset.csv")
    source = source.reindex(columns=TRAINING_COLUMNS)
    for column in ["RSSI", "Channel", "AP_Count", "Signal_Var"]:
        source[column] = pd.to_numeric(source[column], errors="coerce").fillna(0)
    source["Security"] = source["Security"].fillna("OPEN").astype(str).str.upper()
    source["Label"] = source["Label"].replace({"SAFE": "Legit", "MEDIUM": "Fake", "HIGH": "Fake", "CRITICAL": "Fake"}).fillna("Legit")
    source = source.dropna(subset=["SSID", "BSSID"]).drop_duplicates(subset=["BSSID"], keep="last")
    _write(source, base / "training_dataset.csv")
    report["training_dataset"] = len(source)
    return report
