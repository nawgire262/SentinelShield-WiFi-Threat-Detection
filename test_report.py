"""Smoke test for PDF-only report generation."""

from pathlib import Path
from tempfile import TemporaryDirectory

import pandas as pd

from report_generator import ReportGenerator


def test_generate_pdf_report_with_scan_and_alerts():
    with TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        alerts = pd.DataFrame([{
            "Time": "2026-10-19 10:00:00", "SSID": "Test <network>",
            "BSSID": "00:11:22:33:44:55", "Risk": 90, "Reason": "Test & validate",
        }])
        alerts.to_csv(root / "alerts.csv", index=False)
        scan = pd.DataFrame([{
            "SSID": "Campus WiFi", "BSSID": "AA:BB:CC:DD:EE:FF", "RSSI": -52,
            "Channel": 6, "Frequency_MHz": 2437, "Security": "WPA2",
            "ML_Risk": 12, "Combined_Risk": 18, "Threat_Level": "LOW",
        }])
        generator = ReportGenerator(alert_file=root / "alerts.csv", scan_file=root / "missing.csv", output_dir=root / "reports")
        path = Path(generator.generate_pdf_report(scan))
        assert path.is_file()
        assert path.suffix.lower() == ".pdf"
        assert path.stat().st_size > 500
        assert path.read_bytes().startswith(b"%PDF-")


def test_generate_pdf_report_when_inputs_are_missing():
    with TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)
        path = Path(ReportGenerator(
            alert_file=root / "missing_alerts.csv",
            scan_file=root / "missing_scan.csv",
            output_dir=root / "reports",
        ).generate_pdf_report())
        assert path.is_file()
        assert path.read_bytes().startswith(b"%PDF-")
