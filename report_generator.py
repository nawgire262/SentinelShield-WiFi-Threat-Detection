"""Generate PDF-only SentinelShield threat reports."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

import pandas as pd
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.barcharts import VerticalBarChart


class ReportGenerator:
    """Create a readable PDF from the latest scan and persisted alert history."""

    def __init__(self, alert_file="alert_history.csv", scan_file="current_scan.csv", output_dir="reports"):
        self.alert_file = Path(alert_file)
        self.scan_file = Path(scan_file)
        self.output_dir = Path(output_dir)

    @staticmethod
    def _load_csv(path: Path) -> pd.DataFrame:
        try:
            return pd.read_csv(path, on_bad_lines="skip") if path.is_file() else pd.DataFrame()
        except (OSError, pd.errors.EmptyDataError, pd.errors.ParserError, UnicodeDecodeError):
            return pd.DataFrame()

    def load_alerts(self) -> pd.DataFrame:
        return self._load_csv(self.alert_file)

    def load_scan_data(self) -> pd.DataFrame:
        return self._load_csv(self.scan_file)

    @staticmethod
    def _safe_text(value, limit=120) -> str:
        if pd.isna(value):
            return ""
        text = str(value).replace("\r", " ").replace("\n", " ")
        return escape(text[:limit])

    @classmethod
    def _table(cls, frame: pd.DataFrame, columns, page_width, styles, max_rows=30):
        """Create a wrapped table that stays within the printable page width."""
        available = [name for name in columns if name in frame.columns]
        if not available or frame.empty:
            return None

        # Keep column widths equal and make cell content wrap instead of overflowing.
        usable_width = page_width - 0.72 * inch
        col_width = usable_width / len(available)
        cell_style = ParagraphStyle(
            "ReportCell", parent=styles["BodyText"], fontName="Helvetica",
            fontSize=7, leading=8, alignment=TA_LEFT, spaceAfter=0,
        )
        header_style = ParagraphStyle(
            "ReportHeader", parent=cell_style, fontName="Helvetica-Bold",
            textColor=colors.white,
        )
        rows = [[Paragraph(cls._safe_text(name, 48), header_style) for name in available]]
        for _, row in frame[available].head(max_rows).fillna("").iterrows():
            rows.append([Paragraph(cls._safe_text(value), cell_style) for value in row.tolist()])

        table = Table(rows, colWidths=[col_width] * len(available), repeatRows=1, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e78")),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#b7c9d6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#edf4f8")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    @staticmethod
    def _risk_series(scan: pd.DataFrame) -> pd.Series:
        if "Combined_Risk" in scan.columns:
            return pd.to_numeric(scan["Combined_Risk"], errors="coerce").dropna()
        if "ML_Risk" in scan.columns:
            return pd.to_numeric(scan["ML_Risk"], errors="coerce").dropna()
        return pd.Series(dtype=float)

    def generate_pdf_report(self, scan_data=None) -> str:
        """Generate and return the path to a complete PDF report.

        ``scan_data`` can be the live scan DataFrame supplied by the dashboard.
        When omitted, the report reads ``scan_file`` from disk.
        """
        alerts = self.load_alerts()
        scan = pd.DataFrame(scan_data).copy() if scan_data is not None else self.load_scan_data()
        scan = scan.replace({pd.NA: None})
        timestamp = datetime.now()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / f"Threat_Report_{timestamp:%Y%m%d_%H%M%S}.pdf"

        page_size = landscape(A4)
        page_width, _ = page_size
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="ReportSubtitle", parent=styles["Normal"],
            textColor=colors.HexColor("#536579"), fontSize=9, leading=12,
        ))
        elements = [
            Paragraph("SentinelShield Threat Detection Report", styles["Title"]),
            Paragraph(f"Generated: {timestamp:%Y-%m-%d %H:%M:%S}", styles["ReportSubtitle"]),
            Spacer(1, 16),
            Paragraph("Executive Summary", styles["Heading2"]),
        ]

        threat_levels = scan["Threat_Level"].astype(str).str.upper() if "Threat_Level" in scan else pd.Series(dtype=str)
        high_critical = int(threat_levels.isin(["HIGH", "CRITICAL"]).sum())
        critical = int(threat_levels.eq("CRITICAL").sum())
        risks = self._risk_series(scan)
        avg_risk = float(risks.mean()) if not risks.empty else 0.0
        max_risk = float(risks.max()) if not risks.empty else 0.0
        summary_rows = [
            ["Metric", "Result", "Metric", "Result"],
            ["Networks scanned", str(len(scan)), "Recorded alerts", str(len(alerts))],
            ["High / critical threats", str(high_critical), "Critical threats", str(critical)],
            ["Average risk", f"{avg_risk:.1f}%", "Maximum risk", f"{max_risk:.1f}%"],
        ]
        summary_table = Table(summary_rows, colWidths=[1.8 * inch, 1.1 * inch, 1.8 * inch, 1.1 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f4e78")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b7c9d6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#edf4f8")]),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.extend([summary_table, Spacer(1, 14)])

        if not threat_levels.empty:
            counts = threat_levels.value_counts()
            chart = VerticalBarChart()
            chart.x, chart.y, chart.width, chart.height = 35, 20, 480, 125
            chart.data = [counts.tolist()]
            chart.categoryAxis.categoryNames = counts.index.tolist()
            chart.valueAxis.valueMin = 0
            chart.valueAxis.valueMax = max(1, int(counts.max()) + 1)
            chart.valueAxis.valueStep = max(1, int(chart.valueAxis.valueMax / 5))
            chart.barWidth = min(35, 280 / max(1, len(counts)))
            chart.bars[0].fillColor = colors.HexColor("#d9534f")
            drawing = Drawing(550, 165)
            drawing.add(chart)
            elements.extend([Paragraph("Threat-Level Distribution", styles["Heading2"]), drawing, Spacer(1, 8)])

        elements.append(Paragraph("Current Scan Details", styles["Heading2"]))
        scan_table = self._table(
            scan,
            ["SSID", "BSSID", "RSSI", "Channel", "Frequency_MHz", "Security", "ML_Risk", "Combined_Risk", "Threat_Level", "Reason"],
            page_width, styles, max_rows=100,
        )
        elements.append(scan_table or Paragraph("No completed scan data is available yet.", styles["Normal"]))
        if len(scan) > 100:
            elements.append(Paragraph(f"Showing first 100 of {len(scan)} scanned networks.", styles["Italic"]))

        cloud_table = self._table(
            scan,
            ["SSID", "BSSID", "VirusTotal_Risk", "AbuseIPDB_Risk", "BSSID_Reputation", "OpenPhish_Risk", "Cloud_Risk"],
            page_width, styles, max_rows=50,
        )
        if cloud_table is not None:
            elements.extend([Spacer(1, 14), Paragraph("Cloud Threat Intelligence", styles["Heading2"]), cloud_table])

        elements.extend([
            Spacer(1, 18),
            Paragraph("Alert History", styles["Heading2"]),
            Paragraph(f"Total recorded alerts: {len(alerts)}", styles["Normal"]),
            Spacer(1, 6),
        ])
        alert_table = self._table(alerts, ["Time", "Timestamp", "SSID", "BSSID", "Risk", "Threat_Level", "Reason", "Message"], page_width, styles, max_rows=100)
        elements.append(alert_table or Paragraph("No alerts have been recorded.", styles["Normal"]))
        if len(alerts) > 100:
            elements.append(Paragraph(f"Showing first 100 of {len(alerts)} alerts.", styles["Italic"]))

        def add_page_number(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#536579"))
            canvas.drawString(0.36 * inch, 0.22 * inch, "SentinelShield | Generated report")
            canvas.drawRightString(page_width - 0.36 * inch, 0.22 * inch, f"Page {doc.page}")
            canvas.restoreState()

        document = SimpleDocTemplate(
            str(output_path), pagesize=page_size,
            rightMargin=0.36 * inch, leftMargin=0.36 * inch,
            topMargin=0.45 * inch, bottomMargin=0.45 * inch,
            title="SentinelShield Threat Detection Report",
            author="SentinelShield",
        )
        document.build(elements, onFirstPage=add_page_number, onLaterPages=add_page_number)
        if not output_path.is_file() or output_path.stat().st_size < 500:
            raise RuntimeError("PDF report generation did not produce a valid report file.")
        return str(output_path.resolve())
