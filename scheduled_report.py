"""Run SentinelShield report generation on a daily schedule."""

from __future__ import annotations

import time

try:
    import schedule
except ImportError:
    schedule = None

from report_generator import ReportGenerator


def create_daily_report() -> None:
    """Generate both supported report formats without sharing mutable globals."""
    reporter = ReportGenerator()
    reporter.generate_pdf_report()
    reporter.generate_excel_report()
    print("Daily report generated")


def run_scheduler(report_time: str = "18:00", poll_seconds: float = 60.0) -> None:
    if schedule is None:
        raise RuntimeError("The optional 'schedule' package is required to run scheduled reports.")
    schedule.every().day.at(report_time).do(create_daily_report)
    while True:
        schedule.run_pending()
        time.sleep(max(1.0, poll_seconds))


def main() -> None:
    try:
        run_scheduler()
    except RuntimeError as exc:
        print(exc)


if __name__ == "__main__":
    main()
