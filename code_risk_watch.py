#!/usr/bin/env python3
"""
Novelty #2 - Real-Time CI/CD Integrated Security Detection (local watch mode).

Complements code_risk_scan.py: instead of waiting for a CI job or a
manual scan, this watches the working tree with `watchdog` and
re-analyzes a file the moment it's saved, printing findings inline --
"during code generation and integration", not after the fact. Meant
to be run alongside an AI pair-programming session.

Usage:
    python code_risk_watch.py --path .
"""

import argparse
import os
import sys
import time

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from code_risk_analyzer.engine import CodeRiskEngine
from code_risk_analyzer import db


class RiskWatchHandler(FileSystemEventHandler):
    def __init__(self, engine: CodeRiskEngine):
        self.engine = engine
        self._last_run = {}

    def _should_handle(self, path):
        if not path.endswith(".py"):
            return False
        now = time.time()
        if now - self._last_run.get(path, 0) < 1.0:  # debounce
            return False
        self._last_run[path] = now
        return True

    def _rescan_file(self, path):
        report = self.engine._analyze_python_file(path)
        if report is None:
            return

        fp = report["fingerprint"]
        rel = report["file_path"]
        stamp = time.strftime("%H:%M:%S")

        if not report["findings"]:
            print(f"[{stamp}] ✅ {rel}  score={fp['composite_score']} ({fp['grade']}) -- no new findings")
            return

        print(f"[{stamp}] ⚠️  {rel}  score={fp['composite_score']} ({fp['grade']}) -- "
              f"{len(report['findings'])} finding(s):")
        for finding in report["findings"]:
            print(f"          L{finding['line']:<5} [{finding['severity'].upper():<8}] "
                  f"{finding['rule_id']:<16} {finding['message']}")

    def on_modified(self, event):
        if event.is_directory or not self._should_handle(event.src_path):
            return
        self._rescan_file(event.src_path)

    def on_created(self, event):
        if event.is_directory or not self._should_handle(event.src_path):
            return
        self._rescan_file(event.src_path)


def main():
    parser = argparse.ArgumentParser(description="Real-time local code-risk watcher")
    parser.add_argument("--path", default=".", help="Directory to watch")
    args = parser.parse_args()

    path = os.path.abspath(args.path)
    engine = CodeRiskEngine(path)

    print(f"👁  Watching {path} for AI-generated code risk in real time (Ctrl+C to stop)...")

    handler = RiskWatchHandler(engine)
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    sys.exit(main())
