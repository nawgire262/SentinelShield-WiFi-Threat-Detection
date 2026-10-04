import csv
import os
import threading
from datetime import datetime
from database_manager import save_alert


class AlertLogger:
    FIELDNAMES = ["Time", "SSID", "BSSID", "Risk", "Reason"]
    _write_lock = threading.Lock()

    def __init__(self):

        self.file = "alert_history.csv"

        if not os.path.exists(self.file):

            with open(self.file, "w", newline="", encoding="utf-8") as f:

                writer = csv.writer(f)

                writer.writerow(self.FIELDNAMES)

    def log_alert(
        self,
        ssid,
        bssid,
        risk,
        reason
    ):

        # A scan runs in a worker thread, so serialize writes to avoid a
        # partially written CSV when another scan is started immediately.
        with self._write_lock:
            with open(self.file, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ssid,
                    bssid,
                    round(float(risk), 1),
                    reason,
                ])
        save_alert({"ssid": ssid, "alert_type": "Threat Detection", "severity": "CRITICAL" if float(risk) >= 75 else "HIGH", "description": reason})
