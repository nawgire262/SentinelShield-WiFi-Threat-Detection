"""Reliable local and optional remote threat notifications.

Desktop alerts work locally.  Email, Telegram, and Twilio SMS are deliberately
disabled until their environment variables are configured; credentials are
never stored in project files.
"""

from __future__ import annotations

import json
import logging
import os
import smtplib
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime
from email.message import EmailMessage

from runtime_config import load_runtime_config

try:
    from plyer import notification
except ImportError:  # Keeps scanning functional if desktop notifications are absent.
    notification = None


LOGGER = logging.getLogger(__name__)


class NotificationManager:
    def __init__(self):
        self.last_alert = None
        self._last_by_key: dict[str, float] = {}
        configured_cooldown = load_runtime_config()["notifications"]["cooldown_seconds"]
        self.cooldown_seconds = max(0, int(os.getenv("SENTINELSHIELD_ALERT_COOLDOWN_SECONDS", configured_cooldown)))

    def notify(self, title, message, timeout=10) -> bool:
        """Send a Windows desktop notification without allowing failures to stop scans."""
        if sys.platform == "win32":
            # Plyer's legacy Windows tray backend fails in many modern Windows
            # sessions (often asynchronously), so use the OS Forms tray API.
            # It runs in its own short-lived process and can never block scans.
            try:
                ps_title = json.dumps(str(title))
                ps_message = json.dumps(str(message))
                script = (
                    "Add-Type -AssemblyName System.Windows.Forms; "
                    "Add-Type -AssemblyName System.Drawing; "
                    "$n=New-Object System.Windows.Forms.NotifyIcon; "
                    "$n.Icon=[System.Drawing.SystemIcons]::Information; "
                    f"$n.BalloonTipTitle={ps_title}; $n.BalloonTipText={ps_message}; "
                    "$n.Visible=$true; "
                    f"$n.ShowBalloonTip({max(1000, int(timeout) * 1000)}); "
                    f"Start-Sleep -Milliseconds {max(1500, int(timeout) * 1000)}; $n.Dispose()"
                )
                subprocess.Popen(
                    ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
                )
                return True
            except (OSError, ValueError) as exc:
                LOGGER.warning("Native Windows notification failed: %s", exc)
        if notification is None:
            LOGGER.warning("Desktop notification skipped: install the 'plyer' package.")
            return False
        try:
            notification.notify(title=title, message=message, app_name="SentinelShield", timeout=timeout)
            return True
        except Exception as exc:
            LOGGER.warning("Desktop notification failed: %s", exc)
            return False

    def _is_cooled_down(self, ssid: str, bssid: str) -> bool:
        key = f"{ssid}|{bssid}".lower()
        now = time.monotonic()
        if now - self._last_by_key.get(key, -self.cooldown_seconds - 1) < self.cooldown_seconds:
            return True
        self._last_by_key[key] = now
        return False

    @staticmethod
    def _message(ssid, bssid, risk, reason):
        return (f"Network: {ssid}\nBSSID: {bssid}\nRisk score: {float(risk):.1f}%\n\n"
                f"Reason: {reason}\n\nRecommendation: Do not connect to this Wi-Fi network.")

    def danger_alert(self, ssid, risk, reason, bssid="Unknown"):
        self.notify_threat(ssid, bssid, risk, reason)

    def notify_threat(self, ssid, bssid, risk, reason) -> dict[str, bool]:
        """Dispatch one high-risk event to configured channels, with deduplication."""
        if self._is_cooled_down(str(ssid), str(bssid)):
            return {"desktop": False, "email": False, "telegram": False, "sms": False, "suppressed": True}
        title = "SentinelShield Wi-Fi Threat Alert"
        message = self._message(ssid, bssid, risk, reason)
        result = {
            "desktop": self.notify(title, message, 15),
            "email": self._send_email(title, message),
            "telegram": self._send_telegram(title, message),
            "sms": self._send_sms(title, message),
            "suppressed": False,
        }
        self.last_alert = datetime.now()
        LOGGER.info("Threat alert dispatch for %s/%s: %s", ssid, bssid, result)
        return result

    def _send_email(self, subject: str, body: str) -> bool:
        host, recipient = os.getenv("SENTINELSHIELD_SMTP_HOST"), os.getenv("SENTINELSHIELD_ALERT_EMAIL_TO")
        if not host or not recipient:
            return False
        try:
            port = int(os.getenv("SENTINELSHIELD_SMTP_PORT", "587"))
            sender = os.getenv("SENTINELSHIELD_SMTP_FROM") or os.getenv("SENTINELSHIELD_SMTP_USER")
            if not sender:
                return False
            email = EmailMessage()
            email["Subject"], email["From"], email["To"] = subject, sender, recipient
            email.set_content(body)
            with smtplib.SMTP(host, port, timeout=10) as client:
                if os.getenv("SENTINELSHIELD_SMTP_TLS", "true").lower() != "false":
                    client.starttls()
                if os.getenv("SENTINELSHIELD_SMTP_USER"):
                    client.login(os.environ["SENTINELSHIELD_SMTP_USER"], os.getenv("SENTINELSHIELD_SMTP_PASSWORD", ""))
                client.send_message(email)
            return True
        except (OSError, ValueError, smtplib.SMTPException) as exc:
            LOGGER.warning("Email alert failed: %s", exc)
            return False

    def _send_telegram(self, title: str, body: str) -> bool:
        token, chat_id = os.getenv("SENTINELSHIELD_TELEGRAM_BOT_TOKEN"), os.getenv("SENTINELSHIELD_TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            return False
        try:
            payload = json.dumps({"chat_id": chat_id, "text": f"{title}\n\n{body}"}).encode("utf-8")
            request = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(request, timeout=10) as response:
                return 200 <= response.status < 300
        except (OSError, ValueError) as exc:
            LOGGER.warning("Telegram alert failed: %s", exc)
            return False

    def _send_sms(self, title: str, body: str) -> bool:
        """Send SMS through Twilio when all Twilio environment values are supplied."""
        sid, token = os.getenv("SENTINELSHIELD_TWILIO_ACCOUNT_SID"), os.getenv("SENTINELSHIELD_TWILIO_AUTH_TOKEN")
        sender, recipient = os.getenv("SENTINELSHIELD_TWILIO_FROM"), os.getenv("SENTINELSHIELD_SMS_TO")
        if not all((sid, token, sender, recipient)):
            return False
        try:
            payload = urllib.parse.urlencode({"From": sender, "To": recipient, "Body": f"{title}: {body}"}).encode()
            request = urllib.request.Request(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json", data=payload)
            import base64
            request.add_header("Authorization", "Basic " + base64.b64encode(f"{sid}:{token}".encode()).decode())
            with urllib.request.urlopen(request, timeout=10) as response:
                return 200 <= response.status < 300
        except (OSError, ValueError) as exc:
            LOGGER.warning("SMS alert failed: %s", exc)
            return False

    def safe_alert(self, ssid):
        return self.notify("SentinelShield: Safe Wi-Fi", f"{ssid}\nNo threat detected.", 5)

    def fingerprint_alert(self, ssid, match_score):
        return self.notify("SentinelShield: Fingerprint Mismatch", f"{ssid}\nFingerprint match: {match_score}%", 12)

    def connection_alert(self, ssid):
        return self.notify("SentinelShield: Wi-Fi Connected", f"Connected to {ssid}. Analysing security...", 5)

    def monitor_started(self):
        return self.notify("SentinelShield Wi-Fi Monitor", "Background monitoring has started.", 5)
