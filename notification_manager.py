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


def _read_setting(name: str) -> str:
    """Read a setting from process env, falling back to the current Windows user's env registry."""
    value = os.getenv(name, "")
    if value:
        return value.strip()
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value, _ = winreg.QueryValueEx(key, name)
            if isinstance(value, str):
                return value.strip()
        except (ImportError, OSError):
            pass
    return ""


class NotificationManager:
    def __init__(self):
        self.last_alert = None
        self.last_error = ""
        self._last_by_key: dict[str, float] = {}
        configured_cooldown = load_runtime_config()["notifications"]["cooldown_seconds"]
        self.cooldown_seconds = max(0, int(os.getenv("SENTINELSHIELD_ALERT_COOLDOWN_SECONDS", configured_cooldown)))

    # Windows balloon limits: title 63 characters, text 255 characters. Longer
    # text makes Windows drop the balloon without any error.
    _TITLE_MAX = 63
    _TEXT_MAX = 255

    @staticmethod
    def _clip(text, limit: int) -> str:
        text = str(text)
        return text if len(text) <= limit else text[: limit - 3] + "..."

    def _notify_windows(self, title: str, message: str, timeout: int) -> bool:
        """Show a balloon/toast through PowerShell.

        Title and text travel in environment variables, never inside the script.
        Embedding them with json.dumps broke the popup: PowerShell does not read
        JSON escapes, so an em dash showed as \\u2014, a double quote ended the
        string and the script failed silently, and $name was expanded.
        """
        seconds = max(1, int(timeout))
        script = (
            "Add-Type -AssemblyName System.Windows.Forms; "
            "Add-Type -AssemblyName System.Drawing; "
            "$n=New-Object System.Windows.Forms.NotifyIcon; "
            "$n.Icon=[System.Drawing.SystemIcons]::Information; "
            "$n.BalloonTipTitle=$env:SENTINELSHIELD_TOAST_TITLE; "
            "$n.BalloonTipText=$env:SENTINELSHIELD_TOAST_TEXT; "
            "$n.Visible=$true; "
            f"$n.ShowBalloonTip({seconds * 1000}); "
            f"Start-Sleep -Milliseconds {max(1500, seconds * 1000)}; $n.Dispose()"
        )
        env = dict(os.environ)
        env["SENTINELSHIELD_TOAST_TITLE"] = self._clip(title, self._TITLE_MAX)
        env["SENTINELSHIELD_TOAST_TEXT"] = self._clip(message, self._TEXT_MAX)
        try:
            proc = subprocess.Popen(
                ["powershell", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script],
                env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, ValueError) as exc:
            self.last_error = f"Could not start PowerShell: {exc}"
            LOGGER.warning("Native Windows notification failed: %s", exc)
            return False
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            return True  # still running: the balloon is on screen (script sleeps >= 1.5 s)
        if proc.returncode == 0:
            return True
        detail = (proc.stderr.read() or b"").decode("utf-8", "replace").strip()[:200]
        self.last_error = f"PowerShell exited with code {proc.returncode}: {detail}"
        LOGGER.warning("Native Windows notification failed: %s", self.last_error)
        return False

    def notify(self, title, message, timeout=10) -> bool:
        """Send a desktop notification without allowing failures to stop scans.

        Returns True only if a backend accepted it. On failure the reason is in
        ``self.last_error`` so the dashboard can show it.
        """
        self.last_error = ""
        if sys.platform == "win32" and self._notify_windows(title, message, timeout):
            return True
        if notification is None:
            self.last_error = self.last_error or "Desktop notification skipped: install the 'plyer' package."
            LOGGER.warning(self.last_error)
            return False
        try:
            notification.notify(
                title=self._clip(title, self._TITLE_MAX), message=self._clip(message, self._TEXT_MAX),
                app_name="SentinelShield", timeout=timeout,
            )
            return True
        except Exception as exc:
            self.last_error = f"Desktop notification failed: {exc}"
            LOGGER.warning(self.last_error)
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

    def notify_threat(self, ssid, bssid, risk, reason, force: bool = False, desktop: bool = True) -> dict[str, bool]:
        """Dispatch one high-risk event to configured channels, with deduplication.

        force=True skips the cooldown (used by the dashboard's test button).
        desktop=False skips only the popup; email/Telegram/SMS still follow their settings.
        """
        try:
            risk_val = float(risk)
        except (TypeError, ValueError):
            risk_val = 0.0

        if not force and risk_val < 35.0:
            LOGGER.info("Threat alert suppressed for %s/%s: risk %.1f%% below threshold", ssid, bssid, risk_val)
            return {"desktop": False, "email": False, "telegram": False, "sms": False, "suppressed": True}

        if not force and self._is_cooled_down(str(ssid), str(bssid)):
            return {"desktop": False, "email": False, "telegram": False, "sms": False, "suppressed": True}
        title = "SentinelShield Wi-Fi Threat Alert"
        message = self._message(ssid, bssid, risk, reason)
        popup = f"{ssid} ({bssid})\nRisk: {float(risk):.0f}% - do not connect.\n{reason}"
        desktop_ok = self.notify(title, popup, 15) if desktop else False
        result = {
            "desktop": desktop_ok,
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
        token = _read_setting("SENTINELSHIELD_TELEGRAM_BOT_TOKEN")
        chat_id = _read_setting("SENTINELSHIELD_TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            LOGGER.info("Telegram alert skipped: bot token or chat ID is not configured.")
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


if __name__ == "__main__":
    # python notification_manager.py  -> sends one test alert and reports each channel.
    logging.basicConfig(level=logging.INFO)
    manager = NotificationManager()
    outcome = manager.notify_threat(
        "TEST_EVIL_TWIN_WIFI", "AA:BB:CC:DD:EE:FF", 95, 'Self-test "quoted" text \u2014 dash & $dollar', force=True,
    )
    for channel in ("desktop", "email", "telegram", "sms"):
        print(f"{channel:9s}: {'sent' if outcome[channel] else 'not sent'}")
    if not outcome["desktop"]:
        print("Desktop popup problem:", manager.last_error or "unknown")
