import contextlib
import csv
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import notification_manager as nm

TRICKY = 'AP says "Free WiFi" \u2014 cost $5 `x` \u2018smart\u2019'


class WindowsPopup(unittest.TestCase):
    def _run(self, popen):
        manager = nm.NotificationManager()
        with mock.patch.object(nm.sys, "platform", "win32"), mock.patch.object(nm.subprocess, "Popen", popen):
            return manager, manager.notify("Title \u2014 x", TRICKY, 5)

    def test_text_goes_through_environment_not_the_script(self):
        proc = mock.Mock()
        proc.wait.side_effect = subprocess.TimeoutExpired("powershell", 0.5)
        popen = mock.Mock(return_value=proc)
        manager, ok = self._run(popen)
        self.assertTrue(ok)
        args, kwargs = popen.call_args
        script = args[0][-1]
        self.assertNotIn("Free WiFi", script)
        self.assertNotIn("\\u", script)
        self.assertEqual(kwargs["env"]["SENTINELSHIELD_TOAST_TEXT"], TRICKY)
        self.assertEqual(kwargs["env"]["SENTINELSHIELD_TOAST_TITLE"], "Title \u2014 x")

    def test_long_text_is_clipped_to_windows_limit(self):
        proc = mock.Mock()
        proc.wait.side_effect = subprocess.TimeoutExpired("powershell", 0.5)
        popen = mock.Mock(return_value=proc)
        manager = nm.NotificationManager()
        with mock.patch.object(nm.sys, "platform", "win32"), mock.patch.object(nm.subprocess, "Popen", popen):
            manager.notify("T" * 200, "x" * 900, 5)
        env = popen.call_args.kwargs["env"]
        self.assertLessEqual(len(env["SENTINELSHIELD_TOAST_TEXT"]), 255)
        self.assertLessEqual(len(env["SENTINELSHIELD_TOAST_TITLE"]), 63)

    def test_powershell_crash_is_reported_not_swallowed(self):
        proc = mock.Mock(returncode=1)
        proc.wait.return_value = 1
        proc.stderr.read.return_value = b"ParserError: bad token"
        with mock.patch.object(nm, "notification", None):
            manager, ok = self._run(mock.Mock(return_value=proc))
        self.assertFalse(ok)
        self.assertIn("ParserError", manager.last_error)

    def test_missing_powershell_falls_back_to_plyer(self):
        fake = mock.Mock()
        with mock.patch.object(nm, "notification", fake):
            manager, ok = self._run(mock.Mock(side_effect=FileNotFoundError("powershell")))
        self.assertTrue(ok)
        fake.notify.assert_called_once()


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.manager = nm.NotificationManager()
        self.manager.cooldown_seconds = 120
        patcher = mock.patch.object(nm.NotificationManager, "notify", return_value=True)
        self.notify = patcher.start()
        self.addCleanup(patcher.stop)

    def test_cooldown_then_force(self):
        first = self.manager.notify_threat("Cafe", "AA:AA", 90, "r")
        second = self.manager.notify_threat("Cafe", "AA:AA", 90, "r")
        forced = self.manager.notify_threat("Cafe", "AA:AA", 90, "r", force=True)
        self.assertTrue(first["desktop"] and not first["suppressed"])
        self.assertTrue(second["suppressed"])
        self.assertTrue(forced["desktop"])

    def test_desktop_switch_off_skips_popup_only(self):
        result = self.manager.notify_threat("Cafe", "AA:AA", 90, "r", desktop=False)
        self.assertFalse(result["desktop"])
        self.notify.assert_not_called()

    def test_popup_text_fits_balloon_limit(self):
        self.manager.notify_threat("Cafe", "AA:BB:CC:DD:EE:FF", 91.7, "reason " * 80)
        message = self.notify.call_args.args[1]
        self.assertIn("92%", message)


try:
    from streamlit.testing.v1 import AppTest
except ImportError:  # pragma: no cover
    AppTest = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(AppTest is None, "streamlit not installed")
class DashboardAlerts(unittest.TestCase):
    # AppTest re-executes dashboard.py, so module constants cannot be patched.
    # The real files are set aside for the test and restored afterwards.
    FILES = ("alert_history.csv", "current_scan.csv", "adaptive_threshold_state.json")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.alert_file = ROOT / "alert_history.csv"
        self.scan_file = ROOT / "current_scan.csv"
        for name in self.FILES:
            original = ROOT / name
            if original.exists():
                original.replace(Path(self._tmp.name) / name)
        self.addCleanup(self._restore)

    def _restore(self):
        for name in self.FILES:
            (ROOT / name).unlink(missing_ok=True)
            saved = Path(self._tmp.name) / name
            if saved.exists():
                saved.replace(ROOT / name)

    def _app(self):
        return AppTest.from_file(str(ROOT / "dashboard.py"), default_timeout=90)

    def _patched(self):
        return contextlib.nullcontext()

    def test_live_scan_raises_alert_for_high_and_critical(self):
        import pandas as pd
        rows = [("Evil", "DA:00:00:00:00:01", 95), ("Mid", "DA:00:00:00:00:02", 62), ("Safe", "10:00:00:00:00:03", 5)]
        pd.DataFrame([dict(SSID=s, BSSID=b, RSSI=-40, Channel=6, Security="OPEN", Combined_Risk=r,
                           Scan_Time="2026-10-04 12:00:00") for s, b, r in rows]).to_csv(self.scan_file, index=False)
        with self._patched(), mock.patch.object(nm.NotificationManager, "notify", return_value=True):
            at = self._app().run()
            levels = {a["SSID"]: a["Level"] for a in at.session_state["alerts"]}
        self.assertEqual(levels, {"Evil": "CRITICAL", "Mid": "HIGH"})
        self.assertGreaterEqual(len(at.toast), 2)

    def test_old_five_column_history_is_migrated_not_misaligned(self):
        self.alert_file.write_text("Time,SSID,BSSID,Risk,Reason\n2026-01-01 00:00:00,Old,AA:AA,80,legacy row\n", encoding="utf-8")
        with self._patched(), mock.patch.object(nm.NotificationManager, "notify", return_value=True):
            at = self._app().run()
            at.sidebar.radio[0].set_value("Alerts").run()
            [b for b in at.button if b.label == "Trigger test alert"][0].click().run()
        with self.alert_file.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(list(rows[0]), ["Time", "SSID", "BSSID", "Risk", "Level", "Reason"])
        self.assertEqual(rows[0]["Reason"], "legacy row")
        self.assertEqual(rows[1]["Level"], "TEST")

    def test_failed_desktop_popup_is_shown_to_the_user(self):
        def failing(self, *a, **k):
            self.last_error = "backend unavailable"
            return False
        with self._patched(), mock.patch.object(nm.NotificationManager, "notify", failing):
            at = self._app().run()
            at.sidebar.radio[0].set_value("Alerts").run()
            [b for b in at.button if b.label == "Trigger test alert"][0].click().run()
        self.assertTrue(any("backend unavailable" in w.value for w in at.warning))
        self.assertTrue(len(at.toast) >= 1)


if __name__ == "__main__":
    unittest.main()
