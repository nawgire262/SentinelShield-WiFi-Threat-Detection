import os
import unittest
from unittest import mock
import notification_manager as nm

class TelegramSettingsTests(unittest.TestCase):
    def test_process_environment_takes_precedence(self):
        with mock.patch.dict(os.environ, {
            "SENTINELSHIELD_TELEGRAM_BOT_TOKEN": "process-token",
            "SENTINELSHIELD_TELEGRAM_CHAT_ID": "12345",
        }, clear=False):
            self.assertEqual(nm._read_setting("SENTINELSHIELD_TELEGRAM_BOT_TOKEN"), "process-token")
            self.assertEqual(nm._read_setting("SENTINELSHIELD_TELEGRAM_CHAT_ID"), "12345")

    @unittest.skipUnless(nm.sys.platform == "win32", "Windows registry fallback only")
    def test_windows_registry_fallback(self):
        import winreg
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SENTINELSHIELD_TELEGRAM_BOT_TOKEN", None)
            with mock.patch.object(winreg, "OpenKey") as open_key:
                with mock.patch.object(winreg, "QueryValueEx", return_value=(" registry-token ", 1)):
                    open_key.return_value.__enter__.return_value = object()
                    self.assertEqual(nm._read_setting("SENTINELSHIELD_TELEGRAM_BOT_TOKEN"), "registry-token")

if __name__ == "__main__":
    unittest.main()
