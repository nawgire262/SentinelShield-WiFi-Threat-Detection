import unittest

import scanner


class FakeInterface:
    def __init__(self, name, has_profiles=False):
        self.name = name
        self._has_profiles = has_profiles

    def network_profiles(self):
        return [object()] if self._has_profiles else []


class WiFiInterfaceSelectionTests(unittest.TestCase):
    def test_prefers_real_wireless_adapter_over_virtual_adapter(self):
        interfaces = [
            FakeInterface("Microsoft Wi-Fi Direct Virtual Adapter"),
            FakeInterface("Intel(R) Wi‑Fi 6 AX201 160MHz"),
            FakeInterface("Bluetooth Device (Personal Area Network)"),
        ]

        selected = scanner.select_wifi_interface(interfaces)
        self.assertEqual(selected.name, "Intel(R) Wi‑Fi 6 AX201 160MHz")

    def test_rejects_loopback_and_virtual_adapters(self):
        interfaces = [
            FakeInterface("Microsoft Wi-Fi Direct Virtual Adapter"),
            FakeInterface("Loopback Pseudo-Interface 1"),
        ]

        self.assertIsNone(scanner.select_wifi_interface(interfaces))


if __name__ == "__main__":
    unittest.main()
