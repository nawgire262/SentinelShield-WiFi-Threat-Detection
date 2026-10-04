import json
import os
import threading
import time
from pathlib import Path

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, RadioTap, sendp, sniff
except ImportError:
    Dot11 = None
    Dot11Beacon = None
    Dot11Elt = None
    RadioTap = None
    sendp = None
    sniff = None


def is_deception_available():
    return Dot11 is not None and Dot11Beacon is not None and sendp is not None and sniff is not None


class HoneypotManager:
    def __init__(self, interface="wlan0mon", output_path="honeypot_forensics.json"):
        self.interface = interface
        self.active = False
        self.profile = "Open Legacy"
        self.thread = None
        self.events = []
        self.lock = threading.Lock()
        self.output_path = Path(output_path)
        self.profiles = {
            "Open Legacy": {
                "ssids": ["Guest_Free_WiFi", "Legacy_Public"],
                "mac": "02:00:00:00:01:00",
                "security": "OPEN",
                "beacon_interval": 100,
            },
            "Corporate Guest": {
                "ssids": ["CompanyGuest", "Corp-Guest"],
                "mac": "02:00:00:00:02:00",
                "security": "WPA2",
                "beacon_interval": 100,
            },
            "Weak WPA2": {
                "ssids": ["Free_WiFi_WPA2", "CoffeeShop_WPA2"],
                "mac": "02:00:00:00:03:00",
                "security": "WPA2",
                "beacon_interval": 80,
            },
            "High-Interaction Decoy": {
                "ssids": ["SecureCorp-Guest", "Enterprise_SSD"],
                "mac": "02:00:00:00:04:00",
                "security": "OPEN",
                "beacon_interval": 60,
            },
        }

    def set_profile(self, profile_name: str):
        if profile_name in self.profiles:
            self.profile = profile_name

    def start(self):
        if self.active or not is_deception_available():
            return False
        self.active = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        self.active = False
        if self.thread is not None:
            self.thread.join(timeout=1)

    def _persist_events(self):
        try:
            self.output_path.write_text(json.dumps(self.events[-200:], indent=2), encoding="utf-8")
        except Exception:
            pass

    def _store_event(self, event_type, details):
        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event_type,
            "profile": self.profile,
            "details": details,
        }
        with self.lock:
            self.events.append(entry)
        self._persist_events()

    def _make_beacon(self, ssid, mac, security):
        if not is_deception_available():
            return None
        capability = "ESS" if security == "OPEN" else "ESS+privacy"
        beacon = (
            RadioTap()
            / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=mac, addr3=mac)
            / Dot11Beacon(cap=capability)
            / Dot11Elt(ID="SSID", info=ssid.encode(errors="ignore"))
            / Dot11Elt(ID="Rates", info=b"\x82\x84\x8b\x96")
        )
        return beacon

    def _broadcast_beacons(self):
        profile = self.profiles.get(self.profile, {})
        ssids = profile.get("ssids", [])
        mac = profile.get("mac", "02:00:00:00:01:00")
        security = profile.get("security", "OPEN")

        for ssid in ssids:
            pkt = self._make_beacon(ssid, mac, security)
            if pkt is None:
                continue
            try:
                sendp(pkt, iface=self.interface, verbose=False, count=1)
                self._store_event("beacon_sent", {"ssid": ssid, "security": security, "interface": self.interface})
            except Exception as exc:
                self._store_event("beacon_error", {"ssid": ssid, "error": str(exc)})

    def _process_probe_packet(self, packet):
        if not packet.haslayer(Dot11):
            return
        dot11 = packet.getlayer(Dot11)
        if dot11.type == 0 and dot11.subtype == 4:
            ssid = dot11.info.decode(errors="ignore") if hasattr(dot11, "info") else ""
            self._store_event(
                "probe_request",
                {
                    "source": dot11.addr2,
                    "ssid": ssid,
                    "destination": dot11.addr1,
                    "sender_bssid": dot11.addr3,
                },
            )
        elif dot11.type == 0 and dot11.subtype == 11:
            self._store_event(
                "authentication_attempt",
                {
                    "source": dot11.addr2,
                    "destination": dot11.addr1,
                    "sender_bssid": dot11.addr3,
                },
            )

    def _sniff_honeypot_activity(self, timeout=5):
        if not is_deception_available():
            return
        try:
            sniff(iface=self.interface, prn=self._process_probe_packet, timeout=timeout, store=0)
        except Exception as exc:
            self._store_event("sniffer_error", {"error": str(exc), "interface": self.interface})

    def _run(self):
        self._store_event("honeypot_started", {"profile": self.profile, "interface": self.interface})
        while self.active:
            self._broadcast_beacons()
            self._sniff_honeypot_activity(timeout=4)
            time.sleep(1)
        self._store_event("honeypot_stopped", {"profile": self.profile})

    def get_summary(self):
        with self.lock:
            counts = {}
            for event in self.events:
                counts[event["event"]] = counts.get(event["event"], 0) + 1
            return {
                "profile": self.profile,
                "active": self.active,
                "event_count": len(self.events),
                "event_types": counts,
                "forensics_file": str(self.output_path),
            }

    def get_events(self, limit=20):
        with self.lock:
            return list(self.events[-limit:])
