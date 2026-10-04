import os
import sys
from scapy.all import sniff, Dot11, Dot11Deauth, Dot11Disas

class Layer2WirelessMonitor:
    def __init__(self, interface="wlan0mon"):
        self.interface = interface
        self.sequence_tracker = {}
        self.deauth_counter = 0
        self.deauth_threshold = 25  # Burst rate tolerance limit per second loop

    def enable_promiscuous_monitor_mode(self):
        """Issues OS native IO commands to toggle physical interfaces into raw monitor capture states."""
        os.system(f"ip link set {self.interface} down")
        os.system(f"iw dev {self.interface} set type monitor")
        os.system(f"ip link set {self.interface} up")

    def analyze_frame_telemetry(self, packet):
        """Deep dissect 802.11 Layer-2 frame fields in runtime."""
        if not packet.haslayer(Dot11):
            return

        # Feature Vector 1: Detect Burst Denial of Service (Deauthentication Flood Jamming)
        if packet.haslayer(Dot11Deauth) or packet.haslayer(Dot11Disas):
            self.deauth_counter += 1
            if self.deauth_counter > self.deauth_threshold:
                print(f"[!] SYSTEM CRITICAL ALERT: Wi-Fi Deauth Jamming Detected on {packet.addr2}!")
            return

        # Feature Vector 2: Sequence Number Continuity Tracking (Twin-AP/Impersonation Bypass)
        if packet.type == 0 and packet.subtype == 8:  # Beacon Management Frames Dissector
            bssid = packet.addr3
            seq_num = packet.SC >> 4  # Sequence number bits parser extraction
            
            if bssid in self.sequence_tracker:
                prev_seq = self.sequence_tracker[bssid]
                # Frame counts should naturally increment linearly. Large step deltas flag rogue injectors.
                delta = (seq_num - prev_seq) & 0xFFF
                if delta > 50 and delta < 4000:
                    print(f"[!] AI THREAT DETECTION WARNING: Sequence Out-of-Bounds Exception on BSSID: {bssid}! Possible Rogue AP Hijack.")
            
            self.sequence_tracker[bssid] = seq_num

    def execute_sniff_loop(self):
        print(f"[*] Operator OM007: Sn Sniffing Core listening on raw channel matrix via {self.interface}...")
        sniff(iface=self.interface, prn=self.analyze_frame_telemetry, store=0)