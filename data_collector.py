import pywifi
import time
import csv
from collections import defaultdict
from datetime import datetime
import os

from scanner import select_wifi_interface

FILE_NAME = "wifi_dataset.csv"

# Add header only if file doesn't exist
if not os.path.exists(FILE_NAME):
    with open(FILE_NAME, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "SSID", "RSSI", "Channel", "Security",
            "AP_Count", "Signal_Var", "Label"
        ])

wifi = pywifi.PyWiFi()
iface = select_wifi_interface(wifi.interfaces())
if iface is None:
    raise SystemExit("No supported Wi-Fi interface was found.")

signal_history = defaultdict(list)

print("📡 Collecting and appending WiFi data...\n")

# Step 1: Collect signal history
for _ in range(5):
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()

    temp_map = defaultdict(list)

    for net in results:
        temp_map[net.ssid].append(net)

    for ssid, networks in temp_map.items():
        for net in networks:
            signal_history[ssid].append(net.signal)

# Step 2: Final scan for feature extraction
iface.scan()
time.sleep(2)
results = iface.scan_results()

ssid_map = defaultdict(list)

for net in results:
    ssid_map[net.ssid].append(net)

# Step 3: Append data
with open(FILE_NAME, "a", newline="") as f:
    writer = csv.writer(f)

    for ssid, networks in ssid_map.items():

        signals = signal_history[ssid]
        if not signals:
            continue

        bssids = set()
        security_list = []

        for net in networks:
            bssids.add(net.bssid)
            security_list.append("Open" if not net.akm else "WPA2")

        ap_count = len(bssids)
        signal_var = max(signals) - min(signals) if len(signals) > 1 else 0
        avg_signal = sum(signals) // len(signals)

        channel = networks[0].freq
        security = "Open" if not networks[0].akm else "WPA2"

        # Leave label empty (you fill manually later)
        label = ""

        writer.writerow([
            ssid,
            avg_signal,
            channel,
            security,
            ap_count,
            signal_var,
            label
        ])

print("✅ Data appended to existing dataset!")