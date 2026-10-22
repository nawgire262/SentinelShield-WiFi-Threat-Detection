"""Passive Wi-Fi scan collector for authorized research observations.

Captures visible beacon/scan metadata only. It does not connect to networks,
intercept traffic, or assign ground-truth labels automatically.
Run on the research laptop after installing the project's Wi-Fi dependencies.
"""
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict
import argparse, csv, time, uuid

from scanner import select_wifi_interface

FIELDS = ["SSID", "BSSID", "RSSI", "Frequency_MHz", "Channel", "Security",
          "AP_Count", "Signal_Var", "Timestamp", "Session_ID", "Label", "label_source"]


def frequency_to_channel(freq):
    if freq == 2484: return 14
    if 2412 <= freq <= 2472: return round((freq - 2407) / 5)
    if 5000 <= freq < 5925: return round((freq - 5000) / 5)
    if 5925 <= freq <= 7125: return round((freq - 5950) / 5)
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", default="scan-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--scans", type=int, default=5)
    parser.add_argument("--delay", type=float, default=2.5)
    parser.add_argument("--output", default="data/raw/wifi_observations.csv")
    args = parser.parse_args()
    try:
        import pywifi
    except ImportError as exc:
        raise SystemExit("pywifi is missing in this environment. Install project requirements first.") from exc
    iface = select_wifi_interface(pywifi.PyWiFi().interfaces())
    if iface is None:
        raise SystemExit("No supported Wi-Fi interface was found.")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    existed = output.exists() and output.stat().st_size > 0
    history = defaultdict(list)
    observations = []
    for _ in range(max(1, args.scans)):
        iface.scan()
        time.sleep(max(1.0, args.delay))
        for net in iface.scan_results():
            bssid = str(getattr(net, "bssid", "") or "").upper()
            ssid = str(getattr(net, "ssid", "") or "")
            try: rssi = float(getattr(net, "signal"))
            except (TypeError, ValueError): continue
            try: freq = float(getattr(net, "freq"))
            except (TypeError, ValueError): freq = 0.0
            if freq > 10000: freq /= 1000.0
            key = (ssid, bssid)
            history[key].append(rssi)
            akm = getattr(net, "akm", [])
            security = "OPEN" if not akm else "WPA2_OR_OTHER"
            observations.append({"SSID": ssid, "BSSID": bssid, "RSSI": rssi,
                "Frequency_MHz": freq, "Channel": frequency_to_channel(freq),
                "Security": security, "Timestamp": datetime.now(timezone.utc).isoformat(),
                "Session_ID": args.session, "Label": "", "label_source": "unverified"})

    # Keep the last observation per scan result and attach the session-level
    # signal variance and SSID-level AP count. No labels are inferred.
    latest = {}
    for row in observations:
        latest[(row["SSID"], row["BSSID"])] = row
    ap_counts = defaultdict(set)
    for ssid, bssid in latest:
        ap_counts[ssid].add(bssid)
    rows = []
    for key, row in latest.items():
        signals = history[key]
        row["AP_Count"] = len(ap_counts[row["SSID"]])
        mean = sum(signals) / len(signals)
        row["Signal_Var"] = sum((x - mean) ** 2 for x in signals) / len(signals) if len(signals) > 1 else 0.0
        rows.append(row)
    with output.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS)
        if not existed: writer.writeheader()
        writer.writerows(rows)
    print(f"Saved {len(rows)} observations to {output}")
    print("Labels remain blank/unverified. Verify ground truth and edit Label/label_source only after the controlled experiment.")

if __name__ == "__main__":
    main()
