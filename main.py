from notification_manager import NotificationManager
from alert_logger import AlertLogger
from fingerprinting.fingerprint_matcher import compare_fingerprint
try:
    import pywifi
except ImportError as exc:
    raise SystemExit("PyWiFi is required for main.py. Install project dependencies before scanning.") from exc
import time
import pandas as pd
import csv
import json
import os
import pickle
from collections import defaultdict

from scanner import select_wifi_interface
from rssi_raim import rssi_to_distance, raim_consistency_check, is_temporally_unstable
from ensemble_contract import probability_column
import numpy as np

# ================= LOAD MODELS (tiered, graceful fallback) =================
ml_mode = "none"

try:
    with open("rf_model.pkl", "rb") as f:
        rf_model = pickle.load(f)
    with open("knn_model.pkl", "rb") as f:
        knn_model = pickle.load(f)
    with open("le_security.pkl", "rb") as f:
        le_security = pickle.load(f)
    with open("le_label.pkl", "rb") as f:
        le_label = pickle.load(f)

    ml_mode = "basic"
    fake_idx = list(le_label.classes_).index("Fake")

    try:
        with open("iso_model.pkl", "rb") as f:
            iso_model = pickle.load(f)
        with open("meta_model.pkl", "rb") as f:
            meta_model = pickle.load(f)
        with open("scaler.pkl", "rb") as f:
            feature_scaler = pickle.load(f)
        with open("meta_scaler.pkl", "rb") as f:
            meta_scaler = pickle.load(f)
        ml_mode = "hybrid"
    except Exception:
        feature_scaler = None
        meta_scaler = None

except Exception:
    print("⚠️ ML models not found. Running rule-based only.")
    feature_scaler = None
    meta_scaler = None

print(f"🧠 ML mode: {ml_mode}")

DATASET_FILE = "wifi_dataset.csv"
CURRENT_SCAN_FILE = "current_scan.csv"

wifi = pywifi.PyWiFi()
interfaces = wifi.interfaces()
iface = select_wifi_interface(interfaces)
if iface is None:
    raise SystemExit("No supported Wi-Fi interface was found. Use the Streamlit dashboard demo mode or connect a supported adapter.")
notifier = NotificationManager()
logger = AlertLogger()

signal_history = defaultdict(list)
network_map = defaultdict(list)
bssid_signal_history = defaultdict(list)  # (ssid, bssid) -> [rssi per scan pass]

print("📡 Scanning WiFi...\n")

# ================= COLLECT DATA =================
for _ in range(5):
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()

    for net in results:
        if not net.ssid:
            continue
        signal_history[net.ssid].append(net.signal)
        network_map[net.ssid].append(net)
        bssid_signal_history[(net.ssid, net.bssid)].append(net.signal)

print("📊 Smart WiFi Analysis:\n")

# ---------------------------------------
# Detect Currently Connected WiFi
# ---------------------------------------
connected_ssid = None
try:
    profile = iface.network_profiles()
    if profile:
        connected_ssid = profile[0].ssid
        print(f"📶 Connected WiFi : {connected_ssid}")
except Exception:
    connected_ssid = None

# ================= LOAD EXISTING DATASET ENTRIES =================
existing_entries = set()
if os.path.exists(DATASET_FILE):
    with open(DATASET_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                existing_entries.add((row[0], row[1]))  # SSID + BSSID

# ================= CREATE FILES IF NEEDED =================
if not os.path.exists(DATASET_FILE):
    with open(DATASET_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "SSID", "BSSID", "RSSI", "Channel",
            "Security", "AP_Count", "Signal_Var", "Label"
        ])

with open(CURRENT_SCAN_FILE, "w", newline="", encoding="utf-8") as scan_f:
    scan_writer = csv.writer(scan_f)
    scan_writer.writerow([
        "SSID", "BSSID", "Signal", "Channel", "Security",
        "Status", "Risk_Score", "AP_Count", "Signal_Fluctuation",
        "Signal_History", "Random_Forest", "KNN", "Isolation_Forest",
        "Meta_Model", "Meta_Confidence", "Est_Distance_m", "RAIM_Flagged",
        "Temporally_Unstable", "XAI_JSON", "Fingerprint_Similarity", "Reason"
    ])

    with open(DATASET_FILE, "a", newline="", encoding="utf-8") as data_f:
        data_writer = csv.writer(data_f)

        for ssid, signals in signal_history.items():
            networks = network_map[ssid]

            # keep unique BSSID only
            unique_networks = {}
            for net in networks:
                unique_networks[net.bssid] = net

            if not unique_networks:
                continue

            unique_net_values = list(unique_networks.values())
            bssids = list(unique_networks.keys())

            ap_count = len(bssids)
            signal_var = max(signals) - min(signals) if len(signals) > 1 else 0
            avg_signal = sum(signals) // len(signals)

            channel = unique_net_values[0].freq
            security = "Open" if not unique_net_values[0].akm else "WPA2"

            # ================= PAPER 3: RAIM-style multi-AP consistency check =================
            per_bssid_histories = {
                b: bssid_signal_history[(ssid, b)] for b in bssids
            }
            raim_results = raim_consistency_check(per_bssid_histories)

            for bssid, net in unique_networks.items():
                key = (ssid, bssid)

                # ================= RULE-BASED RISK LOGIC =================
                risk = 5
                reasons = []
                rule_contributions = []

                # ================= SIGNAL FINGERPRINTING =================
                current_network = {
                    "SSID": ssid,
                    "BSSID": bssid,
                    "Signal": avg_signal,
                    "Channel": channel,
                    "Security": security,
                    "Vendor": "Unknown"
                }

                # Compare with stored fingerprint
                fp_result = compare_fingerprint(current_network)
                similarity = fp_result["similarity"]

                if similarity is not None:
                    if similarity < 70:
                        risk += 20
                        reasons.append(f"Fingerprint mismatch ({similarity}% similarity)")
                    elif similarity < 90:
                        risk += 10
                        reasons.append(f"Fingerprint partially matched ({similarity}% similarity)")

                # AP count metrics
                if ap_count > 2:
                    risk += 15
                    reasons.append("Multiple AP detected")
                    rule_contributions.append({"factor": "Multiple AP detected", "points": 15})

                if ap_count > 2 and signal_var > 10:
                    risk += 15
                    reasons.append("Unstable multi-AP behavior")
                    rule_contributions.append({"factor": "Unstable multi-AP behavior", "points": 15})

                if signal_var > 15:
                    risk += 15
                    reasons.append("High signal fluctuation")
                    rule_contributions.append({"factor": "High signal fluctuation", "points": 15})

                if security == "Open":
                    risk += 20
                    reasons.append("Open network")
                    rule_contributions.append({"factor": "Open network", "points": 20})

                # ---- PAPER 2: path-loss-model distance estimate ----
                bssid_history = bssid_signal_history[(ssid, bssid)]
                est_distance = round(rssi_to_distance(avg_signal), 2)
                if est_distance < 1.0:
                    risk += 15
                    reasons.append(f"Physically implausible proximity (~{est_distance}m by path-loss model)")
                    rule_contributions.append({"factor": "Physically implausible proximity", "points": 15})

                # ---- PAPER 1: temporal RSSI stability check ----
                unstable = is_temporally_unstable(bssid_history)
                if unstable:
                    risk += 15
                    reasons.append("Unstable/erratic RSSI across repeated scans")
                    rule_contributions.append({"factor": "Unstable/erratic RSSI", "points": 15})

                # ---- PAPER 3: RAIM-style multi-AP distance-consistency check ----
                raim_info = raim_results.get(bssid, {})
                raim_flagged = raim_info.get("flagged", False)
                if raim_flagged:
                    risk += 20
                    reasons.append(
                        f"RAIM check: distance estimate (~{raim_info.get('distance')}m) inconsistent "
                        f"with other APs broadcasting '{ssid}' "
                        f"({raim_info.get('rogue_votes')}/{raim_info.get('rogue_votes', 0) + raim_info.get('benign_votes', 0)} subsets disagree)"
                    )
                    rule_contributions.append({"factor": "RAIM inconsistency", "points": 20})

                rf_result = "N/A"
                knn_result = "N/A"
                iso_result = "N/A"
                meta_result = "N/A"
                meta_conf = "N/A"
                meta_contributions = []

                # ================= ML LAYER =================
                if ml_mode in ("basic", "hybrid"):
                    try:
                        security_name = str(security or "OPEN").upper()
                        security_classes = list(le_security.classes_)
                        if security_name not in security_classes:
                            security_name = "WPA2" if "WPA2" in security_classes else security_classes[0]
                        sec_encoded = le_security.transform([security_name])[0]

                        sample = np.array([[
                            avg_signal,
                            channel,
                            sec_encoded,
                            ap_count,
                            signal_var,
                        ]], dtype=float)
                        if feature_scaler is not None:
                            sample = feature_scaler.transform(sample)

                        rf_proba = float(probability_column(rf_model, rf_model.predict_proba(sample), fake_idx)[0])
                        knn_proba = float(probability_column(knn_model, knn_model.predict_proba(sample), fake_idx)[0])
                        rf_result = "Fake" if rf_proba > 0.5 else "Legit"
                        knn_result = "Fake" if knn_proba > 0.5 else "Legit"
                        meta_contributions.append(("Random Forest", round((rf_proba - 0.5) * 100, 1)))
                        meta_contributions.append(("KNN", round((knn_proba - 0.5) * 100, 1)))

                        if ml_mode == "hybrid":
                            iso_pred = iso_model.predict(sample)[0]
                            iso_score = -iso_model.decision_function(sample)[0]
                            iso_result = "Anomaly" if iso_pred == -1 else "Normal"
                            meta_contributions.append(("Isolation Forest", round((iso_score / max(abs(iso_score), 1)) * 100, 1)))

                            meta_features = np.array([[rf_proba, knn_proba, iso_score]], dtype=float)
                            if meta_scaler is not None:
                                meta_features = meta_scaler.transform(meta_features)
                            meta_pred_num = meta_model.predict(meta_features)[0]
                            meta_proba = float(probability_column(meta_model, meta_model.predict_proba(meta_features), fake_idx)[0])

                            meta_result = le_label.inverse_transform([meta_pred_num])[0]
                            meta_conf = round(float(meta_proba if meta_result == "Fake" else 1 - meta_proba) * 100, 1)

                            if meta_result == "Fake":
                                risk += 20 + round(meta_proba * 10)
                                reasons.append(f"Hybrid model flagged anomaly ({meta_conf}% confidence)")
                            else:
                                reasons.append(f"Hybrid model: no anomaly ({meta_conf}% confidence)")

                            if rf_result == "Fake":
                                reasons.append("Random Forest flagged anomaly")
                            if knn_result == "Fake":
                                reasons.append("KNN flagged anomaly")
                            if iso_result == "Anomaly":
                                reasons.append("Isolation Forest: deviates from known legitimate APs")

                        else:
                            if rf_result == "Fake" and knn_result == "Fake":
                                risk += 25
                                reasons.append("RF + KNN both detected anomaly")
                            elif rf_result == "Fake" or knn_result == "Fake":
                                risk += 15
                                reasons.append("One ML model detected anomaly")

                    except Exception as e:
                        reasons.append(f"ML error: {str(e)}")

                if risk > 100:
                    risk = 100

                label = "Fake" if risk >= 50 else "Legit"
                status = "⚠️ Suspicious" if label == "Fake" else "✅ Safe"
                reason_text = ", ".join(reasons) if reasons else "No major anomaly"

                if connected_ssid == ssid:
                    if risk >= 70:
                        notifier.danger_alert(ssid, risk, reason_text)
                        logger.log_alert(ssid, bssid, risk, reason_text)
                    elif risk >= 40:
                        notifier.fingerprint_alert(ssid, 100 - risk)
                    else:
                        notifier.safe_alert(ssid)

                rf_features = [
                    ("RSSI Signal Spike / Attenuation", float(avg_signal) if avg_signal is not None else 0),
                    ("Channel Congestion Overlap", 25.0 if channel not in (1, 6, 11) else -10.0),
                    ("Unencrypted Open Portal Flag", 80.0 if security == "Open" else -20.0),
                    ("Multi-AP MAC Spoofing Density", min(max((ap_count - 1) * 15, 0), 100)),
                    ("Temporal Signal Fluctuation Variance", min(max(signal_var * 4, 0), 100))
                ]

                xai_payload = {
                    "rules": rule_contributions,
                    "meta": meta_contributions,
                    "rf_features": rf_features,
                }
                xai_json = json.dumps(xai_payload, ensure_ascii=False)

                # ================= CONSOLE OUTPUT =================
                print(f"SSID: {ssid}")
                print(f"BSSID: {bssid}")
                print(f"Signal: {avg_signal} dBm")
                print(f"Channel: {channel}")
                print(f"Security: {security}")
                print(f"Status: {status}")
                print(f"Risk Score: {risk}%")
                print(
                    "Fingerprint Similarity: "
                    f"{similarity if similarity is not None else 'N/A'}"
                    f"{'%' if similarity is not None else ''}"
                )
                print(f"AP Count: {ap_count}")
                print(f"Signal Fluctuation: {signal_var} dBm")
                print(f"Signal History: {signals}")
                print(f"Random Forest: {rf_result}")
                print(f"KNN: {knn_result}")
                print(f"Isolation Forest: {iso_result}")
                print(f"Meta Model: {meta_result} (confidence {meta_conf}%)")
                print(f"Est. Distance (path-loss model): {est_distance} m")
                print(f"RAIM Flagged: {raim_flagged}")
                print(f"Temporally Unstable: {unstable}")
                print(f"Reason: {reason_text}")

                if key in existing_entries:
                    print("📁 Already in dataset")
                else:
                    data_writer.writerow([
                        ssid, bssid, avg_signal, channel,
                        security, ap_count, signal_var, label
                    ])
                    existing_entries.add(key)
                    print("💾 New network saved")

                print("-" * 50)

                # ================= SAVE CURRENT SCAN =================
                scan_writer.writerow([
                    ssid,
                    bssid,
                    avg_signal,
                    channel,
                    security,
                    status,
                    risk,
                    ap_count,
                    signal_var,
                    str(signals),
                    rf_result,
                    knn_result,
                    iso_result,
                    meta_result,
                    meta_conf,
                    est_distance,
                    raim_flagged,
                    unstable,
                    xai_json,
                    similarity,
                    reason_text
                ])

print("\n✅ Process Completed!")
