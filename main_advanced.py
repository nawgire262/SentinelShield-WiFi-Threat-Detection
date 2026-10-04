"""
main_advanced.py
================
Next-generation WiFi threat detection with integrated ML & threat analytics.

Detection Stack:
  ✓ Rule-Based Threat Scoring (6 vectors)
  ✓ Random Forest Classifier
  ✓ KNN Classifier  
  ✓ Isolation Forest (anomaly detection)
  ✓ Logistic Regression Meta-Classifier
  ✓ Advanced Signal Behavior Analysis
"""

import pywifi
import time
import pandas as pd
import csv
import os
import sys
from collections import defaultdict

from scanner import select_wifi_interface

# Import advanced components
try:
    from ml_ensemble import HybridEnsembleDetector
    from threat_analyzer import AdvancedThreatAnalyzer
    from signal_analyzer import AdvancedSignalAnalyzer
    from advanced_features import AdvancedFeatureExtractor
    ml_available = True
except ImportError as e:
    print(f"⚠️ Some advanced modules not found: {e}")
    ml_available = False

# ================= CONFIG =================
DATASET_FILE = "wifi_dataset.csv"
CURRENT_SCAN_FILE = "current_scan.csv"

# Initialize detectors
signal_analyzer = AdvancedSignalAnalyzer()
threat_analyzer = AdvancedThreatAnalyzer()
feature_extractor = AdvancedFeatureExtractor()

# Initialize ML ensemble
ml_mode = "none"
ml_detector = None

if ml_available:
    try:
        ml_detector = HybridEnsembleDetector()
        
        # Try to load existing models
        if ml_detector.load_models():
            ml_mode = "hybrid"
            print("✅ ML ensemble loaded (RF + KNN + IF + LR Meta-Classifier)")
        else:
            print("⚠️  ML models not available. Using rule-based only.")
            ml_detector = None
    
    except Exception as e:
        print(f"⚠️ ML initialization error: {e}")
        ml_detector = None
else:
    print("⚠️ ML components not available")

print(f"🚀 Detection Mode: {ml_mode.upper()}")
print("📡 Scanning WiFi networks...\n")

# ================= SETUP =================
wifi = pywifi.PyWiFi()
iface = select_wifi_interface(wifi.interfaces())
if iface is None:
    raise SystemExit("No supported Wi-Fi interface was found. Use the Streamlit dashboard demo mode or connect a supported adapter.")

signal_history = defaultdict(list)
network_map = defaultdict(list)
bssid_signal_history = defaultdict(list)

# ================= COLLECTION PHASE =================
print("📊 Collecting WiFi signal data (5 passes)...\n")

for scan_pass in range(5):
    print(f"  Scan {scan_pass + 1}/5...", end=' ')
    
    iface.scan()
    time.sleep(2)
    results = iface.scan_results()
    
    for net in results:
        if not net.ssid:
            continue
        
        signal_history[net.ssid].append(net.signal)
        network_map[net.ssid].append(net)
        bssid_signal_history[(net.ssid, net.bssid)].append(net.signal)
        signal_analyzer.add_signal_reading(net.bssid, net.signal)
    
    print(f"found {len(results)} networks")

print(f"\n✅ Collection complete: {len(signal_history)} unique SSIDs detected\n")

# ================= ANALYSIS PHASE =================

# Load existing dataset to avoid duplicates
existing_entries = set()
if os.path.exists(DATASET_FILE):
    with open(DATASET_FILE, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) >= 2:
                existing_entries.add((row[0], row[1]))

# Create files if needed
if not os.path.exists(DATASET_FILE):
    with open(DATASET_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "SSID", "BSSID", "RSSI", "Channel", "Security", 
            "AP_Count", "Signal_Var", "Label"
        ])

# Create current scan file with enhanced columns
with open(CURRENT_SCAN_FILE, "w", newline="", encoding="utf-8") as scan_f:
    scan_writer = csv.writer(scan_f)
    scan_writer.writerow([
        "SSID", "BSSID", "Signal", "Channel", "Security",
        "Status", "Risk_Score", "AP_Count", "Signal_Fluctuation",
        "Signal_History", "Random_Forest", "KNN", "Isolation_Forest",
        "Meta_Model", "Meta_Confidence", "Rule_Based_Score",
        "Threat_Vector_Scores", "Signal_Pattern_Score", "Mobility_Class",
        "Coherence_Score", "Recommendations", "Reason"
    ])
    
    with open(DATASET_FILE, "a", newline="", encoding="utf-8") as data_f:
        data_writer = csv.writer(data_f)
        
        for ssid, signals in signal_history.items():
            networks = network_map[ssid]
            
            # Get unique BSSIDs
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
            
            print(f"\n{'='*60}")
            print(f"SSID: {ssid}")
            print(f"{'='*60}")
            
            for bssid, net in unique_networks.items():
                key = (ssid, bssid)
                
                # =============== RULE-BASED THREAT SCORING ===============
                network_data = {
                    'ssid': ssid,
                    'bssid': bssid,
                    'rssi': avg_signal,
                    'channel': channel,
                    'security': security,
                    'rssi_history': bssid_signal_history[(ssid, bssid)],
                    'ap_count': ap_count,
                    'bssid_list': bssids,
                    'signal_strengths': [networks[i].signal for i, n in enumerate(networks) 
                                        if n.bssid == bssid][:5]
                }
                
                threat_result = threat_analyzer.calculate_overall_threat(network_data)
                rule_based_score = threat_result['total_threat_score']
                threat_vectors = threat_result['vectors']
                
                # =============== SIGNAL BEHAVIOR ANALYSIS ===============
                bssid_history = bssid_signal_history[(ssid, bssid)]
                signal_stats = signal_analyzer.get_bssid_signal_stats(bssid)
                
                if signal_stats:
                    pattern_analysis = signal_stats['pattern_analysis']
                    signal_pattern_score = pattern_analysis.get('pattern_anomaly_score', 0)
                    mobility = signal_stats['mobility']
                    mobility_class = mobility['classification']
                    coherence = signal_stats['temporal_coherence']
                    coherence_score = coherence['coherence_score']
                else:
                    signal_pattern_score = 0
                    mobility_class = 'unknown'
                    coherence_score = 50
                
                # =============== ML ENSEMBLE (if available) ===============
                rf_result = "N/A"
                knn_result = "N/A"
                iso_result = "N/A"
                meta_result = "N/A"
                meta_conf = "N/A"
                ml_risk_addition = 0
                
                if ml_mode == "hybrid" and ml_detector:
                    try:
                        ml_prediction = ml_detector.predict(network_data)
                        
                        if ml_prediction:
                            rf_result = ml_prediction['rf_prediction']
                            knn_result = ml_prediction['knn_prediction']
                            iso_result = ml_prediction['iso_prediction']
                            meta_result = ml_prediction['meta_prediction']
                            meta_conf = ml_prediction['meta_confidence']
                            ml_risk_addition = ml_prediction['ensemble_risk']
                            
                            print(f"  ML Predictions:")
                            print(f"    - Random Forest: {rf_result}")
                            print(f"    - KNN: {knn_result}")
                            if iso_result != "N/A":
                                print(f"    - Isolation Forest: {iso_result}")
                            print(f"    - Meta-Classifier: {meta_result} ({meta_conf}% confidence)")
                    
                    except Exception as e:
                        print(f"  ML error: {e}")
                else:
                    if ml_available:
                        print(f"  ML: Not initialized (using rule-based only)")
                
                # =============== COMBINED RISK SCORE ===============
                # Weighted combination
                combined_risk = int(
                    (rule_based_score * 0.4) +
                    (signal_pattern_score * 0.3) +
                    (ml_risk_addition * 0.3)
                )
                
                combined_risk = min(100, max(0, combined_risk))
                
                # Determine status and label
                if combined_risk >= 70:
                    label = "Fake"
                    status = "🚨 CRITICAL"
                elif combined_risk >= 50:
                    label = "Fake"
                    status = "⚠️ HIGH"
                elif combined_risk >= 25:
                    label = "Suspicious"
                    status = "⚠️ MEDIUM"
                else:
                    label = "Legit"
                    status = "✅ SAFE"
                
                # =============== OUTPUT ===============
                recommendations = ", ".join(threat_result['recommendations'])
                reason_text = ", ".join(threat_result['reasons'][:3])  # First 3 reasons
                
                vector_str = str({k: v['score'] for k, v in threat_vectors.items()})
                
                print(f"\nBSSID: {bssid}")
                print(f"Signal: {avg_signal} dBm")
                print(f"Channel: {channel}")
                print(f"Security: {security}")
                print(f"Status: {status}")
                print(f"\n📊 Risk Scores:")
                print(f"  Rule-Based: {rule_based_score}%")
                print(f"  Signal Pattern: {signal_pattern_score}%")
                print(f"  ML Ensemble: {ml_risk_addition}%")
                print(f"  COMBINED: {combined_risk}%")
                print(f"\n🔬 Analysis:")
                print(f"  Mobility: {mobility_class}")
                print(f"  Signal Coherence: {coherence_score:.0f}%")
                print(f"  ML Verdict: {meta_result} ({meta_conf}%)")
                print(f"\n💡 Recommendations: {recommendations}")
                
                # Write to current scan file
                scan_writer.writerow([
                    ssid, bssid, avg_signal, channel, security,
                    status, combined_risk, ap_count, signal_var,
                    str(bssid_history), rf_result, knn_result, iso_result,
                    meta_result, meta_conf, rule_based_score,
                    vector_str, signal_pattern_score, mobility_class,
                    coherence_score, recommendations, reason_text
                ])
                
                # Add to historical dataset if new
                if key not in existing_entries:
                    data_writer.writerow([
                        ssid, bssid, avg_signal, channel, security,
                        ap_count, signal_var, label
                    ])
                    existing_entries.add(key)
                    print(f"💾 Saved to historical dataset")

print(f"\n{'='*60}")
print("✅ Scan Complete!")
print(f"{'='*60}")
print(f"\n📁 Results saved to:")
print(f"  Current Scan: {CURRENT_SCAN_FILE}")
print(f"  Historical Data: {DATASET_FILE}")
print(f"\n🎯 Detection Stack Active:")
print(f"  ✓ Rule-Based Threat Scoring (6 vectors)")
print(f"  ✓ Signal Behavior Analysis")
if ml_mode == "hybrid":
    print(f"  ✓ Random Forest Classifier")
    print(f"  ✓ KNN Classifier")
    print(f"  ✓ Isolation Forest")
    print(f"  ✓ Logistic Regression Meta-Classifier")
else:
    print(f"  ⚠ ML Models (training required)")

print(f"\n🌐 View results on dashboard at http://localhost:8501")
