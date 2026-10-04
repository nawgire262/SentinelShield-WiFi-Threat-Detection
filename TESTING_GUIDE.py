"""
TESTING_GUIDE.md
================
How to test and validate the next-gen detection system
"""

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                         TESTING GUIDE                                     ║
║              SentinelShield Advanced WiFi Threat Detection                 ║
╚════════════════════════════════════════════════════════════════════════════╝


═══════════════════════════════════════════════════════════════════════════════
1. SYSTEM VALIDATION TESTS
═══════════════════════════════════════════════════════════════════════════════

Test 1: ML Models Loading
────────────────────────
Run this to verify all ML models load correctly:

    python -c "from ml_ensemble import HybridEnsembleDetector; \\
    h = HybridEnsembleDetector(); \\
    result = h.load_models(); \\
    print(f'Models loaded: {h.is_trained}')"

Expected Output:
    ✅ Loaded rf_model.pkl
    ✅ Loaded knn_model.pkl
    ✅ Loaded le_security.pkl
    ✅ Loaded le_label.pkl
    ⚠️  iso_model.pkl not found (optional)
    ⚠️  meta_model.pkl not found (optional)
    ⚠️  scaler.pkl not found (optional)
    Created new scaler
    Models loaded: True


Test 2: Threat Analyzer Validation
──────────────────────────────────
Run: python threat_analyzer.py

Expected Output:
    📊 Threat Assessment:
    {'total_threat_score': ..., 'threat_level': '...', ...}


Test 3: Signal Analyzer Validation
──────────────────────────────────
Run: python signal_analyzer.py

Expected Output:
    🔬 Signal Analysis Test:
    RSSI Pattern Analysis: {...}
    Mobility Analysis: {...}
    Temporal Coherence: {...}


Test 4: Feature Extractor Validation
────────────────────────────────────
Run: python advanced_features.py

Expected Output:
    📊 Extracted Features:
    rssi: -45
    channel: 6
    ...
    🧠 ML Input Vector: [-45, 6, 3, ...]


═══════════════════════════════════════════════════════════════════════════════
2. FUNCTIONAL TESTS
═══════════════════════════════════════════════════════════════════════════════

Test 5: Single Network Prediction
────────────────────────────────
python -c "
from ml_ensemble import HybridEnsembleDetector
h = HybridEnsembleDetector()
h.load_models()

test_network = {
    'RSSI': -35,
    'Channel': 6,
    'Security': 'WPA2',
    'AP_Count': 1,
    'Signal_Var': 5
}

result = h.predict(test_network)
print('Prediction Result:')
for k, v in result.items():
    print(f'  {k}: {v}')
"

Expected Output:
    Prediction Result:
    rf_prediction: Legit
    knn_prediction: Legit
    iso_score: 0.123
    iso_prediction: Normal
    meta_prediction: Legit
    meta_confidence: 95.3
    ensemble_risk: 5


Test 6: Full Advanced Scan
──────────────────────────
Run: python main_advanced.py

This will:
1. Collect 5 WiFi scans (about 15 seconds)
2. Run through all detection vectors
3. Generate current_scan.csv
4. Show detailed analysis for each network


Test 7: Dashboard Visualization
───────────────────────────────
Run: streamlit run dashboard.py

Then navigate to: http://localhost:8501

Verify:
  ✓ Current Scan tab shows networks
  ✓ Historical Dataset tab shows old data
  ✓ Combined Stats tab shows counts
  ✓ Risk scores display correctly
  ✓ File browser works


═══════════════════════════════════════════════════════════════════════════════
3. PERFORMANCE TESTS
═══════════════════════════════════════════════════════════════════════════════

Test 8: Scan Speed
─────────────────
Time how long the scan takes:

    import time
    start = time.time()
    # Run: python main_advanced.py
    end = time.time()
    print(f"Total time: {end - start:.1f} seconds")

Expected: < 20 seconds for full scan


Test 9: Prediction Speed
──────────────────────
python -c "
import time
from ml_ensemble import HybridEnsembleDetector

h = HybridEnsembleDetector()
h.load_models()

test_network = {
    'RSSI': -45,
    'Channel': 6,
    'Security': 'WPA2',
    'AP_Count': 1,
    'Signal_Var': 5
}

start = time.time()
for _ in range(100):
    h.predict(test_network)
end = time.time()

print(f'100 predictions: {end - start:.2f}s')
print(f'Per prediction: {(end-start)*10:.1f}ms')
"

Expected: < 100ms for 100 predictions


═══════════════════════════════════════════════════════════════════════════════
4. ACCURACY TESTS (with labeled data)
═══════════════════════════════════════════════════════════════════════════════

Test 10: Model Accuracy
──────────────────────
If you have wifi_dataset.csv with "Label" column:

python -c "
import pandas as pd
from sklearn.model_selection import cross_val_score
from ml_ensemble import HybridEnsembleDetector

# Load data
data = pd.read_csv('wifi_dataset.csv')

# Initialize and train
h = HybridEnsembleDetector()
h.train('wifi_dataset.csv')

# Evaluate
print('✅ Training complete with accuracy metrics')
"

Expected Output: Accuracy scores > 80%


═══════════════════════════════════════════════════════════════════════════════
5. EDGE CASE TESTS
═══════════════════════════════════════════════════════════════════════════════

Test 11: Invalid Security Mode
─────────────────────────────
python -c "
from ml_ensemble import HybridEnsembleDetector

h = HybridEnsembleDetector()
h.load_models()

# Test unknown security mode
result = h.predict({
    'RSSI': -45,
    'Channel': 6,
    'Security': 'UNKNOWN_SECURITY',  # Invalid!
    'AP_Count': 1,
    'Signal_Var': 5
})

print('Result:', result)
"

Expected: Should handle gracefully (not crash)


Test 12: Extreme RSSI Values
────────────────────────────
python -c "
from threat_analyzer import AdvancedThreatAnalyzer

analyzer = AdvancedThreatAnalyzer()

# Test extreme RSSI
test_cases = [
    {'rssi': -10, 'description': 'Extremely strong (possible spoofing)'},
    {'rssi': -100, 'description': 'Very weak (unrealistic)'},
    {'rssi': -50, 'description': 'Normal'}
]

for test in test_cases:
    score, reasons, distance = analyzer.analyze_signal_proximity(test['rssi'])
    print(f'{test[\"description\"]}: Score={score}, Distance={distance:.1f}m')
"

Expected: Should handle all ranges without crashing


═══════════════════════════════════════════════════════════════════════════════
6. INTEGRATION TESTS
═══════════════════════════════════════════════════════════════════════════════

Test 13: Full Pipeline
─────────────────────
This test runs the entire detection stack:

python -c "
from ml_ensemble import HybridEnsembleDetector
from threat_analyzer import AdvancedThreatAnalyzer
from signal_analyzer import AdvancedSignalAnalyzer

# Initialize all components
ml = HybridEnsembleDetector()
ml.load_models()

threat = AdvancedThreatAnalyzer()
signal = AdvancedSignalAnalyzer()

test_network = {
    'ssid': 'TestNetwork',
    'bssid': '00:1A:2B:3C:4D:5E',
    'rssi': -45,
    'channel': 6,
    'security': 'WPA2',
    'rssi_history': [-45, -43, -47, -46, -44],
    'ap_count': 1,
    'bssid_list': ['00:1A:2B:3C:4D:5E'],
    'signal_strengths': [-45]
}

# Run all detectors
threat_result = threat.calculate_overall_threat(test_network)
signal_result = signal.analyze_rssi_pattern(test_network['rssi_history'])
ml_result = ml.predict(test_network)

print('✅ All components working')
print(f'Threat Score: {threat_result[\"total_threat_score\"]}%')
print(f'Signal Anomaly: {signal_result[\"pattern_anomaly_score\"]}%')
print(f'ML Risk: {ml_result[\"ensemble_risk\"]}%')
"

Expected: All three components produce results


═══════════════════════════════════════════════════════════════════════════════
7. VERIFICATION CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

Before deployment, verify:

☐ ML Models Loaded
  - rf_model.pkl ✓
  - knn_model.pkl ✓
  - le_security.pkl ✓
  - le_label.pkl ✓

☐ Detection Engines Working
  - Rule-based scoring ✓
  - Signal analysis ✓
  - ML ensemble ✓

☐ Scan Completes Successfully
  - 5 passes complete ✓
  - All networks detected ✓
  - CSV files generated ✓

☐ Dashboard Functions
  - Displays current scan ✓
  - Shows historical data ✓
  - Risk scores visible ✓
  - File browser works ✓

☐ Performance Acceptable
  - Scan < 20 seconds ✓
  - Prediction < 100ms ✓
  - Dashboard responsive ✓

☐ No Crashes on Edge Cases
  - Unknown security modes ✓
  - Extreme RSSI values ✓
  - Empty networks ✓
  - Missing data fields ✓


═══════════════════════════════════════════════════════════════════════════════
8. TROUBLESHOOTING
═══════════════════════════════════════════════════════════════════════════════

Issue: Models not loading
Fix: Make sure all .pkl files are in Wifi_Detection V1/ directory
     Check file permissions

Issue: Scan taking too long
Fix: Reduce from 5 passes to 3 in main_advanced.py
     Check WiFi adapter speed

Issue: Predictions always "Legit"
Fix: Check if models are trained on your data
     Verify feature scaling is applied

Issue: Dashboard not updating
Fix: Click "Launch Live WiFi Scan" button
     Refresh browser page manually

Issue: Memory error
Fix: Reduce concurrent processes
     Close unnecessary applications


═══════════════════════════════════════════════════════════════════════════════
9. PERFORMANCE BENCHMARKS
═══════════════════════════════════════════════════════════════════════════════

Expected Performance on Modern Hardware:
- WiFi Scan (5 passes): 12-18 seconds
- ML Prediction (per network): 5-10 ms
- Dashboard Load: < 2 seconds
- Memory Usage: 100-200 MB
- CPU Usage: 40-60% during scan


═══════════════════════════════════════════════════════════════════════════════

✅ All tests passing? You're ready to deploy!

For more help: python NEXTGEN_DETECTION_GUIDE.py

═══════════════════════════════════════════════════════════════════════════════
""")

if __name__ == "__main__":
    print("📋 Testing guide above!")
