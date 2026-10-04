"""
ADVANCED_SETUP.md
=================
Setup guide for next-gen WiFi threat detection system

NEW Files & Components:
  1. ml_ensemble.py - Hybrid ML ensemble (RF + KNN + IF + LR stacker)
  2. threat_analyzer.py - Advanced rule-based threat scoring (6 vectors)
  3. signal_analyzer.py - Signal behavior analysis
  4. advanced_features.py - Feature engineering
  5. main_advanced.py - Integrated scanning engine

Usage Instructions
"""

import subprocess
import sys
import os

print("""
╔════════════════════════════════════════════════════════════════╗
║       SentinelShield - Advanced WiFi Threat Detection          ║
║          Next-Gen ML + Rule-Based Detection Stack              ║
╚════════════════════════════════════════════════════════════════╝

📋 SETUP STEPS:
""")

print("\n1️⃣ INSTALL DEPENDENCIES")
print("   Make sure all required packages are installed:")
print("   - scikit-learn (ML models)")
print("   - pandas (data handling)")
print("   - numpy (numerical computing)")

deps_cmd = [sys.executable, "-m", "pip", "install", 
            "scikit-learn", "pandas", "numpy", "-q"]

print("   Installing...", end=" ")
try:
    subprocess.run(deps_cmd, check=True)
    print("✅ Done!")
except:
    print("⚠️ Some packages may not have installed")

print("\n2️⃣ TRAIN ML MODELS (if you have historical data)")
print("   Command: python ml_ensemble.py")
print("   This will generate:")
print("   - rf_model.pkl (Random Forest)")
print("   - knn_model.pkl (KNN)")
print("   - iso_model.pkl (Isolation Forest)")
print("   - meta_model.pkl (Logistic Regression)")
print("   - scaler.pkl, le_security.pkl, le_label.pkl")

print("\n3️⃣ RUN ADVANCED SCAN")
print("   Command: python main_advanced.py")
print("   This will:")
print("   ✓ Scan WiFi networks (5 passes)")
print("   ✓ Apply rule-based threat scoring")
print("   ✓ Analyze signal behavior")
print("   ✓ Run ML ensemble (if models available)")
print("   ✓ Generate comprehensive threat assessment")
print("   ✓ Save results to current_scan.csv")

print("\n4️⃣ VIEW RESULTS ON DASHBOARD")
print("   Command: streamlit run dashboard.py")
print("   Navigate to: http://localhost:8501")

print("\n" + "="*60)
print("DETECTION STACK OVERVIEW")
print("="*60)

print("""
🎯 RULE-BASED THREAT SCORING (6 Vectors):
  1. Signal Proximity (path-loss model, physical plausibility)
  2. Signal Stability (temporal variance, mobility detection)
  3. Multi-AP Clustering (BSSID spoofing indicators)
  4. Channel Behavior (valid channels, interference analysis)
  5. Security Configuration (encryption strength scoring)
  6. Vendor Reputation (MAC vendor analysis)

🧠 ML ENSEMBLE:
  - Base Layer:
    • Random Forest (100 trees, supervised learning)
    • KNN Classifier (5 neighbors, local similarity)
    • Isolation Forest (anomaly detection on legit data)
  
  - Meta Layer:
    • Logistic Regression (stacked voting with OOF)
    • Cross-validation to avoid data leakage

🔬 SIGNAL BEHAVIOR ANALYSIS:
  - RSSI Pattern Detection (variance, autocorrelation)
  - Mobility Classification (stationary/mobile)
  - Beamforming Detection (signal peak sharpness)
  - TX Power Anomalies (unusual transmit power)
  - Temporal Coherence (smoothness analysis)

📊 OUTPUT METRICS:
  • Combined Risk Score (0-100)
  • Individual Vector Scores
  • Signal Pattern Anomaly Score
  • ML Ensemble Confidence
  • Threat Level (LOW/MEDIUM/HIGH/CRITICAL)
  • Actionable Recommendations
""")

print("\n" + "="*60)
print("QUICK START")
print("="*60)
print("""
Windows PowerShell:
  cd C:\\Users\\OM\\Downloads\\Wifi_Detection V1
  
  # First time setup
  python -m venv .venv
  .\.venv\\Scripts\\Activate.ps1
  pip install -r requirements.txt
  
  # Train models (if you have historical data)
  python ml_ensemble.py
  
  # Run advanced scan
  python main_advanced.py
  
  # View dashboard
  streamlit run dashboard.py
  
Then open: http://localhost:8501
""")

print("\n" + "="*60)
print("FILE DESCRIPTIONS")
print("="*60)
print("""
📄 ml_ensemble.py
   Hybrid stacked ensemble with out-of-fold training.
   Trains: RF, KNN, Isolation Forest, LR meta-classifier
   Usage: python ml_ensemble.py

📄 threat_analyzer.py
   Multi-vector threat assessment engine.
   Analyzes: proximity, stability, clustering, channels, security, vendor
   Usage: from threat_analyzer import AdvancedThreatAnalyzer

📄 signal_analyzer.py
   Advanced signal behavior analysis.
   Detects: pattern anomalies, mobility, beamforming, TX power issues
   Usage: from signal_analyzer import AdvancedSignalAnalyzer

📄 advanced_features.py
   Feature engineering for ML models.
   Extracts: 15+ engineered features from raw WiFi data
   Usage: from advanced_features import AdvancedFeatureExtractor

📄 main_advanced.py
   Integrated scanning engine with full detection stack.
   Combines: rule-based + signal + ML analysis
   Usage: python main_advanced.py

📄 dashboard.py (updated)
   Streamlit dashboard showing all analysis results
   Usage: streamlit run dashboard.py
""")

print("\n✅ Setup complete! Start with Step 1 above.")
