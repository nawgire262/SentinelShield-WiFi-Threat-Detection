"""
System Verification & Setup Check
Validates all components are working before running scans
"""

import sys
import os
from pathlib import Path

def check_environment():
    """Check Python environment and dependencies"""
    
    print("\n" + "="*70)
    print("🔍 ENVIRONMENT CHECK")
    print("="*70)
    
    # Python version
    print(f"\n✓ Python: {sys.version.split()[0]}")
    
    # Check dependencies
    dependencies = {
        'streamlit': 'Frontend Dashboard',
        'pandas': 'Data Processing',
        'numpy': 'Numerical Computing',
        'matplotlib': 'Visualization',
        'scikit-learn': 'Machine Learning',
        'pywifi': 'WiFi Scanning',
    }
    
    missing = []
    for pkg, description in dependencies.items():
        try:
            __import__(pkg)
            print(f"✓ {pkg:15} - {description}")
        except ImportError:
            print(f"✗ {pkg:15} - MISSING!")
            missing.append(pkg)
    
    if missing:
        print(f"\n❌ Missing packages: {', '.join(missing)}")
        print(f"   Fix: pip install {' '.join(missing)}")
        return False
    
    return True

def check_files():
    """Check all required files exist"""
    
    print("\n" + "="*70)
    print("📁 FILE CHECK")
    print("="*70 + "\n")
    
    required_files = {
        'main_advanced.py': 'Main scanner engine',
        'dashboard.py': 'Dashboard UI',
        'background_scanner.py': 'Async backend',
        'threat_analyzer.py': 'Rule-based detection',
        'signal_analyzer.py': 'Signal analysis',
        'advanced_features.py': 'Feature engineering',
        'ml_ensemble.py': 'ML ensemble',
        'fast_scan.py': 'Fast async runner',
        'requirements.txt': 'Dependencies',
    }
    
    ml_models = {
        'rf_model.pkl': 'Random Forest model',
        'knn_model.pkl': 'KNN model',
        'le_security.pkl': 'Security encoder',
        'le_label.pkl': 'Label encoder',
    }
    
    missing_core = []
    for file, desc in required_files.items():
        if Path(file).exists():
            print(f"✓ {file:25} - {desc}")
        else:
            print(f"✗ {file:25} - MISSING!")
            missing_core.append(file)
    
    print("\n--- ML Models (Optional, graceful fallback if missing) ---")
    missing_ml = []
    for file, desc in ml_models.items():
        if Path(file).exists():
            print(f"✓ {file:25} - {desc}")
        else:
            print(f"⚠ {file:25} - Will use rule-based only")
            missing_ml.append(file)
    
    if missing_core:
        print(f"\n❌ Missing core files: {', '.join(missing_core)}")
        return False
    
    return True

def check_ml_models():
    """Check ML models load correctly"""
    
    print("\n" + "="*70)
    print("🤖 ML MODEL CHECK")
    print("="*70 + "\n")
    
    try:
        from ml_ensemble import HybridEnsembleDetector
        print("✓ ML Ensemble import successful")
        
        detector = HybridEnsembleDetector()
        result = detector.load_models()
        
        if result:
            print("✓ ML Models loaded successfully")
            print(f"  Models available: {result}")
            return True
        else:
            print("⚠ Models not available, will use graceful fallback")
            return True
    
    except Exception as e:
        print(f"❌ ML Error: {e}")
        print("   System will still work with rule-based detection only")
        return True  # Not critical

def check_detection_engines():
    """Check all detection engines initialize"""
    
    print("\n" + "="*70)
    print("⚙️  DETECTION ENGINES CHECK")
    print("="*70 + "\n")
    
    try:
        from threat_analyzer import AdvancedThreatAnalyzer
        print("✓ Threat Analyzer loaded")
    except Exception as e:
        print(f"❌ Threat Analyzer: {e}")
        return False
    
    try:
        from signal_analyzer import AdvancedSignalAnalyzer
        print("✓ Signal Analyzer loaded")
    except Exception as e:
        print(f"❌ Signal Analyzer: {e}")
        return False
    
    try:
        from advanced_features import AdvancedFeatureExtractor
        print("✓ Feature Extractor loaded")
    except Exception as e:
        print(f"❌ Feature Extractor: {e}")
        return False
    
    try:
        from background_scanner import BackgroundScanner
        print("✓ Background Scanner loaded")
    except Exception as e:
        print(f"❌ Background Scanner: {e}")
        return False
    
    return True

def check_wifi():
    """Check WiFi adapter"""
    
    print("\n" + "="*70)
    print("📡 WIFI ADAPTER CHECK")
    print("="*70 + "\n")
    
    try:
        import pywifi
        wifi = pywifi.PyWiFi()
        interfaces = wifi.interfaces()
        
        if interfaces:
            print(f"✓ WiFi adapter detected: {len(interfaces)} interface(s)")
            for i, iface in enumerate(interfaces, 1):
                print(f"  {i}. {iface.name()}")
            return True
        else:
            print("❌ No WiFi adapters found!")
            print("   • Check WiFi is enabled")
            print("   • Try restarting WiFi")
            print("   • Run PowerShell as Administrator")
            return False
    
    except Exception as e:
        print(f"❌ WiFi Check Error: {e}")
        return False

def run_all_checks():
    """Run all checks"""
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║               SENTINELSHIELD SYSTEM VERIFICATION                  ║
║           Check all components before running scanner             ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    
    results = {
        'Environment': check_environment(),
        'Files': check_files(),
        'Detection Engines': check_detection_engines(),
        'ML Models': check_ml_models(),
        'WiFi Adapter': check_wifi(),
    }
    
    # Summary
    print("\n" + "="*70)
    print("✅ VERIFICATION SUMMARY")
    print("="*70 + "\n")
    
    all_pass = True
    for check, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{check:30} {status}")
        if not result:
            all_pass = False
    
    print("\n" + "="*70)
    
    if all_pass:
        print("""
✅ ALL CHECKS PASSED!

Ready to run:
   1. python fast_scan.py          (Run background scan)
   2. streamlit run dashboard.py   (View results)

Or run both together:
   Terminal 1: python fast_scan.py
   Terminal 2: streamlit run dashboard.py
        """)
    else:
        print("""
⚠️  SOME CHECKS FAILED

Fix the issues above and try again.

Need help?
   • Check requirements.txt: pip install -r requirements.txt
   • Run PowerShell as Administrator
   • Enable WiFi adapter
   • Ensure Python 3.8+
        """)
    
    print("="*70 + "\n")
    
    return all_pass

if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
