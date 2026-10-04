"""
run_advanced_scan.py
====================
Unified advanced WiFi threat detection scanner.

Combines:
  ✓ Rule-Based Threat Scoring (6 vectors)
  ✓ Signal Behavior Analysis
  ✓ ML Ensemble (RF + KNN + IF + LR Meta-Classifier)
  
Usage: python run_advanced_scan.py
"""

import sys
import os

def print_banner():
    """Print startup banner"""
    print("\n" + "="*70)
    print("  🛡️  SentinelShield - Advanced WiFi Threat Detection")
    print("  Detection Stack: Rule-Based + Signal + ML Ensemble")
    print("="*70 + "\n")

def main():
    print_banner()
    
    # Check if main_advanced.py exists
    if not os.path.exists("main_advanced.py"):
        print("❌ main_advanced.py not found!")
        print("   Make sure you're in the Wifi_Detection V1 directory")
        sys.exit(1)
    
    print("📡 Starting advanced WiFi scan...\n")
    
    # Import and run main_advanced
    try:
        # This will execute main_advanced.py directly
        with open("main_advanced.py", "r") as f:
            code = f.read()
        
        # Execute with proper namespace
        exec(code, {'__name__': '__main__', '__file__': 'main_advanced.py'})
    
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
