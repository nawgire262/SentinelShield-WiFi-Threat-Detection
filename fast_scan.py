"""
Fast Async WiFi Scanner
Runs with zero lag - all detection engines execute in parallel
Results stream to dashboard in real-time
"""

import sys
import time
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from background_scanner import get_scanner, ScanStatus

def main():
    """Run async scan with real-time progress"""
    
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                 🚀 FAST ASYNC WiFi SCANNER                        ║
║                                                                    ║
║   • All detection engines run in parallel (NO BLOCKING)           ║
║   • Rule-based + Signal + ML analysis simultaneous               ║
║   • Real-time progress tracking                                   ║
║   • Zero lag to dashboard                                         ║
╚════════════════════════════════════════════════════════════════════╝
    """)
    
    # Get global scanner
    scanner = get_scanner()
    
    print("✅ Loaded detection engines:")
    print("   • Advanced Threat Analyzer (6 vectors)")
    print("   • Signal Behavior Analyzer")
    print("   • Advanced Feature Extractor")
    print("   • ML Ensemble (RF + KNN + IF + LR)")
    
    if scanner.ml_available:
        print("   • ML Models: ✅ LOADED")
    else:
        print("   • ML Models: ⚠️ FALLBACK (will use rule-based only)")
    
    print("\n🚀 Starting async background scan...")
    print("   → All engines run in parallel threads")
    print("   → No blocking on frontend")
    print("   → Results stream as they complete\n")
    
    # Start async scan
    if not scanner.start_scan_async():
        print("❌ Scan already in progress!")
        return
    
    # Track progress in real-time
    last_progress = 0
    last_networks = 0
    
    while True:
        status = scanner.get_status()
        progress = status['progress']
        networks = status['networks_found']
        
        # Only print on significant changes to avoid spam
        if progress != last_progress or networks != last_networks:
            elapsed = int(status['elapsed_time'])
            
            # Progress bar
            bar_length = 40
            filled = int(bar_length * progress / 100)
            bar = '█' * filled + '░' * (bar_length - filled)
            
            print(f"\r[{bar}] {progress:3d}% | Found: {networks:2d} networks | {elapsed:2d}s elapsed", end='', flush=True)
            
            last_progress = progress
            last_networks = networks
        
        # Check if complete
        if status['status'] == ScanStatus.COMPLETE:
            print("\n\n✅ SCAN COMPLETE!")
            break
        elif status['status'] == ScanStatus.ERROR:
            print(f"\n\n❌ ERROR: {status['error']}")
            return
        
        time.sleep(0.1)  # Small sleep to avoid CPU spinning
    
    # Get final results
    results = scanner.get_results()
    
    print(f"\n📊 RESULTS:")
    print(f"   • Networks scanned: {results.get('count', 0)}")
    print(f"   • Data saved to: {results.get('csv_path', 'N/A')}")
    print(f"   • Timestamp: {results.get('timestamp', 'N/A')}")
    
    # Show brief summary
    if 'networks' in results:
        networks_data = results['networks']
        
        critical = sum(1 for n in networks_data if n.get('Threat_Level') == 'CRITICAL')
        high = sum(1 for n in networks_data if n.get('Threat_Level') == 'HIGH')
        medium = sum(1 for n in networks_data if n.get('Threat_Level') == 'MEDIUM')
        safe = sum(1 for n in networks_data if n.get('Threat_Level') in ['SAFE', None])
        
        print(f"\n🎯 THREAT BREAKDOWN:")
        print(f"   • 🚨 Critical: {critical}")
        print(f"   • 🔴 High: {high}")
        print(f"   • 🟡 Medium: {medium}")
        print(f"   • 🟢 Safe: {safe}")
    
    print("\n💡 Next: streamlit run dashboard.py")
    print("   Open: http://localhost:8501\n")

if __name__ == "__main__":
    main()
