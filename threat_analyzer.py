"""
threat_analyzer.py
====================
Advanced rule-based threat scoring engine with multiple detection vectors.

Detection Vectors:
  1. Signal proximity & path-loss model
  2. Signal stability & temporal RSSI variance
  3. Multi-AP clustering & BSSID spoofing
  4. Channel behavior & frequency anomalies
  5. Security configuration mismatches
  6. MAC address reputation & vendor analysis
"""

import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta

try:
    from threat_intelligence import get_threat_intelligence
except ImportError:
    get_threat_intelligence = None


class AdvancedThreatAnalyzer:
    """Multi-vector threat scoring engine"""
    
    def __init__(self):
        self.threat_history = defaultdict(list)
        self.mac_vendor_db = self._load_mac_vendors()
        self.legitimate_ssids = set()
        self.cloud_intelligence = get_threat_intelligence() if get_threat_intelligence else None
        
    def _load_mac_vendors(self):
        """Load known MAC vendor prefixes"""
        return {
            '00:1A:2B': 'Apple',
            '00:25:86': 'Apple',
            '00:50:F2': 'Microsoft',
            '00:E0:4C': 'Realtek',
            '08:00:27': 'Citrix',
            'AA:BB:CC': 'Unknown',
        }
    
    def analyze_signal_proximity(self, rssi):
        """
        Vector 1: Signal proximity using path-loss model
        
        Path-loss formula: RSSI = -30 - 10*n*log10(distance)
        Where n ≈ 2.0-2.5 in indoor environments
        """
        threat_score = 0
        reasons = []
        
        # Estimate distance using path-loss model
        n = 2.0  # Propagation constant (indoor)
        distance = 10 ** ((rssi + 30) / (-10 * n))
        
        # Physically impossible distances (< 0.5m suggests spoofing/jamming)
        if distance < 0.5:
            threat_score += 30
            reasons.append(f"Physically implausible RSSI ({rssi} dBm = {distance:.2f}m)")
        
        # Very close AP (< 1m) - unusual for legitimate networks
        elif distance < 1.0:
            threat_score += 15
            reasons.append(f"Unusually close AP ({distance:.2f}m)")
        
        # Extreme signal strength (> -20 dBm) - possible Tx power manipulation
        if rssi > -20:
            threat_score += 10
            reasons.append("Abnormally strong signal (possible power manipulation)")
        
        return threat_score, reasons, distance
    
    def analyze_signal_stability(self, rssi_history, time_window=300):
        """
        Vector 2: Signal stability & temporal variance
        
        Legitimate APs have stable RSSI over time.
        Rogue APs often show erratic behavior (spoofing, mobile transmitters).
        """
        threat_score = 0
        reasons = []
        
        if len(rssi_history) < 3:
            return threat_score, reasons
        
        rssi_array = np.array(rssi_history)
        variance = np.var(rssi_array)
        std_dev = np.std(rssi_array)
        max_variance = np.ptp(rssi_array)  # Peak-to-peak
        
        # High variance suggests unstable/mobile transmitter
        if variance > 100:
            threat_score += 25
            reasons.append(f"Extremely high signal variance ({variance:.1f})")
        elif variance > 50:
            threat_score += 15
            reasons.append(f"High signal variance ({variance:.1f})")
        
        # Large range in signal (> 30 dBm) in short time
        if max_variance > 30:
            threat_score += 20
            reasons.append(f"Signal fluctuation range > 30dBm ({max_variance}dBm)")
        
        # Sudden drops in signal (possible movement/spoofing)
        if len(rssi_history) >= 2:
            deltas = [abs(rssi_history[i] - rssi_history[i-1]) 
                     for i in range(1, len(rssi_history))]
            max_delta = max(deltas)
            
            if max_delta > 20:
                threat_score += 10
                reasons.append(f"Sudden signal changes ({max_delta}dBm jumps)")
        
        return threat_score, reasons
    
    def analyze_multi_ap_clustering(self, ssid, bssid_list, signal_strengths):
        """
        Vector 3: Multi-AP clustering & BSSID spoofing detection
        
        Legitimate networks have 2-3 APs (dual-band routers).
        Many APs with same SSID = evil twin attack or spoofing.
        """
        threat_score = 0
        reasons = []
        
        ap_count = len(set(bssid_list))
        
        # Normal WiFi: 1 AP or 2-3 for dual-band/mesh
        if ap_count > 3:
            threat_score += 20
            reasons.append(f"Excessive APs for single SSID ({ap_count} BSSIDs)")
        
        # Check for MAC address similarity (spoofing indicators)
        if len(bssid_list) > 1:
            mac_prefixes = [bssid[:8] for bssid in bssid_list]
            
            # All from same vendor but different MAC = suspicious
            if len(set(mac_prefixes)) == 1:
                threat_score += 15
                reasons.append("Multiple APs with identical MAC prefixes (spoofing pattern)")
        
        # Analyze signal strength consistency
        if len(signal_strengths) > 1:
            avg_signal = np.mean(signal_strengths)
            signal_variance = np.var(signal_strengths)
            
            # Very different signal strengths (one much stronger) = malicious
            if signal_variance > 200:
                threat_score += 12
                reasons.append("Highly inconsistent signal strengths across APs")
        
        return threat_score, reasons
    
    def analyze_channel_behavior(self, channel, frequency=None):
        """
        Vector 4: Channel behavior & frequency anomalies
        
        Valid WiFi channels: 1-13 (2.4GHz), 36-165 (5GHz)
        """
        threat_score = 0
        reasons = []
        
        # Invalid channel number
        if not (1 <= channel <= 13 or 36 <= channel <= 165):
            threat_score += 20
            reasons.append(f"Invalid WiFi channel ({channel})")
        
        # Non-standard channel in 2.4GHz (overlapping channels 1,6,11 are standard)
        if 1 <= channel <= 13 and channel not in [1, 6, 11]:
            threat_score += 5
            reasons.append(f"Non-standard 2.4GHz channel ({channel})")
        
        return threat_score, reasons
    
    def analyze_security_config(self, security_mode):
        """
        Vector 5: Security configuration analysis
        """
        threat_score = 0
        reasons = []
        
        if security_mode == "Open":
            threat_score += 20
            reasons.append("No encryption (Open network)")
        
        elif security_mode == "WEP":
            threat_score += 25
            reasons.append("Deprecated WEP encryption (easily cracked)")
        
        elif security_mode == "WPA":
            threat_score += 10
            reasons.append("Outdated WPA (WPA2/3 recommended)")
        
        elif security_mode == "WPA2":
            # WPA2 is secure, no additional threat
            pass
        
        elif security_mode == "WPA3":
            # WPA3 is most secure
            threat_score -= 5  # Slight boost for security-conscious networks
        
        return threat_score, reasons
    
    def analyze_vendor_reputation(self, bssid):
        """
        Vector 6: MAC address vendor analysis
        """
        threat_score = 0
        reasons = []
        
        if not bssid or len(bssid) < 8:
            return threat_score, reasons
        
        vendor_prefix = bssid[:8]
        vendor = self.mac_vendor_db.get(vendor_prefix, "Unknown")
        
        # Unknown vendors might be suspicious
        if vendor == "Unknown":
            threat_score += 5
            reasons.append(f"Unknown MAC vendor ({vendor_prefix})")
        
        return threat_score, reasons
    
    def calculate_overall_threat(self, network_data):
        """
        Combine all vectors into comprehensive threat assessment
        
        Args:
            network_data: {
                'ssid': str,
                'bssid': str,
                'rssi': int,
                'channel': int,
                'security': str,
                'rssi_history': list,
                'ap_count': int,
                'bssid_list': list,
                'signal_strengths': list
            }
        
        Returns:
            {
                'total_threat_score': int (0-100),
                'threat_level': str (LOW/MEDIUM/HIGH/CRITICAL),
                'vectors': dict,
                'recommendations': list
            }
        """
        
        total_score = 0
        all_reasons = []
        vectors = {}
        
        # Vector 1: Signal Proximity
        score, reasons, distance = self.analyze_signal_proximity(network_data.get('rssi', -50))
        total_score += score
        all_reasons.extend(reasons)
        vectors['signal_proximity'] = {'score': score, 'distance_m': distance}
        
        # Vector 2: Signal Stability
        rssi_history = network_data.get('rssi_history', [network_data.get('rssi', -50)])
        score, reasons = self.analyze_signal_stability(rssi_history)
        total_score += score
        all_reasons.extend(reasons)
        vectors['signal_stability'] = {'score': score}
        
        # Vector 3: Multi-AP Clustering
        bssid_list = network_data.get('bssid_list', [network_data.get('bssid', 'unknown')])
        signal_strengths = network_data.get('signal_strengths', [network_data.get('rssi', -50)])
        score, reasons = self.analyze_multi_ap_clustering(
            network_data.get('ssid', ''),
            bssid_list,
            signal_strengths
        )
        total_score += score
        all_reasons.extend(reasons)
        vectors['multi_ap'] = {'score': score}
        
        # Vector 4: Channel Behavior
        score, reasons = self.analyze_channel_behavior(network_data.get('channel', 6))
        total_score += score
        all_reasons.extend(reasons)
        vectors['channel'] = {'score': score}
        
        # Vector 5: Security Config
        score, reasons = self.analyze_security_config(network_data.get('security', 'Open'))
        total_score += score
        all_reasons.extend(reasons)
        vectors['security'] = {'score': score}
        
        # Vector 6: Vendor Reputation
        score, reasons = self.analyze_vendor_reputation(network_data.get('bssid', ''))
        total_score += score
        all_reasons.extend(reasons)
        vectors['vendor'] = {'score': score}

        # Vector 7: Collaborative cloud reputation.  This is intentionally
        # evaluated before final scoring and remains a no-op in offline mode.
        cloud = self.cloud_intelligence.lookup(network_data.get('bssid', '')) if self.cloud_intelligence else {
            'hit': False, 'risk_score': 0.0, 'threat_type': None
        }
        cloud_penalty = 0.0
        if cloud['hit']:
            # A confirmed BSSID is a strong independent signal, but cap the
            # boost so local observations still contribute to classification.
            cloud_penalty = min(35.0, 15.0 + float(cloud['risk_score']) * 0.20)
            total_score += cloud_penalty
            all_reasons.append(
                f"Cloud reputation hit: {cloud['threat_type']} (cloud risk {cloud['risk_score']:.0f}%)"
            )
        vectors['cloud_intelligence'] = {
            'score': cloud_penalty,
            'hit': cloud['hit'],
            'cloud_risk_score': cloud['risk_score'],
            'threat_type': cloud['threat_type'],
        }
        
        # Clamp score to 0-100
        total_score = max(0, min(100, total_score))
        
        # Determine threat level
        if total_score >= 70:
            threat_level = "CRITICAL"
        elif total_score >= 50:
            threat_level = "HIGH"
        elif total_score >= 25:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_level, all_reasons)
        
        return {
            'total_threat_score': total_score,
            'threat_level': threat_level,
            'vectors': vectors,
            'reasons': all_reasons,
            'recommendations': recommendations,
            'cloud_hit': cloud['hit'],
        }
    
    def _generate_recommendations(self, threat_level, reasons):
        """Generate security recommendations based on threat level"""
        recommendations = []
        
        if threat_level == "CRITICAL":
            recommendations.append("🚨 AVOID connecting to this network")
            recommendations.append("Report to network administrator")
            recommendations.append("Consider alerting security team")
        
        elif threat_level == "HIGH":
            recommendations.append("⚠️ Use caution when connecting")
            recommendations.append("Do not transmit sensitive data")
            recommendations.append("Enable VPN before connecting")
        
        elif threat_level == "MEDIUM":
            recommendations.append("✓ Moderate security - basic protection recommended")
            recommendations.append("Update network security settings")
        
        else:
            recommendations.append("✅ Safe to connect")
        
        return recommendations


if __name__ == "__main__":
    analyzer = AdvancedThreatAnalyzer()
    
    # Test network
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
    
    result = analyzer.calculate_overall_threat(test_network)
    print(f"\n📊 Threat Assessment:\n{result}")
