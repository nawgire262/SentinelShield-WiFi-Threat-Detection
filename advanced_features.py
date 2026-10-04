"""
advanced_features.py
=====================
Advanced feature extraction for WiFi networks.

Extracts engineered features from raw WiFi scan data.
"""

import numpy as np
from collections import defaultdict


class AdvancedFeatureExtractor:
    """Extract advanced features for ML models"""
    
    def __init__(self):
        self.feature_cache = {}
        self.ssid_history = defaultdict(list)
        self.bssid_history = defaultdict(list)
        
    def extract_features(self, network_data):
        """
        Extract comprehensive features from network data
        
        Args:
            network_data: {
                'ssid': str,
                'bssid': str,
                'rssi': int,
                'channel': int,
                'security': str,
                'frequency': int (MHz),
                'max_rate': int,
                'is_80211n': bool,
                'is_80211ac': bool,
                'is_80211ax': bool
            }
        
        Returns:
            dict of engineered features
        """
        
        features = {}
        
        # Basic features
        features['rssi'] = network_data.get('rssi', -50)
        features['channel'] = network_data.get('channel', 6)
        
        # Derived features
        features['rssi_band_category'] = self._categorize_rssi(network_data.get('rssi', -50))
        features['channel_interference_risk'] = self._calculate_channel_interference(
            network_data.get('channel', 6)
        )
        
        # Frequency analysis
        features['frequency'] = network_data.get('frequency', 2400)
        features['frequency_band'] = self._determine_frequency_band(network_data.get('frequency', 2400))
        
        # Security features
        features['security_score'] = self._score_security(network_data.get('security', 'Open'))
        features['security_encoding'] = self._encode_security(network_data.get('security', 'Open'))
        
        # Protocol features
        features['protocol_modernity'] = self._score_protocol_modernity(
            network_data.get('is_80211n', False),
            network_data.get('is_80211ac', False),
            network_data.get('is_80211ax', False)
        )
        
        # Signal quality features
        features['data_rate'] = network_data.get('max_rate', 0)
        features['rate_stability'] = self._estimate_rate_stability(network_data.get('max_rate', 0))
        
        # Behavioral features
        features['ssid_length'] = len(network_data.get('ssid', ''))
        features['ssid_printability'] = self._calculate_ssid_printability(network_data.get('ssid', ''))
        features['bssid_entropy'] = self._calculate_bssid_entropy(network_data.get('bssid', ''))
        
        # Derived threat indicators
        features['spoofing_likelihood'] = self._calculate_spoofing_likelihood(
            network_data.get('ssid', ''),
            network_data.get('bssid', '')
        )
        
        features['hidden_ssid_flag'] = 1 if network_data.get('ssid', '') == '' else 0
        
        return features
    
    def _categorize_rssi(self, rssi):
        """Categorize RSSI into signal strength bands"""
        if rssi >= -30:
            return 5  # Excellent
        elif rssi >= -50:
            return 4  # Very Good
        elif rssi >= -70:
            return 3  # Good
        elif rssi >= -80:
            return 2  # Fair
        else:
            return 1  # Poor
    
    def _calculate_channel_interference(self, channel):
        """
        Calculate interference risk based on channel
        
        2.4GHz: channels 1, 6, 11 don't overlap
        Others cause interference
        """
        if channel in [1, 6, 11]:
            return 1  # Low interference
        elif 1 <= channel <= 13:
            return 3  # Moderate-high interference
        elif 36 <= channel <= 144:
            return 1  # 5GHz channels, generally isolated
        else:
            return 5  # Unknown/invalid
    
    def _determine_frequency_band(self, frequency):
        """Determine frequency band"""
        if 2400 <= frequency <= 2500:
            return 0  # 2.4GHz
        elif 5000 <= frequency <= 6000:
            return 1  # 5GHz
        elif 6000 <= frequency <= 7000:
            return 2  # 6GHz
        else:
            return -1  # Unknown
    
    def _score_security(self, security_mode):
        """Score security mode from 0 (open) to 10 (WPA3)"""
        scoring = {
            'Open': 0,
            'WEP': 1,
            'WPA': 4,
            'WPA2': 8,
            'WPA3': 10,
            'Unknown': 2
        }
        return scoring.get(security_mode, 2)
    
    def _encode_security(self, security_mode):
        """Numerical encoding for security"""
        encoding = {
            'Open': 0,
            'WEP': 1,
            'WPA': 2,
            'WPA2': 3,
            'WPA3': 4,
            'Unknown': 5
        }
        return encoding.get(security_mode, 5)
    
    def _score_protocol_modernity(self, is_n, is_ac, is_ax):
        """Score WiFi protocol modernity"""
        score = 0
        
        if is_ax:
            score = 5  # WiFi 6
        elif is_ac:
            score = 4  # WiFi 5
        elif is_n:
            score = 3  # WiFi 4
        else:
            score = 1  # Older
        
        return score
    
    def _estimate_rate_stability(self, max_rate):
        """Estimate rate stability based on max rate"""
        if max_rate >= 1200:  # AX
            return 5
        elif max_rate >= 867:  # AC
            return 4
        elif max_rate >= 450:  # N
            return 3
        elif max_rate >= 54:   # G
            return 2
        else:
            return 1
    
    def _calculate_ssid_printability(self, ssid):
        """
        Calculate SSID printability score
        
        Legitimate SSIDs: mostly printable ASCII
        Rogue SSIDs: often contain non-printable chars or binary
        """
        if not ssid:
            return 0  # Hidden SSID
        
        printable_count = sum(1 for c in ssid if ord(c) >= 32 and ord(c) <= 126)
        
        return (printable_count / len(ssid)) * 10
    
    def _calculate_bssid_entropy(self, bssid):
        """
        Calculate BSSID entropy
        
        Random MACs have high entropy (suspicious).
        Legitimate MACs follow vendor patterns.
        """
        if not bssid or ':' not in bssid:
            return 0
        
        bytes_list = bssid.split(':')
        
        # Count unique bytes
        unique_bytes = len(set(bytes_list))
        
        # High uniqueness = potential spoofing
        entropy = (unique_bytes / 6) * 10
        
        return entropy
    
    def _calculate_spoofing_likelihood(self, ssid, bssid):
        """
        Calculate likelihood of BSSID spoofing
        
        Indicators:
        - Random BSSID
        - Mismatched vendor for SSID
        """
        score = 0
        
        if not bssid or not ssid:
            return 0
        
        # Check for sequential/random MAC addresses
        mac_bytes = [int(x, 16) for x in bssid.split(':')]
        
        # Very regular MAC = more legitimate
        variance = np.var(mac_bytes) if len(mac_bytes) > 1 else 0
        
        if variance > 50:
            score += 5  # High randomness
        
        return score
    
    def generate_ml_input_vector(self, network_data):
        """Generate feature vector for ML models"""
        features = self.extract_features(network_data)
        
        # Select features in order for ML models
        feature_order = [
            'rssi',
            'channel',
            'security_encoding',
            'protocol_modernity',
            'channel_interference_risk',
            'rssi_band_category'
        ]
        
        vector = [features.get(f, 0) for f in feature_order]
        
        return vector


if __name__ == "__main__":
    extractor = AdvancedFeatureExtractor()
    
    # Test network
    test_network = {
        'ssid': 'TestNetwork',
        'bssid': '00:1A:2B:3C:4D:5E',
        'rssi': -45,
        'channel': 6,
        'security': 'WPA2',
        'frequency': 2437,
        'max_rate': 867,
        'is_80211n': True,
        'is_80211ac': False,
        'is_80211ax': False
    }
    
    features = extractor.extract_features(test_network)
    print("📊 Extracted Features:")
    for key, value in features.items():
        print(f"  {key}: {value}")
    
    ml_vector = extractor.generate_ml_input_vector(test_network)
    print(f"\n🧠 ML Input Vector: {ml_vector}")
