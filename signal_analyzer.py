"""
signal_analyzer.py
===================
Advanced signal behavior analysis for WiFi networks.

Analyzes:
  - RSSI patterns & mobility indicators
  - Signal fluctuation & stability
  - Temporal coherence analysis
  - Beamforming & TX power anomalies
"""

import numpy as np
from collections import defaultdict
from datetime import datetime, timedelta


def _valid_rssi_array(values):
    """Return finite, physically plausible RSSI samples from untrusted input."""
    try:
        array = np.asarray(list(values), dtype=float)
    except (TypeError, ValueError):
        return np.asarray([], dtype=float)
    return array[np.isfinite(array) & (array >= -127.0) & (array <= 0.0)]


class AdvancedSignalAnalyzer:
    """Signal behavior analysis engine"""
    
    def __init__(self, window_size=30):
        self.window_size = max(1, int(window_size))  # seconds
        self.signal_buffer = defaultdict(list)  # BSSID -> [(timestamp, rssi), ...]
        
    def add_signal_reading(self, bssid, rssi, timestamp=None):
        """Add RSSI reading with timestamp"""
        bssid = str(bssid or "").strip().upper()
        try:
            rssi = float(rssi)
        except (TypeError, ValueError):
            return False
        if not bssid or len(bssid) > 64 or not np.isfinite(rssi) or not -127.0 <= rssi <= 0.0:
            return False
        if timestamp is None:
            timestamp = datetime.now()
        if not isinstance(timestamp, datetime):
            return False
        
        self.signal_buffer[bssid].append((timestamp, rssi))
        
        # Keep only recent readings
        cutoff = datetime.now() - timedelta(seconds=self.window_size * 2)
        self.signal_buffer[bssid] = [
            (ts, rssi) for ts, rssi in self.signal_buffer[bssid]
            if ts > cutoff
        ]
        return True
    
    def analyze_rssi_pattern(self, rssi_sequence):
        """
        Analyze RSSI pattern for anomalies
        
        Legitimate patterns: gradual changes, consistent behavior
        Rogue patterns: random jumps, oscillations, phase shifts
        """
        rssi_array = _valid_rssi_array(rssi_sequence)
        if len(rssi_array) < 3:
            return {
                'pattern_anomaly_score': 0,
                'reason': 'insufficient_data'
            }
        
        # 1. Variance analysis
        variance = np.var(rssi_array)
        std_dev = np.std(rssi_array)
        
        # 2. Rate of change
        deltas = np.diff(rssi_array)
        mean_delta = np.mean(np.abs(deltas))
        max_delta = np.max(np.abs(deltas))
        
        # 3. Autocorrelation (signal persistence)
        if len(rssi_array) >= 4:
            lag1_autocorr = np.corrcoef(rssi_array[:-1], rssi_array[1:])[0, 1]
        else:
            lag1_autocorr = 0
        
        # 4. Distribution analysis
        skewness = _calculate_skewness(rssi_array)
        kurtosis = _calculate_kurtosis(rssi_array)
        
        # Score components
        anomaly_score = 0
        reasons = []
        
        # High variance = unstable/moving transmitter
        if variance > 150:
            anomaly_score += 20
            reasons.append("Extremely high variance (unstable source)")
        elif variance > 80:
            anomaly_score += 10
            reasons.append("High variance (mobile or jittery)")
        
        # Large jumps = possible spoofing or sudden power changes
        if max_delta > 25:
            anomaly_score += 15
            reasons.append(f"Large signal jumps ({max_delta}dBm)")
        
        # Negative autocorrelation = random, unnatural pattern
        if lag1_autocorr < -0.3:
            anomaly_score += 15
            reasons.append("Low signal correlation (random pattern)")
        
        # Unusual distribution shape
        if abs(skewness) > 2:
            anomaly_score += 5
            reasons.append("Skewed RSSI distribution")
        
        return {
            'pattern_anomaly_score': min(100, anomaly_score),
            'variance': variance,
            'std_dev': std_dev,
            'mean_delta': mean_delta,
            'max_delta': max_delta,
            'autocorrelation': lag1_autocorr,
            'skewness': skewness,
            'reasons': reasons
        }
    
    def analyze_mobility_pattern(self, rssi_sequence):
        """
        Detect mobility patterns (stationary vs mobile)
        
        Returns indicator of whether AP is stationary or mobile.
        """
        rssi_array = _valid_rssi_array(rssi_sequence)
        if len(rssi_array) < 5:
            return {'mobility_score': 50, 'classification': 'unknown'}
        
        # Calculate metrics
        variance = np.var(rssi_array)
        std_dev = np.std(rssi_array)
        deltas = np.abs(np.diff(rssi_array))
        
        # Mobility score (0 = stationary, 100 = highly mobile)
        # Higher variance and larger deltas = more mobile
        
        mobility_score = min(100, (variance / 10) + (np.mean(deltas) * 2))
        
        if mobility_score < 15:
            classification = "stationary"
        elif mobility_score < 40:
            classification = "low_mobility"
        elif mobility_score < 70:
            classification = "moderate_mobility"
        else:
            classification = "high_mobility"
        
        return {
            'mobility_score': mobility_score,
            'classification': classification,
            'variance': variance,
            'mean_delta': np.mean(deltas)
        }
    
    def analyze_beamforming_indicators(self, signal_strengths, directions=None):
        """
        Detect beamforming or directional transmission patterns
        
        Beamforming characteristics:
        - Sharper signal peaks
        - Rapid changes in specific directions
        - Less omni-directional pattern
        """
        signals = _valid_rssi_array(signal_strengths)
        if len(signals) < 5:
            return {'beamforming_likelihood': 0, 'reason': 'insufficient_data'}
        
        # Calculate kurtosis (beamforming = higher kurtosis, sharper peaks)
        kurt = _calculate_kurtosis(signals)
        
        # Calculate skewness
        skew = _calculate_skewness(signals)
        
        # Peak sharpness
        mean_signal = np.mean(signals)
        peaks = np.sum(signals > mean_signal + np.std(signals))
        peak_ratio = peaks / len(signals)
        
        # Beamforming likelihood (0-100)
        likelihood = min(100, (kurt * 5) + (peak_ratio * 30))
        
        return {
            'beamforming_likelihood': likelihood,
            'kurtosis': kurt,
            'peak_ratio': peak_ratio,
            'interpretation': 'possible_beamforming' if likelihood > 60 else 'omni_directional'
        }
    
    def analyze_tx_power_anomalies(self, rssi_at_distance):
        """
        Analyze TX power anomalies
        
        Standard WiFi TX power: 15-20 dBm
        Unusually high TX power suggests:
        - Amplification/jamming attempt
        - Non-standard hardware
        """
        anomaly_score = 0
        reasons = []
        
        # Estimate TX power from RSSI and distance
        # TX_power = RSSI - 20*log10(distance) - Lfs
        # where Lfs is free-space path loss
        
        # If very strong signal at distance, suggests excessive TX power
        if isinstance(rssi_at_distance, dict):
            rssi = rssi_at_distance.get('rssi', -50)
            distance = rssi_at_distance.get('distance', 10)
            
            if rssi > -20:  # Extremely strong
                anomaly_score += 20
                reasons.append("Excessive TX power detected")
        
        return {
            'tx_power_anomaly_score': anomaly_score,
            'reasons': reasons
        }
    
    def analyze_temporal_coherence(self, rssi_sequence, window=5):
        """
        Analyze temporal coherence (how "smooth" RSSI changes are)
        
        Legitimate APs: smooth, gradual RSSI changes
        Rogue APs: jumpy, erratic changes
        """
        rssi_array = _valid_rssi_array(rssi_sequence)
        if len(rssi_array) < max(3, int(window)):
            return {'coherence_score': 50}
        
        # Calculate smoothness using second derivative
        first_deriv = np.diff(rssi_array)
        second_deriv = np.diff(first_deriv)
        
        # High second derivative = non-smooth (jerky)
        jerkiness = np.mean(np.abs(second_deriv))
        
        # Normalize jerkiness to 0-100 scale
        coherence_score = max(0, 100 - (jerkiness * 5))
        
        return {
            'coherence_score': coherence_score,
            'jerkiness': jerkiness,
            'smoothness_interpretation': 'smooth' if coherence_score > 70 else 'erratic'
        }
    
    def get_bssid_signal_stats(self, bssid):
        """Get aggregated signal statistics for a BSSID"""
        if bssid not in self.signal_buffer or not self.signal_buffer[bssid]:
            return None
        
        readings = [rssi for _, rssi in self.signal_buffer[bssid]]
        
        return {
            'bssid': bssid,
            'sample_count': len(readings),
            'mean_rssi': np.mean(readings),
            'std_rssi': np.std(readings),
            'min_rssi': np.min(readings),
            'max_rssi': np.max(readings),
            'range': np.max(readings) - np.min(readings),
            'pattern_analysis': self.analyze_rssi_pattern(readings),
            'mobility': self.analyze_mobility_pattern(readings),
            'temporal_coherence': self.analyze_temporal_coherence(readings)
        }


def _calculate_skewness(data):
    """Calculate Fisher-Pearson skewness"""
    if len(data) < 3:
        return 0
    
    mean = np.mean(data)
    std = np.std(data)
    
    if std == 0:
        return 0
    
    skewness = np.mean(((data - mean) / std) ** 3)
    return skewness


def _calculate_kurtosis(data):
    """Calculate excess kurtosis"""
    if len(data) < 4:
        return 0
    
    mean = np.mean(data)
    std = np.std(data)
    
    if std == 0:
        return 0
    
    kurtosis = np.mean(((data - mean) / std) ** 4) - 3
    return kurtosis


if __name__ == "__main__":
    analyzer = AdvancedSignalAnalyzer()
    
    # Test with sample data
    test_sequence = [-45, -43, -47, -46, -44, -48, -42, -45, -46]
    
    print("🔬 Signal Analysis Test:\n")
    
    result = analyzer.analyze_rssi_pattern(test_sequence)
    print(f"RSSI Pattern Analysis:\n{result}\n")
    
    mobility = analyzer.analyze_mobility_pattern(test_sequence)
    print(f"Mobility Analysis:\n{mobility}\n")
    
    coherence = analyzer.analyze_temporal_coherence(test_sequence)
    print(f"Temporal Coherence:\n{coherence}")
