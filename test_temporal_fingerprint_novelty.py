import tempfile
import unittest
from pathlib import Path

from temporal_analyzer import TemporalAnalyzer
from wifi_fingerprint import WiFiFingerprintStore
from novelty_alert_engine import evaluate_novelty
from runtime_config import load_runtime_config


class TemporalFingerprintNoveltyTests(unittest.TestCase):
    def test_rssi_history_calculates_variance_and_delta(self):
        cfg = load_runtime_config()
        cfg['temporal_analysis']['minimum_samples'] = 3
        analyzer = TemporalAnalyzer(config=cfg)
        values = [-50, -51, -80]
        result = None
        for i, rssi in enumerate(values):
            result = analyzer.observe({'bssid': 'AA:BB:CC:DD:EE:01', 'rssi_dbm': rssi,
                                       'timestamp': f'2026-01-01T00:00:0{i}+00:00'})
        self.assertEqual(result['sample_count'], 3)
        self.assertGreater(result['rssi_variance'], 0)
        self.assertEqual(result['rssi_delta'], 29)
        self.assertGreater(result['temporal_score'], 0)

    def test_preview_does_not_mutate_history(self):
        analyzer = TemporalAnalyzer()
        obs = {'bssid': 'AA:BB:CC:DD:EE:02', 'rssi_dbm': -55, 'timestamp': '2026-01-01T00:00:00+00:00'}
        analyzer.preview(obs)
        self.assertEqual(analyzer.observe(obs)['sample_count'], 1)

    def test_fingerprint_baseline_is_not_trusted_automatically(self):
        with tempfile.TemporaryDirectory() as temp:
            store = WiFiFingerprintStore(path=Path(temp) / 'baseline.json')
            record = store.observe({'bssid': 'AA:BB:CC:DD:EE:03', 'ssid': 'CampusWiFi', 'rssi_dbm': -60, 'channel': 6, 'security': 'WPA2'})
            self.assertFalse(record['trusted'])
            self.assertEqual(record['observation_count'], 1)
            self.assertEqual(len(record['rssi_history']), 1)

    def test_percent_fingerprint_mismatch_is_recognized_but_not_alone_alerted(self):
        result = evaluate_novelty({'Fingerprint_Similarity': 40, 'Fingerprint_Baseline_Exists': True, 'Combined_Risk': 20})
        self.assertIn('fingerprint differs from baseline', ' '.join(result.evidence).lower())
        self.assertFalse(result.should_alert)

    def test_new_ap_alone_is_not_malicious_alert(self):
        result = evaluate_novelty({'Combined_Risk': 10, 'Fingerprint_Baseline_Exists': False, 'AP_Count': 1})
        self.assertFalse(result.should_alert)
        self.assertEqual(result.level, 'SAFE')

    def test_fingerprint_change_needs_corroboration(self):
        weak = evaluate_novelty({'Fingerprint_Changed': True, 'Combined_Risk': 15})
        self.assertFalse(weak.should_alert)
        corroborated = evaluate_novelty({'Fingerprint_Changed': True, 'Observation_Count': 5,
                                         'Signal_Fluctuation': 25, 'Combined_Risk': 55})
        self.assertTrue(corroborated.should_alert)


if __name__ == '__main__':
    unittest.main()
