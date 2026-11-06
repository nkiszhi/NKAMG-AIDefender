import sys
from pathlib import Path
import unittest

import numpy as np

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'CoDefenderC3'))
from engine.result_formatter import format_scan_result


class EngineResultContractTests(unittest.TestCase):
    def format_result(self, prediction, drift):
        return format_scan_result(
            evidence={
                'predictions': np.array([prediction]), 'scores': np.array([0.8]),
                'per_model_scores': np.array([[0.8, 0.2]]),
                'per_model_preds': np.array([[prediction, prediction]]),
                'drift_evidence': np.zeros((1, 3)), 'sample_drift_type': ['structural'],
                'anomaly_score': np.array([0.7]), 'is_drift_candidate': np.array([drift]),
            },
            identifiers={
                'MD5': 'a' * 32, 'SHA256': 'b' * 64, 'CRC32': 'deadbeef',
                'FileName': 'sample.exe', 'FileSize': 100,
            },
            pack_info={}, model_names=['ModelA', 'ModelB'],
        )

    def test_only_binary_result_labels_are_emitted(self):
        malicious = self.format_result(1, False)
        benign = self.format_result(0, False)
        self.assertEqual((malicious['StatusLabel'], benign['StatusLabel']), ('Malicious', 'Benign'))
        self.assertEqual((malicious['Status'], benign['Status']), (1, 0))
        self.assertTrue(malicious['IsMalicious'])
        self.assertFalse(benign['IsMalicious'])
        self.assertNotIn('VirusName', malicious['ScanResult'])
        self.assertNotIn('VirusName', benign['ScanResult'])

    def test_drift_metadata_does_not_create_a_third_verdict(self):
        result = self.format_result(0, True)
        self.assertEqual(result['StatusLabel'], 'Benign')
        self.assertEqual(result['Status'], 0)
        self.assertTrue(result['ScanResult']['IsDriftCandidate'])


if __name__ == '__main__':
    unittest.main()
