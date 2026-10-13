import unittest
from pathlib import Path
from unittest.mock import patch
from app.codefender_client import parse_codefender_response, scan_file


class V8AdapterTests(unittest.TestCase):
    def test_service_verdict_and_nested_scores(self):
        result = parse_codefender_response({
            "Status": 1, "IsMalicious": True, "Score": 0.4,
            "ScanResult": {
                "VirusName": "Test.Family",
                "PerModelScores": {"MalConv": 0.5, "EmberDNN": 0.2},
                "PerModelPreds": {"MalConv": 1, "EmberDNN": 0},
                "ModelStats": {"OkModels": 2},
            },
        })
        self.assertEqual(result["MalConv"]["result"], "恶意")
        self.assertEqual(result["EmberDNN"]["result"], "安全")
        self.assertEqual(result["集成结果"]["probability"], 0.4)
        self.assertEqual(result["集成结果"]["result"], "恶意")
        self.assertEqual(result["集成结果"]["virus_name"], "Test.Family")

    def test_hash_hit_has_no_fabricated_models(self):
        result = parse_codefender_response({
            "Status": 1, "IsMalicious": True, "Score": 1,
            "ScanResult": {"VirusName": "KnownMalware", "PerModelScores": {}},
        })
        self.assertEqual(list(result), ["签名库预检", "集成结果"])

    def test_zero_successful_models_is_error(self):
        with self.assertRaises(ValueError):
            parse_codefender_response({
                "Status": 0, "Score": 0,
                "ScanResult": {"ModelStats": {"OkModels": 0}},
            })

    def test_drift_is_preserved(self):
        result = parse_codefender_response({
            "Status": 2, "IsMalicious": False, "Score": 0.2,
            "ScanResult": {"PerModelScores": {"MalConv": 0.2}},
        })
        self.assertEqual(result["集成结果"]["result"], "疑似漂移")

    @patch("app.codefender_client._scan_by_upload", return_value=None)
    @patch("app.codefender_client._scan_by_path", return_value=None)
    def test_unavailable_service_is_error(self, path_scan, upload_scan):
        with self.assertRaises(RuntimeError):
            scan_file(Path("sample.exe"))
