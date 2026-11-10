"""Development response trimming must not change inference or Web evidence."""
from copy import deepcopy
import unittest

from engine.dev.projection import project_directory, project_single
from engine.projection import project_directory as project_production_directory


def full_result():
    return {
        "MD5": "m", "SHA256": "s", "CRC32": "c", "FileName": "sample.exe",
        "FilePath": "/samples/sample.exe", "FileSize": 256, "Status": 1,
        "StatusLabel": "Malicious", "IsMalicious": True, "Score": 0.7,
        "ProcessingTime": 1.2, "TimingMethod": "shared_batch",
        "ScanResult": {
            "VirusName": "Generic.ML.Medium", "Packed": {"IsPacked": False},
            "PerModelScores": {"MalConv": 0.7}, "PerModelPreds": {"MalConv": 1},
            "PerModelDetails": [{"model": "MalConv", "status": "ok", "score": 0.7}],
            "DriftEvidence": {"surface": 0.0}, "IsDriftCandidate": False,
            "SampleDriftType": "none", "AnomalyScore": 0.0,
            "ModelStats": {
                "TotalModels": 2, "OkModels": 1, "SkippedModels": 1, "ErrorModels": 0,
                "AggregatedModels": ["MalConv"], "ExcludedModels": {"MalGraph": "include_de_false"},
                "MaliciousVotes": 1, "BenignVotes": 0, "AgreementRate": 1.0,
                "EnsembleScore": 0.7, "EnsemblePred": 1, "ScoreRange": [0.7, 0.7],
                "AggregationMethod": "equal_weight_mean", "DecisionThreshold": 0.5,
            },
        },
    }


class DevelopmentProjectionTests(unittest.TestCase):
    def test_removes_only_requested_fields_without_mutating_evidence(self):
        original = full_result()
        before = deepcopy(original)
        expected = deepcopy(original)
        expected["ScanResult"].pop("PerModelPreds")
        expected["ScanResult"].pop("PerModelDetails")
        expected["ScanResult"]["ModelStats"].pop("AggregatedModels")
        projected = project_single(original)
        self.assertEqual(projected, expected)
        self.assertEqual(original, before)
        self.assertIsNot(projected, original)
        self.assertIsNot(projected["ScanResult"], original["ScanResult"])
        self.assertIsNot(projected["ScanResult"]["ModelStats"], original["ScanResult"]["ModelStats"])
        self.assertEqual(project_single(projected), projected)

    def test_directory_keeps_counters_timing_and_errors(self):
        failure = {"FilePath": "/samples/fail.exe", "Status": -1,
                   "StatusLabel": "Timeout", "IsMalicious": False, "Error": "analysis_timeout"}
        original = {"Summary": {"TotalFiles": 2, "ScannedFiles": 1, "MaliciousCount": 1,
                                "BenignCount": 0, "ErrorCount": 0, "TimeoutCount": 1,
                                "Timing": {"TotalTime": 2.3}},
                    "Results": [full_result(), failure]}
        before = deepcopy(original)
        projected = project_directory(original)
        self.assertEqual(projected["Summary"], original["Summary"])
        self.assertEqual(projected["Results"], [project_single(original["Results"][0]), failure])
        self.assertNotIn("ScanResult", projected["Results"][1])
        self.assertEqual(original, before)
        self.assertEqual(project_production_directory(original), project_production_directory(projected))

    def test_hash_hit_does_not_gain_fake_model_statistics(self):
        hit = {"IsMalicious": True, "Score": 1.0, "Source": "sha256_db",
               "ScanResult": {"PerModelPreds": {}, "PerModelScores": {},
                              "HashMatch": {"sha256": "s"}}}
        before = deepcopy(hit)
        projected = project_single(hit)
        self.assertNotIn("PerModelPreds", projected["ScanResult"])
        self.assertNotIn("ModelStats", projected["ScanResult"])
        self.assertEqual(projected["ScanResult"]["HashMatch"], {"sha256": "s"})
        self.assertEqual(projected["Source"], "sha256_db")
        self.assertEqual(hit, before)

    def test_absent_optional_blocks_are_not_fabricated(self):
        for value in [{}, {"Error": "failure"}, {"ScanResult": None}, {"ScanResult": {}},
                      {"ScanResult": {"ModelStats": None}}]:
            self.assertEqual(project_single(value), value)
        for value in [{}, {"Summary": {}, "Results": []}]:
            self.assertEqual(project_directory(value), value)


class DiagnosticToolTests(unittest.TestCase):
    def test_real_http_verifier_uses_scores_and_counts_after_trimming(self):
        from tools.verify_smda_http import verify_development_diagnostics
        result = project_single(full_result())
        scan = result["ScanResult"]
        scan["PerModelScores"] = {"MalConv": 0.7, "MalGraph": 0.8}
        scan["ModelStats"].update(OkModels=2, SkippedModels=0, ExcludedModels={})
        self.assertEqual(verify_development_diagnostics(result, expected_models=2), 2)
        for field, value in [("OkModels", 1), ("ErrorModels", 1),
                             ("ExcludedModels", {"MalGraph": "failed"}), ("AggregatedModels", [])]:
            broken = deepcopy(result)
            broken["ScanResult"]["ModelStats"][field] = value
            with self.assertRaises(AssertionError):
                verify_development_diagnostics(broken, expected_models=2)
        for field in ["PerModelPreds", "PerModelDetails"]:
            broken = deepcopy(result)
            broken["ScanResult"][field] = []
            with self.assertRaises(AssertionError):
                verify_development_diagnostics(broken, expected_models=2)
        scan["PerModelScores"]["MalGraph"] = float("nan")
        with self.assertRaises(AssertionError):
            verify_development_diagnostics(result, expected_models=2)
        scan["PerModelScores"] = {"MalConv": 0.7, "Other": 0.8}
        with self.assertRaises(AssertionError):
            verify_development_diagnostics(result, expected_models=2)
        with self.assertRaises(AssertionError):
            verify_development_diagnostics({"ScanResult": {}}, expected_models=2)

    def test_scan_summary_keeps_partial_model_diagnostics(self):
        from tools.run_dataset_directory_scan import summarize
        result = project_single(full_result())
        manifest = {"samples": [{"label": "malicious", "scan_path": result["FilePath"],
                                 "source": "/source/sample.exe", "file_name": "sample.exe", "sha256": "s"}]}
        summary = summarize({"Results": [result]}, manifest)
        row = summary["rows"][0]
        self.assertEqual((row["ok_models"], row["total_models"]), (1, 2))
        self.assertEqual(row["non_ok_models"], [{"model": "MalGraph", "status": "excluded", "reason": "include_de_false"}])
        self.assertEqual(row["malgraph"]["status"], "excluded")
        counts = summary["counts_by_folder_label"]["malicious"]
        self.assertEqual(counts["samples_with_model_details"], 0)
        self.assertEqual(counts["samples_with_model_diagnostics"], 1)
        self.assertEqual(counts["partial_model_samples"], 1)
        result["ScanResult"]["PerModelScores"]["MalGraph"] = 0.8
        result["ScanResult"]["ModelStats"].update(OkModels=2, SkippedModels=0, ExcludedModels={})
        summary = summarize({"Results": [result]}, manifest)
        self.assertEqual(summary["rows"][0]["malgraph"]["status"], "ok")
        self.assertEqual(summary["counts_by_folder_label"]["malicious"]["partial_model_samples"], 0)
        result["ScanResult"]["ModelStats"]["OkModels"] = 1
        with self.assertRaises(AssertionError):
            summarize({"Results": [result]}, manifest)

    def test_scan_summary_treats_hidden_production_diagnostics_as_unknown(self):
        from tools.run_dataset_directory_scan import summarize
        from engine.projection import project_directory as production
        result = full_result()
        manifest = {"samples": [{"label": "malicious", "scan_path": result["FilePath"],
                                 "source": "/source/sample.exe", "file_name": "sample.exe", "sha256": "s"}]}
        response = production({"Results": [result], "Summary": {}})
        summary = summarize(response, manifest)
        self.assertNotIn("ok_models", summary["rows"][0])
        self.assertEqual(summary["counts_by_folder_label"]["malicious"]["samples_with_model_diagnostics"], 0)
        self.assertIsNone(summary["counts_by_folder_label"]["malicious"]["partial_model_samples"])


if __name__ == "__main__":
    unittest.main()
