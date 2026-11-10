"""Candidate cache tests use synthetic IR; they do not claim BN/SMDA parity."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import gzip
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import numpy as np
from feature_extraction.ir import BasicBlock, CallSite, Function, ProgramIR, SCHEMA_VERSION, IRValidationError
from feature_extraction.features_from_ir import all_features
from feature_extraction.ir_cache import CandidateCache, FEATURE_SCHEMA, CACHE_SCHEMA, digest, enabled, identity


def sample_ir():
    block = BasicBlock(4096, 8, ("mov", "call", "ret"), (4104, 4096, 4104),
                       constant_count=2, n_outgoing=4, keywords=("mov", "call", "ret"))
    function = Function(4096, 8, (block,), (8192, 8192), callees_known=False,
                        name="sample", call_sites=(CallSite(4098, 8192, None, "func"),))
    return ProgramIR((function,), imports=("kernel32.CreateFileW",), backend="synthetic", backend_version="1",
                     arch="x86", bitness=32)


def metadata():
    return {"cache_schema": CACHE_SCHEMA, "backend": "synthetic", "backend_version": "1",
            "ir_schema": SCHEMA_VERSION, "profile": "features", "adapter_revision": "test/1",
            "analysis_config": {"depth": "basic"}}


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sample = self.root / "sample.exe"
        self.sample.write_bytes(b"synthetic-content-A")
        self.cache = CandidateCache(self.root / "cache")
        self.calls = 0
        self.meta = metadata()

    def tearDown(self):
        self.temp.cleanup()

    def builder(self, path):
        self.calls += 1
        return sample_ir()

    def features(self, **kwargs):
        return self.cache.features(self.sample, metadata=self.meta, builder=self.builder, **kwargs)

    def test_candidate_default_off(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(enabled())

    def test_cache_hit_and_cross_path_content_identity(self):
        first = self.features()
        second = self.features()
        copy = self.root / "another-path.exe"
        copy.write_bytes(self.sample.read_bytes())
        third = self.cache.features(copy, metadata=self.meta, builder=self.builder)
        self.assertEqual(self.calls, 1)
        for key in first:
            np.testing.assert_array_equal(first[key], second[key])
            np.testing.assert_array_equal(first[key], third[key])

    def test_same_path_changed_content_is_not_a_hit(self):
        self.features()
        self.sample.write_bytes(b"synthetic-content-B")
        self.features()
        self.assertEqual(self.calls, 2)

    def test_feature_schema_change_reuses_compatible_ir(self):
        first = self.features()
        second = self.features(feature_schema="new-feature-version")
        self.assertEqual(self.calls, 1)
        for key in first:
            np.testing.assert_array_equal(first[key], second[key])
        self.assertEqual(len(list((self.cache.root / "features").glob("*.npz"))), 2)

    def test_analysis_config_change_rebuilds_ir(self):
        self.features()
        self.meta = dict(self.meta, analysis_config={"depth": "different"})
        self.features()
        self.assertEqual(self.calls, 2)

    def test_backend_version_identity_mismatch_rejected(self):
        self.meta = dict(self.meta, backend_version="2")
        with self.assertRaisesRegex(ValueError, "builder backend/version mismatch"):
            self.features()
        self.assertFalse(list((self.cache.root / "ir").glob("*.gz")))

    def test_graph_profile_rejected(self):
        self.meta = dict(self.meta, profile="graph")
        with self.assertRaisesRegex(ValueError, "non-MalGraph"):
            self.features()

    def test_corrupt_npz_is_quarantined_and_rebuilt_from_ir(self):
        self.features()
        file = next((self.cache.root / "features").glob("*.npz"))
        file.write_bytes(b"half-written")
        self.features()
        self.assertEqual(self.calls, 1)
        self.assertTrue(list(file.parent.glob("*.corrupt-*")))

    def test_corrupt_ir_is_quarantined(self):
        self.features()
        ir = next((self.cache.root / "ir").glob("*.gz"))
        ir.write_bytes(b"damaged gzip")
        # Change only the feature version to force IR lookup, not a feature hit.
        self.features(feature_schema="v-next")
        self.assertEqual(self.calls, 2)
        self.assertTrue(list(ir.parent.glob("*.corrupt-*")))

    def test_payload_tamper_is_not_accepted(self):
        self.features()
        ir = next((self.cache.root / "ir").glob("*.gz"))
        data = json.loads(gzip.decompress(ir.read_bytes()))
        data["ir"]["functions"] = []
        ir.write_bytes(gzip.compress(json.dumps(data).encode()))
        self.features(feature_schema="tamper-test")
        self.assertEqual(self.calls, 2)

    def test_empty_ir_never_cached_as_success(self):
        with self.assertRaisesRegex(ValueError, "empty_de_features"):
            self.cache.features(self.sample, metadata=self.meta, builder=lambda _: ProgramIR((), backend="synthetic", backend_version="1"))
        self.assertFalse(list((self.cache.root / "features").glob("*.npz")))
        self.assertFalse(list((self.cache.root / "ir").glob("*.gz")))

    def test_concurrent_same_key_analyzes_once(self):
        def slow_builder(path):
            time.sleep(0.02)
            return self.builder(path)
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(lambda _: self.cache.features(self.sample, metadata=self.meta, builder=slow_builder), range(8)))
        self.assertEqual(self.calls, 1)
        self.assertEqual(len(results), 8)

    def test_file_changed_during_analysis_has_no_success_marker(self):
        def changing_builder(path):
            self.sample.write_bytes(b"changed underneath")
            return sample_ir()
        with self.assertRaisesRegex(ValueError, "sample changed"):
            self.cache.features(self.sample, metadata=self.meta, builder=changing_builder)
        self.assertFalse(list((self.cache.root / "ir").glob("*.gz")))

    def test_failed_write_keeps_prior_complete_version(self):
        first = self.features()
        feature_file = next((self.cache.root / "features").glob("*.npz"))
        before = feature_file.read_bytes()
        from feature_extraction.ir_cache import write_arrays
        expected = identity(self.sample, self.meta, feature_schema=FEATURE_SCHEMA)
        with patch("feature_extraction.ir_cache.os.replace", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                write_arrays(feature_file, first, expected)
        self.assertEqual(feature_file.read_bytes(), before)
        self.features()
        self.assertEqual(self.calls, 1)

    def test_roundtrip_preserves_all_semantic_fields(self):
        original = sample_ir()
        restored = ProgramIR.from_json(original.to_json())
        self.assertEqual(original, restored)
        for key, array in all_features(original).items():
            np.testing.assert_array_equal(array, all_features(restored)[key])

    def test_integer_addresses_and_tuple_storage_required(self):
        ir = sample_ir()
        with self.assertRaises(IRValidationError):
            replace(ir, functions=list(ir.functions)).validate()
        with self.assertRaises(IRValidationError):
            replace(ir, functions=(replace(ir.functions[0], start=4096.5),)).validate()

    def test_bn_not_imported_by_cache_module(self):
        import sys
        self.assertNotIn("binaryninja", sys.modules)


if __name__ == "__main__":
    unittest.main()
