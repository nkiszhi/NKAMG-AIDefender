"""HTTP/policy/shape regressions with explicit synthetic models, not real weights."""
import asyncio
from collections import OrderedDict
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

os.environ.update(CODEFENDER_HASH_DB_ENABLED="0", CODEFENDER_FUZZY_DB_ENABLED="0",
                  CODEFENDER_REQUIRE_HASH_DB="0", CODEFENDER_DISASM_BACKEND="smda",
                  CODEFENDER_RUNTIME_CFG_DISABLE="1", CODEFENDER_MODEL_DEVICE="cpu",
                  CODEFENDER_NON_MALGRAPH_IR="0", PYTHONDONTWRITEBYTECODE="1")
import numpy as np
import torch
import httpx
from starlette.datastructures import UploadFile
import engine.app as core
import engine.dev.app as development
from engine import contract_pipeline as pipeline, prediction_policy as policy
from engine.naming import name_for_hash_hit, name_for_ml
from engine.scan_runtime import ScanRuntime, ScanBusy, ScanTimeout
from engine.serve import listeners


def pe_bytes():
    data = bytearray(256)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    return bytes(data)


class ShapeModel(torch.nn.Module):
    def __init__(self, internal_dim, expected, score):
        super().__init__()
        self.hidden = torch.nn.Linear(internal_dim, 1)
        self.expected, self.score, self.seen = expected, score, []

    def forward(self, rows):
        self.seen.append(tuple(rows.shape))
        if rows.shape[1] != self.expected:
            raise ValueError("wrong raw input dimension")
        return torch.full((len(rows), 1), self.score, device=rows.device)


def ensemble(score=0.7):
    return SimpleNamespace(
        view_groups=OrderedDict([("V1_byte", ["MalConv"]), ("V8_color", ["IMCFN"])]),
        _model_names=["MalConv", "IMCFN"],
        _models={"MalConv": ShapeModel(128, 32768, score), "IMCFN": ShapeModel(25088, 196608, score)},
        _model_types={"MalConv": "pytorch", "IMCFN": "pytorch"}, _actual_kwargs={},
    )


class Extractor:
    def extract_fast(self, path):
        values = {"B01": np.zeros(32768, dtype=np.int32)}
        for fid in core.config.VIEW_GROUPS["V8_color"]["binja_features"]:
            values[fid] = np.zeros(core.FEATURE_DIMS[fid], dtype=np.float32)
        return values


HASH_NAME_CASES = (
    ("sha256_db", {"sha256": "s"}, "Malicious"),
    ("md5_db", {"md5": "m"}, "Malicious"),
    ("fuzzy_db", {"fuzzy_type": "ssdeep", "sha256": "associated-sha256"}, "Suspicious"),
    ("fuzzy_db", {"fuzzy_type": "tlsh", "sha256": "associated-sha256"}, "Suspicious"),
    ("fuzzy_db", {"fuzzy_type": "imphash", "sha256": "associated-sha256"}, "Malicious"),
    ("fuzzy_db", {"fuzzy_type": "authentihash", "sha256": "associated-sha256"}, "Malicious"),
)


class Contracts(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "sample.no-extension"
        self.path.write_bytes(pe_bytes())
        self.ens = ensemble()
        self.patches = [patch.object(core, "_load_ensemble", return_value=self.ens),
                        patch.object(core, "_get_extractor", return_value=Extractor()),
                        patch.object(core, "_get_sdd_engine", side_effect=RuntimeError("no synthetic baseline")),
                        patch.object(core, "_hash_precheck", return_value=None),
                        patch.object(core, "_hash_precheck_file", return_value=None),
                        patch.object(core, "_SCAN_RUNTIME", ScanRuntime(timeout=5, hard_timeout=6, hard_exit=lambda: None))]
        for item in self.patches:
            item.start()

    async def asyncTearDown(self):
        for item in reversed(self.patches):
            item.stop()
        self.temp.cleanup()

    async def request(self, app, route, **kwargs):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test") as client:
            return await client.post(route, **kwargs)

    async def single(self, app):
        return await self.request(app, "/predict-single", params={"include_de": "false"}, files={"file": ("input.exe", pe_bytes())})

    async def directory(self, app, **params):
        return await self.request(app, "/predict-directory", params={"directory": str(self.path.parent), **params})

    async def test_four_interfaces_and_raw_dimensions(self):
        for app, full in [(core.app, False), (development.app, True)]:
            single = await self.single(app)
            directory = await self.directory(app)
            self.assertEqual(single.status_code, 200, single.text)
            self.assertEqual(directory.status_code, 200, directory.text)
            a, b = single.json(), directory.json()["Results"][0]
            self.assertEqual(a["MD5"], b["MD5"])
            self.assertEqual(a["IsMalicious"], b["IsMalicious"])
            self.assertEqual(a["ScanResult"]["VirusName"], b["ScanResult"]["VirusName"])
            self.assertEqual("Score" in a, full)
            self.assertEqual("Timing" in directory.json()["Summary"], full)
            if full:
                self.assertEqual(a["Score"], b["Score"])
                self.assertEqual(a["ScanResult"]["ModelStats"]["AggregationMethod"], "equal_weight_mean")
                for result in [a, b]:
                    self.assertNotIn("PerModelPreds", result["ScanResult"])
                    self.assertNotIn("PerModelDetails", result["ScanResult"])
                    self.assertNotIn("AggregatedModels", result["ScanResult"]["ModelStats"])
                    self.assertEqual(set(result["ScanResult"]["PerModelScores"]), set(self.ens._model_names))
                    self.assertEqual(result["ScanResult"]["ModelStats"]["OkModels"], 2)
            else:
                self.assertEqual(set(a), {"MD5", "SHA256", "IsMalicious", "ScanResult"})
                self.assertEqual(set(directory.json()["Summary"]), {"TotalFiles", "ScannedFiles", "MaliciousCount", "BenignCount", "ErrorCount"})
                self.assertEqual(set(a["ScanResult"]), {"VirusName", "Packed"})
        for model in self.ens._models.values():
            self.assertEqual(len(model.seen), 4)
            self.assertTrue(all(shape[1] == model.expected for shape in model.seen))

    async def test_web_full_single_directory_and_stream(self):
        for response in [await self.single(core.web_app), await self.directory(core.web_app)]:
            self.assertEqual(response.status_code, 200, response.text)
            result = response.json()
            result = result.get("Results", [result])[0]
            self.assertIn("Score", result)
            self.assertIn("PerModelScores", result["ScanResult"])
            self.assertNotIn("VirusName", result["ScanResult"])
            self.assertIn(result["Status"], [0, 1])
        response = await self.request(core.web_app, "/predict-stream", params={"include_de": "false"}, files={"file": ("input.exe", pe_bytes())})
        self.assertEqual(response.status_code, 200, response.text)
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[-1]["event"], "result")
        self.assertIn("Score", events[-1]["data"])
        self.assertIn("progress", [event["event"] for event in events])
        for model in self.ens._models.values():
            self.assertTrue(all(shape[1] == model.expected for shape in model.seen))

    async def test_hash_short_circuit_and_names(self):
        hit = {"MD5": "m", "SHA256": "s", "IsMalicious": True, "Status": 1,
               "Score": 1.0, "Source": "sha256", "ScanResult": {"VirusName": "old-family"}}
        with patch.object(core, "_hash_precheck", return_value=hit), patch.object(core, "_hash_precheck_file", return_value=hit), patch.object(core, "_load_ensemble", side_effect=AssertionError("must not load")):
            for app in [core.app, development.app]:
                self.assertEqual((await self.single(app)).json()["ScanResult"]["VirusName"], "Malicious")
                self.assertEqual((await self.directory(app)).json()["Results"][0]["ScanResult"]["VirusName"], "Malicious")
        self.assertEqual(hit["ScanResult"]["VirusName"], "old-family")

    async def test_hash_names_across_production_development_web_and_stream(self):
        for source, match, expected in HASH_NAME_CASES:
            with self.subTest(source=source, fuzzy_type=match.get("fuzzy_type")):
                hit = core._build_hash_hit_result("m", "s", "c", "input.exe", 256, match, source)
                original = json.loads(json.dumps(hit))
                with patch.object(core, "_hash_precheck", return_value=hit), \
                     patch.object(core, "_hash_precheck_file", return_value=hit), \
                     patch.object(core, "_load_ensemble", side_effect=AssertionError("hash hit must not load models")):
                    for app in (core.app, development.app, core.web_app):
                        single = await self.single(app)
                        directory = await self.directory(app)
                        self.assertEqual(single.status_code, 200, single.text)
                        self.assertEqual(directory.status_code, 200, directory.text)
                        body = directory.json()
                        self.assertEqual(body["Summary"]["MaliciousCount"], 1)
                        self.assertEqual(body["Summary"]["BenignCount"], 0)
                        self.assertEqual(body["Summary"]["ScannedFiles"], 1)
                        for result in (single.json(), body["Results"][0]):
                            self.assertTrue(result["IsMalicious"])
                            if app is core.web_app:
                                self.assertNotIn("VirusName", result["ScanResult"])
                            else:
                                self.assertEqual(result["ScanResult"]["VirusName"], expected)
                            if app is core.app:
                                self.assertNotIn("StatusLabel", result)
                                self.assertNotIn("HashMatch", result["ScanResult"])
                            else:
                                self.assertEqual(result["StatusLabel"], expected)
                                self.assertEqual(result["Status"], 1)
                                self.assertEqual(result["Score"], 1.0)
                                self.assertEqual(result["Source"], source)
                                self.assertEqual(result["ScanResult"]["HashMatch"], match)
                    stream = await self.request(core.web_app, "/predict-stream",
                                                params={"include_de": "false"},
                                                files={"file": ("input.exe", pe_bytes())})
                    self.assertEqual(stream.status_code, 200, stream.text)
                    final = [json.loads(line) for line in stream.text.splitlines()][-1]
                    self.assertEqual(final["event"], "result")
                    self.assertEqual(final["data"]["StatusLabel"], expected)
                    self.assertTrue(final["data"]["IsMalicious"])
                    self.assertNotIn("VirusName", final["data"]["ScanResult"])
                self.assertEqual(hit, original)

    async def test_development_partial_models_keep_counts_and_exclusion_reasons(self):
        self.ens._model_types["IMCFN"] = "skip"
        for response in [await self.single(development.app), await self.directory(development.app)]:
            self.assertEqual(response.status_code, 200, response.text)
            body = response.json()
            result = body["Results"][0] if "Results" in body else body
            scan = result["ScanResult"]
            self.assertNotIn("PerModelPreds", scan)
            self.assertNotIn("PerModelDetails", scan)
            self.assertEqual(set(scan["PerModelScores"]), {"MalConv"})
            self.assertEqual(scan["ModelStats"]["OkModels"], 1)
            self.assertEqual(scan["ModelStats"]["SkippedModels"], 1)
            self.assertEqual(scan["ModelStats"]["ExcludedModels"], {"IMCFN": "model_pipeline_skipped"})
            self.assertNotIn("AggregatedModels", scan["ModelStats"])

    async def test_development_hash_short_circuit_hides_model_fields(self):
        hit = core._build_hash_hit_result("m", "s", "c", "input.exe", 256, {"sha256": "s"}, "sha256_db")
        with patch.object(core, "_hash_precheck", return_value=hit), patch.object(core, "_hash_precheck_file", return_value=hit):
            for response in [await self.single(development.app), await self.directory(development.app)]:
                self.assertEqual(response.status_code, 200, response.text)
                body = response.json()
                result = body["Results"][0] if "Results" in body else body
                self.assertNotIn("PerModelPreds", result["ScanResult"])
                self.assertNotIn("PerModelDetails", result["ScanResult"])
                self.assertNotIn("ModelStats", result["ScanResult"])
                self.assertEqual(result["Source"], "sha256_db")
                self.assertEqual(result["ScanResult"]["HashMatch"], {"sha256": "s"})
        self.assertIn("PerModelPreds", hit["ScanResult"])

    async def test_exact_half_is_benign_everywhere(self):
        for model in self.ens._models.values():
            model.score = 0.5
        for app in [core.app, development.app]:
            for result in [(await self.single(app)).json(), (await self.directory(app)).json()["Results"][0]]:
                self.assertFalse(result["IsMalicious"])
                self.assertEqual(result["ScanResult"]["VirusName"], "Benign")

    async def test_empty_ensemble_never_successful_benign(self):
        for name in self.ens._model_types:
            self.ens._model_types[name] = "skip"
        for app in [core.app, development.app, core.web_app]:
            response = await self.single(app)
            self.assertEqual(response.status_code, 500, response.text)
            response = await self.directory(app)
            self.assertEqual(response.status_code, 200)
            summary = response.json()["Summary"]
            self.assertEqual(summary["ScannedFiles"], 0)
            self.assertEqual(summary["BenignCount"], 0)
            self.assertEqual(summary["ErrorCount"], 1)
            self.assertIn("Error", response.json()["Results"][0])

    async def test_nonfinite_predictions_are_failures(self):
        for model in self.ens._models.values():
            model.score = float("nan")
        self.assertEqual((await self.single(core.app)).status_code, 500)
        self.assertEqual((await self.directory(core.app)).json()["Summary"]["ErrorCount"], 1)

    async def test_directory_filter_recursion_and_limit(self):
        (self.path.parent / "not-pe.exe").write_text("not PE")
        nested = self.path.parent / "nested"
        nested.mkdir()
        (nested / "another").write_bytes(pe_bytes())
        self.assertEqual((await self.directory(core.app, recursive="false")).json()["Summary"]["TotalFiles"], 1)
        self.assertEqual((await self.directory(core.app, recursive="true")).json()["Summary"]["TotalFiles"], 2)
        with patch.object(core, "MAX_BATCH_FILES", 1):
            self.assertEqual((await self.directory(core.app)).status_code, 400)

    async def test_invalid_missing_empty_upload_and_size(self):
        response = await self.request(core.app, "/predict-single", files={"file": ("bad.exe", b"bad")})
        self.assertEqual(response.status_code, 400)
        response = await self.request(core.app, "/predict-single", files={"file": ("empty.exe", b"")})
        self.assertEqual(response.status_code, 400)
        response = await self.request(core.app, "/predict-directory", params={"directory": str(self.path.parent / "missing")})
        self.assertEqual(response.status_code, 400)
        with patch.object(core, "MAX_UPLOAD_BYTES", 8):
            self.assertEqual((await self.single(core.app)).status_code, 413)

    async def test_upload_read_is_bounded_and_always_closed(self):
        class TrackedUpload(UploadFile):
            async def read(self, size=-1):
                self.requested_size = size
                return await super().read(size)
        handler = next(route.endpoint for route in core.app.routes if route.path == "/predict-single")
        upload = TrackedUpload(io.BytesIO(pe_bytes()), filename="input.exe")
        await handler(upload, False)
        self.assertEqual(upload.requested_size, core.MAX_UPLOAD_BYTES + 1)
        self.assertTrue(upload.file.closed)
        core._SCAN_RUNTIME.active = core._SCAN_RUNTIME.concurrency
        upload = TrackedUpload(io.BytesIO(b"x"), filename="input.exe")
        with self.assertRaises(core.HTTPException) as error:
            await handler(upload, False)
        self.assertEqual(error.exception.status_code, 429)
        self.assertTrue(upload.file.closed)
        core._SCAN_RUNTIME.active = 0

    async def test_same_runtime_busy_across_contracts(self):
        core._SCAN_RUNTIME.active = core._SCAN_RUNTIME.concurrency
        for app in [core.app, development.app, core.web_app]:
            self.assertEqual((await self.single(app)).status_code, 429)
        core._SCAN_RUNTIME.active = 0
        self.assertIs(core.app.state.inference_core, development.app.state.inference_core)
        self.assertIs(core.app.state.inference_core, core.web_app.state.inference_core)

    async def test_warmup_once(self):
        with patch.object(core, "_WARMUP_TASK", None), patch.object(core, "_load_ensemble", return_value=self.ens) as load:
            await asyncio.gather(*(core._warm_runtime_models() for _ in range(3)))
            self.assertEqual(load.call_count, 1)

    async def stream_request(self, **kwargs):
        return await self.request(development.app, "/predict-stream",
                                  params={"include_de": "false"},
                                  files={"file": ("input.exe", pe_bytes())}, **kwargs)

    async def test_development_stream_final_equals_single_and_runs_models_once(self):
        expected = (await self.single(development.app)).json()
        response = await self.stream_request()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["x-accel-buffering"], "no")
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[-1], {"event": "result", "data": expected})
        self.assertEqual(sum(event["event"] == "result" for event in events), 1)
        completed = [event["data"]["models"] for event in events
                     if event["event"] == "progress" and event["data"]["stage"] == "models"]
        self.assertEqual([sum(item["status"] == "ok" for item in rows) for rows in completed], [1, 2])
        for model in self.ens._models.values():
            self.assertEqual(len(model.seen), 2)  # one single request + one stream
        self.assertNotIn("/predict-stream", [route.path for route in core.app.routes])

    async def test_stream_delivers_first_model_before_second_and_keeps_slot_on_disconnect(self):
        handler = next(route.endpoint for route in development.app.routes if route.path == "/predict-stream")
        gate = threading.Event()
        forward = self.ens._models["IMCFN"].forward
        paths = []
        prepare = pipeline._prepare_sample

        def tracked_prepare(*args):
            paths.append(args[1])
            return prepare(*args)

        def blocked(rows):
            if not gate.wait(4):
                raise RuntimeError("test gate timed out")
            return forward(rows)

        with patch.object(self.ens._models["IMCFN"], "forward", side_effect=blocked), \
             patch.object(pipeline, "_prepare_sample", side_effect=tracked_prepare):
            upload = UploadFile(io.BytesIO(pe_bytes()), filename="input.exe")
            response = await handler(upload, False)
            self.assertTrue(upload.file.closed)
            iterator = response.body_iterator
            try:
                first = json.loads(await asyncio.wait_for(iterator.__anext__(), 3))
                self.assertEqual(first["data"]["stage"], "features")
                event = json.loads(await asyncio.wait_for(iterator.__anext__(), 3))
                rows = {item["model"]: item for item in event["data"]["models"]}
                self.assertEqual(rows["MalConv"]["status"], "ok")
                self.assertEqual(rows["IMCFN"]["status"], "waiting")
                self.assertEqual(core._SCAN_RUNTIME.active, 1)
                await iterator.aclose()
                self.assertEqual(core._SCAN_RUNTIME.active, 1)
                self.assertTrue(Path(paths[0]).exists())
                # Disconnect must not admit another request or kill the worker.
                self.assertEqual((await self.single(development.app)).status_code, 429)
            finally:
                gate.set()
                await asyncio.gather(*list(development.app.state.development_stream_producers))
            self.assertEqual(core._SCAN_RUNTIME.active, 0)
            self.assertFalse(Path(paths[0]).exists())

    async def test_development_stream_failures_never_emit_benign_result(self):
        for model in self.ens._models.values():
            model.score = float("nan")
        response = await self.stream_request()
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[-1]["event"], "error")
        self.assertNotIn("result", [event["event"] for event in events])
        self.assertTrue(all(item["status"] == "error" for item in events[-2]["data"]["models"]))

    async def test_development_stream_upload_limits_and_busy(self):
        core._SCAN_RUNTIME.active = 1
        self.assertEqual((await self.stream_request()).status_code, 429)
        core._SCAN_RUNTIME.active = 0
        with patch.object(core, "MAX_UPLOAD_BYTES", 8):
            self.assertEqual((await self.stream_request()).status_code, 413)
        response = await self.request(development.app, "/predict-stream", files={"file": ("empty.exe", b"")})
        self.assertEqual(response.status_code, 400)

    async def test_development_stream_analysis_failure_is_excluded_before_publishing(self):
        prepare = pipeline._prepare_sample
        def failed(*args):
            views, meta, mg, _, _, seconds = prepare(*args)
            return views, meta, mg, ("error", "analysis failed"), {"V8_color"}, seconds
        with patch.object(pipeline, "_prepare_sample", side_effect=failed):
            expected = (await self.single(development.app)).json()
            response = await self.stream_request()
        events = [json.loads(line) for line in response.text.splitlines()]
        self.assertEqual(events[-1]["data"], expected)
        self.assertEqual(expected["ScanResult"]["ModelStats"]["OkModels"], 1)
        self.assertEqual(expected["ScanResult"]["ModelStats"]["ExcludedModels"], {"IMCFN": "analysis failed"})
        for event in events:
            if event["event"] == "progress":
                row = next(item for item in event["data"]["models"] if item["model"] == "IMCFN")
                self.assertNotEqual(row["status"], "ok")
                self.assertNotIn("score", row)

    async def test_four_interfaces_malgraph_calls_main_not_ir_graph(self):
        self.ens.view_groups["V7_graph"] = ["MalGraph"]
        self.ens._model_names.append("MalGraph")
        self.ens._model_types["MalGraph"] = "special"
        sample = {"main_cfg_fcg": True}
        with patch.object(pipeline, "isolated_analysis", return_value={"features": {}, "malgraph": sample}), patch.object(core, "_predict_malgraph_single", return_value=(1, 0.9, {})) as mg:
            for app in [core.app, development.app]:
                single = await self.request(app, "/predict-single", params={"include_de": "true"}, files={"file": ("input.exe", pe_bytes())})
                directory = await self.directory(app, include_de="true")
                self.assertEqual(single.status_code, 200, single.text)
                self.assertEqual(directory.status_code, 200, directory.text)
            self.assertEqual(mg.call_count, 4)
            self.assertTrue(all(call.kwargs["sample"] is sample for call in mg.call_args_list))

    async def test_directory_timeout_count_is_not_successful_benign(self):
        import subprocess
        self.ens.view_groups = {"V7_graph": ["MalGraph"]}
        self.ens._model_names = ["MalGraph"]
        self.ens._model_types = {"MalGraph": "special"}
        with patch.object(pipeline, "isolated_analysis", side_effect=subprocess.TimeoutExpired("analysis", 1)), patch.object(core, "_predict_malgraph_single", side_effect=ValueError("missing main graph")):
            for app in [core.app, development.app]:
                response = await self.directory(app, include_de="true")
                summary = response.json()["Summary"]
                self.assertEqual(summary["ErrorCount"], 1 if app is core.app else 0)
                self.assertEqual(summary["ScannedFiles"], 0)
                self.assertEqual(summary["BenignCount"], 0)
            self.assertEqual(response.json()["Summary"]["TimeoutCount"], 1)


class HashNamingTests(unittest.TestCase):
    def test_names_follow_actual_matching_algorithm(self):
        for source, match, expected in HASH_NAME_CASES:
            with self.subTest(source=source, match=match):
                self.assertEqual(name_for_hash_hit(source, match.get("fuzzy_type")), expected)
        self.assertEqual(name_for_hash_hit(" FUZZY_DB ", " SSDeep "), "Suspicious")
        self.assertEqual(name_for_hash_hit("fuzzy", "TLSH"), "Suspicious")

    def test_other_sources_and_legacy_calls_keep_malicious(self):
        self.assertEqual(name_for_hash_hit(), "Malicious")
        for source, fuzzy_type in ((None, None), ("sha256_db", "tlsh"),
                                   ("md5_db", "ssdeep"), ("unknown", "tlsh"),
                                   ("fuzzy_db", None), ("fuzzy_db", "vhash")):
            with self.subTest(source=source, fuzzy_type=fuzzy_type):
                self.assertEqual(name_for_hash_hit(source, fuzzy_type), "Malicious")

    def test_hash_result_changes_only_display_name(self):
        for source, match, expected in HASH_NAME_CASES:
            with self.subTest(source=source, match=match):
                stored_match = dict(match, name="private-family", size=256)
                hit = core._build_hash_hit_result("m", "s", "c", "input.exe", 256,
                                                 stored_match, source)
                self.assertEqual((hit["Status"], hit["IsMalicious"], hit["Score"]), (1, True, 1.0))
                self.assertEqual(hit["StatusLabel"], expected)
                self.assertEqual(hit["ScanResult"]["HashMatch"], match)
                self.assertNotIn("VirusName", hit["ScanResult"])
                named = pipeline._hash_result(hit, names=True)
                self.assertEqual(named["ScanResult"].pop("VirusName"), expected)
                self.assertEqual(named, hit)
                self.assertEqual(pipeline._hash_result(hit, names=False), hit)

    def test_memory_and_file_prechecks_keep_exact_hash_precedence(self):
        with tempfile.TemporaryDirectory(prefix="hash-naming-fixture-") as directory:
            path = Path(directory) / "input.exe"
            path.write_bytes(pe_bytes())
            for source, match, expected in HASH_NAME_CASES:
                with self.subTest(source=source, match=match):
                    exact = source in ("sha256_db", "md5_db")
                    with patch.object(core, "_sha256_db", object()), \
                         patch.object(core, "_md5_db", object()), \
                         patch.object(core, "_fuzzy_db", object()), \
                         patch.object(core, "_lookup_hashes", return_value=(match, source) if exact else (None, None)), \
                         patch.object(core, "_lookup_fuzzy", return_value=(match, source)) as fuzzy:
                        memory = core._hash_precheck(pe_bytes(), path.name, 256)
                        streamed = core._hash_precheck_file(str(path))
                        self.assertEqual(memory, streamed)
                        self.assertEqual(memory["StatusLabel"], expected)
                        if exact:
                            fuzzy.assert_not_called()
                        else:
                            self.assertEqual(fuzzy.call_count, 2)


class PolicyTests(unittest.TestCase):
    def test_tier_boundaries(self):
        for score, name in [(0.0, "Benign"), (0.5, "Benign"), (0.500001, "Generic.ML.Low"),
                            (0.62, "Generic.ML.Medium"), (0.78, "Generic.ML.High"), (1.0, "Generic.ML.High")]:
            self.assertEqual(name_for_ml(score), name)
        with self.assertRaises(ValueError):
            name_for_ml(float("nan"))

    def test_main_dimensions_override_internal_linear(self):
        ens = ensemble()
        self.assertEqual(core._expected_dim_for_model(ens, "MalConv"), 128)
        self.assertEqual(core._expected_dim_for_model(ens, "IMCFN"), 25088)
        self.assertEqual(core._infer_expected_view_dims(ens), {"V1_byte": 32768, "V8_color": 196608})

    def test_partial_views_no_zero_fill_and_batch_retry(self):
        class Model:
            def predict_proba(self, rows):
                if len(rows) > 1:
                    raise ValueError("batch rejected")
                if rows[0, 0] < 0:
                    raise ValueError("invalid row")
                return np.array([[0.2, 0.8]])
        ens = SimpleNamespace(view_groups={"Vx": ["M"]}, _model_names=["M"],
                              _models={"M": Model()}, _model_types={"M": "numpy"}, _actual_kwargs={})
        views = {0: ({"Vx": np.ones(3)}, {}), 1: ({"Vx": -np.ones(3)}, {}), 2: ({}, {})}
        results = policy._predict_per_model_batch(core, ens, views, [None] * 3, False)
        self.assertEqual([results[i][0]["status"] for i in range(3)], ["ok", "error", "skipped"])
        self.assertNotIn("score", results[1][0])
        self.assertNotIn("score", results[2][0])

    def test_malgraph_uses_main_sample_and_failure_sentinel(self):
        ens = SimpleNamespace(view_groups={"V7_graph": ["MalGraph"]}, _model_names=["MalGraph"],
                              _models={}, _model_types={"MalGraph": "special"})
        sample = {"main_graph": True}
        with patch.object(core, "_predict_malgraph_single", return_value=(1, 0.75, {})) as mg:
            for value in [sample, {}]:
                results = policy._predict_per_model_batch(core, ens, {0: ({}, {})}, ["sample.exe"], True, {0: value})
                self.assertEqual(results[0][0]["status"], "ok")
                self.assertIs(mg.call_args.kwargs["sample"], value)
            mg.reset_mock()
            results = policy._predict_per_model_batch(core, ens, {0: ({}, {})}, ["sample.exe"], False)
            self.assertEqual(results[0][0]["status"], "skipped")
            mg.assert_not_called()

    def test_default_listeners_preserve_web_and_isolate_dev(self):
        self.assertEqual(listeners({})[0], ("engine.web_compat:app", "0.0.0.0", 8000))
        self.assertEqual(listeners({})[1], ("engine.app:app", "127.0.0.1", 18001))
        self.assertEqual(len(listeners({})), 2)
        self.assertEqual(listeners({"CODEFENDER_ENABLE_DEV_API": "1"})[2][1], "127.0.0.1")
        with self.assertRaises(ValueError):
            listeners({"CODEFENDER_PRODUCTION_PORT": "8000"})

    def test_legacy_overlay_default_analysis_needs_no_ir_modules(self):
        import builtins
        import pickle
        import sys
        from engine.analysis_worker import _run_smda
        from unittest.mock import MagicMock
        main_de = {"D01": np.ones(2)}
        main_graph = {"from_main": True}
        extractor = MagicMock()
        extractor.return_value.extract_de.return_value = main_de
        graph = MagicMock(return_value=main_graph)
        original_import = builtins.__import__
        def reject_ir(name, *args, **kwargs):
            if name == "feature_extraction.ir_cache":
                raise ImportError("candidate IR absent in legacy runtime image")
            return original_import(name, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"CODEFENDER_NON_MALGRAPH_IR": "0"}), patch.dict(sys.modules, {
            "feature_extraction.smda_extract": SimpleNamespace(SmdaExtractor=extractor),
            "models.MalGraph_2022.utils": SimpleNamespace(extract_cfg_and_fcg=graph),
        }), patch("builtins.__import__", side_effect=reject_ir):
            output = Path(directory) / "analysis.pkl"
            _run_smda("sample.exe", str(output), 30)
            result = pickle.loads(output.read_bytes())
            self.assertEqual(result["errors"], {})
            np.testing.assert_array_equal(result["features"]["D01"], main_de["D01"])
            self.assertEqual(result["malgraph"], main_graph)
            graph.assert_called_once_with("sample.exe", {})

    def test_native_web_address_can_stay_unchanged(self):
        import configparser
        parser = configparser.ConfigParser()
        parser.read(Path(__file__).resolve().parents[2] / "web" / "config.example.ini")
        from urllib.parse import urlsplit
        web_port = urlsplit(parser["codefender"]["api_base"]).port
        entries = listeners({"CODEFENDER_WEB_COMPAT_PORT": str(web_port),
                             "CODEFENDER_ENABLE_DEV_API": "1"})
        self.assertEqual(entries[0][2], web_port)
        self.assertEqual(entries[1][2], 18001)
        self.assertEqual(entries[2][2], 18002)
        self.assertEqual(len({entry[2] for entry in entries}), 3)

    def test_device_selection_cpu_cuda_and_fallback(self):
        for want, available, expected in [("auto", False, "cpu"), ("auto", True, "cuda"), ("cuda:0", False, "cpu"), ("cuda:0", True, "cuda:0"), ("cpu", True, "cpu")]:
            with patch.object(core, "MODEL_DEVICE", want), patch.object(core.torch.cuda, "is_available", return_value=available):
                self.assertEqual(core._resolve_model_device(), expected)

    def test_view_mask_preserves_shape_and_disabled_values(self):
        from engine.view_masking import apply_view_mask
        parts = [np.ones(256), np.full(12, 2.0)]
        with patch.dict(os.environ, {"CODEFENDER_MASK_VIEWS": ""}):
            actual, masked = apply_view_mask("V6_opcode_stat", ["D02", "D05"], parts)
            np.testing.assert_array_equal(np.concatenate(actual), np.concatenate(parts))
            self.assertFalse(masked)
        with patch.dict(os.environ, {"CODEFENDER_MASK_VIEWS": "V6_opcode_stat"}):
            actual, masked = apply_view_mask("V6_opcode_stat", ["D02", "D05"], parts)
            self.assertEqual(np.concatenate(actual).shape, (268,))
            self.assertEqual(masked, ["D02"])
            self.assertEqual(actual[0].sum(), 0)
            np.testing.assert_array_equal(actual[1], parts[1])

    def test_registered_order_and_partial_sdd_guard(self):
        ens = ensemble()
        per_model = [{"model": "IMCFN", "status": "skipped", "reason": "missing"},
                     {"model": "MalConv", "status": "ok", "score": 0.6}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x"
            path.write_bytes(pe_bytes())
            with patch.object(core, "_get_sdd_engine") as sdd:
                result = policy._format_model_result(core, str(path), "x", 256, ens, per_model, lambda evidence, *_: {"ScanResult": {}, "evidence": evidence})
                sdd.assert_not_called()
            self.assertEqual(result["evidence"]["model_stats"]["AggregatedModels"], ["MalConv"])
            self.assertEqual(result["evidence"]["scores"].shape, (1,))
            per_model.insert(0, {"model": "IMCFN", "status": "ok", "score": 0.8})
            per_model.pop(1)
            with patch.object(core, "_get_sdd_engine") as sdd:
                sdd.return_value.score_samples.return_value = {}
                policy._format_model_result(core, str(path), "x", 256, ens, per_model, lambda *_: {"ScanResult": {}})
                np.testing.assert_allclose(sdd.return_value.score_samples.call_args.args[0], [[0.6, 0.8]])


class RuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_keeps_slot_and_temp_file_until_real_completion(self):
        runtime = ScanRuntime(timeout=0.03, hard_timeout=2, hard_exit=lambda: None)
        entered, release = threading.Event(), threading.Event()
        paths = []
        def work():
            with tempfile.TemporaryDirectory() as directory:
                file = Path(directory) / "still-owned"
                file.write_text("alive")
                paths.append(file)
                entered.set()
                release.wait(1)
                self.assertTrue(file.exists())
        task = asyncio.create_task(runtime.run(work))
        while not entered.is_set():
            await asyncio.sleep(0.001)
        try:
            with self.assertRaises(ScanTimeout):
                await task
            self.assertEqual(runtime.active, 1)
            self.assertTrue(paths[0].exists())
            with self.assertRaises(ScanBusy):
                await runtime.run(lambda: None)
        finally:
            release.set()
            await asyncio.gather(*tuple(runtime._jobs))
        await asyncio.sleep(0)
        self.assertEqual(runtime.active, 0)
        self.assertFalse(paths[0].exists())

    async def test_disconnect_retains_slot(self):
        runtime = ScanRuntime(timeout=1, hard_timeout=2, hard_exit=lambda: None)
        release = threading.Event()
        task = asyncio.create_task(runtime.run(release.wait, 1))
        await asyncio.sleep(0.02)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(runtime.active, 1)
        release.set()
        await asyncio.gather(*tuple(runtime._jobs))
        await asyncio.sleep(0)
        self.assertEqual(runtime.active, 0)


if __name__ == "__main__":
    unittest.main()
