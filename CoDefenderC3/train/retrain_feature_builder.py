"""Fresh-process, pinned byte-stat/SMDA adapter for the split loader.

Only audited numeric byte stats and D/E statistics are supported. Legacy stages
that swallow parser failures are deliberately not exposed as successful output.
"""
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
try:
    from .retrain_contract import ContractError, digest
    from .retrain_cache import file_sha256, read_features, atomic_json
    from .retrain_loader import FeatureResult
except ImportError:
    from retrain_contract import ContractError, digest
    from retrain_cache import file_sha256, read_features, atomic_json
    from retrain_loader import FeatureResult

FAST_VERSION = "retrain-byte-stats-v1"
BYTE_FEATURES = {"B%02d" % i for i in range(1, 8)}
SMDA_FEATURES = {"D%02d" % i for i in range(1, 8)} | {"E03", "E04"}
SOURCE_FILES = (
    "train/retrain_feature_builder.py", "train/retrain_feature_worker.py",
    "train/retrain_contract.py", "engine/feature_contract.py", "train/retrain_cache.py", "train/retrain_loader.py",
    "train/retrain_manifest.py", "train/verify_retrain_manifest.py",
    "feature_extraction/extract_feature.py", "feature_extraction/smda_extract.py",
    "feature_extraction/hashing.py", "insn_categories.py",
)


def source_revision(project=None):
    project = Path(project or Path(__file__).resolve().parents[1])
    return digest({name: file_sha256(project / name) for name in SOURCE_FILES})


def runtime_packages(backend):
    names = ["numpy"] + (["smda", "capstone", "lief", "demangle", "dncil", "dnfile", "purepdb", "pefile"] if backend == "smda" else [])
    return {"python": platform.python_version(), **{n: importlib.metadata.version(n) for n in names}}


def validate_runtime(contract):
    d = contract.document
    backend = d["backend"]
    name, cfg = backend["name"], backend["config"]
    if name not in {"fast", "smda"}:
        raise ContractError("only pinned fast/smda backends are supported")
    fields = {"hard_timeout_seconds"} | ({"analysis_timeout_seconds", "disassembler", "api_name_style"} if name == "smda" else set())
    if set(cfg) != fields or type(cfg["hard_timeout_seconds"]) not in (int, float) or cfg["hard_timeout_seconds"] <= 0:
        raise ContractError("explicit hard timeout/config required")
    if name == "smda" and (type(cfg["analysis_timeout_seconds"]) is not int or cfg["analysis_timeout_seconds"] < 30
                           or cfg["disassembler"] != "intel" or cfg["api_name_style"] not in {"raw", "short"}):
        raise ContractError("SMDA requires >=30s native budget, intel backend, and explicit API style")
    allowed = BYTE_FEATURES | (SMDA_FEATURES if name == "smda" else set())
    if not set(d["features"]).issubset(allowed):
        raise ContractError("requested feature is not audited by this adapter (no inferred graph topology)")
    packages = runtime_packages(name)
    if d["extractor"]["packages"] != packages:
        raise ContractError("runtime package/Python versions differ from contract")
    expected_version = FAST_VERSION if name == "fast" else packages["smda"]
    if backend["version"] != expected_version or d["extractor"]["revision"] != source_revision():
        raise ContractError("backend version or extractor source revision mismatch")


class SubprocessFeatureBuilder:
    def __init__(self, *, python=None, package_paths=()):
        self.python = str(python or sys.executable)
        # Explicit import paths only; inherited PYTHONPATH is never silently trusted.
        self.package_paths = tuple(str(Path(p).resolve()) for p in package_paths)

    def __call__(self, sample, contract):
        cfg = contract.document["backend"]["config"]
        timeout = cfg.get("hard_timeout_seconds")
        if type(timeout) not in (int, float) or timeout <= 0:
            return FeatureResult("error", {}, contract.feature_fingerprint, "positive hard timeout required")
        worker = Path(__file__).with_name("retrain_feature_worker.py")
        identity = dict(schema="retrain-worker-cache-v1", content_sha256=file_sha256(sample),
                        feature_fingerprint=contract.feature_fingerprint, analysis_status="ok")
        with tempfile.TemporaryDirectory(prefix="retrain-worker-") as tmp:
            tmp = Path(tmp)
            cp, output, response = tmp / "contract.json", tmp / "features.npz", tmp / "response.json"
            atomic_json(cp, contract.document)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("CODEFENDER_", "BN_")) and k not in {"PYTHONPATH", "PYTHONHOME"}}
            env.update(PYTHONIOENCODING="utf-8", PYTHONHASHSEED="0", PYTHONNOUSERSITE="1")
            if self.package_paths:
                env["PYTHONPATH"] = os.pathsep.join(self.package_paths)
            try:
                run = subprocess.run([self.python, str(worker), "--sample", str(Path(sample).resolve()),
                                      "--contract", str(cp), "--output", str(output), "--response", str(response)],
                                     env=env, cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     timeout=timeout, check=False)
            except subprocess.TimeoutExpired:
                # subprocess.run kills and waits for the direct native-analysis worker.
                return FeatureResult("timeout", {}, contract.feature_fingerprint, "hard process timeout")
            except OSError as error:
                return FeatureResult("error", {}, contract.feature_fingerprint, str(error))
            try:
                reply = json.loads(response.read_text(encoding="utf-8"))
                if reply.get("feature_fingerprint") != contract.feature_fingerprint or reply.get("content_sha256") != identity["content_sha256"]:
                    raise ContractError("worker result identity mismatch")
                status = reply.get("status")
                if status not in {"ok", "timeout", "partial", "error"}:
                    raise ContractError("unknown worker status")
                if status != "ok":
                    return FeatureResult(status, {}, contract.feature_fingerprint, reply.get("error", "worker failed"))
                if run.returncode != 0:
                    raise ContractError("worker exited unsuccessfully")
                arrays, _ = read_features(output, identity, contract)
                return FeatureResult("ok", arrays, contract.feature_fingerprint)
            except (OSError, ValueError, TypeError) as error:
                return FeatureResult("error", {}, contract.feature_fingerprint, "%s: %s" % (type(error).__name__, error))
