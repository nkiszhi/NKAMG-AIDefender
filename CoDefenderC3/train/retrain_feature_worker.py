"""One-sample worker. Analyze bytes; never execute a PE or import torch."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import types
try:
    from .retrain_contract import FeatureContract, ContractError
    from .retrain_cache import atomic_json, file_sha256, write_features
    from .retrain_feature_builder import validate_runtime, BYTE_FEATURES, SMDA_FEATURES
    from .verify_retrain_manifest import pe_header_type
except ImportError:
    from retrain_contract import FeatureContract, ContractError
    from retrain_cache import atomic_json, file_sha256, write_features
    from retrain_feature_builder import validate_runtime, BYTE_FEATURES, SMDA_FEATURES
    from verify_retrain_manifest import pe_header_type


def module_from_file(name, file):
    spec = importlib.util.spec_from_file_location(name, file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def native_status(report):
    status = getattr(report, "status", None)
    if status not in {"ok", "timeout", "error"}:
        return "error"
    return status


def extract(sample, contract):
    validate_runtime(contract)
    pe_header_type(sample)
    project = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project))
    featdir = project / "feature_extraction"
    # Expose only the directory; do not run the torch-importing package initializer.
    package = types.ModuleType("feature_extraction")
    package.__path__ = [str(featdir)]
    sys.modules["feature_extraction"] = package
    wanted = set(contract.document["features"])
    features = {}
    if wanted & BYTE_FEATURES:
        mod = module_from_file("retrain_fast_extractor", featdir / "extract_feature.py")
        ex = mod.BinjaExtractor.__new__(mod.BinjaExtractor)
        ex.bn, ex._headless = None, True
        # Direct audited stage, not extract_fast's exception-swallowing loop.
        values = ex._extract_byte_stats(Path(sample).read_bytes())
        features.update({k: values[k] for k in wanted & BYTE_FEATURES})
    if wanted & SMDA_FEATURES:
        cfg = contract.document["backend"]["config"]
        os.environ["CODEFENDER_SMDA_API_NAME_STYLE"] = cfg["api_name_style"]
        os.environ["CODEFENDER_SMDA_BACKEND"] = cfg["disassembler"]
        mod = module_from_file("retrain_smda_extractor", featdir / "smda_extract.py")
        ex = mod.SmdaExtractor(timeout=cfg["analysis_timeout_seconds"], backend=cfg["disassembler"])
        report = ex._analyze(str(sample))
        status = native_status(report)
        if status != "ok":
            return status, {}, "SMDA native analysis did not complete"
        values = ex.extract_de(str(sample))
        if mod.de_features_are_empty(values):
            raise ContractError("SMDA has no instructions/functions")
        features.update({k: values[k] for k in wanted & SMDA_FEATURES})
    contract.validate_features(features)
    if "torch" in sys.modules:
        raise ContractError("worker imported forbidden training runtime")
    return "ok", features, ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sample", "contract", "output", "response"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    contract = FeatureContract(json.loads(args.contract.read_text(encoding="utf-8")))
    sha = file_sha256(args.sample)
    try:
        status, arrays, error = extract(args.sample, contract)
        if status == "ok":
            if file_sha256(args.sample) != sha:
                raise ContractError("snapshot changed in worker")
            identity = dict(schema="retrain-worker-cache-v1", content_sha256=sha,
                            feature_fingerprint=contract.feature_fingerprint, analysis_status="ok")
            write_features(args.output, arrays, identity, contract)
    except Exception as exc:
        status, error = "error", "%s: %s" % (type(exc).__name__, exc)
    atomic_json(args.response, dict(status=status, error=error, content_sha256=sha,
                                  feature_fingerprint=contract.feature_fingerprint))
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
