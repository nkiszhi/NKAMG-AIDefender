"""Real-PE, CPU/NumPy retrain smoke; isolated outputs, never a deployment export.

Uses the existing strict split loader, audited subprocess byte extractor, actual
NatarajKNN implementation, frozen input contract and split-aware training runner.
It deliberately does not import the torch-dependent legacy feature registry.
"""
import argparse
from collections import Counter
import csv
from datetime import date
import hashlib
import inspect
import json
import os
from pathlib import Path
import pickle
import platform
import re
import sys
import time

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))
import numpy as np
from engine.decision_policy import DecisionPolicy
from models.input_contract import ModelInputContract, freeze_constructor
from models.NatarajKNN_2011.nataraj_knn import NatarajKNN
from train.build_retrain_dataset import build
from train.retrain_cache import atomic_json, file_sha256
from train.retrain_contract import FeatureContract, ContractError, digest
from train.retrain_feature_builder import FAST_VERSION, runtime_packages, source_revision, SubprocessFeatureBuilder
from train.retrain_loader import RetrainSplitLoader, SPLITS
from train.retrain_manifest import FIELDS, GROUP_RULE, rank, size_bucket, valid_ssdeep
from train.retrain_run import EnsembleTrainingBackend, run_training, verified_manifest, close_batch
from train.retrain_selection import auc
from train.verify_retrain_manifest import verify, pe_header_type

MODEL = "NatarajKNN"
VIEW = "V2_byte_stat"
LIMITATIONS = [
    "Small same-month stratified smoke, NOT temporal/generalization acceptance.",
    "Directory/manifest labels are inherited, not independently adjudicated.",
    "SHA256 and available exact ssdeep dedup only; no near-duplicate/family/software-lineage isolation.",
    "One real NumPy model only; torch/SMDA/special pipelines are not tested.",
    "Threshold is calibration F1 selection, not a low-FPR constrained operating point.",
    "Research artifact only; production ensemble and weights are never overwritten.",
]


class InsufficientSamples(ValueError):
    def __init__(self, name, rows, excluded, inventory):
        super().__init__("insufficient valid unique PE samples: " + name)
        self.rows, self.excluded, self.inventory = rows, excluded, inventory


def split_sizes(count):
    if type(count) is not int or count < 20:
        raise ValueError("at least 20 samples per class required")
    values = [int(count*.60), int(count*.15), int(count*.10)]
    values.append(count-sum(values))
    return dict(zip(SPLITS, values))


def benign_manifest(root):
    result = {}
    for file in sorted(root.rglob("manifest.csv")):
        with file.open(encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                sha = row.get("sha256", "").lower().strip()
                if re.fullmatch(r"[0-9a-f]{64}", sha):
                    if sha in result and result[sha].get("ssdeep") != row.get("ssdeep"):
                        raise ValueError("ambiguous benign manifest ssdeep: " + sha)
                    result[sha] = row
    return result


def sample_files(root, seed):
    files = []
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(directory)/d).is_symlink())
        for name in names:
            file = Path(directory)/name
            if not file.is_symlink() and file.suffix.lower() not in {".csv", ".json", ".txt", ".md", ".log"}:
                files.append(file)
    return sorted(files, key=lambda f: (rank(seed, f.relative_to(root).as_posix()), str(f)))


def select_samples(source_root, count, seed):
    selected, excluded, seen, seen_ssdeep, inventory = [], [], {}, set(), {}
    metadata = benign_manifest(source_root/"benign")
    for label, name in [(0, "benign"), (1, "malicious")]:
        base = source_root/name
        files = sample_files(base, seed)
        inventory[name] = {"candidate_files": len(files), "selected": 0}
        for file in files:
            if inventory[name]["selected"] == count:
                break
            try:
                ft = pe_header_type(file)
                size = file.stat().st_size
                sha = file_sha256(file)
                stem = file.stem.lower() if file.suffix else file.name.lower()
                if re.fullmatch(r"[0-9a-f]{64}", stem) and stem != sha:
                    raise ValueError("filename_sha256_mismatch")
                if sha in seen:
                    raise ValueError("duplicate_sha256" if seen[sha] == label else "cross_label_sha256_conflict")
                info = metadata.get(sha, {}) if label == 0 else {}
                ssdeep = info.get("ssdeep", "").strip()
                if not valid_ssdeep(ssdeep):
                    ssdeep = ""
                if ssdeep and ssdeep in seen_ssdeep:
                    raise ValueError("duplicate_exact_ssdeep")
                stamp, kind, month = "", "unavailable", ""
                if label == 1:
                    for part in file.relative_to(base).parts[:-1]:
                        try:
                            stamp = date.fromisoformat(part).isoformat()
                            kind = "directory_collection_date_unverified_semantics"
                            month = stamp[:7]
                            break
                        except ValueError:
                            pass
                    if not stamp:
                        raise ValueError("malicious_collection_date_unavailable")
                row = dict.fromkeys(FIELDS, "")
                row.update(sample_id=sha, sha256=sha, label=str(label), group_rule=GROUP_RULE,
                           group_id=digest({"exact_ssdeep": ssdeep}) if ssdeep else sha,
                           filetype=ft, parsed_filetype=ft, size=str(size), size_bucket=size_bucket(size),
                           timestamp=stamp, timestamp_kind=kind, month=month,
                           source=name+"/"+file.relative_to(base).parts[0], ssdeep=ssdeep,
                           path=str(file.resolve()), label_provenance="user_directory:"+name,
                           label_confidence="unverified", manifest="directory_selection",
                           row_number=str(len(selected)+1))
                selected.append(row)
                seen[sha] = label
                if ssdeep:
                    seen_ssdeep.add(ssdeep)
                inventory[name]["selected"] += 1
            except (ValueError, OSError) as error:
                excluded.append({"path": str(file), "label": label, "reason": str(error)})
        print(json.dumps({"stage": "selection", "class": name, **inventory[name]}, ensure_ascii=False), flush=True)
        if inventory[name]["selected"] != count:
            raise InsufficientSamples(name, selected, excluded, inventory)
    sizes = split_sizes(count)
    for label in ("0", "1"):
        rows = sorted((r for r in selected if r["label"] == label), key=lambda r: rank(seed, r["sha256"]))
        offset = 0
        for role, n in sizes.items():
            for row in rows[offset:offset+n]:
                row["split"] = role
            offset += n
    return sorted(selected, key=lambda r: r["sample_id"]), excluded, inventory


def freeze_features():
    features = {"B02": {"shape": [256], "dtype": "float32"},
                "B03": {"shape": [256], "dtype": "float32"},
                "B04": {"shape": [256], "dtype": "float32"},
                "B05": {"shape": [8], "dtype": "float32"}}
    return FeatureContract({"schema_version": "retrain-features-v1",
        "backend": {"name": "fast", "version": FAST_VERSION, "config": {"hard_timeout_seconds": 120}},
        "extractor": {"revision": source_revision(), "packages": runtime_packages("fast")},
        "features": features,
        "views": {VIEW: {"features": list(features), "dtype": "float32", "length": None, "masked_features": []}}})


class NumpySmokeBackend(EnsembleTrainingBackend):
    """Real model adapter; reuses strict production fit/restore/predict methods.

    The legacy registry imports torch even for NumPy models. This explicit,
    bounded adapter freezes the actual NatarajKNN class and all constructor
    values instead of installing torch or injecting a fake dependency.
    """
    def __init__(self, contract):
        self.contract = contract
        self.classes, self.specs = {}, {}
        self.input_contract = None
        self.identity = {"backend": "real-nataraj-numpy-smoke-v1", "python": platform.python_version(),
                         "numpy": np.__version__, "selection_device": "cpu",
                         "adapter_sha256": file_sha256(__file__),
                         "registry_sha256": file_sha256(PROJECT/"model_registry.py"),
                         "config_sha256": file_sha256(PROJECT/"config.py")}

    def model_specs(self, names):
        if list(names) != [MODEL]:
            raise ContractError("smoke supports only the explicitly frozen NatarajKNN model")
        kwargs = freeze_constructor(NatarajKNN, {"k": 5})
        spec = dict(view=VIEW, engine="numpy", kwargs=kwargs, loss="none", x_dtype="float",
                    dimension=self.contract.view_dimension(VIEW), dtype=np.dtype("float32").str,
                    source_sha256=file_sha256(inspect.getfile(NatarajKNN)))
        self.classes, self.specs = {MODEL: NatarajKNN}, {MODEL: spec}
        self.input_contract = ModelInputContract.build(self.contract, [MODEL], {MODEL: {
            "class": NatarajKNN, "view": VIEW, "engine": "numpy", "kwargs": kwargs,
            "tensor_dtype": "float32", "output": "binary_proba"}})
        self.input_contract.validate_runtime()
        return self.specs


def metrics(y, scores, predictions):
    y, scores, predictions = np.asarray(y), np.asarray(scores), np.asarray(predictions)
    tp = int(((y == 1) & (predictions == 1)).sum())
    tn = int(((y == 0) & (predictions == 0)).sum())
    fp = int(((y == 0) & (predictions == 1)).sum())
    fn = int(((y == 1) & (predictions == 0)).sum())
    precision, recall = tp/max(tp+fp, 1), tp/max(tp+fn, 1)
    return dict(n=len(y), benign=int((y == 0).sum()), malicious=int((y == 1).sum()),
                tp=tp, tn=tn, fp=fp, fn=fn, accuracy=(tp+tn)/len(y),
                precision=precision, recall=recall, f1=2*precision*recall/max(precision+recall, 1e-15),
                auc=auc(y, scores), fpr=fp/max(fp+tn, 1), fnr=fn/max(fn+tp, 1))


def extract_role(loader, role, builder, output):
    started = time.monotonic()
    completed = 0
    def tracked(sample, contract):
        nonlocal completed
        result = builder(sample, contract)
        completed += 1
        if completed % 50 == 0:
            print(json.dumps({"stage": "feature_progress", "role": role, "extracted": completed, "total": len(loader.split_ids(role))}), flush=True)
        return result
    report = loader.ensure_features(role, tracked)
    atomic_json(output/("features_"+role+".json"), report)
    print(json.dumps({"stage": "features", "role": role, "seconds": time.monotonic()-started,
                      "report": {k:v for k,v in report.items() if k not in {"samples", "statuses", "requested_ids", "included_ids"}}},
                     ensure_ascii=False), flush=True)
    batch = loader.get_split(role, views=[VIEW])
    close_batch(batch)
    return report


def prepare(source, output, count, seed):
    try:
        rows, excluded, inventory = select_samples(source, count, seed)
    except InsufficientSamples as error:
        atomic_json(output/"selection_audit.json", dict(status="insufficient_valid_pe_samples",
            source=str(source), seed=seed, count_per_class=count, inventory=error.inventory,
            excluded=error.excluded, rejection_counts=dict(Counter(r["reason"] for r in error.excluded)),
            limitations=LIMITATIONS))
        raise
    atomic_json(output/"selection_audit.json", dict(source=str(source), seed=seed, count_per_class=count,
        inventory=inventory, excluded=excluded, selected_bytes=sum(int(r["size"]) for r in rows),
        limitations=LIMITATIONS, split_kind="same_month_stratified_random_smoke"))
    manifest = output/"selection_manifest.csv"
    with manifest.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader(); writer.writerows(rows)
    months = sorted({r["month"] for r in rows if r["label"] == "1"})
    if len(months) != 1:
        raise ValueError("this bounded smoke requires one collection month; use temporal planner otherwise")
    counts = Counter(r["split"]+":"+r["label"] for r in rows)
    plan = dict(schema_version="retrain-same-month-smoke-plan-v1", seed=seed,
        split_kind="same_month_stratified_random_smoke", train_months=months,
        development_month=months[0], test_month=months[0], matched_counts=dict(counts),
        outputs={"selection": {"path": str(manifest), "sha256": file_sha256(manifest)}},
        blockers=["smoke_not_formal_temporal_split", "independent_label_and_lineage_review_pending"])
    atomic_json(output/"split_plan.json", plan)
    audit_dir = output/"path_verification"; audit_dir.mkdir()
    audit = verify(manifest, audit_dir)
    if not audit["build_allowed"]:
        raise ValueError("PE path/header/hash audit failed")
    build(audit_dir/"verified_selection_manifest.csv", output/"split_plan.json",
          audit_dir/"path_audit.json", output/"dataset")
    contract = freeze_features()
    atomic_json(output/"dataset"/"feature_contract.json", contract.document)
    atomic_json(output/"prepared.json", dict(source=str(source), count=count, seed=seed,
        feature_fingerprint=contract.feature_fingerprint, counts=dict(counts),
        source_sha256=file_sha256(__file__)))
    print(json.dumps({"stage":"prepared", "counts":dict(counts), "bytes":sum(int(r["size"]) for r in rows)}), flush=True)


def evaluate(loader, backend, output):
    run_dir = output/"runs"/"nataraj_cpu"
    manifest = verified_manifest(run_dir)
    # Hash-verify locally generated artifact before trusted-local unpickling.
    if file_sha256(run_dir/"trained_models.pkl") != manifest["artifact_sha256"]:
        raise ContractError("research artifact checksum mismatch")
    with (run_dir/"trained_models.pkl").open("rb") as stream:
        bundle = pickle.load(stream)
    if (bundle["input_fingerprint"] != backend.input_contract.fingerprint
            or bundle["run_fingerprint"] != manifest["run_fingerprint"]):
        raise ContractError("restored bundle identity mismatch")
    info = manifest["per_model_status"][MODEL]["info"]
    model = backend.restore(MODEL, bundle["trained_models"][MODEL], info)
    batch = loader.get_split("test", views=[VIEW])
    try:
        known = set().union(*(set(manifest["roles"][r]["sample_ids"]) for r in ["train", "model_val", "calibration"]))
        if known.intersection(batch.sample_ids.tolist()):
            raise ContractError("held-out test overlaps development roles")
        raw = backend.predict(MODEL, model, batch)
        if raw["sample_ids"] != batch.sample_ids.tolist():
            raise ContractError("test predictions are misaligned")
        scores = np.asarray(raw["scores"])[:,None]
        policy = DecisionPolicy(manifest["decision_candidate"]["decision_policy"])
        decisions = policy.evaluate(scores, model_names=[MODEL], statuses=np.full(scores.shape,"ok"),
                                    sample_ids=batch.sample_ids).require_decidable()
        result = dict(schema_version="retrain-real-pe-smoke-evaluation-v1", status="complete",
            model_names=[MODEL], run_fingerprint=manifest["run_fingerprint"],
            input_fingerprint=bundle["input_fingerprint"], policy=policy.document,
            test_matrix_fingerprint=batch.matrix_fingerprint, test_count=len(batch.labels),
            test_used_for_selection=False, restored_from_disk=True, deployable=False,
            metrics=metrics(batch.labels, decisions.scores, decisions.predictions), limitations=LIMITATIONS)
        with (output/"test_predictions.csv").open("w",encoding="utf-8",newline="") as stream:
            writer=csv.writer(stream);writer.writerow(["sample_id","label","score","prediction"])
            writer.writerows(zip(batch.sample_ids.tolist(), batch.labels.tolist(), decisions.scores.tolist(), decisions.predictions.tolist()))
        result["test_predictions_sha256"]=file_sha256(output/"test_predictions.csv")
        atomic_json(output/"evaluation.json",result)
        return result
    finally:
        close_batch(batch)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--count-per-class",type=int,default=1000)
    parser.add_argument("--seed",type=int,default=20261116)
    parser.add_argument("--cache-dir",type=Path,help="short cache root; default is an output-specific sibling")
    parser.add_argument("--resume",action="store_true")
    args=parser.parse_args(argv)
    source,output=args.source_root.resolve(),args.output.resolve()
    if output==source or output.is_relative_to(source) or source.is_relative_to(output):
        raise ValueError("source and output must have disjoint namespaces")
    if not 0<=args.seed<2**32:
        raise ValueError("seed out of range")
    split_sizes(args.count_per_class)
    started=time.monotonic()
    if args.resume:
        prepared=json.loads((output/"prepared.json").read_text(encoding="utf-8"))
        if (prepared["source"]!=str(source) or prepared["count"]!=args.count_per_class or prepared["seed"]!=args.seed
                or prepared["source_sha256"]!=file_sha256(__file__)):
            raise ContractError("resume selection/source identity changed")
    else:
        output.mkdir(parents=True,exist_ok=False)
        prepare(source,output,args.count_per_class,args.seed)
    cache=(args.cache_dir.resolve() if args.cache_dir else output.parent/("sc-"+digest(str(output))[:8]))
    if cache==source or cache.is_relative_to(source) or source.is_relative_to(cache):
        raise ValueError("feature cache cannot alias the source namespace")
    atomic_json(output/"runtime.json",dict(cache_dir=str(cache),python=sys.executable,
        python_version=platform.python_version(),numpy_version=np.__version__,device="cpu"))
    loader=RetrainSplitLoader(output/"dataset",cache_dir=cache).load()
    backend=NumpySmokeBackend(loader.contract)
    options=dict(mode="scratch",device="cpu",epochs=1,lr=.001,patience=1,seed=args.seed,
                 weighting="equal",threshold_grid=[float(x) for x in np.linspace(.05,.95,91)])
    builder=SubprocessFeatureBuilder()
    for role in ["train","model_val","calibration"]:
        extract_role(loader,role,builder,output)
    preflight=run_training(loader,backend,[MODEL],options,output/"runs","nataraj_cpu",dry_run=True)
    atomic_json(output/"preflight.json",preflight)
    print(json.dumps({"stage":"preflight",**preflight}),flush=True)
    run_dir=output/"runs"/"nataraj_cpu"
    if args.resume and (run_dir/"complete.json").exists():
        manifest=verified_manifest(run_dir)
        if manifest["run_fingerprint"]!=preflight["run_fingerprint"]:
            raise ContractError("completed candidate differs from current inputs")
    else:
        manifest=run_training(loader,backend,[MODEL],options,output/"runs","nataraj_cpu",
                              resume=args.resume and run_dir.exists())
    print(json.dumps({"stage":"trained", "status":manifest["status"]}),flush=True)
    # Test extraction/access starts ONLY after fit, weights and threshold are frozen.
    extract_role(loader,"test",builder,output)
    result=evaluate(loader,backend,output)
    result["duration_seconds"]=time.monotonic()-started
    atomic_json(output/"evaluation.json",result)
    print(json.dumps(result,ensure_ascii=False),flush=True)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
