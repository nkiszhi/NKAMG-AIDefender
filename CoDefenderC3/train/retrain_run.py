"""Fail-closed split-aware research training. No test feature access or deployment export."""
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import pickle
import platform
import re
import sys
import tempfile
import numpy as np
from engine.decision_policy import DecisionPolicy, PolicyError
from engine.feature_contract import canonical
from models.input_contract import ModelInputContract, freeze_constructor
try:
    from .retrain_contract import ContractError, digest, NAME_RE, SHA_RE
    from .retrain_cache import atomic_json, file_sha256, key_lock
    from .retrain_selection import labels, probabilities, select_weights, aggregate, select_threshold
    from .retrain_training import train_numpy_external, train_torch_external
except ImportError:
    from retrain_contract import ContractError, digest, NAME_RE, SHA_RE
    from retrain_cache import atomic_json, file_sha256, key_lock
    from retrain_selection import labels, probabilities, select_weights, aggregate, select_threshold
    from retrain_training import train_numpy_external, train_torch_external

SCHEMA = "retrain-training-run-v1"
ARTIFACT_SCHEMA = "retrain-training-artifact-v1"


class TrainingFailure(RuntimeError):
    pass


def atomic_pickle(path, value):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix=path.name+".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(value, f, protocol=pickle.HIGHEST_PROTOCOL)
            f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def close_batch(batch):
    for arr in list(batch.views.values()) + [batch.labels, batch.sample_ids, batch.requested_ids]:
        mmap = getattr(arr, "_mmap", None)
        if mmap is not None and not mmap.closed: mmap.close()


def checked_batch(loader, role, views):
    if role not in {"train", "model_val", "calibration"}:
        raise ContractError("training runner cannot read test or role aliases")
    batch = loader.get_split(role, views=views)  # no extraction; no allow_partial override
    ids = list(loader.split_ids(role))
    try:
        if (batch.split != role or batch.sample_ids.tolist() != ids or batch.requested_ids.tolist() != ids
                or batch.report["included_ids"] != ids or batch.report["requested_ids"] != ids
                or batch.report["covered"] != len(ids) or batch.report["requested"] != len(ids)
                or batch.report["excluded"] != 0 or batch.report["coverage"] != 1):
            raise ContractError("full-coverage IDs/report are not aligned")
        labels(batch.labels)
        if (batch.feature_fingerprint != loader.contract.feature_fingerprint
                or batch.view_fingerprint != loader.contract.view_fingerprint(views)
                or not isinstance(batch.matrix_fingerprint, str)
                or not SHA_RE.fullmatch(batch.matrix_fingerprint)):
            raise ContractError("split feature/view/matrix identity mismatch")
        if len(batch.labels) != len(ids) or set(batch.views) != set(views):
            raise ContractError("split labels/views are misaligned")
        for view in views:
            arr = batch.views[view]
            if arr.shape != (len(ids), loader.contract.view_dimension(view)) or arr.dtype != np.dtype(loader.contract.view_spec(view)["dtype"]):
                raise ContractError("split view schema mismatch")
        return batch
    except Exception:
        close_batch(batch)
        raise


def batch_identity(batch):
    return dict(split=batch.split, sample_ids=batch.sample_ids.tolist(), labels=batch.labels.tolist(),
                requested_ids=batch.requested_ids.tolist(), report=batch.report,
                feature_fingerprint=batch.feature_fingerprint, view_fingerprint=batch.view_fingerprint,
                matrix_fingerprint=batch.matrix_fingerprint)


def score_models(backend, names, models, batch):
    columns = []
    for name in names:
        reply = backend.predict(name, models[name], batch)
        if not isinstance(reply, dict) or reply.get("sample_ids") != batch.sample_ids.tolist():
            raise ContractError("model score IDs are misaligned: " + name)
        columns.append(probabilities(reply.get("scores"), len(batch.labels)))
    return np.column_stack(columns)


class EnsembleTrainingBackend:
    """Production model adapters are lazy; no legacy constant-fill predictor is used."""
    requires_input_contract = True

    def __init__(self, baseline, contract):
        from models.ensemble import MultiModelEnsemble
        from model_registry import get_model_config
        self.baseline = Path(baseline).resolve()
        self.ens = MultiModelEnsemble.load(str(self.baseline))
        self.contract = contract
        self.get_config = get_model_config
        self.classes, self.specs = {}, {}
        self.input_contract = None
        self.identity = dict(baseline_sha256=file_sha256(self.baseline),
                             python=platform.python_version(), numpy=np.__version__, selection_device="cpu")

    def model_specs(self, names):
        self.classes, self.specs = {}, {}
        self.input_contract = None
        declarations = {}
        view_of = {}
        for view, members in self.ens.view_groups.items():
            for name in members:
                if name in view_of: raise ContractError("model belongs to duplicate views")
                view_of[name] = view
        for name in names:
            if name not in view_of or view_of[name] not in self.contract.view_names:
                raise ContractError("requested model/view not supported by frozen contract: " + name)
            cfg = self.get_config(name)
            if cfg["engine"] not in {"numpy", "pytorch"} or self.ens._model_types.get(name) in {"special", "skip"}:
                raise ContractError("special/unknown model cannot use generic retraining: " + name)
            cls, _ = self.ens._load_model_class(name)
            if cls is None: raise ContractError("requested model class unavailable: " + name)
            view = view_of[name]
            dtype = np.dtype(self.contract.view_spec(view)["dtype"])
            ft = cfg["feature_type"].name
            x_dtype = "long" if ft in {"RAW_BYTES", "OPCODE_SEQ"} else "float"
            if ((x_dtype == "long" and (dtype.kind not in "iu" or not np.can_cast(dtype, np.int64, casting="safe")))
                    or (x_dtype == "float" and dtype != np.dtype("float32"))
                    or (cfg["engine"] == "numpy" and dtype != np.dtype("float32"))):
                raise ContractError("model requires a compatible explicitly declared view dtype")
            if cfg["engine"] == "pytorch" and cfg["loss"] not in {"bce", "ce"}:
                raise ContractError("unknown model output/loss contract")
            kwargs = dict(cfg["model_kwargs"])
            if "input_dim" in inspect.signature(cls.__init__).parameters:
                kwargs["input_dim"] = self.contract.view_dimension(view)
            kwargs = freeze_constructor(cls, kwargs)
            declarations[name] = {"class": cls, "view": view, "engine": cfg["engine"], "kwargs": kwargs,
                                  "tensor_dtype": "int64" if x_dtype == "long" else "float32",
                                  "output": "binary_proba" if cfg["engine"] == "numpy" else ("probability_1" if cfg["loss"] == "bce" else "logits_2")}
            spec = dict(view=view, engine=cfg["engine"], kwargs=kwargs, loss=cfg["loss"], x_dtype=x_dtype,
                        dimension=self.contract.view_dimension(view), dtype=dtype.str,
                        source_sha256=file_sha256(inspect.getfile(cls)))
            self.classes[name], self.specs[name] = cls, spec
        if any(s["engine"] == "pytorch" for s in self.specs.values()):
            self.identity["torch"] = importlib.metadata.version("torch")
        self.identity["registry_sha256"] = file_sha256(Path(__file__).resolve().parents[1] / "model_registry.py")
        self.identity["config_sha256"] = file_sha256(Path(__file__).resolve().parents[1] / "config.py")
        self.input_contract = ModelInputContract.build(self.contract, names, declarations)
        self.input_contract.validate_runtime()
        return self.specs

    def train(self, name, train, validation, options):
        spec, cls = self.specs[name], self.classes[name]
        if self.input_contract is None:
            raise ContractError("real backend requires frozen model inputs before fitting")
        self.input_contract.validate_runtime()
        X = self.input_contract.prepare(name, train.views[spec["view"]], batch=True)
        Xv = self.input_contract.prepare(name, validation.views[spec["view"]], batch=True)
        if spec["engine"] == "numpy":
            return train_numpy_external(cls, spec["kwargs"], X, train.labels, Xv, validation.labels,
                                        mode=options["mode"], seed=options["seed"])
        warm_state = None
        if options["mode"] == "finetune":
            base = self.ens._models.get(name)
            if base is None or not hasattr(base, "state_dict"):
                raise ContractError("finetune requires a valid baseline torch state")
            warm_state = {k: v.detach().cpu().clone() for k, v in base.state_dict().items()}
        model, info = train_torch_external(cls, spec["kwargs"], X, train.labels, Xv, validation.labels,
                                    device=options["device"], loss_kind=spec["loss"], x_dtype=spec["x_dtype"],
                                    epochs=options["epochs"], lr=options["lr"], patience=options["patience"],
                                    seed=options["seed"], warm_state=warm_state)
        # Selection uses the same CPU inference path for new and resumed models;
        # do not retain all completed models on the training GPU.
        info["selection_device"] = "cpu"
        return model.to("cpu"), info

    def serialize(self, name, model):
        self.input_contract.validate_model(name, model, self.specs[name]["kwargs"])
        if self.specs[name]["engine"] == "numpy": return model
        return {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    def restore(self, name, payload, info):
        spec = self.specs[name]
        if info["actual_kwargs"] != spec["kwargs"]: raise ContractError("checkpoint constructor differs")
        if spec["engine"] == "numpy":
            self.input_contract.validate_model(name, payload, info["actual_kwargs"])
            return payload
        model = self.classes[name](**spec["kwargs"])
        model.load_state_dict(payload, strict=True); model.eval()
        self.input_contract.validate_model(name, model, info["actual_kwargs"])
        return model

    def predict(self, name, model, batch):
        spec = self.specs[name]
        self.input_contract.validate_model(name, model, spec["kwargs"])
        X = self.input_contract.prepare(name, batch.views[spec["view"]], batch=True)
        if spec["engine"] == "numpy":
            proba = np.asarray(model.predict_proba(X))
            if proba.shape != (len(X), 2): raise ContractError("binary model output shape mismatch")
            for column in range(2):
                probabilities(proba[:, column], len(X))
            if not np.allclose(proba.sum(axis=1), 1, rtol=1e-6, atol=1e-6):
                raise ContractError("binary probability columns must sum to one")
            scores = proba[:, 1]
        else:
            import torch
            device = next(model.parameters()).device
            dtype = torch.long if spec["x_dtype"] == "long" else torch.float32
            model.eval(); rows = []
            with torch.no_grad():
                for start in range(0, len(X), 64):
                    out = model(torch.tensor(X[start:start+64], dtype=dtype, device=device))
                    if isinstance(out, tuple): out = out[0]
                    width = 1 if spec["loss"] == "bce" else 2
                    if out.ndim != 2 or out.shape != (min(64, len(X)-start), width): raise ContractError("binary torch output/loss shape mismatch")
                    scores = out[:, 0] if out.shape[1] == 1 else torch.softmax(out, dim=1)[:, 1]
                    rows.append(scores.detach().cpu().numpy())
            scores = np.concatenate(rows)
        return dict(sample_ids=batch.sample_ids.tolist(), scores=scores)


def validate_options(options):
    wanted = {"mode", "device", "epochs", "lr", "patience", "seed", "weighting", "threshold_grid"}
    if not isinstance(options, dict) or set(options) != wanted:
        raise ContractError("complete explicit training options required")
    if (options["mode"] not in {"scratch", "finetune"} or options["device"] not in {"cpu", "cuda"}
            or type(options["epochs"]) is not int or options["epochs"] <= 0
            or type(options["patience"]) is not int or options["patience"] <= 0
            or type(options["seed"]) is not int or not 0 <= options["seed"] < 2**32
            or type(options["lr"]) not in (int, float) or not np.isfinite(options["lr"]) or options["lr"] <= 0
            or options["weighting"] not in {"equal", "auc"}):
        raise ContractError("invalid hyperparameters")
    # Validate a predeclared grid without consuming any held-out data.
    grid = options["threshold_grid"]
    if (not isinstance(grid, list) or not grid or any(type(t) not in (int,float) or not np.isfinite(t) or not 0 <= t <= 1 for t in grid)
            or len(grid) != len(set(grid))):
        raise ContractError("finite unique threshold grid within [0,1] required")


def validate_input_specs(contract, feature_document, names, specs):
    """Semantic binding for v3 research metadata, without importing models."""
    if not isinstance(contract, ModelInputContract) or contract.model_names != tuple(names) or contract.feature_contract.document != feature_document:
        raise ContractError("research model input allowlist/feature contract mismatch")
    for name in names:
        frozen, spec = contract.spec(name), specs[name]
        expected_output = "binary_proba" if spec["engine"] == "numpy" else ("probability_1" if spec["loss"] == "bce" else "logits_2")
        if (frozen["view"] != spec["view"] or frozen["engine"] != spec["engine"]
                or canonical(frozen["constructor"]) != canonical(spec["kwargs"]) or frozen["output"] != expected_output
                or frozen["tensor_dtype"] != ("int64" if spec["x_dtype"] == "long" else "float32")
                or frozen["class_identity"]["source_sha256"] != spec["source_sha256"]
                or contract.feature_contract.view_dimension(spec["view"]) != spec["dimension"]
                or contract.feature_contract.view_spec(spec["view"])["dtype"] != spec["dtype"]):
            raise ContractError("research model spec differs from frozen input: "+name)


def training_revision():
    here = Path(__file__).resolve().parent
    files = ["retrain_run.py", "retrain_selection.py", "retrain_training.py", "train_all.py",
             "retrain_loader.py", "retrain_cache.py", "retrain_contract.py"]
    sources = {"train/"+name: file_sha256(here/name) for name in files}
    for name in ("engine/decision_policy.py", "engine/prediction_policy.py", "models/ensemble.py",
                 "models/input_contract.py", "models/contract_serialization.py", "engine/feature_contract.py"):
        sources[name] = file_sha256(here.parent/name)
    return digest(sources)


PUBLICATION_FILES = {
    "manifest.json": "manifest_sha256", "trained_models.pkl": "artifact_sha256",
    "progress.json": "progress_sha256", "decision_candidate.json": "decision_sha256",
    "locked_weights.json": "weights_sha256", "run_identity.json": "identity_sha256",
    "calibration_identity.json": "calibration_sha256",
}


def safe_member(base, *parts):
    """Reject parent traversal, symlinks and directory junctions in run-owned paths."""
    base = Path(base).resolve()
    candidate = base.joinpath(*parts)
    resolved = candidate.resolve()
    if resolved != candidate or not resolved.is_relative_to(base) or resolved == base:
        raise ContractError("run-owned path escapes or aliases its namespace")
    return candidate


def validate_progress(progress, fingerprint, names):
    if (not isinstance(progress, dict) or progress.get("schema_version") != SCHEMA
            or progress.get("run_fingerprint") != fingerprint or not isinstance(progress.get("models"), dict)
            or set(progress["models"]) - set(names)
            or progress.get("stage") not in {"training", "training_failed", "model_selection_failed",
                                            "weights_locked", "calibration_or_publication_failed",
                                            "complete_research_candidate"}):
        raise ContractError("invalid resume progress schema/identity/stage")
    for item in progress["models"].values():
        if not isinstance(item, dict) or item.get("status") not in {"ok", "failed", "checkpoint_invalid"}:
            raise ContractError("unknown model checkpoint status")
    if progress["stage"] == "complete_research_candidate" and (
            set(progress["models"]) != set(names)
            or any(item["status"] != "ok" for item in progress["models"].values())):
        raise ContractError("completed progress has missing or failed models")


def verified_manifest(run_dir):
    """Verify every published decision/control file without unpickling the bundle."""
    run_dir = Path(run_dir).resolve()
    try:
        pointer = json.loads(safe_member(run_dir, "complete.json").read_text(encoding="utf-8"))
        if pointer.get("schema_version") != SCHEMA:
            raise ContractError("invalid completion pointer schema")
        for name, key in PUBLICATION_FILES.items():
            if file_sha256(safe_member(run_dir, name)) != pointer[key]:
                raise ContractError("completion pointer checksum mismatch: " + name)
        def read(name):
            return json.loads(safe_member(run_dir, name).read_text(encoding="utf-8"))
        manifest, progress, identity = read("manifest.json"), read("progress.json"), read("run_identity.json")
        decision, locked, calibration = read("decision_candidate.json"), read("locked_weights.json"), read("calibration_identity.json")
        fingerprint = pointer["run_fingerprint"]
        if (manifest["schema_version"] != SCHEMA or identity["schema_version"] != SCHEMA
                or digest(identity) != fingerprint or manifest["run_fingerprint"] != fingerprint
                or manifest["status"] != "complete_research_candidate" or progress["stage"] != "complete_research_candidate"
                or manifest.get("deployable") is not False or decision.get("deployable") is not False
                or decision.get("test_used") is not False or manifest["decision_candidate"] != decision
                or locked["run_fingerprint"] != fingerprint or locked["selection"] != decision["weights"]
                or manifest["roles"]["calibration"] != calibration
                or manifest["artifact_sha256"] != pointer["artifact_sha256"]
                or manifest["model_names"] != identity["model_names"]
                or manifest["per_model_status"] != progress["models"]
                or manifest["options"] != identity["options"] or manifest["model_specs"] != identity["model_specs"]
                or manifest["roles"]["train"] != identity["train"] or manifest["roles"]["model_val"] != identity["model_val"]
                or decision["run_fingerprint"] != fingerprint
                or locked["model_val_matrix_fingerprint"] != identity["model_val"]["matrix_fingerprint"]
                or decision["calibration_matrix_fingerprint"] != calibration["matrix_fingerprint"]
                or decision["weights"]["selection_role"] != "model_val"
                or decision["threshold"]["selection_role"] != "calibration"):
            raise ContractError("incomplete or inconsistent candidate publication")
        expected_policy = DecisionPolicy.from_selection(decision["weights"], decision["threshold"])
        # Older v1 publications remain verifiable, never auto-deployed. New v2
        # publications must retain the full policy even if all hashes are rebuilt.
        if decision.get("schema_version") not in {"retrain-decision-candidate-v1", "retrain-decision-candidate-v2", "retrain-decision-candidate-v3"}:
            raise ContractError("unsupported research decision schema")
        if (decision["schema_version"] in {"retrain-decision-candidate-v2", "retrain-decision-candidate-v3"}
                or "decision_policy" in decision or "policy_fingerprint" in decision):
            saved_policy = DecisionPolicy(decision["decision_policy"])
            if saved_policy != expected_policy or decision["policy_fingerprint"] != expected_policy.fingerprint:
                raise ContractError("candidate decision policy differs from frozen selection")
        if decision["schema_version"] == "retrain-decision-candidate-v3" or "input_contract" in identity:
            frozen = ModelInputContract(identity["input_contract"])
            validate_input_specs(frozen, identity["feature_contract"], identity["model_names"], identity["model_specs"])
            for owner in (identity, manifest, decision):
                if owner["input_contract"] != frozen.document or owner["input_fingerprint"] != frozen.fingerprint:
                    raise ContractError("research publication model input contract mismatch")
        validate_progress(progress, fingerprint, manifest["model_names"])
        return manifest
    except ContractError:
        raise
    except (OSError, KeyError, ValueError, TypeError, AttributeError) as error:
        raise ContractError("no verified completed research candidate") from error


def run_training(loader, backend, names, options, run_root, run_id, *, resume=False, dry_run=False):
    validate_options(options)
    if (not isinstance(names, (list, tuple)) or not names or any(not isinstance(n,str) or not NAME_RE.fullmatch(n) for n in names)
            or len(names) != len(set(names))):
        raise ContractError("nonempty unique explicit model allowlist required")
    if (not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id)
            or run_id.endswith(".") or run_id.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *["COM%d"%i for i in range(1,10)], *["LPT%d"%i for i in range(1,10)]}):
        raise ContractError("safe explicit run-id required")
    run_root = Path(run_root).resolve(); run_dir = (run_root/run_id).resolve()
    if run_dir.parent != run_root: raise ContractError("run directory escapes root")
    try: run_dir.relative_to(loader.data_dir)
    except ValueError: pass
    else: raise ContractError("run output cannot be inside the read-only dataset")
    baseline = getattr(backend, "baseline", None)
    if baseline is not None and Path(baseline).resolve().is_relative_to(run_dir):
        raise ContractError("run output would contain/overwrite baseline")
    # Validate all existing run-owned entries before training or checkpoint reads.
    for member in [*PUBLICATION_FILES, "complete.json", "partial"]:
        safe_member(run_dir, member)
    for name in names:
        safe_member(run_dir, "partial", name+".pkl")
    lock = safe_member(run_root, ".retrain-run-locks", run_id+".lock")
    specs = backend.model_specs(names)
    if set(specs) != set(names): raise ContractError("model allowlist/specification mismatch")
    input_contract = getattr(backend, "input_contract", None)
    if getattr(backend, "requires_input_contract", False) is True and not isinstance(input_contract, ModelInputContract):
        raise ContractError("real training backend did not bind frozen model inputs")
    input_fields = {}
    if input_contract is not None:
        validate_input_specs(input_contract, loader.contract.document, names, specs)
        input_contract.validate_runtime()
        input_fields = dict(input_contract=input_contract.document, input_fingerprint=input_contract.fingerprint)
    if options["mode"] == "finetune" and any(specs[n].get("engine") == "numpy" for n in names):
        raise ContractError("NumPy finetune is unsupported; declare scratch explicitly")
    views = list(dict.fromkeys(specs[n]["view"] for n in names))
    train = validation = calibration = None
    try:
        train = checked_batch(loader, "train", views)
        validation = checked_batch(loader, "model_val", views)
        if set(train.sample_ids.tolist()) & set(validation.sample_ids.tolist()):
            raise ContractError("train and model_val sample overlap")
        identity = dict(schema_version=SCHEMA, feature_contract=loader.contract.document,
                        metadata_provenance={k:loader.metadata[k] for k in ("selection_fingerprint", "split_plan_fingerprint", "path_audit_fingerprint")},
                        backend=backend.identity, model_names=list(names), model_specs=specs, options=options,
                        train=batch_identity(train), model_val=batch_identity(validation), training_revision=training_revision(), **input_fields)
        fingerprint = digest(identity)
        if dry_run:
            return dict(status="preflight_ok", run_fingerprint=fingerprint, model_names=list(names), views=views,
                        roles_read=["train", "model_val"], reserved_roles=["calibration", "test"],
                        run_directory_written=False, deployable=False)
        with key_lock(lock):
            if resume:
                saved = json.loads((run_dir/"run_identity.json").read_text(encoding="utf-8"))
                if saved != identity: raise ContractError("resume data/contract/backend/options identity mismatch")
            else:
                run_dir.mkdir(parents=True, exist_ok=False)
                atomic_json(run_dir/"run_identity.json", identity)
            partial = run_dir/"partial"; partial.mkdir(exist_ok=True)
            progress_path = run_dir/"progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8")) if resume else dict(schema_version=SCHEMA, run_fingerprint=fingerprint, models={}, stage="training")
            validate_progress(progress, fingerprint, names)
            progress.pop("error", None); progress.pop("failed_model", None)
            progress["stage"] = "training"; atomic_json(progress_path, progress)
            models, payloads = {}, {}
            def fail(stage, name, exc):
                progress.update(stage=stage+"_failed", failed_model=name, error="%s: %s"%(type(exc).__name__,exc))
                atomic_json(progress_path, progress)
                raise TrainingFailure("%s failed (%s): %s"%(stage,name or "run",exc)) from exc
            for name in names:
                checkpoint = partial/(name+".pkl")
                item = progress["models"].get(name)
                try:
                    resumed_checkpoint = resume and item and item.get("status") == "ok"
                    if resume and item and item.get("status") == "checkpoint_invalid":
                        raise ContractError("invalid checkpoint requires a new run, not silent repair")
                    if resumed_checkpoint:
                        if file_sha256(checkpoint) != item["checkpoint_sha256"]:
                            raise ContractError("checkpoint checksum mismatch")
                        with checkpoint.open("rb") as f: saved = pickle.load(f)  # trusted local artifact only
                        if saved.get("schema_version") != SCHEMA or saved["run_fingerprint"] != fingerprint or saved["model_name"] != name:
                            raise ContractError("checkpoint identity mismatch")
                        info, payload = saved["info"], saved["payload"]
                        if info != item["info"]: raise ContractError("checkpoint/progress status mismatch")
                        model = backend.restore(name, payload, info)
                    else:
                        model, info = backend.train(name, train, validation, options)
                        if model is None: raise ContractError("training returned no model")
                        payload = backend.serialize(name, model)
                    if (not isinstance(info, dict) or info.get("validation_source") != "model_val"
                            or info.get("all_train_rows_used") is not True or info.get("n_train") != len(train.labels)
                            or info.get("n_val") != len(validation.labels)
                            or type(info.get("n_train")) is not int or type(info.get("n_val")) is not int
                            or not isinstance(info.get("actual_kwargs"), dict) or info["actual_kwargs"] != specs[name]["kwargs"]):
                        raise ContractError("model did not prove external validation/full training coverage")
                    # A trained checkpoint is complete only after finite, ID-aligned validation scores.
                    score_models(backend, [name], {name:model}, validation)
                    if not resumed_checkpoint:
                        atomic_pickle(checkpoint, dict(schema_version=SCHEMA, run_fingerprint=fingerprint, model_name=name, info=info, payload=payload))
                    progress["models"][name] = dict(status="ok", info=info, checkpoint_sha256=file_sha256(checkpoint))
                    atomic_json(progress_path, progress)
                    models[name], payloads[name] = model, payload
                except Exception as exc:
                    invalid_checkpoint = resume and item and item.get("status") in {"ok", "checkpoint_invalid"}
                    progress["models"][name] = dict(status="checkpoint_invalid" if invalid_checkpoint else "failed", error="%s: %s"%(type(exc).__name__,exc))
                    fail("training", name, exc)
            try:
                val_scores = score_models(backend, names, models, validation)
                weights = select_weights("model_val", validation.labels, val_scores, names, options["weighting"])
                locked = dict(run_fingerprint=fingerprint, selection=weights, model_val_matrix_fingerprint=validation.matrix_fingerprint)
                wp = run_dir/"locked_weights.json"
                if resume and wp.exists() and json.loads(wp.read_text(encoding="utf-8")) != locked:
                    raise ContractError("locked model_val selection changed during resume")
                atomic_json(wp, locked)
                progress["stage"] = "weights_locked"; atomic_json(progress_path, progress)
            except Exception as exc: fail("model_selection", None, exc)
            try:
                # First calibration feature/label access is after every model and all weights are frozen.
                calibration = checked_batch(loader, "calibration", views)
                if set(calibration.sample_ids.tolist()) & (set(train.sample_ids.tolist()) | set(validation.sample_ids.tolist())):
                    raise ContractError("calibration sample overlap")
                ci = batch_identity(calibration); cip = run_dir/"calibration_identity.json"
                if resume and cip.exists() and json.loads(cip.read_text(encoding="utf-8")) != ci:
                    raise ContractError("calibration identity changed during resume")
                atomic_json(cip, ci)
                cal_scores = score_models(backend, names, models, calibration)
                threshold = select_threshold("calibration", calibration.labels, aggregate(cal_scores, weights), options["threshold_grid"])
                policy = DecisionPolicy.from_selection(weights, threshold)
                decision = dict(decision_policy=policy.document, policy_fingerprint=policy.fingerprint, schema_version="retrain-decision-candidate-v3" if input_fields else "retrain-decision-candidate-v2", run_fingerprint=fingerprint,
                                **input_fields,
                                feature_fingerprint=loader.contract.feature_fingerprint, weights=weights, threshold=threshold,
                                calibration_matrix_fingerprint=calibration.matrix_fingerprint, test_used=False, deployable=False)
                # Publish a NON-legacy schema; cannot be mistaken for reloadable ensemble.pkl.
                bundle = dict(schema_version="retrain-training-artifact-v2" if input_fields else ARTIFACT_SCHEMA,
                              **input_fields, run_fingerprint=fingerprint, model_specs=specs,
                              trained_models=payloads, decision_candidate=decision, deployable=False)
                artifact = run_dir/"trained_models.pkl"
                atomic_pickle(artifact, bundle)
                atomic_json(run_dir/"decision_candidate.json", decision)
                manifest = dict(schema_version=SCHEMA, run_id=run_id, run_fingerprint=fingerprint, status="complete_research_candidate",
                                model_names=list(names), model_specs=specs, options=options, **input_fields, role_usage=dict(train="fit",model_val="external_validation_and_weights",calibration="threshold_only",test="not_read"),
                                roles=dict(train=batch_identity(train), model_val=batch_identity(validation), calibration=ci),
                                per_model_status=progress["models"], artifact_sha256=file_sha256(artifact), artifact_path=str(artifact),
                                decision_candidate=decision, deployable=False, blockers=["candidate_runtime_artifact_publication_pending", "audited_runtime_extractor_dependency_closure_and_independent_test_acceptance_pending"])
                atomic_json(run_dir/"manifest.json", manifest)
                progress["stage"] = "complete_research_candidate"; atomic_json(progress_path, progress)
                atomic_json(run_dir/"complete.json", dict(schema_version=SCHEMA, run_fingerprint=fingerprint, **{key: file_sha256(safe_member(run_dir, name)) for name, key in PUBLICATION_FILES.items()}))
                return manifest
            except Exception as exc: fail("calibration_or_publication", None, exc)
    finally:
        for batch in (train, validation, calibration):
            if batch is not None: close_batch(batch)
