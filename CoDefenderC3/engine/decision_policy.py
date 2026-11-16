"""Immutable, status-aware decision math shared by research and HTTP adapters.

No model loading, feature transforms, calibration fitting, or deployment approval.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import json
import re
import numpy as np

SCHEMA = "decision-policy-v1"
MODEL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")
STATUSES = {"ok", "missing", "skipped", "unavailable", "error", "timeout", "not_requested", "waiting"}


class PolicyError(ValueError):
    pass


class DecisionUnavailable(RuntimeError):
    pass


def array(value):
    try:
        return np.asarray(value)
    except (ValueError, TypeError) as exc:
        raise PolicyError("regular numeric/status array required") from exc


def names(value):
    if (not isinstance(value, (list, tuple)) or not value
            or any(not isinstance(n, str) or not MODEL_RE.fullmatch(n) for n in value)
            or len(set(value)) != len(value)):
        raise PolicyError("explicit unique model names required")
    return tuple(value)


def finite_number(value):
    try:
        return type(value) in (int, float) and bool(np.isfinite(value))
    except (TypeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True)
class DecisionBatch:
    predictions: np.ndarray
    scores: np.ndarray
    raw_scores: np.ndarray
    rows: tuple
    policy_fingerprint: str

    def require_decidable(self):
        failed = [r["sample_id"] for r in self.rows if r["status"] != "ok"]
        if failed:
            raise DecisionUnavailable("decision_unavailable:" + ",".join(failed))
        return self


@dataclass(frozen=True, init=False)
class DecisionPolicy:
    _raw: bytes
    model_names: tuple[str, ...]
    _weights: np.ndarray = field(repr=False, compare=False)
    fingerprint: str

    def __init__(self, document):
        try:
            raw = json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            doc = json.loads(raw)
        except (TypeError, ValueError) as exc:
            raise PolicyError("finite JSON policy required") from exc
        required = {"schema_version", "model_names", "weights", "threshold", "comparator", "calibrator", "missing_model_policy"}
        if not isinstance(doc, dict) or set(doc) != required or doc["schema_version"] != SCHEMA:
            raise PolicyError("explicit decision-policy-v1 schema required")
        selected = names(doc["model_names"])
        ws = array(doc["weights"])
        if ws.dtype.kind in "iuf": ws = ws.astype(np.float64)
        if (ws.shape != (len(selected),) or ws.dtype.kind not in "iuf" or not np.isfinite(ws).all()
                or np.any(ws < 0) or not np.isclose(ws.sum(), 1, rtol=0, atol=1e-12)):
            raise PolicyError("finite nonnegative normalized model weights required")
        if (not finite_number(doc["threshold"]) or not 0 <= doc["threshold"] <= 1
                or doc["comparator"] != "strict_gt" or not isinstance(doc["missing_model_policy"], str)
                or doc["missing_model_policy"] not in {"require_all", "renormalize"}):
            raise PolicyError("explicit finite threshold/comparator/coverage policy required")
        cal = doc["calibrator"]
        if not isinstance(cal, dict):
            raise PolicyError("explicit calibrator required")
        if cal.get("method") == "identity":
            if set(cal) != {"method"}:
                raise PolicyError("identity calibrator has no fitted parameters")
        elif cal.get("method") == "platt_logit":
            if (set(cal) != {"method", "slope", "intercept", "epsilon"}
                    or any(not finite_number(cal[k]) for k in ("slope", "intercept", "epsilon"))
                    or cal["slope"] <= 0 or not 0 < cal["epsilon"] < .5):
                raise PolicyError("prefitted increasing platt_logit parameters required")
        else:
            raise PolicyError("unsupported probability calibrator")
        ws = np.frombuffer(ws.tobytes(), dtype=np.float64)
        object.__setattr__(self, "_raw", raw)
        object.__setattr__(self, "model_names", selected)
        object.__setattr__(self, "_weights", ws)
        object.__setattr__(self, "fingerprint", hashlib.sha256(raw).hexdigest())

    @property
    def document(self):
        return json.loads(self._raw)

    def calibrate(self, scores):
        values = array(scores)
        if values.dtype.kind not in "iuf" or not np.isfinite(values).all() or np.any(values < 0) or np.any(values > 1):
            raise PolicyError("calibration input must be finite probabilities")
        values = values.astype(np.float64)
        cal = self.document["calibrator"]
        if cal["method"] == "identity":
            return values
        clipped = np.clip(values, cal["epsilon"], 1-cal["epsilon"])
        with np.errstate(over="ignore", divide="ignore"):
            logits = cal["slope"] * (np.log(clipped) - np.log1p(-clipped)) + cal["intercept"]
        return np.exp(-np.logaddexp(0, -logits))

    def evaluate(self, scores, *, model_names, statuses=None, sample_ids=None):
        columns = names(model_names)
        values = array(scores)
        states = array(statuses)
        if (values.ndim != 2 or values.shape[1] != len(columns) or values.shape[0] == 0
                or values.dtype.kind not in "iuf" or states.shape != values.shape
                or states.dtype.kind not in "US" or not set(states.reshape(-1).tolist()).issubset(STATUSES)):
            raise PolicyError("aligned nonempty score matrix and explicit model statuses required")
        count = len(values)
        if sample_ids is None:
            ids = tuple(str(i) for i in range(count))
        else:
            candidate = array(sample_ids)
            if (candidate.shape != (count,) or candidate.dtype.kind != "U"
                    or any(not sid for sid in candidate.tolist()) or len(set(candidate.tolist())) != count):
                raise PolicyError("unique row-aligned sample IDs required")
            ids = tuple(candidate.tolist())
        lookup = {n:k for k,n in enumerate(columns)}
        values = values.astype(np.float64)
        selected_values = np.zeros((count, len(self.model_names)), np.float64)
        available = np.zeros_like(selected_values, dtype=bool)
        reasons = {n:["missing_model_column"]*count for n in self.model_names}
        for j, name in enumerate(self.model_names):
            if name not in lookup:
                continue
            k = lookup[name]
            ok = states[:,k] == "ok"
            real = values[ok,k]
            if not np.isfinite(real).all() or np.any(real < 0) or np.any(real > 1):
                raise PolicyError("invalid probability marked ok: " + name)
            selected_values[ok,j] = real
            available[:,j] = ok
            reasons[name] = states[:,k].tolist()
        weights = available * self._weights[None,:]
        totals = weights.sum(axis=1)
        doc = self.document
        complete = available.all(axis=1)
        usable = totals > 0
        if doc["missing_model_policy"] == "require_all":
            usable &= complete
        normalized = np.zeros_like(weights)
        normalized[usable] = weights[usable] / totals[usable,None]
        raw = np.full(count, np.nan, np.float64)
        calibrated = np.full(count, np.nan, np.float64)
        pred = np.full(count, -1, np.int32)  # explicit undecidable, never a benign vote
        raw[usable] = (selected_values[usable] * normalized[usable]).sum(axis=1)
        calibrated[usable] = self.calibrate(np.clip(raw[usable],0,1))
        pred[usable] = apply_threshold(calibrated[usable], doc["threshold"])
        rows = []
        for i, sid in enumerate(ids):
            excluded = {n:reasons[n][i] for j,n in enumerate(self.model_names) if not available[i,j]}
            excluded.update({n:"not_in_policy_allowlist" for n in columns if n not in self.model_names})
            observed = [n for j,n in enumerate(self.model_names) if available[i,j]]
            contributing = [n for j,n in enumerate(self.model_names) if normalized[i,j] > 0]
            rows.append(dict(sample_id=sid, status="ok" if usable[i] else "undecidable",
                             reason=None if usable[i] else "required_models_unavailable" if not complete[i] and doc["missing_model_policy"]=="require_all" else "no_positive_weight_models",
                             observed_models=observed, aggregated_models=contributing, excluded_models=excluded,
                             effective_weights={n:float(normalized[i,j]) for j,n in enumerate(self.model_names) if available[i,j]},
                             coverage=float(available[i].mean()), degraded=not bool(complete[i]),
                             missing_model_policy=doc["missing_model_policy"], threshold=doc["threshold"],
                             comparator=doc["comparator"], calibrator=doc["calibrator"],
                             calibration_profile_status="full_coverage_not_certified" if complete[i] else "unverified_renormalized_profile"))
        for output in (pred, calibrated, raw):
            output.setflags(write=False)
        return DecisionBatch(pred, calibrated, raw, tuple(rows), self.fingerprint)

    @classmethod
    def from_selection(cls, selection, threshold, *, missing_model_policy="require_all"):
        if (not isinstance(selection, dict) or not isinstance(threshold, dict)
                or selection.get("selection_role") != "model_val" or threshold.get("selection_role") != "calibration"):
            raise PolicyError("model_val weights and calibration threshold required")
        if not {"model_names", "weights"}.issubset(selection) or not {"calibrator", "threshold", "comparator"}.issubset(threshold):
            raise PolicyError("incomplete locked selection")
        cal = threshold["calibrator"]
        if not isinstance(cal, dict) or cal.get("method") != "identity":
            raise PolicyError("retrain selection currently supports identity calibration only")
        return cls(dict(schema_version=SCHEMA,model_names=selection["model_names"],weights=selection["weights"],
                        threshold=threshold["threshold"],comparator=threshold["comparator"],
                        calibrator={"method":"identity"},missing_model_policy=missing_model_policy))


def apply_threshold(scores, threshold, *, comparator="strict_gt"):
    """One strict threshold comparator for selection, offline and HTTP decisions."""
    values = array(scores)
    if (not finite_number(threshold) or not 0 <= threshold <= 1 or comparator != "strict_gt"
            or values.dtype.kind not in "iuf" or not np.isfinite(values).all()
            or np.any(values < 0) or np.any(values > 1)):
        raise PolicyError("finite probabilities and strict_gt threshold within [0,1] required")
    return (values.astype(np.float64) > threshold).astype(np.int32)


def for_ensemble(ensemble, *, weights=None):
    """Legacy ensembles use saved weights, strict >.5 and explicit partial coverage.

    A separately installed fixed policy cannot silently accept DSIR/other weights.
    """
    fixed = getattr(ensemble,"_decision_policy",None)
    registered = names(list(ensemble._model_names))
    if fixed is not None:
        if weights is not None:
            raise PolicyError("fixed policy forbids ad-hoc weight overrides")
        policy = fixed if isinstance(fixed,DecisionPolicy) else DecisionPolicy(fixed)
        if not set(policy.model_names).issubset(registered):
            raise PolicyError("policy refers to models outside ensemble registry")
        return policy
    source = weights if weights is not None else getattr(ensemble,"_weights",None)
    ws = np.ones(len(registered),np.float64) if source is None else array(source)
    if ws.dtype.kind in "iuf":
        ws = ws.astype(np.float64)
    if (ws.shape != (len(registered),) or ws.dtype.kind not in "iuf" or not np.isfinite(ws).all()
            or np.any(ws < 0) or not np.isfinite(ws.sum()) or ws.sum() <= 0):
        raise PolicyError("legacy ensemble weights must be finite, nonnegative and nonzero")
    ws = ws.astype(np.float64)/ws.sum()
    return DecisionPolicy(dict(schema_version=SCHEMA,model_names=list(registered),weights=ws.tolist(),threshold=.5,
                               comparator="strict_gt",calibrator={"method":"identity"},missing_model_policy="renormalize"))


def decide_records(ensemble, records):
    """Single-row HTTP adapter. Ignore unselected records, never invent a score."""
    if not isinstance(records,list) or not records:
        raise DecisionUnavailable("no_valid_model_predictions")
    columns = names(list(ensemble._model_names))
    by_name = {}
    for item in records:
        if not isinstance(item,dict) or "model" not in item or "status" not in item:
            raise PolicyError("model/status record required")
        if (not isinstance(item["model"], str) or item["model"] not in columns
                or not isinstance(item["status"], str) or item["status"] not in STATUSES):
            raise PolicyError("registered model and known status required")
        if item["model"] in by_name:
            raise PolicyError("duplicate model result")
        by_name[item["model"]] = item
    scores = np.full((1,len(columns)),np.nan,np.float64)
    states = np.full((1,len(columns)),"missing",dtype="U16")
    for k,name in enumerate(columns):
        item = by_name.get(name)
        if item is not None:
            states[0,k] = item["status"]
            if item["status"]=="ok":
                value = item.get("score")
                if not finite_number(value):
                    raise PolicyError("nonfinite/missing model probability")
                scores[0,k] = value
    policy = for_ensemble(ensemble)
    result = policy.evaluate(scores,model_names=list(columns),statuses=states).require_decidable()
    return policy,result
