"""Dependency-light, role-scoped selection for research training artifacts."""
import numpy as np
from engine.decision_policy import DecisionPolicy, PolicyError, apply_threshold
try:
    from .retrain_contract import ContractError
except ImportError:
    from retrain_contract import ContractError


def numeric_array(value):
    try:
        return np.asarray(value)
    except (TypeError, ValueError) as error:
        raise ContractError("regular numeric array required") from error


def labels(y):
    y = numeric_array(y)
    if y.ndim != 1 or y.size == 0 or y.dtype.kind not in "iu" or set(y.tolist()) != {0, 1}:
        raise ContractError("nonempty binary labels containing both classes required")
    return y


def probabilities(scores, count, models=1):
    scores = numeric_array(scores)
    wanted = (count,) if models == 1 else (count, models)
    if scores.shape != wanted or scores.dtype.kind not in "iuf" or not np.isfinite(scores).all():
        raise ContractError("missing, misaligned, or nonfinite model scores")
    if np.any(scores < 0) or np.any(scores > 1):
        raise ContractError("model probabilities must be within [0,1]")
    return scores.astype(np.float64)


def auc(y, scores):
    y = labels(y)
    scores = probabilities(scores, len(y))
    order = np.argsort(scores, kind="stable")
    ranked = scores[order]
    ranks = np.empty(len(y), np.float64)
    start = 0
    while start < len(y):
        end = start + 1
        while end < len(y) and ranked[end] == ranked[start]:
            end += 1
        ranks[order[start:end]] = (start + 1 + end) / 2
        start = end
    pos = int((y == 1).sum())
    neg = len(y) - pos
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def select_weights(role, y, scores, model_names, method):
    if role != "model_val":
        raise ContractError("weights can only be selected on model_val")
    y = labels(y)
    if not model_names or len(set(model_names)) != len(model_names) or method not in {"equal", "auc"}:
        raise ContractError("explicit models and equal/auc weighting required")
    scores = numeric_array(scores)
    if scores.shape != (len(y), len(model_names)):
        raise ContractError("model score columns are misaligned")
    per_model = [auc(y, scores[:, k]) for k in range(len(model_names))]
    weights = np.ones(len(model_names), np.float64)
    fallback = False
    if method == "auc":
        weights = np.maximum(np.asarray(per_model) - .5, 0) ** 2
        if weights.sum() <= 0:
            weights[:] = 1
            fallback = True
    weights /= weights.sum()
    return dict(selection_role=role, method=method, model_names=list(model_names),
                weights=weights.tolist(), model_val_auc=dict(zip(model_names, per_model)),
                equal_fallback=fallback)


def aggregate(scores, selection):
    """The same strict name/weight/coverage decision math as runtime."""
    try:
        policy = DecisionPolicy.from_selection(selection, dict(
            selection_role="calibration", threshold=.5, comparator="strict_gt",
            calibrator={"method": "identity"}))
        values = numeric_array(scores)
        statuses = np.full(values.shape, "ok", dtype="U16")
        return policy.evaluate(values, model_names=list(policy.model_names),
                               statuses=statuses).require_decidable().scores
    except (PolicyError, KeyError, TypeError, ValueError) as error:
        raise ContractError("invalid locked model weights, columns or scores") from error


def threshold_metrics(y, scores, threshold):
    y = labels(y)
    scores = probabilities(scores, len(y))
    if type(threshold) not in (int, float) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ContractError("finite threshold within [0,1] required")
    pred = apply_threshold(scores, threshold).astype(bool)
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    return dict(threshold=float(threshold), tp=tp, fp=fp, fn=fn, tn=tn,
                f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0.,
                fpr=fp/(fp+tn), recall=tp/(tp+fn), accuracy=(tp+tn)/len(y))


def select_threshold(role, y, scores, grid):
    if role != "calibration":
        raise ContractError("threshold selection is restricted to calibration")
    if (not isinstance(grid, (list, tuple)) or not grid
            or any(type(t) not in (int, float) or not np.isfinite(t) or not 0 <= t <= 1 for t in grid)
            or len(grid) != len(set(grid))):
        raise ContractError("a predeclared unique threshold grid is required")
    rows = [threshold_metrics(y, scores, t) for t in sorted(grid)]
    # Predeclared deterministic tie break: F1, then fewer FP, then larger threshold.
    best = max(rows, key=lambda r: (r["f1"], -r["fp"], r["threshold"]))
    return dict(selection_role=role, objective="f1_then_fewer_fp_then_higher_threshold",
                comparator="strict_gt", threshold=best["threshold"], selected=best, sweep=rows,
                calibrator={"method": "identity", "probability_fit_performed": False},
                note="threshold tuning only; no probability-calibration or low-FPR certification claim")
