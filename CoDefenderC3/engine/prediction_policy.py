"""test_lm real-row batching/aggregation, bound to the protected main core.

No model loaders, IR graph adapters, independent pools or CUDA copies here.
"""
from __future__ import annotations
from typing import Any, Callable, Dict, List, Optional, Tuple
import numpy as np

def _infer_model_scores(
    core,
    ens: MultiModelEnsemble,
    model_name: str,
    rows: np.ndarray,
) -> np.ndarray:
    """Shared single/batch forward pass; return one float32 score per real row."""
    torch = core.torch
    model = ens._models[model_name]
    mtype = ens._model_types.get(model_name, "unknown")
    if mtype == "numpy":
        proba = model.predict_proba(np.asarray(rows, dtype=np.float32))
        scores = np.asarray(proba)[:, 1]
    elif mtype == "pytorch":
        if torch is None:
            raise RuntimeError("torch is not available")
        x_dtype = torch.long if core._input_dtype(model_name) == "long" else torch.float32
        x_t = torch.tensor(rows, dtype=x_dtype)
        try:
            device = next(model.parameters()).device
        except StopIteration:
            device = torch.device("cpu")
        model.eval()
        dim = rows.shape[1]
        batch_size = (16 if dim > 100000 else 32 if dim > 10000 else
                      64 if dim > 2000 else 256 if dim > 500 else 512)
        chunks = []
        with torch.no_grad():
            for start in range(0, len(rows), batch_size):
                out = model(x_t[start:start + batch_size].to(device))
                if isinstance(out, tuple):
                    out = out[0]
                score = (out.squeeze(-1) if out.shape[-1] == 1 else
                         torch.softmax(out, dim=1)[:, 1])
                chunks.append(score.detach().cpu().numpy().reshape(-1))
        scores = np.concatenate(chunks)
    else:
        raise RuntimeError(f"unsupported engine: {mtype}")
    scores = np.asarray(scores, dtype=np.float32).reshape(-1)
    if len(scores) != len(rows):
        raise ValueError(f"invalid score count: {len(scores)} != {len(rows)}")
    return scores


def _predict_per_model_batch(
    core,
    ens: MultiModelEnsemble,
    sample_views: Dict[int, Tuple[Dict[str, np.ndarray], Dict[str, Dict[str, Any]]]],
    pe_paths: List[Optional[str]],
    include_de: bool,
    malgraph_samples: Optional[Dict[int, Dict[str, Any]]] = None,
    on_result: Optional[Callable[[int, Dict[str, Any]], None]] = None,
) -> Dict[int, List[Dict[str, Any]]]:
    """Batch only real feature rows, keeping per-sample success/error records.

    A missing view never gets a zero-filled row. A failed batch forward pass is
    retried per row so one bad sample cannot suppress the model for its peers.
    MalGraph uses the same special pipeline and inclusion rules in both APIs.
    """
    results: Dict[int, List[Dict[str, Any]]] = {idx: [] for idx in sample_views}
    registered = set(ens._model_names)

    def emit(idx: int, item: Dict[str, Any]) -> None:
        results[idx].append(item)
        if on_result is not None:
            on_result(idx, item)

    def emit_score(idx: int, item: Dict[str, Any], score: float) -> None:
        score = float(np.float32(score))
        if not np.isfinite(score):
            item.update(status="error", reason="non_finite_score")
        else:
            item.update(status="ok", score=score, prediction=int(score > 0.5))
        emit(idx, item)

    for vname, model_names in ens.view_groups.items():
        for mname in model_names:
            if mname not in registered:
                continue
            model = ens._models.get(mname)
            mtype = ens._model_types.get(mname, "unknown")
            pending: List[Tuple[int, Dict[str, Any], np.ndarray]] = []
            for idx in sorted(sample_views):
                views, view_meta = sample_views[idx]
                item: Dict[str, Any] = {"model": mname, "view": vname, "engine": mtype}
                if mtype == "special":
                    if mname != "MalGraph":
                        item.update(status="skipped", reason="special_pipeline_not_supported")
                    elif not include_de:
                        item.update(status="skipped", reason="MalGraph requires D/E features; set include_de=true")
                    elif not pe_paths[idx]:
                        item.update(status="error", reason="missing pe_path for MalGraph inference")
                    else:
                        try:
                            sample = (malgraph_samples or {}).get(idx)
                            _, score, mg_meta = core._predict_malgraph_single(pe_paths[idx], sample=sample)
                            item["malgraph_meta"] = mg_meta
                            emit_score(idx, item, score)
                            continue
                        except Exception as exc:
                            item.update(status="unavailable", reason=str(exc))
                    emit(idx, item)
                    continue
                if mtype == "skip":
                    item.update(status="skipped", reason="model_pipeline_skipped")
                    emit(idx, item)
                    continue
                x_view = views.get(vname)
                if x_view is None:
                    reason = view_meta.get(vname, {}).get("reason", "missing_view_feature")
                    item.update(status="skipped", reason=f"missing_view_feature:{reason}")
                    emit(idx, item)
                    continue
                if model is None:
                    item.update(status="unavailable", reason="model_not_loaded")
                    emit(idx, item)
                    continue
                try:
                    expected = None if vname == "V1_byte" or vname.startswith("V8_") else core._expected_dim_for_model(ens, mname)
                    row, dim_note = core._coerce_row_dim(np.asarray(x_view).reshape(-1), expected)
                    if dim_note:
                        item["input_adjust"] = dim_note
                    pending.append((idx, item, row))
                except Exception as exc:
                    item.update(status="error", reason=str(exc))
                    emit(idx, item)

            # Models without a fixed input dimension may receive differently
            # sized real rows. Keep such rows in separate, compatible batches.
            groups: Dict[int, List[Tuple[int, Dict[str, Any], np.ndarray]]] = {}
            for entry in pending:
                groups.setdefault(len(entry[2]), []).append(entry)
            for entries in groups.values():
                rows = np.vstack([entry[2] for entry in entries])
                try:
                    scores = _infer_model_scores(core, ens, mname, rows)
                except Exception as exc:
                    if len(entries) == 1:
                        idx, item, _ = entries[0]
                        item.update(status="error", reason=str(exc))
                        emit(idx, item)
                        continue
                    # No 0.5 placeholder: record the real outcome of each retry.
                    for idx, item, row in entries:
                        try:
                            score = _infer_model_scores(core, ens, mname, row.reshape(1, -1))[0]
                            emit_score(idx, item, score)
                        except Exception as row_exc:
                            item.update(status="error", reason=str(row_exc))
                            emit(idx, item)
                else:
                    for (idx, item, _), score in zip(entries, scores):
                        emit_score(idx, item, score)
    return results


def _format_model_result(
    core,
    pe_path: str,
    file_name: str,
    file_size: int,
    ens: MultiModelEnsemble,
    per_model: List[Dict[str, Any]],
    formatter,
) -> Dict[str, Any]:
    """The sole aggregation/formatting policy for both development endpoints."""
    by_name = {item["model"]: item for item in per_model}
    ok_results = [by_name[name] for name in ens._model_names
                  if name in by_name and by_name[name].get("status") == "ok"]
    if not ok_results:
        raise RuntimeError("no_valid_model_predictions")
    model_names = [item["model"] for item in ok_results]
    scores_arr = np.asarray([item["score"] for item in ok_results], dtype=np.float32).reshape(1, -1)
    if not np.isfinite(scores_arr).all():
        raise ValueError("non_finite_model_scores")
    preds_arr = (scores_arr > 0.5).astype(np.int64)
    ens_score_arr = scores_arr.mean(axis=1)
    ens_pred_arr = (ens_score_arr > 0.5).astype(int)

    identifiers = core.compute_identifiers(pe_path)
    identifiers["FileName"] = file_name
    identifiers["FileSize"] = file_size
    from engine.packer_detector import detect_packer
    pack_info = detect_packer(pe_path)

    drift_ev = {
        "drift_evidence": np.zeros((1, 3)),
        "sample_drift_type": np.array(["none"], dtype=object),
        "anomaly_score": np.zeros(1),
        "is_drift_candidate": np.zeros(1, dtype=bool),
    }
    # SDD's baseline refers to registry column indices. Compact/partial model
    # matrices cannot be scored against it without inventing missing scores.
    if model_names == list(ens._model_names):
        try:
            drift_ev.update(core._get_sdd_engine().score_samples(scores_arr))
        except Exception:
            pass  # Existing fallback: drift evidence is optional, not a vote.

    total_models = len(per_model)
    ok_count = len(ok_results)
    skipped_count = sum(item.get("status") == "skipped" for item in per_model)
    malicious_votes = int(preds_arr.sum())
    model_stats = {
        "TotalModels": total_models,
        "OkModels": ok_count,
        "SkippedModels": skipped_count,
        "ErrorModels": total_models - ok_count - skipped_count,
        "MaliciousVotes": malicious_votes,
        "BenignVotes": ok_count - malicious_votes,
        "AgreementRate": round(malicious_votes / ok_count, 4),
        "EnsembleScore": round(float(ens_score_arr[0]), 6),
        "EnsemblePred": int(ens_pred_arr[0]),
        "ScoreRange": [round(float(scores_arr.min()), 4), round(float(scores_arr.max()), 4)],
        "AggregationMethod": "equal_weight_mean",
        "DecisionThreshold": 0.5,
        "AggregatedModels": model_names,
        "ExcludedModels": {item["model"]: item.get("reason", item.get("status"))
                           for item in per_model if item.get("status") != "ok"},
    }
    evidence = {
        "predictions": ens_pred_arr,
        "scores": ens_score_arr,
        "per_model_scores": scores_arr,
        "per_model_preds": preds_arr,
        "model_stats": model_stats,
        **drift_ev,
    }
    result = formatter(evidence, identifiers, pack_info, model_names)
    result["ScanResult"]["PerModelDetails"] = per_model
    return result
