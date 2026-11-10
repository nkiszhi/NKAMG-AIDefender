"""Shared safe preparation; test_lm single/directory business policy.

All three HTTP contracts use engine.app's one model registry and ScanRuntime.
D/E analysis is disposable; MalGraph input is produced only by main's worker.
"""
from __future__ import annotations

import os
import statistics
import subprocess
import tempfile
import time
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException
from engine import prediction_policy as policy
from engine.naming import name_for_hash_hit
from engine.staged_scan import analysis_timeout, isolated_analysis


def _prepare_sample(core, pe_path, ens, expected, include_de):
    if not core._is_valid_pe(pe_path):
        raise ValueError("invalid or damaged PE file")
    started = time.monotonic()
    features = core._get_extractor().extract_fast(pe_path)
    malgraph_sample = None
    analysis_error = None
    slow_views = {view for view in ens.view_groups
                  if any(fid.startswith(("D", "E")) for fid in
                         core.config.VIEW_GROUPS.get(view, {}).get("binja_features", []))}
    needs_analysis = slow_views or "MalGraph" in ens._model_names
    if include_de and needs_analysis:
        # {} is main's explicit failure sentinel: never silently analyse twice.
        malgraph_sample = {}
        try:
            analysis = isolated_analysis(pe_path, analysis_timeout())
            features = dict(features, **analysis["features"])
            malgraph_sample = analysis.get("malgraph") or {}
        except Exception as exc:
            analysis_error = ("timeout" if isinstance(exc, subprocess.TimeoutExpired) else "error", str(exc))
    views, meta = core._extract_views_for_single_sample(
        pe_path, list(ens.view_groups), include_de, expected, extracted_features=features,
    )
    # Do not feed partial concatenations/padded rows to a model as a valid view.
    for view in list(views):
        reason = meta.get(view, {}).get("reason", "")
        if "partial_binja_features_missing:" in reason:
            views.pop(view)
    return views, meta, malgraph_sample, analysis_error, slow_views, time.monotonic() - started


def _hash_result(hit, names):
    result = deepcopy(hit)
    if names:
        result.setdefault("ScanResult", {})["VirusName"] = name_for_hash_hit()
    return result


def _error_result(path, exc):
    timeout = isinstance(exc, (TimeoutError, subprocess.TimeoutExpired))
    return {"FileName": os.path.basename(path), "FilePath": path,
            "Status": -1, "StatusLabel": "Timeout" if timeout else "Error",
            "IsMalicious": False, "Error": str(exc)}


def scan_paths(core, paths, ens, expected, include_de, formatter):
    """Bound memory, extract real rows, batch by shape, and retry failed rows."""
    chunk_size = max(1, min(64, int(os.environ.get("CODEFENDER_BATCH_SIZE", "16"))))
    workers = max(1, min(8, int(os.environ.get("CODEFENDER_BATCH_EXTRACT_WORKERS", "1"))))
    results = []
    for offset in range(0, len(paths), chunk_size):
        chunk = paths[offset:offset + chunk_size]
        prepared, errors = {}, {}
        def prepare(index):
            try:
                return index, _prepare_sample(core, chunk[index], ens, expected, include_de), None
            except Exception as exc:
                return index, None, exc
        with ThreadPoolExecutor(max_workers=workers) as executor:
            for index, sample, error in executor.map(prepare, range(len(chunk))):
                if error is not None:
                    errors[index] = error
                else:
                    prepared[index] = sample
        sample_views = {index: sample[:2] for index, sample in prepared.items()}
        mg_samples = {index: sample[2] for index, sample in prepared.items()}
        inference_started = time.monotonic()
        per_sample = policy._predict_per_model_batch(
            core, ens, sample_views, chunk, include_de, malgraph_samples=mg_samples,
        ) if sample_views else {}
        inference_share = (time.monotonic() - inference_started) / max(1, len(prepared))
        for index, pe_path in enumerate(chunk):
            if index in errors:
                result = _error_result(pe_path, errors[index])
            else:
                sample = prepared[index]
                per_model = per_sample.get(index, [])
                if sample[3]:
                    status, reason = sample[3]
                    for item in per_model:
                        if item.get("view") in sample[4] or item["model"] == "MalGraph":
                            item.update(status=status, reason=reason)
                            item.pop("score", None)
                            item.pop("prediction", None)
                try:
                    if per_model and all(item.get("status") != "ok" for item in per_model) and sample[3] and sample[3][0] == "timeout":
                        raise TimeoutError("analysis_timeout: no valid model predictions")
                    format_started = time.monotonic()
                    result = policy._format_model_result(
                        core, pe_path, os.path.basename(pe_path), os.path.getsize(pe_path),
                        ens, per_model, formatter,
                    )
                    result["FilePath"] = pe_path
                    result["ProcessingTime"] = round(sample[5] + inference_share + time.monotonic() - format_started, 3)
                    result["TimingMethod"] = "feature_time_plus_shared_batch_forward_and_format"
                except Exception as exc:
                    result = _error_result(pe_path, exc)
            results.append(result)
    return results


def scan_upload(core, content, filename, include_de, formatter):
    hit = core._hash_precheck(content, filename, len(content))
    if hit is not None:
        return _hash_result(hit, names=True)
    ens = core._load_ensemble()
    expected = core._infer_expected_view_dims(ens)
    # Runtime worker owns this directory, including after HTTP timeout/disconnect.
    with tempfile.TemporaryDirectory(prefix="aidefender-contract-") as directory:
        pe_path = os.path.join(directory, "sample.bin")
        with open(pe_path, "wb") as handle:
            handle.write(content)
        if not core._is_valid_pe(pe_path):
            raise ValueError("invalid or damaged PE file")
        result = scan_paths(core, [pe_path], ens, expected, include_de, formatter)[0]
        if result.get("Status") == -1:
            if result.get("StatusLabel") == "Timeout":
                raise HTTPException(504, detail=result["Error"])
            raise RuntimeError(result["Error"])
        result["FileName"] = filename
        result.pop("FilePath", None)
        result.pop("ProcessingTime", None)
        result.pop("TimingMethod", None)
        return result


def scan_directory(core, directory, recursive, include_de, formatter, names=True):
    started = time.monotonic()
    if not os.path.isdir(directory):
        raise HTTPException(400, detail=f"directory not found: {directory}")
    all_files, pe_files = [], []
    for dirname, dirs, files in os.walk(directory):
        dirs.sort()
        for filename in sorted(files):
            pe_path = os.path.join(dirname, filename)
            all_files.append(pe_path)
            if core._is_valid_pe(pe_path):
                pe_files.append(pe_path)
                if len(pe_files) > core.MAX_BATCH_FILES:
                    raise HTTPException(400, detail=f"too many files: > {core.MAX_BATCH_FILES}")
        if not recursive:
            break
    if not all_files:
        raise HTTPException(404, detail="no files found in directory")
    if not pe_files:
        raise HTTPException(404, detail=f"no PE files found in directory (scanned {len(all_files)} files)")
    hits, remaining = [], []
    for pe_path in pe_files:
        hit = core._hash_precheck_file(pe_path)
        if hit is None:
            remaining.append(pe_path)
        else:
            result = _hash_result(hit, names)
            result["FilePath"] = pe_path
            hits.append(result)
    load_start = time.monotonic()
    if remaining:
        ens = core._load_ensemble()
        expected = core._infer_expected_view_dims(ens)
    load_time = time.monotonic() - load_start
    batch_start = time.monotonic()
    results = hits + (scan_paths(core, remaining, ens, expected, include_de, formatter) if remaining else [])
    batch_time = time.monotonic() - batch_start
    successful = [item for item in results if item.get("Status") != -1]
    failed = [item for item in results if item.get("Status") == -1]
    timeouts = sum(item.get("StatusLabel") == "Timeout" for item in failed)
    malicious = sum(bool(item.get("IsMalicious")) for item in successful)
    times = [item["ProcessingTime"] for item in successful if "ProcessingTime" in item]
    elapsed = time.monotonic() - started
    with core._METRICS_LOCK:
        core._METRICS["predict_dir_ok"] += 1
        core._METRICS["scan_files_total"] += len(pe_files)
        core._METRICS["scan_files_malicious"] += malicious
        core._METRICS["scan_files_benign"] += len(successful) - malicious
        core._METRICS["last_predict_ms"] = round(elapsed * 1000, 1)
    return {"Summary": {
        "TotalFiles": len(pe_files), "TotalFilesInDirectory": len(all_files),
        "SkippedNonPE": len(all_files) - len(pe_files), "ScannedFiles": len(successful),
        "MaliciousCount": malicious, "BenignCount": len(successful) - malicious,
        # Keep main/dev separate counters. Production combines them only at its boundary.
        "ErrorCount": len(failed) - timeouts, "TimeoutCount": timeouts, "Directory": directory,
        "Timing": {"TotalTime": round(elapsed, 3), "ModelLoadTime": round(load_time, 3),
                   "BatchScanTime": round(batch_time, 3),
                   "AvgSampleTime": round(statistics.mean(times), 3) if times else 0.0,
                   "MedianSampleTime": round(statistics.median(times), 3) if times else 0.0,
                   "MinSampleTime": round(min(times), 3) if times else 0.0,
                   "MaxSampleTime": round(max(times), 3) if times else 0.0,
                   "Throughput": round(len(successful) / elapsed, 3) if elapsed else 0.0}},
        "Results": results}
