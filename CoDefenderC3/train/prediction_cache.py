"""Invocation-scoped legacy monthly prediction cache with explicit status provenance.

Not a split dataset cache or a reusable training/model artifact. Old status-less
caches are not trusted; every ensemble instance starts a fresh cache scope.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import uuid
import numpy as np
from engine.decision_policy import STATUSES
from train.retrain_cache import key_lock

SCHEMA = "legacy-status-prediction-cache-v1"


def scope(ensemble):
    value = getattr(ensemble, "_status_cache_scope", None)
    if value is None:
        value = uuid.uuid4().hex
        ensemble._status_cache_scope = value
    return {"scope": value, "model_names": list(ensemble._model_names),
            "model_types": [ensemble._model_types.get(n, "unknown") for n in ensemble._model_names]}


def paths(cache_dir, month):
    if not isinstance(month, (int, np.integer)) or isinstance(month, bool):
        raise ValueError("integer month required")
    return {key: Path(cache_dir)/f"m{int(month)}_{key}.npy" for key in ("preds", "scores", "y", "statuses")}


def sha(file):
    h = hashlib.sha256()
    with open(file, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()


def validate(arrays, model_names):
    p, s, y, st = (arrays[k] for k in ("preds", "scores", "y", "statuses"))
    if (y.ndim != 1 or not len(y) or y.dtype.kind not in "iu" or not set(y.tolist()).issubset({0,1})
            or p.shape != (len(y),len(model_names)) or s.shape != p.shape or st.shape != p.shape
            or p.dtype.kind not in "iuf" or s.dtype.kind not in "iuf" or st.dtype.kind != "U"
            or not set(st.reshape(-1).tolist()).issubset(STATUSES)
            or not np.isfinite(p).all() or not set(p.reshape(-1).tolist()).issubset({0,1})):
        raise ValueError("misaligned legacy prediction cache")
    ok = st == "ok"
    if (not np.isfinite(s[ok]).all() or np.any(s[ok]<0) or np.any(s[ok]>1)
            or not np.array_equal(p[ok], (s[ok]>.5).astype(p.dtype))):
        raise ValueError("invalid successful model cache rows")


def load(cache_dir, month, ensemble):
    paths(cache_dir, month)
    if not Path(cache_dir).is_dir(): return None
    with key_lock(Path(cache_dir)/f"m{int(month)}_status_cache.lock"):
        return _load(cache_dir, month, ensemble)


def _load(cache_dir, month, ensemble):
    files = paths(cache_dir,month)
    pointer = Path(cache_dir)/f"m{int(month)}_status_cache.json"
    try:
        meta = json.loads(pointer.read_text(encoding="utf-8"))
        if (set(meta) != {"schema_version", "identity", "files"} or meta["schema_version"] != SCHEMA
                or meta["identity"] != scope(ensemble) or set(meta["files"]) != set(files)):
            return None
        if any(sha(file) != meta["files"][key] for key,file in files.items()): return None
        arrays = {key: np.load(file,allow_pickle=False) for key,file in files.items()}
        validate(arrays,meta["identity"]["model_names"])
        return arrays
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        return None  # Explicit reprediction, never infer ok from a legacy score.


def publish(cache_dir, month, ensemble, *, preds, scores, y, statuses):
    # Serialize writers before replacing the four aligned arrays and final marker.
    paths(cache_dir, month)
    with key_lock(Path(cache_dir)/f"m{int(month)}_status_cache.lock"):
        return _publish(cache_dir, month, ensemble, preds=preds, scores=scores, y=y, statuses=statuses)


def _publish(cache_dir, month, ensemble, *, preds, scores, y, statuses):
    files = paths(cache_dir,month)
    arrays = dict(preds=np.asarray(preds),scores=np.asarray(scores),y=np.asarray(y),statuses=np.asarray(statuses))
    identity = scope(ensemble)
    validate(arrays,identity["model_names"])
    Path(cache_dir).mkdir(parents=True,exist_ok=True)
    for key,target in files.items():
        fd,tmp = tempfile.mkstemp(prefix=target.name+".tmp-",dir=target.parent)
        try:
            with os.fdopen(fd,"wb") as stream:
                np.save(stream,arrays[key],allow_pickle=False); stream.flush(); os.fsync(stream.fileno())
            os.replace(tmp,target)
        finally:
            if os.path.exists(tmp): os.unlink(tmp)
    pointer = Path(cache_dir)/f"m{int(month)}_status_cache.json"
    fd,tmp = tempfile.mkstemp(prefix=pointer.name+".tmp-",dir=pointer.parent)
    try:
        with os.fdopen(fd,"w",encoding="utf-8") as stream:
            json.dump(dict(schema_version=SCHEMA,identity=identity,files={k:sha(f) for k,f in files.items()}),stream,sort_keys=True,allow_nan=False)
            stream.flush(); os.fsync(stream.fileno())
        os.replace(tmp,pointer)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return files


def statuses(cache_dir, month, ensemble):
    arrays = load(cache_dir,month,ensemble)
    if arrays is None: raise ValueError("no verified status-aware prediction cache")
    return arrays["statuses"]
