"""Versioned, content-addressed candidate caches (not MalGraph caches).

Legacy path-MD5/bndb/npz entries are never accepted as IR hits. OS locks are
released on crash; independent temporary files are validated then replaced.
"""
from contextlib import contextmanager
import gzip
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import uuid
import warnings
import weakref
import zipfile
import zlib

import numpy as np
from .ir import ProgramIR, SCHEMA_VERSION
from .features_from_ir import all_features, validate_de_features

FEATURE_SCHEMA = "non-malgraph-de/1-main-fast-crc32"
CACHE_SCHEMA = "codefender-candidate-cache/1"
_LOCKS = weakref.WeakValueDictionary()
_LOCKS_GUARD = threading.Lock()


def enabled():
    return os.environ.get("CODEFENDER_NON_MALGRAPH_IR", "0").lower() in {"1", "true", "yes"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def content_sha256(path):
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def namespace():
    from .backend import current_backend, backend_version, analysis_config
    backend = current_backend()
    # Adapter revision is separate from IR format and numerical feature schema.
    return {"cache_schema": CACHE_SCHEMA, "backend": backend,
            "backend_version": backend_version(backend), "ir_schema": SCHEMA_VERSION,
            "profile": "features", "adapter_revision": "test-lm-main-safe/1",
            "analysis_config": analysis_config(backend)}


def identity(path, metadata=None, *, feature_schema=None):
    meta = dict(namespace() if metadata is None else metadata)
    if meta.get("profile") != "features":
        raise ValueError("only non-MalGraph features profile is supported")
    meta["content_sha256"] = content_sha256(path)
    if feature_schema is not None:
        meta["feature_schema"] = feature_schema
    return meta


@contextmanager
def key_lock(path, timeout=180):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCKS_GUARD:
        lock = _LOCKS.setdefault(str(path.resolve()), threading.RLock())
    with lock:
        # Never unlink a lock file: a waiter may already hold its inode.
        with open(path, "a+b") as handle:
            handle.seek(0, 2)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            deadline = time.monotonic() + timeout
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt
                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("candidate cache lock timed out")
                    time.sleep(0.05)
            try:
                yield
            finally:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def quarantine(path):
    path = Path(path)
    if path.exists():
        os.replace(path, path.with_name(path.name + ".corrupt-" + uuid.uuid4().hex))


def _atomic_bytes(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _arrays_digest(arrays):
    h = hashlib.sha256()
    for name in sorted(arrays):
        array = np.ascontiguousarray(arrays[name])
        if array.dtype.hasobject:
            raise ValueError("object arrays are not accepted in candidate caches")
        h.update(canonical([name, array.dtype.str, array.shape]))
        h.update(array.tobytes())
    return h.hexdigest()


def read_arrays(path, expected):
    with np.load(path, allow_pickle=False) as data:
        if json.loads(str(data["__identity__"].item())) != expected:
            raise ValueError("feature cache identity mismatch")
        arrays = {key: data[key].copy() for key in data.files if not key.startswith("__")}
        if str(data["__payload_sha256__"].item()) != _arrays_digest(arrays):
            raise ValueError("feature cache payload mismatch")
    validate_de_features(arrays)
    return arrays


def write_arrays(path, arrays, expected):
    """Caller holds the key lock. Never append/skip existing NPZ members."""
    validate_de_features(arrays)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".tmp-", suffix=".npz", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            np.savez_compressed(handle, **arrays,
                                __identity__=canonical(expected).decode("utf-8"),
                                __payload_sha256__=_arrays_digest(arrays))
            handle.flush()
            os.fsync(handle.fileno())
        read_arrays(tmp, expected)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class CandidateCache:
    def __init__(self, root=None):
        if os.environ.get("CODEFENDER_DE_CACHE"):
            warnings.warn("CODEFENDER_DE_CACHE is a legacy bndb setting; candidate IR uses a separate namespace")
        self.root = Path(root or os.environ.get("CODEFENDER_IR_CACHE_DIR") or
                         Path(__file__).resolve().parents[1] / ".cache" / "non-malgraph-ir-v1")

    def features(self, path, *, metadata=None, builder=None, feature_schema=FEATURE_SCHEMA):
        from .backend import build_ir_for_features
        ir_id = identity(path, metadata)
        feature_id = dict(ir_id, feature_schema=feature_schema)
        ir_key, feature_key = digest(ir_id), digest(feature_id)
        ir_path = self.root / "ir" / (ir_key + ".json.gz")
        feature_path = self.root / "features" / (feature_key + ".npz")
        # One content/config lock serializes both layers; no cross-layer deadlock.
        with key_lock(self.root / "locks" / (ir_key + ".lock")):
            if feature_path.exists():
                try:
                    return read_arrays(feature_path, feature_id)
                except (OSError, ValueError, KeyError, EOFError, zipfile.BadZipFile, zlib.error):
                    quarantine(feature_path)
            ir = None
            if ir_path.exists():
                try:
                    envelope = json.loads(gzip.decompress(ir_path.read_bytes()))
                    data = envelope["ir"]
                    if envelope["identity"] != ir_id or envelope["payload_sha256"] != digest(data):
                        raise ValueError("IR identity/payload mismatch")
                    if data.get("schema") != SCHEMA_VERSION:
                        raise ValueError("unknown IR schema")
                    ir = ProgramIR.from_dict(data)
                    ir.validate()
                    if ir.backend != ir_id["backend"] or ir.backend_version != ir_id["backend_version"]:
                        raise ValueError("IR backend/version mismatch")
                except (OSError, ValueError, KeyError, TypeError, IndexError, EOFError, zlib.error):
                    quarantine(ir_path)
                    ir = None
            if ir is None:
                ir = builder(path) if builder else build_ir_for_features(path, ir_id["backend"])
                ir.validate()
                if ir.backend != ir_id["backend"] or ir.backend_version != ir_id["backend_version"]:
                    raise ValueError("builder backend/version mismatch")
                # Empty/failed analyses never get a successful IR cache marker.
                features = all_features(ir)
                if content_sha256(path) != ir_id["content_sha256"]:
                    raise ValueError("sample changed during analysis")
                data = ir.to_dict()
                envelope = {"identity": ir_id, "ir": data, "payload_sha256": digest(data)}
                _atomic_bytes(ir_path, gzip.compress(canonical(envelope), mtime=0))
            else:
                features = all_features(ir)
            if content_sha256(path) != ir_id["content_sha256"]:
                raise ValueError("sample changed during feature extraction")
            write_arrays(feature_path, features, feature_id)
            return features
