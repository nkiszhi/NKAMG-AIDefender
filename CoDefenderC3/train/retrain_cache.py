"""Content/schema-bound retrain cache primitives, separate from legacy BN/IR."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import numpy as np
try:
    from .retrain_contract import canonical, ContractError
except ImportError:
    from retrain_contract import canonical, ContractError


def file_sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def arrays_digest(arrays):
    h = hashlib.sha256()
    for name in sorted(arrays):
        arr = np.ascontiguousarray(arrays[name])
        if arr.dtype.hasobject:
            raise ContractError("object arrays are never accepted")
        h.update(canonical([name, arr.dtype.str, list(arr.shape)]))
        h.update(arr.tobytes())
    return h.hexdigest()


@contextmanager
def key_lock(path, timeout=30):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as f:
        f.seek(0, 2)
        if f.tell() == 0:
            f.write(b"0")
            f.flush()
        end = time.monotonic() + timeout
        while True:
            try:
                f.seek(0)
                if os.name == "nt":
                    import msvcrt
                    msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as error:
                if time.monotonic() >= end:
                    raise TimeoutError("cache key lock timed out") from error
                time.sleep(.05)
        try:
            yield
        finally:
            f.seek(0)
            if os.name == "nt":
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(canonical(value) + b"\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_features(path, identity, contract):
    try:
        with np.load(path, allow_pickle=False) as data:
            wanted = set(contract.document["features"]) | {"__identity__", "__payload_sha256__"}
            if set(data.files) != wanted or len(data.files) != len(wanted):
                raise ContractError("feature cache file set mismatch")
            if json.loads(str(data["__identity__"].item())) != identity:
                raise ContractError("feature cache identity mismatch")
            arrays = {k: data[k].copy() for k in data.files if not k.startswith("__")}
            payload = str(data["__payload_sha256__"].item())
        contract.validate_features(arrays)
        if arrays_digest(arrays) != payload:
            raise ContractError("feature payload checksum mismatch")
        return arrays, payload
    except FileNotFoundError:
        raise
    except ContractError:
        raise
    except Exception as error:
        raise ContractError("invalid feature cache envelope") from error


def write_features(path, arrays, identity, contract):
    contract.validate_features(arrays)
    if identity.get("analysis_status") != "ok":
        raise ContractError("failed/partial analyses cannot have a success cache")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".tmp-", suffix=".npz", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            np.savez_compressed(f, **arrays, __identity__=canonical(identity).decode(),
                                __payload_sha256__=arrays_digest(arrays))
            f.flush()
            os.fsync(f.fileno())
        read_features(tmp, identity, contract)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
