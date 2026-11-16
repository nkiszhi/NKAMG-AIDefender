"""Shared explicit input/layout contract for split caches and model runtimes.

No implicit environment masks, dimension inference, right-padding, or ProgramIR.
"""
import copy
import hashlib
import json
import re
import numpy as np

SCHEMA = "retrain-features-v1"
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


class ContractError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def numeric_dtype(value):
    if not isinstance(value, str) or not value:
        raise ContractError("explicit dtype string required")
    try:
        dtype = np.dtype(value)
    except (TypeError, ValueError) as error:
        raise ContractError("invalid dtype") from error
    if dtype.kind not in "iuf" or dtype.hasobject or dtype.fields or dtype.subdtype:
        raise ContractError("only plain integer/float dtypes are supported")
    return dtype


class FeatureContract:
    def __init__(self, document):
        try:
            d = json.loads(canonical(document))
        except (ValueError, TypeError) as error:
            raise ContractError("contract must be finite JSON") from error
        if not isinstance(d, dict) or set(d) != {"schema_version", "backend", "extractor", "features", "views"} or d["schema_version"] != SCHEMA:
            raise ContractError("unknown or incomplete feature contract")
        backend, extractor = d["backend"], d["extractor"]
        if not isinstance(backend, dict) or set(backend) != {"name", "version", "config"}:
            raise ContractError("backend requires name/version/config")
        if not all(isinstance(backend[k], str) and backend[k] for k in ("name", "version")) or not isinstance(backend["config"], dict):
            raise ContractError("invalid backend identity")
        if not isinstance(extractor, dict) or set(extractor) != {"revision", "packages"}:
            raise ContractError("extractor requires revision/packages")
        if not isinstance(extractor["revision"], str) or not SHA_RE.fullmatch(extractor["revision"]):
            raise ContractError("extractor revision must be a SHA256")
        if not isinstance(extractor["packages"], dict) or not all(isinstance(k, str) and k and isinstance(v, str) and v for k, v in extractor["packages"].items()):
            raise ContractError("packages must declare exact versions")
        features, views = d["features"], d["views"]
        if not isinstance(features, dict) or not features or not isinstance(views, dict) or not views:
            raise ContractError("nonempty features/views required")
        for name, spec in features.items():
            if not NAME_RE.fullmatch(name) or not isinstance(spec, dict) or set(spec) != {"shape", "dtype"}:
                raise ContractError("invalid feature spec: " + name)
            shape = spec["shape"]
            if not isinstance(shape, list) or not shape or any(type(n) is not int or n <= 0 for n in shape):
                raise ContractError("positive, fixed feature dimensions required")
            spec["dtype"] = numeric_dtype(spec["dtype"]).str
        for name, spec in views.items():
            if not NAME_RE.fullmatch(name) or not isinstance(spec, dict) or set(spec) != {"features", "dtype", "length", "masked_features"}:
                raise ContractError("view requires ordered features/dtype/length/masked_features")
            ids, masked = spec["features"], spec["masked_features"]
            if not isinstance(ids, list) or not ids or any(not isinstance(fid, str) for fid in ids) or len(ids) != len(set(ids)) or any(fid not in features for fid in ids):
                raise ContractError("invalid ordered feature list: " + name)
            if not isinstance(masked, list) or any(not isinstance(fid, str) for fid in masked) or len(masked) != len(set(masked)) or any(fid not in ids for fid in masked):
                raise ContractError("invalid explicit mask: " + name)
            size = sum(int(np.prod(features[fid]["shape"], dtype=object)) for fid in ids)
            length = spec["length"]
            if length is not None and (type(length) is not int or length <= 0 or length > size):
                raise ContractError("view length may truncate, never right-pad")
            spec["dtype"] = numeric_dtype(spec["dtype"]).str
        self._document = d
        self._bytes = canonical(d)
        self.fingerprint = hashlib.sha256(self._bytes).hexdigest()
        self.feature_fingerprint = digest({k: d[k] for k in ("schema_version", "backend", "extractor", "features")})

    @property
    def document(self):
        return copy.deepcopy(self._document)

    @property
    def view_names(self):
        return tuple(sorted(self._document["views"]))

    def select_views(self, names=None):
        names = list(self.view_names if names is None else names)
        if not names or any(not isinstance(n, str) for n in names) or len(names) != len(set(names)) or any(n not in self._document["views"] for n in names):
            raise ContractError("unknown, empty, or duplicate view request")
        return tuple(names)

    def view_fingerprint(self, names=None):
        names = self.select_views(names)
        return digest({"feature_fingerprint": self.feature_fingerprint,
                       "ordered_views": [{"name": n, **self._document["views"][n]} for n in names]})

    def view_spec(self, name):
        return copy.deepcopy(self._document["views"][name])

    def view_dimension(self, name):
        spec = self._document["views"][name]
        return spec["length"] or sum(int(np.prod(self._document["features"][f]["shape"], dtype=object)) for f in spec["features"])

    def validate_features(self, arrays):
        if not isinstance(arrays, dict):
            raise ContractError("feature dictionary required")
        if set(arrays) != set(self._document["features"]):
            raise ContractError("feature key set mismatch (missing features cannot become zeros)")
        for fid, spec in self._document["features"].items():
            try: arr = np.asarray(arrays[fid])
            except (TypeError, ValueError) as error:
                raise ContractError("regular feature array required: " + fid) from error
            if arr.shape != tuple(spec["shape"]) or arr.dtype.str != spec["dtype"]:
                raise ContractError("feature shape/dtype mismatch: " + fid)
            if not np.isfinite(arr).all():
                raise ContractError("nonfinite feature: " + fid)

    def validate_view(self, name, value, *, batch=False):
        """Validate frozen view bytes; never infer dimensions, pad or cast."""
        if name not in self.view_names:
            raise ContractError("unknown view")
        try: arr = np.asarray(value)
        except (TypeError, ValueError) as error:
            raise ContractError("regular input view required: " + name) from error
        spec = self.view_spec(name)
        dim = self.view_dimension(name)
        valid_shape = arr.ndim == 2 and arr.shape[0] > 0 and arr.shape[1] == dim if batch else arr.shape == (dim,)
        if not valid_shape or arr.dtype.str != spec["dtype"]:
            raise ContractError("view shape/dtype differs from frozen contract: " + name)
        flat = arr.reshape(-1)
        for start in range(0, arr.size, 1 << 20):
            if not np.isfinite(flat[start:start+(1 << 20)]).all():
                raise ContractError("nonfinite input view: " + name)
        offset = 0
        for fid in spec["features"]:
            size = min(int(np.prod(self._document["features"][fid]["shape"], dtype=object)), dim-offset)
            if size <= 0: break
            part = arr[:, offset:offset+size] if batch else arr[offset:offset+size]
            if fid in spec["masked_features"] and np.any(part != 0):
                raise ContractError("frozen masked feature is not zero: " + fid)
            offset += size
        return arr

    def transform(self, arrays, names=None):
        self.validate_features(arrays)
        result = {}
        for name in self.select_views(names):
            spec = self._document["views"][name]
            dtype = np.dtype(spec["dtype"])
            remaining = self.view_dimension(name)
            parts = []
            for fid in spec["features"]:
                if remaining == 0:
                    break
                part = np.asarray(arrays[fid]).reshape(-1)[:remaining]
                remaining -= part.size
                if fid in spec["masked_features"]:
                    part = np.zeros(part.size, dtype=dtype)
                else:
                    if dtype.kind in "iu" and not np.can_cast(part.dtype, dtype, casting="safe"):
                        bounds = np.iinfo(dtype)
                        # Python scalar comparisons stay exact at uint64/int64 limits.
                        # Cast each part before concatenation: NumPy's mixed signed/
                        # unsigned concatenation can otherwise round via float64.
                        low, high = part.min().item(), part.max().item()
                        if (low < int(bounds.min) or high > int(bounds.max)
                                or (part.dtype.kind == "f" and np.any(part != np.trunc(part)))):
                            raise ContractError("lossy integer view cast: " + name)
                    with np.errstate(over="ignore", invalid="ignore"):
                        part = part.astype(dtype)
                    if not np.isfinite(part).all():
                        raise ContractError("nonfinite transformed view: " + name)
                parts.append(part)
            result[name] = np.concatenate(parts)
        return result
