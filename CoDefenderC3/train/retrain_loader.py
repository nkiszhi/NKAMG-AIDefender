"""Explicit split loader with content-bound features and aligned mmap matrices.

This is an opt-in retrain API, not a month-compatible loader. Feature extraction
is explicit and limited to the named role; get_split never starts extraction.
"""
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone, date
import csv
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import MappingProxyType
import numpy as np
try:
    from .retrain_contract import FeatureContract, ContractError, digest, SHA_RE
    from .retrain_cache import file_sha256, key_lock, atomic_json, read_features, write_features
except ImportError:
    from retrain_contract import FeatureContract, ContractError, digest, SHA_RE
    from retrain_cache import file_sha256, key_lock, atomic_json, read_features, write_features

SPLITS = ("train", "model_val", "calibration", "test")
DATA_CONTRACT = "retrain-four-split-v1"


class CoverageError(RuntimeError):
    def __init__(self, report):
        self.report = report
        super().__init__("feature coverage incomplete for %s: %d/%d" %
                         (report["split"], report["covered"], report["requested"]))


@dataclass(frozen=True)
class FeatureResult:
    status: str
    features: dict
    feature_fingerprint: str
    error: str = ""


@dataclass(frozen=True)
class SplitBatch:
    split: str
    views: dict
    labels: np.ndarray
    sample_ids: np.ndarray
    requested_ids: np.ndarray
    report: dict
    feature_fingerprint: str
    view_fingerprint: str
    matrix_fingerprint: str


class RetrainSplitLoader:
    def __init__(self, data_dir, *, contract=None, cache_dir=None):
        self.data_dir = Path(data_dir).resolve()
        if contract is None:
            contract = self.data_dir / "feature_contract.json"
        if isinstance(contract, (str, os.PathLike)):
            contract = json.loads(Path(contract).read_text(encoding="utf-8"))
        self.contract = contract if isinstance(contract, FeatureContract) else FeatureContract(contract)
        self.cache_dir = Path(cache_dir or self.data_dir / ".cache" / "retrain-splits-v1").resolve()
        self._samples = ()
        self._by_role = {}
        self._by_id = {}
        self._metadata = {}
        self._plan = {}
        self._loaded = False

    @property
    def samples(self):
        return self._samples

    @property
    def metadata(self):
        return json.loads(json.dumps(self._metadata))

    def load(self):
        try:
            return self._load_verified()
        except ContractError:
            raise
        except (OSError, ValueError, KeyError, TypeError) as error:
            raise ContractError("invalid materialized dataset provenance") from error

    def _load_verified(self):
        self._loaded = False
        meta = json.loads((self.data_dir / "metadata.json").read_text(encoding="utf-8"))
        if meta.get("split_contract") != DATA_CONTRACT:
            raise ContractError("explicit four-role dataset contract required")
        expected_files = {"verified_selection_manifest.csv": "selection_fingerprint",
                          "split_plan.json": "split_plan_fingerprint",
                          "path_audit.json": "path_audit_fingerprint"}
        for name, key in expected_files.items():
            if file_sha256(self.data_dir / name) != meta.get(key):
                raise ContractError("dataset provenance fingerprint mismatch: " + name)
        plan = json.loads((self.data_dir / "split_plan.json").read_text(encoding="utf-8"))
        audit = json.loads((self.data_dir / "path_audit.json").read_text(encoding="utf-8"))
        if (audit.get("build_allowed") is not True or audit["output"]["sha256"] != meta["selection_fingerprint"]
                or plan["outputs"]["selection"]["sha256"] != audit["input"]["sha256"]):
            raise ContractError("broken plan/selection/path-audit chain")
        with (self.data_dir / "verified_selection_manifest.csv").open(encoding="utf-8-sig", newline="") as f:
            verified = list(csv.DictReader(f))
        originals = {r["sample_id"]: r for r in verified}
        if len(originals) != len(verified):
            raise ContractError("duplicate verified selection identity")
        rows, seen, groups, counts = [], set(), {}, Counter()
        with (self.data_dir / "metadata.jsonl").open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                r = json.loads(line)
                sid, role, label = r.get("sample_id"), r.get("split"), r.get("label")
                if (not isinstance(sid, str) or not SHA_RE.fullmatch(sid) or r.get("sha256") != sid
                        or sid in seen or role not in SPLITS or type(label) is not int or label not in (0, 1)):
                    raise ContractError("invalid sample identity/role/label")
                original = originals.get(sid)
                if original is None:
                    raise ContractError("sample not in verified selection")
                for key in ("sha256", "split", "label", "group_id", "group_rule", "month", "timestamp",
                            "timestamp_kind", "size", "filetype", "source", "family", "ssdeep"):
                    if str(r.get(key, "")) != original.get(key, ""):
                        raise ContractError("metadata/verified selection mismatch: " + key)
                if r.get("path_status") != "verified" or r.get("exclusion_reason"):
                    raise ContractError("unverified or excluded sample")
                gid = r.get("group_id")
                if not isinstance(gid, str) or not gid or (gid in groups and groups[gid] != (role, label)):
                    raise ContractError("cross-role or invalid group")
                if type(r.get("size")) is not int or r["size"] <= 0:
                    raise ContractError("invalid sample size")
                if label == 1:
                    months = plan["train_months"] if role == "train" else [plan["test_month"]] if role == "test" else [plan["development_month"]]
                    if r["month"] not in months or date.fromisoformat(r["timestamp"]).isoformat()[:7] != r["month"]:
                        raise ContractError("temporal role violation")
                elif r["month"] or r["timestamp"] or r["timestamp_kind"] != "unavailable":
                    raise ContractError("benign collection time cannot become appearance time")
                p = Path(r.get("path", ""))
                if not str(r.get("path", "")) or p.is_absolute():
                    raise ContractError("materialized sample path must be relative")
                resolved = (self.data_dir / p).resolve()
                try:
                    resolved.relative_to(self.data_dir)
                except ValueError as error:
                    raise ContractError("sample path escapes dataset") from error
                record = dict(r, path=str(resolved))
                rows.append(MappingProxyType(record))
                seen.add(sid)
                groups[gid] = (role, label)
                counts[role, str(label)] += 1
        if audit.get("total") != len(rows) or audit.get("all_bytes_verified") is not True or audit.get("all_roles_have_both_labels") is not True:
            raise ContractError("incomplete path audit")
        if seen != set(originals) or not rows:
            raise ContractError("metadata and verified selection row sets differ")
        for role in SPLITS:
            for label in ("0", "1"):
                if counts[role, label] <= 0 or counts[role, label] != meta.get("counts", {}).get(role, {}).get(label):
                    raise ContractError("dataset role/count mismatch")
                if (audit.get("counts", {}).get(role + ":" + label) != counts[role, label]
                        or ("matched_counts" in plan and plan["matched_counts"].get(role + ":" + label) != counts[role, label])):
                    raise ContractError("audit/plan role/count mismatch")
        self._samples = tuple(sorted(rows, key=lambda r: r["sample_id"]))
        self._by_id = {r["sample_id"]: r for r in self._samples}
        self._by_role = {role: tuple(r for r in self._samples if r["split"] == role) for role in SPLITS}
        self._metadata, self._plan, self._loaded = meta, plan, True
        return self

    def _role(self, role):
        if not self._loaded:
            raise RuntimeError("load() must be called first")
        if role not in SPLITS:
            raise ContractError("explicit role required; month/range aliases are forbidden")
        return self._by_role[role]

    def split_ids(self, role):
        return tuple(r["sample_id"] for r in self._role(role))

    def _identity(self, sample):
        return {"schema": "retrain-sample-cache-v1", "content_sha256": sample["sha256"],
                "feature_fingerprint": self.contract.feature_fingerprint, "analysis_status": "ok"}

    def feature_cache_path(self, sample_id):
        sample = self._by_id.get(sample_id)
        if sample is None:
            raise ContractError("unknown sample")
        key = digest(self._identity(sample))
        return self.cache_dir / "features" / self.contract.feature_fingerprint / (key + ".npz")

    def _verify_source(self, sample):
        p = Path(sample["path"])
        if p.stat().st_size != sample["size"] or file_sha256(p) != sample["sha256"]:
            raise ContractError("sample bytes changed: " + sample["sample_id"])

    def _status(self, sample, status, error=""):
        value = dict(sample_id=sample["sample_id"], split=sample["split"], status=status, error=error,
                     feature_fingerprint=self.contract.feature_fingerprint,
                     time_utc=datetime.now(timezone.utc).isoformat())
        key = digest(self._identity(sample))
        atomic_json(self.cache_dir / "status" / self.contract.feature_fingerprint / (key + ".json"), value)
        return value

    def ensure_features(self, role, builder):
        """Explicitly extract only one role; cache failed statuses but never failure arrays."""
        statuses = []
        for sample in self._role(role):
            cache_path = self.feature_cache_path(sample["sample_id"])
            key = digest(self._identity(sample))
            with key_lock(self.cache_dir / "locks" / (key + ".lock")):
                snapshot = None
                try:
                    self._verify_source(sample)
                    try:
                        read_features(cache_path, self._identity(sample), self.contract)
                        statuses.append(self._status(sample, "cached"))
                        continue
                    except (FileNotFoundError, ContractError):
                        pass
                    # Analyze an immutable byte copy, not a path/mtime identity. Legacy
                    # SMDA report caches are therefore never reused across source edits.
                    snapshot_dir = self.cache_dir / "snapshots"
                    snapshot_dir.mkdir(parents=True, exist_ok=True)
                    fd, snapshot = tempfile.mkstemp(prefix=key + "-", dir=snapshot_dir)
                    os.close(fd)
                    shutil.copyfile(sample["path"], snapshot)
                    if file_sha256(snapshot) != sample["sha256"]:
                        raise ContractError("source changed while snapshotting")
                    result = builder(Path(snapshot), self.contract)
                    if not isinstance(result, FeatureResult) or result.feature_fingerprint != self.contract.feature_fingerprint:
                        raise ContractError("builder did not prove the requested feature contract")
                    if result.status not in {"ok", "timeout", "partial", "error"}:
                        raise ContractError("unknown analysis status")
                    if result.status != "ok":
                        statuses.append(self._status(sample, result.status, result.error))
                        continue
                    self._verify_source(sample)
                    if file_sha256(snapshot) != sample["sha256"]:
                        raise ContractError("snapshot changed during extraction")
                    write_features(cache_path, result.features, self._identity(sample), self.contract)
                    statuses.append(self._status(sample, "ok"))
                except Exception as error:
                    statuses.append(self._status(sample, "error", "%s: %s" % (type(error).__name__, error)))
                finally:
                    if snapshot is not None and os.path.exists(snapshot):
                        os.unlink(snapshot)
        return {"split": role, "requested": len(statuses), "successful": sum(s["status"] in {"ok", "cached"} for s in statuses), "statuses": statuses}

    def _failure_status(self, sample):
        key = digest(self._identity(sample))
        try:
            value = json.loads((self.cache_dir / "status" / self.contract.feature_fingerprint / (key + ".json")).read_text(encoding="utf-8"))
            if (value.get("sample_id") == sample["sample_id"]
                    and value.get("feature_fingerprint") == self.contract.feature_fingerprint
                    and value.get("status") in {"timeout", "partial", "error"}):
                return value["status"], value.get("error", "")
        except (OSError, ValueError, TypeError):
            pass
        return "missing", "no feature cache"

    def _collect(self, role, allow_partial):
        valid, failed = [], []
        samples = self._role(role)
        for sample in samples:
            try:
                self._verify_source(sample)
            except Exception as error:
                failed.append(dict(sample_id=sample["sample_id"], status="source_invalid", error=str(error)))
                continue
            try:
                _, payload = read_features(self.feature_cache_path(sample["sample_id"]), self._identity(sample), self.contract)
                valid.append((sample, payload))
            except FileNotFoundError:
                status, error = self._failure_status(sample)
                failed.append(dict(sample_id=sample["sample_id"], status=status, error=error))
            except ContractError as error:
                failed.append(dict(sample_id=sample["sample_id"], status="cache_invalid", error=str(error)))
        report = dict(split=role, requested=len(samples), covered=len(valid), excluded=len(failed),
                      coverage=len(valid) / len(samples), excluded_samples=failed,
                      requested_ids=[s["sample_id"] for s in samples],
                      included_ids=[s["sample_id"] for s, _ in valid])
        if failed and not allow_partial:
            raise CoverageError(report)
        return valid, report

    def _matrix_identity(self, role, names, valid, report):
        # Path-independent identity, with IDs/labels/groups/time and exact payloads.
        row_fields = ("sample_id", "label", "group_id", "group_rule", "month", "timestamp", "timestamp_kind", "source", "filetype", "size")
        return dict(schema="retrain-matrix-cache-v1", split=role,
                    view_fingerprint=self.contract.view_fingerprint(names), ordered_views=list(names),
                    members=[{k: s[k] for k in row_fields} for s in self._role(role)],
                    included=[{"sample_id": s["sample_id"], "payload_sha256": p} for s, p in valid],
                    excluded=report["excluded_samples"])

    def _read_matrix(self, folder, expected, names):
        try:
            pointer_text = (folder / "current.json").read_text(encoding="utf-8")
        except FileNotFoundError:
            raise
        try:
            pointer = json.loads(pointer_text)
            if pointer["identity"] != expected:
                raise ContractError("matrix identity mismatch")
            generation = folder / pointer["generation"]
            if generation.resolve().parent != folder.resolve() or not generation.name.startswith("build-"):
                raise ContractError("invalid matrix generation path")
            count = len(expected["included"])
            wanted = {"labels": (np.dtype("int32"), (count,)),
                      "sample_ids": (np.dtype("U64"), (count,)),
                      "requested_ids": (np.dtype("U64"), (len(expected["members"]),))}
            for i, name in enumerate(names):
                wanted["v%03d" % i] = (np.dtype(self.contract.view_spec(name)["dtype"]), (count, self.contract.view_dimension(name)))
            if set(pointer["files"]) != set(wanted):
                raise ContractError("matrix file set mismatch")
            loaded = {}
            for key, (dtype, shape) in wanted.items():
                file = generation / (key + ".npy")
                if file_sha256(file) != pointer["files"][key]:
                    raise ContractError("matrix payload checksum mismatch: " + key)
                arr = np.load(file, allow_pickle=False, mmap_mode="r")
                if arr.shape != shape or arr.dtype != dtype:
                    raise ContractError("matrix shape/dtype mismatch: " + key)
                if dtype.kind in "iuf":
                    flat = arr.reshape(-1)
                    for start in range(0, flat.size, 1 << 20):
                        if not np.isfinite(flat[start:start + (1 << 20)]).all():
                            raise ContractError("nonfinite matrix: " + key)
                loaded[key] = arr
            ids = [r["sample_id"] for r in expected["included"]]
            labels = {r["sample_id"]: r["label"] for r in expected["members"]}
            if (loaded["sample_ids"].tolist() != ids or loaded["labels"].tolist() != [labels[i] for i in ids]
                    or loaded["requested_ids"].tolist() != [r["sample_id"] for r in expected["members"]]):
                raise ContractError("matrix sample IDs/labels are misaligned")
            return loaded
        except FileNotFoundError as error:
            raise ContractError("published matrix generation is missing") from error
        except ContractError:
            raise
        except Exception as error:
            raise ContractError("invalid matrix cache envelope") from error

    def _write_matrix(self, folder, expected, names, valid):
        folder.mkdir(parents=True, exist_ok=True)
        generation = Path(tempfile.mkdtemp(prefix="build-", dir=folder))
        count = len(valid)
        maps = {}
        try:
            for i, name in enumerate(names):
                maps[name] = np.lib.format.open_memmap(generation / ("v%03d.npy" % i), mode="w+",
                    dtype=self.contract.view_spec(name)["dtype"], shape=(count, self.contract.view_dimension(name)))
            for index, (sample, payload) in enumerate(valid):
                self._verify_source(sample)
                arrays, actual = read_features(self.feature_cache_path(sample["sample_id"]), self._identity(sample), self.contract)
                if actual != payload:
                    raise ContractError("features changed while building matrix")
                rows = self.contract.transform(arrays, names)
                for name in names:
                    maps[name][index] = rows[name]
        finally:
            for arr in maps.values():
                arr.flush()
                arr._mmap.close()
            maps.clear()
        np.save(generation / "labels.npy", np.asarray([s["label"] for s, _ in valid], dtype=np.int32), allow_pickle=False)
        np.save(generation / "sample_ids.npy", np.asarray([s["sample_id"] for s, _ in valid], dtype="U64"), allow_pickle=False)
        np.save(generation / "requested_ids.npy", np.asarray([s["sample_id"] for s in self._role(expected["split"])], dtype="U64"), allow_pickle=False)
        files = {p.stem: file_sha256(p) for p in generation.glob("*.npy")}
        # Publish one atomic pointer last. Incomplete/old generations remain inert;
        # no recursive delete and no partially-written month matrices are reused.
        atomic_json(folder / "current.json", dict(identity=expected, generation=generation.name, files=files))

    def get_split(self, role, views=None, *, allow_partial=False):
        names = self.contract.select_views(views)
        valid, report = self._collect(role, allow_partial)
        identity = self._matrix_identity(role, names, valid, report)
        key = digest(identity)
        folder = self.cache_dir / "matrices" / key
        with key_lock(self.cache_dir / "locks" / (key + ".lock")):
            try:
                data = self._read_matrix(folder, identity, names)
            except FileNotFoundError:
                self._write_matrix(folder, identity, names, valid)
                data = self._read_matrix(folder, identity, names)
        return SplitBatch(role, {name: data["v%03d" % i] for i, name in enumerate(names)},
                          data["labels"], data["sample_ids"], data["requested_ids"], report,
                          self.contract.feature_fingerprint, self.contract.view_fingerprint(names), key)
