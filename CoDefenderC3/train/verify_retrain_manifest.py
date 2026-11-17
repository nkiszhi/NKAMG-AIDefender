"""Locate and verify selected PE bytes without executing samples (stdlib only)."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path
import struct
try:
    from .retrain_manifest import FIELDS, GROUP_RULE, SHA_RE, SPLITS, fingerprint, prepare_output, write_json
except ImportError:
    from retrain_manifest import FIELDS, GROUP_RULE, SHA_RE, SPLITS, fingerprint, prepare_output, write_json


def pe_header_type(path):
    """A bounded structural header check; not unpacking or malware execution."""
    with Path(path).open("rb") as f:
        size = f.seek(0, 2)
        f.seek(0)
        dos = f.read(64)
        if len(dos) < 64 or dos[:2] != b"MZ":
            raise ValueError("invalid_dos_header")
        offset = struct.unpack_from("<I", dos, 60)[0]
        if offset < 64 or offset + 26 > size:
            raise ValueError("invalid_pe_offset")
        f.seek(offset)
        header = f.read(26)
        if header[:4] != b"PE\0\0":
            raise ValueError("invalid_pe_signature")
        optional_size = struct.unpack_from("<H", header, 20)[0]
        if optional_size < 2 or offset + 24 + optional_size > size:
            raise ValueError("invalid_optional_header_size")
        characteristics = struct.unpack_from("<H", header, 22)[0]
        magic = struct.unpack_from("<H", header, 24)[0]
        bits = {0x10b: "32", 0x20b: "64"}.get(magic)
        if bits is None:
            raise ValueError("invalid_optional_header_magic")
        return ("dll" if characteristics & 0x2000 else "exe") + bits


def path_map(path):
    if path is None:
        return {}
    path = Path(path).resolve()
    result = {}
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not {"sha256", "path"}.issubset(reader.fieldnames or []):
            raise ValueError("path map requires sha256,path")
        for row in reader:
            sha = row["sha256"].strip().lower()
            p = Path(row["path"])
            p = (path.parent / p).resolve() if not p.is_absolute() else p.resolve()
            if not SHA_RE.fullmatch(sha) or (sha in result and result[sha] != p):
                raise ValueError("invalid or ambiguous path mapping: " + sha)
            result[sha] = p
    return result


def candidates(row, manifest, roots, mappings):
    sha = row["sha256"]
    options = []
    if sha in mappings:
        # Explicit mapping is authoritative: do not silently fall back if incorrect.
        return [mappings[sha]]
    raw = row.get("path", "")
    if raw:
        p = Path(raw)
        options.append(p if p.is_absolute() else manifest.parent / p)
    for root in roots:
        options.extend([root / sha, root / "samples" / sha,
                        root / ("malicious" if row["label"] == "1" else "benign") / sha,
                        root.joinpath(*sha[:5], sha), root / sha[:2] / sha[2:4] / sha])
    return list(dict.fromkeys(p.resolve() for p in options))


def verify(manifest, out, *, roots=(), mapping=None):
    manifest = Path(manifest).resolve()
    mappings = path_map(mapping)
    roots = [Path(r).resolve() for r in roots]
    seen = set()
    groups = {}
    counts, failures = Counter(), Counter()
    output = out / "verified_selection_manifest.csv"
    audit = out / "path_audit.csv"
    with manifest.open(encoding="utf-8-sig", newline="") as f, output.open("w", encoding="utf-8", newline="") as vf, audit.open("w", encoding="utf-8", newline="") as af:
        reader = csv.DictReader(f)
        if not set(FIELDS).issubset(reader.fieldnames or []):
            raise ValueError("selection manifest schema is incomplete")
        writer = csv.DictWriter(vf, fieldnames=FIELDS)
        aw = csv.DictWriter(af, fieldnames=["sample_id", "split", "status", "resolved_path", "details"])
        writer.writeheader()
        aw.writeheader()
        for row in reader:
            sha = row["sha256"]
            if (not SHA_RE.fullmatch(sha) or row["sample_id"] != sha or sha in seen
                    or row["split"] not in SPLITS or row["label"] not in {"0", "1"}
                    or row["exclusion_reason"] or row["group_rule"] != GROUP_RULE
                    or not row["group_id"]):
                raise ValueError("invalid/duplicate selection row: " + sha)
            if row["group_id"] in groups and groups[row["group_id"]] != row["split"]:
                raise ValueError("cross-split group: " + row["group_id"])
            groups[row["group_id"]] = row["split"]
            seen.add(sha)
            ps = candidates(row, manifest, roots, mappings)
            status, details, resolved = "missing", "No candidate file found", ""
            existing = [p for p in ps if p.is_file()]
            for p in existing:
                resolved = str(p)
                try:
                    if p.stat().st_size != int(row["size"]):
                        raise ValueError("size_mismatch")
                    ft = pe_header_type(p)
                    if ft != row["filetype"]:
                        raise ValueError("filetype_mismatch:" + ft)
                    if fingerprint(p) != sha:
                        raise ValueError("sha256_mismatch")
                    status, details = "verified", "SHA256, size, and PE header match"
                    row["parsed_filetype"] = ft
                    break
                except (OSError, ValueError) as error:
                    status, details = "invalid", str(error)
            row["resolved_path"] = resolved
            row["path_status"] = status
            counts[row["split"] + ":" + row["label"]] += 1
            if status != "verified":
                failures[status + ":" + details] += 1
            writer.writerow({k: row[k] for k in FIELDS})
            aw.writerow(dict(sample_id=sha, split=row["split"], status=status,
                             resolved_path=resolved, details=details))
    total = len(seen)
    valid_roles = all(counts[s + ":0"] > 0 and counts[s + ":1"] > 0 for s in SPLITS)
    report = dict(schema_version="retrain-path-audit-v1", input={"path": str(manifest), "sha256": fingerprint(manifest)},
                  total=total, counts=dict(counts), failure_counts=dict(failures),
                  all_bytes_verified=bool(total) and not failures, all_roles_have_both_labels=valid_roles,
                  build_allowed=bool(total) and not failures and valid_roles,
                  ready_for_training=False,
                  output={"path": str(output), "sha256": fingerprint(output)},
                  roots=[str(r) for r in roots],
                  path_map=None if mapping is None else {"path": str(Path(mapping).resolve()), "sha256": fingerprint(mapping)},
                  notes=["Byte/header verification does not validate labels or software lineage.",
                         "Verification never executes, loads, or unpacks PE samples."])
    write_json(out / "path_audit.json", report)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--sample-root", type=Path, action="append", default=[])
    p.add_argument("--path-map", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    out = prepare_output(args.out)
    report = verify(args.manifest, out, roots=args.sample_root, mapping=args.path_map)
    print(json.dumps(report, ensure_ascii=False), flush=True)
    return 0 if report["build_allowed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
