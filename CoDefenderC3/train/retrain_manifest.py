"""Reproducible retrain manifest audit and selection (stdlib only).

No PE is executed. SQLite bounds memory for multi-million-row CSV inputs.
Exact ssdeep equality is a weak grouping rule, NOT a family similarity claim.
"""
import argparse
from collections import Counter
import csv
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sqlite3

SCHEMA_VERSION = "retrain-manifest-v1"
GROUP_RULE = "sha256+exact-ssdeep-v1"
SPLITS = ("train", "model_val", "calibration", "test")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
SSDEEP_RE = re.compile(r"^([0-9]+):[A-Za-z0-9+/]*:[A-Za-z0-9+/]*$")
FIELDS = ["sample_id", "sha256", "label", "split", "group_id", "group_rule",
          "filetype", "parsed_filetype", "size", "size_bucket", "timestamp",
          "timestamp_kind", "month", "source", "family", "ssdeep", "path",
          "resolved_path", "path_status", "label_provenance", "label_confidence",
          "manifest", "row_number", "exclusion_reason"]


def fingerprint(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def rank(seed, value):
    return hashlib.sha256((str(seed) + "\0" + value).encode()).hexdigest()


def valid_ssdeep(value):
    m = SSDEEP_RE.fullmatch(value)
    if not m:
        return False
    n = int(m[1])
    return n >= 3 and n % 3 == 0 and ((n // 3) & ((n // 3) - 1)) == 0


def size_bucket(n):
    for upper, name in [(65536, "0-64KiB"), (262144, "64-256KiB"),
                        (1048576, "256KiB-1MiB"), (4194304, "1-4MiB"),
                        (16777216, "4-16MiB")]:
        if n < upper:
            return name
    return "16MiB+"


def observation(row, label):
    # benign collection/update timestamps are deliberately NOT an appearance date.
    if label == 0:
        return "", "unavailable", ""
    raw = (row.get("date") or "").strip()
    kind = "manifest_date_unverified_semantics"
    if not raw:
        raw = (row.get("name") or "")[:10]
        kind = "name_date_prefix_unverified_semantics"
    try:
        value = date.fromisoformat(raw[:10]).isoformat()
        return value, kind, value[:7]
    except ValueError:
        return "", "invalid", ""


def normalize(row, label, manifest, row_number):
    sha = (row.get("sha256") or "").strip().lower()
    ft = (row.get("filetype") or "").strip().lower()
    ss = (row.get("ssdeep") or "").strip()
    errors = []
    if not SHA_RE.fullmatch(sha):
        errors.append("invalid_sha256")
    try:
        size = int(row.get("length", row.get("size", "")))
        if size <= 0:
            raise ValueError()
    except (ValueError, TypeError):
        size = 0
        errors.append("invalid_size")
    expected = (row.get("label") or "").strip().lower()
    allowed = {"0", "benign", "clean"} if label == 0 else {"1", "malicious", "malware"}
    if expected and expected not in allowed:
        errors.append("unexpected_label")
    ts, kind, month = observation(row, label)
    if label == 1 and not ts:
        errors.append("invalid_observation_date")
    gid = "ssdeep:" + hashlib.sha256(ss.encode()).hexdigest() if valid_ssdeep(ss) else "sha256:" + sha
    if ss and not valid_ssdeep(ss):
        errors.append("invalid_ssdeep")
    p = (row.get("path") or row.get("export_path") or row.get("src_path")
         or row.get("source_path") or "").strip()
    return dict(sha256=sha, label=label, size=size, filetype=ft,
                size_bucket=size_bucket(size), timestamp=ts, timestamp_kind=kind,
                month=month, source=(row.get("source") or row.get("dataset") or "unknown").strip(),
                family=(row.get("family") or "").strip(), ssdeep=ss, group_id=gid,
                path=p, manifest=manifest, row_number=row_number,
                invalid_reason=";".join(errors))


COLUMNS = ["sha256", "label", "size", "filetype", "size_bucket", "timestamp",
           "timestamp_kind", "month", "source", "family", "ssdeep", "group_id",
           "path", "manifest", "row_number", "invalid_reason"]


def open_db(path):
    db = sqlite3.connect(str(path))
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA cache_size=-65536")
    db.execute("PRAGMA temp_store=FILE")
    return db


def ingest(db, benign, malicious):
    db.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, sha256 TEXT, label INTEGER, "
               "size INTEGER, filetype TEXT, size_bucket TEXT, timestamp TEXT, timestamp_kind TEXT, "
               "month TEXT, source TEXT, family TEXT, ssdeep TEXT, group_id TEXT, path TEXT, "
               "manifest TEXT, row_number INTEGER, invalid_reason TEXT)")
    db.execute("CREATE TABLE inputs (path TEXT, label INTEGER, sha256 TEXT, rows INTEGER)")
    inputs = []
    stats = {str(label): {"rows": 0, "filetype": Counter(), "month": Counter(),
                         "source": Counter(), "timestamp_kind": Counter(),
                         "invalid_reason": Counter(), "ssdeep_nonempty": 0,
                         "ssdeep_valid": 0, "bytes": 0} for label in (0, 1)}
    csv.field_size_limit(16 << 20)
    for label, file in [(0, benign)] + [(1, p) for p in malicious]:
        p = Path(file).resolve()
        input_hash = fingerprint(p)
        count = 0
        batch = []
        with p.open(encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames or "sha256" not in reader.fieldnames:
                raise ValueError("missing sha256 column: " + str(p))
            for row_number, raw in enumerate(reader, 2):
                row = normalize(raw, label, str(p), row_number)
                batch.append(tuple(row[c] for c in COLUMNS))
                count += 1
                s = stats[str(label)]
                s["rows"] += 1
                s["bytes"] += row["size"]
                for name in ("filetype", "month", "source", "timestamp_kind"):
                    s[name][row[name] or "unavailable"] += 1
                for reason in row["invalid_reason"].split(";"):
                    if reason:
                        s["invalid_reason"][reason] += 1
                s["ssdeep_nonempty"] += bool(row["ssdeep"])
                s["ssdeep_valid"] += valid_ssdeep(row["ssdeep"])
                if len(batch) >= 5000:
                    db.executemany("INSERT INTO records (" + ",".join(COLUMNS) + ") VALUES (" + ",".join("?" for _ in COLUMNS) + ")", batch)
                    db.commit()
                    batch.clear()
            if batch:
                db.executemany("INSERT INTO records (" + ",".join(COLUMNS) + ") VALUES (" + ",".join("?" for _ in COLUMNS) + ")", batch)
        if fingerprint(p) != input_hash:
            raise ValueError("input changed during ingestion: " + str(p))
        item = {"path": str(p), "label": label, "sha256": input_hash, "rows": count}
        inputs.append(item)
        db.execute("INSERT INTO inputs VALUES (?,?,?,?)", tuple(item[c] for c in ("path", "label", "sha256", "rows")))
        db.commit()
        print(json.dumps({"event": "ingested", **item}), flush=True)
    print(json.dumps({"event": "indexing", "rows": sum(s["rows"] for s in stats.values())}), flush=True)
    db.execute("CREATE INDEX record_sha ON records(sha256)")
    db.execute("CREATE INDEX record_group ON records(group_id)")
    db.commit()
    def scalar(sql):
        return db.execute(sql).fetchone()[0]
    duplicates = {}
    for label in (0, 1):
        duplicates[str(label)] = {
            "unique_sha256": scalar("SELECT COUNT(DISTINCT sha256) FROM records WHERE label=%d AND invalid_reason=''" % label),
            "distinct_ssdeep": scalar("SELECT COUNT(DISTINCT ssdeep) FROM records WHERE label=%d AND ssdeep<>''" % label),
            "repeated_ssdeep_groups": scalar("SELECT COUNT(*) FROM (SELECT ssdeep FROM records WHERE label=%d AND ssdeep<>'' GROUP BY ssdeep HAVING COUNT(*)>1)" % label),
        }
    return dict(schema_version=SCHEMA_VERSION, inputs=inputs, by_label=stats,
                duplicates=duplicates,
                sha256_cross_label_groups=scalar("SELECT COUNT(*) FROM (SELECT sha256 FROM records GROUP BY sha256 HAVING MIN(label)<>MAX(label))"),
                ssdeep_cross_label_groups=scalar("SELECT COUNT(*) FROM (SELECT ssdeep FROM records WHERE ssdeep<>'' GROUP BY ssdeep HAVING MIN(label)<>MAX(label))"),
                malicious_cross_month_ssdeep_groups=scalar("SELECT COUNT(*) FROM (SELECT ssdeep FROM records WHERE label=1 AND ssdeep<>'' GROUP BY ssdeep HAVING COUNT(DISTINCT month)>1)"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def prepare_output(out):
    out = Path(out).resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError("output directory must be new or empty (no overwrite): " + str(out))
    out.mkdir(parents=True, exist_ok=True)
    return out


def record_manifest(row, split, reason=""):
    return dict(sample_id=row["sha256"], sha256=row["sha256"], label=row["label"],
                split=split, group_id=row["group_id"], group_rule=GROUP_RULE,
                filetype=row["filetype"], parsed_filetype="", size=row["size"],
                size_bucket=row["size_bucket"], timestamp=row["timestamp"],
                timestamp_kind=row["timestamp_kind"], month=row["month"], source=row["source"],
                family=row["family"], ssdeep=row["ssdeep"], path=row["path"], resolved_path="",
                path_status="unverified", label_provenance="input_manifest_label_unverified",
                label_confidence="unverified", manifest=row["manifest"], row_number=row["row_number"],
                exclusion_reason=reason)


def plan_selection(db, out, *, seed=20261113, train_months=("2026-01", "2026-02", "2026-03"),
                   development_month="2026-04", test_month="2026-05", max_bytes=16 << 20,
                   pair_cap=0, ood_source="Sophos-ReversingLabs"):
    train_months = tuple(sorted(set(train_months)))
    for month in train_months + (development_month, test_month):
        if not re.fullmatch(r"\d{4}-\d{2}", month):
            raise ValueError("month must be YYYY-MM")
        date.fromisoformat(month + "-01")
    if not train_months or max(train_months) >= development_month or development_month >= test_month:
        raise ValueError("train < development < test windows required")
    if max_bytes <= 0 or pair_cap < 0:
        raise ValueError("invalid size/budget")
    print(json.dumps({"event": "quarantining_conflicts"}), flush=True)
    # Quarantine conflicts before any split or subsampling. This includes ineligible rows.
    db.execute("CREATE TABLE quarantine_sha AS SELECT sha256 FROM records GROUP BY sha256 "
               "HAVING MIN(label)<>MAX(label) OR COUNT(DISTINCT group_id)>1 "
               "OR COUNT(DISTINCT size)>1 OR COUNT(DISTINCT filetype)>1")
    db.execute("CREATE UNIQUE INDEX quarantine_sha_index ON quarantine_sha(sha256)")
    db.execute("CREATE TABLE quarantine_group AS SELECT DISTINCT group_id FROM records WHERE sha256 IN (SELECT sha256 FROM quarantine_sha) "
               "UNION SELECT group_id FROM records GROUP BY group_id HAVING MIN(label)<>MAX(label)")
    db.execute("CREATE UNIQUE INDEX quarantine_group_index ON quarantine_group(group_id)")
    # Reserve all groups seen in the held-out source, including earlier main-source
    # members. Otherwise a source-OOD asset can silently contain training duplicates.
    db.execute("CREATE TABLE ood_groups AS SELECT DISTINCT group_id FROM records WHERE label=1 AND lower(source)=lower(?)", (ood_source,))
    db.execute("CREATE UNIQUE INDEX ood_group_index ON ood_groups(group_id)")
    db.execute("CREATE TABLE decisions (id INTEGER PRIMARY KEY, split TEXT, reason TEXT, rank TEXT)")
    # Rows sorted by weak group, then actual observation, so future records never migrate.
    query = "SELECT r.*, (q.group_id IS NOT NULL) AS quarantine, (o.group_id IS NOT NULL) AS ood_reserved FROM records r LEFT JOIN quarantine_group q USING(group_id) LEFT JOIN ood_groups o USING(group_id) ORDER BY r.group_id, r.timestamp, r.sha256, r.id"
    print(json.dumps({"event": "assigning_roles"}), flush=True)
    last_group = None
    first_window = None
    taken = set()
    batch = []
    for row in db.execute(query):
        if row["group_id"] != last_group:
            last_group = row["group_id"]
            first_window = None
            taken = set()
        split, reason = "excluded", ""
        raw_window = "train" if row["month"] in train_months else "development" if row["month"] == development_month else "test" if row["month"] == test_month else ""
        # A known earlier group remains known even if its earlier member is oversized
        # or has an unparsed filetype; matching/eligibility must not redefine novelty.
        if row["label"] == 1 and raw_window and first_window is None and row["source"].casefold() != ood_source.casefold():
            first_window = raw_window
        if row["quarantine"]:
            reason = "label_or_metadata_conflict_group"
        elif row["invalid_reason"]:
            reason = row["invalid_reason"]
        elif row["size"] > max_bytes:
            reason = "size_limit"
        elif row["source"].casefold() == ood_source.casefold() and row["label"] == 1:
            split = "source_ood"
        elif row["ood_reserved"]:
            reason = "group_reserved_for_source_ood"
        elif row["filetype"] not in {"exe32", "exe64", "dll32", "dll64"}:
            reason = "unparsed_or_unsupported_filetype"
        elif row["label"] == 0:
            p = int(rank(seed, row["group_id"])[:16], 16) / (1 << 64)
            split = "train" if p < .7 else "model_val" if p < .8 else "calibration" if p < .9 else "test"
        else:
            month = row["month"]
            window = "train" if month in train_months else "development" if month == development_month else "test" if month == test_month else ""
            if not window:
                reason = "outside_time_windows"
            else:
                if first_window is None:
                    first_window = window
                if window != first_window:
                    reason = "seen_group_in_earlier_window"
                elif window == "development":
                    split = "model_val" if int(rank(seed, row["group_id"])[0], 16) < 8 else "calibration"
                else:
                    split = window
        if not reason:
            # Single representative per exact group per asset, chosen by real date then SHA.
            if split in taken:
                split, reason = "excluded", "duplicate_group_representative"
            else:
                taken.add(split)
        if reason:
            split = "excluded"
        batch.append((row["id"], split, reason, rank(seed, row["sha256"])))
        if len(batch) >= 5000:
            db.executemany("INSERT INTO decisions VALUES (?,?,?,?)", batch)
            batch.clear()
    if batch:
        db.executemany("INSERT INTO decisions VALUES (?,?,?,?)", batch)
    db.commit()
    db.execute("CREATE INDEX decision_rank ON decisions(split,rank)")
    counts = Counter()
    match_cells = []
    print(json.dumps({"event": "matching_cells"}), flush=True)
    # A slim covering index avoids re-scanning millions of assigned rows for
    # every (role, filetype, size, label) quota; all matching stays on disk.
    db.execute("CREATE TABLE match_candidates AS SELECT r.id,d.split,r.filetype,r.size_bucket,r.label,d.rank FROM records r JOIN decisions d ON r.id=d.id WHERE d.split IN ('train','model_val','calibration','test')")
    db.execute("CREATE INDEX match_cell ON match_candidates(split,filetype,size_bucket,label,rank,id)")
    # Matching happens AFTER allocation; never borrow a held-out benign group.
    for split in SPLITS:
        cells = db.execute("SELECT filetype,size_bucket,SUM(label=0),SUM(label=1) FROM match_candidates WHERE split=? GROUP BY filetype,size_bucket ORDER BY filetype,size_bucket", (split,)).fetchall()
        supplies = {(c[0], c[1]): min(c[2], c[3]) for c in cells}
        quotas = dict(supplies)
        total = sum(supplies.values())
        if pair_cap and total > pair_cap:
            quotas = {k: (v * pair_cap) // total for k, v in supplies.items()}
            remaining = pair_cap - sum(quotas.values())
            order = sorted(supplies, key=lambda k: (-(supplies[k] * pair_cap % total), k))
            for k in order[:remaining]:
                quotas[k] += 1
        for ft, bucket, n0, n1 in cells:
            keep = quotas[ft, bucket]
            match_cells.append(dict(split=split, filetype=ft, size_bucket=bucket,
                                    benign_supply=n0, malicious_supply=n1, pairs=keep))
            for label in (0, 1):
                db.execute("UPDATE decisions SET split='excluded', reason='unmatched_or_budget' WHERE id IN (SELECT id FROM match_candidates WHERE split=? AND filetype=? AND size_bucket=? AND label=? ORDER BY rank,id LIMIT -1 OFFSET ?)", (split, ft, bucket, label, keep))
                counts[split + ":" + str(label)] += keep
    db.commit()
    paths = {"selection": out / "selection_manifest.csv", "excluded": out / "exclusion_ledger.csv", "ood": out / "source_ood_manifest.csv"}
    handles = {k: p.open("w", encoding="utf-8", newline="") for k, p in paths.items()}
    writers = {k: csv.DictWriter(f, fieldnames=FIELDS) for k, f in handles.items()}
    for w in writers.values():
        w.writeheader()
    print(json.dumps({"event": "writing_manifests"}), flush=True)
    emitted = Counter()
    try:
        for row in db.execute("SELECT r.*,d.split,d.reason FROM records r JOIN decisions d ON r.id=d.id ORDER BY r.sha256,r.id"):
            key = "excluded" if row["split"] == "excluded" else "ood" if row["split"] == "source_ood" else "selection"
            writers[key].writerow(record_manifest(row, row["split"], row["reason"]))
            emitted[row["split"]] += 1
    finally:
        for f in handles.values():
            f.close()
    exclusions = dict(db.execute("SELECT reason,COUNT(*) FROM decisions WHERE split='excluded' GROUP BY reason"))
    overlap = db.execute("SELECT COUNT(*) FROM (SELECT r.group_id FROM records r JOIN decisions d ON r.id=d.id WHERE d.split IN ('train','model_val','calibration','test','source_ood') GROUP BY r.group_id HAVING COUNT(DISTINCT d.split)>1)").fetchone()[0]
    if overlap:
        raise RuntimeError("split group isolation failed")
    return dict(schema_version=SCHEMA_VERSION, group_rule=GROUP_RULE, seed=seed,
                train_months=train_months, development_month=development_month, test_month=test_month,
                max_bytes=max_bytes, pair_cap_per_split=pair_cap, ood_source=ood_source,
                counts=dict(emitted), matched_counts=dict(counts), matching_cells=match_cells,
                exclusion_counts=exclusions, cross_split_group_overlap=overlap,
                outputs={k: {"path": str(p), "sha256": fingerprint(p)} for k, p in paths.items()},
                ready_for_training=False,
                blockers=["sample_paths_and_bytes_not_verified", "benign_software_lineage_not_verified",
                          "exact_ssdeep_is_not_complete_near_duplicate_clustering",
                          "timestamp_and_label_semantics_need_source_confirmation",
                          "four_split_training_contract_not_yet_implemented"],
                notes=["No future sample is moved into an earlier window.",
                       "Benign splits are group-hash partitions, NOT temporal extrapolation.",
                       "OOD is malicious-only: do not derive FPR/AUC/ECE from it.",
                       "Matching coarse size buckets is not proof that all shortcuts are removed."])


def parser(select=False):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--benign", type=Path, required=True)
    p.add_argument("--malicious", type=Path, nargs="+", required=True)
    p.add_argument("--out", type=Path, required=True, help="new/empty output directory")
    if select:
        p.add_argument("--seed", type=int, default=20261113)
        p.add_argument("--train-months", default="2026-01,2026-02,2026-03")
        p.add_argument("--development-month", default="2026-04")
        p.add_argument("--test-month", default="2026-05")
        p.add_argument("--max-bytes", type=int, default=16 << 20)
        p.add_argument("--pair-cap", type=int, default=0, help="per-split pair budget; 0=all matched")
        p.add_argument("--ood-source", default="Sophos-ReversingLabs")
    return p


def tool_fingerprints():
    folder = Path(__file__).resolve().parent
    return {p.name: fingerprint(p) for p in (folder / "retrain_manifest.py",
            folder / "analyze_retrain_manifests.py", folder / "plan_retrain_split.py",
            folder / "verify_retrain_manifest.py", folder / "build_retrain_dataset.py")}


def main(select=False):
    args = parser(select).parse_args()
    out = prepare_output(args.out)
    db = open_db(out / "manifest.sqlite3")
    try:
        audit = ingest(db, args.benign, args.malicious)
        audit["tool_fingerprints"] = tool_fingerprints()
        write_json(out / "manifest_audit.json", audit)
        if select:
            report = plan_selection(db, out, seed=args.seed, train_months=args.train_months.split(","),
                                    development_month=args.development_month, test_month=args.test_month,
                                    max_bytes=args.max_bytes, pair_cap=args.pair_cap, ood_source=args.ood_source)
            report["inputs"] = audit["inputs"]
            report["tool_fingerprints"] = audit["tool_fingerprints"]
            write_json(out / "split_plan.json", report)
            print(json.dumps({"event": "selected", "counts": report["counts"], "ready_for_training": False}), flush=True)
    finally:
        db.close()
    return 0
