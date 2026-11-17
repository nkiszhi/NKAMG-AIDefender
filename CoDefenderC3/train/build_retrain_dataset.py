"""Materialize a verified four-role selection; never extract or execute PE files."""
import argparse
import csv
import json
import os
from pathlib import Path
import shutil
try:
    from .retrain_manifest import FIELDS, SPLITS, fingerprint, prepare_output, write_json
    from .verify_retrain_manifest import pe_header_type
except ImportError:
    from retrain_manifest import FIELDS, SPLITS, fingerprint, prepare_output, write_json
    from verify_retrain_manifest import pe_header_type


def build(manifest, plan_path, audit_path, out, *, link=False):
    manifest, plan_path, audit_path = map(lambda p: Path(p).resolve(), (manifest, plan_path, audit_path))
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    if not audit.get("build_allowed") or audit["output"]["sha256"] != fingerprint(manifest):
        raise ValueError("path audit failed or verified manifest fingerprint mismatch")
    if plan["outputs"]["selection"]["sha256"] != audit["input"]["sha256"]:
        raise ValueError("selection/plan/audit fingerprints do not match")
    with manifest.open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    if not rows or len(rows) != audit["total"]:
        raise ValueError("empty selection or audit row count mismatch")
    seen, groups = set(), {}
    for row in rows:
        sha, role = row["sha256"], row["split"]
        if sha in seen or role not in SPLITS or row["sample_id"] != sha or row["path_status"] != "verified" or row["exclusion_reason"]:
            raise ValueError("invalid selection identity/status: " + sha)
        if row["group_id"] in groups and groups[row["group_id"]] != role:
            raise ValueError("group overlap")
        groups[row["group_id"]] = role
        seen.add(sha)
        if row["label"] == "1":
            valid_months = plan["train_months"] if role == "train" else [plan["test_month"]] if role == "test" else [plan["development_month"]]
            if row["month"] not in valid_months or row["timestamp"][:7] != row["month"]:
                raise ValueError("temporal role violation: " + sha)
    # Verify the entire source set again before writing anything, closing stale-audit gaps.
    for row in rows:
        src = Path(row["resolved_path"])
        if src.stat().st_size != int(row["size"]) or pe_header_type(src) != row["filetype"] or fingerprint(src) != row["sha256"]:
            raise ValueError("source changed since path audit: " + str(src))
    out = prepare_output(out)
    (out / "samples").mkdir()
    count = {s: {"0": 0, "1": 0} for s in SPLITS}
    with (out / "metadata.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            src, dst = Path(row["resolved_path"]), out / "samples" / row["sha256"]
            if link:
                try:
                    os.link(src, dst)
                except OSError:
                    shutil.copy2(src, dst)
            else:
                shutil.copy2(src, dst)
            if fingerprint(dst) != row["sha256"]:
                raise ValueError("materialized bytes changed during build")
            rec = {k: row[k] for k in FIELDS}
            rec.update(path=dst.relative_to(out).as_posix(), label=int(row["label"]), size=int(row["size"]))
            # Keep the real YYYY-MM observation; never encode train/val/test as months 1/2/3.
            count[row["split"]][row["label"]] += 1
            f.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
    meta = dict(split_contract="retrain-four-split-v1", schema_version=plan["schema_version"],
                selection_fingerprint=fingerprint(manifest), split_plan_fingerprint=fingerprint(plan_path),
                path_audit_fingerprint=fingerprint(audit_path), counts=count,
                training_ready=False, blockers=plan.get("blockers", []) + ["feature_contract_not_validated"],
                feature_extraction_performed=False,
                materialization="hardlink_preferred" if link else "copy")
    write_json(out / "metadata.json", meta)
    shutil.copy2(manifest, out / "verified_selection_manifest.csv")
    shutil.copy2(plan_path, out / "split_plan.json")
    shutil.copy2(audit_path, out / "path_audit.json")
    return meta


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    p.add_argument("--audit", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--link", action="store_true", help="hardlink where possible; fall back to copy")
    args = p.parse_args()
    result = build(args.manifest, args.plan, args.audit, args.out, link=args.link)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
