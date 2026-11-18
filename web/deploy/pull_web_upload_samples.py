"""Pull verified Web-upload samples from TXY to the workstation archive."""

import argparse
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


HOST = "82.156.70.96"
USER = "ubuntu"
REMOTE_ROOT = "/home/ubuntu/github/NKAMG-AIDefender/web/FastAPI/web_upload_samples"
DEST_ROOT = Path(r"H:\AIDefender_WebUpload_Samples")
DEFAULT_KEY = Path.home() / ".ssh" / "id_ed25519"
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
CATEGORIES = {"模型判断恶意", "模型判断非恶意", "检查失败"}
H_WARNING_BYTES = 11 * 1024**4

logger = logging.getLogger("web_upload_sample_pull")


@dataclass(frozen=True)
class Sample:
    category: str
    sha256: str
    size: int


def parse_manifest(output):
    samples = []
    for line in output.splitlines():
        if not line:
            continue
        try:
            relative, raw_size = line.split("\t", 1)
            category, filename = relative.split("/", 1)
            sha256 = filename.removesuffix(".sample")
            size = int(raw_size)
        except (ValueError, TypeError) as error:
            raise ValueError("TXY sample manifest is malformed") from error
        if category not in CATEGORIES or not HASH_RE.fullmatch(sha256) or filename != sha256 + ".sample" or size < 0:
            raise ValueError("TXY sample manifest contains an unexpected path")
        samples.append(Sample(category, sha256, size))
    return samples


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ssh_options(key):
    return ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
            "-i", str(key)]


def _run(command, runner=subprocess.run):
    result = runner(command, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = (result.stderr or "remote command failed").strip()
        raise RuntimeError(f"{Path(command[0]).name} failed: {detail[-500:]}")
    return result.stdout


def list_samples(host, user, remote_root, key, runner=subprocess.run):
    remote_find = (f"find {shlex.quote(remote_root)} -mindepth 2 -maxdepth 2 -type f "
                   "-name '*.sample' -printf '%P\\t%s\\n'")
    output = _run(["ssh", *_ssh_options(key), f"{user}@{host}", remote_find], runner)
    return parse_manifest(output)


def _remote_path(root, sample):
    return f"{root.rstrip('/')}/{sample.category}/{sample.sha256}.sample"


def _append_receipt(root, sample, size):
    receipt = root / "transfer_receipts.jsonl"
    if receipt.is_symlink():
        raise RuntimeError("H-drive receipt path must not be a symbolic link")
    row = {"sha256": sample.sha256, "category": sample.category, "size": size,
           "received_at": datetime.now(timezone.utc).isoformat(), "status": "verified"}
    with receipt.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def transfer_sample(sample, host, user, remote_root, dest_root, key, runner=subprocess.run):
    root = dest_root.resolve()
    destination_dir = dest_root / sample.category
    if destination_dir.is_symlink():
        raise RuntimeError("H-drive category directory resolves outside the archive root")
    destination_dir.mkdir(parents=True, exist_ok=True)
    if destination_dir.resolve().parent != root:
        raise RuntimeError("H-drive category directory resolves outside the archive root")
    destination = destination_dir / f"{sample.sha256}.sample"
    if destination.is_symlink():
        raise RuntimeError("H-drive sample destination must not be a symbolic link")
    remote_path = _remote_path(remote_root, sample)

    if destination.exists():
        if sha256_file(destination) != sample.sha256:
            raise RuntimeError(f"Existing H-drive file has the wrong SHA256: {destination}")
    else:
        fd, temporary_name = tempfile.mkstemp(prefix=f"{sample.sha256}.", suffix=".part", dir=destination_dir)
        os.close(fd)
        temporary = Path(temporary_name)
        temporary.unlink()
        try:
            _run(["scp", *_ssh_options(key), f"{user}@{host}:{remote_path}", str(temporary)], runner)
            if not temporary.is_file() or temporary.stat().st_size != sample.size:
                raise RuntimeError("Downloaded sample size does not match TXY manifest")
            if sha256_file(temporary) != sample.sha256:
                raise RuntimeError("Downloaded sample SHA256 does not match its filename")
            os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)

    if destination.stat().st_size != sample.size or sha256_file(destination) != sample.sha256:
        raise RuntimeError("H-drive receipt verification failed")
    _append_receipt(dest_root, sample, destination.stat().st_size)
    _run(["ssh", *_ssh_options(key), f"{user}@{host}", f"rm -- {shlex.quote(remote_path)}"], runner)
    return destination


def pull_once(host, user, remote_root, dest_root, key, runner=subprocess.run):
    if not dest_root.is_dir():
        raise RuntimeError(f"H-drive destination is not mounted or does not exist: {dest_root}")
    free_bytes = shutil.disk_usage(dest_root).free
    if free_bytes <= H_WARNING_BYTES:
        logger.warning("H drive is at or below the 11 TiB warning threshold: free_bytes=%d", free_bytes)
    samples = list_samples(host, user, remote_root, key, runner)
    completed = 0
    for sample in samples:
        transfer_sample(sample, host, user, remote_root, dest_root, key, runner)
        completed += 1
        logger.info("verified sample sha256=%s category=%s", sample.sha256, sample.category)
    return completed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--user", default=USER)
    parser.add_argument("--remote-root", default=REMOTE_ROOT)
    parser.add_argument("--destination", type=Path, default=DEST_ROOT)
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY)
    args = parser.parse_args(argv)
    if not args.key.is_file():
        parser.error(f"SSH key does not exist: {args.key}")
    if args.destination.is_dir():
        logging.basicConfig(filename=args.destination / "pull_samples.log", level=logging.INFO,
                            format="%(asctime)s %(levelname)s %(message)s", encoding="utf-8")
    try:
        count = pull_once(args.host, args.user, args.remote_root, args.destination, args.key)
    except Exception:
        logger.exception("sample pull stopped; TXY source files were retained unless verified and acknowledged")
        return 1
    logger.info("sample pull complete; verified=%d", count)
    return 0


if __name__ == "__main__":
    sys.exit(main())
