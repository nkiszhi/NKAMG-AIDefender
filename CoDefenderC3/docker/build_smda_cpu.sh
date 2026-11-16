#!/usr/bin/env bash
# CPU SMDA full-engine build: stage signatures, validate, then docker build.
set -euo pipefail

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    cat <<'HELP'
Usage: bash docker/build_smda_cpu.sh [IMAGE_TAG] [docker build options...]
Default tag: codefender-c3:smda-cpu
Prerequisites: Docker, Python, ensemble.pkl and signatures/ (SHA256/MD5/fuzzy).
PYTHON=/path/to/python selects the staging/check interpreter.
Examples:
  bash docker/build_smda_cpu.sh
  bash docker/build_smda_cpu.sh codefender-c3:smda-cpu --progress=plain
HELP
    exit 0
fi

TAG=codefender-c3:smda-cpu
if [[ $# -gt 0 && "$1" != -* ]]; then
    TAG="$1"
    shift
fi
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONIOENCODING=utf-8

if ! command -v docker >/dev/null 2>&1; then
    echo "[build-smda-cpu] Docker CLI not found; no signatures were staged." >&2
    exit 2
fi
PY="${PYTHON:-}"
if [[ -z "$PY" ]]; then
    for candidate in python3 python py; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PY="$candidate"
            break
        fi
    done
fi
if [[ -z "$PY" ]]; then
    echo "[build-smda-cpu] Python not found; set PYTHON=/path/to/python." >&2
    exit 2
fi

if [[ ! -s ensemble.pkl ]]; then
    echo "[build-smda-cpu] Missing or empty ensemble.pkl; no signatures were staged." >&2
    exit 2
fi

# Read-only full-family gate before creating the staging tree.
echo "[1/4] Check active signature source"
"$PY" -c 'import sys; sys.path.insert(0, "docker"); from pathlib import Path; from stage_signatures import resolve_active_sig_dir; from check_signature_layout import validate_signature_layout; root, _, _ = resolve_active_sig_dir("signatures"); print(validate_signature_layout(Path(root)))'
echo "[2/4] Stage active signatures (source is not updated)"
"$PY" docker/stage_signatures.py
"$PY" docker/check_signature_layout.py --sig-dir .docker_build/signatures
echo "[3/4] Check CPU Docker build context"
"$PY" docker/check_context.py --dockerfile Dockerfile.smda.cpu-serve --context .
echo "[4/4] Build $TAG"
docker build -f Dockerfile.smda.cpu-serve -t "$TAG" "$@" .
