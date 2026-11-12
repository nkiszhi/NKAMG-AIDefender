# CPU + SMDA full-engine image based on the plain MultiScan image.
# Build from CoDefenderC3/: bash docker/build.sh codefender-c3:prod
# Model and SHA256/MD5/fuzzy signatures are embedded; no runtime mounts required.
# Use the non-BinaryNinja base, NOT multiscan_basic_v3:with_binja.
ARG BASE_IMAGE=multiscan_basic_v3
FROM ${BASE_IMAGE}

ARG MODEL_FILE=ensemble.pkl

ARG PYTORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG TORCH_VERSION=2.6.0+cpu
ARG TORCHVISION_VERSION=0.21.0+cpu

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# The private base supplies Python/pip, TLS certificates and OS runtime libraries.
# Fail early if an old or licensed base was selected; do not assume apt is available.
RUN python3 -c "import sys, importlib.util; \
assert sys.version_info >= (3, 10), 'multiscan_basic_v3 needs Python >= 3.10'; \
assert importlib.util.find_spec('binaryninja') is None, 'Use a base without BinaryNinja; do not use with_binja'"

# Pin the same CPU torch/torchvision pair as Dockerfile.smda.
RUN python3 -m pip install --no-cache-dir --timeout 600 \
        --index-url "${PYTORCH_INDEX_URL}" \
        --upgrade --force-reinstall \
        "torch==${TORCH_VERSION}" "torchvision==${TORCHVISION_VERSION}"
RUN python3 -m pip install --no-cache-dir --timeout 300 \
        --index-url "${PIP_INDEX_URL}" torch_geometric supervisor
COPY requirements.txt ./
RUN python3 -m pip install --no-cache-dir --timeout 300 \
        --index-url "${PIP_INDEX_URL}" -r requirements.txt && \
    python3 -m pip check

RUN python3 -c "import torch, torchvision, smda, lief, capstone; \
from smda.Disassembler import Disassembler; from torchvision.ops import nms; \
assert torch.version.cuda is None, 'CPU image must use CPU-only torch'; \
b = torch.tensor([[0., 0., 10., 10.], [0., 0., 9., 9.]]); s = torch.tensor([0.9, 0.8]); \
assert nms(b, s, 0.5).tolist() == [0]; \
print('CPU ABI/import check OK:', torch.__version__, torchvision.__version__)"

# Keep large artifacts before application code to reuse their build layers.
COPY ${MODEL_FILE} ./ensemble.pkl
ARG SIG_STAGE=.docker_build/signatures
COPY ${SIG_STAGE}/ ./signatures/
COPY docker/check_signature_layout.py ./docker/check_signature_layout.py
RUN python3 docker/check_signature_layout.py --sig-dir /app/signatures && \
    if [ -f /app/signatures/_staging_manifest.json ]; then \
        mv /app/signatures/_staging_manifest.json /app/SIGNATURES_SOURCE.json; \
    fi

COPY config.py model_registry.py insn_categories.py ./
COPY engine/ ./engine/
COPY core/ ./core/
COPY models/ ./models/
COPY scaner/ ./scaner/
COPY feature_extraction/ ./feature_extraction/
COPY start_codefender.smda.sh ./start_codefender.sh
COPY supervisord.conf /etc/supervisord.conf
# Retain the optional legacy scanner registration (autostart=false).
COPY MultiScanPoint.ini /etc/supervisord.d/MultiScanPoint.ini
COPY codefender.smda.cpu-serve.ini /etc/supervisord.d/codefender.ini
RUN sed -i 's/\r$//' /app/start_codefender.sh && \
    chmod +x /app/start_codefender.sh && \
    mkdir -p /var/log/supervisor /etc/supervisord.d /home/SCAN

# Critical production/CPU/hash flags are also fixed by Supervisor.
# Budgets and admission capacity remain configurable with docker run -e.
ENV OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    CODEFENDER_MODEL_PATH=/app/ensemble.pkl \
    CODEFENDER_HASH_DB_DIR=/app/signatures \
    CODEFENDER_ENV=prod \
    CODEFENDER_RUNTIME_CFG_DISABLE=1 \
    CODEFENDER_DISASM_BACKEND=smda \
    CODEFENDER_MODEL_DEVICE=cpu \
    CODEFENDER_MALGRAPH_DEVICE=cpu \
    CODEFENDER_HASH_DB_ENABLED=1 \
    CODEFENDER_FUZZY_DB_ENABLED=1 \
    CODEFENDER_REQUIRE_HASH_DB=1 \
    CODEFENDER_ANALYSIS_TIMEOUT=600 \
    CODEFENDER_REQUEST_TIMEOUT=900 \
    CODEFENDER_HARD_TIMEOUT=960 \
    CODEFENDER_MAX_CONCURRENT=1 \
    CODEFENDER_WEB_COMPAT_HOST=0.0.0.0 \
    CODEFENDER_WEB_COMPAT_PORT=8000 \
    CODEFENDER_PRODUCTION_HOST=0.0.0.0 \
    CODEFENDER_PRODUCTION_PORT=18001 \
    CODEFENDER_ENABLE_DEV_API=0

# Import/config checks only; real model and database readiness is checked at startup.
COPY docker/check_model_imports.py ./docker/check_model_imports.py
RUN python3 -c "from engine.startup import configure_disassembly_backend; \
assert configure_disassembly_backend() == 'smda'; \
import config; \
assert config.ENV_PROFILE == 'prod'; \
assert config.HASH_DB_ENABLED and config.FUZZY_DB_ENABLED and config.REQUIRE_HASH_DB; \
assert config.HASH_DB_DIR == '/app/signatures'; \
import engine.app; print('Engine import and production configuration OK')" && \
    python3 docker/check_model_imports.py

EXPOSE 8000 18001
HEALTHCHECK --interval=30s --timeout=5s --start-period=300s --retries=3 \
    CMD ["python3", "-c", "import json, os, urllib.request; port = int(os.environ.get('CODEFENDER_PRODUCTION_PORT', '18001')); r = urllib.request.urlopen('http://127.0.0.1:%d/readyz' % port, timeout=3); assert r.status == 200 and json.load(r).get('ready') is True"]
CMD ["/usr/local/bin/supervisord", "-c", "/etc/supervisord.conf"]
