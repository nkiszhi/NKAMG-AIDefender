"""
FastAPI service for single-sample inference.

Run:
    uvicorn engine.app:app --host 0.0.0.0 --port 8000

Main endpoint:
    POST /predict-single
    form-data:
      - file: uploaded PE sample
      - include_de: whether to extract D/E (disassembly/graph) features via BinaryNinja
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
import traceback
import uuid
import zipfile
import zlib
from collections import Counter
from contextlib import contextmanager
from datetime import datetime
from threading import Lock
from concurrent.futures import ProcessPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from fastapi import Body, FastAPI, File, HTTPException, Query, Request, UploadFile
from starlette.responses import JSONResponse

import config
from feature_extraction.extract_feature import BinjaExtractor
from feature_extraction.unified import FeatureType, extract_feature
from models.ensemble import MultiModelEnsemble, _input_dtype
from engine.inference import compute_identifiers, _is_valid_pe
from engine.result_formatter import format_scan_result

# nkrepo 哈希库（SHA256 + MD5 预检）：scaner 目录入 sys.path 后顶层导入。
# 注意目录名用 scaner（非 scanner），避免与 scanner.py 模块同名遮蔽。
_SCANER_DIR = os.path.join(config.ROOT, "scaner")
if _SCANER_DIR not in sys.path:
    sys.path.insert(0, _SCANER_DIR)
import scanner as nkrepo_scanner  # noqa: E402
import staticinfo as nkrepo_staticinfo  # noqa: E402  # fuzzy 哈希计算 (ppdeep/pefile 缺失自动降级)

try:
    import torch
except Exception:  # pragma: no cover
    torch = None


# ── 启动日志可见性 ───────────────────────────────────────────────
# uvicorn 只给 "uvicorn.*" 命名空间挂了 handler，root logger 默认无 handler；
# 于是 codefender.* 的 INFO 日志（[hashdb] … 签名库就绪 / 预检已禁用、模型加载等）
# 全部被丢弃（Python 的 lastResort 只兜 WARNING+），启动时看不到任何一行。
# 这里只给 "codefender" 命名空间挂一个 StreamHandler（不动 root / uvicorn 配置），
# 让这些启动日志在 uvicorn / supervisor / Docker 下都能看到。
_cf_logger = logging.getLogger("codefender")
if not _cf_logger.handlers:
    _cf_handler = logging.StreamHandler()
    _cf_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s", "%Y-%m-%d %H:%M:%S"))
    _cf_logger.addHandler(_cf_handler)
    _cf_logger.setLevel(logging.INFO)
    _cf_logger.propagate = False   # 避免调用方另行 basicConfig 时重复输出


RAW_LEN = 32768
INT_VIEWS = {"V1_byte", "V6_opcode_seq"}
FEATURE_DIMS = BinjaExtractor.feature_dims()
MAX_UPLOAD_BYTES = int(os.environ.get("CODEFENDER_MAX_UPLOAD_BYTES", 128 * 1024 * 1024))
MODEL_PATH = os.environ.get("CODEFENDER_MODEL_PATH", config.MODEL_PATH)

# 单样本处理超时（秒），/predict-single 超时返回 504，/predict-directory 超时跳过继续下一个
REQUEST_TIMEOUT = int(os.environ.get("CODEFENDER_REQUEST_TIMEOUT", 120))

MALGRAPH_ENABLED = True
MALGRAPH_BASE_DIR = os.path.join(config.ROOT, "models", "MalGraph_2022")
_MALGRAPH_CKPT_ENV = os.environ.get("CODEFENDER_MALGRAPH_CKPT", "").strip()
_MALGRAPH_VOCAB_ENV = os.environ.get("CODEFENDER_MALGRAPH_VOCAB", "").strip()
_MALGRAPH_MAX_VOCAB_ENV = os.environ.get("CODEFENDER_MALGRAPH_MAX_VOCAB_SIZE", "").strip()
MALGRAPH_PARAMS_FILE = os.environ.get("CODEFENDER_MALGRAPH_PARAMS_FILE", "").strip()
MALGRAPH_PARAMS_JSON = os.environ.get("CODEFENDER_MALGRAPH_PARAMS_JSON", "").strip()
MALGRAPH_DEVICE = os.environ.get("CODEFENDER_MALGRAPH_DEVICE", "cuda").strip() or "cuda"
DEFAULT_MALGRAPH_PARAMS = {
    "gnn_type": "graphsage",
    "pool_type": "global_max_pool",
    "acfg_init_dims": 11,
    "cfg_filters": "128-128-128",
    "fcg_filters": "128-128-128",
    "number_classes": 2,
    "dropout_rate": 0.3,
    "ablation_models": "none",
}


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


DEFAULT_INCLUDE_DE = _env_bool("CODEFENDER_INCLUDE_DE", True)
MALGRAPH_ENABLED = _env_bool("CODEFENDER_ENABLE_MALGRAPH", MALGRAPH_ENABLED)

app = FastAPI(
    title="CoDefenderC3 Single-Sample API",
    version="1.0.0",
    description="Upload one PE sample and return per-model prediction results.",
)
# =============================================================================
#  生产加固模块 (items 1-7)
# =============================================================================

# 1. 探针分离：启动时间
_START_TIME = time.time()

# 2. 并发限制信号量
_SCAN_SEMAPHORE = asyncio.Semaphore(
    int(os.environ.get("CODEFENDER_MAX_CONCURRENT", 4))
)

# 3. 请求追踪中间件
@app.middleware("http")
async def _request_id_middleware(request: Request, call_next):
    req_id = str(uuid.uuid4())[:8]
    start_t = time.time()
    response = await call_next(request)
    elapsed_ms = round((time.time() - start_t) * 1000, 1)
    logging.info(
        "[%s] %s %s -> %d  %.1fms",
        req_id, request.method, request.url.path,
        response.status_code, elapsed_ms,
    )
    response.headers["X-Request-ID"] = req_id
    with _METRICS_LOCK:
        _METRICS["total_requests"] += 1
    return response

# 4. 运行时指标
_METRICS: Dict[str, Any] = {
    "total_requests": 0,
    "predict_single_ok": 0,
    "predict_single_error": 0,
    "predict_dir_ok": 0,
    "predict_dir_error": 0,
    "scan_files_total": 0,
    "scan_files_malicious": 0,
    "scan_files_benign": 0,
    "last_predict_ms": 0.0,
    "unhandled_errors": 0,
}
_METRICS_LOCK = Lock()

# 6. 全局异常处理器
@app.exception_handler(Exception)
async def _global_exception_handler(request: Request, exc: Exception):
    with _METRICS_LOCK:
        _METRICS["unhandled_errors"] += 1
    logging.error(
        "[UNHANDLED] %s %s -> %s: %s",
        request.method, request.url.path,
        type(exc).__name__, exc,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "internal server error", "error_type": type(exc).__name__},
    )


_STATE_LOCK = Lock()
_ENSEMBLE: Optional[MultiModelEnsemble] = None
_EXTRACTOR: Optional[BinjaExtractor] = None
_MALGRAPH_RUNTIME: Optional[Dict[str, Any]] = None
_SDD_ENGINE: Optional[Any] = None


def _load_ensemble() -> MultiModelEnsemble:
    global _ENSEMBLE
    if _ENSEMBLE is not None:
        return _ENSEMBLE

    with _STATE_LOCK:
        if _ENSEMBLE is not None:
            return _ENSEMBLE
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"model file not found: {MODEL_PATH}")
        _ENSEMBLE = MultiModelEnsemble.load(MODEL_PATH)
        return _ENSEMBLE


def _get_sdd_engine():
    """Lazy-load SDDEngine (uncalibrated; score_samples returns zero drift evidence)."""
    global _SDD_ENGINE
    if _SDD_ENGINE is not None:
        return _SDD_ENGINE

    with _STATE_LOCK:
        if _SDD_ENGINE is not None:
            return _SDD_ENGINE

        from core.sdd_engine import SDDEngine
        ens = _load_ensemble()
        _SDD_ENGINE = SDDEngine(
            K=ens.K,
            perspective_groups=ens.perspective_groups(),
        )
        return _SDD_ENGINE


def _get_extractor() -> BinjaExtractor:
    global _EXTRACTOR
    if _EXTRACTOR is not None:
        return _EXTRACTOR

    with _STATE_LOCK:
        if _EXTRACTOR is None:
            _EXTRACTOR = BinjaExtractor()
        return _EXTRACTOR


def _load_malgraph_params() -> Dict[str, Any]:
    params: Dict[str, Any] = {}

    if MALGRAPH_PARAMS_FILE:
        if not os.path.exists(MALGRAPH_PARAMS_FILE):
            raise FileNotFoundError(f"MalGraph params file not found: {MALGRAPH_PARAMS_FILE}")
        with open(MALGRAPH_PARAMS_FILE, "r", encoding="utf-8") as f:
            loaded = json.load(f)
        if not isinstance(loaded, dict):
            raise ValueError("MalGraph params file must be a JSON object")
        params.update(loaded)

    if MALGRAPH_PARAMS_JSON:
        loaded = json.loads(MALGRAPH_PARAMS_JSON)
        if not isinstance(loaded, dict):
            raise ValueError("CODEFENDER_MALGRAPH_PARAMS_JSON must be a JSON object")
        params.update(loaded)

    return params


def _resolve_malgraph_ckpt_path() -> str:
    if _MALGRAPH_CKPT_ENV:
        return _MALGRAPH_CKPT_ENV
    candidates = [
        os.path.join(MALGRAPH_BASE_DIR, "best_model.pt"),
        os.path.join(MALGRAPH_BASE_DIR, "saved", "best_model.pt"),
        os.path.join(MALGRAPH_BASE_DIR, "saved", "malgraph_best.pth"),
        os.path.join(MALGRAPH_BASE_DIR, "malgraph_best.pth"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    # fallback for health message
    return candidates[0]


def _resolve_malgraph_vocab_path() -> str:
    if _MALGRAPH_VOCAB_ENV:
        return _MALGRAPH_VOCAB_ENV
    candidates = [
        os.path.join(MALGRAPH_BASE_DIR, "saved", "train_external_function_name_vocab.jsonl"),
        os.path.join(MALGRAPH_BASE_DIR, "train_external_function_name_vocab.jsonl"),
        os.path.join(MALGRAPH_BASE_DIR, "output", "train_external_function_name_vocab.jsonl"),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return candidates[0]


def _extract_state_dict(ckpt_obj: Any) -> Dict[str, Any]:
    if isinstance(ckpt_obj, dict):
        for key in ("state_dict", "model_state_dict"):
            if key in ckpt_obj and isinstance(ckpt_obj[key], dict):
                state = ckpt_obj[key]
                break
        else:
            state = ckpt_obj
    else:
        raise ValueError("unsupported MalGraph checkpoint format")

    if not isinstance(state, dict) or not state:
        raise ValueError("empty/invalid MalGraph state dict")

    # DataParallel checkpoints may prefix params with 'module.'
    if any(isinstance(k, str) and k.startswith("module.") for k in state):
        state = {
            (k[7:] if isinstance(k, str) and k.startswith("module.") else k): v
            for k, v in state.items()
        }
    return state


def _infer_malgraph_params_from_state(state: Dict[str, Any]) -> Tuple[Dict[str, Any], Optional[int]]:
    params = dict(DEFAULT_MALGRAPH_PARAMS)

    key_has_lin_l = any(".lin_l.weight" in k for k in state.keys() if isinstance(k, str))
    params["gnn_type"] = "graphsage" if key_has_lin_l else "gcn"

    def _infer_filters(prefix: str, gnn_type: str) -> Tuple[Optional[int], List[int]]:
        if gnn_type == "graphsage":
            pat = re.compile(rf"^{re.escape(prefix)}\.(\d+)\.lin_l\.weight$")
            suffix = ".lin_l.weight"
        else:
            pat = re.compile(rf"^{re.escape(prefix)}\.(\d+)\.lin\.weight$")
            suffix = ".lin.weight"

        idx_to_key = {}
        for k in state.keys():
            if not isinstance(k, str):
                continue
            m = pat.match(k)
            if m:
                idx_to_key[int(m.group(1))] = k

        if not idx_to_key:
            # fallback: scan by suffix
            for k in state.keys():
                if isinstance(k, str) and k.startswith(prefix + ".") and k.endswith(suffix):
                    parts = k.split(".")
                    if len(parts) >= 4 and parts[1].isdigit():
                        idx_to_key[int(parts[1])] = k

        if not idx_to_key:
            return None, []

        init_dim = None
        outs: List[int] = []
        for i in sorted(idx_to_key.keys()):
            w = state[idx_to_key[i]]
            if not hasattr(w, "shape") or len(getattr(w, "shape", [])) < 2:
                continue
            out_dim = int(w.shape[0])
            in_dim = int(w.shape[1])
            if init_dim is None:
                init_dim = in_dim
            outs.append(out_dim)
        return init_dim, outs

    cfg_init, cfg_outs = _infer_filters("cfg_conv_layers", params["gnn_type"])
    if cfg_init is not None:
        params["acfg_init_dims"] = int(cfg_init)
    if cfg_outs:
        params["cfg_filters"] = "-".join(str(x) for x in cfg_outs)

    _, fcg_outs = _infer_filters("fcg_conv_layers", params["gnn_type"])
    if fcg_outs:
        params["fcg_filters"] = "-".join(str(x) for x in fcg_outs)

    # No parameter in state dict can reveal pooling type reliably; keep default.

    inferred_vocab_size = None
    emb = state.get("external_embedding_layer.weight")
    if hasattr(emb, "shape") and len(getattr(emb, "shape", [])) >= 2:
        inferred_vocab_size = int(emb.shape[0]) - 2

    return params, inferred_vocab_size


def _load_malgraph_runtime() -> Dict[str, Any]:
    global _MALGRAPH_RUNTIME
    if _MALGRAPH_RUNTIME is not None:
        return _MALGRAPH_RUNTIME

    if not MALGRAPH_ENABLED:
        raise RuntimeError("MalGraph disabled by CODEFENDER_ENABLE_MALGRAPH")
    if torch is None:
        raise RuntimeError("torch is not available")
    ckpt_path = _resolve_malgraph_ckpt_path()
    vocab_path = _resolve_malgraph_vocab_path()
    if not os.path.exists(ckpt_path):
        raise FileNotFoundError(f"MalGraph checkpoint not found: {ckpt_path}")
    if not os.path.exists(vocab_path):
        raise FileNotFoundError(f"MalGraph vocab file not found: {vocab_path}")

    with _STATE_LOCK:
        if _MALGRAPH_RUNTIME is not None:
            return _MALGRAPH_RUNTIME

        from models.MalGraph_2022.ParameterClasses import ModelParams
        from models.MalGraph_2022.Vocabulary import Vocab
        from models.MalGraph_2022.malgraph import HierarchicalGraphNeuralNetwork

        ckpt = torch.load(ckpt_path, map_location="cpu")
        state = _extract_state_dict(ckpt)
        inferred_params, inferred_vocab_size = _infer_malgraph_params_from_state(state)
        user_params = _load_malgraph_params()
        inferred_params.update(user_params)
        params_dict = inferred_params

        if _MALGRAPH_MAX_VOCAB_ENV:
            vocab_max_size = int(_MALGRAPH_MAX_VOCAB_ENV)
        elif inferred_vocab_size is not None and inferred_vocab_size > 0:
            vocab_max_size = inferred_vocab_size
        else:
            vocab_max_size = 10000

        model_params = ModelParams(**params_dict)
        vocab = Vocab(freq_file=vocab_path, max_vocab_size=vocab_max_size)
        logger = logging.getLogger("codefender.malgraph")

        model = HierarchicalGraphNeuralNetwork(
            model_params=model_params,
            external_vocab=vocab,
            global_log=logger,
        )
        missing, unexpected = model.load_state_dict(state, strict=False)

        req_dev = MALGRAPH_DEVICE.lower()
        if req_dev.startswith("cuda") and not torch.cuda.is_available():
            device = torch.device("cpu")
        else:
            device = torch.device(req_dev)
        model = model.to(device)
        model.eval()

        _MALGRAPH_RUNTIME = {
            "model": model,
            "device": device,
            "params": params_dict,
            "vocab_max_size": vocab_max_size,
            "checkpoint_path": ckpt_path,
            "vocab_path": vocab_path,
            "missing_keys": list(missing),
            "unexpected_keys": list(unexpected),
        }
        return _MALGRAPH_RUNTIME


def _predict_malgraph_single(pe_path: str, sample=None) -> Tuple[int, float, Dict[str, Any]]:
    runtime = _load_malgraph_runtime()

    from torch_geometric.data import Batch, Data
    if sample is None:
        from models.MalGraph_2022.utils import extract_cfg_and_fcg
        sample = extract_cfg_and_fcg(pe_path, vocab_dict={})
    if not sample:
        raise RuntimeError("MalGraph feature extraction failed")

    acfg_list = sample.get("acfg_list", [])
    if not acfg_list:
        raise RuntimeError("MalGraph no ACFG extracted")

    pyg_graphs = []
    for one_acfg in acfg_list:
        block_features = one_acfg.get("block_features", [])
        block_edges = one_acfg.get("block_edges", [[], []])

        x = torch.tensor(block_features, dtype=torch.float32)
        if x.ndim == 1:
            x = x.reshape(1, -1)
        if x.numel() == 0:
            x = torch.zeros((1, 11), dtype=torch.float32)

        edge_index = torch.tensor(block_edges, dtype=torch.long)
        if edge_index.ndim != 2 or edge_index.shape[0] != 2:
            edge_index = torch.zeros((2, 0), dtype=torch.long)

        pyg_graphs.append(Data(x=x, edge_index=edge_index))

    if not pyg_graphs:
        raise RuntimeError("MalGraph no valid function graph")

    local_batch = Batch.from_data_list(pyg_graphs).to(runtime["device"])
    local_count = len(pyg_graphs)

    all_names = sample.get("function_names", [])
    external_names = all_names[local_count:] if len(all_names) >= local_count else []
    function_edges = sample.get("function_edges", [[], []])
    if not isinstance(function_edges, list) or len(function_edges) != 2:
        function_edges = [[], []]

    model = runtime["model"]
    with torch.no_grad():
        out = model(
            real_local_batch=local_batch,
            real_bt_positions=[0, local_count],
            bt_external_names=[external_names],
            bt_all_function_edges=[function_edges],
            local_device=runtime["device"],
        )

    score = float(out.reshape(-1)[0].detach().cpu().item())
    pred = int(score > 0.5)
    meta = {
        "local_functions": local_count,
        "external_functions": len(external_names),
        "fcg_edges": len(function_edges[0]) if function_edges else 0,
        "checkpoint": runtime.get("checkpoint_path", ""),
        "vocab": runtime.get("vocab_path", ""),
    }
    return pred, score, meta


def _to_numpy_1d(x: Any, dtype: np.dtype) -> np.ndarray:
    arr = np.asarray(x).reshape(-1)
    return arr.astype(dtype, copy=False)


def _coerce_row_dim(row: np.ndarray, expected_dim: Optional[int]) -> Tuple[np.ndarray, Optional[str]]:
    if expected_dim is None or expected_dim <= 0:
        return row, None
    got = int(row.shape[0])
    if got == expected_dim:
        return row, None
    if got < expected_dim:
        out = np.zeros(expected_dim, dtype=row.dtype)
        out[:got] = row
        return out, f"padded_to_expected_dim:{got}->{expected_dim}"
    return row[:expected_dim], f"truncated_to_expected_dim:{got}->{expected_dim}"


def _expected_dim_for_model(ens: MultiModelEnsemble, model_name: str) -> Optional[int]:
    # noqa: SLF001 - reading ensemble internal attributes
    model = ens._models.get(model_name)
    mtype = ens._model_types.get(model_name, "unknown")

    if model is not None and mtype == "numpy":
        nfi = getattr(model, "n_features_in_", None)
        if nfi is not None:
            try:
                d = int(nfi)
                if d > 0:
                    return d
            except Exception:
                pass

    kwargs = ens._actual_kwargs.get(model_name, {})  # noqa: SLF001
    if isinstance(kwargs, dict):
        in_dim = kwargs.get("input_dim")
        if in_dim is not None:
            try:
                d = int(in_dim)
                if d > 0:
                    return d
            except Exception:
                pass

    # B-fix: torch 模型 kwargs 未写 input_dim 时（如图模型），从第一个
    # nn.Linear 的 in_features 推导期望维度 —— 让 _coerce_row_dim 的
    # 截断/拒绝有据可依，而不是放行任意维度的回退特征。
    if model is not None and mtype == "pytorch":
        try:
            import torch as _torch
            first_linear = next(
                m for m in model.modules()
                if isinstance(m, _torch.nn.Linear)
            )
            d = int(first_linear.in_features)
            if d > 0:
                return d
        except Exception:
            pass
    return None


def _infer_expected_view_dims(ens: MultiModelEnsemble) -> Dict[str, int]:
    dims: Dict[str, int] = {}

    for vname, model_names in ens.view_groups.items():
        cand: List[int] = []
        for mname in model_names:
            d = _expected_dim_for_model(ens, mname)
            if d is not None and d > 0:
                cand.append(d)
        if cand:
            dims[vname] = Counter(cand).most_common(1)[0][0]
            continue

        if vname == "V1_byte":
            dims[vname] = RAW_LEN
            continue

        cfg = config.VIEW_GROUPS.get(vname, {})
        binja_ids = cfg.get("binja_features", [])
        if binja_ids:
            fallback = 0
            for fid in binja_ids:
                fallback += int(FEATURE_DIMS.get(fid, 0))
            if fallback > 0:
                dims[vname] = fallback

    return dims


def _build_ember_view(
    ember_full: np.ndarray,
    ember_ranges: Dict[str, Tuple[int, int]],
    range_names: List[str],
) -> Optional[np.ndarray]:
    names = list(ember_ranges.keys()) if range_names == ["__ALL__"] else range_names
    parts: List[np.ndarray] = []
    dim = ember_full.shape[0]
    for rn in names:
        if rn not in ember_ranges:
            continue
        lo, hi = ember_ranges[rn]
        if lo < dim:
            parts.append(ember_full[lo:min(hi, dim)])
    if not parts:
        return None
    return np.concatenate(parts).astype(np.float32, copy=False)


def _extract_views_for_single_sample(
    pe_path: str,
    required_views: List[str],
    include_de: bool,
    expected_view_dims: Optional[Dict[str, int]] = None,
    extracted_features=None,
) -> Tuple[Dict[str, np.ndarray], Dict[str, Dict[str, Any]]]:
    ext = _get_extractor()
    feats = {}
    view_meta: Dict[str, Dict[str, Any]] = {}

    try:
        feats.update(ext.extract_fast(pe_path) if extracted_features is None else extracted_features)
    except Exception as e:
        raise RuntimeError(f"extract_fast failed: {e}") from e

    de_status = "skipped"
    if include_de and extracted_features is None:
        try:
            feats.update(ext.extract_de_only(pe_path))
            de_status = "ok"
        except Exception as e:
            de_status = f"failed: {e}"

    with open(pe_path, "rb") as f:
        raw_bytes = f.read(RAW_LEN)

    ember_full: Optional[np.ndarray] = None
    ember_ranges: Optional[Dict[str, Tuple[int, int]]] = None

    def ensure_ember_full() -> np.ndarray:
        nonlocal ember_full, ember_ranges
        if ember_full is None:
            tensor = extract_feature(pe_path, FeatureType.EMBER_FULL)
            if hasattr(tensor, "detach"):
                ember_full = tensor.detach().cpu().numpy().astype(np.float32, copy=False).reshape(-1)
            else:
                ember_full = np.asarray(tensor, dtype=np.float32).reshape(-1)
            ember_ranges = config.get_ember_ranges(len(ember_full))
        return ember_full

    views: Dict[str, np.ndarray] = {}

    for vn in required_views:
        cfg = config.VIEW_GROUPS.get(vn, {})
        binja_ids = list(cfg.get("binja_features", []))
        expected_dim = (expected_view_dims or {}).get(vn)
        row: Optional[np.ndarray] = None
        source = ""
        reason = ""
        de_blocked = False

        if vn == "V1_byte":
            row_i = np.zeros(RAW_LEN, dtype=np.int32)
            if "B01" in feats:
                src = _to_numpy_1d(feats["B01"], np.int32)[:RAW_LEN]
                row_i[: len(src)] = src
            else:
                raw_arr = np.frombuffer(raw_bytes, dtype=np.uint8).astype(np.int32, copy=False)
                row_i[: len(raw_arr)] = raw_arr
            row = row_i
            source = "binja:B01/raw_fallback"
        elif binja_ids:
            available_ids = [fid for fid in binja_ids if fid in feats]
            missing_ids = [fid for fid in binja_ids if fid not in feats]
            if available_ids:
                dtype = np.int32 if vn in INT_VIEWS else np.float32
                parts = [_to_numpy_1d(feats[fid], dtype) for fid in available_ids]
                row = np.concatenate(parts)
                source = f"binja:{','.join(available_ids)}"
                if missing_ids:
                    reason = f"partial_binja_features_missing:{','.join(missing_ids)}"
            else:
                reason = f"missing_binja_features:{','.join(missing_ids)}"
                if (not include_de or extracted_features is not None) and any(fid.startswith(("D", "E")) for fid in missing_ids):
                    reason += "; hint=include_de=true"
                    # B-fix: include_de=false 时 D/E 视角整体缺失 → 禁止任何回退
                    # （否则 EMBER 切片会伪造维度不符的特征行，喂给模型必然报错
                    #   或产出垃圾分数）。标记 de_blocked，下方回退分支直接跳过。
                    de_blocked = True

        if row is None and "ember_ranges" in cfg and not de_blocked:
            try:
                full = ensure_ember_full()
                ranges = ember_ranges or config.get_ember_ranges(len(full))
                range_names = cfg.get("ember_ranges", [])
                ember_row = _build_ember_view(full, ranges, range_names)
                if ember_row is not None:
                    # For mixed views (both binja+ember defined), only use ember
                    # fallback when model-expected dim matches the ember slice dim.
                    if binja_ids and expected_dim is not None and ember_row.shape[0] != expected_dim:
                        if not reason:
                            reason = (
                                "ember_fallback_dim_mismatch:"
                                f"{ember_row.shape[0]}!=expected_{expected_dim}"
                            )
                    else:
                        row = ember_row
                        source = f"ember:{','.join(range_names)}"
                elif not reason:
                    reason = "empty_ember_slice"
            except Exception as e:
                if not reason:
                    reason = f"ember_extract_failed:{e}"

        if row is None and not reason:
            reason = "no_feature_path_for_view"

        if row is not None:
            row, dim_note = _coerce_row_dim(row.reshape(-1), expected_dim)
            if dim_note:
                reason = f"{reason}; {dim_note}" if reason else dim_note
            views[vn] = row.reshape(1, -1)
            meta = {
                "status": "ok",
                "source": source,
                "shape": list(views[vn].shape),
            }
            if expected_dim is not None:
                meta["expected_dim"] = expected_dim
            if reason:
                meta["note"] = reason
            view_meta[vn] = meta
        else:
            view_meta[vn] = {
                "status": "missing",
                "reason": reason,
            }

    view_meta["_de_feature_extraction"] = {"status": de_status}
    return views, view_meta


def _extract_single_sample_wrapper(args):
    """
    Module-level wrapper function for ProcessPoolExecutor to extract features for a single sample.
    This must be at module level (not nested) for pickling by ProcessPoolExecutor.
    """
    idx, pe_path, required_views, include_de, expected_view_dims = args
    try:
        views, view_meta = _extract_views_for_single_sample(
            pe_path=pe_path,
            required_views=required_views,
            include_de=include_de,
            expected_view_dims=expected_view_dims,
        )
        return idx, views, view_meta, None
    except Exception as e:
        # Return error information for failed samples
        return idx, None, None, str(e)


def _extract_views_for_batch(
    pe_paths: List[str],
    required_views: List[str],
    include_de: bool,
    expected_view_dims: Optional[Dict[str, int]] = None,
) -> Dict[int, Tuple[Dict[str, np.ndarray], Dict[str, Dict[str, Any]]]]:
    """
    Extract features from multiple PE samples in parallel using ProcessPoolExecutor.
    
    Args:
        pe_paths: List of PE file paths to process
        required_views: List of view names to extract
        include_de: Whether to extract D/E features (BinaryNinja disassembly/graph)
        expected_view_dims: Optional dict mapping view names to expected dimensions
    
    Returns:
        Dict mapping sample indices to tuples of (views_dict, view_meta_dict).
        Failed samples are excluded from the result.
    """
    if not pe_paths:
        return {}
    
    # Determine optimal worker count
    max_workers = min(len(pe_paths), os.cpu_count() or 32)
    
    results: Dict[int, Tuple[Dict[str, np.ndarray], Dict[str, Dict[str, Any]]]] = {}
    
    # Use ProcessPoolExecutor for parallel feature extraction
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Create tasks with indices and all required parameters
        tasks = [(i, path, required_views, include_de, expected_view_dims) 
                 for i, path in enumerate(pe_paths)]
        
        # Execute parallel extraction
        for idx, views, view_meta, error in executor.map(_extract_single_sample_wrapper, tasks):
            if error is None:
                # Successful extraction
                results[idx] = (views, view_meta)
            else:
                # Failed extraction - log but continue with other samples
                logging.warning(
                    "[batch_feature_extraction] Sample %d (%s) failed: %s",
                    idx,
                    pe_paths[idx] if idx < len(pe_paths) else "unknown",
                    error,
                )
    
    return results


def _predict_per_model(
    ens: MultiModelEnsemble,
    views: Dict[str, np.ndarray],
    view_meta: Optional[Dict[str, Dict[str, Any]]] = None,
    pe_path: Optional[str] = None,
    include_de: bool = True,
    selected_models=None,
    malgraph_sample=None,
    on_result=None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []

    for vname, model_names in ens.view_groups.items():
        x_view = views.get(vname)
        for mname in model_names:
            if selected_models is not None and mname not in selected_models:
                continue
            model = ens._models.get(mname)  # noqa: SLF001 - existing internal structure
            mtype = ens._model_types.get(mname, "unknown")  # noqa: SLF001

            item: Dict[str, Any] = {
                "model": mname,
                "view": vname,
                "engine": mtype,
            }

            if mtype == "special":
                if mname == "MalGraph":
                    if not include_de:
                        item["status"] = "skipped"
                        item["reason"] = "MalGraph requires D/E features; set include_de=true"
                        results.append(item)
                        if on_result:
                            on_result(dict(item))
                        continue
                    if not pe_path:
                        item["status"] = "error"
                        item["reason"] = "missing pe_path for MalGraph inference"
                        results.append(item)
                        if on_result:
                            on_result(dict(item))
                        continue
                    try:
                        pred, score, mg_meta = _predict_malgraph_single(pe_path, sample=malgraph_sample)
                        item["status"] = "ok"
                        item["score"] = score
                        item["prediction"] = pred
                        item["malgraph_meta"] = mg_meta
                    except Exception as e:
                        item["status"] = "unavailable"
                        item["reason"] = str(e)
                    results.append(item)
                    if on_result:
                        on_result(dict(item))
                    continue
                item["status"] = "skipped"
                item["reason"] = "special_pipeline_not_supported"
                results.append(item)
                if on_result:
                    on_result(dict(item))
                continue

            if x_view is None:
                item["status"] = "skipped"
                meta = (view_meta or {}).get(vname, {})
                miss_reason = meta.get("reason", "missing_view_feature")
                item["reason"] = f"missing_view_feature:{miss_reason}"
                results.append(item)
                if on_result:
                    on_result(dict(item))
                continue

            if model is None:
                item["status"] = "unavailable"
                item["reason"] = "model_not_loaded"
                results.append(item)
                if on_result:
                    on_result(dict(item))
                continue

            x_model = x_view
            expected_model_dim = _expected_dim_for_model(ens, mname)
            if expected_model_dim is not None:
                adj_row, dim_note = _coerce_row_dim(
                    np.asarray(x_view).reshape(-1),
                    expected_model_dim,
                )
                x_model = adj_row.reshape(1, -1)
                if dim_note:
                    item["input_adjust"] = dim_note

            try:
                if mtype == "numpy":
                    x_np = np.asarray(x_model, dtype=np.float32)
                    proba = model.predict_proba(x_np)
                    score = float(proba[0, 1])
                    pred = int(score > 0.5)
                elif mtype == "pytorch":
                    if torch is None:
                        raise RuntimeError("torch is not available")
                    x_dtype = torch.long if _input_dtype(mname) == "long" else torch.float32
                    x_t = torch.tensor(x_model, dtype=x_dtype)

                    try:
                        device = next(model.parameters()).device
                    except StopIteration:
                        device = torch.device("cpu")

                    model.eval()
                    with torch.no_grad():
                        out = model(x_t.to(device))
                        if isinstance(out, tuple):
                            out = out[0]
                        if out.shape[-1] == 1:
                            score = float(out.squeeze(-1).detach().cpu().numpy()[0])
                        else:
                            score = float(torch.softmax(out, dim=1)[:, 1].detach().cpu().numpy()[0])
                        pred = int(score > 0.5)
                else:
                    raise RuntimeError(f"unsupported engine: {mtype}")

                item["status"] = "ok"
                item["score"] = score
                item["prediction"] = pred
            except Exception as e:
                item["status"] = "error"
                item["reason"] = str(e)

            results.append(item)
            if on_result:
                on_result(dict(item))

    return results



# =============================================================================
#  5. MD5 校验工具函数
# =============================================================================

def _file_md5(path: str) -> str:
    """计算文件 MD5 哈希，用于模型完整性校验。"""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================================================================
#  7. 临时文件安全清理
# =============================================================================

@contextmanager
def _tmp_upload(suffix: str = ".bin"):
    """安全临时文件上下文管理器，确保异常路径下也能清理。"""
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# =============================================================================
#  nkrepo SHA256 + MD5 哈希库预检（命中直出 Malicious，跳过模型）
#  + fuzzy 模糊哈希库第三/四级预检（ssdeep / imphash / authentihash / tlsh）
# =============================================================================

_sha256_db = None
_md5_db = None
_fuzzy_db = None


def _active_sig_dir() -> str:
    """解析当前生效的签名库目录（版本化发布后的单一代码路径）。

    优先级：HASH_DB_DIR/current（symlink，Linux 生产用）
          → HASH_DB_DIR/releases/CURRENT 指针文件（Windows 无符号链接权限时的回退）
          → HASH_DB_DIR 本身（首次部署 / 未做过版本化发布）。
    """
    root = config.HASH_DB_DIR
    cur = os.path.join(root, "current")
    if os.path.isdir(cur):  # isdir 会穿透 symlink
        try:
            return os.path.realpath(cur)
        except OSError:
            pass
    ptr = os.path.join(root, "releases", "CURRENT")
    if os.path.isfile(ptr):
        try:
            with open(ptr, "r", encoding="utf-8") as f:
                ver = f.read().strip()
            d = os.path.join(root, "releases", ver)
            if ver and os.path.isdir(d):
                return d
        except OSError:
            pass
    return root


def _copy_sig_family(src_dir: str, dst_dir: str, base: str) -> bool:
    """复制一族签名库（<base>.db.shards/ + <base>.db.bloom/）到 staging。

    排除 -wal/-shm 残留与 *.legacy/*.tmp；任一 shards 目录存在即返回 True。
    """
    ok = False
    for suffix in (".db.shards", ".db.bloom"):
        src = os.path.join(src_dir, base + suffix)
        if not os.path.isdir(src):
            continue
        ok = True

        def _ignore(_src, names, _suffix=suffix):
            return [n for n in names
                    if n.endswith(("-wal", "-shm", ".legacy", ".tmp"))]

        shutil.copytree(src, os.path.join(dst_dir, base + suffix),
                        ignore=_ignore, dirs_exist_ok=True)
    return ok


def _vacuum_shards(db_obj, sids) -> Dict[str, Any]:
    """对指定分片逐个 VACUUM（回收 INSERT 造成的页碎片）。失败仅告警不阻断。"""
    t0 = time.time()
    done = 0
    for sid in sids:
        p = db_obj._shard_path(sid)
        if not os.path.exists(p):
            continue
        try:
            c = sqlite3.connect(p)
            try:
                c.execute("VACUUM")
            finally:
                c.close()
            done += 1
        except sqlite3.Error as e:
            logging.getLogger("codefender.engine").warning(
                "[sigupdate] VACUUM 分片失败(忽略) %s: %s", p, e)
    return {"vacuumed_shards": done, "seconds": round(time.time() - t0, 1)}


def _build_hash_dbs(sig_dir: str, log) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """按当前 config 在给定目录构建三库实例（不触碰全局引用），失败独立降级。

    降级粒度：sha256 库挂 → 双哈希全降；仅 md5 库挂 → 保留 sha256 预检；
    fuzzy/tlsh 库挂 → 独立降级，不影响双哈希预检。本函数不抛异常。

    Returns:
        ({"sha256"|"md5"|"fuzzy": db}, {"族名": "失败原因"})
    """
    dbs: Dict[str, Any] = {}
    problems: Dict[str, str] = {}
    try:
        dbs["sha256"] = nkrepo_scanner.HashSignatureDB(
            os.path.join(sig_dir, "sha256.db"),
            shard_count=config.HASH_DB_SHARDS,
            bloom_fp_rate=config.HASH_DB_FP_RATE,
            max_open_shards=config.HASH_DB_MAX_OPEN,
            layout=config.HASH_DB_LAYOUT,
        )
        log.info("[hashdb] SHA256 签名库就绪: %s 条", f"{dbs['sha256'].count:,}")
    except Exception as e:
        problems["sha256"] = str(e)
        log.warning("[hashdb] SHA256 库不可用，双库降级为纯模型检测: %s", e)
        return dbs, problems          # md5 预检依赖 sha256 的可用性判断，直接放弃

    if os.path.isdir(os.path.join(sig_dir, "md5.db.shards")):
        try:
            dbs["md5"] = nkrepo_scanner.HashSignatureDB(
                os.path.join(sig_dir, "md5.db"),
                shard_count=config.HASH_DB_SHARDS,
                bloom_fp_rate=config.HASH_DB_FP_RATE,
                max_open_shards=config.HASH_DB_MAX_OPEN,
                layout=config.HASH_DB_LAYOUT,
                hash_algo="md5",
            )
            log.info("[hashdb] MD5 签名库就绪: %s 条", f"{dbs['md5'].count:,}")
        except Exception as e:
            problems["md5"] = str(e)
            log.warning("[hashdb] MD5 库不可用，降级（仅 SHA256 预检）: %s", e)

    # fuzzy 模糊哈希库 (5 表 256 分片): 独立降级, 挂了不影响 sha256/md5 预检
    if config.FUZZY_DB_ENABLED and os.path.isdir(os.path.join(sig_dir, "fuzzy.db.shards")):
        try:
            dbs["fuzzy"] = nkrepo_scanner.FuzzySignatureDB(
                os.path.join(sig_dir, "fuzzy.db"),
                max_open_shards=config.FUZZY_DB_MAX_OPEN,
                layout="hex",
            )
            log.info("[hashdb] Fuzzy 模糊哈希库就绪: %s 条 %s",
                     f"{dbs['fuzzy'].count:,}", dbs["fuzzy"]._counts)
        except Exception as e:
            problems["fuzzy"] = str(e)
            log.warning("[hashdb] Fuzzy 库不可用，降级（仅双哈希预检）: %s", e)
    elif not config.FUZZY_DB_ENABLED:
        log.info("[hashdb] Fuzzy 预检已禁用 (CODEFENDER_FUZZY_DB_ENABLED=0)")
    return dbs, problems


def _log_hash_db_summary(dbs: Dict[str, Any], log) -> None:
    """一行总结，便于一眼确认过滤引擎的有效模式。"""
    if not dbs:
        log.info("[hashdb] 过滤引擎未启用 → 所有样本走模型集成（纯模型模式）")
        return
    log.info("[hashdb] 过滤引擎已启用: sha256=%s md5=%s fuzzy=%s",
             f"{dbs['sha256'].count:,}" if dbs.get("sha256") is not None else "关闭",
             f"{dbs['md5'].count:,}" if dbs.get("md5") is not None else "关闭",
             f"{dbs['fuzzy'].count:,}" if dbs.get("fuzzy") is not None else "关闭")


def _log_engine_context(log) -> None:
    """启动横幅：档位 / 覆盖文件是否生效 / 过滤引擎是否硬要求。

    这三个值决定"当前进程到底该跑什么形态"，是排查"配置没生效"的第一现场。
    """
    log.info("[startup] 环境档位=%s 运行时覆盖文件=%s%s", config.ENV_PROFILE,
             "启用" if config.RUNTIME_CFG_FILE_ENABLED else "禁用",
             f"（{config.RUNTIME_CFG_DISABLED_REASON}）"
             if not config.RUNTIME_CFG_FILE_ENABLED else "")
    if getattr(config, "RUNTIME_CFG_SKIPPED", False):
        log.warning("[startup] ⚠ 发现 %s，但当前档位不加载它 → 已忽略（生产档位特征，"
                    "避免开发期开关被带进容器）。要生效请用环境变量。",
                    config.RUNTIME_CFG_FILE)
    if getattr(config, "RUNTIME_CFG_APPLIED", None):
        log.warning("[startup] ⚠ 已按 %s 覆盖配置: %s（开发档位特征；生产请改用环境变量）",
                    config.RUNTIME_CFG_FILE, config.RUNTIME_CFG_APPLIED)
    if getattr(config, "RUNTIME_CFG_ERROR", ""):
        log.error("[startup] runtime_config.json 解析失败，该文件已被整份忽略: %s",
                  config.RUNTIME_CFG_ERROR)
    log.info("[startup] 过滤引擎要求=%s", "硬要求（缺库拒绝启动）"
             if config.REQUIRE_HASH_DB else "允许降级为纯模型")


def _enforce_hash_db_requirement(dbs: Dict[str, Any], log) -> None:
    """生产档位强校验：CODEFENDER_REQUIRE_HASH_DB=1 时缺库就拒绝启动。

    动机：本项目对"哈希库缺失"的历史行为是**静默降级为纯模型**——服务照常返回
    200、样本照常出分，只是预检再也不命中。开发期这很方便；生产期这是漏检，
    而且签名目录写错、挂载漏掉都完全没人发现。生产要的是响的失败。
    抛出的异常会冒泡到模块 import → uvicorn 退出 → supervisord 反复重试，
    在 `docker logs` / `supervisorctl status` 里一眼可见。
    """
    if not config.REQUIRE_HASH_DB:
        return
    if not config.HASH_DB_ENABLED:
        raise RuntimeError(
            "[hashdb] CODEFENDER_REQUIRE_HASH_DB=1（过滤引擎为硬要求）与 "
            "CODEFENDER_HASH_DB_ENABLED=0（关闭哈希预检）冲突：生产档位不允许纯模型模式。\n"
            "  · 想跑纯模型对照（本机开发）：CODEFENDER_ENV=dev + 去掉 REQUIRE_HASH_DB，"
            "或用 dev_model_only.cmd / dev_model_only.sh 启动\n"
            "  · 生产要降级为纯模型：改 codefender.ini 的 environment=，"
            "显式把 CODEFENDER_REQUIRE_HASH_DB 设为 0")
    want = ["sha256", "md5"] + (["fuzzy"] if config.FUZZY_DB_ENABLED else [])
    missing = [k for k in want if dbs.get(k) is None]
    if missing:
        raise RuntimeError(
            f"[hashdb] CODEFENDER_REQUIRE_HASH_DB=1：要求以 {want} 全部就绪，但缺失 {missing}。\n"
            f"  签名库目录={_active_sig_dir()}\n"
            f"  · Docker：签名库已在构建期打进镜像，容器内 {_active_sig_dir()} 应直接含 "
            f"sha256.db.shards / md5.db.shards / fuzzy.db.shards（**不要**用 -v 挂宿主机目录，"
            f"挂载会让容器读到与镜像脱钩的旧库）；镜像不对就重新构建："
            f"python docker/stage_signatures.py && docker build\n"
            f"  · 首次部署：靠 /update-signatures 完成一次发布（releases/v<ts> + current）\n"
            f"  · 确实想允许降级：把 CODEFENDER_REQUIRE_HASH_DB 设为 0")
    log.info("[hashdb] 硬要求校验通过：%s 全部就绪", want)


def _init_hash_dbs():
    """启动时初始化哈希库（默认失败自动降级为纯模型模式，功能不回退）。

    ⚠️ 历史坑（2026-09-23）：本函数曾漏写 `global _fuzzy_db`，赋值落到局部变量，
    fuzzy 库照常加载并打印"就绪"，但模块全局恒为 None → fuzzy/tlsh 预检静默失效。
    现在三库统一由 _build_hash_dbs 返回、在同一处赋值，结构上不再可能漏项。

    ⚠️ 降级行为在 CODEFENDER_REQUIRE_HASH_DB=1（生产推荐）下被禁用：缺库即拒绝启动，
    见 _enforce_hash_db_requirement。
    """
    global _sha256_db, _md5_db, _fuzzy_db
    log = logging.getLogger("codefender.engine")
    if not config.HASH_DB_ENABLED:
        _enforce_hash_db_requirement({}, log)     # 生产档位下这里会直接抛错
        log.info("[hashdb] 哈希库预检已禁用 (CODEFENDER_HASH_DB_ENABLED=0)")
        log.info("[hashdb] 过滤引擎未启用 → 所有样本走模型集成（纯模型模式）")
        return
    dbs, problems = _build_hash_dbs(_active_sig_dir(), log)
    with _STATE_LOCK:
        _sha256_db = dbs.get("sha256")
        _md5_db = dbs.get("md5")
        _fuzzy_db = dbs.get("fuzzy")
    if problems:
        log.warning("[hashdb] 启动时降级的族: %s", problems)
    _log_hash_db_summary(dbs, log)
    _enforce_hash_db_requirement(dbs, log)


_init_hash_dbs()
_log_engine_context(logging.getLogger("codefender.engine"))


def _engine_mode() -> str:
    """当前检测链路形态 —— 一句话回答"预检到底生效没有"。

    model_only            : 三库全关/全不可用 → 所有样本走模型集成
    hash_db+model         : config 声明的族全部就绪（sha256/md5[/fuzzy]）
    hash_db_partial+model : 部分族缺失，剩余族仍在预检（如只有 sha256 可用）
    """
    have = {"sha256": _sha256_db, "md5": _md5_db, "fuzzy": _fuzzy_db}
    if not config.HASH_DB_ENABLED or all(v is None for v in have.values()):
        return "model_only"
    want = ["sha256", "md5"] + (["fuzzy"] if config.FUZZY_DB_ENABLED else [])
    return "hash_db+model" if all(have[k] is not None for k in want) \
        else "hash_db_partial+model"


def _hash_db_state() -> Dict[str, Any]:
    """三库运行时状态（/health、/metrics、/admin/config 共用同一口径）。

    enabled=True 但某族 count 为 None = 该族加载失败已降级，不是"没生效"。
    """
    return {
        "enabled": bool(config.HASH_DB_ENABLED),
        "fuzzy_enabled": bool(config.FUZZY_DB_ENABLED),
        "mode": _engine_mode(),
        "dir": _active_sig_dir(),
        "sha256": _sha256_db.count if _sha256_db is not None else None,
        "md5": _md5_db.count if _md5_db is not None else None,
        "fuzzy": _fuzzy_db.count if _fuzzy_db is not None else None,
    }


def _close_hash_dbs() -> int:
    """摘掉三库全局引用并关闭句柄，返回成功关闭的数量。"""
    global _sha256_db, _md5_db, _fuzzy_db
    with _STATE_LOCK:
        olds = [_sha256_db, _md5_db, _fuzzy_db]
        _sha256_db, _md5_db, _fuzzy_db = None, None, None
    closed = 0
    for db in olds:
        if db is None:
            continue
        try:
            db.close()
            closed += 1
        except Exception as e:
            logging.getLogger("codefender.engine").warning(
                "[hashdb] 关闭旧库句柄失败(忽略): %s", e)
    return closed


def _reload_hash_dbs(reason: str = "") -> Dict[str, Any]:
    """按当前 config 值重建三库引用 —— 免重启切换过滤引擎的落地点。

    **先建后换**：新实例装载完成前旧库继续承接查询，不留"配置已改、查询还是旧行为"
    的空窗。实测整库装载约 9s，若先摘引用再建，这 9s 内所有样本都会走模型集成 ——
    正是"改了配置却没生效/行为对不上"的经典错觉来源。
    两套句柄短暂共存可以接受（分片均为只读，max_open_shards=16 的 LRU 上限不变），
    旧句柄只在新实例就位后才关闭。

    关闭方向（HASH_DB_ENABLED=0）无需装载，直接释放引用，瞬时生效。
    """
    global _sha256_db, _md5_db, _fuzzy_db
    log = logging.getLogger("codefender.engine")
    tag = f" ({reason})" if reason else ""

    if not config.HASH_DB_ENABLED:
        closed = _close_hash_dbs()
        log.info("[hashdb] 过滤引擎已关闭%s → 纯模型模式（释放 %d 个旧句柄）", tag, closed)
        if config.REQUIRE_HASH_DB:
            # 运行时热切换是显式运维动作，不阻止；但生产档位下必须喊出来：
            # 这是内存内生效、重启进程即恢复全引擎，绝不落盘（见 config.save_runtime_cfg_file）。
            log.warning("[hashdb] ⚠ 生产档位(REQUIRE_HASH_DB=1)下被运行时关闭哈希预检"
                        "%s → 当前为纯模型模式；重启进程即恢复全引擎", tag)
        return _hash_db_state()

    dbs, problems = _build_hash_dbs(_active_sig_dir(), log)
    with _STATE_LOCK:
        olds = [_sha256_db, _md5_db, _fuzzy_db]
        _sha256_db = dbs.get("sha256")
        _md5_db = dbs.get("md5")
        _fuzzy_db = dbs.get("fuzzy")

    closed = 0
    for db in olds:
        if db is None:
            continue
        try:
            db.close()
            closed += 1
        except Exception as e:
            log.warning("[hashdb] 关闭旧库句柄失败(忽略): %s", e)

    _log_hash_db_summary(dbs, log)
    st = _hash_db_state()
    log.info("[hashdb] 配置热切换完成%s: mode=%s enabled=%s sha256=%s md5=%s fuzzy=%s (关闭旧句柄 %d 个)",
             tag, st["mode"], st["enabled"], st["sha256"], st["md5"], st["fuzzy"], closed)
    if problems:
        log.warning("[hashdb] 热切换中降级的族: %s", problems)
        if config.REQUIRE_HASH_DB:
            log.error("[hashdb] ⚠ 生产档位要求三库齐备，但热切换后有族不可用: %s。"
                      "旧库已释放，当前处于降级形态；建议修复后再次热切换或重启进程。",
                      problems)
    return st


def _lookup_hashes(md5_hex: str, sha256_hex: str, file_size: int):
    """双库查询：先 SHA256（更抗碰撞、覆盖广）后 MD5（补漏老样本哈希）。

    Returns:
        (hit_dict, source) 命中时；否则 (None, None)。source ∈ {"sha256_db", "md5_db"}
    """
    if _sha256_db is None and _md5_db is None:
        return None, None
    hits, source = None, None
    if _sha256_db is not None:
        hits = _sha256_db.check_hash(sha256_hex, file_size=file_size)
        source = "sha256_db"
    if not hits and _md5_db is not None:
        hits = _md5_db.check_hash(md5_hex, file_size=file_size)
        source = "md5_db"
    if not hits:
        return None, None
    return hits[0], source


def _compute_fuzzy_hashes(content: bytes) -> Dict[str, Optional[str]]:
    """计算预检用的 fuzzy 哈希（单项失败/缺依赖自动降级为 None）。

    - ssdeep: ppdeep 纯 Python, 仅对 ≤ FUZZY_DB_MAX_BYTES 的文件计算 (默认 256KB,
      上游实测 1MB≈24s, 预检为同步路径必须限流; 超限跳过——截断数据算出的
      ssdeep 与库中全文件签名不匹配, 无意义)
    - imphash / authentihash: 仅 PE 样本, pefile 解析毫秒级, 不限大小
    """
    out: Dict[str, Optional[str]] = {"ssdeep": None, "imphash": None, "authentihash": None}
    try:
        if len(content) <= config.FUZZY_DB_MAX_BYTES:
            out["ssdeep"] = nkrepo_staticinfo.compute_ssdeep(content)
    except Exception:
        pass
    try:
        out["imphash"] = nkrepo_staticinfo.compute_imphash(content)
    except Exception:
        pass
    try:
        out["authentihash"] = nkrepo_staticinfo.compute_authentihash(content)
    except Exception:
        pass
    return out


def _compute_tlsh_key(content: bytes, max_bytes: Optional[int] = None) -> Optional[str]:
    """第四级 tlsh 的库口径键 ('t1'+70hex 小写); 超限/不可用返回 None

    独立于 _compute_fuzzy_hashes: tlsh 纯 Python 实测 ~0.53 MB/s，只在
    ssdeep/imphash/authentihash 全未命中时才调用，按档位限流:
    在线单文件 FUZZY_DB_TLSH_MAX_BYTES (默认 1MB) / 离线批量 FUZZY_DB_TLSH_MAX_BYTES_OFFLINE (默认 16MB)。
    """
    try:
        return nkrepo_staticinfo.compute_tlsh_db_key(
            content, max_bytes=max_bytes if max_bytes is not None
            else config.FUZZY_DB_TLSH_MAX_BYTES)
    except Exception:
        return None


def _lookup_fuzzy(content: bytes, file_size: int, tlsh_max_bytes: Optional[int] = None):
    """第三/四级预检：fuzzy 模糊哈希库。

    级序（任一级命中即返回）:
      ssdeep → imphash → authentihash → tlsh

    前三项一起算出后查一次；全部未命中才计算 tlsh（纯 Python 实测 ~0.53 MB/s，
    只在"前三级都没命中"时才付这份代价，按 tlsh_max_bytes 档位限流：
    在线默认 1MB / 离线批量默认 16MB）。

    带 file_size 做大小比对——imphash/vhash/tlsh 类哈希对常见壳/运行时/近似样本
    存在碰撞（TLSH 更是局部敏感哈希, 不同文件可同值），大小校验可显著抑制误报。

    Returns:
        (hit_dict, "fuzzy_db") 命中时；否则 (None, None)。
    """
    if _fuzzy_db is None:
        return None, None
    fz = _compute_fuzzy_hashes(content)
    try:
        hits = _fuzzy_db.check_by_computed_hashes(
            ssdeep=fz.get("ssdeep"),
            imphash_hex=fz.get("imphash"),
            authentihash_hex=fz.get("authentihash"),
            file_size=file_size,
        ) if any(fz.values()) else []
        if not hits:
            # 第四级: tlsh（字符串型, 需库口径 't1'+70hex 小写）
            tlsh_key = _compute_tlsh_key(content, max_bytes=tlsh_max_bytes)
            if tlsh_key:
                hits = _fuzzy_db.check_by_computed_hashes(
                    tlsh=tlsh_key, file_size=file_size)
    except Exception as e:
        logging.getLogger("codefender.engine").warning("[hashdb] fuzzy 查询异常(忽略): %s", e)
        return None, None
    if not hits:
        return None, None
    return hits[0], "fuzzy_db"


def _build_hash_hit_result(md5_hex: str, sha256_hex: str, crc32: str,
                           file_name: str, file_size: int, hit: dict, source: str) -> Dict[str, Any]:
    """组装哈希命中结果：结构与 format_scan_result 完全同构，仅扩展 Source / HashMatch。"""
    return {
        "MD5": md5_hex, "SHA256": sha256_hex, "CRC32": crc32,
        "FileName": file_name, "FileSize": file_size,
        "Status": 1, "StatusLabel": "Malicious", "IsMalicious": True, "Score": 1.0,
        "Source": source,
        "ScanResult": {
            "VirusName": hit.get("name") or "KnownMalware",  # v4 库不存名称, 命中统一显示通用标签
            "Packed": {"IsPacked": False, "PackerName": "", "IsArchive": False, "ArchiveName": ""},
            "PerModelScores": {}, "PerModelPreds": {},
            "DriftEvidence": {"surface": 0.0, "structure": 0.0, "global": 0.0},
            "SampleDriftType": "normal", "AnomalyScore": 0.0, "IsDriftCandidate": False,
            # HashMatch 不暴露 name/size —— 双哈希库 v4 起不存检出名称 (统一 KnownMalware);
            # fuzzy 库虽存 name/size 但命中即恶意, 大小无比对价值, 口径与双哈希库一致。
            # fuzzy 命中额外带 fuzzy_type/sha256 (关联的原始样本哈希) 透出。
            "HashMatch": {k: v for k, v in hit.items() if k not in ("name", "size")},
        },
    }


def _hash_precheck(content: bytes, file_name: str, file_size: int) -> Optional[Dict[str, Any]]:
    """内存四级预检（/predict-single 用）：sha256 → md5 → fuzzy(ssdeep/imphash/authentihash) → tlsh，任一命中返回结果 dict，全部未命中返回 None。"""
    if _sha256_db is None and _md5_db is None and _fuzzy_db is None:
        return None
    md5_hex, _sha1_hex, sha256_hex = nkrepo_scanner.compute_hashes_bytes(content)
    crc32 = format(zlib.crc32(content) & 0xFFFFFFFF, "08x")
    hit, source = _lookup_hashes(md5_hex, sha256_hex, file_size)
    if hit is None:
        hit, source = _lookup_fuzzy(content, file_size)
    if hit is None:
        return None
    return _build_hash_hit_result(md5_hex, sha256_hex, crc32, file_name, file_size, hit, source)


def _hash_precheck_file(path: str) -> Optional[Dict[str, Any]]:
    """流式四级哈希预检（/predict-directory 用，1MB 分块避免整文件载入内存）。

    fuzzy 级需要文件内容算哈希: 未命中双哈希库后才读文件（绝大多数干净文件
    走不到这一步），读入上限 64MB 防御异常大文件；tlsh 用离线档限流
    FUZZY_DB_TLSH_MAX_BYTES_OFFLINE（默认 16MB，实测 ~0.53 MB/s ≈ ≤30s/文件）。
    """
    if _sha256_db is None and _md5_db is None and _fuzzy_db is None:
        return None
    md5_h, sha256_h = hashlib.md5(), hashlib.sha256()
    size = 0
    crc = 0
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            md5_h.update(chunk)
            sha256_h.update(chunk)
            crc = zlib.crc32(chunk, crc)
            size += len(chunk)
    md5_hex, sha256_hex = md5_h.hexdigest(), sha256_h.hexdigest()
    crc32 = format(crc & 0xFFFFFFFF, "08x")
    hit, source = _lookup_hashes(md5_hex, sha256_hex, size)
    if hit is None and _fuzzy_db is not None and size <= 64 * 1024 * 1024:
        try:
            with open(path, "rb") as f:
                content = f.read()
            hit, source = _lookup_fuzzy(
                content, size, tlsh_max_bytes=config.FUZZY_DB_TLSH_MAX_BYTES_OFFLINE)
        except OSError:
            hit, source = None, None
    if hit is None:
        return None
    return _build_hash_hit_result(md5_hex, sha256_hex, crc32, os.path.basename(path), size, hit, source)


# =============================================================================
#  Endpoints: 探针 / 指标
# =============================================================================

# 1. 存活探针（不碰模型）
@app.get("/livez")
def livez() -> Dict[str, Any]:
    """存活探针：只检查进程是否存活，不接触模型。"""
    uptime_sec = int(time.time() - _START_TIME)
    return {
        "alive": True,
        "uptime_sec": uptime_sec,
        "uptime_human": datetime.utcfromtimestamp(uptime_sec).strftime("%H:%M:%S"),
    }


# 1. 就绪探针（检查模型是否已加载）
@app.get("/readyz")
def readyz():
    """就绪探针：检查模型是否已加载并可服务。"""
    if _ENSEMBLE is None:
        return JSONResponse(
            status_code=503,
            content={
                "ready": False,
                "reason": "model not loaded",
                "model_path": MODEL_PATH,
            },
        )
    return {
        "ready": True,
        "model_count": _ENSEMBLE.K,
        "view_count": _ENSEMBLE.V,
    }


# 4. 运行时指标端点
@app.get("/metrics")
def metrics() -> Dict[str, Any]:
    """Prometheus 兼容的运行时指标端点。"""
    with _METRICS_LOCK:
        m = dict(_METRICS)
    m["uptime_sec"] = int(time.time() - _START_TIME)
    m["models_loaded"] = bool(_ENSEMBLE)
    if _ENSEMBLE:
        m["model_count"] = _ENSEMBLE.K
    # 过滤引擎状态（与 /health 同口径）
    _hdb = _hash_db_state()
    m["hash_db_enabled"] = _hdb["enabled"]
    m["hash_db_mode"] = _hdb["mode"]
    m["hash_db_sha256"] = _hdb["sha256"] or 0
    m["hash_db_md5"] = _hdb["md5"] or 0
    m["hash_db_fuzzy"] = _hdb["fuzzy"] or 0
    return m


@app.get("/health")
def health() -> Dict[str, Any]:
    try:
        ens = _load_ensemble()
        # 5. 模型 MD5 完整性校验
        model_md5 = ""
        if os.path.exists(MODEL_PATH):
            try:
                model_md5 = _file_md5(MODEL_PATH)
            except OSError:
                model_md5 = "read_error"

        hdb = _hash_db_state()
        base = {
            "status": "ok",
            # pid / started_at：判断"配置改完没生效"的第一现场证据 —— 重启后这两个
            # 值必须变化。若不变，说明你改的配置根本没进到这个进程（端口被旧进程占着、
            # 或者重启的是别的东西）。
            "pid": os.getpid(),
            "started_at": datetime.fromtimestamp(_START_TIME).strftime("%Y-%m-%d %H:%M:%S"),
            # env=dev 是本机开发档位（可读写 runtime_config.json），prod 是容器/生产档位
            # （覆盖文件被忽略）。engine_mode 一眼回答"预检到底生效没有"。
            "env": config.ENV_PROFILE,
            "engine_mode": hdb["mode"],
            "runtime_cfg_file": config.RUNTIME_CFG_FILE,
            "runtime_cfg_file_enabled": config.RUNTIME_CFG_FILE_ENABLED,
            "runtime_cfg_disabled_reason": config.RUNTIME_CFG_DISABLED_REASON,
            "runtime_cfg_applied": list(getattr(config, "RUNTIME_CFG_APPLIED", [])),
            "runtime_cfg_error": getattr(config, "RUNTIME_CFG_ERROR", ""),
            "require_hash_db": bool(config.REQUIRE_HASH_DB),
            "model_path": MODEL_PATH,
            "model_md5": model_md5,
            "model_count": ens.K,
            "view_count": ens.V,
            "views": list(ens.view_groups.keys()),
            "malgraph": {
                "enabled": MALGRAPH_ENABLED,
                "checkpoint": _resolve_malgraph_ckpt_path(),
                "vocab": _resolve_malgraph_vocab_path(),
            },
            # 过滤引擎（四级哈希签名库预检）实际状态：不接受日志即可确认开关是否生效
            # enabled=False → 三库恒为 None 且 count 全为 null，所有样本走模型。
            "hash_db": hdb,
        }
        if MALGRAPH_ENABLED:
            try:
                rt = _load_malgraph_runtime()
                base["malgraph"]["status"] = "ready"
                base["malgraph"]["device"] = str(rt["device"])
                base["malgraph"]["params"] = rt.get("params", {})
                base["malgraph"]["vocab_max_size"] = rt.get("vocab_max_size")
                base["malgraph"]["missing_keys"] = rt.get("missing_keys", [])
                base["malgraph"]["unexpected_keys"] = rt.get("unexpected_keys", [])
            except Exception as e:
                base["malgraph"]["status"] = "not_ready"
                base["malgraph"]["reason"] = str(e)
        return base
    except Exception as e:
        return {
            "status": "error",
            "model_path": MODEL_PATH,
            "reason": str(e),
        }


# ──────────────────────────────────────────────────────────────────
# 病毒库信息查询
# ──────────────────────────────────────────────────────────────────

@app.get("/model-info")
def model_info() -> Dict[str, Any]:
    """返回当前病毒库/集成模型的完整档案信息。"""
    result: Dict[str, Any] = {}
    try:
        st = os.stat(MODEL_PATH)
        model_md5 = ""
        try:
            model_md5 = _file_md5(MODEL_PATH)
        except OSError:
            model_md5 = "read_error"
        result["file"] = {
            "path": MODEL_PATH,
            "size_bytes": st.st_size,
            "size_mb": round(st.st_size / (1024 * 1024), 2),
            "last_modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
            "md5": model_md5,
        }
    except OSError:
        result["file"] = {"path": MODEL_PATH, "status": "not_found"}
    if _ENSEMBLE is None:
        result["status"] = "not_loaded"
        return result
    ens = _ENSEMBLE
    result["status"] = "loaded"
    try:
        result["ensemble"] = {"model_count": ens.K, "view_count": ens.V}
        models: List[Dict[str, Any]] = []
        for mname in ens._model_names:
            mtype = ens._model_types.get(mname, "unknown")
            model_obj = ens._models.get(mname)
            models.append({"name": mname, "type": mtype, "loaded": model_obj is not None})
        result["models"] = models
        views: Dict[str, Any] = {}
        for vname, mnames in ens.view_groups.items():
            vg_cfg = config.VIEW_GROUPS.get(vname, {})
            views[vname] = {
                "label": vg_cfg.get("label", vname),
                "attck": vg_cfg.get("attck", ""),
                "models": mnames,
                "indices": ens._view_indices.get(vname, []),
            }
        result["views"] = views
        result["sdd"] = {"initialized": _SDD_ENGINE is not None}
        result["malgraph"] = {"enabled": MALGRAPH_ENABLED}
        if MALGRAPH_ENABLED:
            result["malgraph"]["checkpoint"] = _resolve_malgraph_ckpt_path()
            result["malgraph"]["vocab"] = _resolve_malgraph_vocab_path()
            result["malgraph"]["loaded"] = _MALGRAPH_RUNTIME is not None
    except Exception:
        logging.error("model-info build failed:\n%s", traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Failed to build model info: {traceback.format_exc()}",
        )
    return result


# ──────────────────────────────────────────────────────────────────
# 病毒库热更新
# ──────────────────────────────────────────────────────────────────

@app.post("/reload-model")
def reload_model(
    model_path: Optional[str] = Query(
        default=None,
        description="新模型文件绝对路径。不传则重新加载当前 MODEL_PATH。",
    ),
) -> Dict[str, Any]:
    """热更新集成模型。不传参则原地重载；传参则切换到新路径。"""
    global _ENSEMBLE, _SDD_ENGINE, _MALGRAPH_RUNTIME, MODEL_PATH
    target_path = model_path or MODEL_PATH
    if not os.path.isfile(target_path):
        raise HTTPException(400, detail=f"model file not found: {target_path}")
    old_ens = _ENSEMBLE
    old_info: Dict[str, Any] = {"model_path": MODEL_PATH}
    if old_ens is not None:
        old_info["model_count"] = old_ens.K
        old_info["view_count"] = old_ens.V
        try:
            old_info["file_size"] = os.path.getsize(MODEL_PATH)
        except OSError:
            old_info["file_size"] = 0
    else:
        old_info["model_count"] = 0
        old_info["view_count"] = 0
        old_info["file_size"] = 0
    try:
        new_ens = MultiModelEnsemble.load(target_path)
    except Exception:
        logging.error('reload-model 加载新模型失败:\n%s', traceback.format_exc())
        raise HTTPException(
            status_code=500,
            detail=f"Failed to load model: {traceback.format_exc()}",
        )
    with _STATE_LOCK:
        _ENSEMBLE = new_ens
        _SDD_ENGINE = None
        _MALGRAPH_RUNTIME = None
        if model_path:
            os.environ["CODEFENDER_MODEL_PATH"] = target_path
            MODEL_PATH = target_path
    new_info: Dict[str, Any] = {
        "model_path": target_path,
        "model_count": new_ens.K,
        "view_count": new_ens.V,
        "models": [
            {"name": m, "type": new_ens._model_types.get(m, "?")}
            for m in new_ens._model_names
        ],
    }
    try:
        new_info["file_size"] = os.path.getsize(target_path)
    except OSError:
        new_info["file_size"] = 0
    return {"status": "reloaded", "previous": old_info, "current": new_info}


# ──────────────────────────────────────────────────────────────────
# 签名库周更上传（hdb 一条龙：导入 → finalize → 校验 → VACUUM → 发布 → 热切换）
# 上传的是 ClamAV hdb 系明文文件（3 字段行喂 sha256/md5 库，8 字段行喂 fuzzy 库，
# 一个文件混装即可）。全程在 staging 副本上操作，最后一步才原子换引用，失败自动保留旧库。
# ──────────────────────────────────────────────────────────────────

def _sig_families() -> List[str]:
    """需要参与更新的库族名（md5 目录缺失时自动跳过，与 _init_hash_dbs 行为一致）。"""
    fams = ["sha256"]
    if os.path.isdir(os.path.join(_active_sig_dir(), "md5.db.shards")):
        fams.append("md5")
    if config.FUZZY_DB_ENABLED and os.path.isdir(
            os.path.join(_active_sig_dir(), "fuzzy.db.shards")):
        fams.append("fuzzy")
    return fams


def _build_sig_instances(sig_dir: str) -> Dict[str, Any]:
    """按 _init_hash_dbs 同参数在指定目录构建三个库实例（任何一族失败即抛异常，不降级——
    发布路径不允许半残状态，与启动时的降级语义不同）。"""
    out: Dict[str, Any] = {}
    out["sha256"] = nkrepo_scanner.HashSignatureDB(
        os.path.join(sig_dir, "sha256.db"),
        shard_count=config.HASH_DB_SHARDS,
        bloom_fp_rate=config.HASH_DB_FP_RATE,
        max_open_shards=config.HASH_DB_MAX_OPEN,
        layout=config.HASH_DB_LAYOUT,
    )
    if os.path.isdir(os.path.join(sig_dir, "md5.db.shards")):
        out["md5"] = nkrepo_scanner.HashSignatureDB(
            os.path.join(sig_dir, "md5.db"),
            shard_count=config.HASH_DB_SHARDS,
            bloom_fp_rate=config.HASH_DB_FP_RATE,
            max_open_shards=config.HASH_DB_MAX_OPEN,
            layout=config.HASH_DB_LAYOUT,
            hash_algo="md5",
        )
    if config.FUZZY_DB_ENABLED and os.path.isdir(os.path.join(sig_dir, "fuzzy.db.shards")):
        out["fuzzy"] = nkrepo_scanner.FuzzySignatureDB(
            os.path.join(sig_dir, "fuzzy.db"),
            max_open_shards=config.FUZZY_DB_MAX_OPEN,
            layout="hex",
        )
    return out


def _detect_source_format(sample_path: str) -> str:
    """探测签名源文件格式: 'csv' / 'hashbase9' / 'clamav-hdb'（以首个有效行为准）。

    - csv:       日更 CSV（cn_vt*.csv, 22 列, 表头含 sha256/md5/ssdeep）
    - hashbase9: sha256:size:name:ssdeep:tlsh:md5:rich:authentihash:imphash:
    - clamav-hdb: sha256:size:name[:ssdeep:vhash:authentihash:imphash:rich[:tlsh]]
    """
    with open(sample_path, "r", encoding="utf-8-sig", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            low = line.lower()
            if "," in line and "sha256" in low and ("md5" in low or "ssdeep" in low):
                return "csv"
            # 无表头 CSV 兜底: 逗号分段里出现 64 位 hex 字段
            if line.count(",") >= 5:
                cells = [t.strip().lower() for t in line.split(",")]
                if any(len(t) == 64 and all(ch in "0123456789abcdef" for ch in t)
                       for t in cells):
                    return "csv"
            parts = line.split(":")
            if len(parts) < 9:
                return "clamav-hdb"
            f5 = parts[5].strip().lower()
            if len(f5) == 32 and all(ch in "0123456789abcdef" for ch in f5):
                return "hashbase9"
            return "clamav-hdb"
    return "clamav-hdb"


def _detect_hashbase_format(sample_path: str) -> bool:
    """（兼容旧接口）True = hashBase 9 字段 hdb。"""
    return _detect_source_format(sample_path) == "hashbase9"


@app.post("/update-signatures")
def update_signatures(
    file: Optional[UploadFile] = File(
        None, description="上传单个 .csv / .hdb 或 .zip（内含多个）"),
    dir_path: Optional[str] = Query(
        default=None,
        description="服务器本地目录（含日更 CSV 或 00.hdb~ff.hdb，如挂载的 hashBase），与 file 二选一"),
    week_id: Optional[str] = Query(
        default=None,
        description="周/日标识（如 2026W39 或 20260923）：imported_files 以 <week_id>__<文件名> 登记，每次必须换新"),
    malicious_only: bool = Query(
        default=True,
        description="CSV 源专用：跳过无任何威胁标注（category/family/kav/defender/vt）的行"),
    vacuum: bool = Query(
        default=True, description="是否对受影响分片执行 VACUUM（增量更新建议开）"),
) -> Dict[str, Any]:
    """上传/指向签名源（日更 CSV / hdb）→ staging 导入 → 校验 → 发布 releases/v<ts> → 热切换。

    源格式自动探测（逐文件）：
    输入支持单个文件 / .zip 包 / 服务器本地目录。imported_files 以 <week_id>__<文件名>
    登记，同名文件重复投递不会被去重误跳；行级幂等由 INSERT OR IGNORE 保证，
    同一批数据重复喂也安全。重复提交同一输入 → inserted=0 → no_new_rows 不发布。
    """
    log = logging.getLogger("codefender.engine")
    if not config.HASH_DB_ENABLED:
        raise HTTPException(400, detail="hash db disabled (CODEFENDER_HASH_DB_ENABLED=0)")
    # 直接函数调用（测试/脚本）时未传的形参是 FastAPI 的 File/Query 标记对象而非 None,
    # 统一归一化为"实际值或默认值", 否则标记对象恒为真会误判参数二选一
    upload_name = getattr(file, "filename", None) if file is not None else None
    if not isinstance(upload_name, str):
        upload_name = None
    if not isinstance(dir_path, str):
        dir_path = None
    if not isinstance(week_id, str):
        week_id = None
    malicious_only = malicious_only if isinstance(malicious_only, bool) else True
    vacuum = vacuum if isinstance(vacuum, bool) else True
    has_upload = bool(upload_name)
    if has_upload == bool(dir_path):
        raise HTTPException(400, detail="file(上传 .csv/.hdb/.zip) 与 dir_path(本地目录) 必须二选一")

    root = config.HASH_DB_DIR
    build_dir = os.path.join(root, "build")
    os.makedirs(build_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    staging = os.path.join(build_dir, f"staging-{ts}")
    incoming_dir = os.path.join(build_dir, f"incoming-{ts}")
    week = "".join(ch for ch in (week_id or "") if ch.isalnum() or ch in "-_") or ts
    old_counts: Dict[str, Optional[int]] = {}
    new_counts: Dict[str, int] = {}
    inserted_rows: Dict[str, int] = {}
    fmt_count: Dict[str, int] = {}
    csv_stats: Dict[str, int] = {}
    zip_tmp: Optional[str] = None
    src_exts = (".csv", ".hdb")

    try:
        # 2) 收集签名源文件（本地目录 / zip 解包 / 单文件上传，统一落位并带周前缀）
        src_dir = _active_sig_dir()
        fams = _sig_families()
        if not fams:
            raise HTTPException(500, detail="当前签名库目录缺少 sha256.db.shards，无法更新")
        os.makedirs(staging, exist_ok=True)
        os.makedirs(incoming_dir, exist_ok=True)
        sources: List[str] = []
        if dir_path:
            if not os.path.isdir(dir_path):
                raise HTTPException(400, detail=f"dir_path 不是目录: {dir_path}")
            sources = [os.path.join(dir_path, n) for n in sorted(os.listdir(dir_path))
                       if n.lower().endswith(src_exts)]
        else:
            raw_name = os.path.basename(file.filename)
            if os.path.sep in raw_name or "/" in raw_name or raw_name.startswith("."):
                raise HTTPException(400, detail=f"非法文件名: {raw_name!r}")
            if raw_name.lower().endswith(".zip"):
                zip_tmp = os.path.join(build_dir, f"upload-{ts}.zip")
                with open(zip_tmp, "wb") as out:
                    shutil.copyfileobj(file.file, out, length=1024 * 1024)
                try:
                    with zipfile.ZipFile(zip_tmp) as zf:
                        for info in zf.infolist():
                            member = os.path.basename(info.filename)
                            if not member.lower().endswith(src_exts) or member.startswith("."):
                                continue
                            dest = os.path.join(incoming_dir, f"{week}__{member}")
                            with zf.open(info) as fsrc, open(dest, "wb") as fdst:
                                shutil.copyfileobj(fsrc, fdst, length=1024 * 1024)
                            sources.append(dest)
                except zipfile.BadZipFile:
                    raise HTTPException(400, detail="zip 文件损坏")
            elif raw_name.lower().endswith(src_exts):
                dest = os.path.join(incoming_dir, f"{week}__{raw_name}")
                with open(dest, "wb") as out:
                    shutil.copyfileobj(file.file, out, length=1024 * 1024)
                sources = [dest]
            else:
                raise HTTPException(400, detail=f"仅接受 .csv/.hdb/.zip 文件，收到: {raw_name!r}")
        sources = [p for p in sources if os.path.getsize(p) > 0]
        if not sources:
            raise HTTPException(400, detail="输入中未找到任何非空 .csv/.hdb 文件")
        for fam in fams:
            if not _copy_sig_family(src_dir, staging, fam):
                raise HTTPException(500, detail=f"复制 {fam} 库失败: {src_dir} 缺少分片目录")

        # 3) staging 上构建实例并导入（逐文件格式探测；record_name 带周前缀防 basename 去重）
        before_dbs = _build_sig_instances(staging)
        dirty: Dict[str, set] = {}
        try:
            for fam, db in before_dbs.items():
                old_counts[fam] = db.count
                inserted_rows[fam] = 0
            for path in sources:
                rec = os.path.basename(path) if not dir_path \
                    else f"{week}__{os.path.basename(path)}"
                fmt = _detect_source_format(path)
                fmt_count[fmt] = fmt_count.get(fmt, 0) + 1
                if fmt == "csv":
                    per_fam = nkrepo_scanner.import_csv_signatures(
                        path, before_dbs, record_name=rec, malicious_only=malicious_only,
                        stats=csv_stats)
                    for fam, n in per_fam.items():
                        inserted_rows[fam] += int(n)
                elif fmt == "hashbase9":
                    for fam, db in before_dbs.items():
                        inserted_rows[fam] += int(db.import_hashbase_hdb(path, record_name=rec))
                else:
                    for fam, db in before_dbs.items():
                        inserted_rows[fam] += int(db.import_hdb(path, record_name=rec))
            print(f"[sigupdate] %d 个源文件, 格式分布={fmt_count}, week={week}" % len(sources))
            log.info("[sigupdate] 输入 %d 个文件, 格式分布=%s, week=%s, malicious_only=%s",
                     len(sources), fmt_count, week, malicious_only)
            if csv_stats:
                log.info("[sigupdate] CSV 统计: %s", csv_stats)
            # dirty 必须在 finalize 之前采集（finalize 会清空 _bloom_dirty）
            for fam, db in before_dbs.items():
                dirty[fam] = set(db._bloom_dirty)
                db.finalize()
            new_counts = {fam: db.count for fam, db in before_dbs.items()}
        finally:
            for db in before_dbs.values():
                try:
                    db.close()
                except Exception:
                    pass

        # 4) 幂等检查：零新增 = 输入已在库中，不发布
        if sum(inserted_rows.values()) == 0:
            return {"status": "no_new_rows",
                    "detail": "所有输入均未产生新签名（行级去重），未发布新版本",
                    "files": len(sources), "week": week, "formats": fmt_count,
                    "csv_stats": csv_stats, "counts": new_counts}

        # 5) 校验：各库计数不得回退（对照在线旧库；在线库缺席时仅要求 staging 自洽）
        with _STATE_LOCK:
            cur = {"sha256": _sha256_db, "md5": _md5_db, "fuzzy": _fuzzy_db}
        for fam, old_db in cur.items():
            if fam in new_counts and old_db is not None and new_counts[fam] < old_db.count:
                raise HTTPException(409, detail=(
                    f"{fam} 库计数回退: {new_counts[fam]:,} < {old_db.count:,}，拒绝发布"))

        # 6) VACUUM 受影响分片（fuzzy 的 dirty 是 (ftype, sid) 对，分片号取 sid 并集）
        vac_info: Dict[str, Any] = {}
        if vacuum:
            vac_dbs = _build_sig_instances(staging)
            try:
                for fam, db in vac_dbs.items():
                    sids = {sid for (_ft, sid) in dirty[fam]} if fam == "fuzzy" \
                        else dirty[fam]
                    sids = sorted(s for s in sids if isinstance(s, int))
                    if sids:
                        vac_info[fam] = _vacuum_shards(db, sids)
            finally:
                for db in vac_dbs.values():
                    try:
                        db.close()
                    except Exception:
                        pass

        # 7) 发布：staging → releases/v<ts>（同卷 rename，原子）；current 指向它
        rel_dir = os.path.join(root, "releases")
        release = os.path.join(rel_dir, f"v{ts}")
        os.makedirs(rel_dir, exist_ok=True)
        os.rename(staging, release)
        try:
            link = os.path.join(root, "current")
            if os.path.islink(link):
                os.remove(link)
            elif os.path.isdir(link):
                # 已有实体目录（旧布局残留）：不能覆盖，退化为指针文件
                raise OSError("current 为实体目录")
            os.symlink(release, link)
        except OSError:
            # Windows 无符号链接权限等场景：用 releases/CURRENT 指针文件兜底
            with open(os.path.join(rel_dir, "CURRENT"), "w", encoding="utf-8") as f:
                f.write(f"v{ts}")
        # 8) 热切换：直接从发布目录构建新实例，校验通过后换全局引用（失败保留旧库）
        new_dbs = _build_sig_instances(release)
        try:
            for fam, db in new_dbs.items():
                if db.count != new_counts[fam]:
                    raise RuntimeError(f"发布后 {fam} 计数不一致: {db.count} != {new_counts[fam]}")
        except Exception:
            for db in new_dbs.values():
                try:
                    db.close()
                except Exception:
                    pass
            raise

        replaced: Dict[str, Any] = {}
        with _STATE_LOCK:
            globals_map = {"sha256": "_sha256_db", "md5": "_md5_db", "fuzzy": "_fuzzy_db"}
            for fam, gname in globals_map.items():
                if fam in new_dbs:
                    replaced[gname] = globals()[gname]
                    globals()[gname] = new_dbs[fam]
        log.info("[sigupdate] %d 个源文件 (week=%s, 格式=%s) 已发布并热切换: %s → %s",
                 len(sources), week, fmt_count, old_counts, new_counts)
        return {
            "status": "published",
            "files": len(sources),
            "week": week,
            "formats": fmt_count,
            "csv_stats": csv_stats,
            "release": release,
            "active_dir": release,
            "rows_inserted": inserted_rows,
            "counts": {"before": old_counts, "after": new_counts},
            "vacuum": vac_info,
            "note": "已热切换，无需重启。回滚：将 current 指回上一版本目录后重启进程（重启会经 _active_sig_dir 解析回旧版）。",
        }
    except HTTPException:
        raise
    except Exception as e:
        log.error("update-signatures 失败:\n%s", traceback.format_exc())
        raise HTTPException(500, detail=f"update failed: {e}")
    finally:
        if os.path.isdir(staging):
            shutil.rmtree(staging, ignore_errors=True)
        if os.path.isdir(incoming_dir):
            shutil.rmtree(incoming_dir, ignore_errors=True)
        if zip_tmp and os.path.isfile(zip_tmp):
            try:
                os.remove(zip_tmp)
            except OSError:
                pass


# ──────────────────────────────────────────────────────────────────
# 运行时配置（免重启改配置）
# ──────────────────────────────────────────────────────────────────
# 背景：config.py 的常量在 import 时从 env 读一次。环境变量类的问题（CMD 语法、
# 容器 env 固化、supervisord 自管环境）会让人误以为"改配置不生效"。这里给出一条
# 与 env 完全解耦的旁路：直接改 config 模块属性 + 重建受影响的运行期对象。
#
# 与 /update-signatures、/reload-model 一致，本端点不做鉴权，生产请置于内网/网关之后。

_CONFIG_HOT_KEYS = {"HASH_DB_ENABLED", "FUZZY_DB_ENABLED", "HASH_DB_DIR"}
_CONFIG_META_KEYS = {"PERSIST", "RESET", "RELOAD_FILE", "RELOAD_FROM_ENV"}


def _admin_config_payload() -> Dict[str, Any]:
    return {
        "pid": os.getpid(),
        "started_at": datetime.fromtimestamp(_START_TIME).strftime("%Y-%m-%d %H:%M:%S"),
        # 档位：dev 才能读写覆盖文件；prod（容器）忽略它 → 开发期开关进不了生产
        "env_profile": config.ENV_PROFILE,
        "engine_mode": _engine_mode(),
        "config_file": config.RUNTIME_CFG_FILE,
        "config_file_exists": os.path.isfile(config.RUNTIME_CFG_FILE),
        "config_file_enabled": config.RUNTIME_CFG_FILE_ENABLED,
        "config_file_disabled_reason": config.RUNTIME_CFG_DISABLED_REASON,
        "config_file_error": getattr(config, "RUNTIME_CFG_ERROR", ""),
        "config_file_applied": list(getattr(config, "RUNTIME_CFG_APPLIED", [])),
        "require_hash_db": bool(config.REQUIRE_HASH_DB),
        "items": config.runtime_cfg_state(),
        "hash_db": _hash_db_state(),
        "note": ("hot_reload=true 的项改完立即生效；false 的项只影响下次启动，"
                 "需重启进程（如数据集构建期开关）。"
                 "config_file_enabled=false 时覆盖文件被忽略且 persist 会被拒绝"
                 "（生产档位特征，重启即恢复全引擎）。"),
    }


@app.get("/admin/config")
def admin_config_get() -> Dict[str, Any]:
    """查看每个可覆盖配置项的当前值、来源（env/default/runtime）与生效方式。"""
    return _admin_config_payload()


@app.post("/admin/config")
def admin_config_set(payload: Dict[str, Any] = Body(default={})) -> Dict[str, Any]:
    """运行时改配置（默认免重启）。请求体示例：

        {"hash_db_enabled": false}                       # 关闭过滤引擎 → 纯模型
        {"hash_db_enabled": true, "fuzzy_db_enabled": true}
        {"persist": true, "hash_db_enabled": false}      # 同时落盘，重启后仍生效
        {"reset": ["HASH_DB_ENABLED"]}                   # 回到 env/默认基线
        {"reload_file": true}                            # 重新读取 runtime_config.json

    键大小写不敏感，也接受 {"overrides": {...}} 包装形式。

    档位差异（开发 vs 生产）：
      · 内存内覆盖（默认）→ 两种档位都可用；重启进程即恢复，不留痕。
      · persist=true 落盘   → 仅本机开发档位允许；生产档位返回 409（见 config 档位隔离）。
    """
    log = logging.getLogger("codefender.engine")
    # 直接函数调用（探针/单测）时 FastAPI 的默认值是 Body 标记对象而非 dict，容错
    p = payload if isinstance(payload, dict) else {}
    nested = p.get("overrides") if isinstance(p.get("overrides"), dict) else None

    meta = {str(k).upper(): v for k, v in p.items()
            if str(k).upper() in _CONFIG_META_KEYS}
    raw: Dict[str, Any] = {}
    for src in (p, nested or {}):
        for k, v in src.items():
            ku = str(k).upper()
            if ku in _CONFIG_META_KEYS or ku == "OVERRIDES":
                continue
            raw[ku] = v

    bad = [k for k in raw if k not in config.RUNTIME_SPEC]
    if bad:
        raise HTTPException(400, detail=(
            f"不支持的配置项 {bad}；可用: {sorted(config.RUNTIME_SPEC)}"))

    persist = bool(meta.get("PERSIST", False))
    reset = meta.get("RESET") or []
    if isinstance(reset, (str, bytes)):
        reset = [reset]
    reset = [str(r).upper() for r in reset]
    bad_r = [k for k in reset if k not in config.RUNTIME_SPEC]
    if bad_r:
        raise HTTPException(400, detail=f"不支持的配置项 {bad_r}")

    # 档位闸门：生产档位不落盘、也不读覆盖文件。
    # 在动手之前就拒绝 → 整请求原子失败，不会出现"内存改了、盘没写"的中间态。
    if not config.RUNTIME_CFG_FILE_ENABLED:
        _why = (f"当前档位({config.ENV_PROFILE})的运行时覆盖文件被禁用："
                f"{config.RUNTIME_CFG_DISABLED_REASON}")
        _how = ("  · 只做临时切换（重启即恢复、不留痕）：去掉 persist，改用纯内存覆盖\n"
                "  · 要长期固化：改 codefender.ini 的 environment= 行后重启\n"
                "  · 本机开发要用覆盖文件：CODEFENDER_ENV=dev（或 dev_model_only 脚本）")
        if persist:
            raise HTTPException(409, detail=f"{_why}\n{_how}")
        if meta.get("RELOAD_FILE"):
            raise HTTPException(409, detail=f"{_why}\n{_how}")

    try:
        # 1) 覆盖文件重载（可选）：文件 → 模块属性
        file_applied: Dict[str, Any] = {}
        if meta.get("RELOAD_FILE"):
            file_applied, err = config.load_runtime_cfg_file(origin="file")
            if err:
                raise HTTPException(400, detail=f"runtime_config.json 读取失败: {err}")
            config.RUNTIME_CFG_APPLIED = sorted(file_applied)
            config.RUNTIME_CFG_ERROR = ""

        # 2) 显式覆盖 / 复位（API 优先级最高）
        restored = config.reset_runtime_overrides(reset) if reset else {}
        applied = config.apply_runtime_overrides(raw, origin="api", persist=persist) \
            if raw else {}

        # 3) 受影响的运行期对象重建：过滤引擎三库是唯一需要在进程内重建的重对象
        touched = set(applied) | set(restored) | set(file_applied)
        hdb = _reload_hash_dbs(
            "admin/config: " + ",".join(sorted(touched))) if (touched & _CONFIG_HOT_KEYS) \
            else _hash_db_state()

        only_cold = sorted(k for k in (touched & set(config.RUNTIME_SPEC))
                           if not config.RUNTIME_SPEC[k][2])
        resp = _admin_config_payload()
        resp.update({
            "status": "ok",
            "applied": applied,
            "reset": restored,
            "reloaded_from_file": file_applied,
            "persisted_to": config.RUNTIME_CFG_FILE if persist else None,
            "hash_db": hdb,
            "cold_keys_pending_restart": only_cold,
        })
        log.info("[admin/config] applied=%s reset=%s persist=%s → hash_db=%s",
                 applied, list(restored), persist, hdb)
        return resp
    except HTTPException:
        raise
    except Exception as e:
        log.error("admin/config 失败:\n%s", traceback.format_exc())
        raise HTTPException(500, detail=f"config update failed: {e}")


# ──────────────────────────────────────────────────────────────────
# 单文件推理核心函数（供 /predict-single 和 /predict-directory 共用）
# ──────────────────────────────────────────────────────────────────

def _scan_single_pe(
    pe_path: str,
    file_name: str,
    file_size: int,
    ens: MultiModelEnsemble,
    expected_view_dims: Dict[str, int],
    include_de: bool = True,
    per_model_override=None,
) -> Dict[str, Any]:
    """对单个 PE 文件执行完整推理链路，返回 format_scan_result 格式的 dict。"""
    # PE文件格式验证
    if not _is_valid_pe(pe_path):
        raise ValueError("文件结构不对，或者文件格式损坏")

    if per_model_override is None:
        views, view_meta = _extract_views_for_single_sample(
            pe_path=pe_path, required_views=list(ens.view_groups.keys()),
            include_de=include_de, expected_view_dims=expected_view_dims,
        )
        per_model = _predict_per_model(
            ens, views, view_meta=view_meta, pe_path=pe_path, include_de=include_de,
        )
    else:
        per_model = per_model_override
    # ── Build (1, K) matrices from flat per_model list ──
    ok_results = [r for r in per_model if r.get("status") == "ok"]
    K = len(ok_results)
    model_names = [r["model"] for r in ok_results]
    scores_arr = np.array(
        [r["score"] for r in ok_results], dtype=np.float32,
    ).reshape(1, K) if K > 0 else np.zeros((1, 1), dtype=np.float32)
    preds_arr = np.array(
        [r["prediction"] for r in ok_results], dtype=np.int64,
    ).reshape(1, K) if K > 0 else np.zeros((1, 1), dtype=int)

    # ── Ensemble prediction (weighted average, aligns with run_all.py) ──
    ens_model_set = set(ens._model_names)
    ens_ok = [r for r in ok_results if r["model"] in ens_model_set]
    if ens_ok:
        ok_scores = np.array([r["score"] for r in ens_ok], dtype=np.float32)
        ens_score_arr = np.array([ok_scores.mean()], dtype=np.float32)
        ens_pred_arr = np.array([int(ens_score_arr[0] > 0.5)], dtype=int)
    else:
        ens_pred_arr = np.array([0], dtype=int)
        ens_score_arr = np.array([0.0], dtype=np.float32)

    # ── File identifiers + packer detection ──
    identifiers = compute_identifiers(pe_path)
    identifiers["FileName"] = file_name
    identifiers["FileSize"] = file_size
    from engine.packer_detector import detect_packer
    pack_info = detect_packer(pe_path)

    # ── SDD drift evidence ──
    try:
        sdd = _get_sdd_engine()
        drift_ev = sdd.score_samples(scores_arr)
        drift_evidence = drift_ev.get("drift_evidence", np.zeros(3))
        sample_drift_type = drift_ev.get("sample_drift_type", "normal")
        anomaly_score = drift_ev.get("anomaly_score", 0.0)
        is_drift_candidate = drift_ev.get("is_drift_candidate", False)
    except Exception:
        drift_evidence = np.zeros(3)
        sample_drift_type = "normal"
        anomaly_score = 0.0
        is_drift_candidate = False

    # ── Model voting stats ──
    total_models = len(per_model)
    ok_count = len(ok_results)
    skipped_count = sum(1 for r in per_model if r.get("status") == "skipped")
    error_count = total_models - ok_count - skipped_count
    malicious_votes = sum(1 for r in ok_results if r.get("prediction") == 1)
    benign_votes = ok_count - malicious_votes
    agreement_rate = malicious_votes / ok_count if ok_count > 0 else 0.0
    ok_scores = [r["score"] for r in ok_results if "score" in r]

    model_stats = {
        "TotalModels": total_models,
        "OkModels": ok_count,
        "SkippedModels": skipped_count,
        "ErrorModels": error_count,
        "MaliciousVotes": malicious_votes,
        "BenignVotes": benign_votes,
        "AgreementRate": round(agreement_rate, 4),
        "EnsembleScore": round(float(ens_score_arr[0]), 6) if K > 0 else 0.0,
        "EnsemblePred": int(ens_pred_arr[0]) if K > 0 else 0,
        "ScoreRange": [round(min(ok_scores), 4), round(max(ok_scores), 4)] if ok_scores else [0.0, 0.0],
    }

    # ── Build evidence dict for format_scan_result ──
    evidence = {
        "predictions": ens_pred_arr,
        "scores": ens_score_arr,
        "per_model_scores": scores_arr,
        "per_model_preds": preds_arr,
        "drift_evidence": drift_evidence,
        "sample_drift_type": sample_drift_type,
        "anomaly_score": anomaly_score,
        "is_drift_candidate": is_drift_candidate,
        "model_stats": model_stats,
    }

    return format_scan_result(
        evidence=evidence,
        identifiers=identifiers,
        pack_info=pack_info,
        model_names=model_names,
    )

# 7. 同步包装器：使用 _tmp_upload 安全创建临时文件
def _scan_single_pe_wrapper(
    content: bytes,
    suffix: str,
    file_name: str,
    file_size: int,
    ens: MultiModelEnsemble,
    expected_view_dims: Dict[str, int],
    include_de: bool,
) -> Dict[str, Any]:
    """同步包装器：使用 _tmp_upload 安全创建临时文件后调用 _scan_single_pe。"""
    with _tmp_upload(suffix=suffix) as temp_path:
        with open(temp_path, "wb") as f:
            f.write(content)
        return _scan_single_pe(
            pe_path=temp_path,
            file_name=file_name,
            file_size=file_size,
            ens=ens,
            expected_view_dims=expected_view_dims,
            include_de=include_de,
        )




# ──────────────────────────────────────────────────────────────────
# 目录批量扫描
# ──────────────────────────────────────────────────────────────────

_PE_EXTENSIONS = {".exe", ".dll", ".sys", ".ocx", ".scr", ".bat", ".cmd",
                   ".msi", ".ps1", ".vbs", ".js", ".wsf", ".hta", ".cpl",
                   ".com", ".src", ".pif", ".drv", ".bin"}
MAX_BATCH_FILES = int(os.environ.get("CODEFENDER_MAX_BATCH_FILES", 500))


def _build_batch_views(
    sample_views: Dict[int, Tuple[Dict[str, np.ndarray], Dict[str, Dict[str, Any]]]],
    view_names: List[str],
) -> Tuple[Dict[str, np.ndarray], Dict[int, Dict[str, Dict[str, Any]]]]:
    """
    Build batch view matrices from per-sample views.
    
    Args:
        sample_views: Dict mapping sample indices to (views_dict, view_meta_dict)
        view_names: List of view names to build batch matrices for
    
    Returns:
        Tuple of (batch_views, per_sample_meta) where:
        - batch_views: Dict mapping view names to (N, dim) numpy arrays
        - per_sample_meta: Dict mapping sample indices to their view metadata
    """
    if not sample_views:
        return {}, {}
    
    batch_views: Dict[str, np.ndarray] = {}
    per_sample_meta: Dict[int, Dict[str, Dict[str, Any]]] = {}
    
    # Get sorted sample indices
    sorted_indices = sorted(sample_views.keys())
    
    # Extract metadata for all samples (do once, not per view)
    for idx in sorted_indices:
        _, view_meta = sample_views[idx]
        per_sample_meta[idx] = view_meta
    
    # First pass: determine dimension for each view from available samples
    view_dims: Dict[str, int] = {}
    for vname in view_names:
        for idx in sorted_indices:
            views, _ = sample_views[idx]
            if vname in views:
                view_dims[vname] = views[vname].reshape(-1).shape[0]
                break
        # B-fix: 整批都没有该视角（如 include_de=false 时的 D/E 视角）→
        # 不再落 2381 全零兜底矩阵喂模型，直接跳过构建。该视角对应的
        # 模型在 predict_all 中因视角缺席而整轮不参与，由聚合掩码排除。
        if vname not in view_dims and vname == "V1_byte":
            view_dims[vname] = RAW_LEN
    
    # Second pass: build batch matrix for each view
    for vname in view_names:
        if vname not in view_dims:
            continue  # 整批缺席的视角：不构建假矩阵，对应模型由聚合掩码排除
        view_rows: List[np.ndarray] = []
        expected_dim = view_dims[vname]
        
        for idx in sorted_indices:
            views, _ = sample_views[idx]
            
            if vname in views:
                # View exists for this sample
                row = views[vname].reshape(-1)
                # Ensure consistent dimension
                if row.shape[0] != expected_dim:
                    if row.shape[0] < expected_dim:
                        # Pad
                        padded = np.zeros(expected_dim, dtype=np.float32)
                        padded[:row.shape[0]] = row
                        view_rows.append(padded)
                    else:
                        # Truncate
                        view_rows.append(row[:expected_dim])
                else:
                    view_rows.append(row)
            else:
                # View missing - use zero-filled placeholder
                view_rows.append(np.zeros(expected_dim, dtype=np.float32))
        
        if view_rows:
            # Stack into (N, dim) batch matrix
            batch_views[vname] = np.vstack(view_rows).astype(np.float32)
    
    return batch_views, per_sample_meta


def _format_batch_results(
    pe_paths: List[str],
    batch_predictions: np.ndarray,
    batch_scores: np.ndarray,
    per_model_predictions: np.ndarray,
    per_model_scores: np.ndarray,
    model_names: List[str],
    per_sample_meta: Dict[int, Dict[str, Dict[str, Any]]],
    valid_indices: List[int],
) -> List[Dict[str, Any]]:
    """
    Format batch inference results into per-sample result dictionaries.
    
    Args:
        pe_paths: List of all PE file paths
        batch_predictions: (N,) or (N, 1) ensemble predictions
        batch_scores: (N,) or (N, 1) ensemble scores
        per_model_predictions: (N, K) per-model predictions
        per_model_scores: (N, K) per-model scores
        model_names: List of model names (length K)
        per_sample_meta: Dict mapping sample indices to view metadata
        valid_indices: List of sample indices that were successfully processed
    
    Returns:
        List of formatted result dictionaries
    """
    results: List[Dict[str, Any]] = []
    
    # Ensure predictions and scores are at least 1D
    batch_predictions = np.atleast_1d(batch_predictions).flatten()
    batch_scores = np.atleast_1d(batch_scores).flatten()
    
    for batch_idx, sample_idx in enumerate(valid_indices):
        fpath = pe_paths[sample_idx]
        fname = os.path.basename(fpath)
        
        try:
            file_size = os.path.getsize(fpath)
            
            # Extract this sample's predictions and scores (handle 1D arrays)
            ens_pred = int(batch_predictions[batch_idx])
            ens_score = float(batch_scores[batch_idx])
            sample_per_model_preds = per_model_predictions[batch_idx, :].reshape(1, -1)
            sample_per_model_scores = per_model_scores[batch_idx, :].reshape(1, -1)
            
            # Get identifiers and packer info
            identifiers = compute_identifiers(fpath)
            identifiers["FileName"] = fname
            identifiers["FileSize"] = file_size
            
            from engine.packer_detector import detect_packer
            pack_info = detect_packer(fpath)
            
            # SDD drift evidence (placeholder for batch - would need batch SDD implementation)
            drift_evidence = np.zeros(3)
            sample_drift_type = "normal"
            anomaly_score = 0.0
            is_drift_candidate = False
            
            # Model voting stats
            total_models = len(model_names)
            malicious_votes = int(np.sum(sample_per_model_preds > 0.5))
            benign_votes = total_models - malicious_votes
            agreement_rate = malicious_votes / total_models if total_models > 0 else 0.0
            
            model_stats = {
                "TotalModels": total_models,
                "OkModels": total_models,
                "SkippedModels": 0,
                "ErrorModels": 0,
                "MaliciousVotes": malicious_votes,
                "BenignVotes": benign_votes,
                "AgreementRate": round(agreement_rate, 4),
                "EnsembleScore": round(ens_score, 6),
                "EnsemblePred": ens_pred,
                "ScoreRange": [
                    round(float(np.min(sample_per_model_scores)), 4),
                    round(float(np.max(sample_per_model_scores)), 4)
                ],
            }
            
            # Build evidence dict
            evidence = {
                "predictions": np.array([[ens_pred]]),
                "scores": np.array([[ens_score]]),
                "per_model_scores": sample_per_model_scores,
                "per_model_preds": sample_per_model_preds,
                "drift_evidence": drift_evidence,
                "sample_drift_type": sample_drift_type,
                "anomaly_score": anomaly_score,
                "is_drift_candidate": is_drift_candidate,
                "model_stats": model_stats,
            }
            
            result = format_scan_result(
                evidence=evidence,
                identifiers=identifiers,
                pack_info=pack_info,
                model_names=model_names,
            )
            result["FilePath"] = fpath
            results.append(result)
            
        except Exception as e:
            results.append({
                "FileName": fname,
                "FilePath": fpath,
                "Status": -1,
                "StatusLabel": "Error",
                "IsMalicious": False,
                "Error": f"format_result_failed: {e}",
            })
    
    return results


async def _batch_scan_samples(
    pe_paths: List[str],
    ens: MultiModelEnsemble,
    expected_view_dims: Dict[str, int],
    include_de: bool = False,
) -> List[Dict[str, Any]]:
    """
    Batch process multiple PE samples with parallel feature extraction and batch inference.
    
    Args:
        pe_paths: List of PE file paths to process
        ens: MultiModelEnsemble instance
        expected_view_dims: Dict mapping view names to expected dimensions
        include_de: Whether to extract D/E features (BinaryNinja disassembly/graph)
    
    Returns:
        List of formatted result dictionaries (one per sample)
    """
    loop = asyncio.get_event_loop()
    
    # Step 1: Parallel feature extraction
    sample_views = await loop.run_in_executor(
        None,
        _extract_views_for_batch,
        pe_paths,
        list(ens.view_groups.keys()),
        include_de,
        expected_view_dims,
    )
    
    # Handle completely failed samples
    valid_indices = sorted(sample_views.keys())
    if not valid_indices:
        # All samples failed - return error results
        return [{
            "FileName": os.path.basename(fpath),
            "FilePath": fpath,
            "Status": -1,
            "StatusLabel": "Error",
            "IsMalicious": False,
            "Error": "feature_extraction_failed",
        } for fpath in pe_paths]
    
    # Step 2: Build batch view matrices
    batch_views, per_sample_meta = _build_batch_views(
        sample_views,
        list(ens.view_groups.keys()),
    )
    
    try:
        per_model_predictions, per_model_scores = await loop.run_in_executor(
            None,
            ens.predict_all,
            batch_views,
        )
        
        # Step 4: Ensemble prediction (B3/B-fix 掩码聚合)
        # 排除三类无效槽位，避免 0.5 常量把集成分数拉向 0.5：
        #   a) 模型对象缺失 / special / skip（valid_model_mask 口径）
        #   b) 本轮视角整批缺席的模型（如 include_de=false 时的 D/E 模型，
        #      predict_all 从未给它们赋分，_scores 里是 0.5 初值）
        valid_model_of_view = {}
        for vname, mnames in ens.view_groups.items():
            for mname in mnames:
                valid_model_of_view[mname] = vname
        available_views = set(batch_views.keys())

        valid_k: List[int] = []
        excluded: Dict[str, str] = {}
        for k, mname in enumerate(ens._model_names):
            # 先看类型再对象（special 槽位 load() 后对象为 None，但语义是 special）
            if ens._model_types.get(mname) in ("special", "skip"):
                excluded[mname] = "special_pipeline"
                continue
            if ens._models.get(mname) is None:
                excluded[mname] = "model_not_loaded"
                continue
            vname = valid_model_of_view.get(mname)
            if vname is not None and vname not in available_views:
                excluded[mname] = f"view_unavailable:{vname}"
                continue
            valid_k.append(k)

        if valid_k:
            valid_scores = per_model_scores[:, valid_k]       # (N, K_valid)
            batch_scores = valid_scores.mean(axis=1)           # 等权平均
            batch_predictions = (batch_scores > 0.5).astype(int)
            if excluded:
                print(f"  [集成掩码] 本次批量排除 {len(excluded)} 个模型: "
                      f"{ {m: r for m, r in list(excluded.items())[:8]} }"
                      + (" ..." if len(excluded) > 8 else ""))
        else:
            N_batch = per_model_scores.shape[0]
            batch_predictions = np.zeros(N_batch, dtype=int)
            batch_scores = np.full(N_batch, 0.5, dtype=np.float32)

        # Step 5: Format results
        results = _format_batch_results(
            pe_paths=pe_paths,
            batch_predictions=batch_predictions,
            batch_scores=batch_scores,
            per_model_predictions=per_model_predictions,
            per_model_scores=per_model_scores,
            model_names=ens._model_names,
            per_sample_meta=per_sample_meta,
            valid_indices=valid_indices,
        )
        
        # Add back failed samples
        all_results: List[Dict[str, Any]] = []
        result_idx = 0
        for i, fpath in enumerate(pe_paths):
            if i in valid_indices:
                all_results.append(results[result_idx])
                result_idx += 1
            else:
                all_results.append({
                    "FileName": os.path.basename(fpath),
                    "FilePath": fpath,
                    "Status": -1,
                    "StatusLabel": "Error",
                    "IsMalicious": False,
                    "Error": "feature_extraction_failed",
                })
        
        return all_results
        
    except Exception as e:
        # Batch inference failed - return errors for all samples
        logging.error("Batch inference failed: %s", e)
        return [{
            "FileName": os.path.basename(fpath),
            "FilePath": fpath,
            "Status": -1,
            "StatusLabel": "Error",
            "IsMalicious": False,
            "Error": f"batch_inference_failed: {e}",
        } for fpath in pe_paths]


async def _predict_directory_unprotected(
    directory: str = Query(..., description="服务器端目录绝对路径"),
    recursive: bool = Query(default=True, description="是否递归扫描子目录"),
    include_de: bool = Query(
        default=False,
        description="批量模式下默认关闭D/E特征提取以加速",
    ),
) -> Dict[str, Any]:
    """批量扫描目录下所有 PE 样本，返回逐文件检测结果。"""
    if not os.path.isdir(directory):
        raise HTTPException(status_code=400, detail=f"directory not found: {directory}")

    # 收集所有文件（不再依赖扩展名过滤）
    all_files: List[str] = []
    walk_root = directory
    for dirpath, _dirnames, filenames in os.walk(walk_root):
        for fn in filenames:
            all_files.append(os.path.join(dirpath, fn))
        if not recursive:
            break  # 仅扫描顶层目录

    if not all_files:
        raise HTTPException(status_code=404, detail="no files found in directory")

    # 通过读取文件头来判断是否为PE文件（支持无扩展名或非标准扩展名的PE文件）
    pe_files: List[str] = []
    skipped_non_pe: int = 0
    for fpath in all_files:
        if _is_valid_pe(fpath):
            pe_files.append(fpath)
        else:
            skipped_non_pe += 1

    if not pe_files:
        raise HTTPException(
            status_code=404, 
            detail=f"no PE files found in directory (scanned {len(all_files)} files, {skipped_non_pe} non-PE)"
        )

    if len(pe_files) > MAX_BATCH_FILES:
        raise HTTPException(
            status_code=400,
            detail=f"too many files: {len(pe_files)} > {MAX_BATCH_FILES}",
        )

    # ── SHA256 + MD5 哈希库预检：命中直出 Malicious（不占模型批量额度）──
    hash_hits: List[Dict[str, Any]] = []
    remaining_files: List[str] = []
    for fpath in pe_files:
        hit = _hash_precheck_file(fpath)
        if hit is not None:
            hit["FilePath"] = fpath
            hash_hits.append(hit)
        else:
            remaining_files.append(fpath)

    # 2. 并发信号量 + 4. 指标埋点
    start_t = time.time()
    try:
        async with _SCAN_SEMAPHORE:
            # 模型加载阶段计时（全部命中时跳过模型加载）
            model_load_start = time.time()
            if remaining_files:
                ens = _load_ensemble()
                expected_view_dims = _infer_expected_view_dims(ens)
            else:
                ens = None
                expected_view_dims = {}
            model_load_time = time.time() - model_load_start

            # 批量扫描阶段计时 - 仅未命中样本进模型批量（可能为空）
            batch_scan_start = time.time()
            if remaining_files:
                results = await _batch_scan_samples(remaining_files, ens, expected_view_dims, include_de)
            else:
                results = []
            batch_scan_time = time.time() - batch_scan_start

            # 合并结果：哈希命中在前，模型结果在后
            results = hash_hits + results
            
            # Calculate per-sample average time and add to results
            successful_count = sum(1 for r in results if r.get("Status") != -1)
            if successful_count > 0:
                avg_per_sample = batch_scan_time / successful_count
                for r in results:
                    if r.get("Status") != -1:
                        r["ProcessingTime"] = round(avg_per_sample, 3)

        # 统计结果
        error_count = sum(1 for r in results if r.get("Status") == -1 and r.get("StatusLabel") == "Error")
        timeout_count = sum(1 for r in results if r.get("Status") == -1 and r.get("StatusLabel") == "Timeout")
        malicious_count = sum(1 for r in results if r.get("IsMalicious") and r.get("Status") != -1)
        benign_count = sum(1 for r in results if not r.get("IsMalicious") and r.get("Status") != -1)
        
        # 单样本处理时间统计
        sample_times = [r.get("ProcessingTime", 0.0) for r in results if r.get("ProcessingTime") and r.get("Status") != -1]
        min_sample_time = min(sample_times) if sample_times else 0.0
        max_sample_time = max(sample_times) if sample_times else 0.0
        avg_sample_time = sum(sample_times) / len(sample_times) if sample_times else 0.0
        sorted_times = sorted(sample_times)
        median_sample_time = sorted_times[len(sorted_times) // 2] if sorted_times else 0.0

        # 总体时间统计
        total_elapsed = time.time() - start_t
        elapsed_ms = round(total_elapsed * 1000, 1)
        
        with _METRICS_LOCK:
            _METRICS["predict_dir_ok"] += 1
            _METRICS["scan_files_total"] += len(pe_files)
            _METRICS["scan_files_malicious"] += malicious_count
            _METRICS["scan_files_benign"] += benign_count
            _METRICS["last_predict_ms"] = elapsed_ms

        summary = {
            "TotalFiles": len(pe_files),
            "TotalFilesInDirectory": len(all_files),  # 目录中所有文件数
            "SkippedNonPE": skipped_non_pe,           # 跳过的非PE文件数
            "ScannedFiles": len(results) - error_count - timeout_count,
            "MaliciousCount": malicious_count,
            "BenignCount": benign_count,
            "ErrorCount": error_count,
            "TimeoutCount": timeout_count,
            "Directory": directory,
            # 新增详细时间统计
            "Timing": {
                "TotalTime": round(total_elapsed, 3),          # 总耗时(秒)
                "ModelLoadTime": round(model_load_time, 3),    # 模型加载时间(秒)
                "BatchScanTime": round(batch_scan_time, 3),    # 批量扫描时间(秒)
                "AvgSampleTime": round(avg_sample_time, 3),    # 平均每样本时间(秒)
                "MedianSampleTime": round(median_sample_time, 3),  # 中位数样本时间(秒)
                "MinSampleTime": round(min_sample_time, 3),
                "MaxSampleTime": round(max_sample_time, 3),
                "Throughput": round(len(pe_files) / total_elapsed, 3) if total_elapsed > 0 else 0.0,  # 样本/秒
            },
        }

        return {
            "Summary": summary,
            "Results": results,
        }
    except HTTPException:
        raise
    except Exception as e:
        with _METRICS_LOCK:
            _METRICS["predict_dir_error"] += 1
        raise HTTPException(status_code=500, detail=str(e)) from e



# This fragment is installed into engine/app.py by patch_runtime.py.
# It deliberately uses the base image's existing feature/model functions.
from engine.scan_runtime import ScanRuntime, ScanBusy, ScanTimeout
from engine.staged_scan import run_staged
from starlette.responses import StreamingResponse

_SCAN_RUNTIME = ScanRuntime(
    concurrency=int(os.environ.get('CODEFENDER_MAX_CONCURRENT', '1')),
    timeout=int(os.environ.get('CODEFENDER_REQUEST_TIMEOUT', '240')),
    hard_timeout=int(os.environ.get('CODEFENDER_HARD_TIMEOUT', '300')),
)


def _scan_uploaded_sync(content, filename, include_de, on_progress=None):
    # Older v8 images have no signature precheck. Preserve whichever pipeline
    # the base image actually provides instead of importing newer dependencies.
    precheck = globals().get('_hash_precheck')
    if precheck:
        hit = precheck(content, filename, len(content))
        if hit is not None:
            return hit
    ens = _load_ensemble()
    expected = _infer_expected_view_dims(ens)
    # The worker owns its temporary file for its full lifetime. A timed-out
    # HTTP caller must neither delete the file nor release its scan slot.
    with tempfile.TemporaryDirectory(prefix='aidefender-scan-') as directory:
        path = os.path.join(directory, 'sample.bin')
        with open(path, 'wb') as handle:
            handle.write(content)
        return run_staged(globals(), path, filename, len(content), ens, expected, include_de, on_progress)


async def _run_guarded(operation, *args):
    try:
        return await _SCAN_RUNTIME.run(operation, *args)
    except ScanBusy as error:
        raise HTTPException(429, detail=str(error), headers={'Retry-After': '3'}) from error
    except ScanTimeout as error:
        raise HTTPException(504, detail=str(error)) from error


@app.on_event('startup')
async def _warm_runtime_models():
    # /readyz never loads models. Warm up once so Docker probes can remain cheap.
    await _SCAN_RUNTIME.run(_load_ensemble)


@app.post('/predict-single')
async def predict_single(
    file: UploadFile = File(...),
    include_de: bool = Query(default=DEFAULT_INCLUDE_DE),
) -> Dict[str, Any]:
    if not file.filename:
        raise HTTPException(400, detail='empty filename')
    if _SCAN_RUNTIME.active >= _SCAN_RUNTIME.concurrency:
        raise HTTPException(429, detail='model service is busy; retry later', headers={'Retry-After': '3'})
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if not content:
            raise HTTPException(400, detail='empty file content')
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail='file too large')
        return await _run_guarded(_scan_uploaded_sync, content, file.filename, include_de)
    except ValueError as error:
        raise HTTPException(400, detail=str(error)) from error
    finally:
        await file.close()


@app.post('/predict-stream')
async def predict_stream(file: UploadFile = File(...), include_de: bool = Query(default=DEFAULT_INCLUDE_DE)):
    if _SCAN_RUNTIME.active >= _SCAN_RUNTIME.concurrency:
        await file.close()
        raise HTTPException(429, detail='model service is busy; retry later', headers={'Retry-After': '3'})
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if not content or not file.filename:
            raise HTTPException(400, detail='empty file')
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, detail='file too large')
    finally:
        await file.close()
    loop = asyncio.get_running_loop()
    events = asyncio.Queue()

    def progress(payload):
        loop.call_soon_threadsafe(events.put_nowait, {'event': 'progress', 'data': payload})

    async def produce():
        try:
            result = await _run_guarded(_scan_uploaded_sync, content, file.filename, include_de, progress)
            await events.put({'event': 'result', 'data': result})
        except Exception as error:
            await events.put({'event': 'error', 'detail': str(getattr(error, 'detail', error))})

    async def stream():
        # The runtime reserves the slot before starting the real operation.
        # Disconnecting the reader must not release it while inference still runs.
        producer = asyncio.create_task(produce())
        try:
            while True:
                try:
                    event = await asyncio.wait_for(events.get(), timeout=5)
                except asyncio.TimeoutError:
                    yield json.dumps({'event': 'heartbeat'}) + '\n'
                    continue
                yield json.dumps(event, ensure_ascii=False) + '\n'
                if event['event'] in ('result', 'error'):
                    break
        finally:
            if not producer.done():
                producer.cancel()
            await asyncio.gather(producer, return_exceptions=True)

    return StreamingResponse(stream(), media_type='application/x-ndjson', headers={'X-Accel-Buffering': 'no'})


def _directory_in_thread(directory, recursive, include_de):
    # The legacy batch coroutine contains synchronous preparation/postprocessing.
    # Its own loop stays in a worker thread, away from uvicorn's HTTP event loop.
    return asyncio.run(_predict_directory_unprotected(directory, recursive, include_de))


@app.post('/predict-directory')
async def predict_directory(
    directory: str = Query(..., description='服务器端目录绝对路径'),
    recursive: bool = Query(default=True),
    include_de: bool = Query(default=False),
) -> Dict[str, Any]:
    return await _run_guarded(_directory_in_thread, directory, recursive, include_de)
