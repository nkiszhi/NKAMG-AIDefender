import asyncio
import logging
import ctypes
import requests
import ast
import json
import uuid
import re
import time as monotonic_time
from contextlib import asynccontextmanager
from datetime import datetime, time, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import FastAPI, File, Header, HTTPException, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.codefender_client import DEFAULT_MODEL_NAMES, ModelServiceBusy, scan_file
from app.config import settings
from app.http_guard import PublicAPIGuard
from app.file_info import save_upload, UploadStorageFull
from app.sample_repository import SampleRepository
from app.stats_repository import StatsRepository
from app.detection_queue import DetectionTaskStore, ProcessLease, QueueFull


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("aidefender")
sample_repository = SampleRepository(settings)
stats_repository = StatsRepository(settings)
task_store = DetectionTaskStore(
    Path(__file__).resolve().parent / "data" / "detection_tasks.sqlite3",
    settings.task_ttl_seconds,
)
task_wakeup = asyncio.Event()
process_lease = ProcessLease(task_store.path.with_suffix('.lock'))
STATS_SNAPSHOT_PATH = Path(__file__).resolve().parent / "data" / "dashboard_stats.json"


def _load_stats_snapshot() -> dict:
    try:
        return json.loads(STATS_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"available": False, "reason": "统计数据尚未刷新", "updated_at": None}


stats_cache = _load_stats_snapshot()


def _save_stats_snapshot(payload: dict) -> None:
    STATS_SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = STATS_SNAPSHOT_PATH.with_suffix(".tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    temp_path.replace(STATS_SNAPSHOT_PATH)


def _model_catalog() -> list[dict]:
    registry_path = Path(__file__).resolve().parents[2] / "CoDefenderC3" / "config.py"
    try:
        module = ast.parse(registry_path.read_text(encoding="utf-8"))
        registry_node = next(
            node.value for node in module.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "VIEW_GROUPS" for target in node.targets)
        )
        view_groups = ast.literal_eval(registry_node)
    except (OSError, StopIteration, SyntaxError, ValueError) as error:
        logger.warning("读取模型视角注册表失败: %s", error)
        return [{"name": name, "view": "多视角", "source": "CoDefenderC3", "role": "参与恶意文件检测", "optimization": "参见项目模型资料"} for name in DEFAULT_MODEL_NAMES]

    details = {}
    for group in view_groups.values():
        view = group.get("label", "多视角")
        features = ", ".join(group.get("ember_ranges", group.get("binja_features", [])))
        for name, source, architecture in group.get("models", []):
            if name not in DEFAULT_MODEL_NAMES:
                continue
            details[name] = {
                "name": name,
                "view": view,
                "features": features or view,
                "source": source,
                "role": architecture,
                "optimization": "按项目特征维度与模型输入核对；优化记录见 CoDefenderC3/docs/PAPERS.md",
            }
    return [details.get(name, {"name": name, "view": "多视角", "features": "项目特征", "source": "CoDefenderC3项目实现", "role": "参与恶意文件检测", "optimization": "参见项目模型资料"}) for name in DEFAULT_MODEL_NAMES]


async def _stats_loop() -> None:
    global stats_cache
    while True:
        try:
            refreshed = await asyncio.to_thread(stats_repository.refresh)
            if refreshed.get("available"):
                stats_cache = refreshed
                await asyncio.to_thread(_save_stats_snapshot, refreshed)
                logger.info("MySQL统计刷新完成并保存快照: %s", refreshed.get("updated_at"))
            else:
                logger.warning("MySQL统计未刷新，保留最近成功快照: %s", refreshed.get("reason"))
        except Exception:
            logger.exception("MySQL统计刷新异常")
        now = datetime.now(ZoneInfo("Asia/Shanghai"))
        next_refresh = datetime.combine(now.date(), time(8, 30), tzinfo=now.tzinfo)
        if next_refresh <= now:
            next_refresh += timedelta(days=1)
        await asyncio.sleep(max(1, (next_refresh - now).total_seconds()))


@asynccontextmanager
async def lifespan(_app):
    process_lease.acquire()
    try:
        await asyncio.to_thread(task_store.recover)
        stats_task = asyncio.create_task(_stats_loop())
        worker_tasks = [asyncio.create_task(_detection_worker()) for _ in range(settings.max_concurrent_scans)]
        cleanup_task = asyncio.create_task(_cleanup_loop())
        try:
            yield
        finally:
            for task in worker_tasks + [stats_task, cleanup_task]:
                task.cancel()
            await asyncio.gather(*worker_tasks, stats_task, cleanup_task, return_exceptions=True)
    finally:
        process_lease.release()

app = FastAPI(
    title="NKAMG-AIDefender 多模型恶意文件检测",
    version="1.0.0",
    description="NKAMG-AIDefender 文件检测后端，接入 CoDefenderC3 模型服务",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


_uploads_inflight = 0


@app.middleware('http')
async def limit_uploads(request: Request, call_next):
    global _uploads_inflight
    if request.method != 'POST' or request.url.path != '/detect':
        return await call_next(request)
    if _uploads_inflight >= 2:
        return JSONResponse(status_code=429, content={'detail': '检测服务繁忙，请稍后重试'}, headers={'Retry-After': '5'})
    _uploads_inflight += 1
    try:
        return await call_next(request)
    finally:
        _uploads_inflight -= 1


# Outer user middleware: reject oversized bodies before multipart spooling.
app.add_middleware(PublicAPIGuard, max_body_bytes=settings.max_upload_size + 1024 * 1024)


def _response_payload(info: dict, exe_result: dict, detection_mode: str) -> dict:
    return {
        "success": True,
        "original_filename": info["filename"],
        "filename": info["filename"],
        "sha256": info["sha256"],
        "md5": info["md5"],
        "file_size": info["file_size"],
        "file_type": info["file_type"],
        "is_pe": info["is_pe"],
        "pe_info": info["pe_info"],
        "query_result": info["query_result"],
        "exe_result": exe_result,
        "results": exe_result,
        "detection_mode": detection_mode,
        "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _payload(info: dict, **extra) -> dict:
    payload = {
        "success": True,
        "original_filename": info["filename"],
        "filename": info["filename"],
        "sha256": info["sha256"],
        "md5": info["md5"],
        "file_size": info["file_size"],
        "file_type": info["file_type"],
        "is_pe": info["is_pe"],
        "pe_info": info["pe_info"],
        "query_result": info["query_result"],
        "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    payload.update(extra)
    return payload


@app.get("/")
async def root() -> dict:
    return {"message": "NKAMG-AIDefender backend is running", "docs": "/docs"}


@app.get("/health")
async def health_check() -> dict:
    return {"status": "healthy"}


@app.get("/upload-policy")
async def upload_policy() -> dict:
    return {"max_upload_size": settings.max_upload_size,
            "report_ttl_seconds": settings.task_ttl_seconds,
            "sample_retention": "until_task_finishes"}


@app.get("/models")
async def models() -> dict:
    return {"count": len(DEFAULT_MODEL_NAMES), "models": DEFAULT_MODEL_NAMES, "catalog": _model_catalog()}


@app.get("/model-health")
async def model_health() -> dict:
    async with _model_health_lock:
        if monotonic_time.monotonic() - _model_health_cache['at'] < 5:
            return _model_health_cache['data']
        payload = await _fetch_model_health()
        _model_health_cache.update(at=monotonic_time.monotonic(), data=payload)
        return payload


_model_health_lock = asyncio.Lock()
_model_health_cache = {'at': float('-inf'), 'data': {}}


async def _fetch_model_health() -> dict:
    services = await asyncio.gather(*(_fetch_endpoint_health(base) for base in settings.codefender_api_bases))
    ready = [service for service in services if service.get('ready')]
    return {
        'connected': any(service.get('connected') for service in services),
        'ready': bool(ready),
        'model_count': max((service.get('model_count', 0) for service in ready), default=0),
        'ready_workers': len(ready),
        'total_workers': len(services),
        'service': {'workers': services},
    }


async def _fetch_endpoint_health(base) -> dict:
    url = f"{base}/readyz"
    try:
        response = await asyncio.to_thread(requests.get, url, timeout=(2, 3))
        if response.status_code != 503:
            response.raise_for_status()
        payload = response.json()
        return {"connected": True, "ready": payload.get("ready") is True, "model_count": payload.get("model_count", 0), "service": payload}
    except Exception as error:
        logger.warning("模型服务健康检查失败: %s", error)
        return {"connected": False, "ready": False, "model_count": 0, "detail": "模型服务暂不可用"}


@app.get("/stats")
async def stats() -> dict:
    return stats_cache


@app.get("/samples/{sha256}")
async def sample_by_sha256(sha256: str) -> dict:
    """Look up a malicious sample by its content hash for the web search bar."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256 or ""):
        raise HTTPException(status_code=422, detail="请输入有效的 SHA256")
    try:
        record = await asyncio.to_thread(sample_repository.find_malicious, sha256)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail="样本库暂不可用") from error
    if not record:
        raise HTTPException(status_code=404, detail="样本库中未找到该 SHA256")
    public_record = SampleRepository.public_fields(record)
    identity = public_record.get("identity", {})
    return {
        "success": True,
        "database_hit": True,
        "detection_mode": "sample_database",
        "detection_status": "malicious",
        "verdict": "恶意",
        "reason": "命中 NKAMG 恶意样本库",
        "is_pe": True,
        "filename": identity.get("文件名", "-"),
        "file_size": identity.get("文件大小", 0),
        "md5": identity.get("MD5", ""),
        "sha256": sha256.lower(),
        "sample_record": public_record,
        "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


async def _run_detection(file_path: Path, info: dict, on_progress=None) -> dict:
    database_error = None
    try:
        sample_record = await asyncio.to_thread(sample_repository.find_malicious, info["sha256"])
    except RuntimeError as error:
        sample_record = None
        database_error = '样本库暂不可用'
        logger.warning("样本库查询不可用，继续33模型检测: %s", error)

    if sample_record:
        public_record = SampleRepository.public_fields(sample_record)
        return _payload(
            info,
            detection_status="malicious",
            detection_mode="sample_database",
            verdict="恶意",
            reason="命中 NKAMG 恶意样本库，跳过33模型检测",
            database_hit=True,
            database_error=None,
            model_skipped=True,
            sample_record=public_record,
            exe_result={},
            results={},
        )

    for attempt in range(21):
        try:
            exe_result = await asyncio.to_thread(scan_file, file_path, on_progress=on_progress)
            break
        except ModelServiceBusy:
            if attempt == 20:
                raise RuntimeError('模型服务持续繁忙，请稍后再试')
            await asyncio.sleep(3)
    return _payload(
        info,
        detection_status="completed",
        detection_mode="models",
        verdict=None,
        reason=None,
        database_hit=False,
        database_error=database_error,
        model_skipped=False,
        exe_result=exe_result,
        results=exe_result,
    )


async def _detection_worker() -> None:
    while True:
        abandoned = await asyncio.to_thread(task_store.cancel_abandoned)
        for path in abandoned:
            try:
                await asyncio.to_thread(Path(path).unlink, missing_ok=True)
            except OSError:
                logger.warning('取消任务样本暂未删除，交由定期清理: %s', path, exc_info=True)
        task_wakeup.clear()
        row = await asyncio.to_thread(task_store.claim_next)
        if not row:
            try:
                await asyncio.wait_for(task_wakeup.wait(), timeout=1)
            except asyncio.TimeoutError:
                pass
            continue
        task_id = row['task_id']
        file_path = Path(row["file_path"])
        work = asyncio.create_task(_process_detection_task(task_id, file_path, row))
        try:
            await asyncio.shield(work)
        except asyncio.CancelledError:
            # Cancelling the wait does not stop requests' worker thread.
            await work
            raise


async def _process_detection_task(task_id: str, file_path: Path, row: dict) -> None:
    started = monotonic_time.monotonic()
    queued_seconds = max(0, (datetime.now() - datetime.fromisoformat(row['created_at'])).total_seconds())
    logger.info('检测任务开始 task_id=%s queued_seconds=%.3f', task_id, queued_seconds)
    try:
        if not file_path.is_file():
            raise FileNotFoundError('上传样本文件已不存在')
        from app.file_info import build_file_info
        info = await asyncio.to_thread(build_file_info, file_path, row['filename'])
        def progress(payload):
            task_store.update_progress(task_id, {'file_info': info, **payload})
        result = await _run_detection(file_path, info, on_progress=progress)
        result['timing'] = {'queue_seconds': round(queued_seconds, 3),
                            'processing_seconds': round(monotonic_time.monotonic() - started, 3)}
        await asyncio.to_thread(task_store.complete, task_id, result)
        logger.info('检测任务完成 task_id=%s processing_seconds=%.3f', task_id, monotonic_time.monotonic() - started)
    except Exception as error:
        logger.exception('检测任务失败 task_id=%s', task_id)
        await asyncio.to_thread(task_store.set_status, task_id, 'failed', '检测任务失败，请稍后重试或联系管理员')
    finally:
        try:
            await asyncio.to_thread(file_path.unlink, missing_ok=True)
        except OSError:
            logger.warning('样本清理失败 task_id=%s', task_id, exc_info=True)


async def _cleanup_loop() -> None:
    while True:
        try:
            abandoned = await asyncio.to_thread(task_store.cancel_abandoned)
            for path in abandoned:
                await asyncio.to_thread(Path(path).unlink, missing_ok=True)
            paths = await asyncio.to_thread(task_store.cleanup)
            for path in paths:
                await asyncio.to_thread(Path(path).unlink, missing_ok=True)
            if settings.upload_dir.exists():
                orphan_paths = await asyncio.to_thread(
                    task_store.orphan_paths, settings.upload_dir,
                    monotonic_time.time() - settings.orphan_ttl_seconds)
                for path in orphan_paths:
                    await asyncio.to_thread(path.unlink, missing_ok=True)
        except Exception:
            logger.exception('过期任务清理失败')
        await asyncio.sleep(5)


@app.post("/detect")
async def detect(response: Response, file: UploadFile = File(...), x_detection_id: str = Header(default='')) -> dict:
    if x_detection_id and not re.fullmatch(r'[a-f0-9]{32}', x_detection_id):
        raise HTTPException(status_code=400, detail='检测请求标识无效')
    task_id = x_detection_id or uuid.uuid4().hex
    existing = await asyncio.to_thread(task_store.get, task_id)
    if existing:
        return task_store.public_status(existing)
    try:
        file_path, info = await save_upload(file)
    except ValueError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except UploadStorageFull as error:
        raise HTTPException(status_code=507, detail=str(error)) from error
    except OSError as error:
        windows_error = getattr(error, "winerror", None)
        # CPython's file open may expose EINVAL while Windows retains ERROR_VIRUS_INFECTED.
        if windows_error is None and hasattr(ctypes, "windll"):
            windows_error = ctypes.windll.kernel32.GetLastError()
        if windows_error in (225, 226):
            logger.warning("上传样本被 Windows 安全防护拦截: %s", error)
            raise HTTPException(
                status_code=422,
                detail="Windows 安全防护拦截了上传样本，后端无法读取，尚未提交 Docker 检测。请查看 Windows 安全中心的保护历史记录。",
            ) from error
        logger.exception("保存上传文件失败")
        raise HTTPException(status_code=500, detail="保存上传文件失败，请联系管理员") from error
    except Exception as error:
        logger.exception("保存上传文件失败")
        raise HTTPException(status_code=500, detail="保存上传文件失败，请联系管理员") from error

    logger.info("开始检测上传文件: filename=%s sha256=%s", info["filename"], info["sha256"])
    if not info["is_pe"]:
        file_path.unlink(missing_ok=True)
        reason = info["pe_info"].get("reason") or "不是有效PE样本"
        logger.info("非PE文件: filename=%s reason=%s", info["filename"], reason)
        return _payload(
            info,
            detection_status="unsupported",
            detection_mode="rejected",
            verdict="检测失败",
            reason=reason,
            model_skipped=True,
            database_hit=False,
        )

    try:
        row = await asyncio.to_thread(task_store.create, task_id, info['filename'], file_path,
                                      settings.max_queued_scans + settings.max_concurrent_scans)
    except QueueFull:
        file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=429, detail='检测服务繁忙，请稍后重试', headers={'Retry-After': '5'})
    except Exception:
        file_path.unlink(missing_ok=True)
        raise
    if row['file_path'] != str(file_path):
        file_path.unlink(missing_ok=True)
    task_wakeup.set()
    response.status_code = 202
    logger.info("检测任务已加入后台处理: task_id=%s filename=%s", task_id, info["filename"])
    return {
        "success": True,
        "task_id": task_id,
        "status": "queued",
        "detection_status": "queued",
        "filename": info["filename"],
        "message": "已接收检测请求",
    }


@app.get("/detect/tasks/{task_id}")
async def detection_task_status(task_id: str) -> dict:
    if not re.fullmatch(r'[a-f0-9]{32}', task_id):
        raise HTTPException(status_code=400, detail='检测请求标识无效')
    await asyncio.to_thread(task_store.heartbeat, task_id)
    row = await asyncio.to_thread(task_store.get, task_id)
    if not row:
        raise HTTPException(status_code=404, detail="检测任务不存在或已过期")
    return task_store.public_status(row)


@app.post('/detect/tasks/{task_id}/leave', status_code=202)
async def detection_task_leave(task_id: str) -> dict:
    if not re.fullmatch(r'[a-f0-9]{32}', task_id):
        raise HTTPException(status_code=400, detail='检测请求标识无效')
    await asyncio.to_thread(task_store.leave, task_id)
    return {'accepted': True}


if __name__ == "__main__":
    import uvicorn

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
