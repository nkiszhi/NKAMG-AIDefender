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
from typing import Annotated
from zoneinfo import ZoneInfo
from pydantic import BaseModel, Field

from fastapi import FastAPI, File, Header, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.datastructures import UploadFile as StarletteUploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.codefender_client import DEFAULT_MODEL_NAMES, ModelServiceBusy, scan_file, _endpoint_pool
from app import model_runtime
from app.config import settings
from app.http_guard import PublicAPIGuard, BrowserUploadLimit
from app.upload_form import single_file_form
from app.file_info import save_upload, UploadStorageFull
from app.sample_repository import SampleRepository, identify_hash
from app.stored_results import saved_model_payload
from app.aidpe_result_store import ResultOutbox, PrimaryResultWriter, archive_detected_sample
from app.stats_repository import StatsRepository
from app.detection_queue import DetectionTaskStore, ProcessLease, QueueFull, ExpiredRequest


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("aidefender")
sample_repository = SampleRepository(settings)
stats_repository = StatsRepository(settings)
aidpe_outbox = ResultOutbox(settings.aidpe_outbox_path)
aidpe_writer = PrimaryResultWriter(settings)
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
        _endpoint_pool.attach_storage(task_store)
        interrupted = await asyncio.to_thread(task_store.recover)
        if interrupted:
            for base in settings.codefender_api_bases:
                _endpoint_pool.quarantine(base, model_runtime.node_evidence(base))
        stats_task = asyncio.create_task(_stats_loop())
        aidpe_result_task = asyncio.create_task(_aidpe_result_loop())
        worker_tasks = [asyncio.create_task(_detection_worker()) for _ in range(settings.max_concurrent_scans)]
        cleanup_task = asyncio.create_task(_cleanup_loop())
        try:
            yield
        finally:
            for task in worker_tasks + [stats_task, aidpe_result_task, cleanup_task]:
                task.cancel()
            await asyncio.gather(*worker_tasks, stats_task, aidpe_result_task, cleanup_task, return_exceptions=True)
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


app.add_middleware(BrowserUploadLimit)


# Outer user middleware: reject oversized bodies before multipart spooling.
app.add_middleware(PublicAPIGuard, max_body_bytes=settings.max_upload_size + 1024 * 1024,
                   upload_timeout=settings.api_upload_timeout_seconds,
                   upload_idle_timeout=settings.api_upload_idle_timeout_seconds)


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
    allowed, reason = model_runtime.admission_status()
    recovering = _endpoint_pool.recovering()
    return {
        'connected': any(service.get('connected') for service in services),
        'ready': bool(ready),
        'model_count': max((service.get('model_count', 0) for service in ready), default=0),
        'ready_workers': len(ready),
        'total_workers': len(services),
        'dispatch_paused': not allowed or bool(recovering),
        'queue_message': reason or ('模型请求曾异常中断，等待节点恢复或原任务结束' if recovering else ''),
        'recovering_workers': len(recovering),
        **task_store.scheduling_status(settings.large_sample_bytes),
        'service': {'workers': services},
    }


async def _fetch_endpoint_health(base) -> dict:
    url = f"{base}/readyz"
    try:
        response = await asyncio.to_thread(requests.get, url, timeout=(2, 3))
        if response.status_code != 503:
            response.raise_for_status()
        payload = response.json()
        usable = not (base in _endpoint_pool.recovering())
        if settings.model_monitor_path:
            usable = usable and bool(model_runtime.node_evidence(base).get('ready'))
        return {"connected": True, "ready": payload.get("ready") is True and usable, "model_count": payload.get("model_count", 0), "service": payload}
    except Exception as error:
        logger.warning("模型服务健康检查失败: %s", error)
        return {"connected": False, "ready": False, "model_count": 0, "detail": "模型服务暂不可用"}


@app.get("/stats")
async def stats() -> dict:
    return stats_cache


@app.get("/detection-stats")
async def detection_stats() -> dict:
    return await asyncio.to_thread(task_store.detection_summary)


@app.get("/samples/{sha256}")
async def sample_by_sha256(sha256: str) -> dict:
    """Look up a PE result by its content hash for the web search bar."""
    if not re.fullmatch(r"[0-9a-fA-F]{64}", sha256 or ""):
        raise HTTPException(status_code=422, detail="请输入有效的 SHA256")
    query_id = await asyncio.to_thread(task_store.begin_hash_query, 'sha256', sha256.lower())
    try:
        record = await asyncio.to_thread(sample_repository.find_malicious, sha256)
    except RuntimeError as error:
        await asyncio.to_thread(task_store.finish_hash_query, query_id, 'failed')
        raise HTTPException(status_code=503, detail="样本库暂不可用") from error
    await asyncio.to_thread(task_store.finish_hash_query, query_id, 'hit' if record else 'miss',
                            record.get('sha256') if record else None,
                            _stored_query_verdict(record) if record else None)
    if not record:
        raise HTTPException(status_code=404, detail="样本库中未找到该 SHA256")
    public_record = SampleRepository.public_fields(record)
    identity = public_record.get("identity", {})
    is_malicious = record.get('source') == 'malicious_pe'
    models = dict(public_record.get('model_results') or {})
    ensemble = public_record.get('codefender_result')
    if ensemble:
        models['集成结果'] = ensemble
    verdict = ((ensemble or {}).get('display_result') or (ensemble or {}).get('result')) if isinstance(ensemble, dict) else None
    return {
        "success": True,
        "database_hit": is_malicious,
        "record_found": True,
        "detection_mode": "models" if models else "sample_database",
        "detection_status": public_record.get('detection_status') or ('malicious' if is_malicious else 'completed'),
        "verdict": "Malicious" if is_malicious else verdict,
        "reason": "已读取检测结果" if models else "已读取样本记录",
        "is_pe": True,
        "filename": identity.get("文件名", "-"),
        "file_size": identity.get("文件大小", 0),
        "md5": identity.get("MD5", ""),
        "sha256": sha256.lower(),
        "sample_record": public_record,
        **saved_model_payload(record, DEFAULT_MODEL_NAMES),
        "model_version": public_record.get('model_version'),
        "detection_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.get('/sample-search')
async def search_sample_hash(value: str) -> dict:
    value = value.strip()
    try:
        kind = identify_hash(value)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    normalized = value.lower() if kind == 'sha256' else value.upper() if kind == 'tlsh' else value
    if kind != 'sha256' and sample_repository.sha256_only:
        raise HTTPException(status_code=422, detail='当前样本库仅支持SHA256精确查询')
    query_id = await asyncio.to_thread(task_store.begin_hash_query, kind, normalized)
    try:
        record = await asyncio.to_thread(sample_repository.find_by_hash, normalized)
    except RuntimeError as error:
        await asyncio.to_thread(task_store.finish_hash_query, query_id, 'failed')
        raise HTTPException(status_code=503, detail='样本库暂不可用') from error
    await asyncio.to_thread(task_store.finish_hash_query, query_id, 'hit' if record else 'miss',
                            record.get('sha256') if record else None,
                            _stored_query_verdict(record) if record else None)
    public_record = SampleRepository.public_fields(record)
    is_malicious = bool(record and record.get('source') == 'malicious_pe')
    models = dict(public_record.get('model_results') or {})
    ensemble = public_record.get('codefender_result')
    if ensemble:
        models['集成结果'] = ensemble
    ensemble_label = ((ensemble or {}).get('display_result') or (ensemble or {}).get('result')) if isinstance(ensemble, dict) else None
    identity = public_record.get('identity', {})
    return {
        'success': True, 'hash_search': True, 'hash_type': kind,
        'query_hash': normalized, 'database_hit': is_malicious,
        'record_found': bool(record),
        'detection_mode': 'models' if models else 'hash_search', 'model_skipped': True,
        'verdict': ('Malicious' if is_malicious else ensemble_label) if record else 'Unknown',
        'detection_status': public_record.get('detection_status') if record else 'not_detected',
        'reason': ('已读取检测结果' if record else
                   '样本库未匹配到该指纹' if sample_repository.configured else '样本库未配置'),
        'filename': identity.get('文件名', '-'),
        'sha256': identity.get('SHA256', normalized if kind == 'sha256' else ''),
        'md5': identity.get('MD5', ''), 'file_size': identity.get('文件大小', 0),
        'sample_record': public_record,
        **saved_model_payload(record, DEFAULT_MODEL_NAMES),
        'model_version': public_record.get('model_version'),
        'detection_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }


def _stored_query_verdict(record: dict) -> str:
    if record.get('source') == 'malicious_pe':
        return 'malicious_library'
    result = record.get('codefender_result')
    if isinstance(result, str):
        try:
            result = json.loads(result)
        except ValueError:
            result = None
    label = ((result or {}).get('display_result') or (result or {}).get('result')) if isinstance(result, dict) else None
    return {'Malicious': 'malicious', 'Benign': 'benign'}.get(label, 'inconclusive')


async def _lookup_uploaded_sample(info: dict):
    """Cheap database preflight, independent of model queue capacity."""
    database_error = None
    try:
        sample_record = await asyncio.to_thread(sample_repository.find_malicious, info["sha256"])
    except RuntimeError as error:
        sample_record = None
        database_error = '样本库暂不可用'
        logger.warning("样本库查询不可用，转入模型检测流程: %s", error)

    if sample_record:
        public_record = SampleRepository.public_fields(sample_record)
        is_malicious = sample_record.get('source') == 'malicious_pe'
        model_results = dict(public_record.get('model_results') or {})
        ensemble = public_record.get('codefender_result')
        if ensemble:
            model_results['集成结果'] = ensemble
        verdict = ((ensemble or {}).get('display_result') or (ensemble or {}).get('result')) if isinstance(ensemble, dict) else None
        return _payload(
            info,
            detection_status=public_record.get('detection_status') or ('malicious' if is_malicious else 'completed'),
            detection_mode="models" if model_results else "sample_database",
            verdict="Malicious" if is_malicious else verdict,
            database_hit=is_malicious,
            record_found=True,
            database_error=None,
            model_skipped=True,
            sample_record=public_record,
            **({'exe_result': {}, 'results': {}} | saved_model_payload(sample_record, DEFAULT_MODEL_NAMES)),
            model_version=public_record.get('model_version'),
        ), None
    return None, database_error


async def _run_detection(file_path: Path, info: dict, on_progress=None, *, force_models=False) -> dict:
    # Recheck after waiting: the library may have gained this sample meanwhile.
    known_result, database_error = (None, None) if force_models else await _lookup_uploaded_sample(info)
    if known_result is not None:
        return known_result

    for attempt in range(21):
        try:
            options = {'include_de': True} if force_models else {}
            exe_result = await asyncio.to_thread(scan_file, file_path, on_progress=on_progress, **options)
            break
        except ModelServiceBusy:
            if attempt == 20:
                raise RuntimeError('模型服务持续繁忙，请稍后再试')
            await asyncio.sleep(3)
    if force_models:
        ensemble = exe_result.get('集成结果') or {}
        label = ensemble.get('display_result') or ensemble.get('result')
        if label not in ('Generic.ML.Low', 'Generic.ML.Medium', 'Generic.ML.High', 'Benign') or ensemble.get('source') == 'signature':
            raise RuntimeError('模型接口未返回 ML 联合等级，请检查开发诊断接口及引擎预检配置')
    return _payload(
        info,
        detection_status="completed",
        detection_mode="models",
        verdict=(exe_result.get('集成结果') or {}).get('result'),
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
        allowed, _ = model_runtime.admission_status()
        # An abandoned HTTP request may still be computing. Drain before any
        # new dispatch, including a large exclusive task on the other node.
        safe = allowed and not _endpoint_pool.recovering()
        row = await asyncio.to_thread(task_store.claim_next, settings.max_concurrent_scans,
                                      settings.large_sample_bytes) if safe else None
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


async def _enqueue_failed_model_result(task_id: str, row: dict, info: dict) -> None:
    if row.get('request_source') != 'web' or not info.get('is_pe'):
        return
    current = await asyncio.to_thread(task_store.get, task_id)
    progress = json.loads(current.get('progress_json') or '{}') if current else {}
    partial = progress.get('exe_result') or progress.get('results') or progress.get('models') or {}
    result = _payload(info, detection_status='failed', detection_mode='models',
                      database_hit=False, exe_result=partial, results=partial,
                      model_version=settings.model_revision)
    await asyncio.to_thread(aidpe_outbox.enqueue, result, settings.model_revision)


async def _process_detection_task(task_id: str, file_path: Path, row: dict) -> None:
    started = monotonic_time.monotonic()
    queued_seconds = max(0, (datetime.now() - datetime.fromisoformat(row['created_at'])).total_seconds())
    logger.info('检测任务开始 task_id=%s queued_seconds=%.3f', task_id, queued_seconds)
    try:
        if not file_path.is_file():
            raise FileNotFoundError('上传样本文件已不存在')
        from app.file_info import build_file_info
        info = await asyncio.to_thread(build_file_info, file_path, row['filename'])
        await asyncio.to_thread(task_store.set_metadata, task_id, info['sha256'], info['file_size'])
        if await asyncio.to_thread(task_store.memory_failure, info['sha256'], settings.model_revision):
            raise model_runtime.ModelTaskFailure(model_runtime.MEMORY_MESSAGE, code='MODEL_MEMORY_LIMIT')
        def progress(payload):
            task_store.update_progress(task_id, {'file_info': info, **payload})
        api_request = row.get('request_source') == 'api'
        result = await _run_detection(file_path, info, on_progress=None if api_request else progress,
                                      force_models=api_request)
        result['model_version'] = settings.model_revision
        result['uploaded_at'] = row.get('created_at')
        result['timing'] = {'queue_seconds': round(queued_seconds, 3),
                            'processing_seconds': round(monotonic_time.monotonic() - started, 3)}
        await asyncio.to_thread(task_store.complete, task_id, result)
        if result.get('detection_mode') == 'models' and result.get('is_pe'):
            await asyncio.to_thread(aidpe_outbox.enqueue, result, settings.model_revision)
        logger.info('检测任务完成 task_id=%s processing_seconds=%.3f', task_id, monotonic_time.monotonic() - started)
    except model_runtime.ModelTaskFailure as error:
        # The separate Docker observer may lag the socket disconnect briefly.
        is_oom = error.code == 'MODEL_MEMORY_LIMIT'
        for _ in range(12 if error.endpoint and settings.model_monitor_path else 0):
            is_oom = model_runtime.confirmed_oom(error)
            if is_oom:
                break
            await asyncio.sleep(0.5)
        detail = model_runtime.MEMORY_MESSAGE if is_oom else str(error)
        code = 'MODEL_MEMORY_LIMIT' if is_oom else error.code
        if is_oom:
            await asyncio.to_thread(task_store.remember_memory_failure, task_id, settings.model_revision, detail)
        await asyncio.to_thread(task_store.set_status, task_id, 'failed', detail, code, False)
        if 'info' in locals():
            try:
                await _enqueue_failed_model_result(task_id, row, info)
            except Exception:
                logger.exception('检测失败结果未能写入持久台账 task_id=%s', task_id)
        logger.error('检测任务终止 task_id=%s code=%s', task_id, code)
    except Exception as error:
        logger.exception('检测任务失败 task_id=%s', task_id)
        await asyncio.to_thread(task_store.set_status, task_id, 'failed', '检测任务失败，请联系管理员检查；未自动重复检测。', 'DETECTION_FAILED', False)
        if 'info' in locals():
            try:
                await _enqueue_failed_model_result(task_id, row, info)
            except Exception:
                logger.exception('检测失败结果未能写入持久台账 task_id=%s', task_id)
    finally:
        if row.get('request_source') == 'web' and row.get('sha256') and file_path.is_file():
            try:
                await asyncio.to_thread(archive_detected_sample, file_path, settings.aidpe_sample_root,
                                        row['sha256'], locals().get('result'))
                logger.info('网页上传样本已核验并进入短期归档 task_id=%s sha256=%s', task_id, row['sha256'])
            except Exception:
                logger.exception('网页上传样本归档失败，暂留原文件 task_id=%s sha256=%s', task_id, row['sha256'])
        else:
            try:
                await asyncio.to_thread(file_path.unlink, missing_ok=True)
            except OSError:
                logger.warning('样本清理失败 task_id=%s', task_id, exc_info=True)


async def _cleanup_loop() -> None:
    while True:
        try:
            abandoned = await asyncio.to_thread(task_store.cancel_abandoned)
            abandoned += await asyncio.to_thread(task_store.expire_waiting, settings.max_queue_wait_seconds)
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


class UploadPreflight(BaseModel):
    sha256: str = Field(min_length=64, max_length=64, pattern=r'^[a-fA-F0-9]{64}$')
    filename: str = Field(min_length=1, max_length=255)
    file_size: int = Field(strict=True, ge=0)


@app.post('/detect/preflight')
async def upload_preflight(body: UploadPreflight, x_detection_id: str = Header(default='')) -> dict:
    """A miss is only a precheck, never a second query/detection counter."""
    if not re.fullmatch(r'[a-f0-9]{32}', x_detection_id):
        raise HTTPException(status_code=400, detail='检测请求标识无效')
    sha256 = body.sha256.lower()
    if body.file_size > settings.max_upload_size:
        raise HTTPException(status_code=413, detail='文件超过网页上传大小限制')
    existing = await asyncio.to_thread(task_store.get, x_detection_id)
    if existing:
        if existing.get('sha256') != sha256:
            raise HTTPException(status_code=409, detail='此请求标识已用于另一个文件')
        return {**task_store.public_status(existing), 'upload_required': False}
    if await asyncio.to_thread(task_store.request_was_recorded, x_detection_id):
        raise HTTPException(status_code=409, detail='此请求已结束且报告已过期，请重新选择文件')
    try:
        record = await asyncio.to_thread(sample_repository.find_malicious, sha256)
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail='样本库暂不可用，请稍后重试') from error
    if not record:
        return {'upload_required': True, 'request_id': x_detection_id, 'sha256': sha256}
    public_record = SampleRepository.public_fields(record)
    is_malicious = public_record.get('source') == 'malicious_pe'
    model_results = dict(public_record.get('model_results') or {})
    ensemble = public_record.get('codefender_result')
    if ensemble:
        model_results['集成结果'] = ensemble
    ensemble_label = ((ensemble or {}).get('display_result') or (ensemble or {}).get('result')) if isinstance(ensemble, dict) else None
    result = {
        'success': True, 'hash_search': True, 'hash_type': 'sha256', 'query_hash': sha256,
        'sha256': sha256, 'filename': body.filename, 'original_filename': body.filename,
        'file_size': body.file_size, 'is_pe': True, 'pe_structure_checked': False,
        'file_uploaded': False, 'database_hit': is_malicious, 'record_found': True, 'model_skipped': True,
        'detection_mode': 'models' if model_results else 'sample_database',
        'detection_status': public_record.get('detection_status') or ('malicious' if is_malicious else 'completed'),
        'verdict': 'Malicious' if is_malicious else ensemble_label,
        'reason': '已读取检测结果' if model_results else '已读取样本记录',
        'sample_record': public_record,
        **saved_model_payload(record, DEFAULT_MODEL_NAMES),
        'model_version': public_record.get('model_version'),
        'detection_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    try:
        row = await asyncio.to_thread(task_store.record_preflight_hit, x_detection_id, result)
    except (ValueError, ExpiredRequest) as error:
        raise HTTPException(status_code=409, detail='此请求标识已使用，请重新选择文件') from error
    return {**task_store.public_status(row), 'upload_required': False}


async def _aidpe_result_loop() -> None:
    while True:
        entry = await asyncio.to_thread(aidpe_outbox.claim_due)
        if not entry:
            await asyncio.sleep(5)
            continue
        try:
            await asyncio.to_thread(aidpe_writer.write, entry['payload'])
            replicated = False
            for _ in range(60):
                record = await asyncio.to_thread(sample_repository.find_malicious, entry['sha256'])
                if record and _replicated_result_matches(record, entry['payload']):
                    replicated = True
                    break
                await asyncio.sleep(5)
            if not replicated:
                raise RuntimeError('Primary result awaits TXY replica readback')
            await asyncio.to_thread(aidpe_outbox.mark_replicated, entry['sha256'])
            logger.info('AIDefender_PE result replicated sha256=%s', entry['sha256'])
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await asyncio.to_thread(aidpe_outbox.mark_retry, entry['sha256'], entry['attempts'], type(error).__name__)
            logger.warning('AIDefender_PE result remains in durable outbox sha256=%s error=%s',
                           entry['sha256'], type(error).__name__)


def _replicated_result_matches(record: dict, payload: dict) -> bool:
    if (record.get('source') not in ('web_upload', 'malicious_pe')
            or record.get('model_version') != payload.get('model_version')
            or record.get('detection_status') != payload.get('detection_status')):
        return False

    def decoded(value):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except ValueError:
                return value
        return value

    for name, value in (payload.get('models') or {}).items():
        if decoded(record.get(name)) != value:
            return False
    return decoded(record.get('codefender_result')) == payload.get('codefender_result')


@app.post("/detect")
async def detect(response: Response, file: UploadFile = File(...), x_detection_id: str = Header(default=''),
                 x_expected_sha256: Annotated[str, Header()] = '') -> dict:
    if x_detection_id and not re.fullmatch(r'[a-f0-9]{32}', x_detection_id):
        raise HTTPException(status_code=400, detail='检测请求标识无效')
    task_id = x_detection_id or uuid.uuid4().hex
    if x_expected_sha256 and not re.fullmatch(r'[a-fA-F0-9]{64}', x_expected_sha256):
        raise HTTPException(status_code=400, detail='SHA256格式无效')
    expected_sha256 = x_expected_sha256.lower()
    existing = await asyncio.to_thread(task_store.get, task_id)
    if existing:
        if expected_sha256 and existing.get('sha256') != expected_sha256:
            raise HTTPException(status_code=409, detail='此请求标识已用于另一个文件')
        return task_store.public_status(existing)
    if expected_sha256 and await asyncio.to_thread(task_store.request_was_recorded, task_id):
        raise HTTPException(status_code=409, detail='此请求已结束且报告已过期，请重新选择文件')
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

    if expected_sha256 and info['sha256'] != expected_sha256:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        raise HTTPException(status_code=409, detail='上传文件SHA256与本机预查不一致，未提交模型')
    logger.info("开始检测上传文件: filename=%s sha256=%s", info["filename"], info["sha256"])
    if not info["is_pe"]:
        file_path.unlink(missing_ok=True)
        reason = info["pe_info"].get("reason") or "不是有效PE样本"
        logger.info("非PE文件: filename=%s reason=%s", info["filename"], reason)
        result = _payload(
            info,
            detection_status="unsupported",
            detection_mode="rejected",
            verdict=None,
            reason=reason,
            model_skipped=True,
            database_hit=False,
        )
        await asyncio.to_thread(task_store.record_direct_result, task_id, result)
        return result

    # A known sample must not wait behind inference or fail because its queue
    # is full. Hashes are already calculated while saving the upload.
    try:
        known_result, _ = await _lookup_uploaded_sample(info)
    except BaseException:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        raise
    if known_result is not None:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        await asyncio.to_thread(task_store.record_direct_result, task_id, known_result)
        logger.info('上传样本命中数据库，直接返回且不进入模型队列: task_id=%s', task_id)
        return known_result

    blocked = await _reject_memory_sample(task_id, info, file_path, 'web')
    if blocked:
        response.status_code = 202
        return task_store.public_status(blocked)
    try:
        row = await asyncio.to_thread(task_store.create, task_id, info['filename'], file_path,
                                      settings.max_queued_scans + settings.max_concurrent_scans,
                                      sha256=info['sha256'], file_size=info['file_size'])
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
    return _public_task_status(row)


@app.post('/detect/tasks/{task_id}/leave', status_code=202)
async def detection_task_leave(task_id: str) -> dict:
    if not re.fullmatch(r'[a-f0-9]{32}', task_id):
        raise HTTPException(status_code=400, detail='检测请求标识无效')
    await asyncio.to_thread(task_store.leave, task_id)
    return {'accepted': True}


_api_uploads_inflight = 0
API_ML_LABELS = ('Generic.ML.Low', 'Generic.ML.Medium', 'Generic.ML.High', 'Benign')


def _api_error(request_id, status_code, detail, **extra):
    return JSONResponse({'result': 'Failed', 'detail': detail, **extra}, status_code=status_code,
                        headers={'X-Detection-ID': request_id})


async def _reject_memory_sample(task_id, info, file_path, source):
    blocked = await asyncio.to_thread(task_store.memory_failure, info['sha256'], settings.model_revision)
    if not blocked:
        return None
    try:
        return await asyncio.to_thread(task_store.record_rejection, task_id, info, source,
                                       model_runtime.MEMORY_MESSAGE, 'MODEL_MEMORY_LIMIT')
    finally:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)


def _public_task_status(row):
    payload = task_store.public_status(row)
    if row['status'] == 'queued':
        allowed, reason = model_runtime.admission_status()
        if not allowed:
            payload['queue_message'] = reason
        elif _endpoint_pool.recovering():
            payload['queue_message'] = '模型服务异常中断，正在等待恢复；请勿重复上传'
        elif row.get('file_size', 0) >= settings.large_sample_bytes:
            payload['queue_message'] = '大样本已排队，等待当前任务结束后独占模型分析'
        else:
            payload['queue_message'] = f"正在排队，前方还有 {row.get('tasks_ahead', 0)} 个任务"
    return payload


async def _api_final_result(row, response, wait_seconds, *, include_details=False):
    task_id = row['task_id']
    result_url = f'/api/v1/detect/tasks/{task_id}'
    if include_details:
        result_url += '?include_details=true'
    response.headers['X-Detection-ID'] = task_id
    response.headers['Location'] = result_url
    deadline = monotonic_time.monotonic() + wait_seconds
    while row['status'] in ('queued', 'running') and monotonic_time.monotonic() < deadline:
        await asyncio.sleep(min(0.5, max(0, deadline - monotonic_time.monotonic())))
        row = await asyncio.to_thread(task_store.get, task_id)
        if not row:
            return _api_error(task_id, 410, '检测结果已过期，请使用新的请求标识提交')
    if row['status'] == 'completed':
        result = json.loads(row['result_json'])
        ensemble = (result.get('exe_result') or {}).get('集成结果') or {}
        label = ensemble.get('display_result') or ensemble.get('result')
        if label not in API_ML_LABELS:
            return _api_error(task_id, 502, '模型服务没有返回有效联合判定')
        if include_details:
            # Opt-in batch collection shares the normal queue and model admission.
            # No local/remote database is written by this response projection.
            models = {name: value for name, value in (result.get('exe_result') or {}).items()
                      if name in DEFAULT_MODEL_NAMES and isinstance(value, dict)}
            return {'result': label, 'sha256': result.get('sha256'),
                    'model_results': models, 'codefender_result': ensemble}
        return {'result': label}
    if row['status'] in ('failed', 'cancelled'):
        return _api_error(task_id, 502, row.get('error') or '模型检测失败',
                          error_code=row.get('error_code') or 'DETECTION_FAILED',
                          retryable=bool(row.get('retryable')), task_id=task_id)
    response.status_code = 202
    return {'status': row['status'], 'task_id': task_id, 'result_url': result_url,
            'queue_message': _public_task_status(row).get('queue_message', '')}


@app.post('/api/v1/detect', tags=['单文件联合判定'],
          summary='上传一个样本，返回一个模型联合判定',
          description='默认等待最终判定；超过 wait_seconds 返回 202，可按 Location 查询同一任务。'
                      '此接口不设 Web 文件大小上限，网页上传限制保持原样。仅接受有效 PE；不使用 Web 样本库捷径。'
                      '成功结果为 Generic.ML.Low/Medium/High 或 Benign；检测失败为 Failed。'
                      'X-Detection-ID 为可选的 32 位小写十六进制幂等标识，同一标识对应同一个请求。',
          openapi_extra={'requestBody': {'required': True, 'content': {'multipart/form-data': {
              'schema': {'type': 'object', 'required': ['file'], 'properties': {
                  'file': {'type': 'string', 'format': 'binary'}}, 'additionalProperties': False}}}}})
async def api_detect(request: Request, response: Response,
                     x_detection_id: str = Header(default=''),
                     wait_seconds: int = Query(default=600, ge=0, le=3600),
                     include_details: Annotated[bool, Query(description='显式返回本次检测的逐模型与联合结果；默认协议保持不变')] = False):
    global _api_uploads_inflight
    if x_detection_id and not re.fullmatch(r'[a-f0-9]{32}', x_detection_id):
        return _api_error('', 400, '检测请求标识无效')
    task_id = x_detection_id or uuid.uuid4().hex
    existing = await asyncio.to_thread(task_store.get, task_id)
    if existing:
        if existing.get('request_source') != 'api':
            return _api_error(task_id, 409, '请求标识已用于网页任务，请使用新的标识')
        return await _api_final_result(existing, response, wait_seconds, include_details=include_details)
    if _api_uploads_inflight >= 2:
        logger.warning('API 上传名额已满 task_id=%s inflight=%s', task_id, _api_uploads_inflight)
        response = _api_error(task_id, 429, '上传服务繁忙，请稍后重试')
        response.headers['Retry-After'] = '60'
        return response
    _api_uploads_inflight += 1
    upload_started = monotonic_time.monotonic()
    upload_outcome = 'receiving'
    logger.info('API 上传开始 task_id=%s inflight=%s', task_id, _api_uploads_inflight)
    file_path = None
    try:
        # Parse ourselves so multiple file parts (even with different names) are rejected.
        async with single_file_form(request) as form:
            items = list(form.multi_items())
            if len(items) != 1 or items[0][0] != 'file' or not isinstance(items[0][1], StarletteUploadFile):
                return _api_error(task_id, 422, '每次必须且只能上传一个 file 文件')
            file_path, info = await save_upload(items[0][1], unlimited=True)
            upload_outcome = 'stored'
    except UploadStorageFull as error:
        return _api_error(task_id, 507, str(error))
    except StarletteHTTPException as error:
        return _api_error(task_id, error.status_code, str(error.detail))
    except asyncio.CancelledError:
        upload_outcome = 'cancelled'
        raise
    except Exception:
        phase = request.scope.get('state', {}).get('upload_receive', {}).get('phase')
        if phase in ('idle_timeout', 'total_timeout', 'disconnected', 'body_limit'):
            upload_outcome = phase
            # The outer guard sends the final 408/413, or suppresses writes to a
            # disconnected client. Do not turn expected cleanup into a traceback.
            return _api_error(task_id, 408 if 'timeout' in phase else 400, '上传未完成，未进入模型队列')
        upload_outcome = 'error'
        logger.exception('API 样本上传失败 task_id=%s', task_id)
        return _api_error(task_id, 500, '样本上传失败')
    finally:
        _api_uploads_inflight -= 1
        progress = request.scope.get('state', {}).get('upload_receive', {})
        logger.info('API 上传释放名额 task_id=%s outcome=%s phase=%s received_bytes=%s inflight=%s elapsed_seconds=%.3f',
                    task_id, upload_outcome, progress.get('phase', 'unknown'), progress.get('received_bytes', 0),
                    _api_uploads_inflight, monotonic_time.monotonic()-upload_started)
    if not info['is_pe']:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        result = _payload(info, detection_mode='rejected', verdict=None)
        await asyncio.to_thread(task_store.record_direct_result, task_id, result)
        return _api_error(task_id, 422, info['pe_info'].get('reason') or '不是有效 PE 样本，未调用模型')
    blocked = await _reject_memory_sample(task_id, info, file_path, 'api')
    if blocked:
        return await _api_final_result(blocked, response, 0, include_details=include_details)
    try:
        row = await asyncio.to_thread(task_store.create, task_id, info['filename'], file_path,
                                     settings.max_queued_scans + settings.max_concurrent_scans,
                                     sha256=info['sha256'], request_source='api', file_size=info['file_size'])
    except QueueFull:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        return _api_error(task_id, 429, '模型队列已满，请稍后重试')
    except ExpiredRequest:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        return _api_error(task_id, 410, '该请求标识的结果已过期，请使用新的标识')
    except BaseException:
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
        raise
    if row['file_path'] != str(file_path):
        await asyncio.to_thread(file_path.unlink, missing_ok=True)
    if row.get('request_source') != 'api':
        return _api_error(task_id, 409, '请求标识已用于网页任务，请使用新的标识')
    task_wakeup.set()
    return await _api_final_result(row, response, wait_seconds, include_details=include_details)


@app.get('/api/v1/detect/tasks/{task_id}', tags=['单文件联合判定'], summary='查询最终联合判定，不重复检测或计数')
async def api_detection_result(task_id: str, response: Response,
                               wait_seconds: int = Query(default=0, ge=0, le=3600),
                               include_details: Annotated[bool, Query()] = False):
    if not re.fullmatch(r'[a-f0-9]{32}', task_id):
        return _api_error('', 400, '检测请求标识无效')
    row = await asyncio.to_thread(task_store.get, task_id)
    if not row or row.get('request_source') != 'api':
        return _api_error(task_id, 404, 'API 检测任务不存在或结果已过期')
    return await _api_final_result(row, response, wait_seconds, include_details=include_details)


if __name__ == "__main__":
    import uvicorn

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
