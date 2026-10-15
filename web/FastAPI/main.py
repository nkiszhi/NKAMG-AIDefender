import asyncio
import logging
import ctypes
import requests
from datetime import datetime

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from app.codefender_client import DEFAULT_MODEL_NAMES, scan_file
from app.config import settings
from app.file_info import save_upload
from app.sample_repository import SampleRepository


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("aidefender")
sample_repository = SampleRepository(settings)

app = FastAPI(
    title="NKAMG-AIDefender 多模型恶意文件检测",
    version="1.0.0",
    description="NKAMG-AIDefender 文件检测后端，接入 CoDefenderC3 模型服务",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=settings.cors_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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


@app.get("/models")
async def models() -> dict:
    return {"count": len(DEFAULT_MODEL_NAMES), "models": DEFAULT_MODEL_NAMES}


@app.get("/model-health")
async def model_health() -> dict:
    """Expose the Docker model service readiness to the web UI."""
    url = f"{settings.codefender_api_base}/readyz"
    try:
        response = await asyncio.to_thread(requests.get, url, timeout=10)
        if response.status_code != 503:
            response.raise_for_status()
        payload = response.json()
        return {"connected": True, "ready": payload.get("ready") is True, "model_count": payload.get("model_count", 0), "service": payload}
    except Exception as error:
        logger.warning("模型服务健康检查失败: %s", error)
        return {"connected": False, "ready": False, "model_count": 0, "detail": str(error)}


@app.post("/detect")
async def detect(file: UploadFile = File(...)) -> dict:
    try:
        file_path, info = await save_upload(file)
    except ValueError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
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
        raise HTTPException(status_code=500, detail=f"保存上传文件失败: {error}") from error
    except Exception as error:
        logger.exception("保存上传文件失败")
        raise HTTPException(status_code=500, detail=f"保存上传文件失败: {error}") from error

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

    database_error = None
    try:
        sample_record = sample_repository.find_malicious(info["sha256"])
    except RuntimeError as error:
        sample_record = None
        database_error = str(error)
        logger.warning("样本库查询不可用，继续33模型检测: %s", error)

    if sample_record:
        public_record = SampleRepository.public_fields(sample_record)
        logger.info(
            "样本库命中: sha256=%s 来源=%s.%s",
            info["sha256"],
            public_record.get("source_db"),
            public_record.get("source_table"),
        )
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

    try:
        exe_result = await asyncio.to_thread(scan_file, file_path)
    except RuntimeError as error:
        logger.exception("模型服务检测失败")
        raise HTTPException(status_code=502, detail=str(error)) from error
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


if __name__ == "__main__":
    import uvicorn

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
