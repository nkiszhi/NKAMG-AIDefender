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


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("codefender")

app = FastAPI(
    title="Codefender 多模型恶意文件检测",
    version="1.0.0",
    description="独立的 Codefender 文件检测后端",
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


@app.get("/")
async def root() -> dict:
    return {"message": "Codefender backend is running", "docs": "/docs"}


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
        raise HTTPException(status_code=400, detail=f"不是有效PE样本 [{info['filename']}]: {reason}")

    try:
        exe_result = await asyncio.to_thread(scan_file, file_path)
    except RuntimeError as error:
        logger.exception("模型服务检测失败")
        raise HTTPException(status_code=502, detail=str(error)) from error
    return _response_payload(info, exe_result, "file")


if __name__ == "__main__":
    import uvicorn

    settings.upload_dir.mkdir(parents=True, exist_ok=True)
    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=False)
