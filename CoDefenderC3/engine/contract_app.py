"""Separate HTTP contracts over a single main inference/runtime instance."""
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from engine.contract_pipeline import scan_directory, scan_upload
from engine.projection import project_directory, project_single


def create_app(core, *, development=False):
    from engine.production_result_formatter import format_scan_result as production_formatter
    from engine.dev.result_formatter import format_scan_result as development_formatter
    formatter = development_formatter if development else production_formatter
    app = FastAPI(title="CoDefender development" if development else "CoDefender production")
    app.state.inference_core = core
    app.middleware("http")(core._request_id_middleware)
    app.add_exception_handler(Exception, core._global_exception_handler)
    # Keep health/readiness/admin semantics; do not expose the full Web stream
    # on the production boundary (that would leak the fields we just removed).
    for route in core.web_app.routes:
        if route.path in {"/livez", "/readyz", "/health", "/metrics", "/model-info",
                          "/reload-model", "/update-signatures", "/admin/config"}:
            app.router.routes.append(route)
    app.router.add_event_handler("startup", core._warm_runtime_models)

    @app.post("/predict-single")
    async def predict_single(file: UploadFile = File(...),
                             include_de: bool = Query(default=core.DEFAULT_INCLUDE_DE)):
        try:
            if not file.filename:
                raise HTTPException(400, detail="empty filename")
            if core._SCAN_RUNTIME.active >= core._SCAN_RUNTIME.concurrency:
                raise HTTPException(429, detail="model service is busy; retry later", headers={"Retry-After": "3"})
            content = await file.read(core.MAX_UPLOAD_BYTES + 1)
            if not content:
                raise HTTPException(400, detail="empty file content")
            if len(content) > core.MAX_UPLOAD_BYTES:
                raise HTTPException(413, detail="file too large")
            result = await core._run_guarded(scan_upload, core, content, file.filename, include_de, formatter)
            return result if development else project_single(result)
        except ValueError as exc:
            raise HTTPException(400, detail=str(exc)) from exc
        finally:
            await file.close()

    @app.post("/predict-directory")
    async def predict_directory(directory: str = Query(..., description="服务器端目录绝对路径"),
                                recursive: bool = Query(default=True),
                                include_de: bool = Query(default=False)):
        result = await core._run_guarded(scan_directory, core, directory, recursive, include_de, formatter)
        return result if development else project_directory(result)

    return app
