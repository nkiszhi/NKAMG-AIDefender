"""Incremental development diagnostics over the existing single-sample policy.

The final-only endpoint is deliberately untouched. Features and predictions are
computed once; callbacks expose real completed rows before the final projection.
"""
import asyncio
import json
import os
import tempfile
import threading
import time

from fastapi import File, HTTPException, Query, UploadFile
from starlette.responses import StreamingResponse

from engine import contract_pipeline as pipeline, prediction_policy as policy
from engine.dev.projection import project_single


def scan_upload_stream(core, content, filename, include_de, formatter, progress):
    hit = core._hash_precheck(content, filename, len(content))
    if hit is not None:
        return pipeline._hash_result(hit, names=True)
    ens = core._load_ensemble()
    expected = core._infer_expected_view_dims(ens)
    started = time.monotonic()
    states = {name: {"model": name, "status": "waiting"} for name in ens._model_names}

    def publish(stage):
        progress({"stage": stage, "models": [dict(item) for item in states.values()],
                  "elapsed_seconds": round(time.monotonic() - started, 3)})

    # The worker, not the HTTP reader, owns cleanup even after a disconnect or
    # soft timeout. Never run a second inference to produce the final report.
    with tempfile.TemporaryDirectory(prefix="aidefender-stream-") as directory:
        path = os.path.join(directory, "sample.bin")
        with open(path, "wb") as handle:
            handle.write(content)
        publish("features")
        views, meta, mg_sample, analysis_error, slow_views, _ = pipeline._prepare_sample(
            core, path, ens, expected, include_de,
        )

        def completed(index, item):
            # Match scan_paths' exclusion policy BEFORE publishing a row: an
            # analysis failure must never appear as an intermediate valid vote.
            if analysis_error and (item.get("view") in slow_views or item["model"] == "MalGraph"):
                status, reason = analysis_error
                item.update(status=status, reason=reason)
                item.pop("score", None)
                item.pop("prediction", None)
            states[item["model"]] = dict(item)
            publish("models")

        per_model = policy._predict_per_model_batch(
            core, ens, {0: (views, meta)}, [path], include_de,
            malgraph_samples={0: mg_sample}, on_result=completed,
        )[0]
        if (per_model and all(item.get("status") != "ok" for item in per_model)
                and analysis_error and analysis_error[0] == "timeout"):
            raise HTTPException(504, detail="analysis_timeout: no valid model predictions")
        publish("finalizing")
        return policy._format_model_result(
            core, path, filename, len(content), ens, per_model, formatter,
        )


def register_stream(app, core, formatter):
    # Retain producers until they finish, including after the reader disconnects.
    # ScanRuntime keeps the capacity reserved until its real worker exits.
    producers = set()
    app.state.development_stream_producers = producers

    @app.post("/predict-stream")
    async def predict_stream(file: UploadFile = File(...),
                             include_de: bool = Query(default=core.DEFAULT_INCLUDE_DE)):
        try:
            if not file.filename:
                raise HTTPException(400, detail="empty filename")
            if core._SCAN_RUNTIME.active >= core._SCAN_RUNTIME.concurrency:
                raise HTTPException(429, detail="model service is busy; retry later",
                                    headers={"Retry-After": "3"})
            content = await file.read(core.MAX_UPLOAD_BYTES + 1)
            if not content:
                raise HTTPException(400, detail="empty file content")
            if len(content) > core.MAX_UPLOAD_BYTES:
                raise HTTPException(413, detail="file too large")
            filename = file.filename
        finally:
            await file.close()

        loop = asyncio.get_running_loop()
        events = asyncio.Queue()
        disconnected = threading.Event()

        def enqueue(event):
            if not disconnected.is_set():
                events.put_nowait(event)

        def progress(payload):
            if not disconnected.is_set():
                loop.call_soon_threadsafe(enqueue, {"event": "progress", "data": payload})

        async def produce():
            try:
                result = await core._run_guarded(
                    scan_upload_stream, core, content, filename, include_de, formatter, progress,
                )
                enqueue({"event": "result", "data": project_single(result)})
            except Exception as exc:
                enqueue({"event": "error", "status_code": getattr(exc, "status_code", 500),
                         "detail": str(getattr(exc, "detail", exc))})

        async def stream():
            producer = asyncio.create_task(produce())
            producers.add(producer)
            producer.add_done_callback(producers.discard)
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(events.get(), timeout=5)
                    except asyncio.TimeoutError:
                        yield json.dumps({"event": "heartbeat"}) + "\n"
                        continue
                    yield json.dumps(event, ensure_ascii=False, allow_nan=False) + "\n"
                    if event["event"] in ("result", "error"):
                        break
            finally:
                disconnected.set()

        return StreamingResponse(stream(), media_type="application/x-ndjson",
                                 headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"})
