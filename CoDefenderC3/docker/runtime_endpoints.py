# This fragment is installed into engine/app.py by patch_runtime.py.
# It deliberately uses the base image's existing feature/model functions.
from engine.scan_runtime import ScanRuntime, ScanBusy, ScanTimeout
from engine.staged_scan import run_staged, runtime_limits
from starlette.responses import StreamingResponse

_REQUEST_TIMEOUT, _HARD_TIMEOUT = runtime_limits()
_SCAN_RUNTIME = ScanRuntime(
    concurrency=int(os.environ.get('CODEFENDER_MAX_CONCURRENT', '1')),
    timeout=_REQUEST_TIMEOUT,
    hard_timeout=_HARD_TIMEOUT,
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
