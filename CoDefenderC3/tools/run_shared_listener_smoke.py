"""Real loopback HTTP smoke with synthetic PE/models (no deployment claims)."""
import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from test_merge_contracts import core, Extractor, ensemble, pe_bytes
import httpx
from engine.serve import serve


def free_ports():
    sockets = [socket.socket() for _ in range(3)]
    try:
        for sock in sockets:
            sock.bind(("127.0.0.1", 0))
        return [sock.getsockname()[1] for sock in sockets]
    finally:
        for sock in sockets:
            sock.close()


async def main():
    web, production, development = free_ports()
    env = {"CODEFENDER_WEB_COMPAT_HOST": "127.0.0.1", "CODEFENDER_WEB_COMPAT_PORT": str(web),
           "CODEFENDER_PRODUCTION_HOST": "127.0.0.1", "CODEFENDER_PRODUCTION_PORT": str(production),
           "CODEFENDER_ENABLE_DEV_API": "1", "CODEFENDER_DEV_PORT": str(development)}
    ens = ensemble()
    ens.K = len(ens._model_names)
    ens.V = len(ens.view_groups)
    with patch.dict(os.environ, env), patch.object(core, "_ENSEMBLE", ens), patch.object(core, "_load_ensemble", return_value=ens) as load, patch.object(core, "_get_extractor", return_value=Extractor()), patch.object(core, "_get_sdd_engine", side_effect=RuntimeError("synthetic baseline")):
        task = asyncio.create_task(serve())
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                for _ in range(100):
                    if task.done():
                        task.result()
                    try:
                        readiness = await asyncio.gather(*(client.get(f"http://127.0.0.1:{port}/readyz") for port in [web, production, development]))
                        if any(response.status_code >= 500 for response in readiness):
                            raise AssertionError([response.text for response in readiness])
                        if all(response.status_code == 200 for response in readiness):
                            break
                    except httpx.TransportError:
                        pass
                    await asyncio.sleep(0.05)
                else:
                    raise AssertionError("listeners did not become ready")
                assert load.call_count == 1, "three listeners must warm exactly one registry"
                with tempfile.TemporaryDirectory() as directory:
                    (Path(directory) / "sample.no-extension").write_bytes(pe_bytes())
                    for port, full in [(web, True), (production, False), (development, True)]:
                        response = await client.post(f"http://127.0.0.1:{port}/predict-single?include_de=false", files={"file": ("sample.exe", pe_bytes())})
                        assert response.status_code == 200, response.text
                        assert ("Score" in response.json()) == full
                        if port == development:
                            scan = response.json()["ScanResult"]
                            assert "PerModelPreds" not in scan and "PerModelDetails" not in scan
                            assert "AggregatedModels" not in scan["ModelStats"]
                            assert scan["ModelStats"]["OkModels"] == ens.K
                        elif port == web:
                            assert "PerModelPreds" in response.json()["ScanResult"]
                        response = await client.post(f"http://127.0.0.1:{port}/predict-directory", params={"directory": directory})
                        assert response.status_code == 200, response.text
                        assert ("Score" in response.json()["Results"][0]) == full
                        scan = response.json()["Results"][0]["ScanResult"]
                        if port == development:
                            assert "PerModelPreds" not in scan and "PerModelDetails" not in scan
                            assert "AggregatedModels" not in scan["ModelStats"]
                            assert scan["ModelStats"]["OkModels"] == ens.K
                        elif port == web:
                            assert "PerModelPreds" in scan and "PerModelDetails" in scan
                            assert "AggregatedModels" in scan["ModelStats"]
                response = await client.post(f"http://127.0.0.1:{web}/predict-stream?include_de=false", files={"file": ("sample.exe", pe_bytes())})
                events = [json.loads(line) for line in response.text.splitlines()]
                assert events[-1]["event"] == "result", events
                assert "PerModelDetails" in events[-1]["data"]["ScanResult"]
                assert (await client.post(f"http://127.0.0.1:{production}/predict-stream")).status_code == 404
                print("PASS real HTTP: 3 listeners, shared warmup/runtime, 6 predictions, Web NDJSON, compact development fields, no production stream leak")
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    asyncio.run(main())
