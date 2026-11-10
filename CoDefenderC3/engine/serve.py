"""One process/event loop, one model registry, distinct HTTP contracts.

8000: main Web protocol (container-side port; preserve the existing host mapping).
18001: test_lm production projection, loopback-only by default.
18002: optional loopback-only development diagnostics (disabled by default).
Native deployments set CODEFENDER_WEB_COMPAT_PORT to Web's existing engine port.
Never run separate uvicorn workers for these three listeners.
"""
import asyncio
from contextlib import contextmanager
import os
import signal
import socket


def listeners(environ=None):
    env = os.environ if environ is None else environ
    result = [
        ("engine.web_compat:app", env.get("CODEFENDER_WEB_COMPAT_HOST", "0.0.0.0"), int(env.get("CODEFENDER_WEB_COMPAT_PORT", "8000"))),
        ("engine.app:app", env.get("CODEFENDER_PRODUCTION_HOST", "127.0.0.1"), int(env.get("CODEFENDER_PRODUCTION_PORT", "18001"))),
    ]
    if env.get("CODEFENDER_ENABLE_DEV_API", "0").lower() in {"1", "true", "yes"}:
        result.append(("engine.dev.app:app", "127.0.0.1", int(env.get("CODEFENDER_DEV_PORT", "18002"))))
    ports = [port for _, _, port in result]
    if len(set(ports)) != len(ports) or any(not 0 < port < 65536 for port in ports):
        raise ValueError("HTTP contracts must have distinct valid ports")
    return result


async def serve():
    from engine.startup import configure_disassembly_backend
    configure_disassembly_backend()
    import uvicorn

    class SharedServer(uvicorn.Server):
        def install_signal_handlers(self):  # uvicorn < 0.29
            pass

        @contextmanager
        def capture_signals(self):  # uvicorn >= 0.29
            yield

    servers, sockets, tasks = [], [], []
    old_handlers = {}
    try:
        # Bind every socket before starting any API: conflicting ports fail closed.
        for module, host, port in listeners():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if os.name == "nt":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                else:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, port))
                sock.listen(128)
                sock.setblocking(False)
            except BaseException:
                sock.close()
                raise
            sockets.append(sock)
            servers.append(SharedServer(uvicorn.Config(
                module, host=host, port=port, workers=1, lifespan="on", timeout_graceful_shutdown=30,
            )))

        def stop(*_):
            for server in servers:
                server.should_exit = True
        for sig in (signal.SIGINT, signal.SIGTERM):
            old_handlers[sig] = signal.signal(sig, stop)
        tasks = [asyncio.create_task(server.serve(sockets=[sock]))
                 for server, sock in zip(servers, sockets)]
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        stop()
        for task in done:
            task.result()
        await asyncio.gather(*tasks)
        if not all(server.started for server in servers):
            raise RuntimeError("one or more engine listeners failed to start")
    finally:
        for server in servers:
            server.should_exit = True
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for sock in sockets:
            sock.close()
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    asyncio.run(serve())
