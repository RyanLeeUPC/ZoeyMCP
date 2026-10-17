"""Run an ASGI app on a random loopback port for the duration of a test."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

import uvicorn
from starlette.types import ASGIApp

STARTUP_TIMEOUT = 10.0


class _ThreadServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        """Signals belong to the test runner, not to a server running in a thread."""


@contextmanager
def serve(app: ASGIApp) -> Iterator[str]:
    """Serve ``app`` on ``127.0.0.1`` and yield its base URL, e.g. ``http://127.0.0.1:53817``."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning", lifespan="off")
    server = _ThreadServer(config)
    thread = threading.Thread(target=lambda: asyncio.run(server.serve()), daemon=True)
    thread.start()
    deadline = time.monotonic() + STARTUP_TIMEOUT
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise RuntimeError("fake provider failed to start")
        time.sleep(0.01)
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(STARTUP_TIMEOUT)
