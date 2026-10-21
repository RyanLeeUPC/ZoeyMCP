"""Run an ASGI app on a random loopback port for the duration of a test."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import uvicorn
from starlette.types import ASGIApp

STARTUP_TIMEOUT = 10.0
# A connection the client reset can stay registered on Windows until this runs out.
SHUTDOWN_GRACE = 1


class _ThreadServer(uvicorn.Server):
    def install_signal_handlers(self) -> None:
        """Signals belong to the test runner, not to a server running in a thread."""


@contextmanager
def serve(
    app: ASGIApp,
    *,
    lifespan: bool = False,
    proxy_headers: bool = True,
    tls: tuple[Path, Path] | None = None,
) -> Iterator[str]:
    """Serve ``app`` on ``127.0.0.1`` and yield its base URL, e.g. ``http://127.0.0.1:53817``.

    ``lifespan`` runs the app's ASGI lifespan (the fake MCP server needs it). Responses still
    open at the end are cut after ``SHUTDOWN_GRACE`` seconds. ``proxy_headers=False`` is how
    the gateway runs: uvicorn's default trusts ``X-Forwarded-For`` from loopback. ``tls`` is a
    certificate and key file (``tests/acceptance/tls.py``'s ``issue_cert``): the app is then
    served over HTTPS, as the fake resolver's dial map reaches it (M7 design BP-1).
    """
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=0,
        log_level="warning",
        lifespan="on" if lifespan else "off",
        proxy_headers=proxy_headers,
        timeout_graceful_shutdown=SHUTDOWN_GRACE,
        ssl_certfile=None if tls is None else str(tls[0]),
        ssl_keyfile=None if tls is None else str(tls[1]),
    )
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
        yield f"{'http' if tls is None else 'https'}://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(STARTUP_TIMEOUT)
