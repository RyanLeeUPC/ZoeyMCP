"""What the browser tests run against: thin wrappers over the rigs and fakes that exist (D-222).

:func:`portal` is ``tests.portal.rig.running``: the real vault and portal on a server thread,
sockets bound first, a :class:`Clock` the test moves. :class:`GatewayDeployment` (the vault and
gateway in process against the MCP fake) and :class:`ManagedVault` (a vault process) are the
acceptance rigs, for the later items. Two small servers of the harness's own, each on loopback
with its socket bound before the test names its port: :class:`Neighbour`, a page on another
``localhost`` port (manual item 10), and :class:`Forwarder`, a byte-for-byte forwarder from a
second port to the portal's listener, as an SSH tunnel is (item 12).
"""

from __future__ import annotations

import contextlib
import http.server
import socket
import threading
from collections.abc import Callable
from types import TracebackType
from typing import Self

from tests.acceptance.gateway import GatewayDeployment
from tests.acceptance.procs import ManagedVault
from tests.portal.rig import Clock, PortalRig
from tests.portal.rig import running as portal

__all__ = [
    "Clock",
    "Forwarder",
    "GatewayDeployment",
    "ManagedVault",
    "Neighbour",
    "PortalRig",
    "portal",
]

CHUNK = 65536


def bound() -> socket.socket:
    """A listening socket on 127.0.0.1, so its port is known before anything starts."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    return sock


class Neighbour:
    """Serves ``html`` at ``/<name>`` from 127.0.0.1, on the port it bound (``port``), until
    closed; any other path is a 404."""

    def __init__(self, name: str, html: str) -> None:
        body = html.encode("utf-8")
        path = f"/{name}"

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                found = self.path == path
                self.send_response(200 if found else 404)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body) if found else 0))
                self.end_headers()
                if found:
                    self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                pass

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def url(self, name: str) -> str:
        return f"http://localhost:{self.port}/{name}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(10)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class Forwarder:
    """Forwards each connection to ``port`` to ``target``, byte for byte in both directions, and
    keeps the browser's ``Host``. Bind it first (``Forwarder()``), name its port in the portal's
    origins, then :meth:`start` it once the target listens."""

    def __init__(self) -> None:
        self._sock = bound()
        self.port: int = self._sock.getsockname()[1]
        self._threads: list[threading.Thread] = []
        self._open: list[socket.socket] = []
        self._closed = False
        self._lock = threading.Lock()

    def start(self, target: tuple[str, int]) -> None:
        self._spawn(self._accept, target)

    def _spawn(self, run: Callable[..., None], *args: object) -> None:
        thread = threading.Thread(target=run, args=args, daemon=True)
        self._threads.append(thread)
        thread.start()

    def _accept(self, target: tuple[str, int]) -> None:
        while True:
            try:
                client, _ = self._sock.accept()
            except OSError:
                return  # closed
            try:
                upstream = socket.create_connection(target, timeout=10)
            except OSError:
                client.close()
                continue
            upstream.settimeout(None)
            with self._lock:
                if self._closed:  # accepted as close() ran: nothing pumps it
                    client.close()
                    upstream.close()
                    return
                self._open.extend((client, upstream))
            self._spawn(self._pump, client, upstream)
            self._spawn(self._pump, upstream, client)

    @staticmethod
    def _pump(source: socket.socket, sink: socket.socket) -> None:
        try:
            while chunk := source.recv(CHUNK):
                sink.sendall(chunk)
            sink.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # either side closed

    def close(self) -> None:
        # Shut down before closing: on Linux a close from another thread doesn't wake a thread
        # blocked in accept() or recv(), a shutdown does.
        with self._lock:
            self._closed = True
            socks = [self._sock, *self._open]
        for sock in socks:
            with contextlib.suppress(OSError):  # not connected, or already shut
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for thread in self._threads:
            thread.join(10)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
