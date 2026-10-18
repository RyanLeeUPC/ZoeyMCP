from __future__ import annotations

import base64
import socket
import time

import httpx
import pytest

from .echo import EchoProvider
from .harness import serve


def test_echo_reports_the_request() -> None:
    provider = EchoProvider()
    with serve(provider.app()) as base:
        response = httpx.post(
            f"{base}/v1/things?b=2&a=1&a=3",
            content=b"payload",
            headers={"X-Probe": "yes"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["method"] == "POST"
    assert body["path"] == "/v1/things"
    assert body["query"] == [["b", "2"], ["a", "1"], ["a", "3"]]
    assert base64.b64decode(body["body_b64"]) == b"payload"
    [received] = provider.received
    assert received.header("x-probe") == "yes"


def test_sse_streams_events_as_they_happen() -> None:
    provider = EchoProvider(sse_delay=0.2)
    arrivals: list[float] = []
    with serve(provider.app()) as base, httpx.stream("GET", f"{base}/sse?n=3") as response:
        assert response.headers["content-type"].startswith("text/event-stream")
        start = time.monotonic()
        for line in response.iter_lines():
            if line.startswith("data:"):
                arrivals.append(time.monotonic() - start)
    assert len(arrivals) == 3
    # Streamed, not buffered: the first event arrives well before the last one is sent.
    assert arrivals[0] < 0.15
    assert arrivals[-1] >= 0.3


def _read_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        assert chunk, data
        data += chunk
    return data


def test_slow_notes_when_its_caller_leaves() -> None:
    provider = EchoProvider()
    with serve(provider.app()) as base:
        host, port = base.removeprefix("http://").split(":")
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            sock.sendall(b"GET /slow?events=2 HTTP/1.1\r\nHost: fake\r\n\r\n")
            data = _read_until(sock, b"data: slow 1\n\n")
            assert data.startswith(b"HTTP/1.1 200 ")
            assert b"content-type: text/event-stream" in data
            assert b"data: slow 0\n\n" in data
            assert provider.departures == []
            left = time.monotonic()
        assert provider.departed.wait(5)
    [departed] = provider.departures
    assert 0 <= departed - left < 1
    assert [r.path for r in provider.received] == ["/slow"]


def test_slow_without_events_sends_nothing() -> None:
    provider = EchoProvider()
    with serve(provider.app()) as base:
        host, port = base.removeprefix("http://").split(":")
        with socket.create_connection((host, int(port)), timeout=5) as sock:
            sock.sendall(b"POST /slow HTTP/1.1\r\nHost: fake\r\nContent-Length: 2\r\n\r\nhi")
            sock.settimeout(0.3)
            with pytest.raises(TimeoutError):
                sock.recv(1)
        assert provider.departed.wait(5)
    [received] = provider.received
    assert (received.method, received.body) == ("POST", b"hi")


def test_servers_are_independent() -> None:
    first, second = EchoProvider(), EchoProvider()
    with serve(first.app()) as a, serve(second.app()) as b:
        assert a != b
        httpx.get(f"{a}/one")
        httpx.get(f"{b}/two")
    assert [r.path for r in first.received] == ["/one"]
    assert [r.path for r in second.received] == ["/two"]
