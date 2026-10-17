from __future__ import annotations

import base64
import time

import httpx

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


def test_servers_are_independent() -> None:
    first, second = EchoProvider(), EchoProvider()
    with serve(first.app()) as a, serve(second.app()) as b:
        assert a != b
        httpx.get(f"{a}/one")
        httpx.get(f"{b}/two")
    assert [r.path for r in first.received] == ["/one"]
    assert [r.path for r in second.received] == ["/two"]
