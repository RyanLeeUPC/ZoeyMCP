"""The vault's streams and its answers to the gateway (M3 design F.6, J.2, G13, G14).

Streams on stream routes are scrubbed one SSE event or NDJSON line at a time. Buffered answers to
the gateway are scrubbed at any size, and an upstream redirect is a 502 for it. When the caller
leaves, before upstream headers or while relaying, the upstream request is closed.
"""

from __future__ import annotations

import asyncio
import gc
import io
import json
import socket
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any, Literal, cast

import anyio
import httpx
import pytest
from starlette.types import Message

from tests.fakes.echo import EchoProvider
from tests.fakes.harness import serve
from zoeymcp.common.policy import Policy
from zoeymcp.vault import logs
from zoeymcp.vault.app import (
    CONNECT_TIMEOUT,
    LISTENER_SCOPE_KEY,
    MAX_SCRUB_BYTES,
    READ_TIMEOUT,
    REFUSAL_HEADER,
    REFUSAL_MARKER,
    CallerGone,
    Departure,
    VaultApp,
)
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.request import MAX_STREAM_EVENT_BYTES, secret_variants
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore, origin_binding

KEYS = KeySet.from_master(bytes(range(32)))
PH = "ph-agent1-direct-0001"
SECRET = 'fake/key>?+01="x"'
VARIANTS = secret_variants(SECRET)
CRED = {"api-key": {"kind": "header", "secret": "store:api-key"}}
SSE = {"content-type": "text/event-stream"}
NDJSON = {"content-type": "application/x-ndjson"}
JSON = {"content-type": "application/json"}

Caller = Literal["agent", "gateway"]

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def captured() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


@pytest.fixture
async def reported() -> AsyncIterator[list[dict[str, Any]]]:
    """What reaches the loop's exception handler during the test."""
    contexts: list[dict[str, Any]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda loop, context: contexts.append(context))
    try:
        yield contexts
    finally:
        loop.set_exception_handler(None)


def lines(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    parsed = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in parsed if line["event"] == kind]


def make_policy(**overrides: Any) -> Policy:
    route: dict[str, Any] = {
        "name": "api",
        "prefix": "/api",
        "upstream": "https://api.example/base",
        "credential": "api-key",
        "callers": ["gateway", {"placeholder": PH}],
        "stream": True,
        "rules": [{"methods": ["GET", "POST"], "paths": ["/v1/**"]}],
    }
    route.update(overrides)
    return Policy.model_validate(
        {
            "version": 1,
            "mode": "declarative",
            "credentials": CRED,
            "routes": [route],
        }
    )


class Chunks(httpx.AsyncByteStream):
    """An upstream body sent in these chunks. Then it ends, goes silent, or fails."""

    def __init__(
        self, chunks: list[bytes], then: Literal["end", "silence", "error"] = "end"
    ) -> None:
        self.chunks = chunks
        self.then = then
        self.pulled = 0
        self.silent = asyncio.Event()
        self.cancelled = False
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.pulled += 1
            yield chunk
        if self.then == "silence":
            self.silent.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                self.cancelled = True
                raise
        elif self.then == "error":
            raise httpx.ReadError("the upstream reset the connection")

    async def aclose(self) -> None:
        self.closed = True


Answer = Callable[[httpx.Request], Awaitable[httpx.Response]]


def answer(
    chunks: list[bytes],
    headers: dict[str, str],
    *,
    status: int = 200,
    then: Literal["end", "silence", "error"] = "end",
) -> tuple[Answer, Chunks]:
    stream = Chunks(chunks, then)

    async def respond(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers=headers, stream=stream)

    return respond, stream


class Rig:
    def __init__(self, tmp_path: Path, respond: Answer, pol: Policy | None = None) -> None:
        store = SecretStore(tmp_path, KEYS)
        store.load()
        store.put("api-key", SECRET, origin_binding(["https://api.example"]))
        self.respond = respond
        self.requests: list[httpx.Request] = []
        client = httpx.AsyncClient(transport=httpx.MockTransport(self._handle))
        self.app = VaultApp(pol or make_policy(), store, KEYS, client=client, environ={})

    async def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return await self.respond(request)

    async def call(
        self, path: str = "/api/v1/mcp", *, caller: Caller = "agent", method: str = "POST"
    ) -> httpx.Response:
        app: Any = ListenerTag(self.app, "gateway") if caller == "gateway" else self.app
        headers = {} if caller == "gateway" else {"Authorization": f"Bearer {PH}"}
        transport = httpx.ASGITransport(app=app, client=("172.30.4.10", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=headers, content=b"{}")


class RawCaller:
    """Calls the app as an ASGI server would, and can leave at any point."""

    def __init__(self, *, fail: bool = False, failing_send: bool = False) -> None:
        self.leave = asyncio.Event()
        self.sent: list[Message] = []
        self.fail = fail
        self.failing_send = failing_send
        self._body_read = False

    async def receive(self) -> dict[str, Any]:
        if not self._body_read:
            self._body_read = True
            return {"type": "http.request", "body": b"{}", "more_body": False}
        await self.leave.wait()
        if self.fail:
            raise OSError("connection reset")
        return {"type": "http.disconnect"}

    async def send(self, message: Message) -> None:
        if self.failing_send and message.get("body"):
            raise OSError("the caller's connection is gone")
        self.sent.append(message)

    @property
    def body(self) -> bytes:
        return b"".join(m.get("body", b"") for m in self.sent)

    def start(self, app: VaultApp, *, caller: Caller = "agent") -> asyncio.Task[None]:
        headers = [(b"host", b"vault"), (b"content-length", b"2")]
        if caller == "agent":
            headers.append((b"authorization", f"Bearer {PH}".encode()))
        scope = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/mcp",
            "raw_path": b"/api/v1/mcp",
            "query_string": b"",
            "root_path": "",
            "headers": headers,
            "client": ("172.30.4.10", 40000),
            "server": ("vault", 80),
            LISTENER_SCOPE_KEY: "gateway" if caller == "gateway" else "tcp",
        }
        return asyncio.create_task(app(scope, self.receive, self.send))


async def until(condition: Callable[[], object], what: str) -> None:
    """Waits up to 10 seconds for ``condition``, so a broken test fails instead of hanging."""
    for _ in range(1000):
        if condition():
            return
        await asyncio.sleep(0.01)
    raise AssertionError(what)


async def settle() -> None:
    """Let cancellations finish and collect what's gone, so a lost error would be reported."""
    await asyncio.sleep(0)
    gc.collect()
    await asyncio.sleep(0)


def left_over(before: set[asyncio.Task[Any]]) -> set[asyncio.Task[Any]]:
    """Tasks made since ``before`` that still run, besides the test's own."""
    return asyncio.all_tasks() - before - {cast(asyncio.Task[Any], asyncio.current_task())}


# --- scrubbing streams ---------------------------------------------------------------------------


def cuts(variant: bytes) -> list[int]:
    return sorted({1, len(variant) // 2, len(variant) - 1})


# Plain ids: pytest escapes the backslashes in a repr() id again on each collection in one process,
# so mutmut's recorded test names stopped matching.
SPLITS = [
    pytest.param(v, c, id=f"form{i}-cut{c}")
    for i, v in enumerate(sorted(VARIANTS))
    for c in cuts(v)
]


@pytest.mark.parametrize("caller", ["agent", "gateway"])
@pytest.mark.parametrize(("variant", "cut"), SPLITS)
async def test_an_sse_echo_split_across_chunks_is_scrubbed(
    tmp_path: Path, captured: io.StringIO, caller: Caller, variant: bytes, cut: int
) -> None:
    event = b'event: message\ndata: {"error": "bad key ' + variant + b'"}\n\n'
    split = event.index(variant) + cut
    respond, stream = answer([b": ping\n\n", event[:split], event[split:]], SSE)
    r = Rig(tmp_path, respond)
    response = await r.call(caller=caller)
    assert response.status_code == 200
    assert response.content == (
        b': ping\n\nevent: message\ndata: {"error": "bad key [REDACTED]"}\n\n'
    )
    assert stream.closed
    [request] = lines(captured, "request")
    assert (request["streamed"], request["scrubbed"]) == (True, 0)
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["scrubbed"]) == ("ok", 1)
    assert closed["bytes"] == len(response.content)


@pytest.mark.parametrize(("variant", "cut"), SPLITS)
async def test_an_ndjson_echo_split_across_chunks_is_scrubbed(
    tmp_path: Path, captured: io.StringIO, variant: bytes, cut: int
) -> None:
    line = b'{"error": "bad key ' + variant + b'"}\n'
    split = line.index(variant) + cut
    respond, stream = answer([b'{"ok": 1}\n', line[:split], line[split:]], NDJSON)
    r = Rig(tmp_path, respond)
    response = await r.call(caller="gateway")
    assert response.content == b'{"ok": 1}\n{"error": "bad key [REDACTED]"}\n'
    assert stream.closed
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["scrubbed"]) == ("ok", 1)


async def test_an_unended_last_event_is_scrubbed(tmp_path: Path) -> None:
    respond, _ = answer([b"data: " + SECRET.encode()[:5], SECRET.encode()[5:]], SSE)
    response = await Rig(tmp_path, respond).call()
    assert response.content == b"data: [REDACTED]"


async def test_header_and_event_echoes_are_counted(tmp_path: Path, captured: io.StringIO) -> None:
    respond, _ = answer(
        [b"data: " + SECRET.encode() + b"\n\n"], {**SSE, "x-echo": SECRET, "x-other": "ok"}
    )
    response = await Rig(tmp_path, respond).call()
    assert response.headers["x-echo"] == "[REDACTED]"
    assert response.headers["x-other"] == "ok"
    [request] = lines(captured, "request")
    assert request["scrubbed"] == 1
    [closed] = lines(captured, "stream_closed")
    assert set(closed) == {
        "ts",
        "role",
        "event",
        "route",
        "bytes",
        "scrubbed",
        "duration_ms",
        "outcome",
    }
    assert (closed["route"], closed["scrubbed"], closed["outcome"]) == ("api", 2, "ok")
    assert closed["bytes"] == len(b"data: [REDACTED]\n\n")
    assert closed["duration_ms"] >= 0


async def test_a_stream_without_a_credential_passes_as_it_is(
    tmp_path: Path, captured: io.StringIO
) -> None:
    respond, _ = answer([b"data: " + SECRET.encode() + b"\n\n"], SSE)
    r = Rig(tmp_path, respond, make_policy(credential=None))
    response = await r.call()
    assert response.content == b"data: " + SECRET.encode() + b"\n\n"
    [closed] = lines(captured, "stream_closed")
    assert (closed["scrubbed"], closed["outcome"]) == (0, "ok")


async def test_a_stream_without_a_credential_is_not_held(
    tmp_path: Path, captured: io.StringIO
) -> None:
    respond, stream = answer([b"data: one\n"], SSE, then="silence")
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond, make_policy(credential=None)).app)
    await asyncio.wait_for(stream.silent.wait(), 5)
    # The chunk was relayed before the upstream went silent, though its event hasn't ended.
    assert caller.body == b"data: one\n"
    caller.leave.set()
    await asyncio.wait_for(task, 1)
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["bytes"]) == ("cancelled", len(b"data: one\n"))


async def test_an_sse_type_with_parameters_is_held_per_event(
    tmp_path: Path, captured: io.StringIO
) -> None:
    respond, stream = answer(
        [b"data: one\n"], {"content-type": "Text/Event-Stream; charset=utf-8"}, then="silence"
    )
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app)
    await asyncio.wait_for(stream.silent.wait(), 5)
    # A line of an event that hasn't ended is held, as SSE is, not sent as an NDJSON line.
    assert caller.sent[0]["status"] == 200
    assert caller.body == b""
    caller.leave.set()
    await asyncio.wait_for(task, 1)
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["bytes"]) == ("cancelled", 0)


async def test_an_oversized_event_ends_the_stream(tmp_path: Path, captured: io.StringIO) -> None:
    mib = 1024 * 1024
    chunks = [
        b"data: first\n\n",
        b"data: " + b"x" * mib,
        *[b"x" * mib] * 17,
        b"\n\ndata: never\n\n",
    ]
    assert sum(map(len, chunks[1:18])) > MAX_STREAM_EVENT_BYTES
    respond, stream = answer(chunks, SSE)
    response = await Rig(tmp_path, respond).call(caller="gateway")
    assert response.status_code == 200
    assert response.content == b"data: first\n\n"
    # Nothing was read past the chunk that went over the limit.
    assert stream.pulled == 18
    assert stream.closed
    [too_large] = lines(captured, "stream_event_too_large")
    assert too_large["route"] == "api"
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["bytes"]) == ("event_too_large", len(b"data: first\n\n"))
    assert "phase" not in closed


async def test_an_upstream_failure_ends_the_stream(tmp_path: Path, captured: io.StringIO) -> None:
    respond, stream = answer([b"data: one\n\n"], SSE, then="error")
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app)
    await asyncio.wait_for(task, 2)
    assert caller.body == b"data: one\n\n"
    assert caller.sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert stream.closed
    [closed] = lines(captured, "stream_closed")
    assert closed["outcome"] == "upstream_error"


# --- relayed stream headers ----------------------------------------------------------------------


async def test_a_relayed_stream_asks_proxies_not_to_buffer(tmp_path: Path) -> None:
    respond, _ = answer([b"data: one\n\n"], {**SSE, "X-Accel-Buffering": "yes"})
    response = await Rig(tmp_path, respond).call()
    assert response.headers.get_list("x-accel-buffering") == ["no"]


async def test_a_buffered_answer_has_no_buffering_header(tmp_path: Path) -> None:
    respond, _ = answer([b'{"ok": true}'], JSON)
    response = await Rig(tmp_path, respond).call()
    assert response.json() == {"ok": True}
    assert "x-accel-buffering" not in response.headers


# --- buffered answers to the gateway ------------------------------------------------------------


@pytest.mark.parametrize(
    ("caller", "content_type", "scrubbed"),
    [
        ("gateway", "application/json", True),
        ("gateway", "application/octet-stream", True),
        ("agent", "application/json", False),
        ("agent", "application/octet-stream", False),
    ],
)
async def test_the_gateway_gets_every_buffered_answer_scrubbed(
    tmp_path: Path, captured: io.StringIO, caller: Caller, content_type: str, scrubbed: bool
) -> None:
    body = b'{"pad": "' + b"x" * MAX_SCRUB_BYTES + b'", "key": "' + SECRET.encode() + b'"}'
    respond, stream = answer([body[:1000], body[1000:]], {"content-type": content_type})
    response = await Rig(tmp_path, respond).call(caller=caller)
    assert response.status_code == 200
    assert (SECRET.encode() in response.content) is not scrubbed
    assert (b"[REDACTED]" in response.content) is scrubbed
    assert stream.closed
    [request] = lines(captured, "request")
    assert request["scrubbed"] == (1 if scrubbed else 0)


async def test_small_answers_to_other_callers_are_still_scrubbed(tmp_path: Path) -> None:
    respond, _ = answer([b'{"key": "' + SECRET.encode() + b'"}'], JSON)
    response = await Rig(tmp_path, respond).call(caller="agent")
    assert response.json() == {"key": "[REDACTED]"}


# --- redirects (G14) -----------------------------------------------------------------------------


@pytest.mark.parametrize("status", [300, 301, 302, 303, 304, 307, 308, 399])
@pytest.mark.parametrize("headers", [JSON, SSE])
async def test_a_redirect_to_the_gateway_is_a_502(
    tmp_path: Path, captured: io.StringIO, status: int, headers: dict[str, str]
) -> None:
    respond, stream = answer(
        [b'{"moved": true}'], {**headers, "location": "/mail/send"}, status=status
    )
    response = await Rig(tmp_path, respond).call(caller="gateway")
    assert response.status_code == 502
    assert response.json() == {"error": "upstream unavailable"}
    assert response.headers[REFUSAL_HEADER] == REFUSAL_MARKER
    assert "location" not in response.headers
    assert stream.closed
    assert stream.pulled == 0
    [request] = lines(captured, "request")
    assert (request["status"], request["upstream_status"]) == (502, status)
    assert request["reason"] == "redirect refused"
    assert lines(captured, "stream_closed") == []


@pytest.mark.parametrize("status", [200, 299, 400, 404])
async def test_other_statuses_reach_the_gateway(tmp_path: Path, status: int) -> None:
    respond, _ = answer([b'{"ok": true}'], {**JSON, "location": "/elsewhere"}, status=status)
    response = await Rig(tmp_path, respond).call(caller="gateway")
    assert response.status_code == status
    assert REFUSAL_HEADER not in response.headers


async def test_a_redirect_to_another_caller_is_relayed(tmp_path: Path) -> None:
    respond, _ = answer([b""], {**JSON, "location": "/mail/send"}, status=307)
    response = await Rig(tmp_path, respond).call(caller="agent")
    assert response.status_code == 307
    assert response.headers["location"] == "/mail/send"
    assert REFUSAL_HEADER not in response.headers


# --- the caller leaving (F.6) -------------------------------------------------------------------


class SilentUpstream:
    """Never answers, and notes when the vault gives up on it."""

    def __init__(self) -> None:
        self.waiting = asyncio.Event()
        self.cancelled = False

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.waiting.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("never")


@pytest.mark.parametrize("fail", [False, True])
async def test_leaving_before_upstream_headers_closes_the_request(
    tmp_path: Path, captured: io.StringIO, reported: list[dict[str, Any]], fail: bool
) -> None:
    tasks = asyncio.all_tasks()
    upstream = SilentUpstream()
    r = Rig(tmp_path, upstream)
    caller = RawCaller(fail=fail)
    task = caller.start(r.app, caller="gateway")
    await asyncio.wait_for(upstream.waiting.wait(), 5)
    await asyncio.sleep(0.05)
    assert not task.done()
    caller.leave.set()
    await asyncio.wait_for(task, 1)
    assert upstream.cancelled
    assert caller.sent == []
    [request] = lines(captured, "request")
    assert (request["outcome"], request["phase"]) == ("cancelled", "headers")
    assert "status" not in request
    assert request["caller"] == "gateway"
    assert lines(captured, "stream_closed") == []
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_leaving_mid_stream_closes_a_silent_upstream(
    tmp_path: Path, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    respond, stream = answer([b"data: one\n\n"], SSE, then="silence")
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app)
    await asyncio.wait_for(stream.silent.wait(), 5)
    await until(lambda: caller.body == b"data: one\n\n", "the first event never arrived")
    assert caller.sent[0]["status"] == 200
    assert (b"x-accel-buffering", b"no") in caller.sent[0]["headers"]
    assert not task.done()
    caller.leave.set()
    await asyncio.wait_for(task, 1)
    assert stream.cancelled
    assert stream.closed
    # The stream was cut, not ended.
    assert all(m.get("more_body", True) for m in caller.sent[1:])
    [request] = lines(captured, "request")
    assert (request["status"], request["streamed"]) == (200, True)
    assert "outcome" not in request
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["phase"]) == ("cancelled", "relay")
    assert closed["bytes"] == len(b"data: one\n\n")
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_cancelled_relay_closes_the_upstream(
    tmp_path: Path, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    """A relay cancelled from outside (the server shutting down) still closes and logs."""
    tasks = asyncio.all_tasks()
    respond, stream = answer([b"data: one\n\n"], SSE, then="silence")
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app)
    await asyncio.wait_for(stream.silent.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert stream.cancelled
    assert stream.closed
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["phase"]) == ("cancelled", "relay")
    assert closed["bytes"] == len(b"data: one\n\n")
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_leaving_while_a_buffered_answer_arrives_closes_it(
    tmp_path: Path, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    respond, stream = answer([b'{"partial": '], JSON, then="silence")
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app, caller="gateway")
    await asyncio.wait_for(stream.silent.wait(), 5)
    caller.leave.set()
    await asyncio.wait_for(task, 1)
    assert stream.cancelled
    assert stream.closed
    assert caller.sent == []
    [request] = lines(captured, "request")
    assert (request["outcome"], request["phase"]) == ("cancelled", "relay")
    assert request["upstream_status"] == 200
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_ndjson_lines_go_out_as_they_end(tmp_path: Path, captured: io.StringIO) -> None:
    respond, stream = answer([b'{"a": 1}\n{"b"'], NDJSON, then="silence")
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app, caller="gateway")
    await asyncio.wait_for(stream.silent.wait(), 5)
    await until(lambda: caller.body == b'{"a": 1}\n', "the first line never arrived")
    caller.leave.set()
    await asyncio.wait_for(task, 1)
    assert stream.closed
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["bytes"]) == ("cancelled", len(b'{"a": 1}\n'))


async def test_a_buffered_answer_stops_watching_the_caller(
    tmp_path: Path, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    respond, stream = answer([b'{"ok": true}'], JSON)
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app, caller="gateway")
    await asyncio.wait_for(task, 2)
    assert caller.body == b'{"ok": true}'
    assert stream.closed
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_failed_write_ends_the_relay(tmp_path: Path, captured: io.StringIO) -> None:
    respond, stream = answer([b"data: one\n\n", b"data: two\n\n"], SSE)
    caller = RawCaller(failing_send=True)
    task = caller.start(Rig(tmp_path, respond).app)
    await asyncio.wait_for(task, 2)
    assert stream.closed
    assert stream.pulled == 1
    [closed] = lines(captured, "stream_closed")
    assert (closed["outcome"], closed["phase"]) == ("cancelled", "relay")


async def test_a_finished_stream_stops_watching_the_caller(
    tmp_path: Path, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()
    respond, stream = answer([b"data: one\n\n"], SSE)
    caller = RawCaller()
    task = caller.start(Rig(tmp_path, respond).app)
    await asyncio.wait_for(task, 2)
    assert caller.sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}
    assert stream.closed
    [closed] = lines(captured, "stream_closed")
    assert closed["outcome"] == "ok"
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


async def test_a_refusal_after_the_body_stops_watching_the_caller(
    tmp_path: Path, captured: io.StringIO, reported: list[dict[str, Any]]
) -> None:
    tasks = asyncio.all_tasks()

    async def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to the upstream")

    caller = RawCaller()
    task = caller.start(Rig(tmp_path, fail).app)
    await asyncio.wait_for(task, 2)
    assert caller.sent[0]["status"] == 502
    await settle()
    assert left_over(tasks) == set()
    assert reported == []


# --- Departure ---------------------------------------------------------------------------------


def staying() -> tuple[Callable[[], Awaitable[dict[str, Any]]], asyncio.Event]:
    leave = asyncio.Event()

    async def receive() -> dict[str, Any]:
        await leave.wait()
        return {"type": "http.disconnect"}

    return receive, leave


async def test_race_returns_the_work() -> None:
    receive, _ = staying()
    departure = Departure(receive)

    async def work() -> str:
        return "done"

    assert await departure.race(work(), phase="headers") == "done"
    departure.close()


async def test_race_raises_what_the_work_raised() -> None:
    receive, _ = staying()
    departure = Departure(receive)

    async def work() -> str:
        raise httpx.ReadError("broken")

    with pytest.raises(httpx.ReadError):
        await departure.race(work(), phase="relay")
    departure.close()


@pytest.mark.parametrize("phase", ["headers", "relay"])
async def test_race_cancels_the_work_when_the_caller_leaves(
    phase: Literal["headers", "relay"],
) -> None:
    receive, leave = staying()
    departure = Departure(receive)
    cancelled = asyncio.Event()

    async def work() -> str:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return "never"

    leave.set()
    with pytest.raises(CallerGone) as gone:
        await departure.race(work(), phase=phase)
    assert gone.value.phase == phase
    assert str(gone.value) == f"the caller left during {phase}"
    assert cancelled.is_set()
    # Once gone, every later race ends at once.
    with pytest.raises(CallerGone):
        await departure.race(asyncio.sleep(10), phase="relay")
    departure.close()


async def test_race_cancelled_from_outside_cancels_the_work() -> None:
    receive, _ = staying()
    departure = Departure(receive)
    started, cancelled = asyncio.Event(), asyncio.Event()

    async def work() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancelled.set()
            raise

    racing = asyncio.create_task(departure.race(work(), phase="relay"))
    await started.wait()
    racing.cancel()
    with pytest.raises(asyncio.CancelledError):
        await racing
    assert cancelled.is_set()
    departure.close()


# --- real sockets ------------------------------------------------------------------------------


@pytest.mark.parametrize(("phase", "target"), [("headers", "/slow"), ("relay", "/slow?events=1")])
def test_a_closed_socket_closes_a_silent_upstream(tmp_path: Path, phase: str, target: str) -> None:
    """On real servers, the upstream sees the vault leave within a second of the caller."""
    echo = EchoProvider()
    with serve(echo.app()) as upstream_base:
        store = SecretStore(tmp_path, KEYS)
        store.load()
        store.put("api-key", SECRET, origin_binding([upstream_base]))
        pol = make_policy(
            upstream=upstream_base,
            allow_insecure_upstream=True,
            rules=[{"methods": ["GET"], "paths": ["/slow"]}],
        )
        # The real route client is guarded: the loopback fake is listed (M7 design B.2).
        pol = pol.model_copy(update={"egress_private": [upstream_base.removeprefix("http://")]})
        app = VaultApp(pol, store, KEYS, environ={})
        with serve(app) as vault_base:
            host, port = vault_base.removeprefix("http://").split(":")
            with socket.create_connection((host, int(port)), timeout=5) as sock:
                sock.sendall(
                    f"GET /api{target} HTTP/1.1\r\nHost: v\r\n"
                    f"Authorization: Bearer {PH}\r\n\r\n".encode()
                )
                if phase == "relay":
                    data = b""
                    while b"data: slow 0\n\n" not in data:
                        chunk = sock.recv(4096)
                        assert chunk, data
                        data += chunk
                    assert b"x-accel-buffering: no" in data.lower()
                else:
                    deadline = time.monotonic() + 5
                    while not echo.received:
                        assert time.monotonic() < deadline, "the vault never sent the request"
                        time.sleep(0.01)
                    time.sleep(0.1)
                assert echo.departures == []
                left = time.monotonic()
            assert echo.departed.wait(5)
    assert 0 <= echo.departures[0] - left < 1.0
    assert echo.received[0].header("authorization") == f"Bearer {SECRET}"


# --- FM-19's in-process half: a bridge-shaped route has no read timeout (M7 design N.1, GR-10) ----


@pytest.mark.parametrize("stream", [True, False])
async def test_stream_route_has_no_read_timeout(tmp_path: Path, stream: bool) -> None:
    """A bridge's route (a local MCP route, ``stream: true``) is sent with no read timeout, so a
    call silent within the gateway's ``call_timeout`` isn't cut by the vault; a route that
    doesn't stream keeps the vault's 60 s. The connect timeout is the same."""
    pol = make_policy(
        upstream="http://127.0.0.1:9000",
        allow_insecure_upstream=True,
        callers=["gateway"],
        stream=stream,
        rules=[{"methods": ["POST"], "paths": ["/mcp"]}],
    )
    timeouts: list[dict[str, float | None]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200, headers=SSE, content=b"data: {}\n\n")

    store = SecretStore(tmp_path, KEYS)
    store.load()
    store.put("api-key", SECRET, origin_binding(["http://127.0.0.1:9000"]))
    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    app = VaultApp(pol, store, KEYS, client=client, environ={})
    transport = httpx.ASGITransport(app=ListenerTag(app, "gateway"), client=("127.0.0.1", 4000))
    try:
        with anyio.fail_after(5):
            async with httpx.AsyncClient(transport=transport, base_url="http://vault") as caller:
                answer = await caller.post("/api/mcp", content=b"{}")
    finally:
        await app.aclose()
    assert answer.status_code == 200, answer.text
    [timeout] = timeouts
    assert timeout["read"] == (None if stream else READ_TIMEOUT)
    assert timeout["connect"] == CONNECT_TIMEOUT
