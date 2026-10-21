"""Phase 1's requests (M7 design B.5), through an ``httpx.MockTransport``: no network, no sleep.

The headers each request sends and nothing else; the probe's body never read; a redirect
followed nowhere, "not here" only from a well-known candidate; the size and type caps; the count
and the whole discovery's deadline, each refused before anything is sent; every error mapped
to M.2's reason with the host and port; the guard's per-request exception only on the probe
and protected-resource fetches (TI-10); and each request's record for ``discovery_fetch``.
The time limits themselves are FM-5 and FM-6's, in ``test_onboard_service.py`` (step 8a2).
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest

from zoeymcp import __version__
from zoeymcp.common.netguard import AddressVerdict
from zoeymcp.vault.netclient import ONBOARDING_EXTENSION, AddressRefused, ResolveFailed
from zoeymcp.vault.oauth.discovery import (
    LEGACY_PROBE,
    METADATA_MAX,
    MODERN_PROBE,
    REGISTRATION_MAX,
)
from zoeymcp.vault.oauth.fetch import (
    DISCOVERY_DEADLINE,
    DISCOVERY_FETCHES,
    FETCH_CONNECT,
    FETCH_TIMEOUT,
    REGISTRATION_TIMEOUT,
    USER_AGENT,
    Fetched,
    Fetcher,
    FetchError,
    FetchRecord,
    ProbeAnswer,
    ProxyRefused,
)

pytestmark = pytest.mark.anyio

SERVER = "https://mcp.example.com/mcp"
PRM = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
AS = "https://auth.example.com/.well-known/oauth-authorization-server"
REGISTER = "https://auth.example.com/register"
JSON = {"content-type": "application/json"}
Handler = Callable[[httpx.Request], httpx.Response]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Unread(httpx.AsyncByteStream):
    """A body that fails the test if anything reads it."""

    async def __aiter__(self) -> AsyncIterator[bytes]:
        raise AssertionError("the body was read")
        yield b""  # pragma: no cover

    async def aclose(self) -> None:
        pass


class Chunks(httpx.AsyncByteStream):
    """A body of chunks with no Content-Length, counting what was read."""

    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks
        self.read = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.read += 1
            yield chunk


class Recorder:
    """The transport: answers with ``handler`` and keeps every request."""

    def __init__(self, handler: Handler) -> None:
        self.handler = handler
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)


def answer(
    status: int = 200, body: object = None, headers: dict[str, str] | None = None
) -> Handler:
    content = b"" if body is None else json.dumps(body).encode()
    return lambda request: httpx.Response(status, headers=headers or JSON, stream=Chunks([content]))


def fetcher(handler: Handler, **kwargs: Any) -> tuple[Fetcher, Recorder, list[FetchRecord]]:
    recorder = Recorder(handler)
    client = httpx.AsyncClient(transport=httpx.MockTransport(recorder), trust_env=False)
    records: list[FetchRecord] = []
    kwargs.setdefault("clock", Clock())  # a still clock: every record takes 0 ms
    return Fetcher(client, report=records.append, **kwargs), recorder, records


def test_the_limits_are_pinned() -> None:
    assert (FETCH_CONNECT, FETCH_TIMEOUT, DISCOVERY_DEADLINE) == (5.0, 10.0, 30.0)
    assert DISCOVERY_FETCHES == 9
    assert REGISTRATION_TIMEOUT == 15.0
    assert f"zoeymcp/{__version__}" == USER_AGENT


# --- the probe ---------------------------------------------------------------------------------


@pytest.mark.parametrize("probe", [MODERN_PROBE, LEGACY_PROBE])
async def test_a_probe_sends_its_own_headers_and_reads_no_body(probe: Any) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            headers=[
                ("WWW-Authenticate", 'Bearer resource_metadata="x"'),
                ("WWW-Authenticate", "Basic"),
            ],
            stream=Unread(),
        )

    fetcher_, recorder, records = fetcher(handler)
    got = await fetcher_.probe(SERVER, probe)
    assert got == ProbeAnswer(401, ('Bearer resource_metadata="x"', "Basic"))
    (request,) = recorder.requests
    assert request.method == "POST"
    assert str(request.url) == SERVER
    assert request.content == probe.body
    expected = {name.lower(): value for name, value in probe.headers}
    expected |= {
        "user-agent": USER_AGENT,
        "accept-encoding": "identity",
        "host": "mcp.example.com",
        "connection": "keep-alive",
        "content-length": str(len(probe.body)),
    }
    assert dict(request.headers) == expected
    assert records == [FetchRecord("probe", "mcp.example.com", 443, 401, 0, 0, "direct")]


async def test_a_redirected_probe_is_refused() -> None:
    fetcher_, _, records = fetcher(answer(307, headers={"location": "https://x.example/"}))
    with pytest.raises(FetchError) as caught:
        await fetcher_.probe(SERVER, MODERN_PROBE)
    error = caught.value
    assert (error.reason, error.host, error.port, error.status) == (
        "fetch_redirect",
        "mcp.example.com",
        443,
        307,
    )
    assert records[0].status == 307


# --- metadata ----------------------------------------------------------------------------------


async def test_metadata_is_one_json_object() -> None:
    doc = {"resource": SERVER, "authorization_servers": ["https://auth.example.com"]}
    fetcher_, recorder, records = fetcher(answer(200, doc))
    assert await fetcher_.metadata(PRM, "prm", well_known=True) == Fetched(200, doc)
    (request,) = recorder.requests
    assert request.method == "GET"
    assert dict(request.headers) == {
        "host": "mcp.example.com",
        "accept": "application/json",
        "user-agent": USER_AGENT,
        "accept-encoding": "identity",
        "connection": "keep-alive",
    }
    size = len(json.dumps(doc))
    assert records == [FetchRecord("prm", "mcp.example.com", 443, 200, size, 0, "direct")]


@pytest.mark.parametrize("media", ["application/json; charset=utf-8", "Application/JSON"])
async def test_a_json_type_with_parameters(media: str) -> None:
    fetcher_, _, _ = fetcher(answer(200, {"a": 1}, {"content-type": media}))
    assert await fetcher_.metadata(AS, "as", well_known=True) == Fetched(200, {"a": 1})


@pytest.mark.parametrize("status", [404, 405, 410, 301, 302, 307, 308])
async def test_not_here_from_a_well_known_candidate(status: int) -> None:
    fetcher_, _, _ = fetcher(answer(status, {"ignored": True}))
    assert await fetcher_.metadata(AS, "as", well_known=True) == Fetched(status, None)


@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_a_redirect_elsewhere_is_refused(status: int) -> None:
    fetcher_, _, _ = fetcher(answer(status))
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata(PRM, "prm", well_known=False)
    assert (caught.value.reason, caught.value.status) == ("fetch_redirect", status)


@pytest.mark.parametrize("status", [404, 405, 410])
async def test_not_here_from_the_challenges_own_url(status: int) -> None:
    fetcher_, _, _ = fetcher(answer(status))
    assert await fetcher_.metadata(PRM, "prm", well_known=False) == Fetched(status, None)


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500, 503, 100, 199])
async def test_any_other_status_fails(status: int) -> None:
    fetcher_, _, _ = fetcher(answer(status))
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata(AS, "as", well_known=True)
    error = caught.value
    assert (error.reason, error.status, error.why) == ("fetch_failed", status, "status")
    assert (error.host, error.port) == ("auth.example.com", 443)


@pytest.mark.parametrize(
    ("headers", "body", "why"),
    [
        ({"content-type": "text/html"}, b"{}", "type"),
        ({}, b"{}", "type"),
        (JSON, b"[1]", "object"),
        (JSON, b'"text"', "object"),
        (JSON, b'{"a": 1, "a": 2}', "json"),
        (JSON, b"<html>", "json"),
        (JSON, b"\xff{}", "json"),
        (JSON, b'{"n": 9007199254740993}', "json"),
    ],
)
async def test_not_json(headers: dict[str, str], body: bytes, why: str) -> None:
    fetcher_, _, _ = fetcher(
        lambda request: httpx.Response(200, headers=headers, stream=Chunks([body]))
    )
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata(AS, "as", well_known=True)
    assert (caught.value.reason, caught.value.why, caught.value.status) == (
        "fetch_not_json",
        why,
        200,
    )


def padded(size: int) -> bytes:
    """A JSON object of exactly ``size`` bytes."""
    return b'{"p": "' + b"x" * (size - 9) + b'"}'


async def test_metadata_up_to_its_cap_is_read() -> None:
    body = padded(METADATA_MAX)
    assert len(body) == METADATA_MAX
    fetcher_, _, records = fetcher(
        lambda r: httpx.Response(200, headers=JSON, stream=Chunks([body]))
    )
    got = await fetcher_.metadata(AS, "as", well_known=True)
    assert got.document == {"p": "x" * (METADATA_MAX - 9)}
    assert records[0].bytes == METADATA_MAX


async def test_metadata_over_its_cap_by_its_length_is_never_read() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        headers = {**JSON, "content-length": str(METADATA_MAX + 1)}
        return httpx.Response(200, headers=headers, stream=Unread())

    fetcher_, _, _ = fetcher(handler)
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata(AS, "as", well_known=True)
    assert caught.value.reason == "fetch_too_large"


async def test_metadata_over_its_cap_stops_as_it_arrives() -> None:
    chunks = Chunks([b"{" + b" " * (METADATA_MAX - 1), b" ", b"}"])
    fetcher_, _, _ = fetcher(lambda request: httpx.Response(200, headers=JSON, stream=chunks))
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata(AS, "as", well_known=True)
    assert caught.value.reason == "fetch_too_large"
    assert chunks.read == 2


# --- the count and the deadline ----------------------------------------------------------------


async def test_a_discovery_sends_at_most_nine_requests() -> None:
    fetcher_, recorder, _ = fetcher(answer(404))
    await fetcher_.probe(SERVER, MODERN_PROBE)
    for _ in range(DISCOVERY_FETCHES - 1):
        await fetcher_.metadata(AS, "as", well_known=True)
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata(AS, "as", well_known=True)
    assert (caught.value.reason, caught.value.why, caught.value.status) == (
        "fetch_failed",
        "too_many",
        None,
    )
    assert len(recorder.requests) == DISCOVERY_FETCHES
    # The registration comes after the discovery and isn't one of its requests.
    recorder.handler = answer(201, {"client_id": "c"})
    assert (await fetcher_.register(REGISTER, b"{}")).status == 201


def timeout_of(request: httpx.Request) -> dict[str, float]:
    timeout: dict[str, float] = request.extensions["timeout"]
    return timeout


async def test_each_request_has_the_time_the_discovery_has_left() -> None:
    clock = Clock()
    fetcher_, recorder, _ = fetcher(answer(404), clock=clock)
    await fetcher_.metadata(AS, "as", well_known=True)
    clock.now += DISCOVERY_DEADLINE - 4
    await fetcher_.metadata(AS, "as", well_known=True)
    clock.now += 3.5
    await fetcher_.metadata(AS, "as", well_known=True)
    first, second, third = (timeout_of(request) for request in recorder.requests)
    assert first == {"connect": 5.0, "read": 10.0, "write": 10.0, "pool": 10.0}
    assert second == {"connect": 4.0, "read": 4.0, "write": 4.0, "pool": 4.0}
    assert third == {"connect": 0.5, "read": 0.5, "write": 0.5, "pool": 0.5}


@pytest.mark.parametrize("late", [0.0, 1.0])
async def test_nothing_is_sent_past_the_deadline(late: float) -> None:
    clock = Clock()
    fetcher_, recorder, records = fetcher(answer(404), clock=clock)
    clock.now += DISCOVERY_DEADLINE + late
    with pytest.raises(FetchError) as caught:
        await fetcher_.probe(SERVER, MODERN_PROBE)
    assert (caught.value.reason, caught.value.why) == ("fetch_failed", "deadline")
    assert (caught.value.host, caught.value.port) == ("mcp.example.com", 443)
    assert recorder.requests == []
    assert records == []


async def test_the_record_times_each_request() -> None:
    clock = Clock()

    def handler(request: httpx.Request) -> httpx.Response:
        clock.now += 0.25
        return httpx.Response(404)

    fetcher_, _, records = fetcher(handler, clock=clock, proxied=True)
    await fetcher_.metadata("https://Auth.Example.com:8443/x", "as", well_known=True)
    assert records == [FetchRecord("as", "auth.example.com", 8443, 404, 0, 250, "proxy")]


# --- errors ------------------------------------------------------------------------------------


def raising(exc: Exception) -> Handler:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    return handler


@pytest.mark.parametrize(
    ("exc", "reason", "why"),
    [
        (
            AddressRefused("mcp.example.com", 443, AddressVerdict(False, "private", "10.0.0.1")),
            "address_refused",
            "private",
        ),
        (ResolveFailed("mcp.example.com", 443), "resolve_failed", ""),
        (httpx.ConnectError("refused"), "fetch_failed", "connect"),
        (httpx.RemoteProtocolError("bad"), "fetch_failed", "connect"),
        (httpx.ReadTimeout("slow"), "fetch_failed", "timeout"),
        (httpx.ConnectTimeout("slow"), "fetch_failed", "timeout"),
    ],
)
async def test_each_failure_is_a_reason(exc: Exception, reason: str, why: str) -> None:
    fetcher_, _, records = fetcher(raising(exc))
    with pytest.raises(FetchError) as caught:
        await fetcher_.probe(SERVER, MODERN_PROBE)
    error = caught.value
    assert (error.reason, error.why, error.status) == (reason, why, None)
    assert (error.host, error.port) == ("mcp.example.com", 443)
    assert str(error) == f"{reason}: mcp.example.com:443" + (f" ({why})" if why else "")
    assert records == [FetchRecord("probe", "mcp.example.com", 443, None, 0, 0, "direct")]


@pytest.mark.parametrize(
    ("text", "status"),
    [("403 Forbidden", 403), ("407 Proxy Authentication Required", 407), ("502", 502), ("", None)],
)
async def test_a_refused_connect_is_the_proxys(text: str, status: int | None) -> None:
    fetcher_, _, _ = fetcher(raising(httpx.ProxyError(text)), proxied=True)
    with pytest.raises(ProxyRefused) as caught:
        await fetcher_.metadata("https://auth.example.com:8443/x", "as", well_known=True)
    assert (caught.value.host, caught.value.port, caught.value.status) == (
        "auth.example.com",
        8443,
        status,
    )


async def test_an_international_host_is_shown_as_the_guard_sees_it() -> None:
    fetcher_, _, _ = fetcher(answer(500))
    with pytest.raises(FetchError) as caught:
        await fetcher_.metadata("https://b\u00fccher.example/x", "as", well_known=True)
    assert caught.value.host == "xn--bcher-kva.example"


# --- the guard's per-request exception (TI-10) -------------------------------------------------


async def test_only_the_probe_and_prm_carry_the_exception() -> None:
    fetcher_, recorder, _ = fetcher(
        answer(404), onboarding="ob-1", private_target="mcp.example.com:443"
    )
    await fetcher_.probe(SERVER, MODERN_PROBE)
    await fetcher_.metadata(PRM, "prm", well_known=True)
    await fetcher_.metadata(AS, "as", well_known=True)
    await fetcher_.register(REGISTER, b"{}")
    found = [request.extensions.get(ONBOARDING_EXTENSION) for request in recorder.requests]
    assert found == [
        ("ob-1", "probe", "mcp.example.com:443"),
        ("ob-1", "prm", "mcp.example.com:443"),
        None,
        None,
    ]


async def test_without_allow_private_no_request_carries_it() -> None:
    fetcher_, recorder, _ = fetcher(answer(404), onboarding="ob-1")
    await fetcher_.probe(SERVER, MODERN_PROBE)
    await fetcher_.metadata(PRM, "prm", well_known=True)
    assert all(ONBOARDING_EXTENSION not in r.extensions for r in recorder.requests)


# --- registration ------------------------------------------------------------------------------


async def test_a_registration() -> None:
    body = b'{"client_name": "ZoeyMCP (notes)"}'
    fetcher_, recorder, records = fetcher(answer(201, {"client_id": "zc_1"}))
    assert await fetcher_.register(REGISTER, body) == Fetched(201, {"client_id": "zc_1"})
    (request,) = recorder.requests
    assert request.method == "POST"
    assert request.content == body
    assert dict(request.headers) == {
        "host": "auth.example.com",
        "content-type": "application/json",
        "accept": "application/json",
        "user-agent": USER_AGENT,
        "accept-encoding": "identity",
        "connection": "keep-alive",
        "content-length": str(len(body)),
    }
    assert timeout_of(request) == {"connect": 5.0, "read": 15.0, "write": 15.0, "pool": 15.0}
    assert records[0].kind == "register"


async def test_a_registration_refusals_error_is_kept() -> None:
    doc = {"error": "invalid_redirect_uri", "error_description": "no"}
    fetcher_, _, _ = fetcher(answer(400, doc))
    assert await fetcher_.register(REGISTER, b"{}") == Fetched(400, doc)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(400, headers={"content-type": "text/plain"}, stream=Chunks([b"no"])),
        httpx.Response(400, headers=JSON, stream=Chunks([b"[1]"])),
        httpx.Response(400, headers=JSON, stream=Chunks([padded(REGISTRATION_MAX + 1)])),
        httpx.Response(401, headers=JSON, stream=Chunks([b'{"error": "x"}'])),
        httpx.Response(500, headers=JSON, stream=Chunks([b"{}"])),
    ],
)
async def test_any_other_registration_answer_is_its_status(response: httpx.Response) -> None:
    fetcher_, _, _ = fetcher(lambda request: response)
    assert await fetcher_.register(REGISTER, b"{}") == Fetched(response.status_code, None)


async def test_a_registration_answer_must_be_json_within_its_cap() -> None:
    fetcher_, _, _ = fetcher(
        lambda r: httpx.Response(201, headers=JSON, stream=Chunks([padded(REGISTRATION_MAX + 1)]))
    )
    with pytest.raises(FetchError) as caught:
        await fetcher_.register(REGISTER, b"{}")
    assert caught.value.reason == "fetch_too_large"
    fetcher_, _, _ = fetcher(lambda r: httpx.Response(200, headers=JSON, stream=Chunks([b"[]"])))
    with pytest.raises(FetchError) as caught:
        await fetcher_.register(REGISTER, b"{}")
    assert caught.value.reason == "fetch_not_json"


async def test_a_redirected_registration_is_refused() -> None:
    fetcher_, _, _ = fetcher(answer(302))
    with pytest.raises(FetchError) as caught:
        await fetcher_.register(REGISTER, b"{}")
    assert (caught.value.reason, caught.value.status) == ("fetch_redirect", 302)
