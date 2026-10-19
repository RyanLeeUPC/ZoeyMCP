"""The vault link, gateway key, egress transport and policy client (M3 design C.3, D.2, F.2)."""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest

from zoeymcp.common import canonical
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import build_view, dump_view
from zoeymcp.gateway import logs, policyclient
from zoeymcp.gateway.egressrules import CallRegistry
from zoeymcp.gateway.policyclient import PolicyClient, Snapshot
from zoeymcp.gateway.vaultlink import (
    GATEWAY_HEADER,
    GatewayKey,
    KeySource,
    LinkError,
    ResponseTooLarge,
    UpstreamBlocked,
    UpstreamRedirect,
    environ_has_no_secrets,
    is_redirect,
    parse_link,
    upstream_client,
    vault_refusal_code,
    view_client,
)

pytestmark = pytest.mark.anyio
KEY = "zgw1-" + "A" * 43
OTHER_KEY = "zgw1-" + "B" * 43


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


def events(buffer: io.StringIO, kind: str | None = None) -> list[dict[str, Any]]:
    parsed = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in parsed if kind is None or line["event"] == kind]


# --- links ---------------------------------------------------------------------------------


def test_a_unix_link() -> None:
    link = parse_link("unix:/run/zoeymcp-link/vault.sock")
    assert (link.kind, link.uds, link.base_url, link.hardened) == (
        "unix",
        "/run/zoeymcp-link/vault.sock",
        "http://vault.invalid",
        False,
    )
    assert link.target("/notes/mcp").path == "/notes/mcp"
    assert not link.target("/x").hardened


@pytest.mark.parametrize(
    ("spec", "base", "port"),
    [
        ("http://vault:8080", "http://vault:8080", 8080),
        ("http://vault", "http://vault", None),
        ("http://vault:8080/", "http://vault:8080", 8080),
        ("http://[fd00::2]:8080", "http://[fd00::2]:8080", 8080),
    ],
)
def test_an_http_link(spec: str, base: str, port: int | None) -> None:
    link = parse_link(spec)
    assert (link.kind, link.base_url, link.port, link.hardened) == ("http", base, port, True)
    assert link.target("/a/mcp").hardened


@pytest.mark.parametrize(
    "spec",
    [
        "unix:relative.sock",
        "https://vault:8080",
        "vault:8080",
        "http://user:pw@vault:8080",
        "http://vault:8080/path",
        "http://vault:8080?x=1",
        "http://vault:99999",
        "http://",
        "",
    ],
)
def test_bad_links(spec: str) -> None:
    with pytest.raises(LinkError):
        parse_link(spec)


# --- the key ---------------------------------------------------------------------------------


def test_the_key_hides_itself() -> None:
    key = GatewayKey(KEY)
    assert key.reveal() == KEY
    assert repr(key) == "GatewayKey(***)"
    assert KEY not in repr(key)
    assert KEY not in str(key)
    assert key == GatewayKey(KEY)
    assert key != GatewayKey(OTHER_KEY)
    assert key != KEY
    assert len({key, GatewayKey(KEY)}) == 1


def test_logging_the_key_raises() -> None:
    with pytest.raises(TypeError, match="refusing to log a secret"):
        logs.event("x", key=GatewayKey(KEY))
    with pytest.raises(TypeError):
        logs.event("x", keys=[GatewayKey(KEY)])


@pytest.mark.parametrize(
    "value", ["", "zgw1-short", "zgw2-" + "A" * 43, KEY + "A", KEY + "\n", "zgw1-" + "!" * 43]
)
def test_a_malformed_key_is_refused(value: str) -> None:
    with pytest.raises(LinkError, match="zgw1-"):
        GatewayKey(value)


def test_a_key_from_a_value() -> None:
    keys = KeySource(KEY)
    assert keys.current() == GatewayKey(KEY)
    assert keys.configured
    assert keys.reload() is False
    assert not KeySource().configured
    assert KeySource().current() is None


def test_a_key_file_is_read_and_reloaded(tmp_path: Path, captured: io.StringIO) -> None:
    path = tmp_path / "key"
    path.write_text(KEY + "\n", encoding="ascii")
    keys = KeySource(file=path)
    assert keys.current() == GatewayKey(KEY)
    assert keys.reload() is False  # unchanged
    path.write_text(OTHER_KEY, encoding="ascii")
    assert keys.reload() is True
    assert keys.current() == GatewayKey(OTHER_KEY)
    path.write_text("garbage", encoding="ascii")
    assert keys.reload() is False
    assert keys.current() == GatewayKey(OTHER_KEY)  # a bad file keeps the old key
    [line] = events(captured, "gateway_key_unreadable")
    assert "garbage" not in json.dumps(line)


def test_an_unreadable_key_file_at_start_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(LinkError, match="can't be read"):
        KeySource(file=tmp_path / "missing")
    (tmp_path / "bin").write_bytes(b"\xff\xfe")
    with pytest.raises(LinkError, match="can't be read"):
        KeySource(file=tmp_path / "bin")


def test_a_refusal_reloads_at_most_every_ten_seconds(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_text(KEY, encoding="ascii")
    now = [100.0]
    keys = KeySource(file=path, clock=lambda: now[0])
    path.write_text(OTHER_KEY, encoding="ascii")
    assert keys.after_refusal() is True
    path.write_text(KEY, encoding="ascii")
    now[0] = 109.9
    assert keys.after_refusal() is False
    assert keys.current() == GatewayKey(OTHER_KEY)
    now[0] = 110.0
    assert keys.after_refusal() is True
    assert keys.current() == GatewayKey(KEY)


def test_from_environ(tmp_path: Path) -> None:
    assert KeySource.from_environ({"ZOEYMCP_GATEWAY_KEY": KEY}).current() == GatewayKey(KEY)
    path = tmp_path / "key"
    path.write_text(OTHER_KEY, encoding="ascii")
    keys = KeySource.from_environ({"ZOEYMCP_GATEWAY_KEY_FILE": str(path)})
    assert keys.current() == GatewayKey(OTHER_KEY)
    assert not KeySource.from_environ({}).configured


@pytest.mark.parametrize(
    "name", ["ZOEYMCP_MASTER_KEY", "ZOEYMCP_MASTER_KEY_PREVIOUS", "ZOEYMCP_CONFIG"]
)
def test_secrets_in_the_environment(name: str) -> None:
    assert environ_has_no_secrets({name: "x", "PATH": "/bin"}) == name
    assert environ_has_no_secrets({"PATH": "/bin", "ZOEYMCP_GATEWAY_KEY": KEY}) is None


# --- the egress transport --------------------------------------------------------------------


Handler = Callable[[httpx2.Request], httpx2.Response]


def client_for(
    handler: Handler,
    *,
    link: str = "unix:/run/v.sock",
    keys: KeySource | None = None,
    registry: CallRegistry | None = None,
    max_json_bytes: int = 1 << 20,
    noted: list[tuple[int, str | None]] | None = None,
) -> httpx2.AsyncClient:
    def note(request: httpx2.Request, response: httpx2.Response) -> None:
        if noted is not None:
            noted.append((response.status_code, response.headers.get("mcp-session-id")))

    return upstream_client(
        parse_link(link),
        keys,
        server="notes",
        vault_path="/notes/mcp",
        registry=registry or CallRegistry(),
        max_json_bytes=max_json_bytes,
        on_response=note,
        inner=httpx2.MockTransport(handler),
    )


def ok(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})


def ping() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": 1, "method": "ping"}


async def test_an_allowed_request_goes_through() -> None:
    noted: list[tuple[int, str | None]] = []
    async with client_for(ok, noted=noted) as http:
        response = await http.post("http://vault.invalid/notes/mcp", json=ping())
    assert response.json()["result"] == {}
    assert noted == [(200, None)]


async def test_a_blocked_request_never_leaves(captured: io.StringIO) -> None:
    sent: list[httpx2.Request] = []

    def record(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        return ok(request)

    async with client_for(record) as http:
        with pytest.raises(UpstreamBlocked, match="another path"):
            await http.post("http://vault.invalid/mail/send", json=ping())
        with pytest.raises(UpstreamBlocked, match="request method not allowed"):
            await http.post(
                "http://vault.invalid/notes/mcp",
                json={"jsonrpc": "2.0", "id": 2, "method": "sampling/createMessage"},
            )
        with pytest.raises(UpstreamBlocked, match="another path"):
            await http.post("http://vault.invalid/notes/%6dcp", json=ping())
    assert sent == []
    assert [line["reason"] for line in events(captured, "upstream_request_blocked")] == [
        "another path",
        "request method not allowed",
        "another path",
    ]


async def test_a_call_needs_its_registration() -> None:
    registry = CallRegistry()
    registry.register("echo", canonical.digest({"text": "hi"}))
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "echo", "arguments": {"text": "hi"}},
    }
    async with client_for(ok, registry=registry) as http:
        await http.post("http://vault.invalid/notes/mcp", json=call)
        with pytest.raises(UpstreamBlocked, match="not registered"):
            await http.post("http://vault.invalid/notes/mcp", json=call)


async def test_an_error_answer_to_a_server_request_is_logged(captured: io.StringIO) -> None:
    answer = {"jsonrpc": "2.0", "id": 9, "error": {"code": -32601, "message": "nope"}}
    async with client_for(ok) as http:
        await http.post("http://vault.invalid/notes/mcp", json=answer)
    assert [line["server"] for line in events(captured, "upstream_request_refused")] == ["notes"]


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_a_redirect_ends_the_request(status: int, captured: io.StringIO) -> None:
    def redirect(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, headers={"location": "/mail/send"})

    async with client_for(redirect) as http:
        with pytest.raises(UpstreamRedirect):
            await http.post("http://vault.invalid/notes/mcp", json=ping())
    assert [line["status"] for line in events(captured, "upstream_redirect_refused")] == [status]


async def test_cookies_are_never_kept() -> None:
    def cookie(request: httpx2.Request) -> httpx2.Response:
        assert "cookie" not in request.headers
        return httpx2.Response(
            200, headers={"set-cookie": "s=1"}, json={"jsonrpc": "2.0", "id": 1, "result": {}}
        )

    async with client_for(cookie) as http:
        first = await http.post("http://vault.invalid/notes/mcp", json=ping())
        await http.post("http://vault.invalid/notes/mcp", json=ping())
    assert "set-cookie" not in first.headers
    assert not http.cookies


async def test_a_json_answer_is_capped() -> None:
    def big(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, headers={"content-type": "application/json"}, content=b"[" + b"1," * 600 + b"1]"
        )

    async with client_for(big, max_json_bytes=1000) as http:
        with pytest.raises(ResponseTooLarge):
            await http.post("http://vault.invalid/notes/mcp", json=ping())
    async with client_for(big, max_json_bytes=1203) as http:
        response = await http.post("http://vault.invalid/notes/mcp", json=ping())
        assert len(response.content) == 1203


async def test_an_event_stream_is_not_capped_here() -> None:
    def stream(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, headers={"content-type": "text/event-stream"}, content=b"x" * 5000
        )

    async with client_for(stream, max_json_bytes=1000) as http:
        response = await http.get("http://vault.invalid/notes/mcp")
    assert len(response.content) == 5000


@pytest.mark.parametrize(
    ("status", "redirect"),
    [(300, True), (301, True), (304, False), (307, True), (399, True), (200, False), (400, False)],
)
def test_is_redirect(status: int, redirect: bool) -> None:
    assert is_redirect(status) is redirect


async def test_a_304_passes_the_egress_transport() -> None:
    async with client_for(lambda request: httpx2.Response(304)) as http:
        assert (await http.get("http://vault.invalid/notes/mcp")).status_code == 304


@pytest.mark.parametrize(
    ("body", "code"),
    [
        (b'{"error":"refused","code":"oauth_reconsent_needed"}', "oauth_reconsent_needed"),
        (b'{"code":"Bad-Code"}', None),
        (b'{"code":5}', None),
        (b'{"code":"' + b"a" * 65 + b'"}', None),
        (b"not json", None),
        (b"[]", None),
    ],
)
def test_vault_refusal_codes(body: bytes, code: str | None) -> None:
    assert vault_refusal_code(body) == code


async def test_a_vault_refusal_is_logged_with_its_code(captured: io.StringIO) -> None:
    def refused(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            502,
            headers={"x-zoeymcp-vault": "refused", "content-type": "application/json"},
            content=b'{"code":"oauth_reconsent_needed"}',
        )

    async with client_for(refused) as http:
        response = await http.post("http://vault.invalid/notes/mcp", json=ping())
    assert response.status_code == 502
    assert response.content == b'{"code":"oauth_reconsent_needed"}'
    [line] = events(captured, "vault_refused")
    assert (line["server"], line["status"], line["code"]) == (
        "notes",
        502,
        "oauth_reconsent_needed",
    )


async def test_a_vault_403_reloads_the_key_file(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_text(KEY, encoding="ascii")
    keys = KeySource(file=path)
    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get(GATEWAY_HEADER))
        return httpx2.Response(403, headers={"x-zoeymcp-vault": "refused"})

    async with client_for(handler, link="http://vault:8080", keys=keys) as http:
        path.write_text(OTHER_KEY, encoding="ascii")
        await http.post("http://vault:8080/notes/mcp", json=ping())
        await http.post("http://vault:8080/notes/mcp", json=ping())
    assert seen == [KEY, OTHER_KEY]


async def test_the_key_goes_only_on_the_hardened_link() -> None:
    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get(GATEWAY_HEADER))
        return ok(request)

    async with client_for(handler, link="http://vault:8080", keys=KeySource(KEY)) as http:
        await http.post("http://vault:8080/notes/mcp", json=ping())
    async with client_for(handler, keys=KeySource(KEY)) as http:
        await http.post("http://vault.invalid/notes/mcp", json=ping())
    assert seen == [KEY, None]


async def test_the_upstream_client_settings() -> None:
    async with client_for(ok) as http:
        assert http.follow_redirects is False
        assert http.max_redirects == 0
        assert http.trust_env is False
        assert http.timeout.read is None
        assert (http.timeout.connect, http.timeout.write, http.timeout.pool) == (10.0, 30.0, 10.0)


# --- the policy client -----------------------------------------------------------------------

HASH = "sha256:" + "1" * 64


def view_bytes(clients: int = 1, max_stale: int = 300) -> bytes:
    raw = {
        "version": 1,
        "mode": "declarative",
        "gateway": {
            "limits": {"policy_max_stale": max_stale},
            "clients": {f"agent{n}": {"token_sha256": HASH} for n in range(clients)},
        },
    }
    return dump_view(build_view(Policy.model_validate(raw)))


class Vault:
    """The view endpoint, scripted."""

    def __init__(self) -> None:
        self.answers: list[httpx2.Response | Exception] = []
        self.requests: list[httpx2.Request] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


Applied = list[tuple[Snapshot, Snapshot | None]]


def scripted() -> tuple[Vault, Applied, list[float]]:
    """A scripted vault, the views applied so far, and a settable clock."""
    return Vault(), [], [0.0]


def policy_client(
    vault: Vault, applied: list[tuple[Snapshot, Snapshot | None]], now: list[float]
) -> PolicyClient:
    async def apply(snapshot: Snapshot, previous: Snapshot | None) -> None:
        applied.append((snapshot, previous))

    http = view_client(parse_link("unix:/run/v.sock"), None, inner=httpx2.MockTransport(vault))
    return PolicyClient(http, apply, clock=lambda: now[0])


async def test_the_first_fetch_and_a_long_poll(captured: io.StringIO) -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    assert client.fresh() is None
    vault.answers = [httpx2.Response(200, content=view_bytes()), httpx2.Response(304)]
    assert await client.fetch_once() is True
    first = vault.requests[0]
    assert first.url.path == "/_zoeymcp/gateway/v1/view"
    assert "if-none-match" not in first.headers
    assert first.url.query == b""  # no wait on the first fetch
    [(snapshot, previous)] = applied
    assert previous is None
    assert client.fresh() is snapshot
    now[0] = 5
    assert await client.fetch_once() is True
    second = vault.requests[1]
    assert second.headers["if-none-match"] == f'"{snapshot.view.digest}"'
    assert second.url.query == b"wait=25"
    assert client.last_contact == 5
    assert len(applied) == 1
    [line] = events(captured, "policy_applied")
    assert (line["digest"], line["clients"], line["servers"]) == (snapshot.view.digest, 1, 0)


async def test_a_new_view_is_applied_with_the_previous() -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [
        httpx2.Response(200, content=view_bytes(1)),
        httpx2.Response(200, content=view_bytes(2)),
    ]
    await client.fetch_once()
    await client.fetch_once()
    assert [len(s.view.gateway.clients) for s, _ in applied] == [1, 2]
    assert applied[1][1] is applied[0][0]


async def test_the_same_view_again_is_not_reapplied() -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [
        httpx2.Response(200, content=view_bytes()),
        httpx2.Response(200, content=view_bytes()),
    ]
    await client.fetch_once()
    await client.fetch_once()
    assert len(applied) == 1


async def test_a_304_before_any_view_is_not_contact() -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [httpx2.Response(304)]
    assert await client.fetch_once() is False
    assert client.last_contact is None


@pytest.mark.parametrize(
    ("answer", "field", "value"),
    [
        (httpx2.Response(403), "status", 403),
        (httpx2.Response(429), "status", 429),
        (httpx2.ConnectError("refused"), "error_type", "ConnectError"),
        (httpx2.ReadTimeout("slow"), "error_type", "ReadTimeout"),
    ],
)
async def test_failures_are_not_contact(
    answer: Any, field: str, value: Any, captured: io.StringIO
) -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [answer]
    assert await client.fetch_once() is False
    assert client.last_contact is None
    [line] = events(captured, "policy_fetch_failed")
    assert line[field] == value


async def test_a_view_the_gateway_cant_parse_keeps_the_last(captured: io.StringIO) -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    good = view_bytes()
    tampered = good.replace(b'"agent0"', b'"agent9"')
    vault.answers = [httpx2.Response(200, content=good), httpx2.Response(200, content=tampered)]
    await client.fetch_once()
    now[0] = 10
    assert await client.fetch_once() is False
    assert len(applied) == 1
    assert client.last_contact == 0  # not contact: staleness still counts from the last good one
    [line] = events(captured, "policy_refused")
    assert "digest" in line["reason"]


async def test_staleness() -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [httpx2.Response(200, content=view_bytes(max_stale=30))]
    await client.fetch_once()
    now[0] = 30
    assert client.fresh() is not None
    assert client.age() == 30
    now[0] = 30.5
    assert client.fresh() is None


async def test_stale_and_fresh_again_are_logged_once(captured: io.StringIO) -> None:
    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [httpx2.Response(200, content=view_bytes(max_stale=30)), httpx2.Response(304)]
    await client.fetch_once()
    now[0] = 40
    assert client.fresh() is None
    assert client.fresh() is None
    assert len(events(captured, "policy_stale")) == 1
    await client.fetch_once()
    assert client.fresh() is not None
    assert len(events(captured, "policy_fresh")) == 1


def test_backoff() -> None:
    assert [policyclient.backoff(n, 1.0) for n in (1, 2, 3, 4, 5, 6, 7)] == [1, 2, 4, 8, 16, 30, 30]
    assert policyclient.backoff(1, 0.5) == 0.5
    assert policyclient.backoff(10, 1.5) == 45


async def test_the_view_client_fetches_only_the_view() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200)

    async with view_client(
        parse_link("unix:/run/v.sock"), None, inner=httpx2.MockTransport(handler)
    ) as http:
        assert (await http.get("/_zoeymcp/gateway/v1/view")).status_code == 200
        with pytest.raises(UpstreamBlocked):
            await http.get("/notes/mcp")
        with pytest.raises(UpstreamBlocked):
            await http.post("/_zoeymcp/gateway/v1/view")
        with pytest.raises(UpstreamBlocked):
            await http.get("http://elsewhere.example/_zoeymcp/gateway/v1/view")


async def test_the_view_client_refuses_redirects() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(307, headers={"location": "/x"})

    async with view_client(
        parse_link("unix:/run/v.sock"), None, inner=httpx2.MockTransport(handler)
    ) as http:
        with pytest.raises(UpstreamRedirect):
            await http.get("/_zoeymcp/gateway/v1/view")


async def test_refresh_wakes_the_backoff() -> None:
    import anyio

    vault, applied, now = scripted()
    client = policy_client(vault, applied, now)
    vault.answers = [httpx2.ConnectError("down"), httpx2.Response(200, content=view_bytes())]
    async with anyio.create_task_group() as group:
        group.start_soon(client.run)
        with anyio.fail_after(5):
            while len(vault.requests) < 1:
                await anyio.sleep(0.01)
            client.refresh()
            while not applied:
                await anyio.sleep(0.01)
        group.cancel_scope.cancel()
    assert len(vault.requests) >= 2  # then it went on to long-poll
