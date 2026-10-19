"""The gateway's toolkit pieces in isolation (M4 design H.2, H.4): the vault client, the bound
slots, and the loader's decisions."""

from __future__ import annotations

import importlib.metadata
import io
import json
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest

from zoeymcp.common.approvaltext import Plan, Write
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import GatewayView, build_view
from zoeymcp.gateway import logs
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.toolkits import Loaded, Toolkits, Unavailable, origin_problem
from zoeymcp.gateway.toolkitvault import CallState, ToolkitVault
from zoeymcp.gateway.vaultlink import (
    GATEWAY_HEADER,
    KeySource,
    UpstreamBlocked,
    UpstreamRedirect,
    parse_link,
    toolkit_client,
)
from zoeymcp.toolkit import VaultError, rules
from zoeymcp.toolkit.plan import SendLedger

pytestmark = pytest.mark.anyio
KEY = "zgw1-" + "A" * 43
OTHER_KEY = "zgw1-" + "B" * 43
LINK = "http://vault:8080"
MAIL = rules.Slot(
    "/mail",
    "smtp",
    (
        rules.SlotRule(frozenset({"GET"}), ("/mail/config",)),
        rules.SlotRule(frozenset({"POST"}), ("/mail/send",), approved=True),
    ),
)
DB = rules.Slot(
    "/records",
    None,
    (
        rules.SlotRule(frozenset({"GET"}), ("/records/v1/records/{id}",)),
        rules.SlotRule(frozenset({"POST"}), ("/records/v1/notes",)),
    ),
)


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


def events(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    parsed = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [line for line in parsed if line["event"] == kind]


def json_answer(data: Any, status: int = 200, **headers: str) -> httpx2.Response:
    return httpx2.Response(
        status,
        content=json.dumps(data).encode(),
        headers={"content-type": "application/json", **headers},
    )


# --- the client ---------------------------------------------------------------------------------


def allow_all(method: str, path: str) -> str | None:
    return None


async def test_the_client_keeps_the_key_hook_and_the_settings() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return json_answer({})

    client = toolkit_client(
        parse_link(LINK),
        KeySource(KEY),
        server="mail",
        check=allow_all,
        inner=httpx2.MockTransport(handler),
    )
    async with client:
        await client.get("/mail/config")
        assert client.follow_redirects is False
        assert client.max_redirects == 0
        assert client.trust_env is False
    assert seen[0].headers[GATEWAY_HEADER] == KEY


async def test_the_check_runs_before_anything_leaves(captured: io.StringIO) -> None:
    sent: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request.url.path)
        return json_answer({})

    def check(method: str, path: str) -> str | None:
        return "nope" if path.endswith("/send") else None

    client = toolkit_client(
        parse_link(LINK), None, server="mail", check=check, inner=httpx2.MockTransport(handler)
    )
    async with client:
        with pytest.raises(UpstreamBlocked):
            await client.post("/mail/send", content=b"{}")
        with pytest.raises(UpstreamBlocked):
            await client.get("http://elsewhere:8080/mail/config")
        with pytest.raises(UpstreamBlocked):
            await client.get("/mail/config", headers={"x-agent": "1"})
        with pytest.raises(UpstreamBlocked):
            await client.post("/mail/config", content=b"x" * (2**20 + 1))
    assert sent == []
    assert [e["reason"] for e in events(captured, "toolkit_request_blocked")] == [
        "nope",
        "target",
        "header",
        "too_large",
    ]


@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_a_redirect_is_never_followed(status: int) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, headers={"location": "/other"})

    client = toolkit_client(
        parse_link(LINK), None, server="mail", check=allow_all, inner=httpx2.MockTransport(handler)
    )
    async with client:
        with pytest.raises(UpstreamRedirect):
            await client.get("/mail/config")


async def test_a_vault_403_reloads_the_key_file(tmp_path: Path, captured: io.StringIO) -> None:
    path = tmp_path / "key"
    path.write_text(KEY, encoding="ascii")
    keys = KeySource(file=path)
    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get(GATEWAY_HEADER))
        return json_answer(
            {"error": "forbidden", "code": "x_y"}, 403, **{"x-zoeymcp-vault": "refused"}
        )

    client = toolkit_client(
        parse_link(LINK), keys, server="mail", check=allow_all, inner=httpx2.MockTransport(handler)
    )
    async with client:
        path.write_text(OTHER_KEY, encoding="ascii")
        first = await client.get("/mail/config")
        await client.get("/mail/config")
    assert first.status_code == 403
    assert seen == [KEY, OTHER_KEY]
    assert events(captured, "vault_refused")[0]["code"] == "x_y"


# --- the bound slots ----------------------------------------------------------------------------


def vault_for(handler: Callable[[httpx2.Request], httpx2.Response]) -> ToolkitVault:
    return ToolkitVault(
        "kit",
        {"mail": MAIL, "db": DB},
        parse_link(LINK),
        KeySource(KEY),
        inner=httpx2.MockTransport(handler),
    )


async def test_a_plan_write_goes_exactly_as_frozen_once_with_its_key() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return json_answer({"message_id": "<a@b>"})

    write = Write.post("/send", {"b": 1, "a": "x"})
    vault = vault_for(handler)
    state = CallState("send_note", "0123456789abcdef", "approve", SendLedger(Plan("Send", [write])))
    slots = vault.bind(state)
    assert await slots["mail"].send(write) == {"message_id": "<a@b>"}
    with pytest.raises(VaultError) as again:
        await slots["mail"].send(write)
    await vault.aclose()
    assert again.value.code == "blocked_already_sent"
    [request] = seen
    assert request.content == write.body == b'{"a":"x","b":1}'
    assert request.headers["idempotency-key"] == "0123456789abcdef.1"
    assert request.headers["content-type"] == "application/json"
    assert request.url.raw_path == b"/mail/send"


async def test_answers_that_arent_plain_json_objects() -> None:
    answers = iter(
        [
            json_answer(
                {"error": "x", "code": "smtp_refused"}, 502, **{"x-zoeymcp-vault": "refused"}
            ),
            httpx2.Response(200, content=b"<html>", headers={"content-type": "text/html"}),
            json_answer([1, 2]),
            httpx2.Response(200, content=b"{", headers={"content-type": "application/json"}),
            httpx2.Response(302, headers={"location": "/x"}),
        ]
    )
    vault = vault_for(lambda request: next(answers))
    slots = vault.bind(CallState("t", "0123456789abcdef", "allow", SendLedger(None)))
    found = []
    for _ in range(5):
        with pytest.raises(VaultError) as raised:
            await slots["db"].get_object("/v1/records/r1")
        found.append((raised.value.status, raised.value.code))
    await vault.aclose()
    assert found == [
        (502, "smtp_refused"),
        (502, "bad_answer"),
        (502, "bad_answer"),
        (502, "bad_answer"),
        (502, "redirect"),
    ]


async def test_closed_and_blocked_requests_never_leave(captured: io.StringIO) -> None:
    sent: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        sent.append(request.url.path)
        return json_answer({})

    vault = vault_for(handler)
    state = CallState("t", "0123456789abcdef", "allow", SendLedger(None))
    slots = vault.bind(state)
    await slots["db"].post_json("/v1/notes", {"n": 1})
    await slots["db"].get_object("/v1/records/r1", query={"fields": "title"})
    state.close()
    with pytest.raises(VaultError) as closed:
        await slots["db"].get_object("/v1/records/r1")
    await vault.aclose()
    assert closed.value.code == "blocked_closed"
    assert sent == ["/records/v1/notes", "/records/v1/records/r1"]
    [blocked] = events(captured, "toolkit_vault_blocked")
    assert blocked == {**blocked, "server": "kit", "tool": "t", "slot": "db", "reason": "closed"}
    assert "path" not in blocked


def test_the_transport_check() -> None:
    vault = vault_for(lambda request: json_answer({}))
    check = vault._transport_check
    assert check("GET", "/records/v1/records/r1") is None
    assert check("HEAD", "/records/v1") == "method"
    assert check("GET", "/records/../mail/send") == "bad_path"
    assert check("GET", "/broker/mcp") == "not_a_slot"
    assert check("GET", "/") == "not_a_slot"


# --- the loader ---------------------------------------------------------------------------------

GROUP = "zoeymcp.toolkits"


def view_with(module: str, **server: Any) -> GatewayView:
    raw: dict[str, Any] = {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": "127.0.0.1:8081", "hosts": ["localhost"]},
        "gateway": {"servers": {"kit": {"kind": "toolkit", "module": module, **server}}},
    }
    return build_view(Policy.model_validate(raw))


def loader(tmp_path: Path, *entries: importlib.metadata.EntryPoint) -> Toolkits:
    return Toolkits(
        parse_link(LINK),
        None,
        DriftMarks.load(tmp_path),
        entry_points=lambda: list(entries),
        allow_writable=True,
    )


@pytest.mark.parametrize(
    ("value", "reason", "detail"),
    [
        ("os.path:join", "not_a_toolkit", {}),
        (
            "tests.unit.test_gateway_toolkits:NOT_THERE",
            "import_error",
            {"error_type": "AttributeError"},
        ),
    ],
)
def test_what_a_registered_entry_point_must_hold(
    tmp_path: Path, value: str, reason: str, detail: dict[str, str]
) -> None:
    module = value.partition(":")[0]
    toolkits = loader(tmp_path, importlib.metadata.EntryPoint("kit", value, GROUP))
    toolkits.apply(view_with(module).gateway)
    assert toolkits.get("kit") == Unavailable(reason, detail)  # type: ignore[arg-type]


def mail_view(*, servers: bool = True, pinning: str = "off") -> GatewayView:
    raw: dict[str, Any] = {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": "127.0.0.1:8081", "hosts": ["localhost"]},
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": "agent",
                "password": "store:mail-pass",
                "from": "agent@mail.example",
                "to": ["partner@mail.example"],
            }
        },
        "routes": [
            {
                "name": "mail-send",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [{"methods": ["GET"], "paths": ["/config"]}],
            }
        ],
        "gateway": {
            "servers": {
                "kit": {
                    "kind": "toolkit",
                    "module": "example_toolkits.mail",
                    "pinning": pinning,
                    "tools": {"include": ["send_note"], "approve": ["send_note"]},
                    "slots": {
                        "mail": {
                            "route": "mail-send",
                            "rules": [{"methods": ["GET"], "paths": ["/config"]}],
                        }
                    },
                }
            }
            if servers
            else {}
        },
    }
    return build_view(Policy.model_validate(raw))


async def test_a_module_is_imported_once_and_forgotten_servers_go(tmp_path: Path) -> None:
    entry = importlib.metadata.EntryPoint("mail", "example_toolkits.mail:toolkit", GROUP)
    toolkits = loader(tmp_path, entry)
    toolkits.apply(mail_view().gateway)
    first = toolkits.get("kit")
    toolkits.apply(mail_view().gateway)
    again = toolkits.get("kit")
    assert isinstance(first, Loaded)
    assert isinstance(again, Loaded)
    assert first.toolkit is again.toolkit
    assert first.vault is again.vault  # the same slots keep the same client
    assert list(again.evaluation.exposed) == ["send_note"]  # pinning off: its own pin
    toolkits.apply(mail_view(servers=False).gateway)
    assert toolkits.get("kit") is None
    await toolkits.aclose()


def test_the_loading_log_is_quiet_on_repeats(tmp_path: Path, captured: io.StringIO) -> None:
    toolkits = loader(tmp_path)
    view = view_with("example_toolkits.unregistered")
    toolkits.apply(view.gateway)
    toolkits.apply(view.gateway)
    assert len(events(captured, "toolkit_unavailable")) == 1
    toolkits.apply(view_with("zoeymcp").gateway)
    assert [e["reason"] for e in events(captured, "toolkit_unavailable")] == [
        "not_registered",
        "refused_name",
    ]
    assert not isinstance(toolkits.get("kit"), Loaded)


def test_unchecked_origins_are_logged(tmp_path: Path, captured: io.StringIO) -> None:
    loader(tmp_path)
    assert events(captured, "toolkit_origin_unchecked") != []


# --- the origin check (H12) ---------------------------------------------------------------------


def test_a_distribution_without_a_record_is_refused() -> None:
    assert origin_problem(None) == "no_record"


@pytest.mark.skipif(sys.platform == "win32", reason="file ownership is POSIX")
def test_an_installed_distribution_the_gateway_can_write_is_refused() -> None:
    dist = importlib.metadata.distribution("pytest")
    expected = "writable" if os.access(Path(str(dist.locate_file(""))), os.W_OK) else None
    assert origin_problem(dist) in (expected, "outside_environment")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_the_origin_check_refuses_on_windows() -> None:
    assert (
        origin_problem(importlib.metadata.distribution("pytest")) == "no_ownership_on_this_platform"
    )
