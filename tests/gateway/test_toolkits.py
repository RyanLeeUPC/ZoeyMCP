"""Toolkits in the gateway, in process (M4 design H, H11, H12, S15, S16), and a held write's
marker (M8 design C.2, FM-41).

A real vault routes a records API (the fake) and owns an SMTP connector (the fake mail server);
the gateway serves the example toolkits and a fixture toolkit on it. The agent is the SDK client.
"""

from __future__ import annotations

import email
import email.policy
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Any

import anyio
import httpx
import httpx2
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import CallToolResult, TextContent

from tests.acceptance.tls import ProviderCA, make_ca
from tests.fakes.agent import ACCEPT, DECLINE, VERSIONS, Script, Version, agent
from tests.gateway.rig import LINKS, Link, token_for, until
from tests.gateway.toolkit_rig import (
    ENTRY_POINTS,
    GROUP,
    SENDER,
    TO,
    Kit,
    fixtures_server,
    kit,
    mail_server,
    records_server,
    toolkit_gateway,
)
from zoeymcp.common import ledgerformat
from zoeymcp.common.approvaltext import Plan, Write
from zoeymcp.common.envelope import Marker
from zoeymcp.gateway.egressrules import marker_header
from zoeymcp.gateway.ledger import LEDGER_DIR
from zoeymcp.gateway.toolkitvault import CallState, ToolkitVault
from zoeymcp.gateway.upstream import Held
from zoeymcp.gateway.vaultlink import (
    TOOLKIT_MAX_REQUEST_BYTES,
    HeldAnswer,
    UpstreamBlocked,
    parse_link,
)
from zoeymcp.toolkit import VaultError, rules
from zoeymcp.toolkit.plan import SendLedger

pytestmark = pytest.mark.anyio
REF = re.compile(r"\(ref ([0-9a-f]{16})\)$")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("toolkit-ca"))


def headers() -> dict[str, str]:
    return {"authorization": f"Bearer {token_for('agent1')}"}


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


def ledger(deployed: Kit) -> list[ledgerformat.Record]:
    found: list[ledgerformat.Record] = []
    for path in sorted((deployed.state / LEDGER_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return found


def url(running: Any, server: str) -> str:
    return f"{running.url}/s/{server}/mcp"


# --- the mail toolkit (S15) ---------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)  # D-72: over TCP and the link socket
@pytest.mark.parametrize("version", VERSIONS)
async def test_the_message_sent_is_the_message_shown(
    tmp_path: Path, ca: ProviderCA, version: Version, link: Link
) -> None:
    script = Script([ACCEPT])
    with kit(tmp_path, ca, link=link) as deployed, toolkit_gateway(deployed) as running:
        async with agent(
            url(running, "mail"), version=version, script=script, headers=headers()
        ) as client:
            result = await client.call_tool(
                "send_note", {"subject": "Quarterly figures", "body": "Attached below.\nThanks."}
            )
    assert not result.is_error, text(result)
    assert text(result).startswith("sent (<")
    [prompt] = script.prompts
    lines = prompt.message.split("\n")
    ref = lines[0].removeprefix("Approval request ")
    assert "Send an email" in lines
    assert f"From: {SENDER}" in lines
    assert f'To: ["{TO[0]}"]' in lines
    assert "Subject: Quarterly figures" in lines
    assert prompt.message.endswith(f"Attached below.\nThanks.\nEnd of approval request {ref}")
    [raw] = deployed.smtp.messages
    message = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert message["Subject"] == "Quarterly figures"
    assert message.get_content().replace("\r\n", "\n") == "Attached below.\nThanks.\n"
    kinds = [(r.kind, r.fields.get("writes")) for r in ledger(deployed) if r.ref == ref]
    assert kinds == [("asked", 1), ("decided", None), ("outcome", None)]
    # The connector's journal keys the send by the call's ref.
    journal = next((tmp_path / "vault" / "connectors" / "mail-out").glob("journal-*.jsonl"))
    keys = {json.loads(line)["key"] for line in journal.read_text().splitlines()}
    assert keys == {f"{ref}.1"}


@pytest.mark.parametrize("link", LINKS)
async def test_a_declined_message_sends_nothing(tmp_path: Path, ca: ProviderCA, link: Link) -> None:
    with kit(tmp_path, ca, link=link) as deployed, toolkit_gateway(deployed) as running:
        async with agent(
            url(running, "mail"), script=Script([DECLINE]), headers=headers()
        ) as client:
            result = await client.call_tool("send_note", {"subject": "Hi", "body": "x"})
    assert result.is_error
    assert text(result).startswith("declined by operator (ref ")
    assert deployed.smtp.sessions == []


# --- the records toolkit (S16) ------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_a_batch_is_one_prompt_with_per_item_results(
    tmp_path: Path, ca: ProviderCA, link: Link
) -> None:
    script = Script([ACCEPT])
    rows = [{"title": f"t{i}", "amount": i, "day": "2026-01-01"} for i in range(3)]
    with kit(tmp_path, ca, link=link) as deployed, toolkit_gateway(deployed) as running:
        async with agent(url(running, "records"), script=script, headers=headers()) as client:
            added = await client.call_tool("add_records", {"records": rows})
            ids = [item["value"] for item in json.loads(text(added))["items"]]
            fetched = await client.call_tool("get_records", {"ids": [*ids, "r9999"]})
    assert len(script.prompts) == 1
    assert "Records (3):" in script.prompts[0].message
    assert json.loads(text(added))["ok"] == 3
    items = json.loads(text(fetched))["items"]
    assert [item["ok"] for item in items] == [True, True, True, False]
    assert deployed.records.requests.count(("POST", "/v1/records/batch")) == 1


# --- H11: containment ---------------------------------------------------------------------------


async def call(
    running: Any, server: str, tool: str, arguments: dict[str, Any], script: Script | None = None
) -> CallToolResult:
    async with agent(
        url(running, server), script=script or Script([ACCEPT]), headers=headers()
    ) as client:
        return await client.call_tool(tool, arguments)


async def test_containment(tmp_path: Path, ca: ProviderCA) -> None:
    with kit(tmp_path, ca) as deployed, toolkit_gateway(deployed) as running:
        sneaky = await call(running, "fixtures", "sneaky_send", {"note": "hi"})
        wander = await call(running, "fixtures", "wander", {})
        peek = await call(running, "fixtures", "peek_in_prepare", {})
        early = await call(running, "fixtures", "write_in_prepare", {})
        twice = await call(running, "fixtures", "send_twice", {"note": "once"})
    assert text(sneaky) == "blocked 403 blocked_needs_approval"
    assert text(wander) == (
        "blocked 403 blocked_bad_path | blocked 403 blocked_bad_path | blocked 403 blocked_no_rule"
    )
    assert text(peek).startswith("toolkit error: vault answered 403 blocked_prepare_upstream_read")
    assert text(early).startswith("toolkit error: vault answered 403 blocked_write_in_prepare")
    assert text(twice) == "sent | blocked 403 blocked_already_sent"
    assert deployed.smtp.sessions == []
    assert deployed.records.requests == [("POST", "/v1/records/batch")]
    blocked = deployed.events("toolkit_vault_blocked")
    assert {e["reason"] for e in blocked} >= {"needs_approval", "bad_path", "no_rule"}
    assert all("path" not in e for e in blocked)


async def test_an_exception_message_is_never_shown_or_logged(
    tmp_path: Path, ca: ProviderCA
) -> None:
    with kit(tmp_path, ca) as deployed, toolkit_gateway(deployed) as running:
        result = await call(running, "fixtures", "boom", {"note": "secret-note"})
    assert result.is_error
    assert text(result).startswith("toolkit error (ref ")
    assert "secret-note" not in text(result)
    assert "secret-note" not in deployed.log.getvalue()
    [event] = deployed.events("toolkit_error")
    assert event["error_type"] == "ValueError"


# --- H12 and load failures ----------------------------------------------------------------------


@pytest.mark.parametrize("module", ["os", "zoeymcp.vault.app", "example_toolkits.unregistered"])
async def test_an_unregistered_module_imports_nothing(
    tmp_path: Path, ca: ProviderCA, module: str
) -> None:
    servers = {"odd": {"kind": "toolkit", "module": module}}
    before = set(sys.modules)
    with kit(tmp_path, ca, servers=servers) as deployed, toolkit_gateway(deployed) as running:
        async with agent(url(running, "odd"), headers=headers()) as client:
            with pytest.raises(MCPError, match=r"^toolkit unavailable \(ref [0-9a-f]{16}\)$"):
                await client.list_tools()
            result = await client.call_tool("anything", {})
    assert text(result).startswith("toolkit unavailable (ref ")
    assert not {m for m in set(sys.modules) - before if m == module or m.startswith(module + ".")}
    reason = "refused_name" if module.startswith("zoeymcp") else "not_registered"
    assert [e["reason"] for e in deployed.events("toolkit_unavailable")] == [reason]


async def test_a_slot_mismatch(tmp_path: Path, ca: ProviderCA) -> None:
    server = mail_server(slots={})
    with (
        kit(tmp_path, ca, servers={"mail": server}) as deployed,
        toolkit_gateway(deployed) as running,
    ):
        async with agent(url(running, "mail"), headers=headers()) as client:
            with pytest.raises(MCPError, match="toolkit unavailable"):
                await client.list_tools()
    [event] = deployed.events("toolkit_unavailable")
    assert (event["reason"], event["slot"]) == ("slot_mismatch", "mail")


@pytest.mark.parametrize("pinning", ["required", "off"])
async def test_a_classification_mismatch_hides_the_tool(
    tmp_path: Path, ca: ProviderCA, pinning: str
) -> None:
    changes: dict[str, Any] = {"tools": {"include": ["send_note"], "allow": ["send_note"]}}
    if pinning == "off":
        changes.update(pinning="off", review={})
    servers = {"mail": mail_server(**changes)}
    with kit(tmp_path, ca, servers=servers) as deployed, toolkit_gateway(deployed) as running:
        async with agent(url(running, "mail"), headers=headers()) as client:
            listed = await client.list_tools()
            with pytest.raises(MCPError, match="Unknown tool"):
                await client.call_tool("send_note", {"subject": "Hi", "body": "x"})
    assert listed.tools == []
    [event] = deployed.events("toolkit_tool_invalid")
    assert (event["tool"], event["reason"]) == ("send_note", "classification")
    assert deployed.smtp.sessions == []


async def test_drift_hides_a_changed_tool_and_pinning_off_follows_the_image(
    tmp_path: Path, ca: ProviderCA
) -> None:
    stale = mail_server(review={"send_note": "sha256:" + "0" * 64})
    with (
        kit(tmp_path, ca, servers={"mail": stale}) as deployed,
        toolkit_gateway(deployed) as running,
    ):
        async with agent(url(running, "mail"), headers=headers()) as client:
            assert (await client.list_tools()).tools == []
        assert [e["tool"] for e in deployed.events("drift_marked")] == ["send_note"]
        deployed.reload(servers={"mail": mail_server(pinning="off", review={})})
        view = deployed.view.digest
        snapshot = running.app.policy
        await until(lambda: snapshot.snapshot is not None and snapshot.snapshot.view.digest == view)
        async with agent(url(running, "mail"), headers=headers()) as client:
            assert [t.name for t in (await client.list_tools()).tools] == ["send_note"]
    assert running.app.pool.marks.for_server("mail") == frozenset()


# --- review and status --------------------------------------------------------------------------


async def test_review_and_status(tmp_path: Path, ca: ProviderCA) -> None:
    with kit(tmp_path, ca) as deployed, toolkit_gateway(deployed) as running:
        reviewed = httpx.post(f"{running.admin_url}/review/mail", timeout=10).json()
        status = httpx.get(f"{running.admin_url}/status", timeout=10).json()
    assert reviewed["kind"] == "toolkit"
    assert reviewed["module"] == "example_toolkits.mail"
    assert reviewed["clean"] is True
    [tool] = reviewed["tools"]
    assert (tool["name"], tool["state"], tool["consequential"]) == ("send_note", "ok", True)
    mail = status["servers"]["mail"]
    assert (mail["kind"], mail["state"], mail["exposed"]) == ("toolkit", "loaded", 1)


def test_the_entry_points_name_the_fixture_modules() -> None:
    assert {e.value for e in ENTRY_POINTS} == {
        "example_toolkits.mail:toolkit",
        "example_toolkits.records:toolkit",
        "tests.gateway.toolkit_fixtures:toolkit",
    }
    assert all(e.group == GROUP for e in ENTRY_POINTS)
    assert importlib.metadata.EntryPoint("x", "y:z", GROUP).module == "y"
    assert records_server()["module"] == "example_toolkits.records"
    assert fixtures_server()["module"] == "tests.gateway.toolkit_fixtures"


async def test_one_bad_item_refuses_the_batch_before_asking(tmp_path: Path, ca: ProviderCA) -> None:
    """The toolkit's text rules run in the gateway, after the pinned schema (G.2)."""
    rows = [{"title": f"t{i}", "amount": i, "day": "2026-01-01"} for i in range(3)]
    rows[2]["title"] = "hidden" + chr(0x200B) + "text"
    script = Script([ACCEPT])
    with kit(tmp_path, ca) as deployed, toolkit_gateway(deployed) as running:
        result = await call(running, "records", "add_records", {"records": rows}, script)
    assert result.is_error
    assert text(result) == "arguments refused: at /records/2/title: text_rules"
    assert script.prompts == []
    assert deployed.records.requests == []


# --- a held write's marker (M8 design C.2, CR-3; FM-41) ----------------------------------------

HELD_MAIL = rules.Slot(
    "/mail",
    "smtp",
    (
        rules.SlotRule(frozenset({"GET"}), ("/mail/config",)),
        rules.SlotRule(frozenset({"POST"}), ("/mail/send",), approved=True),
    ),
)
# An HTTP route's slot with an approved rule: never a held connector (H11 under Elsewhere).
APPROVED_HTTP = rules.Slot(
    "/records",
    None,
    (rules.SlotRule(frozenset({"POST"}), ("/records/v1/notes",), approved=True),),
)
HELD_REF = "0123456789abcdef"
MARK = Marker(HELD_REF, "agent1", "block", "a1b2c3d4e5f6", "send_note")


def held_vault(handler: Any) -> ToolkitVault:
    return ToolkitVault(
        "mailer",
        {"mail": HELD_MAIL, "records": APPROVED_HTTP},
        parse_link("http://vault:8080"),
        None,
        inner=httpx2.MockTransport(handler),
    )


def approved_answer(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(
        200,
        content=b'{"message_id": "<m@x>"}',
        headers={
            "content-type": "application/json",
            "x-zoeymcp-approval": "approved",
            "x-zoeymcp-held-ref": HELD_REF,
        },
    )


async def test_marker_only_after_registration() -> None:
    """FM-41: a toolkit-built ``x-zoeymcp-held`` header is refused ``header`` by the toolkit
    transport, and nothing is sent; a request nobody registered leaves unmarked; the one held
    write an Elsewhere grant registered leaves marked, after the transport's own checks, and its
    answer is kept on the call; and an approved rule toward a route that isn't a connector is
    refused under the grant (H11), with nothing sent."""
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return approved_answer(request)

    vault = held_vault(handler)
    built = {"content-type": "application/json", "x-zoeymcp-held": marker_header(MARK)}
    with pytest.raises(UpstreamBlocked, match="header"):
        await vault.client.post("/mail/send", content=b"{}", headers=built)
    assert seen == []
    write = Write.post("/send", {"to": "a@b.example"})
    held = Held(MARK)
    state = CallState("send_note", HELD_REF, "approve", SendLedger(Plan("Mail", [write])))
    state.held = held
    slots = vault.bind(state)
    await slots["mail"].get_object("/config")  # not a registered write: unmarked
    assert await slots["mail"].send(write) == {"message_id": "<m@x>"}
    note = Write.post("/v1/notes", {"n": 1})
    other = CallState("send_note", HELD_REF, "approve", SendLedger(Plan("Note", [note])))
    other.held = Held(MARK)
    with pytest.raises(VaultError) as refused:
        await vault.bind(other)["records"].send(note)
    await vault.aclose()
    assert refused.value.code == "blocked_not_held"
    assert other.held is not None
    assert other.held.answer is None
    first, sent = seen
    assert "x-zoeymcp-held" not in first.headers
    assert sent.headers["x-zoeymcp-held"] == marker_header(MARK)
    assert sent.headers["idempotency-key"] == f"{HELD_REF}.1"
    assert held.answer == HeldAnswer(200, False, True, HELD_REF)
    assert vault._marked == {}


async def test_a_held_write_the_transport_refuses_leaves_no_registration() -> None:
    """The marker is added only after every check of the toolkit transport passed: a held write
    its check refuses is never sent and its registration goes, so nothing marked can follow."""
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return approved_answer(request)

    vault = held_vault(handler)
    vault._prefixes = set()  # the transport's own last look refuses every slot now
    write = Write.post("/send", {"to": "a@b.example"})
    state = CallState("send_note", HELD_REF, "approve", SendLedger(Plan("Mail", [write])))
    state.held = Held(MARK)
    with pytest.raises(VaultError) as refused:
        await vault.bind(state)["mail"].send(write)
    await vault.aclose()
    assert refused.value.code == "blocked_transport"
    assert seen == []
    assert vault._marked == {}
    assert state.held.answer is None


async def test_a_held_write_refused_before_the_transport_leaves_no_registration() -> None:
    """A held write the slot refuses itself (its body over the toolkit's request limit) is
    registered never, or never past the request: nothing marked is left to ride on another."""
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return approved_answer(request)

    vault = held_vault(handler)
    write = Write.post("/send", {"to": "a@b.example", "text": "x" * TOOLKIT_MAX_REQUEST_BYTES})
    state = CallState("send_note", HELD_REF, "approve", SendLedger(Plan("Mail", [write])))
    state.held = Held(MARK)
    with pytest.raises(VaultError) as refused:
        await vault.bind(state)["mail"].send(write)
    await vault.aclose()
    assert refused.value.code == "blocked_too_large"
    assert seen == []
    assert vault._marked == {}
    assert state.held.answer is None


async def test_identical_held_writes_of_two_calls_keep_their_own_markers() -> None:
    """Z27 for a toolkit: two calls on one toolkit server sending the same body at once each
    leave with their own marker, which names the ref their Idempotency-Key does, and each keeps
    its own answer; the same write of the same call can't be registered twice."""
    refs = ("0123456789abcdef", "fedcba9876543210")
    seen: list[httpx2.Request] = []
    both = anyio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        if len(seen) == len(refs):
            both.set()
        await both.wait()
        ref = request.headers["idempotency-key"].partition(".")[0]
        return httpx2.Response(
            200,
            content=b'{"message_id": "<m@x>"}',
            headers={
                "content-type": "application/json",
                "x-zoeymcp-approval": "approved",
                "x-zoeymcp-held-ref": ref,
            },
        )

    vault = held_vault(handler)
    write = Write.post("/send", {"to": "a@b.example"})
    states = []
    for ref in refs:
        state = CallState("send_note", ref, "approve", SendLedger(Plan("Mail", [write])))
        state.held = Held(Marker(ref, "agent1", "block", "a1b2c3d4e5f6", "send_note"))
        states.append(state)
    with anyio.fail_after(5):
        async with anyio.create_task_group() as group:
            for state in states:
                group.start_soon(vault.bind(state)["mail"].send, write)
    key = vault.mark("POST", "/mail/send", b"{}", f"{refs[0]}.1", MARK)
    assert key is not None
    assert vault.mark("POST", "/mail/send", b"{}", f"{refs[0]}.1", MARK) is None
    vault.unmark(key)
    await vault.aclose()
    assert len(seen) == len(refs)
    for request in seen:
        ref = request.headers["idempotency-key"].partition(".")[0]
        assert f"ref={ref};" in request.headers["x-zoeymcp-held"]
    for ref, state in zip(refs, states, strict=True):
        assert state.held is not None
        assert state.held.answer == HeldAnswer(200, False, True, ref)
    assert vault._marked == {}
