"""``check_approval`` in process (M8 design F.3-F.5; Z17, Z18; Q46): where it is served (F.4),
its definition, its arguments, and each answer of the vault's collect path as the agent reads it,
with the ending closing the gateway's own record of the call (D.2), against a real ledger and
the vault answering through a mock transport on the approvals client (E.3). The end-to-end shape
is S21's (``tests/acceptance/test_pending_shapes.py``).
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path
from typing import Any

import anyio
import httpx2
import pytest
from mcp.types import TextContent

from tests.gateway.test_elsewhere import VIEW_POLICY, InProcess, in_process
from tests.unit.plainid import plain_id
from zoeymcp.common import ledgerformat
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import ViewGateway, build_view
from zoeymcp.gateway import checkapproval, elsewhere, logs, pipeline
from zoeymcp.gateway.checkapproval import Checker, definition, served
from zoeymcp.gateway.ledger import LEDGER_DIR
from zoeymcp.gateway.vaultlink import (
    APPROVALS_MAX_ANSWER_BYTES,
    COLLECT_PATH,
    Link,
    approvals_client,
)

pytestmark = pytest.mark.anyio
BOUND = 10
REF = "0123456789abcdef"  # in_process's call
LINK = Link("http", "http://vault.test", "http", "vault.test", None)
DEFINITION = {
    "name": "echo",
    "inputSchema": {"type": "object"},
    "outputSchema": {
        "type": "object",
        "properties": {"said": {"type": "string"}},
        "required": ["said"],
    },
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def gateway_of(**changes: Any) -> ViewGateway:
    document = json.loads(json.dumps(VIEW_POLICY))
    for path, value in changes.items():
        place = document
        *parents, last = path.split(".")
        for name in parents:
            place = place.setdefault(name, {})
        place[last] = value
    return build_view(Policy.model_validate(document)).gateway


def text(result: Any) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


# --- F.4: where it is served -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "client", "found"),
    [
        ({"gateway.clients.agent1.approvals": {"attended": True}}, "agent1", True),
        (
            {"gateway.clients.agent1.approvals": {"attended": False, "out_of_band": True}},
            "agent1",
            True,
        ),
        ({"gateway.clients.agent1.approvals": {"attended": False}}, "agent1", False),
        ({}, "agent1", False),
        ({"gateway.clients.agent1.approvals": {"attended": True}}, "agent2", False),
        (
            {
                "gateway.clients.agent1.approvals": {"attended": True},
                "gateway.servers.notes.tools": {"include": ["echo"], "approve": ["echo"]},
            },
            "agent1",
            False,
        ),
        (
            {
                "gateway.clients.agent1.approvals": {"attended": False, "out_of_band": True},
                "gateway.servers.notes.tools": {"include": ["echo"], "approve": ["echo"]},
            },
            "agent1",
            True,
        ),
        (
            {
                "gateway.clients.agent1.approvals": {"attended": True, "out_of_band": True},
                "gateway.servers.notes.tools": {"include": ["echo"], "allow": ["echo"]},
                "gateway.servers.notes.review": {"echo": "sha256:" + "1" * 64},
            },
            "agent1",
            False,
        ),
    ],
    ids=[
        "attended-held",
        "out-of-band",
        "unattended",
        "no-approvals",
        "another-client",
        "attended-nothing-held",
        "out-of-band-nothing-held",
        "no-approve-tool",
    ],
)
def test_where_it_is_served(changes: dict[str, Any], client: str, found: bool) -> None:
    gateway = gateway_of(**changes)
    assert served(gateway, client, gateway.servers["notes"]) is found


def test_never_served_without_an_out_of_band_approver() -> None:
    gateway = gateway_of(**{"gateway.clients.agent1.approvals": {"attended": True}})
    without = gateway.model_copy(
        update={"approvals": gateway.approvals.model_copy(update={"out_of_band": None})}
    )
    assert not served(without, "agent1", without.servers["notes"])


def test_the_definition_names_the_views_result_ttl() -> None:
    out = gateway_of().approvals.out_of_band
    assert out is not None
    found = definition(out.model_copy(update={"result_ttl": 90}))
    assert found["description"].endswith(
        "is kept for 2 minutes after the call runs and is given once."
    )
    assert found["inputSchema"]["properties"]["id"]["pattern"] == "^[0-9a-f]{16}$"
    assert found["inputSchema"]["additionalProperties"] is False
    assert found["annotations"] == {"readOnlyHint": True}
    assert "{ttl}" in checkapproval.DEFINITION["description"]  # the template is untouched


# --- the answers ---------------------------------------------------------------------------


class Vault:
    """The vault's collect path, as a mock transport: records each body, answers ``answer``."""

    def __init__(self, answer: dict[str, Any] | None = None, status: int = 200) -> None:
        self.answer = answer
        self.status = status
        self.bodies: list[dict[str, Any]] = []

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        assert request.method == "POST"
        assert request.url.path == COLLECT_PATH
        self.bodies.append(json.loads(request.content))
        if self.answer is None:
            raise httpx2.ConnectError("the vault is down")
        return httpx2.Response(self.status, json={"v": 1, **self.answer})


async def checker(held: InProcess, vault: Vault) -> Checker:
    http = approvals_client(LINK, None, httpx2.MockTransport(vault.handle))

    async def definitions(tool: str, pin: str) -> dict[str, Any] | None:
        return DEFINITION if (tool, pin) == ("echo", held.call.pin) else None

    return Checker(held.approvals, http, definitions)


async def pend(held: InProcess) -> None:
    """The record as it waits once the vault answered pending (D.2)."""
    held.approvals.table.pend(REF, 1_900_000_000.0)
    await held.approvals.ledger.write(  # type: ignore[union-attr]
        "decided", REF, critical=False, decision="pending", waited_ms=0
    )


def call_of(held: InProcess, client: str = "agent1", server: str = "notes") -> pipeline.Call:
    gateway = held.call.gateway
    return pipeline.Call(client, server, gateway.servers[server], gateway.limits, "modern")


def result_body(structured: dict[str, Any], *, id: Any = "call-1", **fields: Any) -> str:
    message = {
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "content": [{"type": "text", "text": json.dumps(structured)}],
            "structuredContent": structured,
            "isError": False,
            **fields,
        },
    }
    return base64.b64encode(json.dumps(message).encode()).decode()


def done(
    body: str,
    *,
    status: int = 200,
    request_id: Any = "call-1",
    outcome: str = "ok",
    content_type: str = "application/json",
) -> dict[str, Any]:
    return {
        "ref": REF,
        "tool": "echo",
        "state": "done",
        "outcome": outcome,
        "collected": False,
        "lost": None,
        "result": {
            "status": status,
            "content_type": content_type,
            "request_id": request_id,
            "body": body,
        },
    }


def outcomes(held: InProcess) -> list[tuple[Any, Any]]:
    """The gateway ledger's outcome records of the call: each one's outcome and detail."""
    found: list[ledgerformat.Record] = []
    for path in sorted((held.tmp_path / LEDGER_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return [
        (r.fields["outcome"], r.fields.get("detail"))
        for r in found
        if r.ref == REF and r.kind == "outcome"
    ]


# A stream holding a request from the server (it wants input, H13), then the response.
INPUT_ASKED = (
    b'data: {"jsonrpc":"2.0","id":9,"method":"elicitation/create"}\n\n'
    + b"data: "
    + base64.b64decode(result_body({"said": "hi"}))
    + b"\n\n"
)


async def test_a_result_is_finished_as_a_direct_calls(tmp_path: Path) -> None:
    """F.5 steps 5, 6: the vault's collect for the calling client on this server; the result
    read as the held request's one response and checked against the tool's pinned output
    schema; the gateway's record closed ``approved_elsewhere`` and its lock freed."""
    held = await in_process(tmp_path)
    await pend(held)
    vault = Vault(done(result_body({"said": "hi"})))
    with anyio.fail_after(BOUND):
        found = await (await checker(held, vault)).check(
            call_of(held), held.call.gateway, {"id": REF}
        )
    assert not found.is_error
    assert found.structured_content == {"said": "hi"}
    assert vault.bodies == [
        {"epoch": held.approvals.epoch, "client": "agent1", "server": "notes", "ref": REF}
    ]
    assert held.records()[-2:] == [("decided", "approved_elsewhere"), ("outcome", "ok")]
    assert held.approvals.table.get(REF) is None


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        (done(result_body({"said": 1})), "upstream result refused"),
        (done(result_body({"said": "hi"}, id="other")), "upstream sent an unsupported result"),
        (done(result_body({"said": "hi"}), request_id=None), "upstream sent an unsupported result"),
        (done("not base64!"), "upstream sent an unsupported result"),
        (
            done(base64.b64encode(INPUT_ASKED).decode(), content_type="text/event-stream"),
            "refused: the server asked for input this gateway doesn't relay",
        ),
        (
            done(result_body({"said": "hi"}, resultType="input_required")),
            "upstream sent an unsupported result",
        ),
        (
            done(
                base64.b64encode(
                    b'{"jsonrpc":"2.0","id":"call-1","error":{"code":-1,"message":"x"}}'
                ).decode()
            ),
            "upstream error",
        ),
    ],
    ids=[
        "output-schema",
        "other-id",
        "no-id",
        "bad-base64",
        "input-asked",
        "not-complete",
        "rpc-error",
    ],
)
async def test_a_result_that_cant_be_delivered_says_why(
    tmp_path: Path, answer: dict[str, Any], said: str
) -> None:
    held = await in_process(tmp_path)
    vault = Vault(answer)
    with anyio.fail_after(BOUND):
        found = await (await checker(held, vault)).check(
            call_of(held), held.call.gateway, {"id": REF}
        )
    assert found.is_error
    assert text(found) == f"{said} (ref {REF})"


async def test_a_result_whose_pinned_definition_is_gone_is_refused(tmp_path: Path) -> None:
    """Deviation 12: with no pinned definition of the tool, its output schema can't be checked,
    so the result is never delivered (fails closed)."""
    held = await in_process(tmp_path)
    await pend(held)
    http = approvals_client(
        LINK, None, httpx2.MockTransport(Vault(done(result_body({"said": "hi"}))).handle)
    )

    async def gone(tool: str, pin: str) -> dict[str, Any] | None:
        return None

    with anyio.fail_after(BOUND):
        found = await Checker(held.approvals, http, gone).check(
            call_of(held), held.call.gateway, {"id": REF}
        )
    assert found.is_error
    assert text(found) == f"upstream result refused (ref {REF})"
    assert held.records()[-2:] == [("decided", "approved_elsewhere"), ("outcome", "ok")]


LOST = "upstream connection lost; the call may or may not have run"


@pytest.mark.parametrize(
    ("status", "outcome", "said", "ledgered"),
    [
        (502, "not_sent", "upstream unavailable", ("not_sent", None)),
        (502, "unknown", LOST, ("unknown", None)),
        (502, "upstream_error", "upstream error", ("upstream_error", None)),
        (502, "ok", LOST, ("unknown", None)),
        (500, "upstream_error", "upstream error", ("upstream_error", None)),
        (404, "upstream_error", LOST, ("upstream_error", "session_expired")),
    ],
    ids=["not-sent", "unknown", "redirect", "unnamed", "upstream-500", "upstream-404"],
)
async def test_a_forward_that_failed_after_the_approval(
    tmp_path: Path, status: int, outcome: str, said: str, ledgered: tuple[str, str | None]
) -> None:
    """A stored answer outside 2xx is the forward's failure, as the vault's outcome of it says
    (B.8), mapped as the blocking path maps the vault's approved refusal: never sent, the
    upstream's error (its 404: the session was gone, F.6), or it may have run. The gateway's
    ledger says what the vault's chain says."""
    held = await in_process(tmp_path)
    await pend(held)
    vault = Vault(done(result_body({"said": "hi"}), status=status, outcome=outcome))
    with anyio.fail_after(BOUND):
        found = await (await checker(held, vault)).check(
            call_of(held), held.call.gateway, {"id": REF}
        )
    assert found.is_error
    assert text(found) == f"{said} (ref {REF})"
    assert held.records()[-2][1] == "approved_elsewhere"
    assert outcomes(held) == [ledgered]
    assert held.approvals.table.get(REF) is None


STATUS = {"ref": REF, "tool": "echo", "deadline": "2026-11-02T13:05:00+00:00", "outcome": None}
ROWS: list[Any] = [
    (
        {**STATUS, "state": "pending"},
        "still pending: waiting for the operator's approval until 2026-11-02 13:05 UTC",
        None,
    ),
    ({**STATUS, "state": "approved"}, checkapproval.RUNNING, None),
    ({**STATUS, "state": "forwarding"}, checkapproval.RUNNING, None),
    ({**STATUS, "state": "denied"}, checkapproval.DECLINED, ("decline", "not_sent")),
    ({**STATUS, "state": "expired"}, checkapproval.EXPIRED, ("timeout", "not_sent")),
    (
        {**STATUS, "state": "withdrawn", "detail": "changed"},
        "withdrawn: the policy changed; nothing was sent",
        ("withdrawn", "not_sent"),
    ),
    (
        {**STATUS, "state": "withdrawn", "detail": "busy"},
        "withdrawn: it was withdrawn; nothing was sent",
        ("withdrawn", "not_sent"),
    ),
    (
        {**STATUS, "state": "done", "outcome": "ok", "collected": True},
        checkapproval.COLLECTED,
        ("approved_elsewhere", "ok"),
    ),
    (
        {**STATUS, "state": "done", "outcome": "unknown", "lost": "too_large"},
        elsewhere.TOO_LARGE,
        ("approved_elsewhere", "unknown"),
    ),
    (
        {**STATUS, "state": "done", "outcome": "ok", "lost": "not_kept"},
        checkapproval.NOT_KEPT,
        ("approved_elsewhere", "ok"),
    ),
    (
        {"ref": REF, "state": "done", "detail": "ok", "restarted": True},
        checkapproval.RESTART_LOST,
        ("approved_elsewhere", "ok"),
    ),
    (
        {"ref": REF, "state": "done", "detail": "restart", "restarted": True},
        checkapproval.RESTART_LOST,
        ("approved_elsewhere", "unknown"),
    ),
    (
        {"ref": REF, "state": "done", "detail": "not_sent", "restarted": True},
        checkapproval.RESTART_NOT_SENT,
        ("approved_elsewhere", "not_sent"),
    ),
    (
        {"ref": REF, "state": "withdrawn", "detail": "restart", "restarted": True},
        checkapproval.RESTART_NOT_SENT,
        ("withdrawn", "not_sent"),
    ),
    ({"ref": REF, "state": "unknown"}, checkapproval.UNKNOWN, None),
    ({"ref": "fedcba9876543210", "state": "done"}, checkapproval.UNKNOWN, None),
    ({**STATUS, "state": "held"}, checkapproval.UNKNOWN, None),
]


@pytest.mark.parametrize(("answer", "said", "ended"), ROWS, ids=plain_id)
async def test_each_status_answers_what_it_is(
    tmp_path: Path, answer: dict[str, Any], said: str, ended: tuple[str, str] | None
) -> None:
    """F.5 step 7: each status a tool error that says what it is; an ending closes the
    gateway's pending record as the vault decided it (a decline and an expiry start the
    cooldown), and a status that isn't one leaves the record waiting."""
    held = await in_process(tmp_path)
    await pend(held)
    with anyio.fail_after(BOUND):
        found = await (await checker(held, Vault(answer))).check(
            call_of(held), held.call.gateway, {"id": REF}
        )
    assert found.is_error
    assert text(found) == f"{said} (ref {REF})"
    if ended is None:
        assert held.approvals.table.get(REF) is not None
        assert held.records()[-1] == ("decided", "pending")
        return
    decision, outcome = ended
    assert held.records()[-2:] == [("decided", decision), ("outcome", outcome)]
    assert held.approvals.table.get(REF) is None


@pytest.mark.parametrize(
    "arguments",
    [{"id": "0123456789ABCDEF"}, {"id": 1}, {"id": "x"}, {"ref": REF}, [REF], "x"],
    ids=["upper", "number", "short", "other-key", "array", "string"],
)
async def test_the_arguments_are_an_id_or_nothing(tmp_path: Path, arguments: Any) -> None:
    held = await in_process(tmp_path)
    vault = Vault({"ref": REF, "state": "unknown"})
    with anyio.fail_after(BOUND):
        found = await (await checker(held, vault)).check(
            call_of(held), held.call.gateway, arguments
        )
    assert text(found) == checkapproval.ARGUMENTS
    assert vault.bodies == []


async def test_another_clients_or_servers_record_is_never_asked_about(tmp_path: Path) -> None:
    """F.5 step 1: a ref this gateway asked for another client (or on another server) answers
    unknown, and the vault isn't asked."""
    held = await in_process(tmp_path)
    vault = Vault({"ref": REF, "state": "pending"})
    other = pipeline.Call("agent2", "notes", held.call.policy, held.call.gateway.limits, "modern")
    with anyio.fail_after(BOUND):
        found = await (await checker(held, vault)).check(other, held.call.gateway, {"id": REF})
    assert text(found) == f"{checkapproval.UNKNOWN} (ref {REF})"
    assert vault.bodies == []


async def test_a_vault_that_cant_be_asked(tmp_path: Path) -> None:
    held = await in_process(tmp_path)
    checks = await checker(held, Vault(None))
    refused = await checker(held, Vault({"ref": REF}, status=503))
    with anyio.fail_after(BOUND):
        down = await checks.check(call_of(held), held.call.gateway, {"id": REF})
        busy = await refused.check(call_of(held), held.call.gateway, {"id": REF})
        listed = await checks.check(call_of(held), held.call.gateway, None)
    assert text(down) == f"{checkapproval.UNREACHABLE} (ref {REF})"
    assert text(busy) == text(down)
    assert text(listed) == checkapproval.UNREACHABLE
    assert held.approvals.table.get(REF) is not None


@pytest.mark.parametrize(
    ("answer", "error_type"),
    [
        (httpx2.Response(307, headers={"location": "http://elsewhere.test/"}), "UpstreamRedirect"),
        (
            httpx2.Response(200, content=b" " * (APPROVALS_MAX_ANSWER_BYTES + 1)),
            "ResponseTooLarge",
        ),
    ],
    ids=["redirect", "too-large"],
)
async def test_the_approvals_clients_own_refusals_are_a_vault_that_cant_be_asked(
    tmp_path: Path, answer: httpx2.Response, error_type: str
) -> None:
    """E.3: the approvals client never follows a redirect, and cuts an answer off past its
    bound; either is a collect that failed, logged, and the agent is told to try again."""
    held = await in_process(tmp_path)
    await pend(held)
    http = approvals_client(LINK, None, httpx2.MockTransport(lambda request: answer))

    async def definitions(tool: str, pin: str) -> dict[str, Any] | None:
        return DEFINITION

    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        with anyio.fail_after(BOUND):
            found = await Checker(held.approvals, http, definitions).check(
                call_of(held), held.call.gateway, {"id": REF}
            )
    finally:
        logs.set_stream(None)
    assert text(found) == f"{checkapproval.UNREACHABLE} (ref {REF})"
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    failed = [e for e in lines if e.get("event") == "approval_collect_failed"]
    assert [(e["ref"], e["error_type"]) for e in failed] == [(REF, error_type)]
    assert held.approvals.table.get(REF) is not None


async def test_with_no_id_the_clients_own_calls_are_listed(tmp_path: Path) -> None:
    """Q46: no result, no text; only well-formed rows."""
    held = await in_process(tmp_path)
    calls = [
        {**STATUS, "state": "pending"},
        {**STATUS, "ref": "00000000000000a1", "state": "done", "collected": False, "lost": None},
        {**STATUS, "ref": "00000000000000a2", "state": "done", "lost": "not_kept"},
        {**STATUS, "ref": "00000000000000a3", "state": "approved"},
        {**STATUS, "ref": "00000000000000a4", "state": "denied"},
        {**STATUS, "ref": "00000000000000a5", "state": "withdrawn"},
        {**STATUS, "ref": "not a ref", "state": "pending"},
        "not a row",
    ]
    vault = Vault({"calls": calls})
    with anyio.fail_after(BOUND):
        found = await (await checker(held, vault)).check(call_of(held), held.call.gateway, {})
        empty = await (await checker(held, Vault({"calls": []}))).check(
            call_of(held), held.call.gateway, None
        )
    assert not found.is_error
    assert text(found).splitlines() == [
        "Calls of yours on this server that answered pending (collect each by its id):",
        f"{REF} (echo): waiting for approval until 2026-11-02 13:05 UTC",
        "00000000000000a1 (echo): ran; collect its result",
        "00000000000000a2 (echo): ran; its result wasn't kept",
        "00000000000000a3 (echo): approved, running",
        "00000000000000a4 (echo): declined",
        "00000000000000a5 (echo): withdrawn",
    ]
    assert vault.bodies == [{"epoch": held.approvals.epoch, "client": "agent1", "server": "notes"}]
    assert not empty.is_error
    assert text(empty) == checkapproval.NONE_LISTED


async def test_the_approvals_client_reaches_its_paths_only() -> None:
    """E.3: the five approvals paths (a POST, or the decisions GET), and nothing else."""
    seen: list[str] = []

    def handle(request: httpx2.Request) -> httpx2.Response:
        seen.append(f"{request.method} {request.url.raw_path.decode()}")
        return httpx2.Response(200, json={})

    async with approvals_client(LINK, None, httpx2.MockTransport(handle)) as http:
        for name in ("ask", "withdraw", "detach", "collect"):
            await http.post(f"/_zoeymcp/gateway/v1/approvals/{name}", content=b"{}")
        await http.get("/_zoeymcp/gateway/v1/approvals/decisions?epoch=x&after=0&wait=25")
        for method, path in [
            ("GET", "/_zoeymcp/gateway/v1/approvals/collect"),
            ("POST", "/_zoeymcp/gateway/v1/approvals/collect?x=1"),
            ("POST", "/_zoeymcp/gateway/v1/approvals/decisions"),
            ("POST", "/_zoeymcp/gateway/v1/view"),
            ("POST", "http://elsewhere.test/_zoeymcp/gateway/v1/approvals/collect"),
        ]:
            with pytest.raises(Exception, match="approvals paths"):
                await http.request(method, path, content=b"{}" if method == "POST" else None)
    assert len(seen) == 5
