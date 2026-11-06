"""S13, S14, S15 and S16 end to end, from the shipped profiles (M4 design M.4, M.5, N.5; M8
design O.5).

S15: the example mail toolkit sends through the SMTP connector, by S13's implicit TLS or S14's
STARTTLS, through the CONNECT proxy; the human sees the exact message. Since M8 (step 19, D-73's
M8 part, J4) S15 runs under each approval mode, over each link: the gateway asking in the
agent's own client (elicitation), and ``vault_approval``, where the vault holds the connector's
send and its approver (a scripted portal surface) decides it, the gateway only marking the write
and recording the call as approved elsewhere; the link is TCP with the gateway key, or the link
socket on Linux. Each mode's send is accepted, declined, or left unanswered past its deadline,
and only an accepted one is sent. S13/S14's failure matrix through the gateway (replay, unknown
after the dot, a proxy stripping STARTTLS) and S14's direct case stay unit rows
(``test_smtp_connector.py``) until the pre-main test-debt pass. S16: the example records
toolkit's batches against the records API over real TLS. Then the H14 sweep over everything
recorded. In each, the agent offers sampling and roots, and neither is ever called (M.1, D-75).
"""

from __future__ import annotations

import email
import email.policy
import json
import re
import sys
from pathlib import Path
from typing import Any, Literal

import anyio
import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from tests.fakes.agent import ACCEPT, DECLINE, VERSIONS, Answer, Never, Script, Version, agent
from tests.fakes.records_api import SECRET as RECORDS_SECRET
from tests.fakes.smtp_server import PASSWORD, USERNAME
from tests.gateway.rig import Running, token_for
from zoeymcp.common import ledgerformat
from zoeymcp.gateway.ledger import LEDGER_DIR

from .tls import ProviderCA
from .toolkits import AGENT, Approval, Link, Mode, ToolkitDeployment

pytestmark = pytest.mark.anyio
REF = re.compile(r"\(ref ([0-9a-f]{16})\)$")
SUBJECT = "Quarterly figures for review"
BODY = "The figures are attached.\n.A line starting with a dot.\nThanks."


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def headers() -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(AGENT)}"}


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


def url(running: Running, server: str) -> str:
    return f"{running.url}/s/{server}/mcp"


def ledger(deployed: ToolkitDeployment) -> list[ledgerformat.Record]:
    found: list[ledgerformat.Record] = []
    for path in sorted((deployed.state / LEDGER_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return found


@pytest.fixture(params=["implicit", "starttls"], ids=["S13", "S14"])
def transport(request: pytest.FixtureRequest) -> Mode:
    """S13 (implicit TLS on 465) or S14 (STARTTLS on 587), each through the CONNECT proxy."""
    found: Mode = request.param
    return found


@pytest.fixture(params=["gateway", "vault_approval"])
def approval(request: pytest.FixtureRequest) -> Approval:
    found: Approval = request.param
    return found


@pytest.fixture(params=["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))])  # fmt: skip
def link(request: pytest.FixtureRequest) -> Link:
    found: Link = request.param
    return found


@pytest.fixture
def deployed(
    tmp_path: Path, ca: ProviderCA, transport: Mode, approval: Approval, link: Link
) -> ToolkitDeployment:
    return ToolkitDeployment(tmp_path, ca, mode=transport, approval=approval, link=link)


async def send(
    deployed: ToolkitDeployment,
    client: Any,
    arguments: dict[str, Any],
    script: Script,
    decision: Literal["approve", "deny", "expire"],
) -> tuple[CallToolResult, str]:
    """``send_note`` with ``arguments``, decided as ``decision`` by the approver of the
    deployment's mode: the gateway's prompt, answered by ``script``, or the vault's hold,
    decided on its surface while the call waits (or, with ``expire``, left past its end).
    Returns the call's result and the text the human was shown."""
    if deployed.approval == "gateway":
        result: CallToolResult = await client.call_tool("send_note", arguments)
        [prompt] = script.prompts
        return result, prompt.message
    found: list[CallToolResult] = []

    async def call() -> None:
        found.append(await client.call_tool("send_note", arguments))

    with anyio.fail_after(60):
        async with anyio.create_task_group() as group:
            group.start_soon(call)
            [hold] = await deployed.surface.holds(1)
            if decision == "expire":
                await deployed.expire()
            else:
                await deployed.decide(hold, decision)
        await deployed.settled()
    assert script.prompts == []  # the vault asked, never the agent's own client
    return found[0], hold.text.value


# --- S15 ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_s15_the_message_sent_is_the_message_shown(
    deployed: ToolkitDeployment, version: Version
) -> None:
    script, never = Script([ACCEPT]), Never()
    arguments = {"subject": SUBJECT, "body": BODY, "in_reply_to": "<m1.x@mail.example>"}
    with deployed.running() as running:
        async with agent(
            url(running, "mail"),
            version=version,
            script=script,
            headers=headers(),
            **never.options(),
        ) as client:
            result, shown = await send(deployed, client, arguments, script, "approve")
        code, verified, _ = deployed.cli(running, "ledger", "--verify")
    assert not result.is_error, text(result)
    assert never.called == []
    lines = shown.split("\n")
    ref = lines[0].removeprefix("Approval request ")
    plan = [
        "Send an email",
        "From: Agent <agent@mail.example>",
        'To: ["partner@mail.example"]',
        "In reply to: <m1.x@mail.example>",
        f"Subject: {SUBJECT}",
    ]
    if deployed.approval == "gateway":
        assert lines[1:3] == [f"Client: {AGENT}", "Tool: mail \N{RIGHTWARDS ARROW} send_note"]
        assert lines[4:10] == ["", *plan]
    else:  # the vault's frame (E.5), over the plan the vault rendered for its connector (B.7)
        assert lines[1] == f"Client (reported by the gateway): {AGENT}"
        assert lines[3].endswith("UTC. Approve runs this one call, exactly as shown.")
        assert all(line in lines for line in plan[1:]), shown
    assert shown.endswith(f"\n\n{BODY}\nEnd of approval request {ref}")
    # The connector went through the proxy, once, to the mail server's own name.
    assert [t.rsplit(":", 1)[0] for t in deployed.proxy.targets] == ["localhost"]
    [raw] = deployed.smtp.messages
    message = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert (message["Subject"], message["In-Reply-To"]) == (SUBJECT, "<m1.x@mail.example>")
    assert message.get_content().replace("\r\n", "\n") == BODY + "\n"
    assert deployed.smtp.sessions[0].tls_at_auth == [True]
    records = [r for r in ledger(deployed) if r.ref == ref]
    assert [r.kind for r in records] == ["asked", "decided", "outcome"]
    if deployed.approval == "vault_approval":
        assert (records[0].fields["where"], records[1].fields["decision"]) == (
            "vault",
            "approved_elsewhere",
        )
    assert code == 0, verified
    assert ref in text(result) or text(result).startswith("sent (<")
    sweep(deployed)


async def test_s15_a_decline_sends_nothing(deployed: ToolkitDeployment) -> None:
    script, never = Script([DECLINE]), Never()
    with deployed.running() as running:
        async with agent(
            url(running, "mail"), script=script, headers=headers(), **never.options()
        ) as client:
            arguments = {"subject": SUBJECT, "body": BODY}
            result, _ = await send(deployed, client, arguments, script, "deny")
    assert never.called == []
    said = {
        "gateway": "declined by operator (ref ",
        "vault_approval": "refused: the operator declined this call (ref ",
    }[deployed.approval]
    assert text(result).startswith(said), text(result)
    assert deployed.smtp.sessions == []
    assert deployed.proxy.targets == []
    sweep(deployed)


async def test_s15_an_unanswered_send_sends_nothing(deployed: ToolkitDeployment) -> None:
    """S15's timeout: nobody answers the send by its deadline, the agent's own prompt (its
    client's timeout shortened) or the vault's hold (past its end, B.7): nothing is sent, and the
    gateway's ledger has the call timed out and not sent."""
    script, never = Script([Answer(delay=3.0)]), Never()
    if deployed.approval == "gateway":
        deployed.ask_timeout = 1
    with deployed.running() as running:
        async with agent(
            url(running, "mail"), script=script, headers=headers(), **never.options()
        ) as client:
            arguments = {"subject": SUBJECT, "body": BODY}
            result, _ = await send(deployed, client, arguments, script, "expire")
    assert never.called == []
    assert result.is_error
    said = {
        "gateway": "no answer in time",
        "vault_approval": "refused: no answer before the deadline (ref ",
    }[deployed.approval]
    assert text(result).startswith(said), text(result)
    [ref] = {r.ref for r in ledger(deployed) if r.kind == "asked"}  # the send, asked once
    records = [r for r in ledger(deployed) if r.ref == ref]
    assert [(r.kind, r.fields.get("decision") or r.fields.get("outcome")) for r in records][1:] == [
        ("decided", "timeout"),
        ("outcome", "not_sent"),
    ]
    assert deployed.smtp.sessions == []
    assert deployed.proxy.targets == []
    sweep(deployed)


# --- S16 ----------------------------------------------------------------------------------------


def rows(n: int) -> list[dict[str, Any]]:
    return [{"title": f"title {i}", "amount": i, "day": "2026-01-01"} for i in range(n)]


async def test_s16_batches(tmp_path: Path, ca: ProviderCA) -> None:
    deployed = ToolkitDeployment(tmp_path, ca)
    deployed.records.differ_item = 3
    script, never = Script([ACCEPT, ACCEPT]), Never()
    with deployed.running() as running:
        async with agent(
            url(running, "records"), script=script, headers=headers(), **never.options()
        ) as client:
            added = await client.call_tool("add_records", {"records": rows(25)})
            too_many = await client.call_tool("add_records", {"records": rows(26)})
            ids = [item.get("value") for item in json.loads(text(added))["items"]]
            fetched = await client.call_tool("get_records", {"ids": [*ids[:49], "r9999"]})
            over = await client.call_tool("get_records", {"ids": ["r0001"] * 51})
            odd = await client.call_tool("get_records", {"ids": ["a/b"]})
            archived = await client.call_tool("archive_records", {"ids": ids[:2]})
        vault_url = str(running.app.toolkits.link.base_url)
        key = deployed.keys.gateway_key(1)
        delete = httpx.delete(
            f"{vault_url}/records/v1/records/r0001", headers={"x-zoeymcp-gateway": key}
        )
    assert len(script.prompts) == 2  # one per batch: add, then archive
    assert never.called == []
    assert "Records (25):" in script.prompts[0].message
    added_items = json.loads(text(added))["items"]
    assert [i["ok"] for i in added_items].count(False) == 1
    assert added_items[3]["error"] == "read-back differs"
    assert deployed.records.requests.count(("POST", "/v1/records/batch")) == 1
    assert text(too_many).startswith("arguments refused: at /records")
    assert json.loads(text(fetched))["failed"] == 1, text(fetched)
    assert deployed.records.max_in_flight <= 4
    assert text(over).startswith("arguments refused: at /ids")
    assert text(odd).startswith("arguments refused: at /ids/0")
    assert text(archived) == "archived 2 of 2"
    assert delete.status_code == 403  # no DELETE rule on the route: archive, never delete
    sweep(deployed)


# --- H14 ----------------------------------------------------------------------------------------


def sweep(deployed: ToolkitDeployment) -> None:
    """Nothing the logs, ledger, admin answers or CLI output hold is a subject, body, recipient,
    username, password, API key or approval text."""
    seen = deployed.seen.everything()
    seen += "".join(p.read_text(encoding="utf-8") for p in (deployed.state / LEDGER_DIR).glob("*"))
    for value in (SUBJECT, "The figures are attached", "partner@mail.example", USERNAME, PASSWORD,
                  RECORDS_SECRET, "title 1", "Approval request"):  # fmt: skip
        assert value not in seen, value
    assert "hmac-sha256:" not in deployed.seen.log.getvalue()
