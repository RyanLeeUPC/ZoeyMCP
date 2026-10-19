"""S15 and S16 end to end, from the shipped profiles (M4 design M.4, M.5, N.5).

S15: the example mail toolkit sends through the SMTP connector, implicit TLS or STARTTLS, through
the CONNECT proxy; the human sees the exact message. S16: the example records toolkit's batches
against the records API over real TLS. Then the H14 sweep over everything recorded.
"""

from __future__ import annotations

import email
import email.policy
import json
import re
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.types import CallToolResult, TextContent

from tests.fakes.agent import ACCEPT, DECLINE, VERSIONS, Script, Version, agent
from tests.fakes.records_api import SECRET as RECORDS_SECRET
from tests.fakes.smtp_server import PASSWORD, USERNAME
from tests.gateway.rig import Running, token_for
from zoeymcp.common import ledgerformat
from zoeymcp.gateway.ledger import LEDGER_DIR

from .tls import ProviderCA
from .toolkits import AGENT, ToolkitDeployment

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


@pytest.fixture(params=["implicit", "starttls"])
def deployed(request: pytest.FixtureRequest, tmp_path: Path, ca: ProviderCA) -> ToolkitDeployment:
    return ToolkitDeployment(tmp_path, ca, mode=request.param)


# --- S15 ----------------------------------------------------------------------------------------


@pytest.mark.parametrize("version", VERSIONS)
async def test_s15_the_message_sent_is_the_message_shown(
    deployed: ToolkitDeployment, version: Version
) -> None:
    script = Script([ACCEPT])
    with deployed.running() as running:
        async with agent(
            url(running, "mail"), version=version, script=script, headers=headers()
        ) as client:
            result = await client.call_tool(
                "send_note",
                {"subject": SUBJECT, "body": BODY, "in_reply_to": "<m1.x@mail.example>"},
            )
        code, verified, _ = deployed.cli(running, "ledger", "--verify")
    assert not result.is_error, text(result)
    [prompt] = script.prompts
    lines = prompt.message.split("\n")
    ref = lines[0].removeprefix("Approval request ")
    assert lines[1:3] == [f"Client: {AGENT}", "Tool: mail \N{RIGHTWARDS ARROW} send_note"]
    assert lines[4:10] == [
        "",
        "Send an email",
        "From: Agent <agent@mail.example>",
        'To: ["partner@mail.example"]',
        "In reply to: <m1.x@mail.example>",
        f"Subject: {SUBJECT}",
    ]
    assert prompt.message.endswith(f"\n\n{BODY}\nEnd of approval request {ref}")
    # The connector went through the proxy, once, to the mail server's own name.
    assert [t.rsplit(":", 1)[0] for t in deployed.proxy.targets] == ["localhost"]
    [raw] = deployed.smtp.messages
    message = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert (message["Subject"], message["In-Reply-To"]) == (SUBJECT, "<m1.x@mail.example>")
    assert message.get_content().replace("\r\n", "\n") == BODY + "\n"
    assert deployed.smtp.sessions[0].tls_at_auth == [True]
    kinds = [r.kind for r in ledger(deployed) if r.ref == ref]
    assert kinds == ["asked", "decided", "outcome"]
    assert code == 0, verified
    assert ref in text(result) or text(result).startswith("sent (<")
    sweep(deployed)


async def test_s15_a_decline_sends_nothing(deployed: ToolkitDeployment) -> None:
    with deployed.running() as running:
        async with agent(
            url(running, "mail"), script=Script([DECLINE]), headers=headers()
        ) as client:
            result = await client.call_tool("send_note", {"subject": SUBJECT, "body": BODY})
    assert text(result).startswith("declined by operator (ref ")
    assert deployed.smtp.sessions == []
    assert deployed.proxy.targets == []
    sweep(deployed)


# --- S16 ----------------------------------------------------------------------------------------


def rows(n: int) -> list[dict[str, Any]]:
    return [{"title": f"title {i}", "amount": i, "day": "2026-01-01"} for i in range(n)]


async def test_s16_batches(tmp_path: Path, ca: ProviderCA) -> None:
    deployed = ToolkitDeployment(tmp_path, ca)
    deployed.records.differ_item = 3
    script = Script([ACCEPT, ACCEPT])
    with deployed.running() as running:
        async with agent(url(running, "records"), script=script, headers=headers()) as client:
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
