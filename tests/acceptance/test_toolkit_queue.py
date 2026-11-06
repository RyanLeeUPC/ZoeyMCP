"""J4 with a connector: a toolkit's send held by the vault, approved with a passkey in the real
portal queue (M8 design B.7, H, O.5; the pre-main test-debt pass, D-73).

The shipped SMTP (implicit TLS) and mail toolkit profiles, with ``send_note`` in
``vault_approval`` and the portal as the approver, on the real vault and its portal as
``tests/portal/rig.py`` runs them; the real gateway serves the example mail toolkit on that
vault over TCP with the gateway key. The agent calls ``send_note`` and is never asked; the
vault holds the connector's send and the operator, in the portal over the fake browser and
authenticator, opens the hold, reads the message whole, and approves it with a passkey. Then
the message is sent once, exactly as shown, and the agent's call returns it sent.
"""

from __future__ import annotations

import email
import email.policy
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import anyio
import pytest
from mcp.types import CallToolResult, TextContent

from tests.fakes.agent import Never, Script, agent
from tests.fakes.approver import QueueApprover
from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.harness import serve
from tests.fakes.smtp_server import PASSWORD, SmtpFake, serve_smtp
from tests.gateway.rig import Running, WithAdmin, token_for
from tests.gateway.toolkit_rig import ENTRY_POINTS
from tests.portal.flows import set_up
from tests.portal.rig import PortalRig, running
from zoeymcp.common import ledgerformat
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import LEDGER_DIR, Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.toolkits import Toolkits
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client
from zoeymcp.vault.bindings import derive_binding

from .gateway import wait_healthy
from .tls import ProviderCA
from .toolkits import AGENT, merged

pytestmark = pytest.mark.anyio
BOUND = 30.0
SUBJECT = "Quarterly figures for review"
BODY = "The figures are attached.\n.A line starting with a dot.\nThanks."


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def fragment(smtp_port: int) -> dict[str, Any]:
    """The profiles as an operator pastes them, beside the portal rig's admin block: the mail
    server's address and the client's token swapped, ``send_note`` held by the vault, and the
    portal's queue its approver."""
    raw = merged("smtp-implicit-tls.yaml", "toolkit-mail.yaml")
    del raw["version"], raw["mode"]  # the rig's own
    raw["connectors"]["mail-out"].update(host="localhost", port=smtp_port)
    raw["gateway"]["clients"][AGENT].update(
        token_sha256=hash_token(token_for(AGENT)), sources=[], servers=["mail"]
    )
    raw["gateway"]["servers"]["mail"]["tools"]["vault_approval"] = ["send_note"]
    raw["approvers"] = {"portal": {}}
    return raw


@contextmanager
def gateway_on(rig: PortalRig, state: Path) -> Iterator[Running]:
    """The gateway serving the example toolkits on the rig's vault, over TCP with its key."""
    link = parse_link(f"http://127.0.0.1:{rig.proxy_port}")
    keys = KeySource(rig.vault.app._keys.gateway_key(1))
    marks = DriftMarks.load(state)
    pool = UpstreamPool(link, keys, marks, DefinitionStore(state))
    toolkits = Toolkits(link, keys, marks, entry_points=lambda: ENTRY_POINTS, allow_writable=True)
    app = GatewayApp(pool, view_client(link, keys), policy_wait=1, toolkits=toolkits)
    app.ledger, _ = Ledger.open_at(state, max_bytes=2**20)
    with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
        found = Running(app, url)
        wait_healthy(found)
        yield found


def waiting(approver: QueueApprover) -> dict[str, Any]:
    """The queue's one waiting row, once the hold is listed (bounded)."""
    deadline = time.monotonic() + BOUND
    while not (rows := approver.queue().waiting):
        assert time.monotonic() < deadline, "the hold never reached the queue"
        time.sleep(0.05)
    [row] = rows
    return row


def decided(approver: QueueApprover, approval: str) -> dict[str, Any]:
    """Decided recently's row for ``approval``, once its outcome is in (bounded)."""
    deadline = time.monotonic() + BOUND
    while True:
        rows = [r for r in approver.queue().decided if r["approval"] == approval]
        if rows and rows[0]["state"] == "done":
            return rows[0]
        assert time.monotonic() < deadline, "the hold never closed"
        time.sleep(0.05)


def text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


async def test_j4_a_connector_send_approved_with_a_passkey(tmp_path: Path, ca: ProviderCA) -> None:
    smtp = SmtpFake(ca)
    script, never = Script([]), Never()
    found: list[CallToolResult] = []
    with (
        serve_smtp(smtp, tmp_path) as (_, smtp_port),
        running(tmp_path, policy=fragment(smtp_port)) as rig,
    ):
        vault = rig.vault.app
        vault.connectors.tls = ca.client_context()  # the mail server's test CA
        secrets = rig.app.secrets
        assert secrets is not None
        binding = derive_binding(vault.policy, "mail-pass")
        rig.call(lambda: secrets.store.put("mail-pass", PASSWORD, binding))
        page = rig.browser().page(rig.origin)
        authenticator = SoftAuthenticator()
        await anyio.to_thread.run_sync(lambda: set_up(rig, page, authenticator))
        approver = QueueApprover(page, authenticator)
        with gateway_on(rig, tmp_path / "gateway") as gateway:
            async with agent(
                f"{gateway.url}/s/mail/mcp",
                script=script,
                headers={"authorization": f"Bearer {token_for(AGENT)}"},
                **never.options(),
            ) as client:

                async def call() -> None:
                    arguments = {"subject": SUBJECT, "body": BODY}
                    found.append(await client.call_tool("send_note", arguments))

                with anyio.fail_after(60):
                    async with anyio.create_task_group() as group:
                        group.start_soon(call)
                        row = await anyio.to_thread.run_sync(lambda: waiting(approver))
                        approval = row["approval"]
                        shown = await anyio.to_thread.run_sync(lambda: approver.show(approval))
                        assert smtp.sessions == []  # nothing sent before the approval
                        confirmed = await anyio.to_thread.run_sync(
                            lambda: approver.approve(approval)
                        )
            done = await anyio.to_thread.run_sync(lambda: decided(approver, approval))
    [result] = found
    assert not result.is_error, text(result)
    assert text(result).startswith("sent (<")
    assert (script.prompts, never.called) == ([], [])  # the vault asked, never the agent
    assert (row["how_shown"], row["server_shown"], row["tool_shown"], row["client_shown"]) == (
        "Held by the vault",
        "mail",
        "send_note",
        AGENT,
    )
    # The operator read the message whole: the vault's own plan of the send (B.7).
    lines = shown["text"].split("\n")
    assert f"Subject: {SUBJECT}" in lines
    assert 'To: ["partner@mail.example"]' in lines
    assert shown["text"].endswith(f"\n\n{BODY}\nEnd of approval request {row['ref']}")
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json() == {"approval": approval, "state": "approved"}
    assert done["outcome_shown"].startswith("approved here ")
    # Sent once, exactly as shown, over TLS before AUTH.
    [raw] = smtp.messages
    message = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert message["Subject"] == SUBJECT
    assert message.get_content().replace("\r\n", "\n") == BODY + "\n"
    assert [s.tls_at_auth for s in smtp.sessions] == [[True]]
    records = []
    for path in sorted((tmp_path / "gateway" / LEDGER_DIR).glob("*.jsonl")):
        records += [ledgerformat.parse(line) for line in path.read_bytes().splitlines()]
    assert [
        (r.kind, r.fields.get("where") or r.fields.get("decision") or r.fields.get("outcome"))
        for r in records
        if r.ref == row["ref"]
    ] == [
        ("asked", "vault"),
        ("decided", "approved_elsewhere"),
        ("outcome", "ok"),
    ]
