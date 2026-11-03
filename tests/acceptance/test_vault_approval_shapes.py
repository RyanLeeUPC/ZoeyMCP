"""Acceptance: S19, a vault-held MCP tool call, and S20's end-to-end row, the portal queue
approver (M8 design O.5; J2, J3, J4, J7; Z1-Z4, Z13, Z14, Z16; step 19).

Agent (the SDK client) -> gateway -> vault -> the fake MCP server, on S10's shipped profile with
``echo`` an ``approve`` tool the vault holds (``vault_approval``), client ``agent1`` attended and
``agent2`` out of band:

- S19 with S3 (J2), over both eras and both links: each client's call held, shown in the
  operator's Telegram chat (the vault's own surface against the fake Bot API, short timings) in
  the vault's frame, approved there, forwarded once with the key, the agent getting the
  upstream's answer; the message edited "Sending..." then the server's answer; the gateway's
  ledger and the vault's chain each with the call as its writer saw it;
- J3, over both eras and both links: both clients' calls held at once, then denied in Telegram,
  expired, or withdrawn by a policy change that re-pins the tool: nothing sent, each agent told
  why, each message edited to how it ended, and after a deny or an expiry the cooldown;
- B.2's refusals, over both links: what a compromised gateway might send on the held route in
  either client's name (a batch, a disguised or encoded body, routing or parameter headers, a
  method's case, a number with two spellings, a name variant, a declined or hidden-character
  name, an extra header, a query) refused with its rule's code, nobody asked, nothing sent;
- S20 (J4, J7), end to end: the real vault and portal (``tests/portal/rig.py``) with its queue
  and a scripted Telegram surface beside it, a real gateway on its proxy listener, the agent's
  calls answering ``pending``: approved with a passkey and collected, denied with a session, a
  stale decision refused, and Telegram deciding between the queue's prepare and its confirm;
  Telegram told how each call ended, and the sweep over both roles' logs and every answer.
  The queue's own refusals and pages are ``tests/portal/test_approvals_queue.py``'s.

S21 (``pending`` and ``check_approval``) is ``test_pending_shapes.py``; the Telegram surface's own
rows (forged presses, trouble, the token, enrolment) are ``test_telegram_approver.py``'s; a vault
or gateway that stops or restarts is ``test_held_crash.py``'s (Linux). Every test on S10's rig
ends with its sweep, and the bot's token reaches no log, answer or output (O.6).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import functools
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp.types import CallToolResult

from tests.fakes.approver import ApproverSwitch, QueueApprover
from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.harness import serve
from tests.fakes.mcp_server import McpFake
from tests.fakes.telegram import BotApi, Stored
from tests.gateway.holdrig import BOT_TOKEN, OPERATOR_ID, Surface, call, headers, marker
from tests.gateway.holdrig import Clock as HoldClock
from tests.gateway.rig import Running, WithAdmin, agent, pin_of_fake, token_for, until
from tests.portal.flows import set_up, status_reason
from tests.portal.rig import PortalRig
from tests.portal.rig import running as portal_running
from zoeymcp.common import ledgerformat
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway import checkapproval
from zoeymcp.gateway.app import GatewayApp
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.ledger import Ledger
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.upstream import UpstreamPool
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client
from zoeymcp.vault.app import GATEWAY_HEADER
from zoeymcp.vault.approvers import ApproverHub
from zoeymcp.vault.holds import Hold
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import origin_binding
from zoeymcp.vault.vaultledger import CHAIN_DIR, VaultLedger

from .gateway import SERVER, GatewayDeployment, wait_healthy
from .helpers import Seen
from .test_mcp_shapes import KEY, LINKS, declined_rest, deployed, pins, sweep, text
from .test_pending_shapes import ERAS, ledger
from .test_telegram_approver import TIMINGS, bot, edits, prompt
from .tls import ProviderCA

pytestmark = pytest.mark.anyio
BOUND = 60
TOOLS = {"echo": "approve", "add": "allow"}
HELD_PATH = "/notes/mcp"
# The two clients S19 asks for: attended, and out of band (Q39 (a)).
OWN = {
    "agent1": {"attended": True},
    "agent2": {"attended": False, "out_of_band": True},
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Approvers:
    """What the vault holds calls with, made anew for each vault process: its chain, its own
    Telegram surface on ``api`` (short timings) or, with no ``api``, a scripted portal surface
    that decides nothing, and the hold table's clock."""

    def __init__(self, api: BotApi | None) -> None:
        self.api = api
        self.portal = Surface("portal")
        self.clock = HoldClock()

    def __call__(self, state: Path, keys: KeySet) -> dict[str, Any]:
        found: dict[str, Any] = {
            "chain": VaultLedger.open_at(state, keys.chain_key),
            "hold_clock": self.clock,
        }
        if self.api is None:
            return {**found, "hub": ApproverHub([self.portal])}
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.api.app()))
        return {**found, "hub": ApproverHub([]), "telegram": TIMINGS, "approver_client": client}


def extra(*, telegram: bool = True) -> dict[str, Any]:
    """The policy beside S10's: the vault holds ``echo``; its approver is the Telegram bot (or,
    without ``telegram``, the portal queue, and the portal it is in); ``agent1`` attended,
    ``agent2`` out of band."""
    approvers: dict[str, Any] = {"portal": {}}
    found: dict[str, Any] = {
        "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}
    }
    if telegram:
        operator = {"user_id": OPERATOR_ID, "chat_id": OPERATOR_ID}
        approvers = {"telegram": {"bot_token": "store:approver-bot", **operator}}
        found = {}
    return {
        **found,
        "approvers": approvers,
        "gateway": {
            "clients": {name: {"approvals": own} for name, own in OWN.items()},
            "servers": {SERVER: {"tools": {"vault_approval": ["echo"]}}},
        },
    }


@contextlib.contextmanager
def held_deployment(
    tmp_path: Path,
    ca: ProviderCA,
    fake: McpFake,
    approvers: Approvers,
    *,
    link: str = "tcp",
) -> Iterator[GatewayDeployment]:
    options = {"extra": extra(telegram=approvers.api is not None), "held": approvers}
    with deployed(tmp_path, ca, fake, link=link, tools=TOOLS, **options) as gateway:
        if approvers.api is not None:
            binding = origin_binding(["https://api.telegram.org"])
            gateway.vault.store.put("approver-bot", BOT_TOKEN, binding)
        yield gateway
    if approvers.api is not None:
        assert BOT_TOKEN not in gateway.seen.everything()  # O.6


@contextlib.contextmanager
def surfaces_running(gateway: GatewayDeployment) -> Iterator[None]:
    """The vault's approvers started as ``serve()`` starts them, and stopped as its stop does:
    holds withdrawn, forwards drained, edits sent."""
    vault = gateway.vault
    vault.call(vault.app.start_approvers)
    try:
        yield
    finally:

        async def stop() -> None:
            vault.app.stop_holds()
            await vault.app.drain_holds()
            await vault.app.stop_approvers()

        vault.run(stop())


class Calling:
    """An agent's call made in the background, and its answer once it came."""

    def __init__(self) -> None:
        self.result: CallToolResult | None = None

    async def run(self, client: Any, name: str, arguments: dict[str, Any]) -> None:
        self.result = await client.call_tool(name, arguments)

    @property
    def text(self) -> str:
        assert self.result is not None, "the call never answered"
        return text(self.result)


def live(gateway: GatewayDeployment, ref: str) -> Hold:
    """The vault's hold of ``ref``, read on its own loop."""
    vault = gateway.vault
    found = vault.call(lambda: vault.app.holds.by_ref(ref))
    assert found is not None, ref
    return found


def chain(gateway: GatewayDeployment, ref: str) -> list[tuple[str, Any]]:
    """The vault chain's records for ``ref``: each kind, with its decision and surface, or its
    outcome."""
    found: list[ledgerformat.Record] = []
    for path in sorted((gateway.vault.state / CHAIN_DIR).glob("*.jsonl")):
        found.extend(ledgerformat.parse(line) for line in path.read_bytes().splitlines())
    return [
        (
            r.kind,
            (r.fields["decision"], r.fields["via"])
            if r.kind == "decided"
            else r.fields.get("outcome"),
        )
        for r in found
        if r.ref == ref
    ]


def edited(api: BotApi, count: int) -> bool:
    return len(edits(api)) >= count


def short(pin: str) -> str:
    """A pin as the vault's frame shows it (E.5): its first four and last two hex digits."""
    return f"{pin[:11]}\N{HORIZONTAL ELLIPSIS}{pin[-2:]}"


async def settled(gateway: GatewayDeployment) -> None:
    vault = gateway.vault
    await anyio.to_thread.run_sync(lambda: vault.run(vault.app.settle()))


# --- S19 with S3: held, shown in Telegram, approved, forwarded (J2) -----------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("era", sorted(ERAS))
async def test_s19_approved_in_telegram(
    tmp_path: Path, ca: ProviderCA, link: str, era: str
) -> None:
    agent_mode, fake_mode = ERAS[era]
    fake = McpFake(mode=fake_mode)
    api = bot()
    approvers = Approvers(api)
    shown: dict[str, tuple[Stored, Hold]] = {}
    answers: dict[str, Calling] = {}
    with (
        held_deployment(tmp_path, ca, fake, approvers, link=link) as gateway,
        gateway.running() as running,
        surfaces_running(gateway),
    ):
        with anyio.fail_after(BOUND):
            for number, client in enumerate(OWN, start=1):
                async with agent(running, client, mode=agent_mode) as session:
                    calling = answers[client] = Calling()
                    async with anyio.create_task_group() as group:
                        group.start_soon(calling.run, session, "echo", {"text": f"{client} ok"})
                        sent = await prompt(api)  # the last one's keyboard is gone
                        ref = sent.text.split("\n", 1)[0].removeprefix("Approval request ")
                        # As sent: the decision edits the message to its ending.
                        shown[client] = (dataclasses.replace(sent), live(gateway, ref))
                        held = [c for c in fake.calls if c.name == "echo"]
                        assert len(held) == number - 1  # nothing sent before the press
                        api.operator.press(sent.message_id, "Approve")
                await settled(gateway)
                await until(functools.partial(edited, api, 2 * number), BOUND)
            gateway.seen.outputs += [calling.text for calling in answers.values()]
    pin = pins(fake, ["echo"])["echo"]
    assert [call.arguments for call in fake.calls if call.name == "echo"] == [
        {"text": "agent1 ok"},
        {"text": "agent2 ok"},
    ]
    for client, (sent, hold) in shown.items():
        ref = hold.ref
        assert answers[client].text == f"{client} ok"
        # Z14: the vault's frame, as the operator's phone shows it (J2 step 3).
        assert sent.text == hold.text.value
        lines = sent.text.split("\n")
        assert lines[1:3] == [
            f"Client (reported by the gateway): {client}",
            f"Tool: {SERVER} \N{RIGHTWARDS ARROW} echo (pin {short(pin)}, from the vault's policy)",
        ]
        # The deadline's date shows when it falls on another UTC day than the asking.
        assert re.fullmatch(
            r"Answer by (?:\d{4}-\d\d-\d\d )?\d\d:\d\d UTC\. "
            r"Approve runs this one call, exactly as shown\.",
            lines[3],
        ), lines[3]
        assert lines[4:] == [
            "",
            "{",
            f'  "text": "{client} ok"',
            "}",
            f"End of approval request {ref}",
        ]
        assert (sent.single_pre, sent.previews_off, sent.protected) == (True, True, True)
        assert sent.labels() == ["Deny", "Approve"]
        # J2 step 4: "Sending...", then the server's answer, with no keyboard.
        first, last = [edit for edit in edits(api) if edit.startswith(f"Approval request {ref}:")]
        assert first.endswith("UTC in Telegram. Sending\N{HORIZONTAL ELLIPSIS}"), first
        assert last.endswith("UTC in Telegram. Sent: the server answered ok."), last
        assert api.stored(OPERATOR_ID, sent.message_id).reply_markup is None
        # Each writer's record of the one call (J.2): the gateway's, then the vault's.
        assert ledger(gateway, ref) == [
            ("asked", "vault"),
            ("decided", "approved_elsewhere"),
            ("outcome", "ok"),
        ]
        assert chain(gateway, ref) == [
            ("asked", None),
            ("decided", ("accept", "telegram")),
            ("outcome", "ok"),
        ]


# --- J3: denied, expired, withdrawn -------------------------------------------------------------


@pytest.mark.parametrize("ending", ["deny", "expire", "withdraw"])
@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("era", sorted(ERAS))
async def test_deny_expire_withdraw(
    tmp_path: Path, ca: ProviderCA, era: str, link: str, ending: str
) -> None:
    """J3, for an attended and an out-of-band client's call held at once: nothing goes
    upstream; each agent is told why, with its ref; each operator's message becomes one line
    saying how the call ended, with no keyboard; one ending each on the chain. A deny or an
    expiry starts the cooldown: each client's next call is refused at once, nobody asked."""
    agent_mode, fake_mode = ERAS[era]
    fake = McpFake(mode=fake_mode)
    api = bot()
    approvers = Approvers(api)
    answers = {client: Calling() for client in OWN}
    shown: dict[str, tuple[str, int]] = {}  # client -> its call's ref and its message
    later: dict[str, CallToolResult] = {}
    with (
        held_deployment(tmp_path, ca, fake, approvers, link=link) as gateway,
        gateway.running() as running,
        surfaces_running(gateway),
    ):
        with anyio.fail_after(BOUND):
            async with contextlib.AsyncExitStack() as stack:
                sessions = {
                    client: await stack.enter_async_context(agent(running, client, mode=agent_mode))
                    for client in OWN
                }
                async with anyio.create_task_group() as group:
                    for number, (client, session) in enumerate(sessions.items(), start=1):
                        arguments = {"text": f"not {client}'s"}
                        group.start_soon(answers[client].run, session, "echo", arguments)
                        sent = await prompt(api, number)
                        ref = sent.text.split("\n", 1)[0].removeprefix("Approval request ")
                        shown[client] = (ref, sent.message_id)
                    if ending == "deny":
                        for _, message_id in shown.values():
                            api.operator.press(message_id, "Deny")
                    elif ending == "expire":
                        approvers.clock.ahead += 3601  # past approvers.timeout, undecided
                        vault = gateway.vault
                        vault.call(vault.app.sweep_holds)
                    else:  # a save re-pins echo (B.5)
                        changed = {**pins(fake, sorted(TOOLS)), "echo": "sha256:" + "e" * 64}
                        gateway.reload(TOOLS, changed, declined_rest(fake, TOOLS))
                await settled(gateway)
                await until(functools.partial(edited, api, len(OWN)), BOUND)
                if ending != "withdraw":  # a re-pinned tool is refused for its pin instead
                    for client, session in sessions.items():
                        later[client] = await session.call_tool("echo", {"text": "again"})
        gateway.seen.outputs += [calling.text for calling in answers.values()]
        gateway.seen.outputs += [text(result) for result in later.values()]
    said, edit, decision = {
        "deny": ("refused: the operator declined this call", "denied ", ("decline", "telegram")),
        "expire": ("refused: no answer before the deadline", "expired ", ("timeout", "none")),
        "withdraw": (
            "refused: the policy changed; call the tool again",
            "withdrawn: the policy changed.",
            ("withdrawn", "none"),
        ),
    }[ending]
    assert len(edits(api)) == len(OWN)
    for client, (ref, message_id) in shown.items():
        assert answers[client].text == f"{said} (ref {ref})"
        [line] = [line for line in edits(api) if line.startswith(f"Approval request {ref}:")]
        assert line.startswith(f"Approval request {ref}: {edit}"), line
        assert line.endswith(" Nothing was sent."), line
        assert api.stored(OPERATOR_ID, message_id).reply_markup is None
        assert chain(gateway, ref)[1:] == [("decided", decision), ("outcome", "not_sent")]
    for client, result in later.items():  # J3: "a cooldown starts"
        assert "declined moments ago" in text(result), (client, text(result))
    assert len(api.operator.messages()) == len(OWN)  # the cooldown asked nobody
    assert fake.calls == []


# --- B.2: what the vault refuses to read, from either client (Z3, Z4) ----------------------------


def refusals(client: str) -> list[tuple[str, bytes, dict[str, str], str, int, str]]:
    """B.2's rows as a compromised gateway would send them on the held route, marked for
    ``client``: the case, the body, the headers, the path, and the status and code."""
    held = marker(f"{int(client[-1]):015x}f", client=client)
    plain = headers(held=held)
    body = call("echo", {"text": "hi"})
    number = (
        b'{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"text":1.50},'
        b'"name":"echo"}}'
    )
    return [
        ("batch", b"[" + body + b"]", plain, HELD_PATH, 400, "held_batch"),
        ("type", body, {**plain, "content-type": "text/plain"}, HELD_PATH, 415,
         "held_content_type"),
        ("encoded", body, headers(held=held, **{"content-encoding": "gzip"}), HELD_PATH, 400,
         "held_content_encoding"),
        ("mcp-name", body, headers(held=held, **{"mcp-name": "add"}), HELD_PATH, 400,
         "held_header_mismatch"),
        ("param", body, headers(held=held, **{"mcp-param-text": "hi"}), HELD_PATH, 400,
         "held_param_headers"),
        ("method", call("echo", {"text": "hi"}, method="Tools/call"), plain, HELD_PATH, 400,
         "held_method_case"),
        ("number", number, plain, HELD_PATH, 400, "held_number"),
        ("case", call("Echo", {"text": "hi"}), plain, HELD_PATH, 400, "held_name_variant"),
        ("full-width", call("\uff45cho", {"text": "hi"}), plain, HELD_PATH, 400,
         "held_name_variant"),
        ("declined", call("slow", {}), plain, HELD_PATH, 400, "held_unlisted"),
        ("zero-width", call("ec\u200bho", {"text": "hi"}), plain, HELD_PATH, 400,
         "held_unlisted"),
        ("extra", body, headers(held=held, **{"x-account": "other"}), HELD_PATH, 400,
         "held_header_extra"),
        ("query", body, plain, f"{HELD_PATH}?param=1", 400, "held_query"),
    ]  # fmt: skip


@pytest.mark.parametrize("link", LINKS)
async def test_s19_refusals(tmp_path: Path, ca: ProviderCA, link: str) -> None:
    """Z3, Z4: each of B.2's rows, in an attended and an out-of-band client's name, is refused
    by the vault with its rule's code, on the link the gateway uses: nobody is asked, nothing is
    written to the chain, and nothing reaches the upstream."""
    fake = McpFake()
    approvers = Approvers(None)
    seen: list[tuple[str, str, int, str]] = []
    with (
        held_deployment(tmp_path, ca, fake, approvers, link=link) as gateway,
        gateway.vault_running() as tcp,
    ):
        socket = gateway.vault.link_socket
        http, key = tcp, {GATEWAY_HEADER: gateway.vault.keys.gateway_key(1)}
        if socket is not None:  # the standard tier's link: known by its socket, with no key
            transport = httpx.HTTPTransport(uds=str(socket))
            http = httpx.Client(transport=transport, base_url="http://vault", timeout=BOUND)
            key = {}
        with contextlib.nullcontext() if http is tcp else http:
            for client in OWN:
                for case, body, sent, path, _, _ in refusals(client):
                    answer = http.post(path, content=body, headers={**sent, **key})
                    assert answer.headers.get("x-zoeymcp-vault") == "refused", (case, client)
                    seen.append((case, client, answer.status_code, answer.json()["code"]))
    expected = [
        (case, client, status, code)
        for client in OWN
        for case, _, _, _, status, code in refusals(client)
    ]
    assert seen == expected
    assert approvers.portal.shown == []
    assert fake.calls == []
    written = [path.read_bytes() for path in (gateway.vault.state / CHAIN_DIR).glob("*.jsonl")]
    assert b"".join(written) == b""


# --- S20: the portal queue approver, end to end (J4, J7) ----------------------------------------


def queue_policy(fake_url: str, fake: McpFake) -> dict[str, Any]:
    """The portal rig's policy beside its admin block: the fake MCP server on a local route,
    ``echo`` held by the vault, ``agent1`` attended, the portal queue with no block (each call
    answers pending), and a Telegram approver the test stands a scripted surface in for."""
    operator = {"user_id": OPERATOR_ID, "chat_id": OPERATOR_ID}
    return {
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "routes": [
            {
                "name": "notes-mcp",
                "prefix": "/notes",
                "upstream": fake_url,
                "allow_insecure_upstream": True,
                "stream": True,
                "credential": "notes-key",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
            }
        ],
        "approvers": {
            "portal": {},
            "telegram": {"bot_token": "store:approver-bot", **operator},
            "block_seconds": 0,
        },
        "gateway": {
            "clients": {
                "agent1": {
                    "token_sha256": hash_token(token_for("agent1")),
                    "servers": [SERVER],
                    "approvals": {"attended": True},
                }
            },
            "servers": {
                SERVER: {
                    "kind": "remote",
                    "route": "notes-mcp",
                    "path": "/mcp",
                    "tools": {
                        "include": ["echo"],
                        "approve": ["echo"],
                        "vault_approval": ["echo"],
                    },
                    "review": {"echo": pin_of_fake(fake, "echo")},
                }
            },
        },
    }


@contextlib.contextmanager
def gateway_on(rig: PortalRig, state: Path) -> Iterator[Running]:
    """A real gateway on the portal rig's vault, over its proxy listener with the gateway key,
    as the hardened tier runs one."""
    link = parse_link(f"http://127.0.0.1:{rig.proxy_port}")
    keys = KeySource(rig.vault.app._keys.gateway_key(1))
    limits = build_view(rig.vault.app.policy).gateway.limits
    pool = UpstreamPool(link, keys, DriftMarks.load(state), DefinitionStore(state), limits=limits)
    app = GatewayApp(pool, view_client(link, keys), policy_wait=1)
    app.ledger, _ = Ledger.open_at(state, max_bytes=limits.ledger_max_bytes)
    with serve(WithAdmin(app), lifespan=True, proxy_headers=False) as url:
        running = Running(app, url)
        wait_healthy(running)
        yield running


def ref_of(result: CallToolResult) -> str:
    said = text(result)
    assert said.startswith("pending "), said
    return said.split()[1].removesuffix(":")


async def test_queue(tmp_path: Path) -> None:
    """S20 (J4, J7): each call the vault holds is listed in the queue as held by the vault, and:
    approved with a passkey, it runs once and the agent collects its result; denied with a
    session, nothing is sent and the agent reads it was declined; a decision bound to a stale
    text decides nothing; and Telegram deciding between the queue's prepare and its confirm
    wins, the confirm told so, the call run once. Decided recently shows each outcome."""
    fake = McpFake()
    with serve(fake.app(), lifespan=True) as fake_url:
        policy = queue_policy(fake_url, fake)
        with portal_running(tmp_path, policy=policy) as rig:
            secrets = rig.app.secrets
            assert secrets is not None
            binding = origin_binding([fake_url])
            rig.call(lambda: secrets.store.put("notes-key", KEY, binding))
            hub = rig.vault.app.hub
            telegram = Surface("telegram")  # stands in for the bot: its presses are the test's
            rig.call(lambda: hub.install(telegram))
            page = rig.browser().page(rig.origin)
            authenticator = SoftAuthenticator()
            set_up(rig, page, authenticator)
            approver = QueueApprover(page, authenticator)

            pending: list[CallToolResult] = []
            portal: list[httpx.Response] = []

            async def held(session: Any, arguments: dict[str, Any]) -> str:
                pending.append(await session.call_tool("echo", arguments))
                return ref_of(pending[-1])

            def waiting(ref: str) -> dict[str, Any]:
                [row] = [row for row in approver.queue().waiting if row["ref"] == ref]
                return row

            def settle() -> None:
                asyncio.run_coroutine_threadsafe(rig.vault.app.settle(), rig.loop).result(BOUND)

            async def collected(session: Any, ref: str) -> str:
                await anyio.to_thread.run_sync(settle)
                result: CallToolResult = await session.call_tool(checkapproval.NAME, {"id": ref})
                return text(result)

            with gateway_on(rig, tmp_path / "gateway") as running, anyio.fail_after(BOUND):
                async with agent(running, server=SERVER) as session:
                    # J4: approved with a passkey.
                    approved = await held(session, {"text": "approved here"})
                    row = waiting(approved)
                    assert (row["how_shown"], row["tool_shown"], row["client_shown"]) == (
                        "Held by the vault",
                        "echo",
                        "agent1",
                    )
                    assert row["surfaces"] == ["portal", "telegram"]
                    confirmed = approver.approve(row["approval"])
                    assert confirmed.json() == {"approval": row["approval"], "state": "approved"}
                    first = await collected(session, approved)
                    # A stale decision, then Telegram first between the prepare and the confirm.
                    raced = await held(session, {"text": "raced"})
                    approval = waiting(raced)["approval"]
                    stale = QueueApprover(page, authenticator, {ApproverSwitch.STALE_DIGEST})
                    assert status_reason(stale.prepare(approval)) == (409, "digest_changed")
                    shown = approver.show(approval)
                    prepared = approver.prepare(approval)
                    assert prepared.status_code == 200, prepared.text
                    app, digest = rig.vault.app, shown["text_sha256"]
                    rig.call(lambda: app.decide(approval, "approve", "telegram", digest))
                    late = approver.confirm(prepared.json())
                    third = await collected(session, raced)
                    # J7: denied with a session (last: a decline starts the client's cooldown).
                    denied = await held(session, {"text": "denied here"})
                    refused = waiting(denied)["approval"]
                    said = approver.deny(refused)
                    assert said.status_code == 200
                    declined = await collected(session, denied)
                await until(lambda: len(approver.queue().decided) == 3, BOUND)
                decided = {row["approval"]: row for row in approver.queue().decided}
            portal += [confirmed, late, said]
            seen = Seen(rig.log, [first, third, declined, *map(text, pending)])
            seen.outputs += [answer.text for answer in portal]
            gateway_key = rig.vault.app._keys.gateway_key(1)
    assert first == "approved here"
    assert declined == f"{checkapproval.DECLINED} (ref {denied})"
    assert status_reason(late) == (409, "already_decided")
    assert late.json()["error"].startswith("Already decided in Telegram at ")
    assert third == "raced"
    assert [call.arguments for call in fake.calls if call.name == "echo"] == [
        {"text": "approved here"},
        {"text": "raced"},
    ]
    assert decided[row["approval"]]["outcome_shown"].startswith("approved here ")
    assert decided[row["approval"]]["outcome_shown"].endswith("sent: ok")
    assert decided[approval]["outcome_shown"].endswith("sent: ok")
    assert decided[refused]["outcome_shown"].startswith("denied here ")
    # J7: the other surface is told how each call the queue decided ended: approved (G.6's
    # "Sending..."), then sent; or denied.
    assert row["approval"] in [hold.id for hold in telegram.approvals]
    assert (row["approval"], "done") in telegram.closed
    assert (refused, "denied") in telegram.closed
    assert (approval, "done") in telegram.closed
    sweep(seen, clients=("agent1",), gateway_key=gateway_key, fake=fake)
