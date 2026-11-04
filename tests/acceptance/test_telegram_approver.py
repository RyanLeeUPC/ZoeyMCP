"""Acceptance: S3's Telegram approver, the vault's own surface against the fake Bot API (M8 design
G.1-G.7, O.5; J2 step 4, J3, J8, J15; FM-14, FM-15, FM-34, FM-37, FM-43; Z13, Z14, Z15, Z22;
step 14).

The vault holds calls as ``tests/gateway/holdrig.py`` runs it, on the test's own loop, with its
real :class:`~zoeymcp.vault.telegram.TelegramSurface` started as ``serve()`` starts it and short
timings (BP-10). The surface reaches the fake Bot API (``tests/fakes/telegram.py``) on an ASGI
transport, except in the Z22 test, where it reaches the fake over HTTPS through
:func:`~zoeymcp.vault.netclient.approver_client`: the address guard, the fake resolver and
certifi patched to the test CA, as ``procs.py``'s launcher does for a process. The portal queue,
where a test enables it, is a scripted surface.

- the message's shape (Z13, Z14): the composed text exactly, in one ``pre`` entity, previews off,
  content protected, Deny then Approve; the backlog skipped unread at start, and every poll for
  callback queries alone;
- the two-stage edit (G.6, J2 step 4) and the other endings (J3): approved and forwarded once,
  "Sending..." then the server's answer; denied, expired, withdrawn by a policy change, decided in
  the portal, each in one line with no keyboard; a late press, and one on a message from before a
  restart, told and their message edited;
- forged presses (FM-14, FM-37): from another account, or in another chat (no answer at all), on
  an edited message, with a swapped keyboard, a button of another hold: refused by reason, nothing
  decided; the operator's genuine press still is;
- trouble (FM-15, FM-43, J8): a 409 (contested, backed off), a foreign webhook (contested, never
  deleted), a 403 on send (the chat unreachable, the portal still decides), an outage
  (unreachable, then back), a 429 on an edit (every write waits ``retry_after``, edits first);
- a text Telegram can't carry (G.4): refused before anyone is asked with no portal; a notice and
  the portal with one; a text Telegram returned changed (deleted, refused, the portal's row
  too);
- the token (G.1, G.7, J15, FM-34): shared under a second name, as ``env:`` or through a route to
  the Bot API whose template names the bot's id (the surface never starts, health says so, and it
  starts once nothing shares it); rotated with ``secret set`` (the next poll uses it), or to a
  value another secret holds (every write stops until nothing shares it); hidden and shown again
  (the same surface runs again);
- B.5: the approver switched off, its message edited, the hold kept in the portal alone; switched
  on again, a press on the old message still reads how it ended;
- the enrolment and the probe (G.8, J1, FM-38; step 16), over the admin socket on the test's
  loop: J1 in its new order, a re-presented code (contested), a code presented only from another
  account (unconfirmed), the refusals, a re-enrolment pausing the running poller, and the probe.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import anyio
import certifi
import httpx
import pytest
from starlette.types import ASGIApp, Receive, Scope, Send

from tests.fakes.harness import serve
from tests.fakes.resolver import FakeResolver
from tests.fakes.telegram import FOREIGN_WEBHOOK, BotApi, Person, Stored, Switch, keyboard
from tests.gateway.holdrig import (
    BOT_TOKEN,
    EPOCH,
    OPERATOR_ID,
    HoldRig,
    call,
    headers,
    marker,
    policy,
)
from tests.gateway.holdrig import KEYS as VAULT_KEYS
from tests.gateway.rig import until
from zoeymcp.common import canonical
from zoeymcp.vault import logs, netclient, telegramwire
from zoeymcp.vault import telegram as telegram_approver
from zoeymcp.vault.admin import AdminApp, HealthReader, SetupCodes
from zoeymcp.vault.approvers import SurfaceName
from zoeymcp.vault.holds import DecideRefusal, Hold
from zoeymcp.vault.store import origin_binding
from zoeymcp.vault.telegram import ALLOWED_UPDATES as ALLOWED
from zoeymcp.vault.telegram import ENROL_UPDATES, PROBE, RESTARTED, SWITCHED_OFF, Timings

from .tls import ProviderCA, issue_cert

pytestmark = pytest.mark.anyio

BOUND = 30
SHOP = "/shop/mcp"
TIMINGS = Timings(
    send_spacing=0.05,
    contested_backoff=0.3,
    unreachable_after=0.6,
    backoff_max=0.2,
    poll_timeout=1,
)
# One second of a getUpdates timeout in the fake: a long poll lasts 50 ms here.
SECOND = 0.05
OPERATOR = Person(OPERATOR_ID, "Operator", "operator_example")
ATTACKER = Person(2002, "Operator", "operator_examp1e")
BOT_API = origin_binding(["https://api.telegram.org"])
NEW_TOKEN = "730041977:AAF-rotated-token-sentinel-77c0e4a1"
# A character outside the Basic Multilingual Plane: one code point, two UTF-16 code units, so a
# text within the budget (3,000 code points) is over Telegram's 4,096.
WIDE = "\U00020000"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


def bot(*switches: Switch, retry_after: int = 1) -> BotApi:
    """The fake Bot API for the rig's bot, the operator the rig's enrolled account; no flood
    control but what a switch opens (the surface spaces its writes itself)."""
    return BotApi(
        BOT_TOKEN,
        switches=set(switches),
        second=SECOND,
        flood_interval=None,
        retry_after=retry_after,
        operator_account=OPERATOR,
        attacker_account=ATTACKER,
    )


class Timed:
    """The fake's app, with when each Bot API call arrived and its method."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app
        self.at: list[tuple[float, str]] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            self.at.append((time.monotonic(), str(scope["path"]).rsplit("/", 1)[-1]))
        await self.app(scope, receive, send)


@asynccontextmanager
async def vault(
    tmp_path: Path,
    api: BotApi,
    *,
    surfaces: tuple[SurfaceName, ...] = ("telegram",),
    client: httpx.AsyncClient | None = None,
    environ: dict[str, str] | None = None,
    **options: Any,
) -> AsyncIterator[tuple[HoldRig, httpx.AsyncClient]]:
    """The hold rig with its own Telegram surface on ``api``, started as ``serve()`` starts it,
    and stopped as its stop does: holds withdrawn, forwards drained, edits sent."""
    if client is None:
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=api.app()))
    rig = HoldRig(
        tmp_path,
        {"block_seconds": 0, **options},
        link="asgi",
        surfaces=surfaces,
        telegram=TIMINGS,
        approver_client=client,
        environ=environ,
    )
    async with rig.running() as http:
        rig.app.start_approvers()
        try:
            yield rig, http
        finally:
            rig.app.stop_holds()
            await rig.app.drain_holds()
            await rig.app.stop_approvers()


async def held(
    rig: HoldRig,
    http: httpx.AsyncClient,
    ref: str,
    *,
    client: str = "agent1",
    tool: str = "place_order",
    **arguments: Any,
) -> httpx.Response:
    """A held call marked ``wait=pending``: with no block it answers pending at once, and the
    hold waits for its decision. One undecided hold per client and tool (D.3's fairness)."""
    body = call(tool, arguments=arguments or None)
    sent = headers(held=marker(ref, client=client, wait="pending"))
    return await http.post(SHOP, content=body, headers=sent)


# Four keys a test may hold at once: each client, each held tool.
KEYS = [
    {"client": client, "tool": tool}
    for tool in ("place_order", "cancel_order")
    for client in ("agent1", "agent2")
]
BOTH_HELD = ("place_order", "cancel_order")


def live(rig: HoldRig, ref: str) -> Hold:
    found = rig.app.holds.by_ref(ref)
    assert found is not None, ref
    return found


async def prompt(api: BotApi, count: int = 1) -> Stored:
    """The ``count``-th prompt in the operator's chat, once it is there."""
    await until(lambda: len(api.operator.prompts()) >= count, BOUND)
    return api.operator.prompts()[count - 1]


def edits(api: BotApi, *, taken: bool = True) -> list[str]:
    """Every text the bot edited a message to, in order: those Telegram took, or every try."""
    return [
        str(c.params["text"])
        for c in api.calls
        if c.method == "editMessageText" and (c.status == 200 or not taken)
    ]


def answered(api: BotApi) -> list[str | None]:
    return [answer.text for answer in api.answers]


# --- the message (Z13, Z14) ----------------------------------------------------------------------


async def test_message_shape(tmp_path: Path) -> None:
    """G.3, G.4: the backlog skipped unread at start; then the composed text exactly, one
    ``pre`` entity over all of it, no parse mode, previews off, content protected, and two
    buttons, Deny first, each 38 bytes; every poll asks for callback queries alone."""
    api = bot()
    stale = api.push("callback_query", {"id": "1", "from": OPERATOR.user(), "data": "x"})
    assert stale is not None
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            await until(lambda: len(api.polls) >= 3, BOUND)
            response = await held(rig, http, "00000000000000a1")
            assert response.json()["code"] == "approval_pending"
            sent = await prompt(api)
            hold = live(rig, "00000000000000a1")
            # As sent: the stop edits the message to its ending.
            assert sent.text == hold.text.value
            assert sent.labels() == ["Deny", "Approve"]
            assert all(len(sent.data_for(label).encode()) == 38 for label in ("Deny", "Approve"))
    assert (sent.single_pre, sent.previews_off, sent.protected) == (True, True, True)
    [send] = [c for c in api.calls if c.method == "sendMessage"]
    assert "parse_mode" not in send.params
    assert [c.method for c in api.calls[:3]] == ["getWebhookInfo", "getMe", "getUpdates"]
    first, skip, *polls = api.polls
    assert (first.offset, first.timeout) == (-1, 0)
    assert first.returned == [stale.update_id]  # dropped unread, confirmed by the next poll
    assert skip.offset == stale.update_id + 1
    for poll in (first, skip, *polls):
        assert poll.allowed_updates == ["callback_query"]
    assert api.answers == []  # the backlog's press was never read
    assert rig.upstream.received == []


class Gated:
    """The fake's app with ``getMe`` held until :attr:`opened` is set: the poller's start
    sequence waits there, after ``getWebhookInfo``. The first ``fail`` calls to ``getMe`` answer
    502 at once instead (a Bot API not reachable yet), so the start fails and runs again."""

    def __init__(self, app: ASGIApp, *, fail: int = 0) -> None:
        self.app = app
        self.fail = fail
        self.reached = anyio.Event()
        self.opened = anyio.Event()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and str(scope["path"]).endswith("/getMe"):
            if self.fail:
                self.fail -= 1
                body = b'{"ok": false, "error_code": 502, "description": "Bad Gateway"}'
                headers = [(b"content-type", b"application/json")]
                await send({"type": "http.response.start", "status": 502, "headers": headers})
                await send({"type": "http.response.body", "body": body})
                return
            self.reached.set()
            await self.opened.wait()
        await self.app(scope, receive, send)


@pytest.mark.parametrize("fail", [0, 1], ids=["first_start", "after_a_failed_start"])
async def test_the_first_send_waits_for_the_backlog_skip(tmp_path: Path, fail: int) -> None:
    """G.3, Z10 (step 14's open minor, M8 step 17): a prompt shown while the poller's start
    sequence still runs isn't sent until that start has skipped the backlog, so the operator's
    press on it can never be in the backlog ``getUpdates(offset=-1)`` drops unread; the press
    then decides the hold. A start that failed (``getMe`` refused once) releases nothing: the
    prompt waits for the start that runs again and succeeds."""
    api = bot()
    gated = Gated(api.app(), fail=fail)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=gated))
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, client=client) as (rig, http):
            surface = rig.app.telegram
            assert surface is not None
            await gated.reached.wait()
            async with anyio.create_task_group() as group:
                group.start_soon(held, rig, http, "00000000000000f1")
                await until(lambda: surface._prompts, BOUND)  # its show queued the send
                await anyio.wait_all_tasks_blocked()  # and the writer had every chance
                before = [c.method for c in api.calls]
                gated.opened.set()
            sent = await prompt(api)
            api.operator.press(sent.message_id, "Approve")
            await until(lambda: len(rig.upstream.posts()) == 1, BOUND)
            await rig.settled()
    # The prompt waited, though its show had queued it (a refused getMe never reaches the fake).
    assert before == ["getWebhookInfo"] * (fail + 1)
    skip = next(
        i
        for i, c in enumerate(api.calls)
        if c.method == "getUpdates" and c.params.get("offset") == -1
    )
    assert [c.method for c in api.calls].index("sendMessage") > skip
    assert answered(api) == ["Approved"]
    assert rig.kinds("00000000000000f1")[1:] == [("decided", "accept"), ("outcome", "ok")]


async def test_the_two_stage_edit(tmp_path: Path) -> None:
    """G.6, J2 step 4: approved in Telegram, the message says so and "Sending..." once its
    decided record is on disk, then the server's answer, with no keyboard; the call is forwarded
    once, and a later press on it is no longer pending, its message edited to how it ended."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            await held(rig, http, "00000000000000b1")
            sent = await prompt(api)
            data = sent.data_for("Approve")
            api.operator.press(sent.message_id, "Approve")
            await until(lambda: len(edits(api)) >= 2, BOUND)
            await rig.settled()
            api.press(sent.message_id, data=data, by=OPERATOR)  # its button gone, its data kept
            await until(lambda: len(edits(api, taken=False)) >= 3, BOUND)
    first, last = edits(api)
    head = "Approval request 00000000000000b1: approved "
    assert re.fullmatch(re.escape(head) + r"\d\d:\d\d UTC in Telegram\. Sending\u2026", first), (
        first
    )
    assert re.fullmatch(
        re.escape(head) + r"\d\d:\d\d UTC in Telegram\. Sent: the server answered ok\.", last
    ), last
    assert answered(api) == ["Approved", telegramwire.NOT_PENDING]
    assert edits(api, taken=False)[2] == last  # the late press's message: how the hold ended
    assert api.stored(OPERATOR.id, sent.message_id).reply_markup is None
    assert len(rig.upstream.posts()) == 1
    assert rig.kinds("00000000000000b1")[1:] == [("decided", "accept"), ("outcome", "ok")]


async def test_deny_expire_and_the_portal(tmp_path: Path) -> None:
    """J3, D.4: denied here, denied in the portal, expired: each message becomes one line with
    no keyboard, and nothing is sent."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal"), held=BOTH_HELD) as (
            rig,
            http,
        ):
            for number, key in enumerate(KEYS, start=1):
                await held(rig, http, f"00000000000000c{number}", **key)
            await prompt(api, 4)
            prompts = api.operator.prompts()
            api.operator.press(prompts[0].message_id, "Deny")
            await until(lambda: len(edits(api)) >= 1, BOUND)
            await rig.decide(live(rig, "00000000000000c4"), "deny", via="portal")
            await until(lambda: len(edits(api)) >= 2, BOUND)
            await rig.later(3601)  # c2 and c3 pass their deadline, undecided
            await until(lambda: len(edits(api)) >= 4, BOUND)
            await rig.settled()
    texts = edits(api)
    time_ = r"\d\d:\d\d UTC"
    assert re.fullmatch(
        rf"Approval request 00000000000000c1: denied {time_} in Telegram\. Nothing was sent\.",
        texts[0],
    ), texts[0]
    assert re.fullmatch(
        rf"Approval request 00000000000000c4: denied {time_} in the portal\. Nothing was sent\.",
        texts[1],
    ), texts[1]
    expired = sorted(texts[2:])
    for number, text in zip((2, 3), expired, strict=True):
        pattern = rf"Approval request 00000000000000c{number}: expired {time_}\. Nothing was sent\."
        assert re.fullmatch(pattern, text), text
    for sent in prompts:
        assert api.stored(OPERATOR.id, sent.message_id).reply_markup is None
    assert rig.upstream.received == []


async def test_a_policy_change_withdraws_and_edits(tmp_path: Path) -> None:
    """J3's last row (B.5, Z7): the tool leaves ``vault_approval``: withdrawn, the message says
    why; a press on it afterwards is no longer pending."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            await held(rig, http, "00000000000000d1")
            sent = await prompt(api)
            data = sent.data_for("Approve")
            await rig.reload(held=())
            await until(lambda: len(edits(api)) >= 1, BOUND)
            api.press(sent.message_id, data=data, by=OPERATOR)
            await until(lambda: len(api.answers) >= 1, BOUND)
            await rig.settled()
    assert edits(api)[0] == (
        "Approval request 00000000000000d1: withdrawn: the policy changed. Nothing was sent."
    )
    assert answered(api) == [telegramwire.NOT_PENDING]
    assert rig.upstream.received == []


async def test_a_press_from_before_a_restart_is_told_so(tmp_path: Path) -> None:
    """G.6, MISS-4: a button this process never sent (another key, a hold it doesn't know)
    names nothing here: "no longer pending", and its message says the vault restarted."""
    api = bot()
    buttons = telegramwire.keyboard(telegramwire.new_key(), "AbCdEfGh_-012345", "0" * 64)
    old = api._send_message(  # a prompt an earlier process sent, its hold gone with it
        {
            "chat_id": OPERATOR.id,
            "text": "Approval request 00000000000000e0\nEnd of approval request 00000000000000e0",
            "reply_markup": json.dumps(keyboard(*buttons)),
        },
        limited=False,
    )
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            await held(rig, http, "00000000000000e1")  # the vault's loop is known from here
            await until(lambda: len(api.polls) >= 2, BOUND)
            api.operator.press(int(old["message_id"]), "Approve")
            await until(lambda: RESTARTED in edits(api), BOUND)
    assert answered(api) == [telegramwire.NOT_PENDING]
    assert rig.upstream.received == []


# --- forged presses (FM-14, FM-37; Z13) ----------------------------------------------------------


async def test_forged_presses(tmp_path: Path, log: io.StringIO) -> None:
    """G.5: a stranger's press (another account in the operator's chat, a copy of the prompt in
    its own) gets no answer at all; a press with the keyboard swapped (no ``edit_date``), with
    another hold's button, or on an edited message is refused by reason; nothing is decided, and
    the operator's own press on a message as sent still is. The keyboard swap is undated here
    (``MARKUP_EDIT_UNDATED``), so its refusal is the keyboard's own: Telegram dates it (D-255),
    which the vault refuses as ``edited``."""
    api = bot(Switch.MARKUP_EDIT_UNDATED)
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, held=BOTH_HELD) as (rig, http):
            await held(rig, http, "00000000000000f1", **KEYS[0])
            await held(rig, http, "00000000000000f2", **KEYS[1], item="toaster")
            first, second = await prompt(api, 1), await prompt(api, 2)
            attacker = api.attacker
            attacker.press(first.message_id, "Approve")  # 1: another user, the operator's chat
            copied = attacker.copy(first.message_id)
            attacker.press(copied.message_id, "Approve", own_chat=True)  # 1: and its own chat
            # 6b: the labels swapped, with no edit_date (FM-37); Approve now carries Deny's data.
            swapped = [("Approve", first.data_for("Deny")), ("Deny", first.data_for("Approve"))]
            attacker.edit_markup(first.message_id, keyboard(*swapped))
            api.operator.press(first.message_id, "Approve")
            # 4: the second prompt's button, pressed on the first's message.
            api.press(first.message_id, data=second.data_for("Approve"), by=OPERATOR)
            # 5: the second prompt's text rewritten (edit_date set).
            attacker.edit_text(second.message_id, second.text.replace("toaster", "kettle!"))
            api.operator.press(second.message_id, "Approve")
            await until(lambda: len(events(log, "approver_press_refused")) >= 5, BOUND)
            assert live(rig, "00000000000000f1").state == "held"
            assert live(rig, "00000000000000f2").state == "held"
            await held(rig, http, "00000000000000f3", **KEYS[2])
            third = await prompt(api, 3)
            api.operator.press(third.message_id, "Deny")
            await until(lambda: rig.app.holds.by_ref("00000000000000f3") is None, BOUND)
            await rig.settled()
    reasons = [e["reason"] for e in events(log, "approver_press_refused")]
    assert reasons == ["wrong_user", "wrong_user", "markup_changed", "wrong_message", "edited"]
    refused = telegramwire.REFUSED
    assert answered(api) == [refused, refused, refused, "Denied"]  # strangers get nothing
    for line in events(log, "approver_press_refused"):
        assert set(line) == {"ts", "role", "event", "reason", "level"}
    assert rig.kinds("00000000000000f3")[1:] == [("decided", "decline"), ("outcome", "not_sent")]
    assert rig.upstream.received == []


# --- trouble (FM-15, FM-43, J8) ------------------------------------------------------------------


async def test_outage_and_409(tmp_path: Path, log: io.StringIO) -> None:
    """G.3, J8: another consumer's 409 is contested and backed off, never fought; a 403 on send
    makes the chat unreachable, and the portal still decides; an outage makes the approver
    unreachable, health says so, and it recovers once Telegram answers again."""
    api = bot(Switch.CONFLICT)
    timed = Timed(api.app())
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=timed))
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal"), client=client) as (
            rig,
            http,
        ):
            surface = rig.app.telegram
            assert surface is not None
            await until(lambda: surface.state().contested, BOUND)
            await until(lambda: [m for _, m in timed.at].count("getWebhookInfo") >= 2, BOUND)
            api.switches = {Switch.FORBIDDEN_SEND}
            await until(lambda: not surface.state().contested, BOUND)
            await held(rig, http, "0000000000000101")
            await until(lambda: surface.state().chat_unreachable, BOUND)
            hold = live(rig, "0000000000000101")
            assert not surface.delivered(hold.id)  # the queue's "not delivered to Telegram"
            await rig.decide(hold, via="portal")
            await rig.settled()
            api.switches = {Switch.OUTAGE}
            await until(lambda: surface.state().unreachable, BOUND)
            health = HealthReader(
                rig.store,
                lambda: rig.app.policy,
                chain=rig.chain,
                waiting=rig.app.waiting,
                telegram=rig.app.approver_state,
            ).report()
            codes = [f["code"] for f in health["approvals"]["findings"]]
            assert codes == ["approver_unreachable", "approver_chat_unreachable"]
            # The policy enables the portal queue, so the finding says it still decides.
            unreachable = health["approvals"]["findings"][0]["text"]
            assert unreachable.endswith("held calls are still decided in the portal, or expire")
            api.switches = set()
            await until(lambda: not surface.state().unreachable, BOUND)
    # Backed off: each refused poll waits the contested backoff before the start runs again.
    refused = [i for i, c in enumerate(api.calls) if c.method == "getUpdates" and c.status == 409]
    assert refused
    gap = timed.at[refused[0] + 1][0] - timed.at[refused[0]][0]
    assert gap >= TIMINGS.contested_backoff * 0.9
    assert [e["reason"] for e in events(log, "approver_contested")] == ["refused"]
    assert {e["status"] for e in events(log, "approver_poll_failed")} == {502}
    assert [e["status"] for e in events(log, "approver_send_failed")] == [403]
    assert not any(c.method == "deleteWebhook" for c in api.calls)
    assert len(rig.upstream.posts()) == 1


async def test_a_foreign_webhook_is_contested_and_left(tmp_path: Path, log: io.StringIO) -> None:
    """G.3: a webhook the vault didn't set is contested at start; the vault never deletes it,
    and polls only once it is gone."""
    api = bot(Switch.FOREIGN_WEBHOOK)
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, _):
            surface = rig.app.telegram
            assert surface is not None
            await until(lambda: surface.state().contested, BOUND)
            assert {c.method for c in api.calls} == {"getWebhookInfo"}
            api.switches = set()
            await until(lambda: surface.state().last_poll_ago is not None, BOUND)
    assert not any(c.method in ("deleteWebhook", "setWebhook") for c in api.calls)
    assert [e["reason"] for e in events(log, "approver_contested")] == ["webhook"]
    assert FOREIGN_WEBHOOK not in log.getvalue()


async def test_a_429_on_an_edit_holds_every_write(tmp_path: Path) -> None:
    """FM-43: flood control is per chat across the writing methods, so a 429 on an edit holds
    every write to the chat for its ``retry_after``: the next write comes that long after, and
    it is the same edit again (edits first), before the prompts queued behind it."""
    api = bot(Switch.RATE_LIMITED_EDIT, retry_after=1)
    timed = Timed(api.app())
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=timed))
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, held=BOTH_HELD, client=client) as (rig, http):
            await held(rig, http, "0000000000000201")
            sent = await prompt(api)
            api.operator.press(sent.message_id, "Approve")
            await until(lambda: any(c.status == 429 for c in api.calls), BOUND)
            await held(rig, http, "0000000000000202", **KEYS[1])
            await held(rig, http, "0000000000000203", **KEYS[2])
            await until(lambda: len(api.sent()) >= 3, BOUND)  # the first's keyboard is gone
            await until(lambda: len(edits(api)) >= 2, BOUND)
            surface = rig.app.telegram
            assert surface is not None
            assert surface.state().rate_limited
    at = [moment for moment, method in timed.at if method in ("sendMessage", "editMessageText")]
    writes = [c for c in api.calls if c.method in ("sendMessage", "editMessageText")]
    assert len(at) == len(writes)
    limited = next(i for i, c in enumerate(writes) if c.status == 429)
    taken = next(i for i, c in enumerate(writes) if i > limited and c.status == 200)
    # Until it is taken, only that edit is tried again (a clock's tick may refuse one more),
    # each try a retry_after after the last.
    for index in range(limited, taken + 1):
        assert writes[index].method == "editMessageText"
        assert writes[index].params["text"] == writes[limited].params["text"]
    for index in range(limited + 1, taken + 1):
        assert at[index] - at[index - 1] >= 0.9
    after = writes[taken + 1 :]
    assert all(c.status == 200 for c in after)
    sends = [i for i, c in enumerate(after) if c.method == "sendMessage"]
    assert len(sends) == 2
    assert all(c.method == "editMessageText" for c in after[: sends[0]])


# --- a text Telegram can't carry (G.4) -----------------------------------------------------------


async def test_a_text_telegram_cant_carry(tmp_path: Path) -> None:
    """G.4: with Telegram alone, refused 422 ``telegram_too_long`` before anyone is asked: no
    record, no prompt, the ref unused."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            refused = await held(rig, http, "0000000000000301", item=WIDE * 2100)
            assert (refused.status_code, refused.json()["code"]) == (422, "telegram_too_long")
            assert rig.kinds("0000000000000301") == []
            assert api.sent() == []
            again = await held(rig, http, "0000000000000301")
            assert again.json()["code"] == "approval_pending"  # the ref was never used
            await prompt(api)
    assert [kind for kind, _ in rig.kinds("0000000000000301")].count("asked") == 1


async def test_a_relayed_text_telegram_cant_carry_is_refused(tmp_path: Path) -> None:
    """G.4 for a relay (E.4): the vault's own relay line above the gateway's text, too long for
    Telegram with no portal, is refused 422 before the hold begins; the ref stays unused."""
    api = bot()

    async def ask(http: httpx.AsyncClient, ref: str, body: str) -> httpx.Response:
        text = f"Approval request {ref}\n{body}\nEnd of approval request {ref}"
        sent = {
            "v": 1,
            "epoch": EPOCH,
            "ref": ref,
            "client": "agent1",
            "server": "shop",
            "tool": "cancel_order",
            "text": text,
            "text_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "deadline_ms": 1_900_000_000_000,
            "wait": "pending",
        }
        return await http.post(
            "/_zoeymcp/gateway/v1/approvals/ask",
            content=canonical.dumps_canonical(sent),
            headers={"content-type": "application/json"},
        )

    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, out_of_band=True) as (rig, http):
            refused = await ask(http, "0000000000000351", WIDE * 2100)
            assert (refused.status_code, refused.json()["code"]) == (422, "telegram_too_long")
            assert rig.kinds("0000000000000351") == []
            taken = await ask(http, "0000000000000351", "a short one")
            assert taken.status_code == 201, taken.text
            await prompt(api)


async def test_a_text_too_long_for_telegram_goes_to_the_portal(tmp_path: Path) -> None:
    """G.4, D.4: with the portal too, Telegram gets a notice with no buttons pointing there,
    the portal decides, and the notice is edited as a prompt would be."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal")) as (rig, http):
            await held(rig, http, "0000000000000302", item=WIDE * 2100)
            await until(lambda: len(api.operator.messages()) >= 1, BOUND)
            [notice] = api.operator.messages()
            text, markup = notice.text, notice.reply_markup
            [hold] = await rig.surfaces["portal"].holds(1)
            await rig.decide(hold, via="portal")
            await until(lambda: len(edits(api)) >= 2, BOUND)
            await rig.settled()
    assert text == (
        "Approval request 0000000000000302: shop \N{RIGHTWARDS ARROW} place_order. This one is "
        "too long for this chat; decide it in the portal."
    )
    assert markup is None
    assert edits(api)[-1].endswith(" UTC in the portal. Sent: the server answered ok.")


async def test_a_text_returned_changed_is_deleted_and_refused(tmp_path: Path) -> None:
    """G.4: Telegram returned another text than the one sent, so the operator would read
    something else: the message is deleted and the hold refused 502."""
    api = bot(Switch.TEXT_CHANGED)
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            response = await held(rig, http, "0000000000000401")
            await until(lambda: all(sent.deleted for sent in api.sent()), BOUND)
            await rig.settled()
    assert (response.status_code, response.json()["code"]) == (502, "telegram_text_changed")
    assert len(api.sent()) == 1
    assert rig.kinds("0000000000000401")[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    assert rig.upstream.received == []


async def test_a_text_returned_changed_is_refused_with_the_portal_too(tmp_path: Path) -> None:
    """G.4 with the portal queue enabled: the portal showing the hold doesn't keep it waiting; a
    text Telegram returned changed refuses it all the same, and the portal's row closes."""
    api = bot(Switch.TEXT_CHANGED)
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal")) as (rig, http):
            response = await held(rig, http, "0000000000000402")
            await until(lambda: all(sent.deleted for sent in api.sent()), BOUND)
            await rig.settled()
            portal = rig.surfaces["portal"]
            assert [hold.ref for hold in portal.shown] == ["0000000000000402"]
            assert [outcome for _, outcome in portal.closed] == ["withdrawn"]
    assert (response.status_code, response.json()["code"]) == (502, "telegram_text_changed")
    assert rig.kinds("0000000000000402")[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    assert rig.upstream.received == []


# --- the token (G.1, G.7, J15; FM-34) -----------------------------------------------------------


async def test_shared_token_refused(tmp_path: Path, log: io.StringIO) -> None:
    """FM-34, T-5: the bot's token under a second name: at install the surface isn't started
    and shows nothing, health says why, and the portal still shows the hold; once nothing
    shares the token, the next install starts it."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("portal",)) as (rig, http):
            await held(rig, http, "0000000000000501")
            rig.store.put("copy", BOT_TOKEN, BOT_API)
            await rig.reload(surfaces=("portal", "telegram"))
            surface = rig.app.telegram
            assert surface is not None
            assert not surface.running
            assert "telegram" not in rig.app.hub.names
            assert surface.state().token_shared
            assert live(rig, "0000000000000501").surfaces == frozenset({"portal"})
            assert api.calls == []
            rig.store.delete("copy")
            await rig.reload(surfaces=("portal", "telegram"), cooldown=16)
            assert surface.running
            assert "telegram" in rig.app.hub.names
            await until(lambda: len(api.polls) >= 1, BOUND)
    assert len(events(log, "approver_token_shared")) == 1


async def test_a_token_of_the_same_bot_in_the_environment_is_refused(tmp_path: Path) -> None:
    """FM-34's ``env:`` row: an ``env:`` secret the policy reads holding a token of the same bot
    (its id before the ``:``) refuses the surface at install."""
    api = bot()
    other = "730041977:AAF-same-bot-another-secret-91d3"
    with anyio.fail_after(BOUND):
        async with vault(
            tmp_path, api, environ={"SHOP_KEY": other}, shop_secret="env:SHOP_KEY"
        ) as (rig, _):
            surface = rig.app.telegram
            assert surface is not None
            assert surface.state().token_shared
            assert not surface.running
    assert api.calls == []


BOT_ID, SECRET_HALF = BOT_TOKEN.split(":")


@pytest.mark.parametrize("stored", [False, True], ids=["template_alone", "secret_half_stored"])
async def test_a_route_to_the_bot_api_carrying_the_bot_id_is_refused(
    tmp_path: Path, stored: bool
) -> None:
    """G.7's route clause (T-5): a route to ``api.telegram.org`` whose path template names the
    approver bot's id, its secret the token's secret half under another name or not stored at
    all, reaches the same bot: the surface doesn't start."""
    api = bot()
    route = {"kind": "path", "template": f"/bot{BOT_ID}:{{secret}}", "secret": "store:bot-key"}
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("portal",)) as (rig, http):
            await held(rig, http, "0000000000000531")  # the vault's loop is known from here
            if stored:
                rig.store.put("bot-key", SECRET_HALF, BOT_API)
            await rig.reload(surfaces=("portal", "telegram"), bot_route=route)
            surface = rig.app.telegram
            assert surface is not None
            assert surface.state().token_shared
            assert not surface.running
            assert "telegram" not in rig.app.hub.names
            # The same route with a template of another bot shares nothing.
            other = {**route, "template": "/bot1234:{secret}"}
            if stored:
                rig.store.delete("bot-key")
            await rig.reload(surfaces=("portal", "telegram"), bot_route=other, cooldown=16)
            assert surface.running
            await until(lambda: len(api.polls) >= 1, BOUND)


async def test_a_token_rotated_to_a_shared_value_stops_every_write(tmp_path: Path) -> None:
    """T-5 at run time: ``secret set`` gives the approver a token another secret holds. The
    poller sees it at its next cycle and stops; a hold shown meanwhile waits unsent (not
    delivered, health says why), and once nothing shares the token the next install lets its
    prompt go."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal")) as (rig, http):
            await until(lambda: len(api.polls) >= 2, BOUND)
            surface = rig.app.telegram
            assert surface is not None
            rig.store.put("copy", NEW_TOKEN, BOT_API)
            api.token = NEW_TOKEN
            rig.store.put("approver-bot", NEW_TOKEN, BOT_API)
            await until(lambda: surface.state().token_shared, BOUND)
            response = await held(rig, http, "0000000000000511")
            assert response.json()["code"] == "approval_pending"
            hold = live(rig, "0000000000000511")
            await anyio.sleep(10 * TIMINGS.send_spacing)  # an open queue would have sent it
            assert not any(c.method == "sendMessage" for c in api.calls)
            assert not surface.delivered(hold.id)
            assert "telegram" in rig.app.hub.names  # shown on, so the next install decides
            rig.store.delete("copy")
            await rig.reload(surfaces=("telegram", "portal"), cooldown=16)
            assert not surface.state().token_shared
            sent = await prompt(api)
            assert sent.text == hold.text.value
            await until(lambda: surface.delivered(hold.id), BOUND)


async def test_a_token_shared_then_not_restarts_the_same_surface(tmp_path: Path) -> None:
    """A surface hidden at one install (its token shared) and shown again at the next, before
    its stop has ended: it polls and writes again, and a new hold's prompt goes."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, http):
            await until(lambda: len(api.polls) >= 2, BOUND)
            surface = rig.app.telegram
            assert surface is not None
            await held(rig, http, "0000000000000521", **KEYS[0])
            await prompt(api)
            rig.store.put("copy", BOT_TOKEN, BOT_API)
            await rig.reload(cooldown=16)
            assert "telegram" not in rig.app.hub.names
            rig.store.delete("copy")
            await rig.reload(cooldown=17)
            assert rig.app.telegram is surface
            assert surface.running
            assert "telegram" in rig.app.hub.names
            polled = len(api.polls)
            await until(lambda: len(api.polls) >= polled + 2, BOUND)
            # The first prompt, open when the surface was hidden, says it was switched off.
            await until(lambda: edits(api) == [SWITCHED_OFF], BOUND)
            await held(rig, http, "0000000000000522", **KEYS[1])
            sent = await prompt(api)
            assert sent.text == live(rig, "0000000000000522").text.value


async def test_token_rotated(tmp_path: Path) -> None:
    """J15: the token is read at every request, so once the old one is revoked (401) and
    ``secret set`` stores the new one, the next poll uses it."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, _):
            await until(lambda: len(api.polls) >= 3, BOUND)
            api.token = NEW_TOKEN  # revoked with the bot-making account, a new one issued
            await until(lambda: any(c.status == 401 for c in api.calls), BOUND)
            rig.store.put("approver-bot", NEW_TOKEN, BOT_API)
            polled = len(api.polls)
            await until(lambda: len(api.polls) >= polled + 3, BOUND)
            surface = rig.app.telegram
            assert surface is not None
            assert not surface.state().unreachable


# --- switched off (B.5) --------------------------------------------------------------------------


async def test_switched_off(tmp_path: Path) -> None:
    """B.5, J15: ``approvers.telegram`` removed while a hold waits on both surfaces: its message
    says the approver was switched off, a decision through Telegram is refused, and the portal
    still decides."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal")) as (rig, http):
            await held(rig, http, "0000000000000601")
            sent = await prompt(api)
            await rig.reload(surfaces=("portal",))
            await until(lambda: edits(api) == [SWITCHED_OFF], BOUND)
            hold = live(rig, "0000000000000601")
            assert hold.surfaces == frozenset({"portal"})
            assert rig.app.telegram is None
            assert await rig.decide(hold, via="telegram") == DecideRefusal("unknown")
            await rig.decide(hold, via="portal")
            await rig.settled()
    assert api.stored(OPERATOR.id, sent.message_id).reply_markup is None
    assert len(rig.upstream.posts()) == 1
    assert edits(api) == [SWITCHED_OFF]  # the surface that went edits nothing more


async def test_a_press_after_the_approver_came_back_reads_how_it_ended(tmp_path: Path) -> None:
    """G.6 across a surface replaced (B.5): switched off, then on again, the new surface keeps
    the old one's endings, so a press on a message the old one closed is told "no longer
    pending" and its message keeps that ending, not the restart's line."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, surfaces=("telegram", "portal")) as (rig, http):
            await held(rig, http, "0000000000000611")
            sent = await prompt(api)
            data = sent.data_for("Approve")
            await rig.reload(surfaces=("portal",))
            await until(lambda: edits(api) == [SWITCHED_OFF], BOUND)
            await rig.reload(surfaces=("telegram", "portal"))
            surface = rig.app.telegram
            assert surface is not None
            assert surface.running
            polled = len(api.polls)
            await until(lambda: len(api.polls) >= polled + 1, BOUND)
            api.press(sent.message_id, data=data, by=OPERATOR)
            await until(lambda: len(edits(api, taken=False)) >= 2, BOUND)
    assert answered(api) == [telegramwire.NOT_PENDING]
    assert edits(api, taken=False)[1] == SWITCHED_OFF
    assert RESTARTED not in edits(api, taken=False)
    assert rig.upstream.received == []


# --- the guarded client (Z22, G.2) ---------------------------------------------------------------


async def test_the_bot_api_is_reached_through_the_guard(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Z22: the approver's client is a vault netclient: ``api.telegram.org`` resolves once per
    connection and its address passes the guard, TLS is verified against certifi's roots (here
    the test CA), with no redirects and a read longer than the long poll."""
    cert = issue_cert(ca, "api.telegram.org", tmp_path)
    api = bot()
    with serve(api.app(), tls=cert) as url, anyio.fail_after(BOUND):
        resolver = FakeResolver()
        resolver.serve("api.telegram.org", int(url.rsplit(":", 1)[1]))
        monkeypatch.setattr(netclient, "HOOKS", resolver.hooks())
        monkeypatch.setattr(certifi, "where", lambda: str(ca.ca_file))
        client = netclient.approver_client(None)
        assert (client.timeout.read, client.timeout.connect) == (60.0, 10.0)
        assert not client.follow_redirects
        async with vault(tmp_path / "vault", api, client=client) as (rig, http):
            await held(rig, http, "0000000000000701")
            await prompt(api)
    assert ("api.telegram.org", 443) in resolver.lookups
    # The poller's start sequence (G.3); the writer's first send waits for it (M8 step 17), and
    # may go before or after the first long poll begins.
    polled = [c.method for c in api.calls if c.method in {"getWebhookInfo", "getMe", "getUpdates"}]
    assert polled[:3] == ["getWebhookInfo", "getMe", "getUpdates"]


# --- enrolment and the probe (G.8, J1, K.3; step 16) ---------------------------------------------


@asynccontextmanager
async def socket(tmp_path: Path, rig: HoldRig) -> AsyncIterator[httpx.AsyncClient]:
    """The vault's admin socket, on the test's loop, as ``zoeymcp approver telegram`` reaches
    it."""
    admin = AdminApp(
        rig.store,
        VAULT_KEYS,
        lambda: rig.app.policy,
        SetupCodes(tmp_path, VAULT_KEYS.portal_key),
        chain=rig.chain,
        holds=rig.app,
        approvals=rig.app,
    )
    transport = httpx.ASGITransport(app=admin.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://admin") as http:
        yield http


ENROL = "/approvers/telegram/enrol"


def allowed(rig: HoldRig) -> bool:
    """Whether the vault's egress list names the Bot API."""
    return "api.telegram.org" in json.dumps(rig.app.allowlist_document())


async def opened(admin: httpx.AsyncClient, name: str = "approver-bot") -> tuple[str, str]:
    """An enrolment opened with store secret ``name``: its id and its one-time code, read from
    its link."""
    answer = await admin.post(ENROL, json={"secret": name})
    assert answer.status_code == 200, answer.text
    found = answer.json()
    return str(found["enrolment"]), str(found["link"]).partition("?start=")[2]


async def state(admin: httpx.AsyncClient, enrolment: str, wait: int = 0) -> dict[str, Any]:
    answer = await admin.get(f"{ENROL}/{enrolment}", params={"wait": wait})
    assert answer.status_code == 200, answer.text
    found: dict[str, Any] = answer.json()
    return found


def ended(rig: HoldRig) -> bool:
    enrolment = rig.app.enrolment
    return enrolment is not None and enrolment.state == "ended"


async def test_setup(tmp_path: Path, log: io.StringIO) -> None:
    """J1 in its new order (G.8, Q43): with no Telegram approver in the policy, the enrolment
    opens its own temporary egress allowance and Bot API session, names the bot and its
    one-time link, reads the operator's ``/start`` from messages alone, shows who pressed it and
    sends that chat a confirmation code; the code typed, it answers the policy lines and closes
    the allowance. The lines installed (as the import's install does), the surface starts
    without a restart, the probe reaches the chat with no buttons, and health shows the bot."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with (
            vault(tmp_path, api, surfaces=("portal",)) as (rig, _),
            socket(tmp_path, rig) as admin,
        ):
            assert not allowed(rig)
            answer = await admin.post(ENROL, json={"secret": "approver-bot"})
            assert answer.status_code == 200, answer.text
            found = answer.json()
            assert (found["state"], found["bot"]) == ("waiting", "example_bot")
            assert found["allowance"] == "api.telegram.org:443"
            link = str(found["link"])
            assert re.fullmatch(r"https://t\.me/example_bot\?start=[A-Za-z0-9_-]{22}", link)
            assert allowed(rig)
            await api.poll_began()
            assert api.polls[-1].allowed_updates == ["message"]
            api.operator.start(link.partition("?start=")[2])
            seen = await state(admin, found["enrolment"], wait=BOUND)
            assert seen["state"] == "seen"
            assert seen["seen"] == {
                "user_id": OPERATOR_ID,
                "chat_id": OPERATOR_ID,
                "name": "Operator",
                "username": "operator_example",
            }
            code = api.operator.confirmation_code()
            [sent] = [m for m in api.operator.messages() if code in m.text]
            assert (sent.reply_markup, sent.protected) == (None, True)
            confirmed = await admin.post(
                f"{ENROL}/{found['enrolment']}/confirm", json={"code": code}
            )
            assert confirmed.status_code == 200, confirmed.text
            assert confirmed.json()["state"] == "confirmed"
            assert confirmed.json()["lines"] == [
                "approvers:",
                f"  telegram: {{bot_token: store:approver-bot, user_id: {OPERATOR_ID}, "
                f"chat_id: {OPERATOR_ID}}}",
                "  timeout: 3600",
                "  block_seconds: 0",
            ]
            assert not allowed(rig)
            # The lines in the policy: the install starts the surface, with no restart.
            rig.app.reload(policy(**{**rig.options, "surfaces": ("portal", "telegram")}))
            await until(lambda: any(p.allowed_updates == ALLOWED for p in api.polls), BOUND)
            probe = await admin.post("/approvers/telegram/test")
            assert probe.json() == {"sent": True, "finding": None}
            [message] = [m for m in api.operator.messages() if m.text == PROBE]
            assert message.reply_markup is None
            health = (await admin.get("/health")).json()
            assert health["approvals"]["telegram"]["username"] == "example_bot"
    [enrolled] = events(log, "approver_enrolled")
    assert str(OPERATOR_ID) not in json.dumps(enrolled)


async def test_a_represented_code_aborts(tmp_path: Path) -> None:
    """G.8 step 3, T33: a second presentation of the code while the enrolment is open (here
    from a token holder's own account) aborts it ``enrolment_contested``, which raises
    ``approver_contested``; the operator's confirmation code is refused, and nothing is
    enrolled."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with (
            vault(tmp_path, api, surfaces=("portal",)) as (rig, _),
            socket(tmp_path, rig) as admin,
        ):
            enrolment, code = await opened(admin)
            await api.poll_began()
            api.operator.start(code)
            assert (await state(admin, enrolment, wait=BOUND))["state"] == "seen"
            api.attacker.present(code)
            await until(lambda: ended(rig), BOUND)
            assert (await state(admin, enrolment))["reason"] == "enrolment_contested"
            typed = api.operator.confirmation_code()
            refused = await admin.post(f"{ENROL}/{enrolment}/confirm", json={"code": typed})
            assert (refused.status_code, refused.json()["reason"]) == (
                409,
                "enrolment_contested",
            )
            assert not allowed(rig)
            health = (await admin.get("/health")).json()
    codes = [finding["code"] for finding in health["approvals"]["findings"]]
    assert "approver_contested" in codes


OTHER_TOKEN = "511223344:AAF-other-bot-token-sentinel-9e0d7c61"  # another bot than the rig's


async def test_a_contested_enrolment_names_its_own_bot(tmp_path: Path) -> None:
    """G.8 step 3 with two bots: an enrolment of another bot than the running approver's, found
    contested (a foreign webhook on it), names that bot's store secret in health, and the
    approver's bot isn't marked contested, since its token isn't the one to revoke. A contested
    re-enrolment of the approver's own bot marks it, and the other bot's finding goes with the
    next enrolment."""
    api = bot()
    other = BotApi(OTHER_TOKEN, switches={Switch.FOREIGN_WEBHOOK}, second=SECOND)
    apps = {OTHER_TOKEN: other.app(), BOT_TOKEN: api.app()}

    async def either(scope: Scope, receive: Receive, send: Send) -> None:
        mine = OTHER_TOKEN in str(scope.get("path", ""))
        await apps[OTHER_TOKEN if mine else BOT_TOKEN](scope, receive, send)

    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=either))
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api, client=client) as (rig, _), socket(tmp_path, rig) as admin:
            await until(lambda: len(api.polls) >= 3, BOUND)
            rig.store.put("other-bot", OTHER_TOKEN, BOT_API)
            refused = await admin.post(ENROL, json={"secret": "other-bot"})
            assert refused.json()["reason"] == "enrolment_contested"
            found = (await admin.get("/health")).json()["approvals"]
            assert found["telegram"]["username"] == "example_bot"
            [contested] = found["findings"]
            assert (contested["code"], contested["level"]) == ("approver_contested", "error")
            assert "the bot stored as other-bot; revoke that bot's token" in contested["text"]
            enrolment, code = await opened(admin)
            await api.poll_began(len(api.polls) + 2)  # the enrolment's polls, the surface paused
            api.operator.start(code)
            assert (await state(admin, enrolment, wait=BOUND))["state"] == "seen"
            api.attacker.present(code)
            await until(lambda: ended(rig), BOUND)
            found = (await admin.get("/health")).json()["approvals"]
    [contested] = found["findings"]
    assert contested["text"] == "another program reads this bot's updates; revoke the token"


async def test_enrolment_confirmation(tmp_path: Path) -> None:
    """FM-38, T-12: a token holder that took the code in a gap between polls presents it from its
    own account, the only presentation the vault sees, under a look-alike name. The confirmation
    code goes to that account's chat, the operator's phone gets none, and what the host types
    doesn't match: ``enrolment_unconfirmed``, and no lines."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with (
            vault(tmp_path, api, surfaces=("portal",)) as (rig, _),
            socket(tmp_path, rig) as admin,
        ):
            enrolment, code = await opened(admin)
            await api.poll_began()
            api.attacker.present(code)
            seen = await state(admin, enrolment, wait=BOUND)
            assert seen["seen"]["user_id"] == ATTACKER.id
            assert seen["seen"]["name"] == "Operator"  # easy to mimic: the code decides
            [sent] = [m for m in api.sent() if m.chat_id == ATTACKER.id]
            assert api.operator.messages() == []
            theirs = re.search(r"\b(\d{6})\b", sent.text)
            assert theirs is not None
            guess = "123456" if theirs.group(1) != "123456" else "654321"
            typed = await admin.post(f"{ENROL}/{enrolment}/confirm", json={"code": guess})
            assert (typed.status_code, typed.json()["reason"]) == (409, "enrolment_unconfirmed")
            again = await admin.post(f"{ENROL}/{enrolment}/confirm", json={"code": theirs.group(1)})
            assert again.json()["reason"] == "enrolment_unconfirmed"  # single use
            assert (await state(admin, enrolment))["state"] == "ended"
            assert not allowed(rig)


async def test_enrolment_refusals(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """G.8 step 1 and M.2: a foreign webhook (contested), a bot that can manage other bots, a
    name the store has no Bot API token under, a token another secret holds too, a second
    enrolment while one is open, an unknown enrolment, and one that ends before its code is
    presented; each closes the allowance it opened."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with (
            vault(tmp_path, api, surfaces=("portal",)) as (rig, _),
            socket(tmp_path, rig) as admin,
        ):

            async def refused(name: str = "approver-bot") -> tuple[int, str]:
                answer = await admin.post(ENROL, json={"secret": name})
                return answer.status_code, str(answer.json()["reason"])

            api.switches = {Switch.FOREIGN_WEBHOOK}
            assert await refused() == (409, "enrolment_contested")
            api.switches = {Switch.MANAGES_BOTS}
            assert await refused() == (409, "approver_can_manage_bots")
            api.switches = set()
            assert await refused("no-such-bot") == (404, "enrolment_secret")
            assert await refused("shop-key") == (404, "enrolment_secret")  # another origin
            rig.store.put("second-bot", BOT_TOKEN, BOT_API)
            assert await refused() == (409, "approver_token_shared")
            rig.store.delete("second-bot")
            assert not allowed(rig)
            enrolment, _ = await opened(admin)
            assert await refused() == (409, "enrolment_busy")
            stopped = await admin.delete(f"{ENROL}/{enrolment}")
            assert stopped.json()["reason"] == "enrolment_expired"
            assert not allowed(rig)
            unknown = await admin.get(f"{ENROL}/{'0' * 16}")
            assert (unknown.status_code, unknown.json()["reason"]) == (
                404,
                "enrolment_unknown",
            )
            monkeypatch.setattr(telegram_approver, "ENROL_TTL", 0.3)
            enrolment, _ = await opened(admin)
            found = await state(admin, enrolment, wait=BOUND)
            assert (found["state"], found["reason"]) == ("ended", "enrolment_expired")
            assert not allowed(rig)


async def test_an_enrolment_ends_at_its_time_whatever_its_poll(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G.8 step 4, Q43: an enrolment ends when its time is up even while a long poll is still
    in flight, so the code typed after that is refused ``enrolment_unconfirmed``, and its
    allowance went with it."""
    monkeypatch.setattr(telegram_approver, "ENROL_TTL", 2.0)
    api = bot()
    with anyio.fail_after(BOUND):
        async with (
            vault(tmp_path, api, surfaces=("portal",)) as (rig, _),
            socket(tmp_path, rig) as admin,
        ):
            enrolment, code = await opened(admin)
            await api.poll_began()
            api.operator.start(code)
            assert (await state(admin, enrolment, wait=BOUND))["state"] == "seen"
            api.second = 600.0  # the next long poll outlasts the enrolment's time
            await api.poll_began(len(api.polls) + 1)
            await until(lambda: ended(rig), BOUND)
            assert (await state(admin, enrolment))["reason"] == "enrolment_unconfirmed"
            assert not allowed(rig)
            typed = api.operator.confirmation_code()
            late = await admin.post(f"{ENROL}/{enrolment}/confirm", json={"code": typed})
            assert (late.status_code, late.json()["reason"]) == (409, "enrolment_unconfirmed")


async def test_a_re_enrolment_pauses_the_poller(tmp_path: Path) -> None:
    """G.8 step 2: enrolling the bot the running surface polls pauses its poller for the
    enrolment's life, so neither session's ``getUpdates`` ends the other's (no 409); confirmed,
    the surface polls again from its start sequence."""
    api = bot()
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, _):
            await until(lambda: len(api.polls) >= 3, BOUND)
            async with socket(tmp_path, rig) as admin:
                enrolment, code = await opened(admin)
                begun = len(api.polls)
                await api.poll_began(begun + 2)
                kinds = [p.allowed_updates for p in api.polls[begun:]]
                assert kinds == [ENROL_UPDATES] * len(kinds)
                api.operator.start(code)
                assert (await state(admin, enrolment, wait=BOUND))["state"] == "seen"
                typed = api.operator.confirmation_code()
                confirmed = await admin.post(f"{ENROL}/{enrolment}/confirm", json={"code": typed})
                assert confirmed.status_code == 200, confirmed.text
                resumed = len(api.polls)
                await until(lambda: len(api.polls) >= resumed + 2, BOUND)
                assert api.polls[resumed].offset == -1  # the start sequence's backlog skip
                assert api.polls[-1].allowed_updates == ALLOWED
    assert all(c.status != 409 for c in api.calls)


async def test_the_probe(tmp_path: Path) -> None:
    """G.8's probe: Telegram took it, or the finding that says why not (a 429 is flood control,
    not an unreachable Telegram); with no Telegram approver, ``approver_not_set``."""
    api = bot(Switch.FORBIDDEN_SEND)
    with anyio.fail_after(BOUND):
        async with vault(tmp_path, api) as (rig, _), socket(tmp_path, rig) as admin:
            await until(lambda: len(api.polls) >= 3, BOUND)
            refused = await admin.post("/approvers/telegram/test")
            assert refused.json() == {"sent": False, "finding": "approver_chat_unreachable"}
            api.switches = set()
            sent = await admin.post("/approvers/telegram/test")
            assert sent.json() == {"sent": True, "finding": None}
            api.switches = {Switch.RATE_LIMITED_SEND}
            limited = await admin.post("/approvers/telegram/test")
            assert limited.json() == {"sent": False, "finding": "approver_rate_limited"}
            rig.app.reload(policy(**{**rig.options, "surfaces": ("portal",)}))
            none = await admin.post("/approvers/telegram/test")
            assert (none.status_code, none.json()["reason"]) == (409, "approver_not_set")
