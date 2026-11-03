"""The Telegram approver surface (M8 design G.1-G.3, G.6, G.7; Z13, Z14, Z15, Z22). I/O, not
mutated: ``tests/acceptance/test_telegram_approver.py`` runs it against the fake Bot API.

Every rule it follows is :mod:`.telegramwire`'s; this module sends, polls and edits.

- **The token** (G.1) is the store secret ``approvers.telegram.bot_token`` names, read at every
  request, so a ``secret set`` with a new token is used by the next one (J15). It goes into a
  :class:`~.telegramwire.SecretUrl`, revealed only for the transport call; every
  ``httpx.HTTPError`` is reduced to its type name, ``raise_for_status`` is never called, and no
  answer's description is kept (a Bot API refusal may echo the path, token and all). A token
  another secret shares (``approver_token_shared``, T-5) stops the poller and every write until
  nothing shares it: a prompt shown meanwhile waits unsent, and is not delivered.
- **One poller** (G.3): at start ``getWebhookInfo`` (a webhook the vault didn't set is
  contested, and never deleted), ``getMe`` (the bot's username, for health) and a
  ``getUpdates(offset=-1)`` that skips the backlog unread (Z10); then a long ``getUpdates`` of
  callback queries alone, restated on every call. A network error or a 5xx backs off 1, 2, 4 ...
  :data:`BACKOFF_MAX` s; a 409 backs off :data:`CONTESTED_BACKOFF` and never fights for the
  token; a 429 waits its ``retry_after``.
- **One write queue for the chat** (G.3, G.4): sends, edits and deletes alike, spaced
  :data:`SEND_SPACING` apart, edits and deletes before sends (so a decided hold's message changes
  before the next prompt goes); a 429 holds every write for exactly its ``retry_after``.
  ``answerCallbackQuery`` answers the presser's own tap and goes at once. A send that fails
  otherwise is retried with backoff until the hold's deadline, a 403 gives up on the chat for
  that hold (the portal still shows it), and a failed edit is a log line.
- **A press** (G.5) runs :func:`.telegramwire.press`'s checks 1-7; check 8 is the vault's
  ``decide``. A stranger (checks 1-2) gets no answer at all; a stale press gets "This request is
  no longer pending", and its message the ending this surface, or the one it replaced, closed
  it with, or, unknown here (a message from before a restart), "the vault restarted".
- **After the decision** (G.6): an approval's message becomes "approved ... Sending..." when its
  forward starts, then the outcome; every other ending replaces the message with one line and no
  keyboard.

Its timings are :class:`Timings`, the constructor's (M.3's defaults, :data:`TIMINGS`), so process
tests pass short ones (BP-10).

Two host commands use the Bot API besides (M8 design G.8, K.3; step 16):

- **The probe** (:meth:`TelegramSurface.probe`, ``zoeymcp approver telegram test``): a message
  with no buttons, through the write queue as any other, answered once Telegram took it or with
  the finding that says why not.
- **The enrolment** (:class:`Enrolment`, ``zoeymcp approver telegram enrol``): its own session
  with the named store secret, independent of the policy, which may name no approver yet. It
  refuses a foreign webhook (``enrolment_contested``) and a bot that can manage other bots
  (``approver_can_manage_bots``), makes a one-time code (16 random bytes, kept only as its
  SHA-256, for :data:`ENROL_TTL`) for the ``t.me`` link, and long-polls messages until one
  ``/start <code>`` comes from a private chat. A second presentation of the code, or a 409 (a
  webhook, or another reader) while it is open, aborts it ``enrolment_contested``. It then sends
  that chat a 6-digit confirmation code (its SHA-256 alone kept), which the host types: a
  mismatch, or the end of :data:`ENROL_TTL`, aborts it ``enrolment_unconfirmed``, and only a
  match gives the identity it found (T-12, FM-38). The vault opens the temporary egress
  allowance and pauses a surface polling the same bot for its life (``vault/app.py``).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import re
import secrets
import time
from collections import OrderedDict, deque
from collections.abc import Callable, Coroutine, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

import httpx

from ..common.policy.schema import TelegramApprover
from . import logs, telegramwire
from .approvers import NotShown, Shown, SurfaceName
from .health import TelegramState
from .holds import Decided, DecideRefusal, Hold
from .store import SecretStore, SecretUnavailable
from .telegramwire import Message, PressRefusal, Sent, TextChanged, TooLong

# A surface's decision on a hold: VaultApp.decide.
Decide = Callable[
    [str, Literal["approve", "deny"], Literal["telegram"], str], Decided | DecideRefusal
]

POLL_TIMEOUT: Final = 50  # getUpdates' long poll, in seconds (below the client's 60 s read)
POLL_LIMIT: Final = 20
ALLOWED_UPDATES: Final = ["callback_query"]
SEND_SPACING: Final = 1.1  # between two writes to the chat, in seconds
CONTESTED_BACKOFF: Final = 60.0
UNREACHABLE_AFTER: Final = 120.0  # no good poll for this long: approver_unreachable
BACKOFF_MAX: Final = 60.0
RATE_LIMITED_FOR: Final = 600.0  # approver_rate_limited lasts this long after a 429
# The endings kept for a late press on a message this surface closed.
ENDINGS_KEPT: Final = 4096
STORE_PREFIX: Final = "store:"

RESTARTED: Final = "This request is no longer waiting: the vault restarted. Nothing was sent."
SWITCHED_OFF: Final = "This approver was switched off."
NOTHING_SENT: Final = "Nothing was sent."
# A forward's outcome, as an approval's last edit says it (G.6).
RESULTS: Final[Mapping[str, str]] = {
    "ok": "Sent: the server answered ok.",
    "tool_error": "Sent: the server answered an error.",
    "upstream_error": "Sent: the server answered an error.",
    "refused": NOTHING_SENT,
    "not_sent": NOTHING_SENT,
    "relayed": "The gateway runs it: see the Ledger.",
}
UNKNOWN_RESULT: Final = "The outcome is unknown: see the Ledger."
# A withdrawal's reason (the hold's detail), as its edit says it (G.6).
WITHDRAWN: Final[Mapping[str, str]] = {
    "changed": "withdrawn: the policy changed",
    "shutdown": "withdrawn: the vault stopped",
    "stream_lost": "withdrawn: the agent cancelled",
    "caller_cancelled": "withdrawn: the agent cancelled",
    "gateway_restarted": "withdrawn: the gateway restarted",
    "gateway_stopped": "withdrawn: the gateway stopped",
    "ledger": "withdrawn: the vault couldn't record it",
}
WHERE: Final[Mapping[str, str]] = {"telegram": " in Telegram", "portal": " in the portal"}
# The probe (G.8): no buttons, nothing to answer; its wait for Telegram's answer, in seconds.
PROBE: Final = (
    "ZoeyMCP test: approvals reach this chat. This message has no buttons and needs no answer."
)
PROBE_WAIT: Final = 30.0
# The enrolment (G.8, M.3): its life, its one-time code's bytes (22 base64url characters), the
# confirmation code's digits, and the updates it reads.
ENROL_TTL: Final = 600.0
ENROL_CODE_BYTES: Final = 16
CONFIRM_DIGITS: Final = 6
ENROL_UPDATES: Final = ["message"]
CONFIRM_TEXT: Final = (
    "ZoeyMCP enrolment: your confirmation code is {code}. Type it where you ran zoeymcp "
    "approver telegram enrol. If you didn't, ignore this message."
)
START: Final = "/start "
# A bot's username, as a t.me link names it.
_USERNAME: Final = re.compile(r"[A-Za-z][A-Za-z0-9_]{3,31}")


@dataclass(frozen=True)
class Timings:
    """The surface's timing constants (G.3, M.3), as constructor arguments (BP-10)."""

    send_spacing: float = SEND_SPACING
    contested_backoff: float = CONTESTED_BACKOFF
    unreachable_after: float = UNREACHABLE_AFTER
    backoff_max: float = BACKOFF_MAX
    poll_timeout: int = POLL_TIMEOUT


# The timings a surface the vault builds gets. Production never changes it; a process test's
# launcher sets short ones (tests/acceptance/procs.py, BP-10).
TIMINGS = Timings()


def secret_name(settings: TelegramApprover) -> str | None:
    """The store name of the bot's token, or None for a reference ``check`` refuses (row 10)."""
    ref = settings.bot_token
    return ref.removeprefix(STORE_PREFIX) if ref.startswith(STORE_PREFIX) else None


def same_bot(token: str) -> Callable[[str], bool]:
    """Whether another secret's value is ``token``, a token of the same bot, or the token's
    secret half, the part after its ``:``, which a route's template can complete with the bot's
    id (G.7, T-5)."""
    bot = telegramwire.bot_id(token)
    half = token.partition(":")[2] if bot is not None else None

    def matches(value: str) -> bool:
        if value == token:
            return True
        return bot is not None and (telegramwire.bot_id(value) == bot or value == half)

    return matches


def clock_time(wall: float) -> str:
    """``HH:MM`` in UTC, as the edits say a decision's time."""
    return datetime.fromtimestamp(wall, UTC).strftime("%H:%M")


def ending(hold: Hold, outcome: str, at: str) -> str:
    """The one line a closed hold's message becomes (G.6). ``outcome`` is the hold's end state
    (``done`` with the forward's outcome in ``hold.detail``), ``at`` the decision's time."""
    head = f"Approval request {hold.ref}"
    where = WHERE.get(hold.via or "", "")
    if outcome == "done":
        result = RESULTS.get(hold.detail or "", UNKNOWN_RESULT)
        return f"{head}: approved {at} UTC{where}. {result}"
    if outcome == "denied":
        return f"{head}: denied {at} UTC{where}. {NOTHING_SENT}"
    if outcome == "expired":
        return f"{head}: expired {at} UTC. {NOTHING_SENT}"
    if hold.via == "host":
        return f"{head}: withdrawn by the operator. {NOTHING_SENT}"
    return f"{head}: {WITHDRAWN.get(hold.detail or '', 'withdrawn')}. {NOTHING_SENT}"


def sending(hold: Hold, at: str) -> str:
    """An approval's first edit, when its forward starts (G.6)."""
    where = WHERE.get(hold.via or "", "")
    return f"Approval request {hold.ref}: approved {at} UTC{where}. Sending\N{HORIZONTAL ELLIPSIS}"


class _Failed(Exception):
    """A Bot API call that didn't succeed: its HTTP status (0: no answer), what kind of failure
    (an exception's type name, or ``refused``/``unreadable``), and a 429's ``retry_after``. It
    holds nothing from the answer's text."""

    def __init__(self, status: int, kind: str, retry_after: int | None = None) -> None:
        super().__init__(kind)
        self.status, self.kind, self.retry_after = status, kind, retry_after


class _NoToken(Exception):
    """The store has no bot token by that name, or one it can't give."""


@dataclass
class _Prompt:
    """A hold shown here: its message, the first send's verdict, and what Telegram took."""

    hold: Hold
    message: Message
    verdict: asyncio.Future[Shown | NotShown]
    message_id: int | None = None
    sent: Sent | None = None
    decided: bool = False  # approved: a send still queued is dropped


@dataclass(eq=False)
class _Write:
    """One write to the chat: a send (a hold's prompt or notice, or a saturation notice), an
    edit or a delete."""

    method: str
    params: dict[str, Any]
    hold_id: str | None = None
    message: Message | None = None  # a send's
    attempts: int = 0
    retry_at: float = 0.0
    # The probe's: None once Telegram took it, else the finding that says why not.
    done: asyncio.Future[str | None] | None = None


@dataclass
class _Health:
    username: str | None = None
    started_at: float | None = None
    last_poll: float | None = None
    contested: bool = False
    chat_unreachable: bool = False
    rate_limited_at: float | None = None
    token_missing: bool = False
    token_shared: bool = False
    failures: int = 0
    contested_logged: bool = False


class TelegramSurface:
    """The Telegram approver of ``approvers.telegram`` (D.1's :class:`.approvers.Surface`):
    started, stopped and restarted by ``VaultApp`` as the block comes, goes or changes (B.5,
    I.4). ``client`` is :func:`.netclient.approver_client`'s, built once from the startup policy
    (Z22); ``decide`` is ``VaultApp.decide``; ``shared`` says whether another secret holds the
    token or the same bot; ``clock`` is the hold table's, so a hold's deadline and decision time
    read right; ``ended`` holds the endings of the surface this one replaces (a late press
    on a message it closed, G.6)."""

    def __init__(
        self,
        settings: TelegramApprover,
        *,
        store: SecretStore,
        client: httpx.AsyncClient,
        decide: Decide,
        shared: Callable[[str], bool],
        clock: Callable[[], float],
        wall: Callable[[], float] = time.time,
        timings: Timings | None = None,
        key: bytes | None = None,
        ended: Mapping[str, str] | None = None,
    ) -> None:
        self.settings = settings
        self._secret = secret_name(settings)
        self._store = store
        self._client = client
        self._decide = decide
        self._shared = shared
        self._clock = clock
        self._wall = wall
        self.timings = timings or TIMINGS
        self._key = key or telegramwire.new_key()
        self._enrolled = telegramwire.Enrolled(settings.user_id, settings.chat_id)
        self._prompts: dict[str, _Prompt] = {}
        self._ended: OrderedDict[str, str] = OrderedDict()  # hold id -> its ending's text
        for hold_id, text in (ended or {}).items():
            self._remember(hold_id, text)
        self._edits: deque[_Write] = deque()  # edits and deletes, first
        self._sends: deque[_Write] = deque()
        self._work = asyncio.Event()
        self._idle = asyncio.Event()
        self._idle.set()
        self._next_write = 0.0  # time.monotonic()
        self._checked: str | None = None  # the digest of the token last checked for sharing
        self._health = _Health()
        self._poller: asyncio.Task[None] | None = None
        self._writer: asyncio.Task[None] | None = None
        self._stopping = False  # a stop waits for its edits: a start meanwhile cancels it
        self._paused = False  # an enrolment of the same bot polls instead (G.8 step 2)

    @property
    def name(self) -> SurfaceName:
        return "telegram"

    @property
    def running(self) -> bool:
        return self._poller is not None or self._paused

    # --- lifecycle ------------------------------------------------------------------------------

    def start(self) -> None:
        """Start the poller and the write queue on the running loop (I.4). A stop still sending
        its edits (a surface hidden, then shown again) is called off: its writer runs on."""
        self._stopping = self._paused = False
        loop = asyncio.get_running_loop()
        if self._writer is None:
            self._writer = loop.create_task(self._write())
        if self._poller is None:
            self._health.started_at = time.monotonic()
            self._poller = loop.create_task(self.poll_forever())
            logs.event("approver_started", surface="telegram")

    def stop(self, grace: float) -> Coroutine[Any, Any, None]:
        """Stop polling now, before any later :meth:`start` (no press is read from here on, and
        a surface that replaces this one is the bot's only reader); the awaitable it returns
        sends the edits already queued for at most ``grace`` seconds (best effort, I.2; none
        while the token is shared), then stops writing, unless a :meth:`start` came meanwhile."""
        self._stopping = True
        self._paused = False
        poller, self._poller = self._poller, None
        if poller is not None:
            poller.cancel()
            logs.event("approver_stopped", surface="telegram")
        return self._stopped(poller, grace)

    def pause(self) -> None:
        """An enrolment of the same bot is open (G.8 step 2): no poll from here until
        :meth:`resume`, so the two sessions never end each other's ``getUpdates``. Writes go
        on."""
        poller, self._poller = self._poller, None
        if poller is not None:
            poller.cancel()
            self._paused = True

    def resume(self) -> None:
        """The enrolment closed: poll again, from the start sequence (the backlog skipped)."""
        if self._paused:
            self._paused = False
            self._poller = asyncio.get_running_loop().create_task(self.poll_forever())

    async def _stopped(self, poller: asyncio.Task[None] | None, grace: float) -> None:
        if poller is not None:
            with contextlib.suppress(asyncio.CancelledError):
                await poller
        if self._writer is not None:
            with contextlib.suppress(TimeoutError):
                async with asyncio.timeout(grace):
                    while not self._health.token_shared and (
                        self._edits or not self._idle.is_set()
                    ):
                        await self._idle.wait()
                        await asyncio.sleep(0)
        if not self._stopping:
            return  # started again while its edits went: it runs on
        writer, self._writer = self._writer, None
        if writer is not None:
            writer.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await writer

    def token_shared(self) -> bool:
        """Whether another secret holds the bot's token or the same bot now (T-5): read from the
        store, never kept. A token the store doesn't have shares nothing yet."""
        try:
            token = self._token()
        except _NoToken:
            return False
        shared = self._shared(token)
        self._checked = _digest(token)
        self._health.token_shared = shared
        self._work.set()  # the writer looks again: writes wait while the token is shared
        return shared

    def state(self) -> TelegramState:
        """What health shows (G.7)."""
        now = time.monotonic()
        health = self._health
        since = health.last_poll if health.last_poll is not None else health.started_at
        limited = health.rate_limited_at
        return TelegramState(
            secret=self._secret or "",
            username=health.username,
            last_poll_ago=None if health.last_poll is None else now - health.last_poll,
            unreachable=since is not None and now - since >= self.timings.unreachable_after,
            token_missing=self._secret is None or health.token_missing,
            token_shared=health.token_shared,
            contested=health.contested,
            chat_unreachable=health.chat_unreachable,
            rate_limited=limited is not None and now - limited < RATE_LIMITED_FOR,
        )

    def delivered(self, hold_id: str) -> bool:
        """Whether Telegram took this hold's message (the queue's "not delivered to Telegram")."""
        prompt = self._prompts.get(hold_id)
        return prompt is not None and prompt.message_id is not None

    def endings(self) -> dict[str, str]:
        """The endings this surface remembers, oldest first, for the one that replaces it."""
        return dict(self._ended)

    # --- the surface (D.1) ----------------------------------------------------------------------

    async def show(self, hold: Hold) -> Shown | NotShown:
        """Queue ``hold``'s prompt (G.4), or the notice when its text is too long and the portal
        shows it too, and answer once the first send is tried: :class:`~.approvers.NotShown`
        only when Telegram returned another text (the message is deleted); a send that failed
        otherwise goes on being tried until the hold's deadline. While the token is shared the
        send waits, and the answer is at once."""
        made = telegramwire.message(hold, self._key)
        if isinstance(made, TooLong):
            if made.notice is None:  # refused before the hold began; never asked here
                return NotShown("telegram", TooLong.code, TooLong.status)
            made = made.notice
        prompt = _Prompt(hold, made, asyncio.get_running_loop().create_future())
        self._prompts[hold.id] = prompt
        self._queue_send(_Write("sendMessage", made.params(self.settings.chat_id), hold.id, made))
        if self._health.token_shared:
            prompt.verdict.set_result(Shown("telegram"))  # not delivered while it is (T-5)
        return await asyncio.shield(prompt.verdict)

    async def approved(self, hold: Hold) -> None:
        """Its forward starts (G.6's first edit): "approved ... Sending...". A prompt still
        queued is never sent."""
        prompt = self._prompts.get(hold.id)
        if prompt is None:
            return
        prompt.decided = True
        if prompt.message_id is not None:
            self._queue_edit(prompt.message_id, sending(hold, self._at(hold)))

    async def close(self, hold: Hold, outcome: str) -> None:
        """Its ending (G.6): the message becomes one line, its keyboard gone, and the hold is
        forgotten here but for that line, for a late press."""
        prompt = self._prompts.pop(hold.id, None)
        text = ending(hold, outcome, self._at(hold))
        self._remember(hold.id, text)
        if prompt is None:
            return
        if not prompt.verdict.done():
            prompt.verdict.set_result(Shown("telegram"))
        if prompt.message_id is not None:
            self._queue_edit(prompt.message_id, text)

    async def notice(self, text: str) -> None:
        """D.3's saturation notice: a message with no buttons."""
        notice = Message(text)
        self._queue_send(_Write("sendMessage", notice.params(self.settings.chat_id), None, notice))

    async def probe(self) -> str | None:
        """``zoeymcp approver telegram test`` (G.8): a message with no buttons, queued as any
        write to the chat. None once Telegram took it; else the finding that says why not
        (G.7): the token missing or shared, the chat refusing it, flood control (a 429 for it,
        or one that kept it waiting), or no answer from Telegram within :data:`PROBE_WAIT`."""
        try:
            token = self._token()
        except _NoToken:
            return "approver_token_missing"
        if self._shared(token):
            return "approver_token_shared"
        probe = Message(PROBE)
        write = _Write("sendMessage", probe.params(self.settings.chat_id), None, probe)
        done = write.done = asyncio.get_running_loop().create_future()
        self._queue_send(write)
        try:
            async with asyncio.timeout(PROBE_WAIT):
                return await asyncio.shield(done)
        except TimeoutError:
            with contextlib.suppress(ValueError):
                self._sends.remove(write)
            if self.state().rate_limited:
                return "approver_rate_limited"  # it waited behind flood control's window
            return "approver_unreachable"

    def retire(self, ended: Mapping[str, Hold]) -> None:
        """The surface is switched off or replaced (B.5): each message still open becomes "This
        approver was switched off.", or, for a hold the same change withdrew (in ``ended``), its
        ending; a prompt not sent yet never is."""
        for hold_id, prompt in list(self._prompts.items()):
            gone = ended.get(hold_id)
            text = SWITCHED_OFF if gone is None else ending(gone, gone.state, self._at(gone))
            self._remember(hold_id, text)
            if not prompt.verdict.done():
                prompt.verdict.set_result(Shown("telegram"))
            if prompt.message_id is not None:
                self._queue_edit(prompt.message_id, text)
        self._prompts.clear()

    # --- the poller (G.3) -----------------------------------------------------------------------

    async def poll_forever(self) -> None:
        """Poll for presses for as long as the surface runs."""
        offset: int | None = None
        begun_for: str | None = None  # the token the start's three calls ran for
        while True:
            try:
                token = self._token()
            except _NoToken:
                self._health.token_missing = True
                await asyncio.sleep(self.timings.backoff_max)
                continue
            self._health.token_missing = False
            digest = _digest(token)
            if digest != self._checked:
                self._checked = digest
                self._health.token_shared = self._shared(token)
                self._work.set()  # the writer looks again: writes wait while it is shared
            if self._health.token_shared:
                await asyncio.sleep(self.timings.contested_backoff)
                continue
            try:
                if begun_for != digest:
                    offset = await self._begin(token)
                    begun_for = digest
                params: dict[str, Any] = {
                    "timeout": self.timings.poll_timeout,
                    "limit": POLL_LIMIT,
                    "allowed_updates": ALLOWED_UPDATES,
                }
                if offset is not None:
                    params["offset"] = offset
                updates = await self._call(token, "getUpdates", params)
            except Exception as exc:  # a poll that fails never stops the poller
                failed = _failure(exc)
                if failed.status == 409:
                    begun_for = None  # a webhook may have been set: look again
                await self._poll_failed(failed)
                continue
            self._polled()
            for update in updates if isinstance(updates, list) else ():
                update_id = update.get("update_id") if isinstance(update, dict) else None
                if isinstance(update_id, int) and not isinstance(update_id, bool):
                    offset = update_id + 1
                try:
                    await self._press(update)
                except Exception as exc:  # one update never stops the poller
                    logs.event("approver_poll_failed", error_type=type(exc).__name__, level="error")

    async def _begin(self, token: str) -> int | None:
        """G.3's start: no webhook the vault didn't set, the bot's username, and the backlog
        skipped unread. Returns the offset to poll from."""
        info = await self._call(token, "getWebhookInfo", {})
        if isinstance(info, dict) and info.get("url"):
            raise _Failed(409, "webhook")
        me = await self._call(token, "getMe", {})
        username = me.get("username") if isinstance(me, dict) else None
        self._health.username = username if isinstance(username, str) else None
        skipped = await self._call(
            token,
            "getUpdates",
            {"offset": -1, "timeout": 0, "allowed_updates": ALLOWED_UPDATES},
        )
        ids = [
            update["update_id"]
            for update in (skipped if isinstance(skipped, list) else ())
            if isinstance(update, dict)
            and isinstance(update.get("update_id"), int)
            and not isinstance(update["update_id"], bool)
        ]
        return max(ids) + 1 if ids else None

    def _polled(self) -> None:
        health = self._health
        health.last_poll = time.monotonic()
        health.failures = 0
        health.contested = health.contested_logged = False

    async def _poll_failed(self, failed: _Failed) -> None:
        health = self._health
        if failed.status == 409:
            health.contested = True
            if not health.contested_logged:
                health.contested_logged = True
                logs.event("approver_contested", reason=failed.kind, level="error")
            await asyncio.sleep(self.timings.contested_backoff)
            return
        if failed.status == 429:
            health.rate_limited_at = time.monotonic()
            await asyncio.sleep(failed.retry_after or 1)
            return
        health.failures += 1
        logs.event(
            "approver_poll_failed",
            error_type=failed.kind,
            status=failed.status or None,
            level="warning",
        )
        await asyncio.sleep(min(2.0 ** (health.failures - 1), self.timings.backoff_max))

    # --- a press (G.5) --------------------------------------------------------------------------

    async def _press(self, update: object) -> None:
        stored = {
            hold_id: prompt.sent
            for hold_id, prompt in self._prompts.items()
            if prompt.sent is not None
        }
        found = telegramwire.press(update, self._enrolled, stored, self._key)
        if isinstance(found, PressRefusal):
            logs.event("approver_press_refused", reason=found.reason, level="warning")
            answer = found.answer
            if answer is not None and found.query_id is not None:
                await self._answer(found.query_id, answer)
            if found.reason == "not_pending" and found.message_id is not None:
                self._stale(found.hold_id, found.message_id)
            return
        decided = self._decide(found.hold_id, found.decision, "telegram", found.text_sha256)
        if isinstance(decided, DecideRefusal):
            logs.event("approver_press_refused", reason=decided.reason, level="warning")
            await self._answer(found.query_id, telegramwire.NOT_PENDING)
            return
        await self._answer(found.query_id, found.answer)

    def _stale(self, hold_id: str | None, message_id: int) -> None:
        """A press on a message for a hold no longer shown here (G.6): edited to the ending
        this surface closed it with, else to the restart's line. A message still open for
        another hold is never touched."""
        if any(prompt.message_id == message_id for prompt in self._prompts.values()):
            return
        text = None if hold_id is None else self._ended.get(hold_id)
        self._queue_edit(message_id, text or RESTARTED)

    async def _answer(self, query_id: str, text: str) -> None:
        """``answerCallbackQuery`` at once: it answers the presser's tap, not a chat message,
        so flood control doesn't queue it (G.3)."""
        try:
            token = self._token()
            await self._call(
                token, "answerCallbackQuery", {"callback_query_id": query_id, "text": text}
            )
        except (_Failed, _NoToken) as exc:
            self._send_failed("answerCallbackQuery", exc)

    # --- the write queue (G.3, G.4) -------------------------------------------------------------

    def _queue_send(self, write: _Write) -> None:
        self._sends.append(write)
        self._idle.clear()
        self._work.set()

    def _queue_edit(self, message_id: int, text: str) -> None:
        params = {"chat_id": self.settings.chat_id, "message_id": message_id, "text": text}
        self._edits.append(_Write("editMessageText", params))
        self._idle.clear()
        self._work.set()

    def _queue_delete(self, message_id: int) -> None:
        params = {"chat_id": self.settings.chat_id, "message_id": message_id}
        self._edits.append(_Write("deleteMessage", params))
        self._idle.clear()
        self._work.set()

    def _take(self, now: float) -> tuple[_Write | None, float | None]:
        """The next write due, edits and deletes first; else None, with the seconds until a
        retried send is due (None: nothing is waiting). Nothing is due while the token is
        shared (T-5)."""
        if self._health.token_shared:
            return None, None
        if self._edits:
            return self._edits.popleft(), None
        due: float | None = None
        for write in list(self._sends):
            prompt = None if write.hold_id is None else self._prompts.get(write.hold_id)
            if write.hold_id is not None and (prompt is None or prompt.decided):
                self._sends.remove(write)  # closed or approved before it went: never sent
                continue
            if write.retry_at <= now:
                self._sends.remove(write)
                return write, None
            due = write.retry_at - now if due is None else min(due, write.retry_at - now)
        return None, due

    async def _write(self) -> None:
        """Every write to the chat, one at a time, :attr:`Timings.send_spacing` apart."""
        while True:
            wait = self._next_write - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
                continue
            write, due = self._take(time.monotonic())
            if write is None:
                if not self._edits or self._health.token_shared:
                    self._idle.set()
                self._work.clear()
                with contextlib.suppress(TimeoutError):
                    async with asyncio.timeout(due):
                        await self._work.wait()
                continue
            self._idle.clear()
            try:
                result = await self._call(self._token(), write.method, write.params)
            except Exception as exc:  # a write that fails never stops the queue
                # Spaced as any write; a 429 sets its own wait instead (_write_failed).
                self._next_write = time.monotonic() + self.timings.send_spacing
                self._write_failed(write, _failure(exc))
                continue
            self._next_write = time.monotonic() + self.timings.send_spacing
            if write.done is not None and not write.done.done():
                write.done.set_result(None)
            if write.method == "sendMessage":
                self._health.chat_unreachable = False
                try:
                    self._sent(write, result)
                except Exception as exc:  # one answer never stops the queue
                    self._send_failed(write.method, exc)

    def _sent(self, write: _Write, result: object) -> None:
        """What Telegram returned for a send (G.4)."""
        if write.hold_id is None or write.message is None:
            return  # a saturation notice
        prompt = self._prompts.get(write.hold_id)
        message_id = result.get("message_id") if isinstance(result, dict) else None
        known = isinstance(message_id, int) and not isinstance(message_id, bool)
        if prompt is None:
            # Closed while it went: it ends as the hold did.
            text = self._ended.get(write.hold_id)
            if known and text is not None:
                assert isinstance(message_id, int)  # noqa: S101 - known
                self._queue_edit(message_id, text)
            return
        if not write.message.buttons:
            # A notice (G.4): read for its id alone, never refused.
            prompt.message_id = message_id if known else None
            if not prompt.verdict.done():
                prompt.verdict.set_result(Shown("telegram"))
            return
        found = telegramwire.sent(write.message, self.settings.chat_id, result)
        if isinstance(found, TextChanged):
            if found.message_id is not None:
                self._queue_delete(found.message_id)
            logs.event("approver_send_failed", method="sendMessage", error_type="text_changed")
            del self._prompts[write.hold_id]
            refused = NotShown("telegram", TextChanged.code, TextChanged.status)
            if not prompt.verdict.done():
                prompt.verdict.set_result(refused)
            return
        prompt.sent, prompt.message_id = found, found.message_id
        if not prompt.verdict.done():
            prompt.verdict.set_result(Shown("telegram"))
        if prompt.decided:
            self._queue_edit(found.message_id, sending(prompt.hold, self._at(prompt.hold)))

    def _write_failed(self, write: _Write, failed: _Failed) -> None:
        """G.3's failure table, for a write."""
        now = time.monotonic()
        if failed.status == 429:
            # Every write to the chat waits exactly retry_after, this one first again (FM-43).
            self._health.rate_limited_at = now
            self._next_write = now + (failed.retry_after or 1)
            if write.done is not None:
                # The probe: one try, and flood control is why Telegram didn't take it.
                if not write.done.done():
                    write.done.set_result("approver_rate_limited")
                return
            (self._edits if write.method != "sendMessage" else self._sends).appendleft(write)
            return
        self._send_failed(write.method, failed)
        if write.done is not None and not write.done.done():
            # The probe: one try, its failure the finding it answers with.
            if failed.status == 403:
                self._health.chat_unreachable = True
            found = "approver_chat_unreachable" if failed.status == 403 else "approver_unreachable"
            write.done.set_result(found)
        if write.method != "sendMessage" or write.hold_id is None:
            return  # an edit, a delete, a notice or the probe: a log line, never a state change
        prompt = self._prompts.get(write.hold_id)
        if prompt is None:
            return
        if failed.status == 403:
            # The chat wasn't started, or the bot is blocked: Telegram is out for this hold.
            self._health.chat_unreachable = True
            if not prompt.verdict.done():
                prompt.verdict.set_result(Shown("telegram"))
            return
        if not prompt.verdict.done():
            prompt.verdict.set_result(Shown("telegram"))  # it is tried again, to the deadline
        write.attempts += 1
        backoff = min(2.0 ** (write.attempts - 1), self.timings.backoff_max)
        if self._clock() + backoff < prompt.hold.deadline:
            write.retry_at = now + backoff
            self._sends.append(write)

    def _send_failed(self, method: str, failed: Exception) -> None:
        status = failed.status if isinstance(failed, _Failed) else 0
        kind = failed.kind if isinstance(failed, _Failed) else type(failed).__name__
        logs.event(
            "approver_send_failed",
            method=method,
            error_type=kind,
            status=status or None,
            level="warning",
        )

    # --- the Bot API ----------------------------------------------------------------------------

    def _token(self) -> str:
        if self._secret is None:
            raise _NoToken
        try:
            return self._store.get_for_origin(self._secret, telegramwire.API).reveal()
        except SecretUnavailable:
            raise _NoToken from None

    async def _call(self, token: str, method: str, params: dict[str, Any]) -> Any:
        return await _bot_call(self._client, token, method, params)

    # --- helpers --------------------------------------------------------------------------------

    def _at(self, hold: Hold) -> str:
        """When ``hold`` was decided (or ended undecided), in UTC, from the hold table's clock."""
        decided = hold.decided_at if hold.decided_at is not None else self._clock()
        return clock_time(self._wall() - (self._clock() - decided))

    def _remember(self, hold_id: str, text: str) -> None:
        self._ended[hold_id] = text
        self._ended.move_to_end(hold_id)
        while len(self._ended) > ENDINGS_KEPT:
            self._ended.popitem(last=False)


# --- the enrolment (G.8) -------------------------------------------------------------------------

# An enrolment's states: its code awaited, then seen (the confirmation code sent), then
# confirmed, or ended by the refusal that stopped it (M.2).
EnrolState = Literal["waiting", "seen", "confirmed", "ended"]
# The host's Telegram commands' refusals (M.2): an enrolment's, and the probe's with no approver.
EnrolReason = Literal[
    "approver_not_set",
    "enrolment_contested",
    "enrolment_expired",
    "enrolment_unconfirmed",
    "enrolment_unreachable",
    "enrolment_secret",
    "enrolment_busy",
    "enrolment_unknown",
    "approver_can_manage_bots",
    "approver_token_shared",
]


class EnrolRefused(Exception):
    """Why an enrolment stopped, or never began: the catalogue's reason (M.2)."""

    def __init__(self, reason: EnrolReason) -> None:
        super().__init__(reason)
        self.reason: EnrolReason = reason


@dataclass(frozen=True, repr=False)
class Identity:
    """Who presented the code (G.8 step 3): for the confirmation and the policy lines alone,
    never logged."""

    user_id: int
    chat_id: int
    name: str
    username: str | None

    def __repr__(self) -> str:
        return "Identity(<hidden>)"


class Enrolment:
    """One host-started enrolment (G.8): its own Bot API session with the store secret
    ``secret``, the one-time code, the long poll of messages and the confirmation code.
    ``ended`` is called once when it ends, however it ends, for the vault to close the egress
    allowance and resume a paused surface. ``clock`` is monotonic; ``wall`` the clock its
    expiry is shown on. Made on the running loop, where its expiry is timed: it ends at
    ``ttl`` whatever its poll is doing, so neither it nor its allowance outlives that."""

    def __init__(
        self,
        secret: str,
        *,
        store: SecretStore,
        client: httpx.AsyncClient,
        ended: Callable[[Enrolment], None],
        timings: Timings | None = None,
        ttl: float = ENROL_TTL,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self.id = secrets.token_urlsafe(12)
        self.secret = secret
        self._store = store
        self._client = client
        self._ended = ended
        self.timings = timings or TIMINGS
        self._clock = clock
        self._deadline = clock() + ttl
        self.expires = int(wall() + ttl)
        self.state: EnrolState = "waiting"
        self.reason: EnrolReason | None = None
        self.username: str | None = None
        self.identity: Identity | None = None
        self._code = b""  # the one-time code's SHA-256
        self._confirm: bytes | None = None  # the confirmation code's SHA-256
        self._changed = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._timer = asyncio.get_running_loop().call_later(ttl, self._lapse)

    @property
    def open(self) -> bool:
        return self.state in ("waiting", "seen")

    def token(self) -> str:
        """The bot's token, read from the store at each request, as the surface reads it."""
        try:
            return self._store.get_for_origin(self.secret, telegramwire.API).reveal()
        except SecretUnavailable:
            raise EnrolRefused("enrolment_secret") from None

    async def begin(self) -> str:
        """Steps 1 and 2: no webhook (a foreign one is ``enrolment_contested``), the bot by
        ``getMe`` (one that can manage other bots is refused), then the one-time code. Returns
        the ``t.me`` link, the one place the code ever appears."""
        token = self.token()
        try:
            info = await _bot_call(self._client, token, "getWebhookInfo", {})
            if isinstance(info, dict) and info.get("url"):
                raise EnrolRefused("enrolment_contested")
            me = await _bot_call(self._client, token, "getMe", {})
        except _Failed as failed:
            reason: EnrolReason = (
                "enrolment_contested" if failed.status == 409 else "enrolment_unreachable"
            )
            raise EnrolRefused(reason) from None
        if not isinstance(me, dict):
            raise EnrolRefused("enrolment_unreachable")
        if me.get("can_manage_bots") is True:
            raise EnrolRefused("approver_can_manage_bots")
        username = me.get("username")
        if not isinstance(username, str) or not _USERNAME.fullmatch(username):
            raise EnrolRefused("enrolment_unreachable")
        self.username = username
        code = secrets.token_urlsafe(ENROL_CODE_BYTES)
        self._code = _sha256(code)
        return f"https://t.me/{username}?start={code}"

    def start(self) -> None:
        """Step 3's long poll, on the running loop. A poll that fails for good ends the
        enrolment, so its allowance never outlives it."""
        self._task = asyncio.get_running_loop().create_task(self._poll())
        self._task.add_done_callback(self._polled)

    def _polled(self, task: asyncio.Task[None]) -> None:
        if not task.cancelled() and task.exception() is not None:
            self.end("enrolment_unreachable")

    async def wait(self, seconds: float) -> None:
        """While its code is awaited: until someone presents it, it ends, or ``seconds`` pass."""
        changed = self._changed
        if self.state == "waiting" and seconds > 0:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(changed.wait(), seconds)

    def confirm(self, typed: str) -> Identity:
        """Step 4: the code the host typed, once. A mismatch aborts it
        ``enrolment_unconfirmed``, as does one typed after its time is up (step 4's timeout);
        only a match in time gives the identity."""
        if self._clock() >= self._deadline:
            self._lapse()
        if self.state != "seen" or self._confirm is None or self.identity is None:
            raise EnrolRefused(self.reason or "enrolment_unconfirmed")
        if not hmac.compare_digest(_sha256(typed.strip()), self._confirm):
            self.end("enrolment_unconfirmed")
            raise EnrolRefused("enrolment_unconfirmed")
        self._finish("confirmed", None)
        return self.identity

    def end(self, reason: EnrolReason) -> None:
        """Stop it, refused for ``reason`` (``enrolment_expired`` when the host stops it)."""
        if self.open:
            self._finish("ended", reason)

    def _lapse(self) -> None:
        """Its time is up (G.8 step 4): ``enrolment_expired`` while its code is awaited, else
        ``enrolment_unconfirmed``."""
        self.end("enrolment_expired" if self.state == "waiting" else "enrolment_unconfirmed")

    def answer(self) -> dict[str, Any]:
        """``GET /approvers/telegram/enrol/{enrolment}`` (G.8): its state, the bot, its expiry,
        once seen who presented the code, and the reason it ended. Never a code."""
        seen = self.identity
        return {
            "enrolment": self.id,
            "state": self.state,
            "bot": self.username,
            "expires": self.expires,
            "reason": self.reason,
            "seen": None
            if seen is None
            else {
                "user_id": seen.user_id,
                "chat_id": seen.chat_id,
                "name": seen.name,
                "username": seen.username,
            },
        }

    def _finish(self, state: EnrolState, reason: EnrolReason | None) -> None:
        self.state, self.reason = state, reason
        self._timer.cancel()
        task, self._task = self._task, None
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        self._changed.set()
        self._changed = asyncio.Event()
        self._ended(self)

    async def _poll(self) -> None:
        offset: int | None = None
        failures = 0
        while self.open:
            left = self._deadline - self._clock()
            if left <= 0:
                self._lapse()
                return
            params: dict[str, Any] = {
                "timeout": max(1, min(self.timings.poll_timeout, int(left))),
                "allowed_updates": ENROL_UPDATES,
            }
            if offset is not None:
                params["offset"] = offset  # confirms every update read so far
            try:
                updates = await _bot_call(self._client, self.token(), "getUpdates", params)
            except EnrolRefused as refused:
                self.end(refused.reason)
                return
            except _Failed as failed:
                if failed.status == 409:
                    # Another reader of the bot's updates, or a webhook (T33).
                    self.end("enrolment_contested")
                    return
                failures += 1
                await asyncio.sleep(min(2.0 ** (failures - 1), self.timings.backoff_max, left))
                continue
            failures = 0
            for update in updates if isinstance(updates, list) else ():
                update_id = update.get("update_id") if isinstance(update, dict) else None
                if isinstance(update_id, int) and not isinstance(update_id, bool):
                    offset = update_id + 1
                await self._read(update)
                if not self.open:
                    return

    async def _read(self, update: object) -> None:
        """One update: a ``/start`` with the code is a presentation; any other message is none
        of the enrolment's business."""
        message = update.get("message") if isinstance(update, dict) else None
        if not isinstance(message, dict):
            return
        text = message.get("text")
        if not isinstance(text, str) or not text.startswith(START):
            return
        if not hmac.compare_digest(_sha256(text.removeprefix(START).strip()), self._code):
            return
        found = _presenter(message)
        if self.identity is not None or found is None:
            # A second presentation, or one from no private chat: someone else has the code.
            self.end("enrolment_contested")
            return
        code = f"{secrets.randbelow(10**CONFIRM_DIGITS):0{CONFIRM_DIGITS}d}"
        params = {
            "chat_id": found.chat_id,
            "text": CONFIRM_TEXT.format(code=code),
            "protect_content": True,
        }
        try:
            await _bot_call(self._client, self.token(), "sendMessage", params)
        except (_Failed, EnrolRefused):
            self.end("enrolment_unreachable")
            return
        self._confirm, self.identity, self.state = _sha256(code), found, "seen"
        self._changed.set()
        self._changed = asyncio.Event()


def _presenter(message: Mapping[str, Any]) -> Identity | None:
    """Who sent ``message``, in their private chat with the bot; None for any other chat, or a
    bot."""
    chat, sender = message.get("chat"), message.get("from")
    if not isinstance(chat, dict) or not isinstance(sender, dict):
        return None
    if chat.get("type") != "private" or sender.get("is_bot") is not False:
        return None
    user_id, chat_id = sender.get("id"), chat.get("id")
    if not isinstance(user_id, int) or not isinstance(chat_id, int):
        return None
    if isinstance(user_id, bool) or isinstance(chat_id, bool) or min(user_id, chat_id) < 1:
        return None
    names = (sender.get("first_name"), sender.get("last_name"))
    name = " ".join(part for part in names if isinstance(part, str) and part)
    username = sender.get("username")
    return Identity(user_id, chat_id, name, username if isinstance(username, str) else None)


def enrolment_lines(secret: str, identity: Identity, timeout: int, block_seconds: int) -> list[str]:
    """The policy lines an enrolment found (G.8 step 5, J1), with the approvers block's waits
    as the running policy has them."""
    telegram = (
        f"{{bot_token: {STORE_PREFIX}{secret}, user_id: {identity.user_id}, "
        f"chat_id: {identity.chat_id}}}"
    )
    return [
        "approvers:",
        f"  telegram: {telegram}",
        f"  timeout: {timeout}",
        f"  block_seconds: {block_seconds}",
    ]


async def _bot_call(
    client: httpx.AsyncClient, token: str, method: str, params: dict[str, Any]
) -> Any:
    """One Bot API call: its ``result``, or :class:`_Failed` with nothing of the URL or the
    answer's text (G.1, contract 67)."""
    try:
        url = telegramwire.method_url(token, method)
    except ValueError:
        raise _Failed(0, "bad_token") from None
    try:
        response = await client.post(url.reveal(), json=params)
    except httpx.HTTPError as exc:
        raise _Failed(0, type(exc).__name__) from None
    status = response.status_code
    try:
        body = response.json()
    except ValueError:
        raise _Failed(status, "unreadable") from None
    if not isinstance(body, dict) or body.get("ok") is not True:
        retry = None
        parameters = body.get("parameters") if isinstance(body, dict) else None
        if isinstance(parameters, dict):
            found = parameters.get("retry_after")
            if isinstance(found, int) and not isinstance(found, bool) and found >= 0:
                retry = found
        raise _Failed(status if status != 200 else 0, "refused", retry)
    return body.get("result")


def _sha256(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8")).digest()


def _failure(exc: Exception) -> _Failed:
    """Any exception from a Bot API call as a failure: its type name alone."""
    if isinstance(exc, _Failed):
        return exc
    return _Failed(0, "token_missing" if isinstance(exc, _NoToken) else type(exc).__name__)


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
