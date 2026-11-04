"""A fake Telegram Bot API, the approver's chat service for the vault's tests (M8 design O.1).

It grew from the S3 shape's ``TelegramFake`` (``tests/acceptance/fakes.py``), which now delegates
to it. Every method lives at ``/bot<token>/<method>``, as on the real service; another token gets
401, and an unknown method 404 with the path in its description (as some real APIs echo it, so a
test can show the vault scrubs it). Parameters come as a query string, a form or a JSON body, and
answers are the Bot API's ``{"ok": ..., "result": ...}`` or ``{"ok": false, "error_code": ...,
"description": ..., "parameters": {"retry_after": ...}}``. It runs in process (``httpx``'s ASGI
transport, or ``harness.serve`` with TLS) and never reaches a real host.

The methods the approver uses:

- ``getMe``: the bot, its id the token's numeric prefix, with ``can_manage_bots``;
- ``getWebhookInfo``, and ``setWebhook`` and ``deleteWebhook`` for a token holder;
- ``sendMessage``: stores the message and returns it with the text exactly as sent (the Bot API
  documents no trim, SC-11), refusing an empty text, one over 4,096 UTF-16 code units, entities
  outside the text, and an inline keyboard whose ``callback_data`` isn't 1-64 bytes. Each send
  records what O.1 checks: previews off (``link_preview_options.is_disabled``),
  ``protect_content``, and exactly one ``pre`` entity over the whole text with no ``parse_mode``;
- ``getUpdates``: a long poll (``timeout``, each of its seconds lasting ``second`` here) that
  answers as soon as an update is queued; ``offset`` confirms every earlier update, a negative one
  keeps only that many from the end and forgets the rest; ``limit`` caps the answer; and
  ``allowed_updates`` is kept server-side and applies only to updates created after the call (an
  update the bot doesn't want when it is made is dropped, into :attr:`BotApi.dropped`). A second
  ``getUpdates`` while one waits ends the waiting one with 409, as Telegram does;
- ``editMessageText`` (a new text, and the keyboard it is given or none), which sets
  ``edit_date``; ``editMessageReplyMarkup``, which sets it too unless ``MARKUP_EDIT_UNDATED``;
  ``deleteMessage``; ``answerCallbackQuery``, once per query.

Flood control is per chat across the writing methods (``sendMessage``, both edits,
``deleteMessage``; ``answerCallbackQuery`` is exempt): a write within ``flood_interval`` of the
chat's last one gets 429 with ``retry_after``, and so does every write until that window ends.
:class:`Switch` holds the scripted faults (409 from another consumer, a foreign webhook, 429 on a
send or an edit, 403 on a send, an outage, a changed text) and variants; each is read per request.

The people are :class:`Person` accounts, each with its private chat with the bot (the chat id is
the user id). :attr:`BotApi.operator` is the scripted operator: it presses a prompt's buttons,
sends ``/start <code>`` and reads the 6-digit confirmation code the bot sent it.
:attr:`BotApi.attacker` holds the token and an account of its own made to look like the
operator's: it edits a message's text or keyboard, presses from its own account in the operator's
chat or from its own chat, replays a stale ``callback_data``, sends a look-alike prompt, and
reads, confirms and re-presents an enrolment code (its read is a ``getUpdates`` call, so it ends a
long poll waiting at that moment with 409, and goes unnoticed in a gap between polls).

For a fake in another process (``run_telegram.py``), three routes outside the Bot API drive the
operator: ``GET /_fake/messages`` lists the stored messages with what each send asked for, ``POST
/_fake/press`` with ``{"message_id", "label"}`` presses a button, and ``POST /_fake/start`` with
``{"code"}`` sends ``/start <code>``.
"""

from __future__ import annotations

import enum
import itertools
import json
import math
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import parse_qsl

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

Clock = Callable[[], float]
Json = dict[str, Any]

BOT_USERNAME: Final = "example_bot"
BOT_NAME: Final = "ZoeyMCP approvals"
# A token with no numeric prefix (not a real token's shape) gets this bot id.
DEFAULT_BOT_ID: Final = 42
FIRST_UPDATE_ID: Final = 100_000
MAX_TEXT: Final = 4096  # UTF-16 code units
MAX_CALLBACK_DATA: Final = 64  # bytes
MAX_LIMIT: Final = 100
FOREIGN_WEBHOOK: Final = "https://attacker.example/telegram-hook"
# Telegram's flood control allows about one message a second in a chat.
FLOOD_INTERVAL: Final = 1.0
# The window the 429 switches open.
RETRY_AFTER: Final = 3
# How often a waiting long poll looks at the queue.
POLL_TICK: Final = 0.01
# A bot that never named its update types gets every one but these (the Bot API's default).
NOT_BY_DEFAULT: Final = frozenset({"chat_member", "message_reaction", "message_reaction_count"})
CONFIRMATION: Final = re.compile(r"\b(\d{6})\b")

CONFLICT_POLL: Final = (
    "Conflict: terminated by other getUpdates request; make sure that only one bot instance is "
    "running"
)
CONFLICT_WEBHOOK: Final = (
    "Conflict: can't use getUpdates method while webhook is active; use deleteWebhook to delete "
    "the webhook first"
)
NOT_MODIFIED: Final = (
    "Bad Request: message is not modified: specified new message content and reply markup are "
    "exactly the same as a current content and reply markup of the message"
)
QUERY_INVALID: Final = (
    "Bad Request: query is too old and response timeout expired or query ID is invalid"
)
OUTAGE_PAGE: Final = (
    b"<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n"
    b"<center><h1>502 Bad Gateway</h1></center>\r\n</body>\r\n</html>\r\n"
)


class Switch(enum.StrEnum):
    """One scripted fault or variant (O.1)."""

    # getUpdates: 409, as when another program polls the same token.
    CONFLICT = "conflict"
    # A webhook the vault didn't set: getWebhookInfo names it and getUpdates gets 409.
    FOREIGN_WEBHOOK = "foreign_webhook"
    # The next send (or edit) opens a flood window of retry_after seconds on its chat, then the
    # switch turns itself off; every write to that chat gets 429 until the window ends.
    RATE_LIMITED_SEND = "rate_limited_send"
    RATE_LIMITED_EDIT = "rate_limited_edit"
    # sendMessage: 403, the user blocked the bot (or never started it).
    FORBIDDEN_SEND = "forbidden_send"
    # Every method: 502 from the front end, an HTML page, not the Bot API's JSON.
    OUTAGE = "outage"
    # sendMessage keeps and returns the text without its last character.
    TEXT_CHANGED = "text_changed"
    # editMessageReplyMarkup leaves edit_date unset. Telegram sets it (M8's live check, D-255);
    # the switch keeps the case a press must refuse by its keyboard alone (FM-37).
    MARKUP_EDIT_UNDATED = "markup_edit_undated"
    # getMe: can_manage_bots is true.
    MANAGES_BOTS = "manages_bots"


@dataclass(frozen=True)
class Person:
    """A Telegram account and its private chat with the bot."""

    id: int
    first_name: str
    username: str | None = None
    is_bot: bool = False

    def user(self) -> Json:
        user: Json = {"id": self.id, "is_bot": self.is_bot, "first_name": self.first_name}
        if self.username is not None:
            user["username"] = self.username
        return user

    def chat(self) -> Json:
        chat: Json = {"id": self.id, "first_name": self.first_name, "type": "private"}
        if self.username is not None:
            chat["username"] = self.username
        return chat


OPERATOR: Final = Person(1001, "Operator", "operator_example")
# Another account made to look like the operator's: the same display name, a username one
# character off.
ATTACKER: Final = Person(2002, "Operator", "operator_examp1e")


class BotError(Exception):
    """A Bot API refusal: its status, description and any ``retry_after``."""

    def __init__(self, status: int, description: str, retry_after: int | None = None) -> None:
        super().__init__(description)
        self.status = status
        self.description = description
        self.retry_after = retry_after


@dataclass
class Stored:
    """One message in a chat, as the fake keeps it."""

    chat: Json
    message_id: int
    sender: Json
    date: int
    text: str
    from_bot: bool
    entities: list[Json] | None = None
    reply_markup: Json | None = None
    edit_date: int | None = None
    deleted: bool = False
    # What the send asked for (O.1).
    previews_off: bool = False
    protected: bool = False
    single_pre: bool = False

    @property
    def chat_id(self) -> int:
        chat_id: int = self.chat["id"]
        return chat_id

    def wire(self) -> Json:
        """The ``Message`` object the Bot API returns for it."""
        message: Json = {
            "message_id": self.message_id,
            "from": self.sender,
            "chat": self.chat,
            "date": self.date,
        }
        if self.edit_date is not None:
            message["edit_date"] = self.edit_date
        if self.protected:
            message["has_protected_content"] = True
        message["text"] = self.text
        if self.entities:
            message["entities"] = self.entities
        if self.previews_off:
            message["link_preview_options"] = {"is_disabled": True}
        if self.reply_markup is not None:
            message["reply_markup"] = self.reply_markup
        return message

    def buttons(self) -> list[Json]:
        if self.reply_markup is None:
            return []
        return [button for row in self.reply_markup["inline_keyboard"] for button in row]

    def labels(self) -> list[str]:
        return [str(button["text"]) for button in self.buttons()]

    def data_for(self, label: str) -> str:
        for button in self.buttons():
            if button["text"] == label:
                return str(button["callback_data"])
        raise LookupError(f"no button {label!r} on message {self.message_id}")

    def record(self) -> Json:
        """What the control route shows of it."""
        return {
            "chat_id": self.chat_id,
            "message_id": self.message_id,
            "from_bot": self.from_bot,
            "text": self.text,
            "labels": self.labels(),
            "edited": self.edit_date is not None,
            "deleted": self.deleted,
            "previews_off": self.previews_off,
            "protected": self.protected,
            "single_pre": self.single_pre,
        }


@dataclass(frozen=True)
class Update:
    update_id: int
    kind: str
    body: Json

    def wire(self) -> Json:
        return {"update_id": self.update_id, self.kind: self.body}


@dataclass
class Call:
    """One Bot API request: its method, its parameters as parsed, and the status answered."""

    method: str
    params: Json
    status: int = 0


@dataclass
class Poll:
    """One ``getUpdates``: what it asked, and the update ids it got (None: refused)."""

    offset: int | None
    limit: int
    timeout: int
    allowed_updates: list[str] | None
    returned: list[int] | None = None


@dataclass(frozen=True)
class Answered:
    """One ``answerCallbackQuery``."""

    query_id: str
    text: str | None
    show_alert: bool


def utf16_len(text: str) -> int:
    """The length Telegram counts: UTF-16 code units."""
    return len(text.encode("utf-16-le")) // 2


@dataclass
class BotApi:
    """The fake Bot API for one bot, its token ``token``. ``app()`` serves it."""

    token: str
    switches: set[Switch] = field(default_factory=set)
    clock: Clock = time.time
    flood_interval: float | None = FLOOD_INTERVAL
    retry_after: int = RETRY_AFTER
    # How long one second of a getUpdates timeout lasts, so a test can poll briefly.
    second: float = 1.0
    operator_account: Person = OPERATOR
    attacker_account: Person = ATTACKER

    calls: list[Call] = field(default_factory=list)
    polls: list[Poll] = field(default_factory=list)
    messages: dict[tuple[int, int], Stored] = field(default_factory=dict)
    # Updates queued and not yet confirmed, oldest first; and those the bot didn't want.
    updates: list[Update] = field(default_factory=list)
    dropped: list[Update] = field(default_factory=list)
    answers: list[Answered] = field(default_factory=list)
    webhook_url: str = ""

    # None: the bot never named its update types.
    _allowed: frozenset[str] | None = field(default=None, repr=False)
    _update_ids: itertools.count[int] = field(
        default_factory=lambda: itertools.count(FIRST_UPDATE_ID), repr=False
    )
    _query_ids: itertools.count[int] = field(default_factory=itertools.count, repr=False)
    _message_ids: dict[int, int] = field(default_factory=dict, repr=False)
    # Each callback query's id, and whether it was answered.
    _queries: dict[str, bool] = field(default_factory=dict, repr=False)
    _last_write: dict[int, float] = field(default_factory=dict, repr=False)
    _windows: dict[int, float] = field(default_factory=dict, repr=False)
    _poll_generation: int = field(default=0, repr=False)
    # Set when the next getUpdates begins, made only while a test awaits :meth:`poll_began`.
    _poll_event: anyio.Event | None = field(default=None, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    # --- the app ----------------------------------------------------------------------------------

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/_fake/messages", self._control_messages, methods=["GET"]),
                Route("/_fake/press", self._control_press, methods=["POST"]),
                Route("/_fake/start", self._control_start, methods=["POST"]),
                Route("/{bot}/{method}", self.endpoint, methods=["GET", "POST"]),
            ]
        )

    async def endpoint(self, request: Request) -> Response:
        """One Bot API request at ``/{bot}/{method}``."""
        method = request.path_params["method"]
        call = Call(method, {})
        self.calls.append(call)
        try:
            call.params = await _params(request)
            if Switch.OUTAGE in self.switches:
                call.status = 502
                return Response(OUTAGE_PAGE, status_code=502, media_type="text/html")
            if request.path_params["bot"] != f"bot{self.token}":
                raise BotError(401, "Unauthorized")
            if method == "getUpdates":
                result: Any = await self._get_updates(call.params)
            else:
                handler = self._handlers().get(method)
                if handler is None:
                    raise BotError(404, f"Not Found: {request.url.path}")
                result = handler(call.params)
        except BotError as error:
            call.status = error.status
            return _refusal(error)
        call.status = 200
        return JSONResponse({"ok": True, "result": result})

    def _handlers(self) -> Mapping[str, Callable[[Json], Any]]:
        """The methods other than ``getUpdates``, which long-polls."""
        return {
            "getMe": self._get_me,
            "getWebhookInfo": self._get_webhook_info,
            "setWebhook": self._set_webhook,
            "deleteWebhook": self._delete_webhook,
            "sendMessage": self._send_message,
            "editMessageText": self._edit_message_text,
            "editMessageReplyMarkup": self._edit_message_reply_markup,
            "deleteMessage": self._delete_message,
            "answerCallbackQuery": self._answer_callback_query,
        }

    # --- people -----------------------------------------------------------------------------------

    @property
    def bot(self) -> Person:
        prefix = self.token.partition(":")[0]
        bot_id = int(prefix) if prefix.isdigit() else DEFAULT_BOT_ID
        return Person(bot_id, BOT_NAME, BOT_USERNAME, is_bot=True)

    @property
    def operator(self) -> Operator:
        return Operator(self, self.operator_account)

    @property
    def attacker(self) -> Attacker:
        return Attacker(self, self.attacker_account, self.operator_account)

    def chat_of(self, chat_id: int) -> Json:
        for person in (self.operator_account, self.attacker_account):
            if person.id == chat_id:
                return person.chat()
        return {"id": chat_id, "first_name": f"Chat {chat_id}", "type": "private"}

    # --- the methods ------------------------------------------------------------------------------

    def _get_me(self, params: Json) -> Json:
        return {
            **self.bot.user(),
            "can_join_groups": True,
            "can_read_all_group_messages": False,
            "supports_inline_queries": False,
            "can_connect_to_business": False,
            "has_main_web_app": False,
            "can_manage_bots": Switch.MANAGES_BOTS in self.switches,
        }

    @property
    def webhook(self) -> str:
        return FOREIGN_WEBHOOK if Switch.FOREIGN_WEBHOOK in self.switches else self.webhook_url

    def _get_webhook_info(self, params: Json) -> Json:
        info: Json = {
            "url": self.webhook,
            "has_custom_certificate": False,
            "pending_update_count": len(self.updates),
        }
        if self.webhook:
            info["max_connections"] = 40
        return info

    def _set_webhook(self, params: Json) -> bool:
        url = params.get("url")
        if not isinstance(url, str):
            raise BotError(400, "Bad Request: bad webhook: URL must be a string")
        self.webhook_url = url
        return True

    def _delete_webhook(self, params: Json) -> bool:
        with self._lock:
            self.webhook_url = ""
            if _flag(params, "drop_pending_updates"):
                self.updates.clear()
        return True

    def _send_message(self, params: Json, *, limited: bool = True) -> Json:
        chat_id = _integer(params, "chat_id", "Bad Request: chat_id is empty")
        text = _text(params)
        entities = _entities(params, text)
        markup = _markup(params)
        parse_mode = params.get("parse_mode")
        previews = _object(params, "link_preview_options")
        if Switch.FORBIDDEN_SEND in self.switches and limited:
            raise BotError(403, "Forbidden: bot was blocked by the user")
        with self._lock:
            if limited:
                self._write(chat_id, Switch.RATE_LIMITED_SEND)
            kept = text[:-1] if Switch.TEXT_CHANGED in self.switches else text
            stored = Stored(
                chat=self.chat_of(chat_id),
                message_id=self._next_message_id(chat_id),
                sender=self.bot.user(),
                date=int(self.clock()),
                text=kept,
                from_bot=True,
                entities=entities,
                reply_markup=markup,
                previews_off=previews is not None and previews.get("is_disabled") is True,
                protected=_flag(params, "protect_content"),
                single_pre=parse_mode is None
                and entities == [{"type": "pre", "offset": 0, "length": utf16_len(text)}],
            )
            self.messages[(chat_id, stored.message_id)] = stored
        return stored.wire()

    async def _get_updates(self, params: Json) -> list[Json]:
        if self.webhook:
            raise BotError(409, CONFLICT_WEBHOOK)
        if Switch.CONFLICT in self.switches:
            raise BotError(409, CONFLICT_POLL)
        offset = _integer(params, "offset", None)
        limit = min(max(_integer(params, "limit", None) or MAX_LIMIT, 1), MAX_LIMIT)
        timeout = max(_integer(params, "timeout", None) or 0, 0)
        allowed = params.get("allowed_updates")
        if isinstance(allowed, str):
            allowed = _loads(allowed, "allowed_updates")
        if allowed is not None and not (
            isinstance(allowed, list) and all(isinstance(kind, str) for kind in allowed)
        ):
            raise BotError(400, "Bad Request: can't parse allowed_updates")
        poll = Poll(offset, limit, timeout, allowed)
        with self._lock:
            self.polls.append(poll)
            if self._poll_event is not None:
                self._poll_event.set()
                self._poll_event = None
            generation = self._begin_poll()
            if allowed is not None:
                self._allowed = frozenset(allowed) if allowed else None
            self._confirm(offset)
        deadline = time.monotonic() + timeout * self.second
        while True:
            with self._lock:
                if generation != self._poll_generation:
                    raise BotError(409, CONFLICT_POLL)
                found = self.updates[:limit]
            if found or time.monotonic() >= deadline:
                break
            await anyio.sleep(POLL_TICK)
        poll.returned = [update.update_id for update in found]
        return [update.wire() for update in found]

    def _edit_message_text(self, params: Json, *, limited: bool = True) -> Json:
        stored = self._editable(params)
        text = _text(params)
        entities = _entities(params, text)
        markup = _markup(params)
        if (text, entities, markup) == (stored.text, stored.entities, stored.reply_markup):
            raise BotError(400, NOT_MODIFIED)
        with self._lock:
            if limited:
                self._write(stored.chat_id, Switch.RATE_LIMITED_EDIT)
            stored.text, stored.entities, stored.reply_markup = text, entities, markup
            stored.edit_date = int(self.clock())
        return stored.wire()

    def _edit_message_reply_markup(self, params: Json, *, limited: bool = True) -> Json:
        stored = self._editable(params)
        markup = _markup(params)
        if markup == stored.reply_markup:
            raise BotError(400, NOT_MODIFIED)
        with self._lock:
            if limited:
                self._write(stored.chat_id, Switch.RATE_LIMITED_EDIT)
            stored.reply_markup = markup
            if Switch.MARKUP_EDIT_UNDATED not in self.switches:
                stored.edit_date = int(self.clock())
        return stored.wire()

    def _delete_message(self, params: Json) -> bool:
        chat_id = _integer(params, "chat_id", "Bad Request: chat_id is empty")
        message_id = _integer(
            params, "message_id", "Bad Request: message identifier is not specified"
        )
        with self._lock:
            stored = self.messages.get((chat_id, message_id))
            if stored is None or stored.deleted:
                raise BotError(400, "Bad Request: message to delete not found")
            self._write(chat_id, None)
            stored.deleted = True
        return True

    def _answer_callback_query(self, params: Json) -> bool:
        query_id = params.get("callback_query_id")
        text = params.get("text")
        with self._lock:
            if not isinstance(query_id, str) or self._queries.get(query_id) is not False:
                raise BotError(400, QUERY_INVALID)
            self._queries[query_id] = True
            self.answers.append(
                Answered(
                    query_id, text if isinstance(text, str) else None, _flag(params, "show_alert")
                )
            )
        return True

    # --- state ------------------------------------------------------------------------------------

    def _editable(self, params: Json) -> Stored:
        if "chat_id" not in params or "message_id" not in params:
            raise BotError(400, "Bad Request: message identifier is not specified")
        chat_id = _integer(params, "chat_id", "Bad Request: chat_id is empty")
        message_id = _integer(
            params, "message_id", "Bad Request: message identifier is not specified"
        )
        stored = self.messages.get((chat_id, message_id))
        if stored is None or stored.deleted:
            raise BotError(400, "Bad Request: message to edit not found")
        if not stored.from_bot:
            raise BotError(400, "Bad Request: message can't be edited")
        return stored

    def _write(self, chat_id: int, switch: Switch | None) -> None:
        """Flood control for one write to ``chat_id`` (called under the lock): refuse it 429, or
        note it."""
        now = self.clock()
        if switch is not None and switch in self.switches:
            self.switches.discard(switch)
            self._windows[chat_id] = now + self.retry_after
        until = self._windows.get(chat_id, 0.0)
        last = self._last_write.get(chat_id)
        if self.flood_interval is not None and last is not None:
            until = max(until, last + self.flood_interval)
        if now < until:
            self._windows[chat_id] = until
            wait = max(math.ceil(until - now), 1)
            raise BotError(429, f"Too Many Requests: retry after {wait}", retry_after=wait)
        self._last_write[chat_id] = now

    def _next_message_id(self, chat_id: int) -> int:
        self._message_ids[chat_id] = self._message_ids.get(chat_id, 0) + 1
        return self._message_ids[chat_id]

    async def poll_began(self, count: int = 1) -> None:
        """Wait, without sleeping, until ``count`` ``getUpdates`` calls have begun.

        For a test in the fake's own event loop (``httpx.ASGITransport``): the event isn't
        thread-safe, so a fake served from another thread (``harness.serve``) can't wake it.
        """
        while len(self.polls) < count:
            if self._poll_event is None:
                self._poll_event = anyio.Event()
            await self._poll_event.wait()

    def _begin_poll(self) -> int:
        """A ``getUpdates`` began: one still waiting ends with 409. Returns this one's number."""
        self._poll_generation += 1
        return self._poll_generation

    def _confirm(self, offset: int | None) -> None:
        if offset is None or offset == 0:
            return
        if offset > 0:
            self.updates = [update for update in self.updates if update.update_id >= offset]
        else:
            self.updates = self.updates[offset:]

    def _wants(self, kind: str) -> bool:
        if self._allowed is None:
            return kind not in NOT_BY_DEFAULT
        return kind in self._allowed

    def push(self, kind: str, body: Json) -> Update | None:
        """Queue an update of ``kind``, unless the bot's update types leave it out (then it is
        dropped, as Telegram never keeps it). Returns it if queued."""
        with self._lock:
            update = Update(next(self._update_ids), kind, body)
            if not self._wants(kind):
                self.dropped.append(update)
                return None
            self.updates.append(update)
            return update

    def stored(self, chat_id: int, message_id: int) -> Stored:
        stored = self.messages.get((chat_id, message_id))
        if stored is None or stored.deleted:
            raise LookupError(f"no message {message_id} in chat {chat_id}")
        return stored

    def press(
        self,
        message_id: int,
        label: str | None = None,
        *,
        by: Person,
        chat_id: int | None = None,
        data: str | None = None,
        inaccessible: bool = False,
    ) -> Update | None:
        """``by`` presses a button of message ``message_id`` in chat ``chat_id`` (``by``'s own
        unless given): the button labelled ``label``, or one carrying ``data``. An inaccessible
        message comes as Telegram sends one, its ``date`` 0 and nothing else but its chat and
        id."""
        chat_id = by.id if chat_id is None else chat_id
        with self._lock:
            stored = self.stored(chat_id, message_id)
            if data is None:
                if label is None:
                    raise ValueError("a press needs a label or its data")
                data = stored.data_for(label)
            query_id = str(4_000_000_000 + next(self._query_ids))
            message = stored.wire()
            if inaccessible:
                message = {"chat": stored.chat, "message_id": message_id, "date": 0}
            self._queries[query_id] = False
            body = {
                "id": query_id,
                "from": by.user(),
                "message": message,
                "chat_instance": f"instance-{chat_id}",
                "data": data,
            }
            return self.push("callback_query", body)

    def say(self, by: Person, text: str) -> Update | None:
        """``by`` sends ``text`` to the bot in their private chat."""
        with self._lock:
            stored = Stored(
                chat=by.chat(),
                message_id=self._next_message_id(by.id),
                sender=by.user(),
                date=int(self.clock()),
                text=text,
                from_bot=False,
            )
            if text.startswith("/"):
                command = text.split(" ", 1)[0]
                stored.entities = [{"type": "bot_command", "offset": 0, "length": len(command)}]
            self.messages[(by.id, stored.message_id)] = stored
            return self.push("message", stored.wire())

    def sent(self) -> list[Stored]:
        """Every message the bot sent, in order, deleted ones included (a snapshot: the server
        thread may be sending)."""
        with self._lock:
            return [stored for stored in self.messages.values() if stored.from_bot]

    # --- control routes (run_telegram.py) ---------------------------------------------------------

    async def _control_messages(self, request: Request) -> Response:
        with self._lock:
            records = [stored.record() for stored in self.messages.values()]
        return JSONResponse({"messages": records})

    async def _control_press(self, request: Request) -> Response:
        body = await _control_body(request)
        try:
            update = self.operator.press(int(body["message_id"]), str(body["label"]))
        except (KeyError, LookupError, TypeError, ValueError):
            return JSONResponse({"error": "no such message or button"}, status_code=404)
        return JSONResponse({"queued": update is not None})

    async def _control_start(self, request: Request) -> Response:
        body = await _control_body(request)
        code = body.get("code")
        if not isinstance(code, str):
            return JSONResponse({"error": "code must be a string"}, status_code=400)
        return JSONResponse({"queued": self.operator.start(code) is not None})


@dataclass(frozen=True)
class Operator:
    """The scripted operator, from ``account``'s private chat with the bot."""

    api: BotApi
    account: Person

    def messages(self) -> list[Stored]:
        """The bot's messages in the operator's chat, not deleted, oldest first."""
        return [
            stored
            for stored in self.api.sent()
            if stored.chat_id == self.account.id and not stored.deleted
        ]

    def prompts(self) -> list[Stored]:
        """Those with buttons."""
        return [stored for stored in self.messages() if stored.reply_markup is not None]

    def press(self, message_id: int, label: str) -> Update | None:
        return self.api.press(message_id, label, by=self.account)

    def start(self, code: str) -> Update | None:
        return self.api.say(self.account, f"/start {code}")

    def confirmation_code(self) -> str:
        """The 6-digit code in the bot's latest message to the operator that holds one."""
        for stored in reversed(self.messages()):
            found = CONFIRMATION.search(stored.text)
            if found is not None:
                return found.group(1)
        raise LookupError("the bot sent the operator no confirmation code")


@dataclass(frozen=True)
class Attacker:
    """A token holder with an account of its own (``account``), against ``victim``."""

    api: BotApi
    account: Person
    victim: Person

    def edit_text(self, message_id: int, text: str) -> Json:
        """Rewrite a message in the victim's chat; its keyboard goes, as the Bot API does when
        an edit names none, unless it is given back."""
        stored = self.api.stored(self.victim.id, message_id)
        params: Json = {"chat_id": self.victim.id, "message_id": message_id, "text": text}
        if stored.entities is not None:
            params["entities"] = [
                {**entity, "length": utf16_len(text)} if entity["type"] == "pre" else entity
                for entity in stored.entities
            ]
        if stored.reply_markup is not None:
            params["reply_markup"] = stored.reply_markup
        return self.api._edit_message_text(params, limited=False)

    def edit_markup(self, message_id: int, markup: Json) -> Json:
        """Swap a message's keyboard in the victim's chat."""
        params = {"chat_id": self.victim.id, "message_id": message_id, "reply_markup": markup}
        return self.api._edit_message_reply_markup(params, limited=False)

    def press(
        self,
        message_id: int,
        label: str | None = None,
        *,
        data: str | None = None,
        own_chat: bool = False,
    ) -> Update | None:
        """Press from the attacker's account: in the victim's chat, or in its own."""
        chat_id = self.account.id if own_chat else self.victim.id
        return self.api.press(message_id, label, by=self.account, chat_id=chat_id, data=data)

    def look_alike(self, text: str, markup: Json) -> Stored:
        """Send the victim a prompt of the attacker's making."""
        return self._send(self.victim.id, text, markup)

    def copy(self, message_id: int) -> Stored:
        """Send a message of the victim's chat, text and keyboard, to the attacker's own."""
        stored = self.api.stored(self.victim.id, message_id)
        return self._send(self.account.id, stored.text, stored.reply_markup)

    def _send(self, chat_id: int, text: str, markup: Json | None) -> Stored:
        params: Json = {"chat_id": chat_id, "text": text}
        if markup is not None:
            params["reply_markup"] = markup
        sent = self.api._send_message(params, limited=False)
        return self.api.stored(chat_id, int(sent["message_id"]))

    def steal_code(self) -> str:
        """Read the queue for the first ``/start <code>``, confirm through it, and return the
        code. The read is a ``getUpdates`` call: a long poll waiting now ends with 409."""
        with self.api._lock:
            self.api._begin_poll()
            for update in self.api.updates:
                text = update.body.get("text", "") if update.kind == "message" else ""
                if text.startswith("/start "):
                    self.api._confirm(update.update_id + 1)
                    return str(text.removeprefix("/start "))
        raise LookupError("no /start message is queued")

    def present(self, code: str) -> Update | None:
        """Send ``/start <code>`` from the attacker's own account."""
        return self.api.say(self.account, f"/start {code}")

    def set_webhook(self) -> None:
        self.api.webhook_url = FOREIGN_WEBHOOK


def keyboard(*buttons: tuple[str, str]) -> Json:
    """An inline keyboard of one row: ``(label, callback_data)`` pairs."""
    return {"inline_keyboard": [[{"text": text, "callback_data": data} for text, data in buttons]]}


# --- parameters -----------------------------------------------------------------------------------


async def _params(request: Request) -> Json:
    """The request's parameters, from its query string and then its body."""
    params: Json = dict(request.query_params)
    body = await request.body()
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type == "application/json" and body:
        loaded = _loads(body.decode("utf-8", errors="replace"), "the request")
        if not isinstance(loaded, dict):
            raise BotError(400, "Bad Request: the request must be a JSON object")
        params.update(loaded)
    elif content_type == "application/x-www-form-urlencoded":
        params.update(parse_qsl(body.decode("utf-8", errors="replace")))
    return params


def _loads(text: str, name: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        raise BotError(400, f"Bad Request: can't parse {name}") from None


def _integer(params: Json, name: str, missing: str | None) -> Any:
    """``params[name]`` as an integer; absent, a refusal with ``missing``, or None."""
    value = params.get(name)
    if value is None:
        if missing is not None:
            raise BotError(400, missing)
        return None
    if isinstance(value, bool):
        raise BotError(400, f"Bad Request: {name} must be an integer")
    try:
        return int(value)
    except (TypeError, ValueError):
        raise BotError(400, f"Bad Request: {name} must be an integer") from None


def _flag(params: Json, name: str) -> bool:
    value = params.get(name)
    return value is True or value in ("true", "True", "1")


def _object(params: Json, name: str) -> Json | None:
    value = params.get(name)
    if isinstance(value, str):
        value = _loads(value, name)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise BotError(400, f"Bad Request: can't parse {name}")
    return value


def _text(params: Json) -> str:
    text = params.get("text")
    if not isinstance(text, str) or not text:
        raise BotError(400, "Bad Request: message text is empty")
    if utf16_len(text) > MAX_TEXT:
        raise BotError(400, "Bad Request: message is too long")
    return text


def _entities(params: Json, text: str) -> list[Json] | None:
    value = params.get("entities")
    if isinstance(value, str):
        value = _loads(value, "entities")
    if value is None:
        return None
    length = utf16_len(text)
    if not isinstance(value, list) or not all(_entity_fits(entity, length) for entity in value):
        raise BotError(400, "Bad Request: can't parse entities")
    return value


def _entity_fits(entity: Any, length: int) -> bool:
    if not isinstance(entity, dict) or not isinstance(entity.get("type"), str):
        return False
    offset, size = entity.get("offset"), entity.get("length")
    if not isinstance(offset, int) or not isinstance(size, int):
        return False
    return offset >= 0 and size > 0 and offset + size <= length


def _markup(params: Json) -> Json | None:
    markup = _object(params, "reply_markup")
    if markup is None:
        return None
    rows = markup.get("inline_keyboard")
    if not isinstance(rows, list) or not all(isinstance(row, list) for row in rows):
        raise BotError(400, "Bad Request: can't parse reply keyboard markup JSON object")
    for row in rows:
        for button in row:
            if not isinstance(button, dict) or not isinstance(button.get("text"), str):
                raise BotError(400, "Bad Request: can't parse inline keyboard button")
            data = button.get("callback_data")
            if not isinstance(data, str) or not 1 <= len(data.encode()) <= MAX_CALLBACK_DATA:
                raise BotError(400, "Bad Request: BUTTON_DATA_INVALID")
    return markup


def _refusal(error: BotError) -> Response:
    body: Json = {"ok": False, "error_code": error.status, "description": error.description}
    if error.retry_after is not None:
        body["parameters"] = {"retry_after": error.retry_after}
    return JSONResponse(body, status_code=error.status)


async def _control_body(request: Request) -> Json:
    try:
        body = json.loads(await request.body())
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}
