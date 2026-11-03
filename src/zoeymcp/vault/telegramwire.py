"""The Telegram approver's wire rules (M8 design G.1, G.4, G.5; Z13, Z14, Z15). Pure, standard
library only, mutation-tested.

``vault/telegram.py`` sends, polls and edits (step 14); every rule it follows is here, so each one
is tested without a network:

- **The URL** (G.1, G-8). The bot token sits in the Bot API's URL path, so :func:`method_url`
  returns a :class:`SecretUrl`: its ``str`` and ``repr`` show ``/bot<redacted>/<method>`` and
  logging it raises. :meth:`SecretUrl.reveal` gives the real URL, for the transport call only.
- **A prompt** (G.4, Z14). :func:`message` is the composed text unchanged, in one ``pre`` entity
  with no ``parse_mode``, previews off, ``protect_content``, and two buttons, Deny then Approve,
  each carrying ``v1.<id>.<a|d>.<mac>`` (:data:`CALLBACK_BYTES`). A text over
  :data:`TELEGRAM_MAX_UTF16` UTF-16 code units isn't sent, nor split or cut (:func:`too_long`):
  when the portal's queue is among the hold's surfaces Telegram gets a notice pointing there, and
  otherwise the hold is refused :data:`TOO_LONG` before anyone is asked
  (:func:`refused_too_long`, before the hold is begun). :func:`sent` reads what
  ``sendMessage`` returned: the text must come back exactly as sent, else :data:`TEXT_CHANGED`.
- **A press** (G.5, Z13). :func:`press` runs checks 1 to 7 in order and refuses on the first that
  fails. Check 8 (the hold is still held, unexpired and shown on Telegram) is
  ``HoldTable.decide``'s, which also lets only the first valid decision win; a press naming a hold
  this surface has no message for is refused ``not_pending``, as check 8 would refuse it.

The callback MAC's key is 32 random bytes made at the vault's start and kept in memory
(:func:`new_key`, C-3), so a button from before a restart fails check 7.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, ClassVar, Final, Literal

from ..common.logs import refuse_type
from .holds import Hold

Decision = Literal["approve", "deny"]
# (label, callback_data), in the order shown.
Button = tuple[str, str]
PressReason = Literal[
    # 1. a callback query from the enrolled user, who isn't a bot
    "not_callback",
    "wrong_user",
    "from_bot",
    # 2. on an accessible message in the enrolled private chat
    "no_message",
    "inaccessible",
    "wrong_chat",
    "not_private",
    # 3. callback data the vault writes
    "bad_data",
    # 4. a hold this surface sent a message for (else check 8's answer), and that message
    "not_pending",
    "wrong_message",
    # 5, 6, 6b. the message as sent: never edited, its text, its keyboard
    "edited",
    "text_changed",
    "markup_changed",
    # 7. the MAC under this process's key
    "bad_mac",
]

API: Final = "https://api.telegram.org"
TELEGRAM_MAX_UTF16: Final = 4096  # sendMessage's limit on a text, in UTF-16 code units
CALLBACK_BYTES: Final = 38  # v1.<16>.<a|d>.<16>, under callback_data's 64
KEY_BYTES: Final = 32
MAC_BYTES: Final = 12  # 16 base64url characters
MAC_CONTEXT: Final = b"zoeymcp/telegram/v1\n"
# The hold refusals (M.2), with the status each answers the gateway with.
TOO_LONG: Final = "telegram_too_long"
TOO_LONG_STATUS: Final = 422
TEXT_CHANGED: Final = "telegram_text_changed"
TEXT_CHANGED_STATUS: Final = 502
# The two buttons, Deny first (G.4); no other button exists.
LABELS: Final[tuple[tuple[str, Literal["d", "a"]], ...]] = (("Deny", "d"), ("Approve", "a"))
DECISIONS: Final[Mapping[str, Decision]] = {"a": "approve", "d": "deny"}
# What answerCallbackQuery tells the presser (G.5, G.6).
ANSWERS: Final[Mapping[Decision, str]] = {"approve": "Approved", "deny": "Denied"}
NOT_PENDING: Final = "This request is no longer pending"
REFUSED: Final = "Refused: this button doesn't match the request the vault sent"
# Checks 1 and 2: a press from anyone but the operator, in their chat, gets no answer at all.
STRANGER: Final[frozenset[PressReason]] = frozenset(
    {
        "not_callback",
        "wrong_user",
        "from_bot",
        "no_message",
        "inaccessible",
        "wrong_chat",
        "not_private",
    }
)

_METHOD: Final = re.compile(r"[A-Za-z]{1,64}")
_TOKEN: Final = re.compile(r"[0-9]{1,20}:[A-Za-z0-9_-]{1,128}")
_ID: Final = re.compile(r"[A-Za-z0-9_-]{16}")
_DATA: Final = re.compile(r"v1\.([A-Za-z0-9_-]{16})\.([ad])\.([A-Za-z0-9_-]{16})")


# --- the URL -------------------------------------------------------------------------------------


class SecretUrl:
    """A Bot API method's URL, which holds the bot token (G.1, G-8). Its ``str`` and ``repr``
    show the token as ``<redacted>``, and logging it raises: only :meth:`reveal` gives the URL,
    inside the transport call, and the URL is never stored, formatted or logged."""

    __slots__ = ("_method", "_token")

    def __init__(self, token: str, method: str) -> None:
        # Neither shape is shown: a token that isn't one is still a secret.
        if not _TOKEN.fullmatch(token):
            raise ValueError("the bot token isn't <bot id>:<secret>")
        if not _METHOD.fullmatch(method):
            raise ValueError("a Bot API method is a name of letters")
        self._token = token
        self._method = method

    @property
    def method(self) -> str:
        return self._method

    def reveal(self) -> str:
        """The real URL, for the transport call alone."""
        return f"{API}/bot{self._token}/{self._method}"

    def __str__(self) -> str:
        return f"{API}/bot<redacted>/{self._method}"

    def __repr__(self) -> str:
        return f"SecretUrl({self})"


refuse_type(SecretUrl)


def method_url(token: str, method: str) -> SecretUrl:
    """The URL of the Bot API's ``method`` for the bot ``token`` (G.1)."""
    return SecretUrl(token, method)


def bot_id(value: str) -> str | None:
    """The bot id of a value shaped as a bot token, the digits before its ``:``, or None for
    any other value (G.7's ``approver_token_shared``: another secret holding the same bot)."""
    return value.partition(":")[0] if _TOKEN.fullmatch(value) else None


# --- a prompt ------------------------------------------------------------------------------------


def utf16_len(text: str) -> int:
    """``text``'s length in UTF-16 code units, as Telegram counts a text and an entity's offset
    and length: a character outside the Basic Multilingual Plane is two."""
    return len(text.encode("utf-16-le", "surrogatepass")) // 2


def fits(text: str) -> bool:
    """Whether ``text`` is short enough for one Telegram message (G.4, Z14)."""
    return utf16_len(text) <= TELEGRAM_MAX_UTF16


def new_key() -> bytes:
    """The callback MAC's key: :data:`KEY_BYTES` random bytes, made at start, memory only (C-3)."""
    return secrets.token_bytes(KEY_BYTES)


def mac(key: bytes, id: str, decision: str, text_sha256: str) -> str:
    """The callback's MAC over the hold's id, the decision and the text's digest (G.5 check 7):
    HMAC-SHA256's first :data:`MAC_BYTES` bytes, base64url."""
    data = MAC_CONTEXT + f"{id}{decision}{text_sha256}".encode()
    digest = hmac.new(key, data, hashlib.sha256).digest()[:MAC_BYTES]
    return base64.urlsafe_b64encode(digest).decode()


def callback_data(key: bytes, id: str, decision: Literal["a", "d"], text_sha256: str) -> str:
    """``v1.<id>.<a|d>.<mac>``, :data:`CALLBACK_BYTES` bytes."""
    if not _ID.fullmatch(id):
        raise ValueError("a hold's id is 16 base64url characters")
    return f"v1.{id}.{decision}.{mac(key, id, decision, text_sha256)}"


def keyboard(key: bytes, id: str, text_sha256: str) -> tuple[Button, ...]:
    """The prompt's two buttons, Deny then Approve, each bound to the hold and its text."""
    return tuple((label, callback_data(key, id, d, text_sha256)) for label, d in LABELS)


def markup(buttons: tuple[Button, ...]) -> dict[str, Any]:
    """The ``reply_markup`` of ``buttons``, one row, as sent and as Telegram returns it."""
    return {"inline_keyboard": [[{"text": text, "callback_data": data} for text, data in buttons]]}


@dataclass(frozen=True, repr=False)
class Message:
    """What ``sendMessage`` is given, the chat aside: a prompt, with its buttons, or a notice,
    with none. Logging it raises: a prompt holds the approval text (Z14)."""

    text: str
    buttons: tuple[Button, ...] = ()

    def __repr__(self) -> str:
        return f"Message(<{len(self.text)} characters>, buttons={len(self.buttons)})"

    def params(self, chat_id: int) -> dict[str, Any]:
        """``sendMessage``'s parameters: no ``parse_mode`` (no markup is read from the text),
        previews off and ``protect_content``; a prompt's text is one ``pre`` entity, whole."""
        params: dict[str, Any] = {
            "chat_id": chat_id,
            "text": self.text,
            "link_preview_options": {"is_disabled": True},
            "protect_content": True,
        }
        if self.buttons:
            params["entities"] = [{"type": "pre", "offset": 0, "length": utf16_len(self.text)}]
            params["reply_markup"] = markup(self.buttons)
        return params


refuse_type(Message)


@dataclass(frozen=True)
class TooLong:
    """The hold's text is over :data:`TELEGRAM_MAX_UTF16` (G.4), so its prompt isn't sent.
    ``notice`` is what Telegram gets instead when the portal's queue shows the hold; with none,
    the hold is refused :data:`TOO_LONG`, before anyone is asked."""

    notice: Message | None

    code: ClassVar[str] = TOO_LONG
    status: ClassVar[int] = TOO_LONG_STATUS


def refused_too_long(text: str, surfaces: Collection[str]) -> bool:
    """Whether a call whose composed text is ``text``, asked on ``surfaces``, is refused
    :data:`TOO_LONG` (G.4): Telegram can't carry it and no portal queue takes it. It needs no
    hold, so the vault checks it before ``HoldTable.begin``: nobody is asked, the ref isn't used
    and the call doesn't count against the caps, as when the text breaks a text rule."""
    return "telegram" in surfaces and "portal" not in surfaces and not fits(text)


def too_long(hold: Hold) -> TooLong | None:
    """Whether ``hold``'s prompt can't be sent to Telegram, and what is done instead (G.4). A
    :class:`TooLong` with no notice is :func:`refused_too_long`'s case, which the vault refuses
    before the hold is begun, so only a hold the portal also shows gets here over the limit."""
    if fits(hold.text.value):
        return None
    if "portal" not in hold.surfaces:
        return TooLong(None)
    notice = (
        f"Approval request {hold.ref}: {hold.server} \N{RIGHTWARDS ARROW} {hold.tool}. "
        "This one is too long for this chat; decide it in the portal."
    )
    return TooLong(Message(notice))


def message(hold: Hold, key: bytes) -> Message | TooLong:
    """``hold``'s prompt: its composed text exactly, and its two buttons (G.4)."""
    over = too_long(hold)
    if over is not None:
        return over
    return Message(hold.text.value, keyboard(key, hold.id, hold.text_sha256))


@dataclass(frozen=True, repr=False)
class Sent:
    """A prompt Telegram took (G.4): what a press on it is checked against. ``text_sha256`` is
    the digest of the text Telegram returned, which is the text sent. Logging it raises: its
    buttons carry their MACs (O.6)."""

    message_id: int
    chat_id: int
    text_sha256: str
    buttons: tuple[Button, ...]

    def __repr__(self) -> str:
        return f"Sent(message_id={self.message_id})"


refuse_type(Sent)


@dataclass(frozen=True)
class TextChanged:
    """``sendMessage`` returned another message than the one sent (G.4): the vault deletes it,
    when its ``message_id`` is known, and refuses the hold :data:`TEXT_CHANGED`, since the
    operator would read something else."""

    message_id: int | None

    code: ClassVar[str] = TEXT_CHANGED
    status: ClassVar[int] = TEXT_CHANGED_STATUS


def sent(sent_message: Message, chat_id: int, result: object) -> Sent | TextChanged:
    """Read ``sendMessage``'s ``result`` for ``sent_message``, sent to ``chat_id``: its message
    id, in that chat, with the text exactly as sent. The composed text has no leading or trailing
    whitespace and the Bot API documents no trim, so any difference is a change."""
    if not isinstance(result, dict):
        return TextChanged(None)
    message_id = _int(result.get("message_id"))
    if message_id is None:
        return TextChanged(None)
    chat = result.get("chat")
    if not isinstance(chat, dict) or _int(chat.get("id")) != chat_id:
        return TextChanged(message_id)
    text = result.get("text")
    if not isinstance(text, str) or text != sent_message.text:
        return TextChanged(message_id)
    return Sent(message_id, chat_id, _digest(text), sent_message.buttons)


# --- a press -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Enrolled:
    """The approver's enrolled identities (``approvers.telegram``): the operator's account, and
    their private chat with the bot."""

    user_id: int
    chat_id: int


@dataclass(frozen=True)
class Press:
    """A press that passed checks 1 to 7, for ``HoldTable.decide`` (check 8)."""

    query_id: str  # for answerCallbackQuery
    hold_id: str
    decision: Decision
    text_sha256: str
    message_id: int

    @property
    def answer(self) -> str:
        """What answerCallbackQuery says once the decision is taken."""
        return ANSWERS[self.decision]


@dataclass(frozen=True)
class PressRefusal:
    """Why a press is refused, logged by its reason only (G.5). From check 3 on it names the
    pressed message, and from check 4 on the hold the press names, for G.6's edit."""

    reason: PressReason
    query_id: str | None = None
    message_id: int | None = None
    hold_id: str | None = None

    @property
    def answer(self) -> str | None:
        """What answerCallbackQuery says: nothing at all to a stranger (checks 1 and 2)."""
        if self.reason in STRANGER:
            return None
        return NOT_PENDING if self.reason == "not_pending" else REFUSED


def press(
    update: object, enrolled: Enrolled, stored: Mapping[str, Sent], key: bytes
) -> Press | PressRefusal:
    """G.5's checks 1 to 7 on one update, in order, refusing on the first that fails. ``stored``
    maps a hold's id to the prompt sent for it."""
    query = update.get("callback_query") if isinstance(update, dict) else None
    query_id = query.get("id") if isinstance(query, dict) else None
    if not isinstance(query, dict) or not isinstance(query_id, str):
        return PressRefusal("not_callback")
    # 1. From the enrolled user, who isn't a bot.
    sender = query.get("from")
    if not isinstance(sender, dict) or _int(sender.get("id")) != enrolled.user_id:
        return PressRefusal("wrong_user", query_id)
    if sender.get("is_bot") is not False:
        return PressRefusal("from_bot", query_id)
    # 2. On an accessible message (an inaccessible one has date 0) in the enrolled private chat.
    found = query.get("message")
    if not isinstance(found, dict):
        return PressRefusal("no_message", query_id)
    date = _int(found.get("date"))
    if date is None or date <= 0:
        return PressRefusal("inaccessible", query_id)
    chat = found.get("chat")
    if not isinstance(chat, dict) or _int(chat.get("id")) != enrolled.chat_id:
        return PressRefusal("wrong_chat", query_id)
    if chat.get("type") != "private":
        return PressRefusal("not_private", query_id)
    message_id = _int(found.get("message_id"))
    # 3. v1.<id>.<a|d>.<mac>.
    data = query.get("data")
    parsed = _DATA.fullmatch(data) if isinstance(data, str) else None
    if parsed is None:
        return PressRefusal("bad_data", query_id, message_id)
    hold_id, letter, given = parsed.groups()
    # 4. The message this surface sent for that hold.
    prompt = stored.get(hold_id)
    if prompt is None:
        return PressRefusal("not_pending", query_id, message_id, hold_id)
    if message_id != prompt.message_id:
        return PressRefusal("wrong_message", query_id, message_id, hold_id)
    # 5. Never edited: the vault edits a prompt only once it is decided.
    if "edit_date" in found:
        return PressRefusal("edited", query_id, message_id, hold_id)
    # 6. Its text, as Telegram returned it when sent.
    text = found.get("text")
    if not isinstance(text, str) or _digest(text) != prompt.text_sha256:
        return PressRefusal("text_changed", query_id, message_id, hold_id)
    # 6b. Its keyboard, as sent: labels, order and data (editMessageReplyMarkup may not set
    # edit_date, so check 5 isn't relied on for it).
    if found.get("reply_markup") != markup(prompt.buttons):
        return PressRefusal("markup_changed", query_id, message_id, hold_id)
    # 7. The MAC under this process's key, over the hold, the decision and the text.
    expected = mac(key, hold_id, letter, prompt.text_sha256)
    if not hmac.compare_digest(given, expected):
        return PressRefusal("bad_mac", query_id, message_id, hold_id)
    return Press(query_id, hold_id, DECISIONS[letter], prompt.text_sha256, prompt.message_id)


def _int(value: object) -> int | None:
    """A JSON integer, never a boolean."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _digest(text: str) -> str:
    """SHA-256 of ``text``'s UTF-8, as the vault digests a hold's text; a lone surrogate (which
    JSON can carry) is kept, so it digests differently from any text the vault composed."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
