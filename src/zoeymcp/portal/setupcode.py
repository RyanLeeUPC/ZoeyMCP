"""Setup codes (M5 design E): the code, its record and MAC, the typed form, the redeem decision.

Pure, so each rule can be tested. :class:`~zoeymcp.vault.admin.SetupCodes` writes and removes the
record, holds the lock and keeps what happened to the code for ``GET /setup-code/status``.

A code is 15 random bytes in base32, four groups of six (120 bits). Only the SHA-256 of its
grouped form is kept, in ``<state>/setup.json``, with its expiry, whether it was issued with
``--reset``, and a MAC under ``K_portal``, so a writer of ``/state`` without the master key can't
plant a code it knows (T16). A record written before M5 (no ``v``), or one that fails to parse
or verify, is no code. There is no attempt counter: guessing 120 bits is pointless, and a counter
would let anything that reaches the portal burn every code the operator issues (judge error S1).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from base64 import b32encode
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..common.canonical import JSONRejected, dumps_canonical, loads_strict
from ..common.logs import refuse_type
from ..vault.keys import PortalKey

FILE: Final = "setup.json"
VERSION: Final = 1
# How long a code works, in seconds.
TTL: Final = 15 * 60
CODE_BYTES: Final = 15
CODE_CHARS: Final = 24
GROUP: Final = 6
# Typed text longer than this is a wrong code, never normalized.
MAX_TYPED: Final = 64
# A larger record is no code, unread.
MAX_FILE_BYTES: Final = 4096
# Keeps this MAC apart from anything else K_portal authenticates.
_MAC_CONTEXT: Final = b"zoeymcp/setup-code/v1\n"
_FIELDS: Final = frozenset({"v", "key_id", "sha256", "expires", "reset", "mac"})
_BASE32: Final = re.compile(r"[A-Z2-7]{24}")
_SHA256: Final = re.compile(r"[0-9a-f]{64}")

RefusedReason = Literal["no_code", "wrong", "expired"]


class SetupCode:
    """A setup code as issued, in its grouped form. Its ``repr`` hides it; logging it raises."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "SetupCode(<hidden>)"

    __str__ = __repr__


refuse_type(SetupCode)


@dataclass(frozen=True)
class Record:
    """What ``setup.json`` holds of a code: its hash, when it stops working (Unix seconds), and
    whether enrolling with it removes every other passkey."""

    sha256: str = field(repr=False)
    expires: int
    reset: bool


@dataclass(frozen=True)
class Redeemed:
    """The code matched and hadn't expired: the setup session it opens copies ``reset``."""

    expires: int
    reset: bool


@dataclass(frozen=True)
class Refused:
    """One answer to the portal whatever the reason (``setup_code_refused``); the reason is for
    tests and the vault's own decisions, never shown."""

    reason: RefusedReason


# --- the code -----------------------------------------------------------------------------------


def group(raw: str) -> str:
    """24 base32 characters as four groups of six, joined by dashes."""
    return "-".join(raw[i : i + GROUP] for i in range(0, CODE_CHARS, GROUP))


def new_code(random: Callable[[int], bytes]) -> SetupCode:
    """A new code from ``CODE_BYTES`` random bytes: 120 bits, no padding."""
    return SetupCode(group(b32encode(random(CODE_BYTES)).decode("ascii")))


def normalize(typed: object) -> str | None:
    """The grouped form of a typed code, ignoring case, spaces and dashes; None unless exactly 24
    base32 characters remain. Only ASCII is read, so no other letter upper-cases into one."""
    if not isinstance(typed, str) or len(typed) > MAX_TYPED or not typed.isascii():
        return None
    raw = typed.upper().replace(" ", "").replace("-", "")
    if not _BASE32.fullmatch(raw):
        return None
    return group(raw)


def digest(grouped: str) -> str:
    """The SHA-256 the record keeps of a code's grouped form, as hex."""
    return hashlib.sha256(grouped.encode("ascii")).hexdigest()


def new_record(code: SetupCode, *, now: float, reset: bool) -> Record:
    return Record(digest(code.reveal()), int(now) + TTL, reset)


# --- the record ---------------------------------------------------------------------------------


def _mac(content: dict[str, Any], key: PortalKey) -> str:
    return key.mac(_MAC_CONTEXT + dumps_canonical(content)).hex()


def seal(record: Record, key: PortalKey) -> bytes:
    """The record file's bytes: the record and its MAC under ``key``."""
    content: dict[str, Any] = {
        "v": VERSION,
        "key_id": key.key_id,
        "sha256": record.sha256,
        "expires": record.expires,
        "reset": record.reset,
    }
    content["mac"] = _mac(content, key)
    return dumps_canonical(content) + b"\n"


def unseal(data: bytes, key: PortalKey) -> Record | None:
    """The record in a file's bytes, or None for no code: too large, not JSON, a record written
    before M5, another shape, another master key, a MAC that doesn't verify, or values that
    don't fit. A code lasts 15 minutes, so one sealed under a previous master key is no code
    either: issue another."""
    if len(data) > MAX_FILE_BYTES:
        return None
    try:
        content = loads_strict(data)
    except JSONRejected:
        return None
    if not isinstance(content, dict) or content.keys() != _FIELDS:
        return None
    mac = content["mac"]
    if content["key_id"] != key.key_id or not isinstance(mac, str):
        return None
    rest = {name: value for name, value in content.items() if name != "mac"}
    if not hmac.compare_digest(mac.encode(), _mac(rest, key).encode()):
        return None
    sha256, expires, reset = content["sha256"], content["expires"], content["reset"]
    if not (
        type(content["v"]) is int
        and content["v"] == VERSION
        and isinstance(sha256, str)
        and _SHA256.fullmatch(sha256)
        and type(expires) is int
        and expires >= 0
        and type(reset) is bool
    ):
        return None
    return Record(sha256, expires, reset)


# --- redeeming ----------------------------------------------------------------------------------


def decide(record: Record | None, typed: object, now: float) -> Redeemed | Refused:
    """Whether ``typed`` redeems the code ``record`` holds at ``now``: the typed form, then the
    hash compared in constant time, then the expiry (a code stops working at its second). The
    caller removes the record before it acts on :class:`Redeemed`, so a code works once."""
    grouped = normalize(typed)
    if record is None:
        return Refused("no_code")
    candidate = "" if grouped is None else digest(grouped)
    if not hmac.compare_digest(candidate.encode(), record.sha256.encode()):
        return Refused("wrong")
    if now >= record.expires:
        return Refused("expired")
    return Redeemed(record.expires, record.reset)
