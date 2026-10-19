"""The key hierarchy (design §4.5).

``ZOEYMCP_MASTER_KEY`` holds 32 random bytes, base64url-encoded without padding. Every other key
is derived from it with HKDF-SHA256, with a separate context per purpose, so no derived key can
be turned into another or back into the master key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..common.logs import refuse_type

MASTER_KEY_ENV = "ZOEYMCP_MASTER_KEY"
PREVIOUS_MASTER_KEY_ENV = "ZOEYMCP_MASTER_KEY_PREVIOUS"
MASTER_KEY_BYTES = 32
GATEWAY_KEY_PREFIX = "zgw1-"

_SALT = b"zoeymcp/v1"
CONTEXT_STORE = "zoeymcp/store/v1"
CONTEXT_CONFIG = "zoeymcp/config/v1"
CONTEXT_KEY_ID = "zoeymcp/key-id/v1"
CONTEXT_GATEWAY = "zoeymcp/gateway/v1/gen-{generation}"
# The SMTP connector's send journal keys its request digests with this (M4 design J.3).
CONTEXT_AUDIT = "zoeymcp/audit/v1"


class MasterKeyError(ValueError):
    """The master key is missing or malformed."""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def derive(master: bytes, context: str, length: int = 32) -> bytes:
    """HKDF-SHA256 of ``master`` for one purpose."""
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=_SALT, info=context.encode("ascii")
    ).derive(master)


def generate_master_key() -> str:
    """A new master key, in the form ``ZOEYMCP_MASTER_KEY`` expects."""
    return _b64url(os.urandom(MASTER_KEY_BYTES))


def parse_master_key(text: str) -> bytes:
    """Decode a master key, refusing anything that isn't exactly 32 bytes of base64url."""
    if text != text.strip() or not text:
        raise MasterKeyError("the master key is empty or has surrounding whitespace")
    if any(c in text for c in "+/="):
        raise MasterKeyError("the master key must be base64url without padding")
    try:
        # validate=True refuses characters outside the alphabet instead of silently dropping them.
        raw = base64.b64decode(text + "=" * (-len(text) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise MasterKeyError("the master key isn't valid base64url") from exc
    if len(raw) != MASTER_KEY_BYTES:
        raise MasterKeyError(f"the master key must be {MASTER_KEY_BYTES} bytes, not {len(raw)}")
    if _b64url(raw) != text:
        raise MasterKeyError("the master key isn't in canonical base64url form")
    return raw


class AuditKey:
    """The send journal's HMAC key. Its ``repr`` hides it, and logging it raises."""

    __slots__ = ("_key",)

    def __init__(self, key: bytes) -> None:
        self._key = key

    def digest(self, data: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        return "AuditKey(<hidden>)"


refuse_type(AuditKey)


@dataclass(frozen=True)
class KeySet:
    """The keys derived from one master key. ``repr`` never shows key material."""

    store_key: bytes = field(repr=False)
    config_key: bytes = field(repr=False)
    key_id: str
    _master: bytes = field(repr=False)

    @classmethod
    def from_master(cls, master: bytes) -> KeySet:
        if len(master) != MASTER_KEY_BYTES:
            raise MasterKeyError(f"the master key must be {MASTER_KEY_BYTES} bytes")
        return cls(
            store_key=derive(master, CONTEXT_STORE),
            config_key=derive(master, CONTEXT_CONFIG),
            key_id=derive(master, CONTEXT_KEY_ID, 8).hex(),
            _master=master,
        )

    @classmethod
    def from_text(cls, text: str) -> KeySet:
        return cls.from_master(parse_master_key(text))

    @property
    def audit_key(self) -> AuditKey:
        """The key the SMTP connector's send journal digests requests under."""
        return AuditKey(derive(self._master, CONTEXT_AUDIT))

    def gateway_key(self, generation: int) -> str:
        """The gateway's credential for one key generation (hardened tier)."""
        if generation < 1:
            raise ValueError("generations start at 1")
        context = CONTEXT_GATEWAY.format(generation=generation)
        return GATEWAY_KEY_PREFIX + _b64url(derive(self._master, context))
