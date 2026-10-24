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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..common.logs import refuse_type

MASTER_KEY_ENV = "ZOEYMCP_MASTER_KEY"
PREVIOUS_MASTER_KEY_ENV = "ZOEYMCP_MASTER_KEY_PREVIOUS"
MASTER_KEY_BYTES = 32
GATEWAY_KEY_PREFIX = "zgw1-"
# The egress role's read-only key (M7 design G.3): the allowlists, nothing else.
EGRESS_KEY_PREFIX = "zeg1-"

_SALT = b"zoeymcp/v1"
CONTEXT_STORE = "zoeymcp/store/v1"
CONTEXT_CONFIG = "zoeymcp/config/v1"
CONTEXT_KEY_ID = "zoeymcp/key-id/v1"
CONTEXT_GATEWAY = "zoeymcp/gateway/v1/gen-{generation}"
CONTEXT_EGRESS = "zoeymcp/egress/v1/gen-{generation}"
# The SMTP connector's send journal keys its request digests with this (M4 design J.3).
CONTEXT_AUDIT = "zoeymcp/audit/v1"
# The portal's state files are MAC'd with this, and passkey fingerprints keyed (M5 design D.4, E.2).
CONTEXT_PORTAL = "zoeymcp/portal/v1"
# The managed policy's revisions are encrypted with this (M6 design D.2, D.3).
CONTEXT_POLICY = "zoeymcp/policy/v1"
# AES-GCM's nonce for a policy revision. ``AESGCM`` itself takes 8 to 128 bytes (contract 61).
POLICY_NONCE_BYTES = 12


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


class PortalKey:
    """``K_portal``: the MAC key of the portal's state files, with the ID of the master key it
    comes from. Its ``repr`` hides the key, and logging it raises."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: bytes, key_id: str) -> None:
        self._key = key
        self.key_id = key_id

    def mac(self, data: bytes) -> bytes:
        """HMAC-SHA256 of ``data``. Each use puts its own context line first."""
        return hmac.new(self._key, data, hashlib.sha256).digest()

    def __repr__(self) -> str:
        return f"PortalKey(key_id={self.key_id}, <hidden>)"


refuse_type(PortalKey)


class PolicyKey:
    """``K_policy``: the AES-256-GCM key of the managed policy's revision bodies (M6 design D.2),
    with the ID of the master key it comes from. Its ``repr`` hides the key, and logging it
    raises."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: bytes, key_id: str) -> None:
        self._key = key
        self.key_id = key_id

    def encrypt(self, nonce: bytes, plaintext: bytes, associated: bytes) -> bytes:
        """The ciphertext and its tag. ``nonce`` is 12 fresh random bytes, never reused."""
        return AESGCM(self._key).encrypt(_policy_nonce(nonce), plaintext, associated)

    def decrypt(self, nonce: bytes, ciphertext: bytes, associated: bytes) -> bytes:
        """The plaintext. Raises ``cryptography.exceptions.InvalidTag`` for a ciphertext, nonce or
        associated data that isn't what :meth:`encrypt` was given."""
        return AESGCM(self._key).decrypt(_policy_nonce(nonce), ciphertext, associated)

    def __repr__(self) -> str:
        return f"PolicyKey(key_id={self.key_id}, <hidden>)"


def _policy_nonce(nonce: bytes) -> bytes:
    if len(nonce) != POLICY_NONCE_BYTES:
        raise ValueError(f"a policy nonce is {POLICY_NONCE_BYTES} bytes, not {len(nonce)}")
    return nonce


refuse_type(PolicyKey)


class ConfigMac:
    """``K_config`` as a MAC, with the ID of the master key it comes from. Each use names its own
    context line, which goes first (M6 design D.3). Its ``repr`` hides the key, and logging it
    raises."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: bytes, key_id: str) -> None:
        self._key = key
        self.key_id = key_id

    def mac(self, context: bytes, data: bytes) -> bytes:
        """HMAC-SHA256 of ``context`` and then ``data``. ``context`` is one line, ending in a
        newline, so no use's message can be read as another's."""
        if not context.endswith(b"\n") or b"\n" in context[:-1]:
            raise ValueError("a MAC context is one line, ending in a newline")
        return hmac.new(self._key, context + data, hashlib.sha256).digest()

    def __repr__(self) -> str:
        return f"ConfigMac(key_id={self.key_id}, <hidden>)"


refuse_type(ConfigMac)


@dataclass(frozen=True)
class KeySet:
    """The keys derived from one master key. ``repr`` never shows key material.

    ``K_config`` (``config_key``, :attr:`config_mac`) authenticates four kinds of file, each under
    its own context line: the gateway-key state (``zoeymcp/gateway-key-state/v1``,
    ``gatewaykeys``, which reads the raw bytes) and the managed policy's revisions, head and
    anchor (``zoeymcp/policy-revision/v1``, ``zoeymcp/policy-head/v1`` and
    ``zoeymcp/policy-anchor/v1``, ``policyseal``). ``K_policy`` (:attr:`policy_key`) encrypts the
    revisions' bodies.
    """

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

    @property
    def portal_key(self) -> PortalKey:
        """The key the portal's passkey file and setup code record are MAC'd under."""
        return PortalKey(derive(self._master, CONTEXT_PORTAL), self.key_id)

    @property
    def policy_key(self) -> PolicyKey:
        """The key the managed policy's revision bodies are encrypted under (M6 design D.2)."""
        return PolicyKey(derive(self._master, CONTEXT_POLICY), self.key_id)

    @property
    def config_mac(self) -> ConfigMac:
        """``config_key`` as a MAC for the managed policy's files (M6 design D.2, D.3)."""
        return ConfigMac(self.config_key, self.key_id)

    def gateway_key(self, generation: int) -> str:
        """The gateway's credential for one key generation (hardened tier)."""
        if generation < 1:
            raise ValueError("generations start at 1")
        context = CONTEXT_GATEWAY.format(generation=generation)
        return GATEWAY_KEY_PREFIX + _b64url(derive(self._master, context))

    def egress_key(self, generation: int) -> str:
        """The egress role's key for one key generation (M7 design G.3). It grants the
        allowlists alone; a new generation retires the old key at once."""
        if generation < 1:
            raise ValueError("generations start at 1")
        context = CONTEXT_EGRESS.format(generation=generation)
        return EGRESS_KEY_PREFIX + _b64url(derive(self._master, context))
