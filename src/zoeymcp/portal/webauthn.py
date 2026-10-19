"""The passkey verifier (M5 design D.1-D.3). Pure, so each check can be tested.

The vault builds the ceremony options; the page passes them to ``navigator.credentials`` and
posts back the raw fields, base64url-encoded, parsing none of them (D.1). Every check is here.

A new credential's public key is read from ``authenticatorData`` by fixed per-algorithm templates
(D.2): the CTAP2 canonical COSE keys of ES256, EdDSA (Ed25519) and RS256 are compared byte for byte
at known offsets, so no CBOR is parsed, and a key in any other encoding is refused
(``key_encoding``). ``getPublicKey()``, when the browser gives it (Safari's is null for EdDSA and
RS256), must be the same key. No attestation is read: trust in a new key comes from the session
that began the enrolment.

A refusal raises :class:`WebAuthnError`. Its ``reason`` is stable and the checks run in D.3's
order, so the first failing check names it; the caller words it (M.2). A counter that doesn't
rise is not a refusal: :class:`Asserted` flags it, and the caller logs it and keeps the higher
value (D10).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from ..common.canonical import JSONRejected, loads_strict

# Flags (L3 §6.1). The RFU bits are ignored.
UP: Final = 0x01
UV: Final = 0x04
BE: Final = 0x08
BS: Final = 0x10
AT: Final = 0x40
ED: Final = 0x80

# COSE algorithms, in the order offered: ES256 first, so an authenticator that can make several
# makes the one every browser's getPublicKey() supports.
ES256: Final = -7
EDDSA: Final = -8
RS256: Final = -257
ALGORITHMS: Final = (ES256, EDDSA, RS256)

MAX_PASSKEYS: Final = 32
TIMEOUT_MS: Final = 300_000
# Sizes of the posted fields, decoded, in bytes.
MAX_CLIENT_DATA: Final = 4096
MAX_REGISTRATION_DATA: Final = 4096
MAX_ASSERTION_DATA: Final = 1024
MAX_PUBLIC_KEY: Final = 2048
MAX_SIGNATURE: Final = 1024
MAX_CREDENTIAL_ID: Final = 1023
MAX_USER_HANDLE: Final = 64
MAX_TRANSPORTS: Final = 8
# AuthenticatorTransport (L3 §5.8.4).
TRANSPORTS: Final = frozenset({"usb", "nfc", "ble", "smart-card", "hybrid", "internal"})

REGISTRATION_FIELDS: Final = frozenset(
    {
        "id",
        "client_data_json",
        "authenticator_data",
        "public_key",
        "public_key_algorithm",
        "transports",
    }
)
ASSERTION_FIELDS: Final = frozenset(
    {"id", "client_data_json", "authenticator_data", "signature", "user_handle"}
)

_BOM: Final = bytes.fromhex("efbbbf")  # U+FEFF in UTF-8
# The fixed parts of D.2's templates. ES256: head, x[32], y's head, y[32] (77 bytes). EdDSA:
# head, x[32] (42 bytes). RS256: head, len[2] (256 to 512), n[len], e = 65537 (len + 16 bytes).
_ES256_HEAD: Final = bytes.fromhex("a5010203262001215820")
_ES256_Y: Final = bytes.fromhex("225820")
_EDDSA_HEAD: Final = bytes.fromhex("a4010103272006215820")
_RS256_HEAD: Final = bytes.fromhex("a40103033901002059")
_RS256_TAIL: Final = bytes.fromhex("2143010001")
_MIN_RSA_BITS: Final = 2048

Reason = Literal[
    "too_large",
    "bad_field",
    "client_data",
    "wrong_type",
    "wrong_challenge",
    "wrong_origin",
    "cross_origin",
    "top_origin",
    "no_attested_data",
    "wrong_rp",
    "not_present",
    "not_verified",
    "backup_flags",
    "credential_id",
    "raw_id_mismatch",
    "key_encoding",
    "algorithm",
    "public_key",
    "key_mismatch",
    "duplicate_credential",
    "too_many_passkeys",
    "not_allowed",
    "unknown_credential",
    "user_handle",
    "at_flag",
    "trailing_bytes",
    "backup_eligibility_changed",
    "signature",
]


class WebAuthnError(ValueError):
    """A refused ceremony, with D.3's stable ``reason``."""

    def __init__(self, reason: Reason) -> None:
        super().__init__(reason)
        self.reason: Reason = reason


class CredentialRecord(Protocol):
    """What the verifier reads of an enrolled credential (the passkey file's record, D.4)."""

    @property
    def id(self) -> bytes: ...
    @property
    def rp_id(self) -> str: ...
    @property
    def alg(self) -> int: ...
    @property
    def spki(self) -> bytes: ...
    @property
    def sign_count(self) -> int: ...
    @property
    def backup_eligible(self) -> bool: ...
    @property
    def transports(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class NewCredential:
    """A registration that passed every check. ``spki`` is the key's SubjectPublicKeyInfo DER."""

    id: bytes
    rp_id: str
    alg: int
    spki: bytes
    sign_count: int
    backup_eligible: bool
    backup_state: bool
    transports: tuple[str, ...]


@dataclass(frozen=True)
class Asserted:
    """An assertion that passed every check. The caller applies it only after the session or
    action that needed it passes its own checks (L3 §7.2 step 24). ``sign_count`` is the higher
    of the stored and the new value; ``regressed``: the counter didn't rise (D10)."""

    credential_id: bytes
    sign_count: int
    backup_state: bool
    regressed: bool


# --- encodings ----------------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    """Base64url without padding (L3 §3)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Strict base64url (D.1): only the one text :func:`b64url` gives for its bytes.

    The decoder ignores excess padding and skips characters outside its alphabet, so the
    round trip is what refuses padding, ``+``, ``/``, white space and non-zero trailing bits.
    Raises :class:`ValueError`.
    """
    data = base64.urlsafe_b64decode(text + "==")
    if b64url(data) != text:
        raise ValueError("not canonical base64url")
    return data


# --- ceremony options (D.1) ---------------------------------------------------------------------


def _descriptors(credentials: Iterable[CredentialRecord], rp_id: str) -> list[dict[str, Any]]:
    return [
        {"type": "public-key", "id": b64url(c.id), "transports": list(c.transports)}
        for c in credentials
        if c.rp_id == rp_id
    ]


def creation_options(
    *, challenge: bytes, user_handle: bytes, rp_id: str, exclude: Iterable[CredentialRecord]
) -> dict[str, Any]:
    """The options for ``create()``. ``exclude``: the credentials the authenticator must not
    already hold, of which those of ``rp_id`` are listed (none for a reset enrolment)."""
    return {
        "rp": {"id": rp_id, "name": "ZoeyMCP"},
        "user": {
            "id": b64url(user_handle),
            "name": "zoeymcp",
            "displayName": "ZoeyMCP operator",
        },
        "challenge": b64url(challenge),
        "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in ALGORITHMS],
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "none",
        "excludeCredentials": _descriptors(exclude, rp_id),
        "timeout": TIMEOUT_MS,
    }


def request_options(
    *, challenge: bytes, rp_id: str, allow: Iterable[CredentialRecord] = ()
) -> dict[str, Any]:
    """The options for ``get()``. A login allows none, so an unauthenticated caller learns
    nothing about the credentials (Q13); a step-up lists those of ``rp_id``."""
    return {
        "challenge": b64url(challenge),
        "rpId": rp_id,
        "userVerification": "required",
        "allowCredentials": _descriptors(allow, rp_id),
        "timeout": TIMEOUT_MS,
    }


# --- the posted fields --------------------------------------------------------------------------


def _fields(body: object, names: frozenset[str]) -> dict[str, Any]:
    if not isinstance(body, dict) or body.keys() != names:
        raise WebAuthnError("bad_field")
    return body


def _decoded(value: object, limit: int) -> bytes:
    if not isinstance(value, str):
        raise WebAuthnError("bad_field")
    try:
        data = b64url_decode(value)
    except ValueError:
        raise WebAuthnError("bad_field") from None
    if len(data) > limit:
        raise WebAuthnError("too_large")
    return data


def _transports(value: object) -> tuple[str, ...]:
    """``getTransports()``: unique known values (L3 §5.2.1), kept sorted."""
    if not isinstance(value, list):
        raise WebAuthnError("bad_field")
    if len(value) > MAX_TRANSPORTS:
        raise WebAuthnError("too_large")
    if not all(isinstance(t, str) and t in TRANSPORTS for t in value) or len(set(value)) != len(
        value
    ):
        raise WebAuthnError("bad_field")
    return tuple(sorted(value))


# --- the checks ---------------------------------------------------------------------------------


def _check_client_data(raw: bytes, type_: str, challenge: bytes, origin: str) -> None:
    """L3 §7.1 steps 5-11 and §7.2 steps 8-14. ``raw`` is hashed elsewhere exactly as received;
    here one leading byte order mark is stripped, and unknown keys are allowed in any order."""
    try:
        data = loads_strict(raw.removeprefix(_BOM))
    except JSONRejected:
        raise WebAuthnError("client_data") from None
    if not (
        isinstance(data, dict)
        and all(isinstance(data.get(key), str) for key in ("type", "challenge", "origin"))
        and ("crossOrigin" not in data or isinstance(data["crossOrigin"], bool))
    ):
        raise WebAuthnError("client_data")
    if data["type"] != type_:
        raise WebAuthnError("wrong_type")
    try:
        sent = b64url_decode(data["challenge"])
    except ValueError:
        raise WebAuthnError("wrong_challenge") from None
    if not hmac.compare_digest(sent, challenge):
        raise WebAuthnError("wrong_challenge")
    if data["origin"] != origin:
        raise WebAuthnError("wrong_origin")
    if data.get("crossOrigin"):
        raise WebAuthnError("cross_origin")
    if "topOrigin" in data:
        raise WebAuthnError("top_origin")


def _check_flags(auth_data: bytes, rp_id: str) -> int:
    """The RP ID hash, UP, UV, and BS only with BE. Returns the flags."""
    if auth_data[:32] != hashlib.sha256(rp_id.encode()).digest():
        raise WebAuthnError("wrong_rp")
    flags = auth_data[32]
    if not flags & UP:
        raise WebAuthnError("not_present")
    if not flags & UV:
        raise WebAuthnError("not_verified")
    if flags & BS and not flags & BE:
        raise WebAuthnError("backup_flags")
    return flags


def _read_key(cose: bytes, extensions: bool) -> tuple[int, bytes]:
    """The algorithm and key bytes of a COSE key in one of D.2's templates: x and y for ES256,
    x for EdDSA, n for RS256. With ED clear the key ends authData; with it set, extensions
    follow, which are never parsed."""
    if cose[:10] == _ES256_HEAD and cose[42:45] == _ES256_Y:
        alg, material, end = ES256, cose[10:42] + cose[45:77], 77
    elif cose[:10] == _EDDSA_HEAD:
        alg, material, end = EDDSA, cose[10:42], 42
    elif (
        cose[:9] == _RS256_HEAD
        and 256 <= (size := int.from_bytes(cose[9:11], "big")) <= 512
        and cose[11 + size : 16 + size] == _RS256_TAIL
    ):
        alg, material, end = RS256, cose[11 : 11 + size], size + 16
    else:
        raise WebAuthnError("key_encoding")
    if len(cose) < end or (len(cose) > end) != extensions:
        raise WebAuthnError("key_encoding")
    return alg, material


def _public_key(alg: int, material: bytes) -> bytes:
    """The SPKI DER of a template's key: a P-256 point on the curve, an Ed25519 key, or RSA with
    a minimal n of 2048 to 4096 bits (the template fixes e = 65537 and n's length)."""
    key: ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | rsa.RSAPublicKey
    n = int.from_bytes(material, "big")
    if alg == RS256 and (material[0] == 0 or n.bit_length() < _MIN_RSA_BITS):
        raise WebAuthnError("public_key")
    try:
        if alg == ES256:
            key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + material)
        elif alg == EDDSA:
            key = ed25519.Ed25519PublicKey.from_public_bytes(material)
        else:
            key = rsa.RSAPublicNumbers(65537, n).public_key()
    except ValueError:
        raise WebAuthnError("public_key") from None
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _same_key(sent: bytes, spki: bytes) -> bool:
    """Whether ``getPublicKey()``'s SPKI loads and serializes to the template key's SPKI. The
    same SPKI is the same key type, curve, size and exponent, so this pins the type too."""
    try:
        loaded = serialization.load_der_public_key(sent)
    except (ValueError, UnsupportedAlgorithm):
        return False
    encoded = loaded.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return encoded == spki


def _signed(credential: CredentialRecord, message: bytes, signature: bytes) -> bool:
    """L3 §7.2 steps 20-21: ES256 DER ECDSA, EdDSA raw Ed25519, RS256 PKCS#1 v1.5, each with the
    stored key's type pinned to the stored algorithm."""
    try:
        key = serialization.load_der_public_key(credential.spki)
        if (
            credential.alg == ES256
            and isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1)
        ):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif credential.alg == EDDSA and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        elif credential.alg == RS256 and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
    except (InvalidSignature, ValueError, UnsupportedAlgorithm):
        return False
    return True


# --- the ceremonies -----------------------------------------------------------------------------


def verify_registration(
    body: object,
    *,
    challenge: bytes,
    origin: str,
    rp_id: str,
    enrolled: Collection[CredentialRecord],
) -> NewCredential:
    """Check what the page posts from ``create()`` (D.3's registration table, in order).

    ``body`` is the parsed JSON, exactly :data:`REGISTRATION_FIELDS`; ``challenge`` the
    ceremony's (F.3); ``origin`` and ``rp_id`` the entry's; ``enrolled`` every credential of
    every RP ID.
    """
    fields = _fields(body, REGISTRATION_FIELDS)
    raw_id = _decoded(fields["id"], MAX_CREDENTIAL_ID)
    client_data = _decoded(fields["client_data_json"], MAX_CLIENT_DATA)
    auth_data = _decoded(fields["authenticator_data"], MAX_REGISTRATION_DATA)
    sent_key = fields["public_key"]
    public_key = None if sent_key is None else _decoded(sent_key, MAX_PUBLIC_KEY)
    sent_alg = fields["public_key_algorithm"]
    if sent_alg is not None and type(sent_alg) is not int:
        raise WebAuthnError("bad_field")
    transports = _transports(fields["transports"])

    _check_client_data(client_data, "webauthn.create", challenge, origin)
    # rpIdHash[32] flags[1] signCount[4] aaguid[16] L[2] credentialId[L] key [extensions]
    if len(auth_data) < 55 or not auth_data[32] & AT:
        raise WebAuthnError("no_attested_data")
    flags = _check_flags(auth_data, rp_id)
    length = int.from_bytes(auth_data[53:55], "big")
    if not 1 <= length <= MAX_CREDENTIAL_ID or len(auth_data) < 55 + length:
        raise WebAuthnError("credential_id")
    credential_id = auth_data[55 : 55 + length]
    if raw_id != credential_id:
        raise WebAuthnError("raw_id_mismatch")
    alg, material = _read_key(auth_data[55 + length :], bool(flags & ED))
    if sent_alg is not None and sent_alg != alg:
        raise WebAuthnError("algorithm")
    spki = _public_key(alg, material)
    if public_key is not None and not _same_key(public_key, spki):
        raise WebAuthnError("key_mismatch")
    if any(c.id == credential_id for c in enrolled):
        raise WebAuthnError("duplicate_credential")
    if len(enrolled) >= MAX_PASSKEYS:
        raise WebAuthnError("too_many_passkeys")
    return NewCredential(
        id=credential_id,
        rp_id=rp_id,
        alg=alg,
        spki=spki,
        sign_count=int.from_bytes(auth_data[33:37], "big"),
        backup_eligible=bool(flags & BE),
        backup_state=bool(flags & BS),
        transports=transports,
    )


def verify_assertion(
    body: object,
    *,
    challenge: bytes,
    origin: str,
    rp_id: str,
    credentials: Iterable[CredentialRecord],
    user_handle: bytes,
    allowed: Collection[bytes] = (),
    login: bool,
) -> Asserted:
    """Check what the page posts from ``get()`` (D.3's assertion table, in order).

    ``body`` is the parsed JSON, exactly :data:`ASSERTION_FIELDS`; ``credentials`` every
    enrolled credential, of which only those of the entry's ``rp_id`` can match; ``user_handle``
    the operator's; ``allowed`` the IDs the options listed (none at login). A login needs the
    user handle, which a discoverable credential always returns.
    """
    fields = _fields(body, ASSERTION_FIELDS)
    raw_id = _decoded(fields["id"], MAX_CREDENTIAL_ID)
    client_data = _decoded(fields["client_data_json"], MAX_CLIENT_DATA)
    auth_data = _decoded(fields["authenticator_data"], MAX_ASSERTION_DATA)
    signature = _decoded(fields["signature"], MAX_SIGNATURE)
    sent_handle = fields["user_handle"]
    handle = None if sent_handle is None else _decoded(sent_handle, MAX_USER_HANDLE)

    if allowed and raw_id not in allowed:
        raise WebAuthnError("not_allowed")
    credential = next((c for c in credentials if c.id == raw_id and c.rp_id == rp_id), None)
    if credential is None:
        raise WebAuthnError("unknown_credential")
    if handle is None and login:
        raise WebAuthnError("user_handle")
    if handle is not None and not hmac.compare_digest(handle, user_handle):
        raise WebAuthnError("user_handle")
    _check_client_data(client_data, "webauthn.get", challenge, origin)
    # rpIdHash[32] flags[1] signCount[4], then extensions only if ED is set.
    if len(auth_data) < 37:
        raise WebAuthnError("trailing_bytes")
    if auth_data[32] & AT:
        raise WebAuthnError("at_flag")
    if (len(auth_data) > 37) != bool(auth_data[32] & ED):
        raise WebAuthnError("trailing_bytes")
    flags = _check_flags(auth_data, credential.rp_id)
    if bool(flags & BE) != credential.backup_eligible:
        raise WebAuthnError("backup_eligibility_changed")
    if not _signed(credential, auth_data + hashlib.sha256(client_data).digest(), signature):
        raise WebAuthnError("signature")
    # L3 §7.2 step 22: a counter that doesn't rise, when either value is nonzero, is a sign of a
    # cloned authenticator, but not proof. Accepted (D10); the stored value never goes down.
    count = int.from_bytes(auth_data[33:37], "big")
    stored = credential.sign_count
    return Asserted(
        credential_id=credential.id,
        sign_count=max(count, stored),
        backup_state=bool(flags & BS),
        regressed=(count != 0 or stored != 0) and count <= stored,
    )
