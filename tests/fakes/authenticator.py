"""A software authenticator, and the browser in front of it, for the passkey tests (M5 design O.1).

It makes ES256, EdDSA and RS256 credentials with ``cryptography`` and answers ``create()`` and
``get()`` with what the portal page posts back (design D.1): ``clientDataJSON`` as Chrome builds
it, ``getAuthenticatorData()`` in the L3 §6.1 layout with the COSE key in the attested credential
data (§6.5.1), ``getPublicKey()`` as SPKI DER, and a signature over ``authData ||
SHA-256(clientDataJSON)`` (§6.5.5). Credentials are discoverable and kept per RP ID and user
handle, as authenticators keep them: a second ``create()`` for the same pair overwrites the first,
and one that lists a held credential in ``excludeCredentials`` raises :class:`InvalidStateError`.

:class:`Switch` turns on each malformed or adversarial answer the verifier must refuse (design
D.3); :class:`Kind` adds the keys it must refuse. Any other field can be changed with
``dataclasses.replace`` on the frozen :class:`Attestation` and :class:`Assertion`. The fake doesn't
check the RP ID against the origin, as a browser would, so a test can pair any two.

The COSE key is written here by a small CBOR writer, independently of the verifier's fixed byte
templates, so each checks the other; nothing here imports the portal. ECDSA signs with RFC 6979
nonces, so a fixed key gives fixed output (the spec's §16 vectors do the same). RSA keys are slow
to make, so each size is generated once per process and shared by every credential of that kind.
"""

from __future__ import annotations

import base64
import enum
import functools
import hashlib
import json
import secrets
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

# Flags (L3 §6.1).
UP: Final = 0x01
UV: Final = 0x04
BE: Final = 0x08
BS: Final = 0x10
AT: Final = 0x40
ED: Final = 0x80

# COSE algorithms (RFC 9053, RFC 8812).
ES256: Final = -7
EDDSA: Final = -8
RS256: Final = -257

RP_ID: Final = "localhost"
ORIGIN: Final = "http://localhost:8081"
TOP_ORIGIN: Final = "https://other.example"
BOM: Final = b"\xef\xbb\xbf"
CHROME_EXTRA_KEY: Final = "other_keys_can_be_added_here"
CHROME_EXTRA_VALUE: Final = (
    "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
)
EXTENSIONS: Final = {"credProtect": 2}
"""The extension output written after the rest of authData when ED is set."""

Browser = Literal["chrome", "firefox", "safari"]
PrivateKey = ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey
PublicKey = (
    ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey | ed448.Ed448PublicKey | rsa.RSAPublicKey
)


class InvalidStateError(Exception):
    """The browser's answer when the authenticator holds an excluded credential (L3 §6.3.2)."""


class NotAllowedError(Exception):
    """The browser's answer when the authenticator holds no credential the request allows."""


class NotSupportedError(Exception):
    """The browser's answer when no offered algorithm is one the authenticator supports."""


class Switch(enum.Enum):
    NO_UP = "no_up"  # UP clear
    NO_UV = "no_uv"  # UV clear
    WRONG_TYPE = "wrong_type"  # the other ceremony's client-data type
    CROSS_ORIGIN = "cross_origin"  # "crossOrigin": true
    TOP_ORIGIN = "top_origin"  # a "topOrigin" (with "crossOrigin": false unless CROSS_ORIGIN)
    BOM = "bom"  # clientDataJSON starts with a UTF-8 byte order mark
    EXTRA_KEY = "extra_key"  # Chrome's extra client-data key (it adds one at random)
    BS_WITHOUT_BE = "bs_without_be"  # BS set, BE clear
    FLIP_BE = "flip_be"  # get: BE the opposite of what registration said
    AT_ON_ASSERTION = "at_on_assertion"  # get: AT set, attested credential data included
    EXTENSIONS = "extensions"  # ED set, an extensions map after the rest
    TRAILING_BYTE = "trailing_byte"  # one byte after the end of authData, ED clear
    COSE_REORDERED = "cose_reordered"  # create: the COSE key's entries out of canonical order
    COSE_EXTRA_PARAMETER = "cose_extra_parameter"  # create: an optional COSE parameter (kid)
    NULL_PUBLIC_KEY = "null_public_key"  # create: getPublicKey() is null, as Safari's can be
    OTHER_PUBLIC_KEY = "other_public_key"  # create: getPublicKey() gives another key
    WRONG_ALGORITHM = "wrong_algorithm"  # create: getPublicKeyAlgorithm() names another
    COUNTER_BACK = "counter_back"  # get: the counter goes back by one (not below zero)
    FLIP_SIGNATURE = "flip_signature"  # get: the signature's last byte flipped
    RAW_ID_MISMATCH = "raw_id_mismatch"  # rawId differs from the credential's ID


class Kind(enum.Enum):
    """The key an authenticator makes. The last three are keys the verifier must refuse."""

    ES256 = "es256"
    EDDSA = "eddsa"
    RS256 = "rs256"  # RSA 2048
    RS256_3072 = "rs256_3072"
    RS256_4096 = "rs256_4096"
    RS256_1024 = "rs256_1024"  # too short
    RS256_E3 = "rs256_e3"  # RSA 2048 with e = 3
    ES256_P384 = "es256_p384"  # claims ES256 for a P-384 key

    @property
    def alg(self) -> int:
        if self in (Kind.ES256, Kind.ES256_P384):
            return ES256
        if self is Kind.EDDSA:
            return EDDSA
        return RS256


KIND_OF_ALG: Final = {ES256: Kind.ES256, EDDSA: Kind.EDDSA, RS256: Kind.RS256}
OTHER_ALG: Final = {ES256: EDDSA, EDDSA: RS256, RS256: ES256}
_RSA: Final = {
    Kind.RS256: (2048, 65537),
    Kind.RS256_3072: (3072, 65537),
    Kind.RS256_4096: (4096, 65537),
    Kind.RS256_1024: (1024, 65537),
    Kind.RS256_E3: (2048, 3),
}
_COSE_CURVES: Final = {"secp256r1": 1, "secp384r1": 2, "secp521r1": 3}


# --- encodings ----------------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError("too large for CBOR")


def cbor(value: object, *, canonical: bool = True) -> bytes:
    """CBOR for the few shapes WebAuthn uses: ints, bytes, text, booleans and maps.

    Maps are written in CTAP2 canonical order (major type, then length, then bytes) unless
    ``canonical`` is false, when the outer map keeps the caller's order.
    """
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return _head(3, len(data)) + data
    if isinstance(value, Mapping):
        items = [(cbor(k), cbor(v)) for k, v in value.items()]
        if canonical:
            items.sort(key=lambda item: (item[0][0] >> 5, len(item[0]), item[0]))
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"no CBOR for {type(value).__name__}")


def _unsigned(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, "big")


def cose_key(
    key: PublicKey, alg: int, *, reordered: bool = False, extra_parameter: bool = False
) -> bytes:
    """The credential public key as a COSE_Key (L3 §6.5.1.1), CTAP2 canonical by default."""
    params: dict[int, int | bytes]
    if isinstance(key, ec.EllipticCurvePublicKey):
        size = (key.curve.key_size + 7) // 8
        numbers = key.public_numbers()
        params = {
            1: 2,
            3: alg,
            -1: _COSE_CURVES[key.curve.name],
            -2: numbers.x.to_bytes(size, "big"),
            -3: numbers.y.to_bytes(size, "big"),
        }
    elif isinstance(key, ed25519.Ed25519PublicKey | ed448.Ed448PublicKey):
        raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        crv = 6 if isinstance(key, ed25519.Ed25519PublicKey) else 7
        params = {1: 1, 3: alg, -1: crv, -2: raw}
    else:
        numbers_rsa = key.public_numbers()
        params = {1: 3, 3: alg, -1: _unsigned(numbers_rsa.n), -2: _unsigned(numbers_rsa.e)}
    if extra_parameter:
        params[2] = b"\x01"  # kid, an OPTIONAL parameter §6.5.1.1 forbids
    if reordered:
        params = {3: params.pop(3), **params}  # alg before kty
        return cbor(params, canonical=False)
    return cbor(params)


def spki(key: PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def client_data_json(
    type_: str,
    challenge: bytes,
    origin: str,
    *,
    cross_origin: bool = False,
    top_origin: str | None = None,
    extra_key: bool = False,
    bom: bool = False,
) -> bytes:
    """``clientDataJSON`` as Chromium's ``BuildClientDataJson`` writes it (L3 §5.8.1.1's order)."""
    parts = [
        f'"type":{json.dumps(type_)}',
        f'"challenge":{json.dumps(b64url(challenge))}',
        f'"origin":{json.dumps(origin)}',
        f'"crossOrigin":{"true" if cross_origin else "false"}',
    ]
    if top_origin is not None:
        parts.append(f'"topOrigin":{json.dumps(top_origin)}')
    if extra_key:
        parts.append(f"{json.dumps(CHROME_EXTRA_KEY)}:{json.dumps(CHROME_EXTRA_VALUE)}")
    data = ("{" + ",".join(parts) + "}").encode("utf-8")
    return BOM + data if bom else data


def authenticator_data(
    rp_id: str, flags: int, sign_count: int, attested: bytes = b"", extensions: bytes = b""
) -> bytes:
    """``rpIdHash[32] || flags[1] || signCount[4]``, then attested data and extensions (§6.1)."""
    return (
        hashlib.sha256(rp_id.encode("utf-8")).digest()
        + bytes([flags])
        + sign_count.to_bytes(4, "big")
        + attested
        + extensions
    )


def attested_credential_data(aaguid: bytes, credential_id: bytes, cose: bytes) -> bytes:
    """``aaguid[16] || L[2] || credentialId[L] || credentialPublicKey`` (§6.5.1)."""
    return aaguid + len(credential_id).to_bytes(2, "big") + credential_id + cose


def attestation_object_none(auth_data: bytes) -> bytes:
    """The attestation object with ``"fmt": "none"`` (§8.7), which the page never posts."""
    return cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})


# --- keys ---------------------------------------------------------------------------------------


@functools.cache
def _rsa_key(bits: int, exponent: int, slot: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=exponent, key_size=bits)


def new_key(kind: Kind, *, slot: int = 0) -> PrivateKey:
    """A key of this kind. RSA keys are shared per kind and ``slot``; the others are fresh."""
    if kind is Kind.ES256:
        return ec.generate_private_key(ec.SECP256R1())
    if kind is Kind.ES256_P384:
        return ec.generate_private_key(ec.SECP384R1())
    if kind is Kind.EDDSA:
        return ed25519.Ed25519PrivateKey.generate()
    bits, exponent = _RSA[kind]
    return _rsa_key(bits, exponent, slot)


def rsa_from_primes(p: int, q: int, e: int = 65537) -> rsa.RSAPrivateKey:
    """An RSA key from its primes, as the spec's §16.10 vector gives it."""
    d = pow(e, -1, (p - 1) * (q - 1))
    return rsa.RSAPrivateNumbers(
        p=p,
        q=q,
        d=d,
        dmp1=rsa.rsa_crt_dmp1(d, p),
        dmq1=rsa.rsa_crt_dmq1(d, q),
        iqmp=rsa.rsa_crt_iqmp(p, q),
        public_numbers=rsa.RSAPublicNumbers(e, p * q),
    ).private_key()


def kind_of(key: PrivateKey) -> Kind:
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return Kind.ES256 if isinstance(key.curve, ec.SECP256R1) else Kind.ES256_P384
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return Kind.EDDSA
    return Kind.RS256


def sign(key: PrivateKey, message: bytes) -> bytes:
    """ES256: DER ECDSA with SHA-256; EdDSA: raw Ed25519; RS256: PKCS#1 v1.5 with SHA-256."""
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(message, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return key.sign(message)
    return key.sign(message, padding.PKCS1v15(), hashes.SHA256())


# --- options, as the vault builds them (design D.1) ---------------------------------------------


def creation_options(
    challenge: bytes,
    user_handle: bytes,
    *,
    rp_id: str = RP_ID,
    exclude: Sequence[bytes] = (),
    algorithms: Sequence[int] = (ES256, EDDSA, RS256),
) -> dict[str, Any]:
    return {
        "rp": {"id": rp_id, "name": "ZoeyMCP"},
        "user": {
            "id": b64url(user_handle),
            "name": "zoeymcp",
            "displayName": "ZoeyMCP operator",
        },
        "challenge": b64url(challenge),
        "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in algorithms],
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "none",
        "excludeCredentials": [{"type": "public-key", "id": b64url(i)} for i in exclude],
        "timeout": 300000,
    }


def request_options(
    challenge: bytes, *, rp_id: str = RP_ID, allow: Sequence[bytes] = ()
) -> dict[str, Any]:
    return {
        "challenge": b64url(challenge),
        "rpId": rp_id,
        "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": b64url(i)} for i in allow],
        "timeout": 300000,
    }


# --- what the page posts back --------------------------------------------------------------------


@dataclass(frozen=True)
class Attestation:
    """The fields the page reads from ``create()``'s result, raw (design D.1)."""

    id: bytes  # rawId
    client_data_json: bytes
    authenticator_data: bytes  # getAuthenticatorData()
    public_key: bytes | None  # getPublicKey()
    public_key_algorithm: int  # getPublicKeyAlgorithm()
    transports: tuple[str, ...]  # getTransports()
    attestation_object: bytes  # not posted

    def body(self) -> dict[str, Any]:
        """The JSON body the page posts, base64url-encoded."""
        return {
            "id": b64url(self.id),
            "client_data_json": b64url(self.client_data_json),
            "authenticator_data": b64url(self.authenticator_data),
            "public_key": None if self.public_key is None else b64url(self.public_key),
            "public_key_algorithm": self.public_key_algorithm,
            "transports": list(self.transports),
        }


@dataclass(frozen=True)
class Assertion:
    """The fields the page reads from ``get()``'s result, raw (design D.1)."""

    id: bytes
    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: bytes | None

    def body(self) -> dict[str, Any]:
        return {
            "id": b64url(self.id),
            "client_data_json": b64url(self.client_data_json),
            "authenticator_data": b64url(self.authenticator_data),
            "signature": b64url(self.signature),
            "user_handle": None if self.user_handle is None else b64url(self.user_handle),
        }


# --- the authenticator --------------------------------------------------------------------------


@dataclass
class Credential:
    """A discoverable credential the authenticator holds."""

    id: bytes
    rp_id: str
    user_handle: bytes
    kind: Kind
    private_key: PrivateKey
    backup_eligible: bool
    sign_count: int = 0

    @property
    def public_key(self) -> PublicKey:
        return self.private_key.public_key()

    @property
    def spki(self) -> bytes:
        return spki(self.public_key)


def _flags(base: int, switches: Collection[Switch]) -> int:
    flags = base
    if Switch.NO_UP in switches:
        flags &= ~UP
    if Switch.NO_UV in switches:
        flags &= ~UV
    if Switch.BS_WITHOUT_BE in switches:
        flags = (flags | BS) & ~BE
    if Switch.EXTENSIONS in switches:
        flags |= ED
    return flags


def _client_data(type_: str, challenge: bytes, origin: str, switches: Collection[Switch]) -> bytes:
    if Switch.WRONG_TYPE in switches:
        type_ = "webauthn.get" if type_ == "webauthn.create" else "webauthn.create"
    return client_data_json(
        type_,
        challenge,
        origin,
        cross_origin=Switch.CROSS_ORIGIN in switches,
        top_origin=TOP_ORIGIN if Switch.TOP_ORIGIN in switches else None,
        extra_key=Switch.EXTRA_KEY in switches,
        bom=Switch.BOM in switches,
    )


def _tail(switches: Collection[Switch]) -> bytes:
    extensions = cbor(EXTENSIONS) if Switch.EXTENSIONS in switches else b""
    return extensions + (b"\x00" if Switch.TRAILING_BYTE in switches else b"")


def _raw_id(credential_id: bytes, switches: Collection[Switch]) -> bytes:
    if Switch.RAW_ID_MISMATCH not in switches:
        return credential_id
    if not credential_id:
        return b"\x00"
    return credential_id[:-1] + bytes([credential_id[-1] ^ 0x01])


@dataclass
class SoftAuthenticator:
    """One authenticator behind one browser.

    A synced passkey provider (the defaults) reports BE and BS and a zero counter; a security
    key is ``backup_eligible=False, counts=True``. ``browser="safari"`` gives a null
    ``getPublicKey()`` for EdDSA and RS256, as Safari does (WebKit bug 312081).
    """

    aaguid: bytes = bytes(16)
    backup_eligible: bool = True
    backup_state: bool = True
    counts: bool = False
    transports: tuple[str, ...] = ("hybrid", "internal")
    browser: Browser = "chrome"
    credentials: dict[tuple[str, bytes], Credential] = field(default_factory=dict)

    def held(self, rp_id: str) -> list[Credential]:
        """The credentials held for this RP ID, oldest first."""
        return [c for (rp, _), c in self.credentials.items() if rp == rp_id]

    def _backup(self, eligible: bool) -> int:
        return (BE if eligible else 0) | (BS if eligible and self.backup_state else 0)

    def create(
        self,
        options: Mapping[str, Any],
        origin: str = ORIGIN,
        *,
        switches: Collection[Switch] = (),
        kind: Kind | None = None,
        key: PrivateKey | None = None,
        credential_id: bytes | None = None,
        id_length: int = 32,
        rp_id: str | None = None,
    ) -> Attestation:
        """``navigator.credentials.create()``. ``rp_id`` overrides the options' RP ID."""
        rp = rp_id if rp_id is not None else str(options["rp"]["id"])
        user_handle = b64url_decode(options["user"]["id"])
        excluded = {b64url_decode(c["id"]) for c in options.get("excludeCredentials", [])}
        if any(c.id in excluded for c in self.held(rp)):
            raise InvalidStateError("the authenticator holds an excluded credential")
        if kind is None:
            if key is not None:
                kind = kind_of(key)
            else:
                offered = [p["alg"] for p in options["pubKeyCredParams"]]
                supported = [KIND_OF_ALG[alg] for alg in offered if alg in KIND_OF_ALG]
                if not supported:
                    raise NotSupportedError("no offered algorithm is supported")
                kind = supported[0]
        private_key = key if key is not None else new_key(kind)
        cred_id = credential_id if credential_id is not None else secrets.token_bytes(id_length)
        credential = Credential(
            cred_id, rp, user_handle, kind, private_key, backup_eligible=self.backup_eligible
        )
        cose = cose_key(
            credential.public_key,
            kind.alg,
            reordered=Switch.COSE_REORDERED in switches,
            extra_parameter=Switch.COSE_EXTRA_PARAMETER in switches,
        )
        flags = _flags(UP | UV | AT | self._backup(self.backup_eligible), switches)
        auth_data = authenticator_data(
            rp,
            flags,
            credential.sign_count,
            attested_credential_data(self.aaguid, cred_id, cose),
            _tail(switches),
        )
        public_key: bytes | None = credential.spki
        if Switch.NULL_PUBLIC_KEY in switches or (self.browser == "safari" and kind.alg != ES256):
            public_key = None
        elif Switch.OTHER_PUBLIC_KEY in switches:
            public_key = spki(new_key(kind, slot=1).public_key())
        alg = OTHER_ALG[kind.alg] if Switch.WRONG_ALGORITHM in switches else kind.alg
        self.credentials.pop((rp, user_handle), None)  # overwritten, as §6.3.2 step 7 says
        self.credentials[(rp, user_handle)] = credential
        return Attestation(
            id=_raw_id(cred_id, switches),
            client_data_json=_client_data(
                "webauthn.create", b64url_decode(options["challenge"]), origin, switches
            ),
            authenticator_data=auth_data,
            public_key=public_key,
            public_key_algorithm=alg,
            transports=self.transports,
            attestation_object=attestation_object_none(auth_data),
        )

    def get(
        self,
        options: Mapping[str, Any],
        origin: str = ORIGIN,
        *,
        switches: Collection[Switch] = (),
        credential_id: bytes | None = None,
        rp_id: str | None = None,
    ) -> Assertion:
        """``navigator.credentials.get()``. With several candidates the newest is chosen, as
        an operator picking from the account list might; ``credential_id`` picks one."""
        rp = rp_id if rp_id is not None else str(options["rpId"])
        allowed = [b64url_decode(c["id"]) for c in options.get("allowCredentials", [])]
        candidates = self.held(rp)
        if allowed:
            candidates = [c for c in candidates if c.id in allowed]
        if credential_id is not None:
            candidates = [c for c in candidates if c.id == credential_id]
        if not candidates:
            raise NotAllowedError("no credential the request allows is held")
        credential = candidates[-1]
        if Switch.COUNTER_BACK in switches:
            credential.sign_count = max(credential.sign_count - 1, 0)
        elif self.counts:
            credential.sign_count += 1
        backup = self._backup(credential.backup_eligible)
        if Switch.FLIP_BE in switches:
            backup = 0 if credential.backup_eligible else BE
        flags = _flags(UP | UV | backup, switches)
        attested = b""
        if Switch.AT_ON_ASSERTION in switches:
            flags |= AT
            cose = cose_key(credential.public_key, credential.kind.alg)
            attested = attested_credential_data(self.aaguid, credential.id, cose)
        auth_data = authenticator_data(rp, flags, credential.sign_count, attested, _tail(switches))
        client_data = _client_data(
            "webauthn.get", b64url_decode(options["challenge"]), origin, switches
        )
        signature = sign(credential.private_key, auth_data + hashlib.sha256(client_data).digest())
        if Switch.FLIP_SIGNATURE in switches:
            signature = signature[:-1] + bytes([signature[-1] ^ 0x01])
        return Assertion(
            id=_raw_id(credential.id, switches),
            client_data_json=client_data,
            authenticator_data=auth_data,
            signature=signature,
            user_handle=credential.user_handle,
        )
