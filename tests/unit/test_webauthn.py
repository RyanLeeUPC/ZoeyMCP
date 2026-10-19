"""The passkey verifier (M5 design D.1-D.3, O.2): every check both ways, in D.3's order.

Ceremonies come from the software authenticator (``tests/fakes/authenticator.py``), which writes
its COSE keys with its own CBOR writer, so the verifier's fixed templates are checked against an
independent encoder; and from the WebAuthn L3 §16 vectors in ``data/webauthn``, whose README gives
each vector's outcome.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
from collections.abc import Callable, Collection, Iterable
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, utils, x25519
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.fakes.authenticator import (
    BOM,
    ORIGIN,
    RP_ID,
    Assertion,
    Attestation,
    InvalidStateError,
    Kind,
    PrivateKey,
    SoftAuthenticator,
    Switch,
    attested_credential_data,
    authenticator_data,
    client_data_json,
    cose_key,
    rsa_from_primes,
    sign,
)
from zoeymcp.portal import webauthn
from zoeymcp.portal.webauthn import (
    ALGORITHMS,
    AT,
    BE,
    BS,
    ED,
    EDDSA,
    ES256,
    MAX_PASSKEYS,
    RS256,
    TRANSPORTS,
    UP,
    UV,
    Asserted,
    NewCredential,
    WebAuthnError,
    b64url,
    b64url_decode,
    creation_options,
    request_options,
    verify_assertion,
    verify_registration,
)

DATA = Path(__file__).resolve().parent / "data" / "webauthn"
SECTIONS = ["16.2", "16.4", "16.5", "16.6", "16.7", "16.8", "16.9", "16.10", "16.11", "16.12"]
SECTIONS += ["16.13"]
CHALLENGE = bytes(range(32))
USER = b"\x5a" * 32
OTHER_RP = "other.example"
ACCEPTED = "accepted"
# One kind of each algorithm.
GOOD_KINDS = [Kind.ES256, Kind.EDDSA, Kind.RS256]


def refused(call: Callable[..., object], *args: Any, **kwargs: Any) -> str:
    with pytest.raises(WebAuthnError) as info:
        call(*args, **kwargs)
    assert str(info.value) == info.value.reason
    return info.value.reason


def outcome(call: Callable[..., object], *args: Any, **kwargs: Any) -> str:
    try:
        call(*args, **kwargs)
    except WebAuthnError as exc:
        return exc.reason
    return ACCEPTED


def register(
    body: object,
    *,
    challenge: bytes = CHALLENGE,
    origin: str = ORIGIN,
    rp_id: str = RP_ID,
    enrolled: Collection[NewCredential] = (),
) -> NewCredential:
    return verify_registration(
        body, challenge=challenge, origin=origin, rp_id=rp_id, enrolled=enrolled
    )


def options(
    *, user: bytes = USER, rp_id: str = RP_ID, exclude: Iterable[NewCredential] = ()
) -> dict[str, Any]:
    return creation_options(challenge=CHALLENGE, user_handle=user, rp_id=rp_id, exclude=exclude)


def get_options(*, rp_id: str = RP_ID, allow: Iterable[NewCredential] = ()) -> dict[str, Any]:
    return request_options(challenge=CHALLENGE, rp_id=rp_id, allow=allow)


@dataclasses.dataclass
class Enrolled:
    """An authenticator holding one credential, and the vault's record of it."""

    authenticator: SoftAuthenticator
    credential: NewCredential
    user: bytes = USER

    @property
    def private_key(self) -> PrivateKey:
        held = self.authenticator.held(self.credential.rp_id)
        return next(c for c in held if c.id == self.credential.id).private_key

    def get(self, *switches: Switch) -> Assertion:
        return self.authenticator.get(
            get_options(), credential_id=self.credential.id, switches=switches
        )

    def verify(
        self,
        assertion: Assertion | dict[str, Any],
        *,
        login: bool = True,
        allowed: Collection[bytes] = (),
        challenge: bytes = CHALLENGE,
        origin: str = ORIGIN,
        rp_id: str = RP_ID,
        credentials: Iterable[NewCredential] | None = None,
        user: bytes | None = None,
    ) -> Asserted:
        body = assertion.body() if isinstance(assertion, Assertion) else assertion
        return verify_assertion(
            body,
            challenge=challenge,
            origin=origin,
            rp_id=rp_id,
            credentials=[self.credential] if credentials is None else credentials,
            user_handle=self.user if user is None else user,
            allowed=allowed,
            login=login,
        )

    def resigned(
        self,
        assertion: Assertion,
        *,
        client_data: bytes | None = None,
        auth_data: bytes | None = None,
    ) -> Assertion:
        """The assertion with other bytes, signed again with the credential's key."""
        client_data = assertion.client_data_json if client_data is None else client_data
        auth_data = assertion.authenticator_data if auth_data is None else auth_data
        signature = sign(self.private_key, auth_data + hashlib.sha256(client_data).digest())
        return dataclasses.replace(
            assertion,
            client_data_json=client_data,
            authenticator_data=auth_data,
            signature=signature,
        )


def enrol(
    kind: Kind = Kind.ES256,
    authenticator: SoftAuthenticator | None = None,
    *,
    user: bytes = USER,
    **kwargs: Any,
) -> Enrolled:
    authenticator = SoftAuthenticator() if authenticator is None else authenticator
    attestation = authenticator.create(options(user=user), kind=kind, **kwargs)
    return Enrolled(authenticator, register(attestation.body()), user)


def attest(kind: Kind = Kind.ES256, *switches: Switch, **kwargs: Any) -> Attestation:
    return SoftAuthenticator().create(options(), kind=kind, switches=switches, **kwargs)


def with_body(attestation: Attestation, **changes: Any) -> dict[str, Any]:
    body = attestation.body()
    body.update(changes)
    return body


def record(
    credential_id: bytes = b"\x01" * 16, rp_id: str = RP_ID, **changes: Any
) -> NewCredential:
    base = NewCredential(credential_id, rp_id, ES256, b"", 0, False, False, ())
    return dataclasses.replace(base, **changes)


def client_data(**fields: Any) -> bytes:
    """Client data from these fields, in this order, as compact JSON."""
    return json.dumps(fields, separators=(",", ":")).encode()


def create_data(**changes: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "type": "webauthn.create",
        "challenge": b64url(CHALLENGE),
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    fields.update(changes)
    return fields


def padded(raw: bytes, size: int) -> bytes:
    """Client data with an extra key that brings it to exactly ``size`` bytes."""
    head = raw[:-1] + b',"pad":"'
    return head + b"x" * (size - len(head) - 2) + b'"}'


def crafted(
    cose: bytes,
    *,
    flags: int = UP | UV | AT,
    credential_id: bytes = b"\x01" * 16,
    tail: bytes = b"",
    public_key: bytes | None = None,
    alg: int | None = None,
) -> dict[str, Any]:
    """A registration body around a hand-made COSE key."""
    auth_data = authenticator_data(
        RP_ID, flags, 0, attested_credential_data(bytes(16), credential_id, cose), tail
    )
    return {
        "id": b64url(credential_id),
        "client_data_json": b64url(client_data_json("webauthn.create", CHALLENGE, ORIGIN)),
        "authenticator_data": b64url(auth_data),
        "public_key": None if public_key is None else b64url(public_key),
        "public_key_algorithm": alg,
        "transports": [],
    }


def es256_cose(x: bytes, y: bytes) -> bytes:
    return bytes.fromhex("a5010203262001215820") + x + bytes.fromhex("225820") + y


def eddsa_cose(x: bytes) -> bytes:
    return bytes.fromhex("a4010103272006215820") + x


def rs256_cose(n: bytes, *, length: int | None = None, tail: str = "2143010001") -> bytes:
    size = len(n) if length is None else length
    head = bytes.fromhex("a40103033901002059") + size.to_bytes(2, "big")
    return head + n + bytes.fromhex(tail)


def der(key: Any) -> bytes:
    encoded: bytes = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return encoded


@cache
def rsa_key(bits: int) -> rsa.RSAPublicKey:
    return rsa.generate_private_key(65537, bits).public_key()


def rsa_n(size: int, top: int) -> bytes:
    """An odd n of ``size`` bytes whose first byte is ``top``."""
    return bytes([top]) + b"\x5a" * (size - 2) + b"\x01"


# --- the §16 vectors, with the README's outcomes ------------------------------------------------


@cache
def vector(section: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((DATA / f"{section}.json").read_text(encoding="utf-8"))
    return loaded


def hexed(part: dict[str, Any], name: str) -> bytes:
    return bytes.fromhex(part[name])


def vector_body(v: dict[str, Any], *, flags: int | None = None) -> dict[str, Any]:
    """The page's post for the vector; with ``flags``, those flags and plain client data
    (neither is signed at registration)."""
    reg = v["registration"]
    auth_data = bytearray(hexed(reg, "authenticator_data"))
    raw = hexed(reg, "client_data_json")
    if flags is not None:
        auth_data[32] = flags
        raw = client_data_json("webauthn.create", hexed(reg, "challenge"), v["origin"])
    return {
        "id": b64url(hexed(reg, "credential_id")),
        "client_data_json": b64url(raw),
        "authenticator_data": b64url(bytes(auth_data)),
        "public_key": b64url(hexed(reg, "public_key")),
        "public_key_algorithm": v["algorithm"],
        "transports": [],
    }


def register_vector(v: dict[str, Any], body: dict[str, Any]) -> NewCredential:
    return verify_registration(
        body,
        challenge=hexed(v["registration"], "challenge"),
        origin=v["origin"],
        rp_id=v["rp_id"],
        enrolled=(),
    )


def vector_record(v: dict[str, Any]) -> NewCredential:
    """The record the README's assertions are checked against: the vector's ID and key, the
    registration's BE, a stored counter of 0."""
    reg = v["registration"]
    flags = int(reg["flags"], 16)
    return NewCredential(
        id=hexed(reg, "credential_id"),
        rp_id=v["rp_id"],
        alg=v["algorithm"],
        spki=hexed(reg, "public_key"),
        sign_count=0,
        backup_eligible=bool(flags & BE),
        backup_state=bool(flags & BS),
        transports=(),
    )


def assert_vector(v: dict[str, Any], *, allowed: Collection[bytes]) -> Asserted:
    auth = v["authentication"]
    body = {
        "id": b64url(hexed(v["registration"], "credential_id")),
        "client_data_json": b64url(hexed(auth, "client_data_json")),
        "authenticator_data": b64url(hexed(auth, "authenticator_data")),
        "signature": b64url(hexed(auth, "signature")),
        "user_handle": None,
    }
    return verify_assertion(
        body,
        challenge=hexed(auth, "challenge"),
        origin=v["origin"],
        rp_id=v["rp_id"],
        credentials=[vector_record(v)],
        user_handle=USER,
        allowed=allowed,
        login=False,
    )


@pytest.mark.parametrize("section", SECTIONS)
def test_each_vector_registration_has_the_readme_outcome(section: str) -> None:
    v = vector(section)
    expected = v["registration"]["expected"]
    assert outcome(register_vector, v, vector_body(v)) == expected
    if expected == ACCEPTED:
        new = register_vector(v, vector_body(v))
        reg = v["registration"]
        flags = int(reg["flags"], 16)
        assert new == NewCredential(
            id=hexed(reg, "credential_id"),
            rp_id="example.org",
            alg=v["algorithm"],
            spki=hexed(reg, "public_key"),
            sign_count=0,
            backup_eligible=bool(flags & BE),
            backup_state=bool(flags & BS),
            transports=(),
        )


@pytest.mark.parametrize("section", SECTIONS)
def test_each_vector_assertion_has_the_readme_outcome(section: str) -> None:
    v = vector(section)
    expected = v["authentication"]["expected"]
    if expected is None:
        # No credential of this algorithm can be enrolled, so none is ever asserted.
        assert v["algorithm"] not in ALGORITHMS
        return
    credential_id = hexed(v["registration"], "credential_id")
    for allowed in ((), (credential_id,), (b"other", credential_id)):
        assert outcome(assert_vector, v, allowed=allowed) == expected
    if expected == ACCEPTED:
        assert assert_vector(v, allowed=()) == Asserted(credential_id, 0, False, False)


def test_the_vectors_hold_the_hard_cases() -> None:
    v = vector("16.6")
    assert len(hexed(v["registration"], "credential_id")) == 1023
    # §16.5 has both crossOrigin and topOrigin: crossOrigin (row 10) comes first.
    raw = json.loads(hexed(vector("16.5")["registration"], "client_data_json"))
    assert raw["crossOrigin"] is True
    assert "topOrigin" in raw
    accepted = {
        vector(s)["algorithm"]
        for s in SECTIONS
        if vector(s)["registration"]["expected"] == ACCEPTED
    }
    assert accepted == {ES256, RS256}


@pytest.mark.parametrize("section", SECTIONS)
def test_the_templates_match_exactly_the_supported_vector_keys(section: str) -> None:
    """With UV set (registration authData isn't signed), every ES256, Ed25519 and RS256 key
    matches its template and gives the vector's SPKI; the ES384, ES512 and Ed448 keys match
    none. The template's length is exact: one byte more or less is refused, and extensions
    may follow only with ED set."""
    v = vector(section)
    body = vector_body(v, flags=UP | UV | AT)
    auth_data = b64url_decode(body["authenticator_data"])
    if v["algorithm"] not in ALGORITHMS:
        assert refused(register_vector, v, body) == "key_encoding"
        return
    new = register_vector(v, body)
    assert new.alg == v["algorithm"]
    assert new.spki == hexed(v["registration"], "public_key")
    assert register_vector(v, dict(body, public_key=None)).spki == new.spki
    for wrong in (auth_data + b"\xa0", auth_data[:-1]):
        assert refused(register_vector, v, dict(body, authenticator_data=b64url(wrong))) == (
            "key_encoding"
        )
    with_ed = bytearray(auth_data)
    with_ed[32] |= ED
    assert register_vector(v, dict(body, authenticator_data=b64url(bytes(with_ed) + b"\xa0")))
    # ED set with nothing after the key: the extensions are missing.
    assert (
        refused(register_vector, v, dict(body, authenticator_data=b64url(bytes(with_ed))))
        == "key_encoding"
    )


def test_the_template_lengths_are_pinned() -> None:
    lengths = {}
    for section in ("16.7", "16.11", "16.10"):
        v = vector(section)
        auth_data = hexed(v["registration"], "authenticator_data")
        lengths[v["algorithm"]] = (
            len(auth_data) - 55 - len(hexed(v["registration"], "credential_id"))
        )
    n = rsa_from_primes(
        int(vector("16.10")["credential_key"]["private_key_p"], 16),
        int(vector("16.10")["credential_key"]["private_key_q"], 16),
    ).public_key()
    assert n.key_size == 3482
    assert lengths == {ES256: 77, EDDSA: 42, RS256: 436 + 16}


# --- our known answers --------------------------------------------------------------------------


@cache
def known_answers() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((DATA / "known-answer.json").read_text(encoding="utf-8"))
    return loaded


def known_case(name: str) -> dict[str, Any]:
    return next(c for c in known_answers()["cases"] if c["name"] == name)


KNOWN = ["es256-synced", "eddsa-security-key", "rs256-platform"]


def known_registration(case: dict[str, Any]) -> dict[str, Any]:
    reg = case["registration"]
    return {
        "id": b64url(bytes.fromhex(case["credential_id"])),
        "client_data_json": b64url(hexed(reg, "client_data_json")),
        "authenticator_data": b64url(hexed(reg, "authenticator_data")),
        "public_key": b64url(hexed(reg, "public_key")),
        "public_key_algorithm": reg["public_key_algorithm"],
        "transports": case["transports"],
    }


def known_assertion(case: dict[str, Any]) -> dict[str, Any]:
    auth = case["authentication"]
    return {
        "id": b64url(bytes.fromhex(case["credential_id"])),
        "client_data_json": b64url(hexed(auth, "client_data_json")),
        "authenticator_data": b64url(hexed(auth, "authenticator_data")),
        "signature": b64url(hexed(auth, "signature")),
        "user_handle": b64url(hexed(auth, "user_handle")),
    }


def known_credential(case: dict[str, Any]) -> NewCredential:
    return verify_registration(
        known_registration(case),
        challenge=hexed(case["registration"], "challenge"),
        origin=known_answers()["origin"],
        rp_id=known_answers()["rp_id"],
        enrolled=(),
    )


def known_verify(case: dict[str, Any], body: dict[str, Any], **changes: Any) -> Asserted:
    kwargs: dict[str, Any] = {
        "challenge": hexed(case["authentication"], "challenge"),
        "origin": known_answers()["origin"],
        "rp_id": known_answers()["rp_id"],
        "credentials": [known_credential(case)],
        "user_handle": bytes.fromhex(known_answers()["user_handle"]),
        "login": True,
    }
    kwargs.update(changes)
    return verify_assertion(body, **kwargs)


@pytest.mark.parametrize("name", KNOWN)
def test_the_known_answers_are_accepted(name: str) -> None:
    case = known_case(name)
    new = known_credential(case)
    assert new == NewCredential(
        id=bytes.fromhex(case["credential_id"]),
        rp_id="localhost",
        alg=case["algorithm"],
        spki=hexed(case["registration"], "public_key"),
        sign_count=0,
        backup_eligible=case["backup_eligible"],
        backup_state=case["backup_state"],
        transports=tuple(case["transports"]),
    )
    count = case["authentication"]["sign_count"]
    assert known_verify(case, known_assertion(case)) == Asserted(
        new.id, count, case["backup_state"], False
    )
    # Its key, with getPublicKey() null as Safari gives it, comes from the template alone.
    assert (
        verify_registration(
            dict(known_registration(case), public_key=None),
            challenge=hexed(case["registration"], "challenge"),
            origin="http://localhost:8081",
            rp_id="localhost",
            enrolled=(),
        )
        == new
    )


def test_the_known_answers_cover_each_algorithm() -> None:
    assert {known_case(n)["algorithm"] for n in KNOWN} == set(ALGORITHMS)
    assert ALGORITHMS == (ES256, EDDSA, RS256) == (-7, -8, -257)


# --- each algorithm, each switch, each kind -----------------------------------------------------


@pytest.mark.parametrize("kind", [*GOOD_KINDS, Kind.RS256_3072, Kind.RS256_4096])
def test_a_ceremony_for_each_accepted_kind(kind: Kind) -> None:
    authenticator = SoftAuthenticator(backup_eligible=False, backup_state=False, counts=True)
    enrolled = enrol(kind, authenticator)
    new = enrolled.credential
    held = authenticator.held(RP_ID)[0]
    assert new == NewCredential(
        held.id, RP_ID, kind.alg, held.spki, 0, False, False, ("hybrid", "internal")
    )
    assert enrolled.verify(enrolled.get()) == Asserted(new.id, 1, False, False)
    assert enrolled.verify(enrolled.get()) == Asserted(new.id, 2, False, False)


@pytest.mark.parametrize("kind", [Kind.EDDSA, Kind.RS256])
def test_safari_null_public_key_is_accepted_from_the_template(kind: Kind) -> None:
    safari = SoftAuthenticator(browser="safari")
    attestation = safari.create(options(), kind=kind)
    assert attestation.body()["public_key"] is None
    new = register(attestation.body())
    assert new.spki == safari.held(RP_ID)[0].spki
    assert Enrolled(safari, new).verify(safari.get(get_options())).credential_id == new.id


CREATE_SWITCHES: dict[Switch, str] = {
    Switch.NO_UP: "not_present",
    Switch.NO_UV: "not_verified",
    Switch.WRONG_TYPE: "wrong_type",
    Switch.CROSS_ORIGIN: "cross_origin",
    Switch.TOP_ORIGIN: "top_origin",
    Switch.BOM: ACCEPTED,
    Switch.EXTRA_KEY: ACCEPTED,
    Switch.BS_WITHOUT_BE: "backup_flags",
    Switch.FLIP_BE: ACCEPTED,  # get only
    Switch.AT_ON_ASSERTION: ACCEPTED,  # get only
    Switch.EXTENSIONS: ACCEPTED,
    Switch.TRAILING_BYTE: "key_encoding",
    Switch.COSE_REORDERED: "key_encoding",
    Switch.COSE_EXTRA_PARAMETER: "key_encoding",
    Switch.NULL_PUBLIC_KEY: ACCEPTED,
    Switch.OTHER_PUBLIC_KEY: "key_mismatch",
    Switch.WRONG_ALGORITHM: "algorithm",
    Switch.COUNTER_BACK: ACCEPTED,  # get only
    Switch.FLIP_SIGNATURE: ACCEPTED,  # get only
    Switch.RAW_ID_MISMATCH: "raw_id_mismatch",
}
GET_SWITCHES: dict[Switch, str] = {
    Switch.NO_UP: "not_present",
    Switch.NO_UV: "not_verified",
    Switch.WRONG_TYPE: "wrong_type",
    Switch.CROSS_ORIGIN: "cross_origin",
    Switch.TOP_ORIGIN: "top_origin",
    Switch.BOM: ACCEPTED,
    Switch.EXTRA_KEY: ACCEPTED,
    Switch.BS_WITHOUT_BE: "backup_flags",
    Switch.FLIP_BE: "backup_eligibility_changed",
    Switch.AT_ON_ASSERTION: "at_flag",
    Switch.EXTENSIONS: ACCEPTED,
    Switch.TRAILING_BYTE: "trailing_bytes",
    Switch.COSE_REORDERED: ACCEPTED,  # create only
    Switch.COSE_EXTRA_PARAMETER: ACCEPTED,  # create only
    Switch.NULL_PUBLIC_KEY: ACCEPTED,  # create only
    Switch.OTHER_PUBLIC_KEY: ACCEPTED,  # create only
    Switch.WRONG_ALGORITHM: ACCEPTED,  # create only
    Switch.COUNTER_BACK: ACCEPTED,
    Switch.FLIP_SIGNATURE: "signature",
    Switch.RAW_ID_MISMATCH: "unknown_credential",
}


def test_every_switch_has_an_expected_outcome() -> None:
    assert set(CREATE_SWITCHES) == set(GET_SWITCHES) == set(Switch)


@pytest.mark.parametrize("kind", GOOD_KINDS)
@pytest.mark.parametrize("switch", list(Switch))
def test_each_create_switch(switch: Switch, kind: Kind) -> None:
    attestation = attest(kind, switch)
    assert outcome(register, attestation.body()) == CREATE_SWITCHES[switch]


@pytest.mark.parametrize("kind", GOOD_KINDS)
@pytest.mark.parametrize("switch", list(Switch))
def test_each_get_switch(switch: Switch, kind: Kind) -> None:
    enrolled = enrol(kind)
    assertion = enrolled.get(switch)
    assert outcome(enrolled.verify, assertion) == GET_SWITCHES[switch]


def test_get_switches_on_a_device_bound_credential() -> None:
    enrolled = enrol(authenticator=SoftAuthenticator(backup_eligible=False, backup_state=False))
    assert not enrolled.credential.backup_eligible
    flipped = enrolled.get(Switch.FLIP_BE)
    assert refused(enrolled.verify, flipped) == "backup_eligibility_changed"
    bs = enrolled.get(Switch.BS_WITHOUT_BE)
    assert refused(enrolled.verify, bs) == "backup_flags"


KINDS: dict[Kind, str] = {
    Kind.ES256: ACCEPTED,
    Kind.EDDSA: ACCEPTED,
    Kind.RS256: ACCEPTED,
    Kind.RS256_3072: ACCEPTED,
    Kind.RS256_4096: ACCEPTED,
    Kind.RS256_1024: "key_encoding",  # n is 128 bytes: below the template's 256
    Kind.RS256_E3: "key_encoding",  # the template fixes e = 65537
    Kind.ES256_P384: "key_encoding",  # crv 2 and 48-byte coordinates
}


@pytest.mark.parametrize("kind", list(Kind))
def test_each_kind(kind: Kind) -> None:
    assert set(KINDS) == set(Kind)
    assert outcome(register, attest(kind).body()) == KINDS[kind]


# --- D.3's order --------------------------------------------------------------------------------

CREATE_ORDER = [
    ({Switch.WRONG_TYPE, Switch.NO_UP}, "wrong_type"),
    ({Switch.CROSS_ORIGIN, Switch.TOP_ORIGIN}, "cross_origin"),
    ({Switch.TOP_ORIGIN, Switch.NO_UP}, "top_origin"),
    ({Switch.NO_UP, Switch.NO_UV}, "not_present"),
    ({Switch.NO_UV, Switch.BS_WITHOUT_BE}, "not_verified"),
    ({Switch.NO_UV, Switch.COSE_REORDERED}, "not_verified"),
    ({Switch.BS_WITHOUT_BE, Switch.RAW_ID_MISMATCH}, "backup_flags"),
    ({Switch.RAW_ID_MISMATCH, Switch.COSE_EXTRA_PARAMETER}, "raw_id_mismatch"),
    ({Switch.COSE_REORDERED, Switch.WRONG_ALGORITHM}, "key_encoding"),
    ({Switch.WRONG_ALGORITHM, Switch.OTHER_PUBLIC_KEY}, "algorithm"),
]


@pytest.mark.parametrize(("switches", "reason"), CREATE_ORDER)
def test_registration_checks_run_in_order(switches: set[Switch], reason: str) -> None:
    assert refused(register, attest(Kind.ES256, *switches).body()) == reason


def test_registration_order_beyond_the_switches() -> None:
    attestation = attest(Kind.ES256, Switch.NO_UV)
    body = attestation.body()
    huge = b64url(padded(attestation.client_data_json, 4097))
    assert refused(register, dict(body, client_data_json=huge)) == "too_large"
    assert refused(register, body, challenge=b"\x00" * 32, origin="x") == "wrong_challenge"
    assert refused(register, body, origin="http://localhost:3000") == "wrong_origin"
    assert refused(register, body, rp_id=OTHER_RP) == "wrong_rp"
    # No attested data comes before the RP ID hash; the client data before both.
    no_at = attestation.authenticator_data[:32] + bytes([UP]) + attestation.authenticator_data[33:]
    assert (
        refused(register, dict(body, authenticator_data=b64url(no_at)), rp_id=OTHER_RP)
        == "no_attested_data"
    )
    wrong_type = attest(Kind.ES256, Switch.WRONG_TYPE)
    short = b64url(wrong_type.authenticator_data[:54])
    assert refused(register, with_body(wrong_type, authenticator_data=short)) == "wrong_type"
    # The key's checks come before the enrolled credentials are looked at.
    other = attest(Kind.ES256, Switch.OTHER_PUBLIC_KEY)
    full = [record(bytes([i]) * 16) for i in range(MAX_PASSKEYS)]
    same_id = record(b64url_decode(other.body()["id"]))
    assert refused(register, other.body(), enrolled=[same_id, *full]) == "key_mismatch"
    good = attest(Kind.ES256)
    duplicate = record(good.id)
    assert refused(register, good.body(), enrolled=[duplicate, *full]) == "duplicate_credential"


GET_ORDER = [
    ({Switch.WRONG_TYPE, Switch.AT_ON_ASSERTION}, "wrong_type"),
    ({Switch.CROSS_ORIGIN, Switch.TOP_ORIGIN}, "cross_origin"),
    ({Switch.AT_ON_ASSERTION, Switch.NO_UP}, "at_flag"),
    ({Switch.TRAILING_BYTE, Switch.NO_UP}, "trailing_bytes"),
    ({Switch.NO_UP, Switch.NO_UV}, "not_present"),
    ({Switch.NO_UV, Switch.BS_WITHOUT_BE}, "not_verified"),
    ({Switch.BS_WITHOUT_BE, Switch.FLIP_SIGNATURE}, "backup_flags"),
    ({Switch.FLIP_BE, Switch.FLIP_SIGNATURE}, "backup_eligibility_changed"),
    ({Switch.RAW_ID_MISMATCH, Switch.WRONG_TYPE}, "unknown_credential"),
]


@pytest.mark.parametrize(("switches", "reason"), GET_ORDER)
def test_assertion_checks_run_in_order(switches: set[Switch], reason: str) -> None:
    enrolled = enrol()
    assertion = enrolled.get(*switches)
    assert refused(enrolled.verify, assertion) == reason


def test_assertion_order_beyond_the_switches() -> None:
    enrolled = enrol()
    wrong_type = enrolled.get(Switch.WRONG_TYPE, Switch.NO_UV)
    unknown = dataclasses.replace(wrong_type, id=b"unknown")
    assert refused(enrolled.verify, unknown, allowed=[b"other"]) == "not_allowed"
    assert refused(enrolled.verify, dataclasses.replace(unknown, user_handle=None)) == (
        "unknown_credential"
    )
    assert refused(enrolled.verify, wrong_type, user=b"other") == "user_handle"
    assert refused(enrolled.verify, wrong_type, origin="x", challenge=b"") == "wrong_type"
    # The RP ID hash comes after the length checks, and before UP.
    no_up = enrolled.get(Switch.NO_UP, Switch.TRAILING_BYTE)
    other_rp = enrolled.resigned(
        no_up, auth_data=hashlib.sha256(OTHER_RP.encode()).digest() + no_up.authenticator_data[32:]
    )
    assert refused(enrolled.verify, other_rp) == "trailing_bytes"
    no_up = enrolled.get(Switch.NO_UP)
    other_rp = enrolled.resigned(
        no_up, auth_data=hashlib.sha256(OTHER_RP.encode()).digest() + no_up.authenticator_data[32:]
    )
    assert refused(enrolled.verify, other_rp) == "wrong_rp"
    huge = dataclasses.replace(wrong_type, signature=b"\x00" * 1025)
    assert refused(enrolled.verify, huge, allowed=[b"other"]) == "too_large"


# --- the posted fields: shape and sizes ---------------------------------------------------------


@pytest.mark.parametrize("body", [None, [], "body", 1, {"id": "AA"}])
def test_a_body_that_isnt_the_fields_is_refused(body: Any) -> None:
    assert refused(register, body) == "bad_field"
    enrolled = enrol()
    assert refused(enrolled.verify, body) == "bad_field"


def test_a_missing_or_extra_field_is_refused() -> None:
    body = attest().body()
    for name in body:
        assert refused(register, {k: v for k, v in body.items() if k != name}) == "bad_field"
    assert refused(register, dict(body, name="laptop")) == "bad_field"
    enrolled = enrol()
    get_body = enrolled.get().body()
    for name in get_body:
        missing = {k: v for k, v in get_body.items() if k != name}
        assert refused(enrolled.verify, missing) == "bad_field"
    assert refused(enrolled.verify, dict(get_body, extra=None)) == "bad_field"
    assert set(body) == webauthn.REGISTRATION_FIELDS
    assert set(get_body) == webauthn.ASSERTION_FIELDS


E_ACUTE = chr(0xE9)
NOT_BASE64URL = [1, None, ["AA"], "AA==", "A", "AB", "a+b/", "AA AA", " AAAA", "AAAA\n", E_ACUTE]


@pytest.mark.parametrize("value", NOT_BASE64URL)
def test_each_bytes_field_must_be_strict_base64url(value: Any) -> None:
    body = attest().body()
    for name in ("id", "client_data_json", "authenticator_data", "public_key"):
        if name == "public_key" and value is None:
            continue
        assert refused(register, dict(body, **{name: value})) == "bad_field"
    enrolled = enrol()
    get_body = enrolled.get().body()
    for name in ("id", "client_data_json", "authenticator_data", "signature", "user_handle"):
        if name == "user_handle" and value is None:
            continue
        assert refused(enrolled.verify, dict(get_body, **{name: value})) == "bad_field"


@pytest.mark.parametrize("value", [True, False, "-7", -7.0, [-7], {"alg": -7}])
def test_the_algorithm_must_be_an_integer_or_null(value: Any) -> None:
    attestation = attest()
    assert refused(register, with_body(attestation, public_key_algorithm=value)) == "bad_field"
    assert register(with_body(attestation, public_key_algorithm=None)).alg == ES256
    assert register(with_body(attestation, public_key=None, public_key_algorithm=None))


def test_transports() -> None:
    attestation = attest()
    for transport in sorted(TRANSPORTS):
        new = register(with_body(attestation, transports=[transport]))
        assert new.transports == (transport,)
    assert sorted(TRANSPORTS) == ["ble", "hybrid", "internal", "nfc", "smart-card", "usb"]
    assert register(with_body(attestation, transports=[])).transports == ()
    every = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"]
    assert register(with_body(attestation, transports=every)).transports == tuple(sorted(every))
    wrongs: list[object] = [
        ["cable"],
        ["USB"],
        [1],
        [["usb"]],
        [None],
        ["usb", "usb"],
        "usb",
        None,
        {},
    ]
    for wrong in wrongs:
        assert refused(register, with_body(attestation, transports=wrong)) == "bad_field"
    eight = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal", "usb", "nfc"]
    assert refused(register, with_body(attestation, transports=eight)) == "bad_field"
    assert refused(register, with_body(attestation, transports=[*eight, "ble"])) == "too_large"
    assert refused(register, with_body(attestation, transports=[[]] * 9)) == "too_large"


def test_registration_sizes() -> None:
    attestation = attest(Kind.ES256, Switch.EXTENSIONS)
    body = attestation.body()
    for size, expected in ((4096, ACCEPTED), (4097, "too_large")):
        data = b64url(padded(attestation.client_data_json, size))
        assert outcome(register, dict(body, client_data_json=data)) == expected
        # Extensions are never parsed, so any bytes after the key make up the size.
        tail = b"\x00" * (size - len(attestation.authenticator_data))
        auth = b64url(attestation.authenticator_data + tail)
        assert outcome(register, dict(body, authenticator_data=auth)) == expected
    for size, expected in ((2048, "key_mismatch"), (2049, "too_large")):
        key = b64url(b"\x30" * size)
        assert outcome(register, dict(body, public_key=key)) == expected


@pytest.mark.parametrize(
    ("length", "expected"),
    [(0, "credential_id"), (1, ACCEPTED), (1023, ACCEPTED), (1024, "too_large")],
)
def test_credential_id_lengths(length: int, expected: str) -> None:
    authenticator = SoftAuthenticator()
    attestation = authenticator.create(options(), id_length=length)
    assert outcome(register, attestation.body()) == expected
    if expected == ACCEPTED:
        enrolled = Enrolled(authenticator, register(attestation.body()))
        assert len(enrolled.credential.id) == length
        assert enrolled.verify(enrolled.get()).credential_id == enrolled.credential.id


def test_the_credential_id_length_in_authenticator_data() -> None:
    long = attest(id_length=1024)
    # rawId within the size limit, authData's L of 1024 over the spec's limit.
    assert refused(register, with_body(long, id=b64url(long.id[:1023]))) == "credential_id"
    good = attest()
    auth = good.authenticator_data
    # authData that ends inside the credential ID, and one that ends right after it.
    for end, expected in ((55 + 31, "credential_id"), (55 + 32, "key_encoding")):
        body = with_body(good, authenticator_data=b64url(auth[:end]))
        assert refused(register, body) == expected
    for end, expected in ((54, "no_attested_data"), (55, "credential_id")):
        cut = auth[:53] + b"\x00\x00" if end == 55 else auth[:54]
        body = with_body(good, authenticator_data=b64url(cut))
        assert refused(register, body) == expected


def test_assertion_sizes() -> None:
    authenticator = SoftAuthenticator()
    long_user = b"\x01" * 64
    enrolled = enrol(authenticator=authenticator, user=long_user)
    assertion = enrolled.get(Switch.EXTENSIONS)
    for size, expected in ((4096, ACCEPTED), (4097, "too_large")):
        data = enrolled.resigned(assertion, client_data=padded(assertion.client_data_json, size))
        assert outcome(enrolled.verify, data) == expected
    for size, expected in ((1024, ACCEPTED), (1025, "too_large")):
        tail = b"\x00" * (size - len(assertion.authenticator_data))
        data = enrolled.resigned(assertion, auth_data=assertion.authenticator_data + tail)
        assert outcome(enrolled.verify, data) == expected
    for size, expected in ((1024, "signature"), (1025, "too_large")):
        data = dataclasses.replace(assertion, signature=b"\x30" * size)
        assert outcome(enrolled.verify, data) == expected
    assert enrolled.verify(assertion, user=long_user).credential_id == enrolled.credential.id
    longer = dataclasses.replace(assertion, user_handle=long_user + b"\x01")
    assert refused(enrolled.verify, longer, user=long_user + b"\x01") == "too_large"
    for size, expected in ((1023, "unknown_credential"), (1024, "too_large")):
        data = dataclasses.replace(assertion, id=b"\x02" * size)
        assert outcome(enrolled.verify, data) == expected


# --- base64url ----------------------------------------------------------------------------------


def test_base64url_is_strict() -> None:
    assert b64url(b"\xfb\xff") == "-_8"
    assert b64url_decode("-_8") == b"\xfb\xff"
    assert b64url_decode("") == b""
    assert b64url_decode("AAAA") == b"\x00\x00\x00"
    for text in ("+/8", "-_8=", "AA==", "AB", "A", "AA!A", "AA\nAA", " AA", E_ACUTE, "AAA="):
        with pytest.raises(ValueError, match=r"base64|ASCII|padding|data characters"):
            b64url_decode(text)


@settings(max_examples=100, deadline=None)
@given(st.binary(max_size=80))
def test_base64url_round_trips(data: bytes) -> None:
    assert b64url_decode(b64url(data)) == data
    assert "=" not in b64url(data)


# --- client data --------------------------------------------------------------------------------


def with_client_data(raw: bytes, **kwargs: Any) -> str:
    attestation = attest()
    return outcome(register, with_body(attestation, client_data_json=b64url(raw)), **kwargs)


CLIENT_DATA_REFUSED = [
    (b"", "client_data"),
    (b"[]", "client_data"),
    (b"null", "client_data"),
    (b'"webauthn.create"', "client_data"),
    (b"\xff" + client_data(**create_data()), "client_data"),
    (client_data(**create_data())[:-1], "client_data"),
    (BOM + BOM + client_data(**create_data()), "client_data"),
    (client_data(**create_data(n=float("nan"))), "client_data"),
    (client_data(**create_data())[:-1] + b',"type":"webauthn.create"}', "client_data"),
    (client_data(**create_data(type=1)), "client_data"),
    (client_data(**create_data(challenge=None)), "client_data"),
    (client_data(**create_data(challenge=list(CHALLENGE))), "client_data"),
    (client_data(**create_data(origin=["http://localhost:8081"])), "client_data"),
    (client_data(**create_data(crossOrigin="false")), "client_data"),
    (client_data(**create_data(crossOrigin=0)), "client_data"),
    (client_data(**create_data(crossOrigin=None)), "client_data"),
    (client_data(**{k: v for k, v in create_data().items() if k != "type"}), "client_data"),
    (client_data(**{k: v for k, v in create_data().items() if k != "challenge"}), "client_data"),
    (client_data(**{k: v for k, v in create_data().items() if k != "origin"}), "client_data"),
    (client_data(**create_data(type="webauthn.get")), "wrong_type"),
    (client_data(**create_data(type="payment.get")), "wrong_type"),
    (client_data(**create_data(type="webauthn.create ")), "wrong_type"),
    (client_data(**create_data(challenge=b64url(CHALLENGE[:-1]))), "wrong_challenge"),
    (client_data(**create_data(challenge=b64url(CHALLENGE + b"\x00"))), "wrong_challenge"),
    (client_data(**create_data(challenge=b64url(bytes(32)))), "wrong_challenge"),
    (client_data(**create_data(challenge=b64url(CHALLENGE) + "=")), "wrong_challenge"),
    (client_data(**create_data(challenge="")), "wrong_challenge"),
    (client_data(**create_data(challenge="!")), "wrong_challenge"),
    (client_data(**create_data(origin=ORIGIN + "/")), "wrong_origin"),
    (client_data(**create_data(origin="http://LOCALHOST:8081")), "wrong_origin"),
    (client_data(**create_data(origin="http://localhost:8082")), "wrong_origin"),
    (client_data(**create_data(origin="https://localhost:8081")), "wrong_origin"),
    (client_data(**create_data(origin="http://localhost")), "wrong_origin"),
    (client_data(**create_data(origin="")), "wrong_origin"),
    (client_data(**create_data(crossOrigin=True)), "cross_origin"),
    (client_data(**create_data(topOrigin="https://other.example")), "top_origin"),
    (client_data(**create_data(topOrigin=None)), "top_origin"),
    (client_data(**create_data(crossOrigin=True, topOrigin=ORIGIN)), "cross_origin"),
    # Each check before the next.
    (client_data(**create_data(type="webauthn.get", challenge="")), "wrong_type"),
    (client_data(**create_data(challenge="", origin="")), "wrong_challenge"),
    (client_data(**create_data(origin="", crossOrigin=True)), "wrong_origin"),
]


@pytest.mark.parametrize(("raw", "reason"), CLIENT_DATA_REFUSED)
def test_client_data_refusals(raw: bytes, reason: str) -> None:
    assert with_client_data(raw) == reason


CLIENT_DATA_ACCEPTED = [
    client_data(**create_data()),
    BOM + client_data(**create_data()),
    client_data(**{k: v for k, v in create_data().items() if k != "crossOrigin"}),
    client_data(origin=ORIGIN, challenge=b64url(CHALLENGE), type="webauthn.create"),
    client_data(**create_data(tokenBinding={"status": "present"}, extraData=[1, "two"])),
    json.dumps(create_data(), separators=(" , ", " : "), indent=1).encode(),
]


@pytest.mark.parametrize("raw", CLIENT_DATA_ACCEPTED)
def test_client_data_accepted(raw: bytes) -> None:
    assert with_client_data(raw) == ACCEPTED


@pytest.mark.parametrize(("raw", "reason"), CLIENT_DATA_REFUSED[:12])
def test_assertion_client_data_has_the_same_checks(raw: bytes, reason: str) -> None:
    enrolled = enrol()
    raw = raw.replace(b"webauthn.create", b"webauthn.get")
    assertion = enrolled.resigned(enrolled.get(), client_data=raw)
    assert refused(enrolled.verify, assertion) == reason
    created = enrolled.resigned(enrolled.get(), client_data=client_data(**create_data()))
    assert refused(enrolled.verify, created) == "wrong_type"


def test_the_client_data_is_hashed_as_received() -> None:
    enrolled = enrol()
    with_bom = enrolled.get(Switch.BOM)
    assert with_bom.client_data_json.startswith(BOM)
    assert enrolled.verify(with_bom)
    # Signed over the client data without its BOM: the hash must be of the bytes received.
    stripped = with_bom.client_data_json.removeprefix(BOM)
    signature = sign(
        enrolled.private_key,
        with_bom.authenticator_data + hashlib.sha256(stripped).digest(),
    )
    assert refused(enrolled.verify, dataclasses.replace(with_bom, signature=signature)) == (
        "signature"
    )


# --- registration: flags, keys and the enrolled set ---------------------------------------------


def test_registration_flags() -> None:
    good = attest()
    auth = bytearray(good.authenticator_data)
    for flags, expected in (
        (UP | UV | AT, ACCEPTED),
        (UP | UV | AT | BE, ACCEPTED),
        (UP | UV | AT | BE | BS, ACCEPTED),
        (UP | UV | AT | 0x02 | 0x20, ACCEPTED),  # RFU bits are ignored
        (UP | UV | AT | BS, "backup_flags"),
        (UV | AT, "not_present"),
        (UP | AT, "not_verified"),
        (UP | UV, "no_attested_data"),
        (UP | UV | AT | ED, "key_encoding"),
    ):
        auth[32] = flags
        body = with_body(good, authenticator_data=b64url(bytes(auth)))
        assert outcome(register, body) == expected
    auth[32] = UP | UV | AT | BE
    new = register(with_body(good, authenticator_data=b64url(bytes(auth))))
    assert (new.backup_eligible, new.backup_state) == (True, False)
    auth[32] = UP | UV | AT | BE | BS
    auth[33:37] = (7).to_bytes(4, "big")
    new = register(with_body(good, authenticator_data=b64url(bytes(auth))))
    assert (new.backup_eligible, new.backup_state, new.sign_count) == (True, True, 7)


def test_the_rp_id_hash() -> None:
    attestation = SoftAuthenticator().create(options(), rp_id=OTHER_RP)
    assert refused(register, attestation.body()) == "wrong_rp"
    assert register(attestation.body(), rp_id=OTHER_RP).rp_id == OTHER_RP


def test_the_ceremony_values_are_checked() -> None:
    attestation = attest()
    assert refused(register, attestation.body(), challenge=CHALLENGE[:-1]) == "wrong_challenge"
    assert refused(register, attestation.body(), origin="http://localhost:3000") == "wrong_origin"
    elsewhere = SoftAuthenticator().create(options(), "http://localhost:3000")
    assert register(elsewhere.body(), origin="http://localhost:3000")


@pytest.mark.parametrize("fixed", [*range(10), 42, 43, 44])
def test_every_fixed_byte_of_the_es256_template(fixed: int) -> None:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    cose = cose_key(key, ES256)
    assert register(crafted(cose)).spki == der(key)
    for delta in (0x01, 0x80, 0xFF):
        changed = bytearray(cose)
        changed[fixed] ^= delta
        assert refused(register, crafted(bytes(changed))) == "key_encoding"


@pytest.mark.parametrize("fixed", range(10))
def test_every_fixed_byte_of_the_eddsa_template(fixed: int) -> None:
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    cose = cose_key(key, EDDSA)
    assert register(crafted(cose)).spki == der(key)
    for delta in (0x01, 0x80, 0xFF):
        changed = bytearray(cose)
        changed[fixed] ^= delta
        assert refused(register, crafted(bytes(changed))) == "key_encoding"


def test_every_fixed_byte_of_the_rs256_template() -> None:
    key = rsa_key(2048)
    cose = cose_key(key, RS256)
    assert register(crafted(cose)).spki == der(key)
    for fixed in [*range(9), *range(len(cose) - 5, len(cose))]:
        for delta in (0x01, 0x80, 0xFF):
            changed = bytearray(cose)
            changed[fixed] ^= delta
            body = crafted(bytes(changed))
            assert refused(register, body) == "key_encoding"


@pytest.mark.parametrize(
    ("size", "top", "expected"),
    [
        (255, 0xFF, "key_encoding"),
        (256, 0x80, ACCEPTED),  # 2048 bits
        (256, 0x7F, "public_key"),  # 2047 bits
        (256, 0x00, "public_key"),
        (300, 0x00, "public_key"),  # not minimal, though over 2048 bits
        (300, 0x01, ACCEPTED),
        (512, 0xFF, ACCEPTED),  # 4096 bits
        (512, 0x00, "public_key"),
        (513, 0x01, "key_encoding"),
    ],
)
def test_rsa_template_lengths_and_sizes(size: int, top: int, expected: str) -> None:
    n = rsa_n(size, top)
    assert outcome(register, crafted(rs256_cose(n))) == expected
    if expected == ACCEPTED:
        new = register(crafted(rs256_cose(n)))
        assert new.alg == RS256
        loaded = serialization.load_der_public_key(new.spki)
        assert isinstance(loaded, rsa.RSAPublicKey)
        assert loaded.public_numbers() == rsa.RSAPublicNumbers(65537, int.from_bytes(n, "big"))


def test_rsa_template_structure() -> None:
    n = rsa_n(256, 0xC0)
    assert register(crafted(rs256_cose(n)))
    # The length field must be n's length: shorter or longer, the tail isn't where it should be.
    for length in (255, 257):
        body = crafted(rs256_cose(n, length=length))
        assert refused(register, body) == "key_encoding"
    # e = 3, or e = 65537 written another way.
    for tail in ("214103", "21430100", "214401000001", "2243010001"):
        body = crafted(rs256_cose(n, tail=tail))
        assert refused(register, body) == "key_encoding"
    assert refused(register, crafted(rs256_cose(n)[:-1])) == "key_encoding"
    with_ed = crafted(rs256_cose(n), flags=UP | UV | AT | ED, tail=b"\xa0")
    assert register(with_ed).alg == RS256


def test_es256_points_off_the_curve_are_refused() -> None:
    one = (1).to_bytes(32, "big")
    assert refused(register, crafted(es256_cose(one, one))) == "public_key"
    assert refused(register, crafted(es256_cose(bytes(32), bytes(32)))) == "public_key"
    big = b"\xff" * 32
    assert refused(register, crafted(es256_cose(big, big))) == "public_key"
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    numbers = key.public_numbers()
    x, y = numbers.x.to_bytes(32, "big"), numbers.y.to_bytes(32, "big")
    assert register(crafted(es256_cose(x, y))).spki == der(key)
    flipped = y[:-1] + bytes([y[-1] ^ 1])
    assert refused(register, crafted(es256_cose(x, flipped))) == "public_key"
    assert refused(register, crafted(es256_cose(x, y)[:-1])) == "key_encoding"


def test_eddsa_keys_from_the_template() -> None:
    key = ed25519.Ed25519PrivateKey.generate().public_key()
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert register(crafted(eddsa_cose(raw))).spki == der(key)
    assert refused(register, crafted(eddsa_cose(raw[:-1]))) == "key_encoding"
    assert refused(register, crafted(eddsa_cose(raw) + b"\x00")) == "key_encoding"


def test_the_algorithm_must_be_the_templates() -> None:
    for kind in GOOD_KINDS:
        attestation = attest(kind)
        assert register(attestation.body()).alg == kind.alg
        for alg in (*ALGORITHMS, -35, -36, -53, -9, -19, 0, 7):
            if alg == kind.alg:
                continue
            body = with_body(attestation, public_key_algorithm=alg)
            assert refused(register, body) == "algorithm"


def other_spkis(key: Any) -> list[bytes]:
    """Keys that aren't ``key``: another of its kind, other kinds, and near-misses."""
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()
    others = [
        der(p256),
        der(ec.generate_private_key(ec.SECP384R1()).public_key()),
        der(ed25519.Ed25519PrivateKey.generate().public_key()),
        der(x25519.X25519PrivateKey.generate().public_key()),
        der(rsa_key(2048)),
    ]
    if isinstance(key, rsa.RSAPublicKey):
        n = key.public_numbers().n
        others.append(der(rsa.RSAPublicNumbers(3, n).public_key()))
    encoded = der(key)
    others += [encoded + b"\x00", encoded[:-1], b"", b"\x30\x00", encoded[:-1] + b"\x00"]
    return [o for o in others if o != encoded]


@pytest.mark.parametrize("kind", GOOD_KINDS)
def test_get_public_key_must_be_the_same_key(kind: Kind) -> None:
    authenticator = SoftAuthenticator()
    attestation = authenticator.create(options(), kind=kind)
    key = authenticator.held(RP_ID)[0].public_key
    for other in other_spkis(key):
        body = with_body(attestation, public_key=b64url(other))
        assert refused(register, body) == "key_mismatch"
    assert register(attestation.body()).spki == der(key)


def test_a_compressed_point_of_the_same_key_is_the_same_key() -> None:
    authenticator = SoftAuthenticator()
    attestation = authenticator.create(options())
    key = authenticator.held(RP_ID)[0].public_key
    point = key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    compressed = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200") + point
    new = register(with_body(attestation, public_key=b64url(compressed)))
    assert new.spki == der(key) != compressed


def test_the_enrolled_credentials() -> None:
    attestation = attest()
    same_elsewhere = record(attestation.id, rp_id=OTHER_RP)
    assert refused(register, attestation.body(), enrolled=[same_elsewhere]) == (
        "duplicate_credential"
    )
    near = [record(attestation.id[:-1]), record(attestation.id + b"\x00")]
    assert register(attestation.body(), enrolled=near)
    others = [record(i.to_bytes(2, "big")) for i in range(MAX_PASSKEYS)]
    assert register(attestation.body(), enrolled=others[:-1])
    assert refused(register, attestation.body(), enrolled=others) == "too_many_passkeys"
    assert MAX_PASSKEYS == 32


# --- assertion: lookup, user handle, lengths, flags, signature, counter -------------------------


def test_the_allow_list() -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    own = enrolled.credential.id
    assert enrolled.verify(assertion, allowed=[own])
    assert enrolled.verify(assertion, allowed=[b"other", own])
    assert enrolled.verify(assertion, allowed=())
    for allowed in ([b"other"], [own[:-1]], [own + b"\x00"]):
        assert refused(enrolled.verify, assertion, allowed=allowed) == "not_allowed"


def test_the_credential_is_looked_up_within_the_entrys_rp_id() -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    own = enrolled.credential
    elsewhere = dataclasses.replace(own, rp_id=OTHER_RP)
    for credentials in ([], [elsewhere], [record(own.id[:-1]), record(own.id + b"\x00")]):
        assert refused(enrolled.verify, assertion, credentials=credentials) == (
            "unknown_credential"
        )
    # Among several, the one with this ID and RP ID.
    decoys = [elsewhere, record(b"\x01" * 16), dataclasses.replace(own, rp_id="example.org")]
    assert enrolled.verify(assertion, credentials=[*decoys, own]).credential_id == own.id
    assert refused(enrolled.verify, assertion, rp_id=OTHER_RP) == "unknown_credential"


def test_the_user_handle() -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    without = dataclasses.replace(assertion, user_handle=None)
    assert refused(enrolled.verify, without, login=True) == "user_handle"
    assert enrolled.verify(without, login=False)
    for login in (True, False):
        assert enrolled.verify(assertion, login=login)
        for user in (b"\x00" * 32, USER[:-1], USER + b"\x5a", b""):
            assert refused(enrolled.verify, assertion, login=login, user=user) == "user_handle"
    empty = dataclasses.replace(assertion, user_handle=b"")
    assert refused(enrolled.verify, empty, login=False) == "user_handle"
    assert enrolled.verify(empty, login=False, user=b"")


def test_assertion_lengths_and_flags() -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    auth = assertion.authenticator_data
    flags = auth[32]
    cases = [
        (auth, ACCEPTED),
        (auth[:36], "trailing_bytes"),
        (b"", "trailing_bytes"),
        (auth + b"\xa0", "trailing_bytes"),
        (auth[:32] + bytes([flags | ED]) + auth[33:], "trailing_bytes"),
        (auth[:32] + bytes([flags | ED]) + auth[33:] + b"\xa0", ACCEPTED),
        (auth[:32] + bytes([flags | AT]) + auth[33:], "at_flag"),
        (auth[:32] + bytes([flags | 0x02 | 0x20]) + auth[33:], ACCEPTED),  # RFU ignored
        (auth[:32] + bytes([flags & ~UP]) + auth[33:], "not_present"),
        (auth[:32] + bytes([flags & ~UV]) + auth[33:], "not_verified"),
        (auth[:32] + bytes([flags & ~BS]) + auth[33:], ACCEPTED),  # BS may change
        (auth[:32] + bytes([flags & ~BE]) + auth[33:], "backup_flags"),
        (auth[:32] + bytes([flags & ~BE & ~BS]) + auth[33:], "backup_eligibility_changed"),
        (bytes(32) + auth[32:], "wrong_rp"),
    ]
    for data, expected in cases:
        resigned = enrolled.resigned(assertion, auth_data=data)
        assert outcome(enrolled.verify, resigned) == expected
    without_bs = enrolled.resigned(
        assertion, auth_data=auth[:32] + bytes([flags & ~BS]) + auth[33:]
    )
    assert enrolled.verify(without_bs).backup_state is False
    assert enrolled.verify(assertion).backup_state is True


def test_the_signature() -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    message = assertion.authenticator_data + hashlib.sha256(assertion.client_data_json).digest()
    key = enrolled.private_key
    assert isinstance(key, ec.EllipticCurvePrivateKey)
    r, s = utils.decode_dss_signature(assertion.signature)
    wrong = [
        b"",
        assertion.signature + b"\x00",
        r.to_bytes(32, "big") + s.to_bytes(32, "big"),  # raw r || s, not DER
        sign(key, assertion.authenticator_data),  # without the client data hash
        sign(key, assertion.authenticator_data + assertion.client_data_json),
        sign(
            key, hashlib.sha256(assertion.client_data_json).digest() + assertion.authenticator_data
        ),
        key.sign(message, ec.ECDSA(hashes.SHA384())),
        sign(ec.generate_private_key(ec.SECP256R1()), message),
    ]
    for signature in wrong:
        replaced = dataclasses.replace(assertion, signature=signature)
        assert refused(enrolled.verify, replaced) == "signature"
    assert enrolled.verify(assertion)


def test_the_stored_key_is_pinned_to_its_algorithm() -> None:
    es256 = enrol(Kind.ES256)
    eddsa = enrol(Kind.EDDSA)
    rs256 = enrol(Kind.RS256)
    for enrolled in (es256, eddsa, rs256):
        assertion = enrolled.get()
        own = enrolled.credential
        for alg in (*ALGORITHMS, -35, 0):
            if alg == own.alg:
                continue
            credential = dataclasses.replace(own, alg=alg)
            assert refused(enrolled.verify, assertion, credentials=[credential]) == "signature"
        for spki_ in (b"", b"\x30\x00", own.spki[:-1]):
            credential = dataclasses.replace(own, spki=spki_)
            assert refused(enrolled.verify, assertion, credentials=[credential]) == "signature"
    # A P-384 key stored as ES256, with a P-384 signature over SHA-256, is refused too.
    p384 = ec.generate_private_key(ec.SECP384R1())
    assertion = es256.get()
    signature = p384.sign(
        assertion.authenticator_data + hashlib.sha256(assertion.client_data_json).digest(),
        ec.ECDSA(hashes.SHA256()),
    )
    credential = dataclasses.replace(es256.credential, spki=der(p384.public_key()))
    signed = dataclasses.replace(assertion, signature=signature)
    assert refused(es256.verify, signed, credentials=[credential]) == "signature"


@pytest.mark.parametrize(
    ("stored", "new", "kept", "regressed"),
    [
        (0, 0, 0, False),
        (5, 6, 6, False),
        (5, 5, 5, True),
        (5, 4, 5, True),
        (0, 3, 3, False),
        (3, 0, 3, True),
        (0, 1, 1, False),
        (1, 0, 1, True),
        (2**32 - 1, 2**32 - 1, 2**32 - 1, True),
    ],
)
def test_the_counter(stored: int, new: int, kept: int, regressed: bool) -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    auth = assertion.authenticator_data
    counted = enrolled.resigned(assertion, auth_data=auth[:33] + new.to_bytes(4, "big"))
    credential = dataclasses.replace(enrolled.credential, sign_count=stored)
    assert enrolled.verify(counted, credentials=[credential]) == Asserted(
        credential.id, kept, True, regressed
    )


def test_a_counter_that_goes_back_is_flagged_and_accepted() -> None:
    authenticator = SoftAuthenticator(counts=True)
    enrolled = enrol(authenticator=authenticator)
    for _ in range(3):
        asserted = enrolled.verify(enrolled.get())
        enrolled.credential = dataclasses.replace(
            enrolled.credential, sign_count=asserted.sign_count
        )
    assert enrolled.credential.sign_count == 3
    back = enrolled.verify(enrolled.get(Switch.COUNTER_BACK))
    assert (back.sign_count, back.regressed) == (3, True)


# --- options (D.1) ------------------------------------------------------------------------------


def test_the_creation_options() -> None:
    mine = record(b"\x01" * 16, transports=("hybrid", "internal"))
    other = record(b"\x02" * 16, rp_id=OTHER_RP, transports=("usb",))
    usb = record(b"\x03" * 16, transports=("usb",))
    assert creation_options(
        challenge=CHALLENGE, user_handle=USER, rp_id=RP_ID, exclude=[mine, other, usb]
    ) == {
        "rp": {"id": "localhost", "name": "ZoeyMCP"},
        "user": {"id": b64url(USER), "name": "zoeymcp", "displayName": "ZoeyMCP operator"},
        "challenge": b64url(CHALLENGE),
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -8},
            {"type": "public-key", "alg": -257},
        ],
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": True,
            "userVerification": "required",
        },
        "attestation": "none",
        "excludeCredentials": [
            {
                "type": "public-key",
                "id": b64url(b"\x01" * 16),
                "transports": ["hybrid", "internal"],
            },
            {"type": "public-key", "id": b64url(b"\x03" * 16), "transports": ["usb"]},
        ],
        "timeout": 300000,
    }
    reset = creation_options(challenge=CHALLENGE, user_handle=USER, rp_id=RP_ID, exclude=())
    assert reset["excludeCredentials"] == []


def test_the_request_options() -> None:
    mine = record(b"\x01" * 16, transports=("internal",))
    other = record(b"\x02" * 16, rp_id=OTHER_RP)
    assert request_options(challenge=CHALLENGE, rp_id=RP_ID) == {
        "challenge": b64url(CHALLENGE),
        "rpId": "localhost",
        "userVerification": "required",
        "allowCredentials": [],
        "timeout": 300000,
    }
    step_up = request_options(challenge=CHALLENGE, rp_id=RP_ID, allow=[mine, other])
    assert step_up["allowCredentials"] == [
        {"type": "public-key", "id": b64url(b"\x01" * 16), "transports": ["internal"]}
    ]


def test_the_options_drive_an_authenticator() -> None:
    authenticator = SoftAuthenticator()
    first = enrol(authenticator=authenticator)
    assert first.credential.alg == ES256  # offered first
    # A second enrolment on the same authenticator is refused by the browser, not overwritten.
    with pytest.raises(InvalidStateError):
        authenticator.create(options(exclude=[first.credential]))
    # A reset excludes nothing: the authenticator overwrites its credential.
    replaced = register(authenticator.create(options(exclude=())).body())
    assert [c.id for c in authenticator.held(RP_ID)] == [replaced.id]
    allow = request_options(challenge=CHALLENGE, rp_id=RP_ID, allow=[replaced])
    assert Enrolled(authenticator, replaced).verify(
        authenticator.get(allow), allowed=[replaced.id], login=False
    )


# --- properties ---------------------------------------------------------------------------------


@settings(max_examples=60, deadline=None)
@given(
    name=st.sampled_from(KNOWN),
    field=st.sampled_from(["authenticator_data", "client_data_json", "signature"]),
    data=st.data(),
)
def test_any_single_byte_change_is_refused(name: str, field: str, data: st.DataObject) -> None:
    case = known_case(name)
    body = known_assertion(case)
    raw = bytearray(b64url_decode(body[field]))
    position = data.draw(st.integers(0, len(raw) - 1))
    raw[position] ^= data.draw(st.integers(1, 255))
    changed = dict(body, **{field: b64url(bytes(raw))})
    with pytest.raises(WebAuthnError):
        known_verify(case, changed)


JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-(2**53) + 1, 2**53 - 1),
    st.text(st.characters(exclude_categories=["Cs"]), max_size=20),
)
NAMED = ("type", "challenge", "origin", "crossOrigin", "topOrigin")


@settings(max_examples=60, deadline=None)
@given(
    order=st.permutations(["type", "challenge", "origin", "crossOrigin"]),
    extra=st.dictionaries(
        st.text(st.characters(exclude_categories=["Cs"]), max_size=12).filter(
            lambda k: k not in NAMED
        ),
        JSON_SCALARS,
        max_size=4,
    ),
    data=st.data(),
)
def test_client_data_keys_in_any_order_with_extra_keys_are_accepted(
    order: list[str], extra: dict[str, Any], data: st.DataObject
) -> None:
    case = known_case("es256-synced")
    auth = case["authentication"]
    values = {
        "type": "webauthn.get",
        "challenge": b64url(hexed(auth, "challenge")),
        "origin": known_answers()["origin"],
        "crossOrigin": False,
    }
    items = [(k, values[k]) for k in order] + list(extra.items())
    shuffled = data.draw(st.permutations(items))
    raw = json.dumps(dict(shuffled)).encode()
    key = ec.derive_private_key(
        int(case["credential_key"]["credential_private_key"], 16), ec.SECP256R1()
    )
    auth_data = hexed(auth, "authenticator_data")
    body = dict(
        known_assertion(case),
        client_data_json=b64url(raw),
        signature=b64url(sign(key, auth_data + hashlib.sha256(raw).digest())),
    )
    assert known_verify(case, body).credential_id == bytes.fromhex(case["credential_id"])


@settings(max_examples=40, deadline=None)
@given(scalar=st.integers(1, 2**255), seed=st.binary(min_size=32, max_size=32))
def test_the_templates_round_trip_ec_and_eddsa(scalar: int, seed: bytes) -> None:
    p256 = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
    ed = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key()
    for key, alg in ((p256, ES256), (ed, EDDSA)):
        new = register(crafted(cose_key(key, alg), public_key=der(key), alg=alg))
        assert (new.alg, new.spki) == (alg, der(key))


@settings(max_examples=40, deadline=None)
@given(size=st.integers(256, 512), data=st.data())
def test_the_template_round_trips_every_rsa_length(size: int, data: st.DataObject) -> None:
    top = data.draw(st.integers(0x80 if size == 256 else 0x01, 0xFF))
    middle = data.draw(st.binary(min_size=size - 2, max_size=size - 2))
    n = int.from_bytes(bytes([top]) + middle + b"\x01", "big")
    key = rsa.RSAPublicNumbers(65537, n).public_key()
    cose = cose_key(key, RS256)
    assert len(cose) == size + 16
    new = register(crafted(cose, public_key=der(key), alg=RS256))
    assert (new.alg, new.spki) == (RS256, der(key))


FIELD_VALUES = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.text(max_size=8),
    st.lists(st.text(max_size=8), max_size=10),
    st.binary(max_size=200).map(b64url),
)


def registration_prefix(flags: int, length: int) -> bytes:
    return (
        hashlib.sha256(RP_ID.encode()).digest()
        + bytes([flags])
        + bytes(4)
        + bytes(16)
        + length.to_bytes(2, "big")
        + b"\x01" * min(length, 1023)
    )


AUTH_DATA = st.one_of(
    st.binary(max_size=200),
    st.builds(
        lambda flags, length, head, rest: registration_prefix(flags, length) + head + rest,
        st.integers(0, 255),
        st.sampled_from([0, 1, 16, 1023, 1024, 4000]),
        st.sampled_from(
            [
                b"",
                bytes.fromhex("a5010203262001215820"),
                bytes.fromhex("a4010103272006215820"),
                bytes.fromhex("a40103033901002059"),
                bytes.fromhex("a401030339010020590100"),
                bytes.fromhex("a401030339010020590200"),
            ]
        ),
        st.binary(max_size=600),
    ),
)


def only_refuses(call: Callable[..., object], *args: Any, **kwargs: Any) -> None:
    with contextlib.suppress(WebAuthnError):
        call(*args, **kwargs)


@settings(max_examples=200, deadline=None)
@given(
    body=st.one_of(
        FIELD_VALUES,
        st.dictionaries(st.sampled_from(sorted(webauthn.REGISTRATION_FIELDS)), FIELD_VALUES),
        st.fixed_dictionaries(
            {
                "id": st.one_of(st.just(b64url(b"\x01" * 16)), FIELD_VALUES),
                "client_data_json": st.one_of(
                    st.just(b64url(client_data_json("webauthn.create", CHALLENGE, ORIGIN))),
                    st.binary(max_size=100).map(b64url),
                ),
                "authenticator_data": AUTH_DATA.map(b64url),
                "public_key": st.one_of(st.none(), st.binary(max_size=300).map(b64url)),
                "public_key_algorithm": st.one_of(st.none(), st.sampled_from(ALGORITHMS)),
                "transports": st.one_of(
                    st.lists(st.sampled_from(sorted(TRANSPORTS)), max_size=10), FIELD_VALUES
                ),
            }
        ),
    )
)
def test_any_registration_input_raises_only_a_refusal(body: Any) -> None:
    only_refuses(register, body)


@settings(max_examples=200, deadline=None)
@given(
    body=st.one_of(
        FIELD_VALUES,
        st.dictionaries(st.sampled_from(sorted(webauthn.ASSERTION_FIELDS)), FIELD_VALUES),
        st.fixed_dictionaries(
            {
                "id": st.one_of(st.just(b64url(b"\x01" * 16)), FIELD_VALUES),
                "client_data_json": st.one_of(
                    st.just(b64url(client_data_json("webauthn.get", CHALLENGE, ORIGIN))),
                    st.binary(max_size=100).map(b64url),
                ),
                "authenticator_data": st.one_of(
                    st.binary(max_size=100),
                    st.builds(
                        lambda flags, rest: (
                            hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + rest
                        ),
                        st.integers(0, 255),
                        st.binary(max_size=40),
                    ),
                ).map(b64url),
                "signature": st.binary(max_size=600).map(b64url),
                "user_handle": st.one_of(st.none(), st.just(b64url(USER)), FIELD_VALUES),
            }
        ),
    ),
    alg=st.sampled_from([*ALGORITHMS, -35]),
    spki_=st.one_of(st.just(der(rsa_key(2048))), st.binary(max_size=100)),
)
def test_any_assertion_input_raises_only_a_refusal(body: Any, alg: int, spki_: bytes) -> None:
    credentials = [record(b"\x01" * 16, alg=alg, spki=spki_, backup_eligible=True)]
    for login in (True, False):
        only_refuses(
            verify_assertion,
            body,
            challenge=CHALLENGE,
            origin=ORIGIN,
            rp_id=RP_ID,
            credentials=credentials,
            user_handle=USER,
            login=login,
        )
