"""The software authenticator builds what browsers and authenticators build (M5 design O.1).

Its layouts are checked against the WebAuthn L3 §16 vectors in ``tests/unit/data/webauthn``:
the COSE keys, authenticator data, attestation objects, client data and signatures it writes for
the vectors' inputs are the vectors' bytes. The same tests check the vector files themselves:
each ``authenticator_data`` is where the README says it was cut from the attestation object.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

from .authenticator import (
    AT,
    BE,
    BOM,
    BS,
    CHROME_EXTRA_KEY,
    ED,
    EDDSA,
    ES256,
    ORIGIN,
    RP_ID,
    RS256,
    TOP_ORIGIN,
    UP,
    UV,
    Assertion,
    Attestation,
    InvalidStateError,
    Kind,
    NotAllowedError,
    NotSupportedError,
    PublicKey,
    SoftAuthenticator,
    Switch,
    attestation_object_none,
    attested_credential_data,
    authenticator_data,
    b64url,
    b64url_decode,
    cbor,
    client_data_json,
    cose_key,
    creation_options,
    request_options,
    rsa_from_primes,
    sign,
    spki,
)

SPEC = "https://www.w3.org/TR/2026/REC-webauthn-3-20260825/"
DATA = Path(__file__).resolve().parents[1] / "unit" / "data" / "webauthn"
SECTIONS = ["16.2", "16.4", "16.5", "16.6", "16.7", "16.8", "16.9", "16.10", "16.11", "16.12"]
SECTIONS += ["16.13"]
KEYED = ["16.2", "16.4", "16.5", "16.6", "16.7", "16.10", "16.11", "16.13"]  # ES256, EdDSA, RS256
SUPPORTED = {ES256, EDDSA, RS256}
CURVES = {-7: ec.SECP256R1(), -35: ec.SECP384R1(), -36: ec.SECP521R1()}
USER = bytes(range(32))
CHALLENGE = b"\x07" * 32


@cache
def vector(section: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((DATA / f"{section}.json").read_text(encoding="utf-8"))
    return loaded


def vector_key(v: dict[str, Any]) -> Any:
    """The vector's credential private key."""
    fields = v["credential_key"]
    alg = v["algorithm"]
    if alg in CURVES:
        return ec.derive_private_key(int(fields["credential_private_key"], 16), CURVES[alg])
    if alg == RS256:
        return rsa_from_primes(int(fields["private_key_p"], 16), int(fields["private_key_q"], 16))
    if alg == EDDSA:
        return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fields["private_key"]))
    return ed448.Ed448PrivateKey.from_private_bytes(bytes.fromhex(fields["private_key"]))


@cache
def section_key(section: str) -> Any:
    return vector_key(vector(section))


def hexed(v: dict[str, Any], part: str, name: str) -> bytes:
    return bytes.fromhex(v[part][name])


def verify(public_key: PublicKey, signature: bytes, message: bytes, alg: int) -> None:
    if alg == ES256:
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    elif alg == EDDSA:
        assert isinstance(public_key, ed25519.Ed25519PublicKey)
        public_key.verify(signature, message)
    else:
        assert isinstance(public_key, rsa.RSAPublicKey)
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())


def signed(assertion: Assertion) -> bytes:
    return assertion.authenticator_data + hashlib.sha256(assertion.client_data_json).digest()


def enrol(
    authenticator: SoftAuthenticator, user: bytes = USER, **kwargs: Any
) -> tuple[Attestation, bytes]:
    attestation = authenticator.create(creation_options(CHALLENGE, user), **kwargs)
    return attestation, attestation.authenticator_data[55 : 55 + len(attestation.id)]


# --- the vector files and the layouts, against L3 §16 -------------------------------------------


@pytest.mark.parametrize("section", SECTIONS)
def test_the_vector_file_is_cut_as_the_readme_says(section: str) -> None:
    v = vector(section)
    assert v["section"] == section
    assert v["source"].startswith(f"{SPEC}#sctn-test-vectors-")
    attestation_object = hexed(v, "registration", "attestation_object")
    auth_data = hexed(v, "registration", "authenticator_data")
    header = b"\x58" + bytes([len(auth_data)]) if len(auth_data) < 256 else b"\x59"
    if len(auth_data) >= 256:
        header += len(auth_data).to_bytes(2, "big")
    assert attestation_object.endswith(cbor("authData") + header + auth_data)
    assert v["registration"]["flags"] == f"0x{auth_data[32]:02x}"
    assert (
        v["authentication"]["flags"]
        == f"0x{hexed(v, 'authentication', 'authenticator_data')[32]:02x}"
    )
    assert auth_data[:32] == hashlib.sha256(v["rp_id"].encode()).digest()
    public_key = serialization.load_der_public_key(hexed(v, "registration", "public_key"))
    assert spki(section_key(section).public_key()) == spki(public_key)  # type: ignore[arg-type]


@pytest.mark.parametrize("section", SECTIONS)
def test_the_layouts_rebuild_each_vector(section: str) -> None:
    v = vector(section)
    reg = v["registration"]
    auth_data = hexed(v, "registration", "authenticator_data")
    cose = cose_key(section_key(section).public_key(), v["algorithm"])
    flags = int(reg["flags"], 16)
    assert flags & ED == 0
    rebuilt = authenticator_data(
        v["rp_id"],
        flags,
        0,
        attested_credential_data(
            hexed(v, "registration", "aaguid"), hexed(v, "registration", "credential_id"), cose
        ),
    )
    assert rebuilt == auth_data
    a_auth_data = hexed(v, "authentication", "authenticator_data")
    assert authenticator_data(v["rp_id"], a_auth_data[32], 0) == a_auth_data


def test_the_cose_lengths_are_the_templates() -> None:
    lengths = {}
    for section in SECTIONS:
        v = vector(section)
        auth_data = hexed(v, "registration", "authenticator_data")
        cose = auth_data[55 + int.from_bytes(auth_data[53:55], "big") :]
        lengths[section] = len(cose)
        if v["algorithm"] == ES256:
            assert len(cose) == 77
            assert cose.startswith(bytes.fromhex("a5010203262001215820"))
        elif v["algorithm"] == EDDSA:
            assert len(cose) == 42
            assert cose.startswith(bytes.fromhex("a4010103272006215820"))
    # RS256: the template is len(n) + 16 bytes; §16.10's n is 436 bytes (a 3482-bit modulus).
    v = vector("16.10")
    n = section_key("16.10").public_key().public_numbers().n
    assert (n.bit_length(), (n.bit_length() + 7) // 8) == (3482, 436)
    assert lengths["16.10"] == 436 + 16 == 452
    cose = hexed(v, "registration", "authenticator_data")[55 + 32 :]
    assert cose[:11] == bytes.fromhex("a40103033901002059") + (436).to_bytes(2, "big")
    assert cose[-5:] == bytes.fromhex("2143010001")
    # ES384, ES512 and Ed448 keys are longer than every template.
    assert (lengths["16.8"], lengths["16.9"], lengths["16.12"]) == (110, 146, 68)


@pytest.mark.parametrize("section", ["16.2", "16.4", "16.5", "16.6"])
def test_the_none_attestation_object_is_the_vectors(section: str) -> None:
    v = vector(section)
    auth_data = hexed(v, "registration", "authenticator_data")
    assert attestation_object_none(auth_data) == hexed(v, "registration", "attestation_object")


@pytest.mark.parametrize("section", KEYED)
def test_the_signatures_are_the_vectors(section: str) -> None:
    v = vector(section)
    message = (
        hexed(v, "authentication", "authenticator_data")
        + hashlib.sha256(hexed(v, "authentication", "client_data_json")).digest()
    )
    # ECDSA signs with RFC 6979 nonces, as the vectors' signatures were made.
    assert sign(section_key(section), message) == hexed(v, "authentication", "signature")
    verify(
        section_key(section).public_key(),
        hexed(v, "authentication", "signature"),
        message,
        v["algorithm"],
    )


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("part", ["registration", "authentication"])
def test_the_client_data_is_the_vectors(section: str, part: str) -> None:
    v = vector(section)
    raw = hexed(v, part, "client_data_json")
    parsed = json.loads(raw)
    rebuilt = client_data_json(
        parsed["type"],
        hexed(v, part, "challenge"),
        parsed["origin"],
        cross_origin=parsed["crossOrigin"],
        top_origin=parsed.get("topOrigin"),
    )
    if "extraData" in parsed:  # the vectors' own extra key, which the fake doesn't write
        extra = json.dumps(parsed["extraData"])
        assert raw == rebuilt[:-1] + b',"extraData":' + extra.encode() + b"}"
    else:
        assert raw == rebuilt
    assert parsed["origin"] == v["origin"] == "https://example.org"


def test_the_cbor_writer_is_ctap2_canonical() -> None:
    assert cbor({-1: 1, 3: -7, 1: 2}) == bytes.fromhex("a3010203262001")
    assert cbor({3: -7, 1: 2}, canonical=False) == bytes.fromhex("a203260102")
    assert cbor({"authData": b"", "fmt": "none", "attStmt": {}}) == bytes.fromhex(
        "a363666d74646e6f6e656761747453746d74a068617574684461746140"
    )
    assert cbor(-257) == bytes.fromhex("390100")
    assert cbor(b"\x00" * 256)[:3] == bytes.fromhex("590100")
    assert cbor(True) + cbor(False) == b"\xf5\xf4"
    with pytest.raises(TypeError):
        cbor(1.5)


# --- ceremonies ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "cose_length"),
    [(Kind.ES256, 77), (Kind.EDDSA, 42), (Kind.RS256, 256 + 16)],
)
def test_a_ceremony_for_each_algorithm(kind: Kind, cose_length: int) -> None:
    authenticator = SoftAuthenticator()
    attestation, cred_id = enrol(authenticator, kind=kind)
    auth_data = attestation.authenticator_data
    assert attestation.id == cred_id
    assert len(cred_id) == 32
    assert auth_data[:32] == hashlib.sha256(RP_ID.encode()).digest()
    assert auth_data[32] == UP | UV | BE | BS | AT
    assert auth_data[33:37] == bytes(4)
    assert int.from_bytes(auth_data[53:55], "big") == 32
    assert len(auth_data) == 55 + 32 + cose_length
    assert attestation.public_key_algorithm == kind.alg
    assert attestation.public_key is not None
    public_key = serialization.load_der_public_key(attestation.public_key)
    assert auth_data[55 + 32 :] == cose_key(public_key, kind.alg)  # type: ignore[arg-type]
    client_data = json.loads(attestation.client_data_json)
    assert client_data == {
        "type": "webauthn.create",
        "challenge": b64url(CHALLENGE),
        "origin": ORIGIN,
        "crossOrigin": False,
    }
    body = attestation.body()
    assert b64url_decode(body["authenticator_data"]) == auth_data
    assert body["transports"] == ["hybrid", "internal"]

    assertion = authenticator.get(request_options(b"\x09" * 32))
    assert assertion.id == cred_id
    assert assertion.user_handle == USER
    assert len(assertion.authenticator_data) == 37
    assert assertion.authenticator_data[32] == UP | UV | BE | BS
    verify(public_key, assertion.signature, signed(assertion), kind.alg)  # type: ignore[arg-type]
    assert json.loads(assertion.client_data_json)["type"] == "webauthn.get"
    assert b64url_decode(assertion.body()["signature"]) == assertion.signature


@pytest.mark.parametrize(("kind", "n_bytes"), [(Kind.RS256_3072, 384), (Kind.RS256_4096, 512)])
def test_larger_rsa_keys_fill_the_template(kind: Kind, n_bytes: int) -> None:
    attestation, _ = enrol(SoftAuthenticator(), kind=kind)
    cose = attestation.authenticator_data[55 + 32 :]
    assert len(cose) == n_bytes + 16
    assert cose[:11] == bytes.fromhex("a40103033901002059") + n_bytes.to_bytes(2, "big")
    assert cose[-5:] == bytes.fromhex("2143010001")


def test_the_keys_the_verifier_must_refuse() -> None:
    short, _ = enrol(SoftAuthenticator(), kind=Kind.RS256_1024)
    assert short.authenticator_data[55 + 32 :][8:10] == bytes.fromhex("5880")  # 128-byte n
    e3, _ = enrol(SoftAuthenticator(), kind=Kind.RS256_E3)
    assert e3.authenticator_data[-3:] == bytes.fromhex("214103")
    p384, _ = enrol(SoftAuthenticator(), kind=Kind.ES256_P384)
    cose = p384.authenticator_data[55 + 32 :]
    assert cose[:10] == bytes.fromhex("a5010203262002215830")  # alg -7, crv 2 (P-384)
    assert p384.public_key_algorithm == ES256
    assert p384.public_key is not None
    loaded = serialization.load_der_public_key(p384.public_key)
    assert isinstance(loaded, ec.EllipticCurvePublicKey)
    assert isinstance(loaded.curve, ec.SECP384R1)


def test_the_first_offered_algorithm_is_chosen() -> None:
    authenticator = SoftAuthenticator()
    options = creation_options(CHALLENGE, USER, algorithms=(-35, EDDSA, ES256))
    assert authenticator.create(options).public_key_algorithm == EDDSA
    with pytest.raises(NotSupportedError):
        authenticator.create(creation_options(CHALLENGE, USER, algorithms=(-35, -36)))


def test_safari_gives_no_public_key_for_eddsa_and_rs256() -> None:
    safari = SoftAuthenticator(browser="safari")
    for kind in (Kind.EDDSA, Kind.RS256):
        attestation, _ = enrol(safari, user=kind.value.encode(), kind=kind)
        assert attestation.public_key is None
        assert attestation.body()["public_key"] is None
    attestation, _ = enrol(safari, kind=Kind.ES256)
    assert attestation.public_key is not None


def test_credentials_are_kept_per_rp_id_and_user_handle() -> None:
    authenticator = SoftAuthenticator()
    first, first_id = enrol(authenticator)
    _, other_id = enrol(authenticator, user=b"\x01" * 32)
    elsewhere = authenticator.create(creation_options(CHALLENGE, USER, rp_id="admin.example"))
    assert [c.id for c in authenticator.held(RP_ID)] == [first_id, other_id]
    # The same RP ID and user handle again: the first credential is overwritten (§6.3.2).
    _, second_id = enrol(authenticator)
    assert [c.id for c in authenticator.held(RP_ID)] == [other_id, second_id]
    assert [c.id for c in authenticator.held("admin.example")] == [elsewhere.id]
    # Login with an empty allow list picks the newest; an allow list restricts the choice.
    assert authenticator.get(request_options(CHALLENGE)).id == second_id
    assert authenticator.get(request_options(CHALLENGE, allow=[other_id])).id == other_id
    assert authenticator.get(request_options(CHALLENGE), credential_id=other_id).id == other_id
    with pytest.raises(NotAllowedError):
        authenticator.get(request_options(CHALLENGE, allow=[first_id]))
    with pytest.raises(NotAllowedError):
        authenticator.get(request_options(CHALLENGE, rp_id="other.example"))
    assert first.id == first_id


def test_an_excluded_credential_refuses_the_ceremony() -> None:
    authenticator = SoftAuthenticator()
    _, cred_id = enrol(authenticator)
    with pytest.raises(InvalidStateError):
        authenticator.create(creation_options(CHALLENGE, b"\x02" * 32, exclude=[cred_id]))
    # Excluding it under another RP ID, or excluding an unknown ID, doesn't.
    authenticator.create(
        creation_options(CHALLENGE, USER, rp_id="admin.example", exclude=[cred_id])
    )
    authenticator.create(creation_options(CHALLENGE, b"\x02" * 32, exclude=[b"unknown"]))


def test_counters() -> None:
    synced = SoftAuthenticator()
    enrol(synced)
    counts = [synced.get(request_options(CHALLENGE)).authenticator_data[33:37] for _ in range(2)]
    assert counts == [bytes(4), bytes(4)]
    key = SoftAuthenticator(backup_eligible=False, backup_state=False, counts=True)
    attestation, _ = enrol(key)
    assert attestation.authenticator_data[32] == UP | UV | AT
    seen = [
        int.from_bytes(key.get(request_options(CHALLENGE)).authenticator_data[33:37], "big")
        for _ in range(3)
    ]
    assert seen == [1, 2, 3]
    back = key.get(request_options(CHALLENGE), switches={Switch.COUNTER_BACK})
    assert back.authenticator_data[32] == UP | UV
    assert int.from_bytes(back.authenticator_data[33:37], "big") == 2


@pytest.mark.parametrize("length", [0, 1023, 1024])
def test_credential_id_lengths(length: int) -> None:
    attestation, cred_id = enrol(SoftAuthenticator(), id_length=length)
    assert len(attestation.id) == len(cred_id) == length
    assert int.from_bytes(attestation.authenticator_data[53:55], "big") == length


def test_the_given_key_and_id_are_used() -> None:
    key = ec.derive_private_key(12345, ec.SECP256R1())
    attestation, cred_id = enrol(SoftAuthenticator(), key=key, credential_id=b"chosen")
    assert cred_id == attestation.id == b"chosen"
    assert attestation.public_key == spki(key.public_key())


# --- switches -----------------------------------------------------------------------------------


def test_flag_switches() -> None:
    def flags(switch: Switch, ceremony: str) -> int:
        authenticator = SoftAuthenticator()
        attestation, _ = enrol(authenticator, switches={switch} if ceremony == "create" else ())
        if ceremony == "create":
            return attestation.authenticator_data[32]
        return authenticator.get(request_options(CHALLENGE), switches={switch}).authenticator_data[
            32
        ]

    for ceremony, base in (("create", UP | UV | BE | BS | AT), ("get", UP | UV | BE | BS)):
        assert flags(Switch.NO_UP, ceremony) == base & ~UP
        assert flags(Switch.NO_UV, ceremony) == base & ~UV
        assert flags(Switch.BS_WITHOUT_BE, ceremony) == base & ~BE
        assert flags(Switch.EXTENSIONS, ceremony) == base | ED
    assert flags(Switch.FLIP_BE, "get") == UP | UV
    assert flags(Switch.AT_ON_ASSERTION, "get") == UP | UV | BE | BS | AT
    device_bound = SoftAuthenticator(backup_eligible=False)
    enrol(device_bound)
    flipped = device_bound.get(request_options(CHALLENGE), switches={Switch.FLIP_BE})
    assert flipped.authenticator_data[32] == UP | UV | BE


def test_client_data_switches() -> None:
    def client_data(*switches: Switch) -> bytes:
        authenticator = SoftAuthenticator()
        enrol(authenticator)
        return authenticator.get(request_options(CHALLENGE), switches=switches).client_data_json

    assert json.loads(client_data(Switch.WRONG_TYPE))["type"] == "webauthn.create"
    assert json.loads(client_data(Switch.CROSS_ORIGIN))["crossOrigin"] is True
    top = json.loads(client_data(Switch.TOP_ORIGIN))
    assert (top["crossOrigin"], top["topOrigin"]) == (False, TOP_ORIGIN)
    both = client_data(Switch.CROSS_ORIGIN, Switch.TOP_ORIGIN)
    assert both.endswith(b'"crossOrigin":true,"topOrigin":"' + TOP_ORIGIN.encode() + b'"}')
    with_bom = client_data(Switch.BOM)
    assert with_bom.startswith(BOM)
    assert json.loads(with_bom[3:])["type"] == "webauthn.get"
    assert CHROME_EXTRA_KEY in json.loads(client_data(Switch.EXTRA_KEY))
    created = SoftAuthenticator().create(
        creation_options(CHALLENGE, USER), switches={Switch.WRONG_TYPE}
    )
    assert json.loads(created.client_data_json)["type"] == "webauthn.get"
    elsewhere = SoftAuthenticator().create(
        creation_options(CHALLENGE, USER), "http://localhost:3000"
    )
    assert json.loads(elsewhere.client_data_json)["origin"] == "http://localhost:3000"


def test_authenticator_data_switches() -> None:
    attestation, _ = enrol(SoftAuthenticator(), switches={Switch.EXTENSIONS})
    assert attestation.authenticator_data.endswith(cbor({"credProtect": 2}))
    assert len(attestation.authenticator_data) == 55 + 32 + 77 + len(cbor({"credProtect": 2}))
    trailing, _ = enrol(SoftAuthenticator(), switches={Switch.TRAILING_BYTE})
    assert len(trailing.authenticator_data) == 55 + 32 + 77 + 1
    other_rp = SoftAuthenticator().create(creation_options(CHALLENGE, USER), rp_id="other.example")
    assert other_rp.authenticator_data[:32] == hashlib.sha256(b"other.example").digest()

    authenticator = SoftAuthenticator()
    _, cred_id = enrol(authenticator)
    with_extensions = authenticator.get(request_options(CHALLENGE), switches={Switch.EXTENSIONS})
    assert with_extensions.authenticator_data[37:] == cbor({"credProtect": 2})
    one_more = authenticator.get(request_options(CHALLENGE), switches={Switch.TRAILING_BYTE})
    assert len(one_more.authenticator_data) == 38
    with_at = authenticator.get(request_options(CHALLENGE), switches={Switch.AT_ON_ASSERTION})
    assert with_at.authenticator_data[55 : 55 + 32] == cred_id
    public_key = authenticator.held(RP_ID)[0].public_key
    for assertion in (with_extensions, one_more, with_at):  # the signature covers every byte
        verify(public_key, assertion.signature, signed(assertion), ES256)


def test_cose_switches() -> None:
    reordered, _ = enrol(SoftAuthenticator(), switches={Switch.COSE_REORDERED})
    assert reordered.authenticator_data[55 + 32 :][:5] == bytes.fromhex("a503260102")
    assert len(reordered.authenticator_data) == 55 + 32 + 77
    extra, _ = enrol(SoftAuthenticator(), switches={Switch.COSE_EXTRA_PARAMETER})
    assert extra.authenticator_data[55 + 32 :][:7] == bytes.fromhex("a6010202410103")
    eddsa, _ = enrol(SoftAuthenticator(), kind=Kind.EDDSA, switches={Switch.COSE_REORDERED})
    assert eddsa.authenticator_data[55 + 32 :][:5] == bytes.fromhex("a403270101")


def test_public_key_switches() -> None:
    attestation, _ = enrol(SoftAuthenticator(), switches={Switch.NULL_PUBLIC_KEY})
    assert attestation.public_key is None
    for kind in (Kind.ES256, Kind.EDDSA, Kind.RS256):
        authenticator = SoftAuthenticator()
        other, _ = enrol(authenticator, kind=kind, switches={Switch.OTHER_PUBLIC_KEY})
        assert other.public_key is not None
        assert other.public_key != authenticator.held(RP_ID)[0].spki
        assert type(serialization.load_der_public_key(other.public_key)) is type(
            authenticator.held(RP_ID)[0].public_key
        )
    wrong = {
        kind: enrol(SoftAuthenticator(), kind=kind, switches={Switch.WRONG_ALGORITHM})[0]
        for kind in (Kind.ES256, Kind.EDDSA, Kind.RS256)
    }
    assert {k: a.public_key_algorithm for k, a in wrong.items()} == {
        Kind.ES256: EDDSA,
        Kind.EDDSA: RS256,
        Kind.RS256: ES256,
    }


def test_signature_and_id_switches() -> None:
    authenticator = SoftAuthenticator()
    attestation, cred_id = enrol(authenticator, switches={Switch.RAW_ID_MISMATCH})
    assert attestation.id != cred_id
    assert len(attestation.id) == len(cred_id)
    flipped = authenticator.get(request_options(CHALLENGE), switches={Switch.FLIP_SIGNATURE})
    with pytest.raises(InvalidSignature):
        verify(authenticator.held(RP_ID)[0].public_key, flipped.signature, signed(flipped), ES256)
    mismatched = authenticator.get(request_options(CHALLENGE), switches={Switch.RAW_ID_MISMATCH})
    assert mismatched.id != cred_id
    empty, _ = enrol(SoftAuthenticator(), id_length=0, switches={Switch.RAW_ID_MISMATCH})
    assert empty.id == b"\x00"
    replaced = dataclasses.replace(mismatched, user_handle=None)
    assert replaced.body()["user_handle"] is None


# --- our known-answer vectors -------------------------------------------------------------------


def test_the_known_answers_are_reproduced() -> None:
    data = json.loads((DATA / "known-answer.json").read_text(encoding="utf-8"))
    assert (data["rp_id"], data["origin"]) == (RP_ID, ORIGIN)
    user = bytes.fromhex(data["user_handle"])
    assert {case["algorithm"] for case in data["cases"]} == SUPPORTED
    for case in data["cases"]:
        reg, auth = case["registration"], case["authentication"]
        authenticator = SoftAuthenticator(
            aaguid=bytes.fromhex(case["aaguid"]),
            backup_eligible=case["backup_eligible"],
            backup_state=case["backup_state"],
            counts=case["counts"],
            transports=tuple(case["transports"]),
        )
        key = vector_key({"algorithm": case["algorithm"], "credential_key": case["credential_key"]})
        attestation = authenticator.create(
            creation_options(bytes.fromhex(reg["challenge"]), user),
            key=key,
            credential_id=bytes.fromhex(case["credential_id"]),
        )
        assert attestation.client_data_json.hex() == reg["client_data_json"]
        assert attestation.authenticator_data.hex() == reg["authenticator_data"]
        assert attestation.public_key is not None
        assert attestation.public_key.hex() == reg["public_key"]
        assert attestation.public_key_algorithm == reg["public_key_algorithm"] == case["algorithm"]
        assert reg["flags"] == f"0x{attestation.authenticator_data[32]:02x}"
        assertion = authenticator.get(request_options(bytes.fromhex(auth["challenge"])))
        assert assertion.client_data_json.hex() == auth["client_data_json"]
        assert assertion.authenticator_data.hex() == auth["authenticator_data"]
        assert assertion.signature.hex() == auth["signature"]
        assert assertion.user_handle is not None
        assert assertion.user_handle.hex() == auth["user_handle"] == data["user_handle"]
        assert auth["sign_count"] == int.from_bytes(assertion.authenticator_data[33:37], "big")
        public_key = serialization.load_der_public_key(attestation.public_key)
        verify(public_key, assertion.signature, signed(assertion), case["algorithm"])  # type: ignore[arg-type]
        assert reg["expected"] == auth["expected"] == "accepted"
