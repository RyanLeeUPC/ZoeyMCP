"""The managed policy's revisions, head and anchor, sealed (M6 design D.2; Q6 (b), Q40, T-4, T-13).

A seal and its unseal round trip; one flipped byte anywhere, and a change to any field, is refused;
a revision's digest survives a re-seal under another master key while its nonce, ciphertext, key
ID and MAC change; another deployment, an unknown master key and the previous one; two seals of
one policy differ by their salt; every form rule both ways, before and after the MAC; every cap
both sides; and the head and the anchor. The MAC and the encryption are recomputed here from the
derived keys, so a forged file reaches the checks that come after the MAC.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zoeymcp.common import logs
from zoeymcp.common.canonical import digest, dumps_canonical
from zoeymcp.vault import policyseal
from zoeymcp.vault.keys import CONTEXT_POLICY, KeySet, derive
from zoeymcp.vault.policyseal import (
    ANCHOR_CONTEXT,
    ANCHOR_FIELDS,
    ANCHOR_MAX,
    BODY_CONTEXT,
    BODY_FIELDS,
    HEAD_CONTEXT,
    HEAD_FIELDS,
    HEADER_FIELDS,
    KINDS,
    ORIGIN_KINDS,
    ORIGINS,
    REASON_MAX,
    REVISION_BODY_MAX,
    REVISION_CONTEXT,
    REVISION_FIELDS,
    REVISION_FILE_MAX,
    REVISION_MAX,
    VIAS,
    Anchor,
    Body,
    Head,
    SealRefused,
    Unsealed,
    body_digest,
    make_body,
    revision_digest,
    seal_anchor,
    seal_head,
    seal_revision,
    unseal_anchor,
    unseal_head,
    unseal_revision,
)

MASTER = bytes(range(32))
KEYS = KeySet.from_master(MASTER)
OLD_MASTER = bytes(range(1, 33))
OLD = KeySet.from_master(OLD_MASTER)
OTHER_MASTER = bytes(range(2, 34))
OTHER = KeySet.from_master(OTHER_MASTER)
MASTERS = {KEYS.key_id: MASTER, OLD.key_id: OLD_MASTER, OTHER.key_id: OTHER_MASTER}
DEPLOYMENT = "0123456789abcdef" * 2
ELSEWHERE = "fedcba9876543210" * 2
SALT = bytes(range(32))
NONCE = bytes(range(12))
SEED = "sha256:" + "5" * 64
PARENT = "sha256:" + "1" * 64
FINGERPRINT = "0123456789abcdef"
# What a revision's body must never show in clear (D.4).
SENTINEL = "policyseal-placeholder-sentinel"
POLICY: dict[str, Any] = {
    "version": 1,
    "mode": "managed",
    "routes": [{"name": "notes", "placeholder": SENTINEL}],
}
RATCHET: dict[str, Any] = {"egress_key_floor": 1, "gateway_key_floor": 1}


def body(**changes: Any) -> bytes:
    fields: dict[str, Any] = {
        "salt": SALT,
        "policy": POLICY,
        "ratchet": RATCHET,
        "seed_digest": SEED,
        "reason": None,
    }
    fields.update(changes)
    return make_body(**fields)


def header(plaintext: bytes | None = None, **changes: Any) -> dict[str, Any]:
    found: dict[str, Any] = {
        "v": 1,
        "deployment": DEPLOYMENT,
        "revision": 17,
        "parent": PARENT,
        "created": 1_792_900_000,
        "origin": "save",
        "kind": "tool.repin",
        "author": {"by": "passkey", "fingerprint": FINGERPRINT},
        "base": 16,
        "target": None,
        "jumped_from": None,
        "body_digest": body_digest(body() if plaintext is None else plaintext),
    }
    found.update(changes)
    return found


def form(origin: str) -> dict[str, Any]:
    """The changes that make :func:`header` a valid revision of ``origin``: its command's kind, a
    seed as revision 1 by the vault itself, a reseed with no parent, a rollback with a source."""
    kind = "tool.repin" if origin == "save" else f"policy.{origin}"
    changes: dict[str, Any] = {"origin": origin, "kind": kind}
    if origin == "seed":
        changes |= {"revision": 1, "parent": None, "base": None, "author": {"by": "seed"}}
    if origin == "reseed":
        changes["parent"] = None
    if origin == "rollback":
        changes["target"] = 15
    return changes


def sealed(keys: KeySet = KEYS, nonce: bytes = NONCE, **changes: Any) -> bytes:
    return seal_revision(header(**changes), body(), keys=keys, nonce=nonce)


def mac(context: bytes, document: dict[str, Any], keys: KeySet = KEYS) -> str:
    """The MAC as D.2 states it: HMAC-SHA256 under ``K_config`` of the context line and the
    canonical form of every other field."""
    message = context + dumps_canonical({k: v for k, v in document.items() if k != "mac"})
    return hmac.new(keys.config_key, message, hashlib.sha256).hexdigest()


def forged(context: bytes, document: dict[str, Any], keys: KeySet = KEYS) -> bytes:
    """``document`` under a MAC that verifies, whatever its fields hold."""
    document = {**document, "key_id": keys.key_id}
    document["mac"] = mac(context, document, keys)
    return dumps_canonical(document) + b"\n"


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def encrypted(head: dict[str, Any], plaintext: bytes, keys: KeySet = KEYS) -> dict[str, str]:
    """``plaintext`` encrypted as D.2 states it, bound to ``head``'s header fields."""
    associated = BODY_CONTEXT + digest({k: head[k] for k in HEADER_FIELDS}).encode()
    key = derive(MASTERS[keys.key_id], CONTEXT_POLICY)
    ciphertext = AESGCM(key).encrypt(NONCE, plaintext, associated)
    return {"nonce": b64(NONCE), "ciphertext": b64(ciphertext)}


def forged_revision(
    head: dict[str, Any], plaintext: bytes | None = None, keys: KeySet = KEYS
) -> bytes:
    plaintext = body() if plaintext is None else plaintext
    return forged(REVISION_CONTEXT, {**head, "body": encrypted(head, plaintext, keys)}, keys)


def refused(data: bytes, keys: KeySet = KEYS, previous: KeySet | None = None) -> SealRefused:
    with pytest.raises(SealRefused) as caught:
        unseal_revision(data, keys, previous, deployment=DEPLOYMENT)
    return caught.value


def test_the_constants() -> None:
    assert REVISION_MAX == 9_999_999_999
    assert (REVISION_BODY_MAX, REVISION_FILE_MAX) == (1_048_576, 2_097_152)
    assert (policyseal.HEAD_MAX, ANCHOR_MAX) == (4096, 4096)
    assert (policyseal.SALT_BYTES, REASON_MAX, policyseal.VERSION) == (32, 200, 1)
    assert BODY_CONTEXT == b"zoeymcp/policy-body/v1\n"
    assert REVISION_CONTEXT == b"zoeymcp/policy-revision/v1\n"
    assert HEAD_CONTEXT == b"zoeymcp/policy-head/v1\n"
    assert ANCHOR_CONTEXT == b"zoeymcp/policy-anchor/v1\n"
    assert {"seed", "save", "rollback", "import", "resume", "reseed", "acknowledge"} == ORIGINS
    assert {
        "policy.save",
        "tool.repin",
        "tool.allow",
        "client.servers",
        "policy.rollback",
        "connector.limits",
        "policy.import",
        "policy.seed",
        "policy.resume",
        "policy.reseed",
        "policy.acknowledge",
    } == KINDS
    assert {"socket", "offline", "source"} == VIAS
    assert set(header()) == HEADER_FIELDS
    assert HEADER_FIELDS | {"body", "key_id", "mac"} == REVISION_FIELDS
    assert {"nonce", "ciphertext"} == policyseal.SEALED_FIELDS
    assert {"salt", "policy", "ratchet", "seed", "reason"} == BODY_FIELDS
    assert {
        "v",
        "deployment",
        "revision",
        "digest",
        "oldest",
        "oldest_parent",
        "key_id",
        "mac",
    } == HEAD_FIELDS
    assert {
        "v",
        "deployment",
        "highest",
        "parked",
        "retired_key_id",
        "key_id",
        "mac",
    } == ANCHOR_FIELDS


# --- the body ------------------------------------------------------------------------------------


def test_the_body_is_canonical_and_salted() -> None:
    data = body(reason="rotate the notes key")
    assert data == dumps_canonical(
        {
            "policy": POLICY,
            "ratchet": RATCHET,
            "reason": "rotate the notes key",
            "salt": b64(SALT),
            "seed": {"digest": SEED},
        }
    )
    assert body_digest(data) == "sha256:" + hashlib.sha256(data).hexdigest()


def test_two_bodies_of_one_policy_differ_by_their_salt() -> None:
    """The salt makes the digest useless for confirming a guessed policy (E-10)."""
    first, second = body(), body(salt=bytes(range(1, 33)))
    assert body_digest(first) != body_digest(second)
    unsalted = dumps_canonical({"policy": POLICY, "ratchet": RATCHET})
    assert body_digest(unsalted) not in {body_digest(first), body_digest(second)}
    one = revision_digest(header(first))
    assert one != revision_digest(header(second))


@pytest.mark.parametrize(
    "changes",
    [
        {"salt": bytes(31)},
        {"salt": bytes(33)},
        {"seed_digest": "sha256:" + "5" * 63},
        {"seed_digest": "SHA256:" + "5" * 64},
        {"seed_digest": None},
        {"reason": ""},
        {"reason": "x" * 201},
        {"reason": "two\nlines"},
        {"reason": "hidden \u202e text"},
        {"policy": {"big": "x" * REVISION_BODY_MAX}},
    ],
    ids=lambda changes: repr(changes)[:40],
)
def test_make_body_refuses_what_unseal_would(changes: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"^a revision body is a 32-byte salt, a policy"):
        body(**changes)


def test_make_body_keeps_each_bound() -> None:
    for reason in ("x", "x" * 200, "caf\u00e9 \u65e5\u672c"):
        assert json.loads(body(reason=reason))["reason"] == reason
    overhead = len(body(policy={"big": ""}))
    largest = body(policy={"big": "x" * (REVISION_BODY_MAX - overhead)})
    assert len(largest) == REVISION_BODY_MAX
    with pytest.raises(ValueError, match=r"in at most 1 MiB$"):
        body(policy={"big": "x" * (REVISION_BODY_MAX - overhead + 1)})


# --- a revision ----------------------------------------------------------------------------------


def test_a_revision_round_trips() -> None:
    plaintext = body(reason="r")
    data = seal_revision(header(plaintext), plaintext, keys=KEYS, nonce=NONCE)
    for deployment in (DEPLOYMENT, None):
        found = unseal_revision(data, KEYS, None, deployment=deployment)
        assert found.header == header(plaintext)
        assert found.digest == revision_digest(header(plaintext))
        assert found.key_id == KEYS.key_id
        assert found.body == Body(SALT, POLICY, RATCHET, SEED, "r")
        assert found.plaintext == plaintext
        assert found.revision == 17


def test_the_revision_file_is_as_d2_states_it() -> None:
    data = sealed()
    assert data.endswith(b"}\n")
    document = json.loads(data)
    assert dumps_canonical(document) + b"\n" == data
    assert set(document) == REVISION_FIELDS
    assert document["key_id"] == KEYS.key_id
    assert document["mac"] == mac(REVISION_CONTEXT, document)
    assert document["body"]["nonce"] == b64(NONCE)
    head = {k: document[k] for k in HEADER_FIELDS}
    assert head == header()
    name = digest(head)
    assert revision_digest(header()) == name
    key = derive(MASTER, CONTEXT_POLICY)
    ciphertext = base64.b64decode(document["body"]["ciphertext"])
    associated = b"zoeymcp/policy-body/v1\n" + name.encode()
    assert AESGCM(key).decrypt(NONCE, ciphertext, associated) == body()
    assert SENTINEL.encode() not in data


def test_the_digest_is_the_headers_alone() -> None:
    whole = json.loads(sealed())
    assert revision_digest(whole) == revision_digest(header())
    for name in HEADER_FIELDS:
        partial = {k: v for k, v in header().items() if k != name}
        with pytest.raises(ValueError, match=r"^a revision header needs every field"):
            revision_digest(partial)


def test_the_digest_survives_a_reseal() -> None:
    """A master-key rotation (D.7): a new nonce under the new key, the same plaintext, so the same
    digest, and so no parent or head digest moves."""
    first = unseal_revision(sealed(), KEYS, None, deployment=DEPLOYMENT)
    again = seal_revision(first.header, first.plaintext, keys=OLD, nonce=bytes(range(1, 13)))
    second = unseal_revision(again, OLD, None, deployment=DEPLOYMENT)
    assert (second.digest, second.header, second.body) == (first.digest, first.header, first.body)
    assert second.key_id == OLD.key_id
    before, after = json.loads(sealed()), json.loads(again)
    for name in ("body", "key_id", "mac"):
        assert before[name] != after[name], name
    assert {k: before[k] for k in HEADER_FIELDS} == {k: after[k] for k in HEADER_FIELDS}


def test_every_flipped_byte_is_refused() -> None:
    data = sealed()
    for index in range(len(data)):
        flipped = data[:index] + bytes([data[index] ^ 1]) + data[index + 1 :]
        with pytest.raises(SealRefused):
            unseal_revision(flipped, KEYS, None, deployment=DEPLOYMENT)


def _changed(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return 1
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        return value[:-1] + ("0" if value[-1] != "0" else "1")
    return {name: _changed(item) for name, item in value.items()}


@pytest.mark.parametrize("name", sorted(REVISION_FIELDS))
def test_a_change_to_any_field_is_refused(name: str) -> None:
    document = json.loads(sealed())
    document[name] = _changed(document[name])
    reason = "key_unknown" if name == "key_id" else "tampered"
    assert refused(dumps_canonical(document)).reason == reason


def test_another_deployment_is_refused() -> None:
    error = refused(sealed(deployment=ELSEWHERE))
    assert (error.reason, error.detail) == (
        "deployment",
        "belongs to deployment fedcba98, not 01234567",
    )
    assert unseal_revision(sealed(deployment=ELSEWHERE), KEYS, None, deployment=None)


def test_an_unknown_master_key_is_named() -> None:
    for previous in (None, OLD):
        error = refused(sealed(keys=OTHER), previous=previous)
        assert (error.reason, error.key_id) == ("key_unknown", OTHER.key_id)
        assert str(error) == error.detail
        assert error.detail == (
            f"was written under master key ID {OTHER.key_id}, which is neither "
            "ZOEYMCP_MASTER_KEY nor ZOEYMCP_MASTER_KEY_PREVIOUS"
        )


def test_the_previous_master_key_verifies_its_own() -> None:
    found = unseal_revision(sealed(keys=OLD), KEYS, OLD, deployment=DEPLOYMENT)
    assert found.key_id == OLD.key_id
    assert found.body.policy == POLICY
    assert unseal_revision(sealed(), KEYS, OLD, deployment=DEPLOYMENT).key_id == KEYS.key_id
    assert refused(sealed(keys=OLD)).reason == "key_unknown"


def test_a_mac_from_another_master_is_tampered() -> None:
    document = json.loads(sealed(keys=OTHER))
    document["key_id"] = KEYS.key_id
    error = refused(dumps_canonical(document))
    assert (error.reason, error.detail) == (
        "tampered",
        "was tampered with, or written under another master key",
    )
    assert error.key_id is None


def test_a_body_moved_to_another_header_is_refused() -> None:
    """The associated data binds the ciphertext to its header (D.2)."""
    moved = json.loads(sealed())
    moved["created"] += 1
    error = refused(forged(REVISION_CONTEXT, moved))
    assert (error.reason, error.detail) == ("body", "its body doesn't decrypt")
    # Under the right key, but encrypted under another master's K_policy.
    other = forged(REVISION_CONTEXT, json.loads(sealed(keys=OTHER)))
    assert refused(other).reason == "body"


def test_a_body_its_header_doesnt_name_is_refused() -> None:
    error = refused(forged_revision(header(), body(reason="other")))
    assert (error.reason, error.detail) == ("body", "its body isn't the one its header names")
    assert unseal_revision(forged_revision(header()), KEYS, None, deployment=DEPLOYMENT)


def _noncanonical(text: str) -> str:
    """``text`` with its last character's unused low bits set: the same bytes, spelled otherwise."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = text.rstrip("=")[-1]
    padding = len(text) - len(text.rstrip("="))
    spelled = text.rstrip("=")[:-1] + alphabet[alphabet.index(last) | 1] + "=" * padding
    assert base64.b64decode(spelled) == base64.b64decode(text)
    assert spelled != text
    return spelled


NONCANONICAL = _noncanonical(b64(SALT))


def _plain(**changes: Any) -> bytes:
    document: dict[str, Any] = {
        "salt": b64(SALT),
        "policy": POLICY,
        "ratchet": RATCHET,
        "seed": {"digest": SEED},
        "reason": None,
    }
    document.update(changes)
    return dumps_canonical(document)


@pytest.mark.parametrize(
    "plaintext",
    [
        _plain()[:-1] + b" }",
        _plain(extra=1),
        _plain(salt=b64(SALT).rstrip("=")),
        _plain(salt=NONCANONICAL),
        _plain(salt=b64(bytes(31))),
        _plain(salt=1),
        _plain(policy=[POLICY]),
        _plain(ratchet=None),
        _plain(seed=SEED),
        _plain(seed={"digest": SEED, "x": 1}),
        _plain(seed={"digest": "sha256:" + "5" * 65}),
        _plain(reason=7),
        _plain(reason="x" * 201),
        b"[]",
        b"not json",
    ],
    ids=lambda p: p[:40].decode(errors="replace"),
)
def test_a_body_that_isnt_one_is_refused(plaintext: bytes) -> None:
    """Each reaches the body's checks: its digest is the header's and its MAC verifies."""
    data = forged_revision(header(plaintext), plaintext)
    assert refused(data).reason == "body"
    with pytest.raises(ValueError, match=r"^isn't a revision body$"):
        seal_revision(header(plaintext), plaintext, keys=KEYS, nonce=NONCE)


def test_unreadable_files() -> None:
    for data in (b"not json", b"\xef\xbb\xbf{}", b'{"v":1,"v":1}', b"{" * 100 + b"}" * 100):
        assert refused(data).reason == "unreadable"
    padded = sealed()
    padded += b" " * (REVISION_FILE_MAX - len(padded))
    assert unseal_revision(padded, KEYS, None, deployment=DEPLOYMENT).revision == 17
    error = refused(padded + b" ")
    assert error.reason == "unreadable"
    assert error.detail == "isn't a policy revision: input is larger than 2097152 bytes"


def _without(document: dict[str, Any], name: str) -> dict[str, Any]:
    return {k: v for k, v in document.items() if k != name}


@pytest.mark.parametrize(
    "change",
    [
        lambda d: [d],
        lambda d: _without(d, "created"),
        lambda d: {**d, "extra": 1},
        lambda d: {**d, "key_id": d["key_id"].upper()},
        lambda d: {**d, "key_id": d["key_id"][:15]},
        lambda d: {**d, "key_id": 1},
        lambda d: {**d, "mac": d["mac"][:63]},
        lambda d: {**d, "mac": d["mac"].upper()},
        lambda d: {**d, "mac": None},
    ],
)
def test_a_file_that_isnt_a_revision_is_refused_before_its_mac(change: Any) -> None:
    error = refused(dumps_canonical(change(json.loads(sealed()))))
    assert (error.reason, error.detail) == ("not_a_revision", "isn't a policy revision")


BAD_HEADERS: list[dict[str, Any]] = [
    {"v": 2},
    {"v": True},
    {"v": "1"},
    {"deployment": DEPLOYMENT.upper()},
    {"deployment": DEPLOYMENT[:31]},
    {"deployment": 1},
    {"revision": 0},
    {"revision": True},
    {"revision": "17"},
    {"parent": PARENT[:-1]},
    {"parent": PARENT.upper()},
    {"revision": 1, "parent": PARENT, "base": None},
    # Only revision 1 and a reseed (F.3) have no parent, and a reseed has none.
    {"parent": None},
    {"origin": "reseed"},
    {"created": -1},
    {"created": 1.5},
    {"origin": "other"},
    {"origin": ["save"]},
    {"kind": "tool.clear"},
    {"kind": ["tool.repin"]},
    {"author": {"by": "passkey"}},
    {"author": {"by": "passkey", "fingerprint": FINGERPRINT.upper()}},
    {"author": {"by": "passkey", "fingerprint": FINGERPRINT[:15]}},
    {"author": {"by": "passkey", "fingerprint": FINGERPRINT, "via": "socket"}},
    {"author": {"by": "host"}},
    {"author": {"by": "host", "via": "portal"}},
    {"author": {"by": "host", "via": ["socket"]}},
    {"author": {"by": "host", "via": "socket", "fingerprint": FINGERPRINT}},
    {"author": {"by": "seed", "via": "socket"}},
    {"author": {"by": "other"}},
    {"author": {}},
    {"author": "seed"},
    {"base": 17},
    {"base": 0},
    {"base": "16"},
    {**form("rollback"), "target": 17},
    {**form("rollback"), "target": 0},
    {**form("acknowledge"), "jumped_from": 17},
    {**form("acknowledge"), "jumped_from": True},
    # target is a rollback's alone, and every rollback names one; jumped_from is acknowledge-
    # restore's alone (D.2).
    *({**form(origin), "target": 16} for origin in sorted(ORIGINS - {"rollback"})),
    {**form("rollback"), "target": None},
    *({**form(origin), "jumped_from": 16} for origin in sorted(ORIGINS - {"acknowledge"})),
    # Each origin writes its own kinds only (D.2).
    *(
        {**form(origin), "kind": kind}
        for origin in sorted(ORIGINS)
        for kind in sorted(KINDS - ORIGIN_KINDS[origin])
    ),
    # Only the seed is the vault's own, and only as revision 1 (F.3).
    {"author": {"by": "seed"}},
    {**form("seed"), "author": {"by": "host", "via": "socket"}},
    {**form("seed"), "revision": 17, "parent": PARENT, "base": 16},
    {"body_digest": "sha256:" + "0" * 63},
]


@pytest.mark.parametrize("changes", BAD_HEADERS, ids=repr)
def test_a_header_unseal_refuses_seal_refuses_too(changes: dict[str, Any]) -> None:
    head = header(**changes)
    error = refused(forged_revision(head))
    assert (error.reason, error.detail) == ("not_a_revision", "isn't a policy revision")
    with pytest.raises(ValueError, match=r"^isn't a revision header$"):
        seal_revision(head, body(), keys=KEYS, nonce=NONCE)


def test_a_header_with_another_field_is_refused() -> None:
    with pytest.raises(ValueError, match=r"^isn't a revision header$"):
        seal_revision({**header(), "key_id": KEYS.key_id}, body(), keys=KEYS, nonce=NONCE)
    with pytest.raises(ValueError, match=r"^isn't a revision header$"):
        seal_revision(_without(header(), "target"), body(), keys=KEYS, nonce=NONCE)


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": REVISION_MAX, "base": REVISION_MAX - 1},
        {"revision": 1, "parent": None, "base": None},
        {**form("rollback"), "revision": 2, "base": 1, "target": 1},
        {**form("acknowledge"), "revision": 2, "base": 1, "jumped_from": 1},
        {**form("acknowledge"), "jumped_from": None},
        {**form("reseed"), "revision": 1, "base": None},
        {"created": 0},
        {"created": 2**53 - 1},
        {"base": None},
        *(form(origin) for origin in sorted(ORIGINS)),
        *(
            {**form(origin), "kind": kind}
            for origin in sorted(ORIGINS)
            for kind in sorted(ORIGIN_KINDS[origin])
        ),
        *({"author": {"by": "host", "via": via}} for via in sorted(VIAS)),
    ],
    ids=repr,
)
def test_every_header_form_round_trips(changes: dict[str, Any]) -> None:
    data = seal_revision(header(**changes), body(), keys=KEYS, nonce=NONCE)
    assert unseal_revision(data, KEYS, None, deployment=DEPLOYMENT).header == header(**changes)


def test_every_kind_belongs_to_one_origin() -> None:
    kinds = [kind for origin in sorted(ORIGINS) for kind in sorted(ORIGIN_KINDS[origin])]
    assert sorted(kinds) == sorted(KINDS)
    assert set(ORIGIN_KINDS) == ORIGINS


def test_a_revision_past_the_counter_is_refused() -> None:
    """T-4: the ten-digit file names hold no more."""
    for revision in (REVISION_MAX + 1, 10**12):
        with pytest.raises(ValueError, match=r"^a revision can't go above 9,999,999,999$"):
            seal_revision(header(revision=revision), body(), keys=KEYS, nonce=NONCE)
    head = header(revision=REVISION_MAX + 1)
    assert refused(forged_revision(head)).reason == "not_a_revision"


def test_seal_checks_the_body_digest_and_the_nonce() -> None:
    with pytest.raises(ValueError, match=r"^body_digest isn't the body's digest$"):
        seal_revision(header(body(reason="x")), body(), keys=KEYS, nonce=NONCE)
    for nonce in (bytes(11), bytes(13), bytes(16)):
        with pytest.raises(ValueError, match="a policy nonce is 12 bytes"):
            seal_revision(header(), body(), keys=KEYS, nonce=nonce)


@pytest.mark.parametrize(
    "sealed_body",
    [
        "not an object",
        {"nonce": b64(NONCE)},
        {"nonce": b64(NONCE), "ciphertext": "AAAA", "tag": "AAAA"},
        {"nonce": b64(bytes(16)), "ciphertext": "AAAA"},
        {"nonce": b64(bytes(11)), "ciphertext": "AAAA"},
        {"nonce": b64(NONCE)[:-1], "ciphertext": "AAAA"},
        {"nonce": "\u00e9" * 16, "ciphertext": "AAAA"},
        {"nonce": b64(NONCE), "ciphertext": "AAA"},
        {"nonce": b64(NONCE), "ciphertext": 1},
    ],
    ids=repr,
)
def test_a_sealed_body_that_isnt_one_is_refused(sealed_body: Any) -> None:
    error = refused(forged(REVISION_CONTEXT, {**header(), "body": sealed_body}))
    assert (error.reason, error.detail) == ("not_a_revision", "isn't a policy revision")


def test_the_deployment_is_checked_before_the_body() -> None:
    data = forged(REVISION_CONTEXT, {**header(), "body": {"nonce": b64(NONCE), "ciphertext": ""}})
    assert refused(data).reason == "body"
    with pytest.raises(SealRefused) as caught:
        unseal_revision(data, KEYS, None, deployment=ELSEWHERE)
    assert caught.value.reason == "deployment"


# --- the head ------------------------------------------------------------------------------------

DIGEST = "sha256:" + "d" * 64
HEAD = Head(DEPLOYMENT, 17, DIGEST, 1, None, KEYS.key_id)


def test_a_head_round_trips_as_d2_states_it() -> None:
    data = seal_head(HEAD, KEYS)
    document = json.loads(data)
    assert dumps_canonical(document) + b"\n" == data
    assert document == {
        "v": 1,
        "deployment": DEPLOYMENT,
        "revision": 17,
        "digest": DIGEST,
        "oldest": 1,
        "oldest_parent": None,
        "key_id": KEYS.key_id,
        "mac": mac(HEAD_CONTEXT, document),
    }
    assert unseal_head(data, KEYS, None) == HEAD
    old = replace(HEAD, key_id=OLD.key_id)
    assert unseal_head(seal_head(old, OLD), KEYS, OLD) == old


@pytest.mark.parametrize(
    "head",
    [
        replace(HEAD, oldest=17),
        replace(HEAD, oldest=2, oldest_parent=PARENT),
        replace(HEAD, oldest=9, oldest_parent=None),
        replace(HEAD, revision=REVISION_MAX),
        replace(HEAD, revision=1),
    ],
    ids=repr,
)
def test_every_head_form_round_trips(head: Head) -> None:
    assert unseal_head(seal_head(head, KEYS), KEYS, None) == head


BAD_HEADS: list[dict[str, Any]] = [
    {"v": 2},
    {"deployment": DEPLOYMENT[:31]},
    {"deployment": None},
    {"revision": 0},
    {"revision": REVISION_MAX + 1},
    {"revision": "17"},
    {"digest": DIGEST[:-1]},
    {"digest": None},
    {"oldest": 0},
    {"oldest": 18},
    {"oldest": True},
    {"oldest_parent": PARENT},
    {"oldest": 2, "oldest_parent": PARENT[:-1]},
    {"oldest": 2, "oldest_parent": 1},
]


@pytest.mark.parametrize("changes", BAD_HEADS, ids=repr)
def test_a_head_unseal_refuses_seal_refuses_too(changes: dict[str, Any]) -> None:
    document = {**json.loads(seal_head(HEAD, KEYS)), **changes}
    with pytest.raises(SealRefused) as caught:
        unseal_head(forged(HEAD_CONTEXT, document), KEYS, None)
    assert (caught.value.reason, caught.value.detail) == ("not_a_revision", "isn't a policy head")
    fields = {k: v for k, v in document.items() if k not in {"v", "mac"}}
    if changes.keys() != {"v"}:
        with pytest.raises(ValueError, match=r"^isn't a policy head$"):
            seal_head(Head(**fields), KEYS)


def test_a_head_is_sealed_under_its_own_master_key() -> None:
    with pytest.raises(ValueError, match=r"^the head must be sealed under its own master key$"):
        seal_head(HEAD, OLD)


def test_a_changed_or_foreign_head_is_refused() -> None:
    data = seal_head(HEAD, KEYS)
    for index in range(len(data)):
        flipped = data[:index] + bytes([data[index] ^ 1]) + data[index + 1 :]
        with pytest.raises(SealRefused):
            unseal_head(flipped, KEYS, None)
    other = seal_head(replace(HEAD, key_id=OTHER.key_id), OTHER)
    with pytest.raises(SealRefused) as caught:
        unseal_head(other, KEYS, OLD)
    assert (caught.value.reason, caught.value.key_id) == ("key_unknown", OTHER.key_id)
    document = json.loads(data)
    document["revision"] = 18
    with pytest.raises(SealRefused, match=r"^was tampered with") as caught:
        unseal_head(dumps_canonical(document), KEYS, None)
    assert caught.value.reason == "tampered"
    for bad in (b"[]", dumps_canonical({**document, "extra": 1})):
        with pytest.raises(SealRefused, match=r"^isn't a policy head$"):
            unseal_head(bad, KEYS, None)


def test_the_head_cap() -> None:
    data = seal_head(HEAD, KEYS)
    padded = data + b" " * (policyseal.HEAD_MAX - len(data))
    assert unseal_head(padded, KEYS, None) == HEAD
    with pytest.raises(SealRefused) as caught:
        unseal_head(padded + b" ", KEYS, None)
    assert caught.value.reason == "unreadable"
    assert caught.value.detail == "isn't a policy head: input is larger than 4096 bytes"


# --- the anchor ----------------------------------------------------------------------------------

ANCHOR = Anchor(DEPLOYMENT, 17, None, None, KEYS.key_id)


def test_an_anchor_round_trips_as_d2_states_it() -> None:
    data = seal_anchor(ANCHOR, KEYS)
    document = json.loads(data)
    assert dumps_canonical(document) + b"\n" == data
    assert document == {
        "v": 1,
        "deployment": DEPLOYMENT,
        "highest": 17,
        "parked": None,
        "retired_key_id": None,
        "key_id": KEYS.key_id,
        "mac": mac(ANCHOR_CONTEXT, document),
    }
    assert unseal_anchor(data, KEYS, None) == ANCHOR
    old = replace(ANCHOR, key_id=OLD.key_id)
    assert unseal_anchor(seal_anchor(old, OLD), KEYS, OLD) == old


@pytest.mark.parametrize(
    "anchor",
    [
        replace(ANCHOR, highest=0),
        replace(ANCHOR, highest=REVISION_MAX),
        replace(ANCHOR, parked=17),
        replace(ANCHOR, parked=1),
        replace(ANCHOR, retired_key_id=OLD.key_id),
        replace(ANCHOR, retired_key_id=KEYS.key_id),
    ],
    ids=repr,
)
def test_every_anchor_form_round_trips(anchor: Anchor) -> None:
    """A retired key naming the anchor's own key is read: refusing it is the start's (D.6 row 1)."""
    assert unseal_anchor(seal_anchor(anchor, KEYS), KEYS, None) == anchor


BAD_ANCHORS: list[dict[str, Any]] = [
    {"v": 0},
    {"deployment": DEPLOYMENT.upper()},
    {"highest": -1},
    {"highest": REVISION_MAX + 1},
    {"highest": None},
    {"parked": 0},
    {"parked": 18},
    {"parked": "17"},
    {"retired_key_id": OLD.key_id[:15]},
    {"retired_key_id": OLD.key_id.upper()},
    {"retired_key_id": 1},
]


@pytest.mark.parametrize("changes", BAD_ANCHORS, ids=repr)
def test_an_anchor_unseal_refuses_seal_refuses_too(changes: dict[str, Any]) -> None:
    document = {**json.loads(seal_anchor(ANCHOR, KEYS)), **changes}
    with pytest.raises(SealRefused) as caught:
        unseal_anchor(forged(ANCHOR_CONTEXT, document), KEYS, None)
    assert (caught.value.reason, caught.value.detail) == ("not_a_revision", "isn't a policy anchor")
    fields = {k: v for k, v in document.items() if k not in {"v", "mac"}}
    if changes.keys() != {"v"}:
        with pytest.raises(ValueError, match=r"^isn't a policy anchor$"):
            seal_anchor(Anchor(**fields), KEYS)


def test_an_anchor_is_sealed_under_its_own_master_key() -> None:
    with pytest.raises(ValueError, match=r"^the anchor must be sealed under its own master key$"):
        seal_anchor(ANCHOR, OLD)


def test_a_changed_or_foreign_anchor_is_refused() -> None:
    data = seal_anchor(ANCHOR, KEYS)
    for index in range(len(data)):
        flipped = data[:index] + bytes([data[index] ^ 1]) + data[index + 1 :]
        with pytest.raises(SealRefused):
            unseal_anchor(flipped, KEYS, None)
    with pytest.raises(SealRefused) as caught:
        unseal_anchor(seal_anchor(replace(ANCHOR, key_id=OLD.key_id), OLD), KEYS, None)
    assert (caught.value.reason, caught.value.key_id) == ("key_unknown", OLD.key_id)
    document = json.loads(data)
    document["highest"] = 16
    with pytest.raises(SealRefused) as caught:
        unseal_anchor(dumps_canonical(document), KEYS, None)
    assert caught.value.reason == "tampered"
    # A head's MAC doesn't verify as an anchor's: each has its own context line.
    head = json.loads(seal_head(HEAD, KEYS))
    as_anchor = {**document, "mac": head["mac"]}
    with pytest.raises(SealRefused) as caught:
        unseal_anchor(dumps_canonical(as_anchor), KEYS, None)
    assert caught.value.reason == "tampered"


def test_the_anchor_cap() -> None:
    data = seal_anchor(ANCHOR, KEYS)
    padded = data + b" " * (ANCHOR_MAX - len(data))
    assert unseal_anchor(padded, KEYS, None) == ANCHOR
    with pytest.raises(SealRefused) as caught:
        unseal_anchor(padded + b" ", KEYS, None)
    assert caught.value.detail == "isn't a policy anchor: input is larger than 4096 bytes"


# --- what never shows --------------------------------------------------------------------------


def test_nothing_from_the_body_shows_or_is_logged() -> None:
    found = unseal_revision(sealed(), KEYS, None, deployment=DEPLOYMENT)
    for shown in (repr(found), repr(found.body)):
        assert SENTINEL not in shown
        assert b64(SALT) not in shown
        # Unsalted, the seed's digest would confirm a guessed policy (E-10).
        assert SEED not in shown
    assert repr(found.body) == "Body()"
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        for value, name in ((found, "Unsealed"), (found.body, "Body"), (ANCHOR, "Anchor")):
            with pytest.raises(TypeError, match=rf"refusing to log a secret \({name}\)"):
                logs.Log("vault").event("probe", value=[value])
    finally:
        logs.set_stream(None)
    assert buffer.getvalue() == ""
    assert {Unsealed, Body, Anchor} <= set(logs.refused_types())


def test_a_refusal_carries_its_reason() -> None:
    error = SealRefused("tampered", "detail text")
    assert (error.reason, error.detail, error.key_id, str(error)) == (
        "tampered",
        "detail text",
        None,
        "detail text",
    )
    assert isinstance(error, ValueError)
