"""The passkey file (M5 design D.4): names, fingerprints, transitions, the MAC, and the holder."""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import stat
import sys
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import ORIGIN, RP_ID, SoftAuthenticator
from zoeymcp.common import files
from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.portal import passkeys
from zoeymcp.portal.passkeys import (
    ALGORITHM_NAMES,
    DAY,
    DIRECTORY,
    FILE,
    MAX_FILE_BYTES,
    MAX_SIGN_COUNT,
    VIAS,
    Passkey,
    PasskeyError,
    PasskeyFile,
    PasskeyFileError,
    Passkeys,
    Reason,
    Refusal,
    add,
    check_name,
    describe,
    find,
    fingerprint,
    new_file,
    rejected_name,
    remove,
    rename,
    reset_with,
    seal,
    touch,
    unseal,
)
from zoeymcp.portal.webauthn import (
    MAX_CREDENTIAL_ID,
    MAX_PASSKEYS,
    MAX_PUBLIC_KEY,
    Asserted,
    NewCredential,
    WebAuthnError,
    creation_options,
    request_options,
    verify_assertion,
    verify_registration,
)
from zoeymcp.vault import logs
from zoeymcp.vault.keys import CONTEXT_PORTAL, KeySet, PortalKey, derive

MASTER = bytes(range(32))
KEY = KeySet.from_master(MASTER).portal_key
OLD = KeySet.from_master(bytes(range(1, 33))).portal_key
OTHER = KeySet.from_master(bytes(range(2, 34))).portal_key
HANDLE = bytes(range(32))
FRESH = b"\x77" * 32
# A time 0.7 s into a day's 123rd second, so truncation shows.
NOW = 20_000 * DAY + 123.7


def credential(n: int = 1, **changes: Any) -> NewCredential:
    made = NewCredential(
        id=bytes([n]) * 16,
        rp_id=RP_ID,
        alg=-7,
        spki=b"spki-" + bytes([n]),
        sign_count=0,
        backup_eligible=True,
        backup_state=True,
        transports=("hybrid", "internal"),
    )
    return replace(made, **changes)


def made(*ids: int, now: float = NOW) -> PasskeyFile:
    """A file with these credentials, enrolled in order from a full session."""
    document = new_file(HANDLE)
    for n in ids:
        result = add(document, credential(n), name=f"key {n}", via="portal", origin=ORIGIN, now=now)
        assert isinstance(result, PasskeyFile)
        document = result
    return document


def asserted(
    n: int = 1, count: int = 0, *, state: bool = True, regressed: bool = False
) -> Asserted:
    return Asserted(bytes([n]) * 16, count, state, regressed)


class Clock:
    def __init__(self, now: float = NOW) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    for line in lines:
        del line["ts"], line["role"]
    return lines


# --- names --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("laptop", True),
        ("a", True),
        ("a" * 64, True),
        ("\u00e9" * 64, True),  # code points, not bytes
        (" leading and trailing ", True),
        ("Caf\u00e9 \u65e5\u672c \U0001f511", True),
        ("", False),
        ("a" * 65, False),
        ("two\nlines", False),
        ("a\tb", False),
        ("a\rb", False),
        ("zero\u200bwidth", False),
        ("bidi\u202eflip", False),
        ("tag\U000e0041", False),
        ("blank\u3164", False),
        ("c1\x85", False),
        ("private\ue000", False),
        (None, False),
        (64, False),
        (["laptop"], False),
    ],
)
def test_names(name: object, ok: bool) -> None:
    assert check_name(name) is ok


# --- fingerprints -------------------------------------------------------------------------------


def test_the_fingerprint_is_keyed_and_pinned() -> None:
    credential_id = b"\x01" * 16
    expected = hmac.new(
        derive(MASTER, CONTEXT_PORTAL), b"zoeymcp/passkey-fp/v1\n" + credential_id, hashlib.sha256
    ).hexdigest()[:16]
    assert fingerprint(KEY, credential_id) == expected == "59d1baed2126f146"
    assert fingerprint(OTHER, credential_id) != expected
    assert fingerprint(KEY, b"\x02" * 16) != expected
    # The fingerprint doesn't name the ID unkeyed.
    assert hashlib.sha256(credential_id).hexdigest()[:16] != expected


def test_find_by_fingerprint() -> None:
    document = made(1, 2)
    second = document.credentials[1]
    assert find(document, KEY, fingerprint(KEY, second.id)) is second
    assert find(document, KEY, fingerprint(OTHER, second.id)) == Refusal("not_found")
    assert find(document, KEY, "") == Refusal("not_found")
    assert find(new_file(HANDLE), KEY, fingerprint(KEY, second.id)) == Refusal("not_found")


def test_describe_shows_how_and_where_never_the_key() -> None:
    document = add(
        made(1),
        credential(2, alg=-8, backup_eligible=False, backup_state=False, transports=("usb",)),
        name="security key",
        via="setup_code",
        origin="https://zoeymcp.tailnet.example",
        now=NOW + 5,
    )
    assert isinstance(document, PasskeyFile)
    first, second = document.credentials
    assert describe(first, "f" * 16) == {
        "fingerprint": "f" * 16,
        "name": "key 1",
        "rp_id": RP_ID,
        "alg": "ES256",
        "synced": True,
        "transports": ["hybrid", "internal"],
        "via": "portal",
        "origin": ORIGIN,
        "created": int(NOW),
        "last_used": None,
    }
    shown = describe(second, "0" * 16)
    assert (shown["alg"], shown["synced"], shown["transports"]) == ("EdDSA", False, ["usb"])
    assert (shown["via"], shown["origin"], shown["created"]) == (
        "setup_code",
        "https://zoeymcp.tailnet.example",
        int(NOW) + 5,
    )
    used = touch(document, asserted(1, 3), NOW + DAY)
    assert describe(used.credentials[0], "f" * 16)["last_used"] == int(NOW) // DAY * DAY + DAY
    rsa = replace(first, alg=-257)
    assert describe(rsa, "f" * 16)["alg"] == "RS256"
    assert ALGORITHM_NAMES == {-7: "ES256", -8: "EdDSA", -257: "RS256"}


def test_an_ambiguous_fingerprint_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # An enroller can't grind a keyed fingerprint, but if two ever match, neither is taken.
    monkeypatch.setattr(passkeys, "fingerprint", lambda key, credential_id: "same")
    assert find(made(1, 2), KEY, "same") == Refusal("ambiguous_fingerprint")
    assert find(made(1), KEY, "same") == made(1).credentials[0]


# --- the transitions ----------------------------------------------------------------------------


def test_a_new_file_is_empty_and_never_written() -> None:
    document = new_file(HANDLE)
    assert document == PasskeyFile(0, HANDLE, ())
    assert document.last_regressed is None
    assert document.get(b"\x01" * 16) is None


def test_add_records_the_credential() -> None:
    new = credential(1, alg=-8, sign_count=5, backup_eligible=False, backup_state=False)
    result = add(new_file(HANDLE), new, name="laptop", via="setup_code", origin=ORIGIN, now=NOW)
    assert result == PasskeyFile(
        1,
        HANDLE,
        (
            Passkey(
                id=new.id,
                rp_id=RP_ID,
                alg=-8,
                spki=new.spki,
                sign_count=5,
                backup_eligible=False,
                backup_state=False,
                transports=("hybrid", "internal"),
                name="laptop",
                via="setup_code",
                origin=ORIGIN,
                created=int(NOW),
                last_used=None,
                last_regressed=None,
            ),
        ),
    )


def test_add_appends_and_raises_the_generation() -> None:
    document = made(1, 2, 3)
    assert document.generation == 3
    assert [c.id[0] for c in document.credentials] == [1, 2, 3]
    assert document.user_handle == HANDLE


@pytest.mark.parametrize(
    ("document", "new", "name", "reason"),
    [
        (made(1), credential(2), "", "bad_name"),
        (made(1), credential(2), "a\u200b", "bad_name"),
        (made(1, 2), credential(2), "again", "duplicate_credential"),
        (made(*range(1, MAX_PASSKEYS + 1)), credential(99), "one more", "too_many_passkeys"),
    ],
)
def test_add_refuses(document: PasskeyFile, new: NewCredential, name: str, reason: Reason) -> None:
    assert add(document, new, name=name, via="portal", origin=ORIGIN, now=NOW) == Refusal(reason)


def test_add_takes_up_to_the_limit() -> None:
    almost = made(*range(1, MAX_PASSKEYS))
    result = add(almost, credential(99), name="last", via="portal", origin=ORIGIN, now=NOW)
    assert isinstance(result, PasskeyFile)
    assert len(result.credentials) == MAX_PASSKEYS


def test_reset_replaces_every_credential_and_keeps_the_user_handle() -> None:
    result = reset_with(made(1, 2), credential(3), name="new", origin=ORIGIN, now=NOW)
    assert isinstance(result, PasskeyFile)
    assert result.generation == 3
    assert result.user_handle == HANDLE
    [only] = result.credentials
    assert (only.id, only.name, only.via, only.created) == (
        credential(3).id,
        "new",
        "setup_code_reset",
        int(NOW),
    )
    empty = reset_with(new_file(HANDLE), credential(3), name="new", origin=ORIGIN, now=NOW)
    assert isinstance(empty, PasskeyFile)
    assert empty.generation == 1
    assert reset_with(made(1), credential(3), name="", origin=ORIGIN, now=NOW) == Refusal(
        "bad_name"
    )


def test_rename() -> None:
    document = made(1, 2, 3)
    result = rename(document, credential(2).id, "phone")
    assert isinstance(result, PasskeyFile)
    assert result.generation == 4
    assert [c.name for c in result.credentials] == ["key 1", "phone", "key 3"]
    assert result.credentials[1] == replace(document.credentials[1], name="phone")
    # Names needn't be unique.
    same = rename(result, credential(3).id, "phone")
    assert isinstance(same, PasskeyFile)
    assert [c.name for c in same.credentials] == ["key 1", "phone", "phone"]


def test_renaming_to_the_same_name_changes_nothing() -> None:
    document = made(1)
    assert rename(document, credential(1).id, "key 1") is document


@pytest.mark.parametrize(
    ("credential_id", "name", "reason"),
    [
        (credential(1).id, "", "bad_name"),
        (credential(1).id, "a" * 65, "bad_name"),
        (credential(9).id, "phone", "not_found"),
    ],
)
def test_rename_refuses(credential_id: bytes, name: str, reason: Reason) -> None:
    assert rename(made(1), credential_id, name) == Refusal(reason)


def test_remove() -> None:
    document = made(1, 2, 3)
    result = remove(document, credential(2).id)
    assert isinstance(result, PasskeyFile)
    assert result.generation == 4
    assert result.credentials == (document.credentials[0], document.credentials[2])


def test_the_last_passkey_is_removed_only_when_allowed() -> None:
    assert remove(made(1), credential(1).id) == Refusal("last_passkey")
    result = remove(made(1), credential(1).id, allow_last=True)
    assert isinstance(result, PasskeyFile)
    assert result.credentials == ()
    assert result.generation == 2
    assert remove(made(1), credential(2).id, allow_last=True) == Refusal("not_found")
    assert remove(made(1, 2), credential(9).id) == Refusal("not_found")
    two = remove(made(1, 2), credential(1).id)
    assert isinstance(two, PasskeyFile)
    assert [c.id[0] for c in two.credentials] == [2]


def test_touch_keeps_the_use() -> None:
    document = made(1, 2)
    result = touch(document, asserted(2, 7, state=False), NOW)
    assert result.generation == 3
    first, second = result.credentials
    assert first == document.credentials[0]
    assert second == replace(
        document.credentials[1], sign_count=7, backup_state=False, last_used=20_000 * DAY
    )
    assert result.last_regressed is None


def test_the_stored_counter_never_goes_down() -> None:
    document = touch(made(1), asserted(1, 9), NOW)
    assert document.credentials[0].sign_count == 9
    lower = touch(document, asserted(1, 4, regressed=True), NOW + DAY)
    assert lower.credentials[0].sign_count == 9
    assert lower.credentials[0].last_regressed == 20_001 * DAY
    assert lower.last_regressed == 20_001 * DAY


def test_a_regression_is_kept_to_the_day() -> None:
    once = touch(made(1, 2), asserted(1, regressed=True), NOW)
    later = touch(once, asserted(2, regressed=True), NOW + 3 * DAY)
    assert [c.last_regressed for c in later.credentials] == [20_000 * DAY, 20_003 * DAY]
    assert later.last_regressed == 20_003 * DAY
    # A later honest use keeps the day it happened.
    honest = touch(later, asserted(1, 5), NOW + 4 * DAY)
    assert honest.credentials[0].last_regressed == 20_000 * DAY
    assert honest.last_regressed == 20_003 * DAY


@pytest.mark.parametrize(
    ("now", "day"),
    [(20_000 * DAY, 20_000 * DAY), (20_000 * DAY - 0.5, 19_999 * DAY), (NOW, 20_000 * DAY)],
)
def test_last_used_is_kept_to_the_day(now: float, day: int) -> None:
    assert touch(made(1), asserted(1), now).credentials[0].last_used == day


def test_a_synced_passkey_writes_once_a_day() -> None:
    document = touch(made(1), asserted(1), NOW)
    assert touch(document, asserted(1), NOW + 60) is document
    assert touch(document, asserted(1), 20_001 * DAY).generation == document.generation + 1


def test_touch_for_a_removed_credential_changes_nothing() -> None:
    document = made(1)
    assert touch(document, asserted(2, 5, regressed=True), NOW) is document


def test_a_device_bound_credential_never_shows_as_backed_up() -> None:
    bound = add(
        new_file(HANDLE),
        credential(1, backup_eligible=False, backup_state=False),
        name="key",
        via="portal",
        origin=ORIGIN,
        now=NOW,
    )
    assert isinstance(bound, PasskeyFile)
    assert touch(bound, asserted(1, state=True), NOW).credentials[0].backup_state is False


def test_reprs_hide_ids_keys_names_and_the_user_handle() -> None:
    document = made(1)
    text = repr(document)
    for hidden in (HANDLE.hex(), repr(HANDLE), repr(credential(1).id), "spki-", "key 1"):
        assert hidden not in text
    assert "generation=1" in text
    assert "rp_id='localhost'" in text


# --- with the verifier --------------------------------------------------------------------------


def test_a_record_is_what_the_verifier_reads() -> None:
    authenticator = SoftAuthenticator(backup_eligible=False, backup_state=False, counts=True)
    challenge = bytes(32)
    options = creation_options(challenge=challenge, user_handle=HANDLE, rp_id=RP_ID, exclude=())
    attestation = authenticator.create(options, switches=())
    new = verify_registration(
        attestation.body(), challenge=challenge, origin=ORIGIN, rp_id=RP_ID, enrolled=()
    )
    document = add(new_file(HANDLE), new, name="key", via="setup_code", origin=ORIGIN, now=NOW)
    assert isinstance(document, PasskeyFile)
    sealed, _ = unseal(seal(document, KEY), KEY)
    assertion = authenticator.get(request_options(challenge=challenge, rp_id=RP_ID))
    result = verify_assertion(
        assertion.body(),
        challenge=challenge,
        origin=ORIGIN,
        rp_id=RP_ID,
        credentials=sealed.credentials,
        user_handle=sealed.user_handle,
        login=True,
    )
    assert result == Asserted(new.id, 1, False, False)
    assert touch(sealed, result, NOW).credentials[0].sign_count == 1
    # The records are what the verifier checks a new enrolment against, too.
    with pytest.raises(WebAuthnError, match=r"^duplicate_credential$"):
        verify_registration(
            attestation.body(),
            challenge=challenge,
            origin=ORIGIN,
            rp_id=RP_ID,
            enrolled=sealed.credentials,
        )


# --- the file -----------------------------------------------------------------------------------


def _mac(content: dict[str, Any], key: PortalKey = KEY) -> str:
    return key.mac(b"zoeymcp/passkeys/v1\n" + dumps_canonical(content)).hex()


def signed(content: dict[str, Any], key: PortalKey = KEY) -> bytes:
    """``content`` with a valid MAC, however inconsistent it is."""
    return dumps_canonical({**content, "mac": _mac(content, key)})


def touched_file() -> PasskeyFile:
    """Two credentials, one used and regressed, one never used."""
    document = touch(made(1, 2), asserted(1, 3, regressed=True), NOW)
    return replace(document, generation=7)


def test_seal_format() -> None:
    document = touched_file()
    data = seal(document, KEY)
    assert data.endswith(b"}\n")
    assert data.count(b"\n") == 1
    content = json.loads(data)
    mac = content.pop("mac")
    assert mac == _mac(content)
    assert dumps_canonical({**content, "mac": mac}) + b"\n" == data
    assert content["v"] == 1
    assert content["key_id"] == KEY.key_id
    assert content["generation"] == 7
    assert content["user_handle"] == base64.urlsafe_b64encode(HANDLE).rstrip(b"=").decode()
    first, second = content["credentials"]
    assert first == {
        "id": "AQEBAQEBAQEBAQEBAQEBAQ",
        "rp_id": RP_ID,
        "alg": -7,
        "public_key": "c3BraS0B",
        "sign_count": 3,
        "backup_eligible": True,
        "backup_state": True,
        "transports": ["hybrid", "internal"],
        "name": "key 1",
        "via": "portal",
        "origin": ORIGIN,
        "created": int(NOW),
        "last_used": 20_000 * DAY,
        "last_regressed": 20_000 * DAY,
    }
    assert (second["last_used"], second["last_regressed"]) == (None, None)


def test_unseal_reads_what_seal_wrote() -> None:
    for document in (new_file(HANDLE), touched_file(), made(*range(1, MAX_PASSKEYS + 1))):
        if document.generation == 0:
            document = replace(document, generation=1)
        assert unseal(seal(document, KEY), KEY) == (document, False)
        assert unseal(seal(document, KEY), KEY, OLD) == (document, False)


def test_unseal_under_the_previous_master_key() -> None:
    document = touched_file()
    assert unseal(seal(document, OLD), KEY, OLD) == (document, True)


# Each reason's message, which is safe to print; not_json's adds the parser's.
MESSAGES = {
    "too_large": "is larger than 131072 bytes",
    "not_json": "isn't a passkey file: ",
    "shape": "isn't a version-1 passkey file",
    "mac": "was changed, or written under another master key: it can't be verified",
    "inconsistent": "isn't a consistent version-1 passkey file",
}


def reason_of(data: bytes, key: PortalKey = KEY, previous: PortalKey | None = None) -> str:
    with pytest.raises(PasskeyFileError) as info:
        unseal(data, key, previous)
    reason = info.value.reason
    message = str(info.value)
    if reason == "not_json":
        assert message.startswith(MESSAGES[reason])
        assert len(message) > len(MESSAGES[reason])
    elif reason != "master_key":
        assert message == MESSAGES[reason]
    return reason


def test_unseal_names_an_unknown_master() -> None:
    data = seal(touched_file(), OTHER)
    with pytest.raises(PasskeyFileError) as info:
        unseal(data, KEY, OLD)
    assert info.value.reason == "master_key"
    assert str(info.value) == (
        f"was written under master key ID {OTHER.key_id}, but the master key's ID is "
        f"{KEY.key_id}. If you are rotating the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS "
        "to the old key; otherwise run zoeymcp setup-code --reset."
    )
    assert reason_of(seal(touched_file(), OLD)) == "master_key"


def test_every_changed_byte_is_refused() -> None:
    data = seal(touched_file(), KEY)
    for position in range(len(data)):
        changed = data[:position] + bytes([data[position] ^ 0x01]) + data[position + 1 :]
        with pytest.raises(PasskeyFileError):
            unseal(changed, KEY, OLD)


def test_a_changed_value_fails_the_mac() -> None:
    content = json.loads(seal(touched_file(), KEY))
    content["credentials"][0]["sign_count"] = 0
    assert reason_of(dumps_canonical(content)) == "mac"
    # A MAC from another master key fails the same way.
    rest = {k: v for k, v in content.items() if k != "mac"}
    assert reason_of(dumps_canonical({**rest, "mac": _mac(rest, OTHER)})) == "mac"


def test_the_size_limit() -> None:
    data = seal(touched_file(), KEY)
    padded = data + b" " * (MAX_FILE_BYTES - len(data))
    assert len(padded) == MAX_FILE_BYTES
    assert unseal(padded, KEY)[0] == touched_file()
    assert reason_of(padded + b" ") == "too_large"
    assert MAX_FILE_BYTES == 128 * 1024


@pytest.mark.parametrize("data", [b"", b"{", b"\xff", b"\xef\xbb\xbf{}", b'{"v":1,"v":1}'])
def test_unseal_refuses_what_isnt_json(data: bytes) -> None:
    assert reason_of(data) == "not_json"


def base_content() -> dict[str, Any]:
    content: dict[str, Any] = json.loads(seal(touched_file(), KEY))
    del content["mac"]
    return content


@pytest.mark.parametrize(
    "change",
    [
        lambda c: [c],
        lambda c: {k: v for k, v in c.items() if k != "generation"},
        lambda c: {**c, "extra": 1},
        lambda c: {**c, "key_id": c["key_id"].upper()},
        lambda c: {**c, "key_id": c["key_id"][:15]},
        lambda c: {**c, "key_id": 5},
        lambda c: {**c, "mac": 5},
    ],
)
def test_unseal_refuses_another_shape(change: Any) -> None:
    content = change(base_content())
    if isinstance(content, dict) and "mac" not in content:
        content["mac"] = "0" * 64
    assert reason_of(dumps_canonical(content)) == "shape"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@pytest.mark.parametrize(
    ("name", "value", "ok"),
    [
        ("v", 1, True),
        ("v", 2, False),
        ("v", True, False),
        ("v", 1.0, False),
        ("generation", 1, True),
        ("generation", 0, False),
        ("generation", -1, False),
        ("generation", True, False),
        ("generation", "7", False),
        ("user_handle", b64(bytes(32)), True),
        ("user_handle", b64(bytes(31)), False),
        ("user_handle", b64(bytes(33)), False),
        ("user_handle", b64(bytes(32)) + "=", False),
        ("user_handle", 5, False),
        ("credentials", [], True),
        ("credentials", {}, False),
    ],
)
def test_the_top_level_is_checked(name: str, value: Any, ok: bool) -> None:
    content = {**base_content(), name: value}
    if ok:
        unseal(signed(content), KEY)
    else:
        assert reason_of(signed(content)) == "inconsistent"


def record_json(n: int, **changes: Any) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(seal(made(n), KEY))["credentials"][0]
    record.update(changes)
    return record


@pytest.mark.parametrize("count", [MAX_PASSKEYS, MAX_PASSKEYS + 1])
def test_at_most_max_passkeys(count: int) -> None:
    content = {**base_content(), "credentials": [record_json(n) for n in range(1, count + 1)]}
    if count <= MAX_PASSKEYS:
        assert len(unseal(signed(content), KEY)[0].credentials) == count
    else:
        assert reason_of(signed(content)) == "inconsistent"


def test_a_credential_id_appears_once() -> None:
    content = {**base_content(), "credentials": [record_json(1), record_json(1, name="again")]}
    assert reason_of(signed(content)) == "inconsistent"


@pytest.mark.parametrize(
    ("name", "value", "ok"),
    [
        ("id", b64(b"\x01"), True),
        ("id", b64(b"\x01" * MAX_CREDENTIAL_ID), True),
        ("id", "", False),
        ("id", b64(b"\x01" * (MAX_CREDENTIAL_ID + 1)), False),
        ("id", "AQ=", False),
        ("id", "A+", False),
        ("id", 1, False),
        ("rp_id", "example.com", True),
        ("rp_id", "", False),
        ("rp_id", 5, False),
        ("alg", -8, True),
        ("alg", -257, True),
        ("alg", -35, False),
        ("alg", -7.0, False),
        ("alg", "-7", False),
        ("public_key", b64(b"\x01" * MAX_PUBLIC_KEY), True),
        ("public_key", b64(b"\x01"), True),
        ("public_key", "", False),
        ("public_key", b64(b"\x01" * (MAX_PUBLIC_KEY + 1)), False),
        ("public_key", None, False),
        ("sign_count", 0, True),
        ("sign_count", MAX_SIGN_COUNT, True),
        ("sign_count", MAX_SIGN_COUNT + 1, False),
        ("sign_count", -1, False),
        ("sign_count", True, False),
        ("backup_eligible", 1, False),
        ("backup_state", 0, False),
        ("transports", [], True),
        ("transports", ["ble", "hybrid", "internal", "nfc", "smart-card", "usb"], True),
        ("transports", ["internal", "hybrid"], False),
        ("transports", ["hybrid", "hybrid"], False),
        ("transports", ["hybrid", "bluetooth"], False),
        ("transports", [5], False),
        ("transports", [["hybrid"]], False),
        ("transports", [{"hybrid": 1}], False),
        ("transports", "hybrid", False),
        ("name", "a" * 64, True),
        ("name", "", False),
        ("name", "a\u200bb", False),
        ("name", None, False),
        ("via", "nowhere", False),
        ("via", None, False),
        ("origin", "https://zoeymcp.lan.example", True),
        ("origin", "", False),
        ("origin", None, False),
        ("created", 0, True),
        ("created", -1, False),
        ("created", None, False),
        ("last_used", None, True),
        ("last_used", 0, True),
        ("last_used", -1, False),
        ("last_used", True, False),
        ("last_used", "x", False),
        ("last_regressed", None, True),
        ("last_regressed", 0, True),
        ("last_regressed", -1, False),
        ("last_regressed", False, False),
        ("last_regressed", 1.5, False),
    ],
)
def test_each_record_field_is_checked(name: str, value: Any, ok: bool) -> None:
    content = {**base_content(), "credentials": [record_json(1, **{name: value})]}
    if ok:
        [parsed] = unseal(signed(content), KEY)[0].credentials
        assert parsed.spki == base64.urlsafe_b64decode(
            content["credentials"][0]["public_key"] + "=="
        )
    else:
        assert reason_of(signed(content)) == "inconsistent"


@pytest.mark.parametrize("via", VIAS)
def test_every_via_is_read(via: str) -> None:
    content = {**base_content(), "credentials": [record_json(1, via=via)]}
    assert unseal(signed(content), KEY)[0].credentials[0].via == via


@pytest.mark.parametrize(
    ("eligible", "state", "ok"),
    [(True, True, True), (True, False, True), (False, False, True), (False, True, False)],
)
def test_backed_up_means_eligible(eligible: bool, state: bool, ok: bool) -> None:
    record = record_json(1, backup_eligible=eligible, backup_state=state)
    content = {**base_content(), "credentials": [record]}
    if ok:
        parsed = unseal(signed(content), KEY)[0].credentials[0]
        assert (parsed.backup_eligible, parsed.backup_state) == (eligible, state)
    else:
        assert reason_of(signed(content)) == "inconsistent"


@pytest.mark.parametrize(
    "change",
    [
        lambda r: [r],
        lambda r: {k: v for k, v in r.items() if k != "origin"},
        lambda r: {**r, "extra": 1},
    ],
)
def test_a_record_of_another_shape_is_refused(change: Any) -> None:
    content = {**base_content(), "credentials": [change(record_json(1))]}
    assert reason_of(signed(content)) == "inconsistent"


def test_one_bad_record_among_good_ones_is_refused() -> None:
    records = [record_json(1), record_json(2, alg=-1), record_json(3)]
    assert reason_of(signed({**base_content(), "credentials": records})) == "inconsistent"


def test_rejected_name() -> None:
    assert rejected_name(1_760_000_000.5) == "passkeys.rejected-1760000000500.json"


# --- the holder ---------------------------------------------------------------------------------


def path_in(state: Path) -> Path:
    return state / DIRECTORY / FILE


def written(state: Path, document: PasskeyFile, key: PortalKey = KEY) -> Path:
    path = path_in(state)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(seal(document, key))
    return path


def handle(size: int) -> bytes:
    assert size == 32
    return FRESH


def load(state: Path, previous: PortalKey | None = None, clock: Clock | None = None) -> Passkeys:
    return Passkeys.load(state, KEY, previous, clock=clock or Clock(), random=handle)


def failing(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """Make every write fail; returns what was attempted."""
    attempts: list[bytes] = []

    def broken(path: Path, data: bytes) -> None:
        attempts.append(data)
        raise OSError("read-only")

    monkeypatch.setattr(passkeys, "write_atomic", broken)
    return attempts


def on_disk(state: Path) -> PasskeyFile:
    return unseal(path_in(state).read_bytes(), KEY)[0]


def test_a_missing_file_is_no_passkeys(tmp_path: Path, log_buffer: io.StringIO) -> None:
    holder = load(tmp_path)
    assert holder.document == PasskeyFile(0, FRESH, ())
    assert holder.user_handle == FRESH
    assert holder.unavailable is False
    assert holder.dirty is False
    assert not path_in(tmp_path).exists()
    assert events(log_buffer) == [{"event": "passkeys_loaded", "count": 0, "generation": 0}]
    clock = Clock()
    assert load(tmp_path, clock=clock).clock is clock


def test_load_reads_the_file(tmp_path: Path, log_buffer: io.StringIO) -> None:
    written(tmp_path, touched_file())
    holder = load(tmp_path)
    assert holder.document == touched_file()
    assert holder.user_handle == HANDLE
    assert holder.unavailable is False
    assert events(log_buffer) == [{"event": "passkeys_loaded", "count": 2, "generation": 7}]


def test_load_reseals_under_the_current_master_key(tmp_path: Path, log_buffer: io.StringIO) -> None:
    written(tmp_path, touched_file(), OLD)
    holder = load(tmp_path, OLD)
    assert holder.document == replace(touched_file(), generation=8)
    assert on_disk(tmp_path) == holder.document
    assert holder.dirty is False
    assert events(log_buffer) == [{"event": "passkeys_loaded", "count": 2, "generation": 8}]


def test_a_reseal_that_cant_be_written_is_kept_in_memory(
    tmp_path: Path, log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = written(tmp_path, touched_file(), OLD)
    before = path.read_bytes()
    failing(monkeypatch)
    holder = load(tmp_path, OLD)
    assert holder.document == replace(touched_file(), generation=8)
    assert holder.dirty
    assert holder.unavailable is False
    assert path.read_bytes() == before
    assert events(log_buffer) == [
        {
            "event": "portal_state_not_written",
            "level": "critical",
            "state": "passkeys",
            "kept_in_memory": True,
            "error_type": "OSError",
        },
        {"event": "passkeys_loaded", "count": 2, "generation": 8},
    ]


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"{", "not_json"),
        (b"x" * (MAX_FILE_BYTES + 1), "too_large"),
        (b"[]", "shape"),
    ],
    ids=["not_json", "too_large", "shape"],
)
def test_a_file_that_doesnt_verify_makes_the_portal_unavailable(
    tmp_path: Path, log_buffer: io.StringIO, data: bytes, reason: str
) -> None:
    path = written(tmp_path, touched_file())
    path.write_bytes(data)
    holder = load(tmp_path)
    assert holder.unavailable
    assert holder.document == PasskeyFile(0, FRESH, ())
    assert path.read_bytes() == data  # never overwritten at load
    assert events(log_buffer) == [
        {"event": "passkey_store_tampered", "level": "critical", "reason": reason}
    ]


def test_a_file_under_another_master_key_makes_the_portal_unavailable(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    written(tmp_path, touched_file(), OLD)
    assert load(tmp_path).unavailable
    data = bytearray(seal(touched_file(), KEY))
    data[data.index(b'"name":"key 1"') + 8] ^= 0x01
    path_in(tmp_path).write_bytes(bytes(data))
    assert load(tmp_path).unavailable
    reasons = [e["reason"] for e in events(log_buffer)]
    assert reasons == ["master_key", "mac"]


def test_an_unreadable_file_makes_the_portal_unavailable(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    path_in(tmp_path).mkdir(mode=0o700, parents=True)  # opening a directory fails
    holder = load(tmp_path)
    assert holder.unavailable
    assert events(log_buffer) == [
        {"event": "passkey_store_tampered", "level": "critical", "reason": "unreadable"}
    ]


def test_load_reads_no_more_than_the_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    written(tmp_path, touched_file())
    sizes: list[int] = []
    real = passkeys.unseal

    def spy(data: bytes, key: PortalKey, previous: PortalKey | None = None) -> Any:
        sizes.append(len(data))
        return real(data, key, previous)

    monkeypatch.setattr(passkeys, "unseal", spy)
    path_in(tmp_path).write_bytes(b" " * (MAX_FILE_BYTES + 100))
    assert load(tmp_path).unavailable
    assert sizes == [MAX_FILE_BYTES + 1]


def test_add_writes_before_it_takes_effect(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Clock()
    holder = load(tmp_path, clock=clock)
    seen: list[tuple[bool, PasskeyFile]] = []
    real = passkeys.write_atomic

    def spy(path: Path, data: bytes) -> None:
        # The lock is held, and memory hasn't changed yet.
        seen.append((holder._lock.locked(), holder.document))
        real(path, data)

    monkeypatch.setattr(passkeys, "write_atomic", spy)
    record = holder.add(credential(1), name="laptop", via="setup_code", origin=ORIGIN)
    assert seen == [(True, PasskeyFile(0, FRESH, ()))]
    assert record == holder.document.credentials[0]
    assert (record.name, record.via, record.created) == ("laptop", "setup_code", int(NOW))
    assert holder.document.generation == 1
    assert holder.document.user_handle == FRESH
    assert on_disk(tmp_path) == holder.document
    clock.now += 10
    second = holder.add(credential(2), name="phone", via="portal", origin=ORIGIN)
    assert second.created == int(NOW) + 10
    assert on_disk(tmp_path).credentials == (record, second)


def test_a_write_uses_the_atomic_helper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[Path, str]] = []
    real = files.write_atomic

    def spy(path: Path, data: bytes, *, prefix: str) -> None:
        calls.append((path, prefix))
        real(path, data, prefix=prefix)

    monkeypatch.setattr(files, "write_atomic", spy)
    load(tmp_path).add(credential(1), name="laptop", via="portal", origin=ORIGIN)
    assert calls == [(path_in(tmp_path), ".passkeys-")]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_file_is_private(tmp_path: Path) -> None:
    load(tmp_path).add(credential(1), name="laptop", via="portal", origin=ORIGIN)
    assert stat.S_IMODE(path_in(tmp_path).stat().st_mode) == 0o600


def test_a_failed_write_changes_nothing(
    tmp_path: Path, log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = written(tmp_path, made(1, 2))
    holder = load(tmp_path)
    before, data = holder.document, path.read_bytes()
    log_buffer.truncate(0)
    log_buffer.seek(0)
    failing(monkeypatch)
    fp = holder.fingerprint(credential(2).id)
    calls: list[Callable[[], object]] = [
        lambda: holder.add(credential(3), name="x", via="portal", origin=ORIGIN),
        lambda: holder.rename(fp, "new"),
        lambda: holder.remove(fp),
        lambda: holder.reset_with(credential(3), name="x", origin=ORIGIN),
    ]
    for call in calls:
        with pytest.raises(PasskeyError) as info:
            call()
        assert info.value.reason == "not_written"
        assert str(info.value) == "not_written"
        assert holder.document is before
        assert path.read_bytes() == data
        assert holder.dirty is False
    assert events(log_buffer) == [
        {
            "event": "portal_state_not_written",
            "level": "critical",
            "state": "passkeys",
            "kept_in_memory": False,
            "error_type": "OSError",
        }
    ] * len(calls)


@pytest.mark.parametrize(
    ("name", "reason"),
    [("", "bad_name"), ("dup", "duplicate_credential")],
)
def test_add_refuses_without_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, reason: str
) -> None:
    written(tmp_path, made(1))
    holder = load(tmp_path)
    attempts = failing(monkeypatch)
    new = credential(1) if reason == "duplicate_credential" else credential(2)
    with pytest.raises(PasskeyError) as info:
        holder.add(new, name=name, via="portal", origin=ORIGIN)
    assert info.value.reason == reason
    assert attempts == []


def test_the_holder_renames(tmp_path: Path) -> None:
    written(tmp_path, made(1, 2))
    holder = load(tmp_path)
    renamed = holder.rename(holder.fingerprint(credential(2).id), "phone")
    assert renamed == replace(made(1, 2).credentials[1], name="phone")
    assert holder.document.credentials[1] == renamed
    assert holder.document.generation == 3
    assert on_disk(tmp_path) == holder.document


def test_renaming_to_the_same_name_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written(tmp_path, made(1))
    holder = load(tmp_path)
    attempts = failing(monkeypatch)
    same = holder.rename(holder.fingerprint(credential(1).id), "key 1")
    assert same == made(1).credentials[0]
    assert attempts == []
    assert holder.document == made(1)


def test_the_holder_removes(tmp_path: Path) -> None:
    written(tmp_path, made(1, 2))
    holder = load(tmp_path)
    removed = holder.remove(holder.fingerprint(credential(1).id))
    assert removed == made(1, 2).credentials[0]
    assert [c.id[0] for c in holder.document.credentials] == [2]
    assert on_disk(tmp_path) == holder.document
    with pytest.raises(PasskeyError) as info:
        holder.remove(holder.fingerprint(credential(2).id))
    assert info.value.reason == "last_passkey"
    last = holder.remove(holder.fingerprint(credential(2).id), allow_last=True)
    assert last.id == credential(2).id
    assert on_disk(tmp_path).credentials == ()
    assert on_disk(tmp_path).generation == 4


def test_an_unknown_fingerprint(tmp_path: Path) -> None:
    written(tmp_path, made(1, 2))
    holder = load(tmp_path)
    calls: list[Callable[[], object]] = [
        lambda: holder.find("0" * 16),
        lambda: holder.rename("0" * 16, "x"),
        lambda: holder.remove("0" * 16),
    ]
    for call in calls:
        with pytest.raises(PasskeyError) as info:
            call()
        assert info.value.reason == "not_found"


def test_an_ambiguous_fingerprint_is_refused_by_the_holder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written(tmp_path, made(1, 2))
    holder = load(tmp_path)
    assert holder.find(holder.fingerprint(credential(2).id)) == made(1, 2).credentials[1]
    monkeypatch.setattr(passkeys, "fingerprint", lambda key, credential_id: "same")
    with pytest.raises(PasskeyError) as info:
        holder.remove("same")
    assert info.value.reason == "ambiguous_fingerprint"
    assert holder.document == made(1, 2)


def unavailable(tmp_path: Path) -> tuple[Passkeys, bytes]:
    path = written(tmp_path, made(1, 2))
    bad = path.read_bytes().replace(b'"key 1"', b'"key 9"')
    path.write_bytes(bad)
    holder = load(tmp_path)
    assert holder.unavailable
    return holder, bad


def test_an_unavailable_file_refuses_everything_but_a_reset(tmp_path: Path) -> None:
    holder, _ = unavailable(tmp_path)
    calls: list[Callable[[], object]] = [
        lambda: holder.find("0" * 16),
        lambda: holder.add(credential(3), name="x", via="setup_code", origin=ORIGIN),
        lambda: holder.rename("0" * 16, "x"),
        lambda: holder.remove("0" * 16, allow_last=True),
    ]
    for call in calls:
        with pytest.raises(PasskeyError) as info:
            call()
        assert info.value.reason == "unavailable"


def test_a_reset_moves_an_unverifiable_file_aside(tmp_path: Path) -> None:
    clock = Clock(1_760_000_000.5)
    path = written(tmp_path, made(1, 2))
    bad = path.read_bytes().replace(b'"key 1"', b'"key 9"')
    path.write_bytes(bad)
    holder = load(tmp_path, clock=clock)
    assert holder.reset_with(credential(3), name="new", origin=ORIGIN) == ()
    assert holder.unavailable is False
    aside = path.with_name("passkeys.rejected-1760000000500.json")
    assert aside.read_bytes() == bad
    assert holder.document.generation == 1
    assert holder.document.user_handle == FRESH
    [only] = holder.document.credentials
    assert (only.id, only.via) == (credential(3).id, "setup_code_reset")
    assert on_disk(tmp_path) == holder.document
    holder.add(credential(4), name="phone", via="portal", origin=ORIGIN)


def test_a_reset_that_cant_move_the_file_changes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, bad = unavailable(tmp_path)

    def refuse(self: Path, target: Path) -> Path:
        raise PermissionError("no")

    monkeypatch.setattr(Path, "rename", refuse)
    attempts: list[bytes] = []
    monkeypatch.setattr(passkeys, "write_atomic", lambda path, data: attempts.append(data))
    with pytest.raises(PasskeyError) as info:
        holder.reset_with(credential(3), name="new", origin=ORIGIN)
    assert info.value.reason == "not_written"
    assert holder.unavailable
    assert path_in(tmp_path).read_bytes() == bad
    assert attempts == []


def test_a_reset_whose_write_fails_after_the_move_can_be_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, bad = unavailable(tmp_path)
    real = passkeys.write_atomic
    failing(monkeypatch)
    with pytest.raises(PasskeyError):
        holder.reset_with(credential(3), name="new", origin=ORIGIN)
    assert holder.unavailable
    assert not path_in(tmp_path).exists()
    [aside] = path_in(tmp_path).parent.glob("passkeys.rejected-*.json")
    assert aside.read_bytes() == bad
    monkeypatch.setattr(passkeys, "write_atomic", real)
    assert holder.reset_with(credential(3), name="new", origin=ORIGIN) == ()
    assert holder.unavailable is False
    assert on_disk(tmp_path) == holder.document


def test_a_reset_of_a_good_file_returns_what_it_removed(tmp_path: Path) -> None:
    written(tmp_path, made(1, 2))
    holder = load(tmp_path)
    assert holder.reset_with(credential(3), name="new", origin=ORIGIN) == made(1, 2).credentials
    assert holder.document.user_handle == HANDLE
    assert holder.document.generation == 3
    assert list(path_in(tmp_path).parent.glob("passkeys.rejected-*")) == []
    with pytest.raises(PasskeyError) as info:
        holder.reset_with(credential(4), name="", origin=ORIGIN)
    assert info.value.reason == "bad_name"


def test_touch_writes_the_counter(tmp_path: Path, log_buffer: io.StringIO) -> None:
    written(tmp_path, made(1))
    holder = load(tmp_path)
    holder.touch(asserted(1, 4))
    assert holder.document.credentials[0].sign_count == 4
    assert on_disk(tmp_path) == holder.document
    assert holder.document.generation == 2
    assert [e["event"] for e in events(log_buffer)] == ["passkeys_loaded"]


def test_touch_without_a_change_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written(tmp_path, touch(made(1), asserted(1), NOW))
    holder = load(tmp_path)
    attempts = failing(monkeypatch)
    holder.touch(asserted(1))
    assert attempts == []
    assert holder.dirty is False


def test_a_regression_is_logged(tmp_path: Path, log_buffer: io.StringIO) -> None:
    written(tmp_path, touch(made(1), asserted(1, 9), NOW))
    holder = load(tmp_path)
    holder.touch(asserted(1, 2, regressed=True))
    assert holder.document.credentials[0].sign_count == 9
    assert holder.document.last_regressed == 20_000 * DAY
    assert events(log_buffer)[1:] == [
        {
            "event": "passkey_counter_regressed",
            "level": "critical",
            "credential": fingerprint(KEY, credential(1).id),
        }
    ]
    assert on_disk(tmp_path) == holder.document


def test_a_touch_that_cant_be_written_keeps_the_login(
    tmp_path: Path, log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = written(tmp_path, made(1))
    holder = load(tmp_path)
    data = path.read_bytes()
    real = passkeys.write_atomic
    attempts = failing(monkeypatch)
    holder.touch(asserted(1, 4))
    assert holder.document.credentials[0].sign_count == 4
    assert holder.dirty
    assert path.read_bytes() == data
    assert events(log_buffer)[1:] == [
        {
            "event": "portal_state_not_written",
            "level": "critical",
            "state": "passkeys",
            "kept_in_memory": True,
            "error_type": "OSError",
        }
    ]
    # The same login again changes nothing, but the write is tried again.
    holder.touch(asserted(1, 4))
    assert len(attempts) == 2
    monkeypatch.setattr(passkeys, "write_atomic", real)
    holder.touch(asserted(1, 4))
    assert holder.dirty is False
    assert on_disk(tmp_path) == holder.document


def test_the_next_change_saves_a_counter_kept_in_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    written(tmp_path, made(1))
    holder = load(tmp_path)
    real = passkeys.write_atomic
    failing(monkeypatch)
    holder.touch(asserted(1, 4))
    monkeypatch.setattr(passkeys, "write_atomic", real)
    holder.add(credential(2), name="phone", via="portal", origin=ORIGIN)
    assert holder.dirty is False
    saved = on_disk(tmp_path)
    assert saved.credentials[0].sign_count == 4
    assert len(saved.credentials) == 2


def test_touch_while_unavailable_does_nothing(
    tmp_path: Path, log_buffer: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    holder, _ = unavailable(tmp_path)
    attempts = failing(monkeypatch)
    holder.touch(asserted(1, 4, regressed=True))
    assert attempts == []
    assert holder.document == PasskeyFile(0, FRESH, ())
    assert [e["event"] for e in events(log_buffer)] == ["passkey_store_tampered"]


def test_the_holder_is_found_where_the_design_puts_it(tmp_path: Path) -> None:
    load(tmp_path).add(credential(1), name="laptop", via="portal", origin=ORIGIN)
    assert (tmp_path / "portal" / "passkeys.json").is_file()
