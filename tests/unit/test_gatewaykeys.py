"""The gateway key ratchet (M3 design C.2): transitions, the file, and the vault's use of it."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.echo import EchoProvider
from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.common.policy import Policy
from zoeymcp.vault import gatewaykeys, logs
from zoeymcp.vault.app import GATEWAY_HEADER, VaultApp
from zoeymcp.vault.gatewaykeys import (
    BACKWARDS,
    STATE_FILE,
    TAMPERED,
    WINDOW,
    AcceptedKey,
    GatewayKeyError,
    GatewayKeys,
    Previous,
    Refusal,
    State,
    accepted_keys,
    advance,
    expired,
    initial,
    matching,
    rekey,
    retire,
    seal,
    unseal,
    utc,
    window_open,
    write_atomic,
)
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, origin_binding

KEYS = KeySet.from_master(bytes(range(32)))
OLD = KeySet.from_master(bytes(range(1, 33)))
OTHER = KeySet.from_master(bytes(range(2, 34)))
KID = KEYS.key_id
OLD_KID = OLD.key_id
OTHER_KID = OTHER.key_id
NOW = 1_000_000.0


def key(keys: KeySet, generation: int) -> bytes:
    return keys.gateway_key(generation).encode()


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
        del line["ts"]
    return lines


# --- transitions -------------------------------------------------------------------------------


def test_initial() -> None:
    assert initial(KID, 3) == State(KID, 3, 3, None)


def test_advance_to_the_same_generation_changes_nothing() -> None:
    state = State(KID, 3, 2, Previous(2, KID, 500))
    assert advance(state, 3, NOW) is state


def test_advance_refuses_a_lower_generation() -> None:
    result = advance(State(KID, 3, 3), 2, NOW)
    assert result == Refusal(f"gateway_key_generation 2 is below 3: {BACKWARDS}")
    assert BACKWARDS == "the generation went backwards; that would revive a retired key"
    assert advance(State(KID, 3, 3), 0, NOW) == Refusal(
        f"gateway_key_generation 0 is below 3: {BACKWARDS}"
    )


def test_advance_keeps_the_current_key_for_the_window() -> None:
    assert WINDOW == 300
    assert advance(State(KID, 3, 3), 4, NOW + 0.9) == State(KID, 4, 3, Previous(3, KID, 1_000_300))
    assert advance(State(KID, 3, 3), 7, NOW) == State(KID, 7, 3, Previous(3, KID, 1_000_300))


def test_advance_drops_an_older_previous_key() -> None:
    state = State(KID, 3, 2, Previous(2, KID, 1_000_100))
    assert advance(state, 4, NOW) == State(KID, 4, 3, Previous(3, KID, 1_000_300))


def test_rekey_with_the_same_master_changes_nothing() -> None:
    state = State(KID, 3, 3)
    assert rekey(state, KID, NOW) is state


def test_rekey_keeps_the_previous_masters_key() -> None:
    assert rekey(State(OLD_KID, 3, 3), KID, NOW + 0.5) == State(
        KID, 3, 3, Previous(3, OLD_KID, 1_000_300)
    )


def test_rekey_keeps_an_open_window() -> None:
    # The master key and the generation changed in one restart: the gateway still holds key(2)
    # under the old master, and the window keeps its deadline.
    state = State(OLD_KID, 3, 2, Previous(2, OLD_KID, 1_000_100))
    assert rekey(state, KID, NOW) == State(KID, 3, 2, Previous(2, OLD_KID, 1_000_100))


def test_rekey_after_a_window_closed() -> None:
    state = State(OLD_KID, 3, 2, Previous(2, OLD_KID, 1_000_000))
    assert rekey(state, KID, NOW) == State(KID, 3, 3, Previous(3, OLD_KID, 1_000_300))


def test_rekey_replaces_a_window_from_an_older_master() -> None:
    # A second master-key rotation inside the first one's window: the oldest master isn't loaded
    # any more, so its key can't be accepted; the previous master's key(current) starts a window.
    state = State(OLD_KID, 3, 3, Previous(3, OTHER_KID, 1_000_100))
    assert rekey(state, KID, NOW) == State(KID, 3, 3, Previous(3, OLD_KID, 1_000_300))
    bumped = State(OLD_KID, 3, 2, Previous(2, OTHER_KID, 1_000_100))
    assert rekey(bumped, KID, NOW) == State(KID, 3, 3, Previous(3, OLD_KID, 1_000_300))


def test_retire() -> None:
    assert retire(State(KID, 4, 3, Previous(3, KID, 1_000_300))) == State(KID, 4, 4)
    assert retire(State(KID, 4, 4)) == State(KID, 4, 4)


def test_window_boundaries() -> None:
    state = State(KID, 4, 3, Previous(3, KID, 1_000_300))
    assert window_open(state, 1_000_299.9) is True
    assert window_open(state, 1_000_300) is False
    assert expired(state, 1_000_299.9) is False
    assert expired(state, 1_000_300) is True
    assert window_open(State(KID, 4, 4), 0) is False
    assert expired(State(KID, 4, 4), 2_000_000_000) is False


# --- accepted keys -----------------------------------------------------------------------------


def test_accepted_keys_without_a_previous() -> None:
    assert accepted_keys(State(KID, 2, 2), KEYS, OLD, NOW) == [
        AcceptedKey(2, KID, True, key(KEYS, 2))
    ]


def test_accepted_keys_in_the_window() -> None:
    state = State(KID, 4, 3, Previous(3, KID, 1_000_300))
    both = [AcceptedKey(4, KID, True, key(KEYS, 4)), AcceptedKey(3, KID, False, key(KEYS, 3))]
    assert accepted_keys(state, KEYS, None, 1_000_299.9) == both
    assert accepted_keys(state, KEYS, None, 1_000_300) == both[:1]


def test_accepted_keys_after_a_master_rotation() -> None:
    state = State(KID, 3, 3, Previous(3, OLD_KID, 1_000_300))
    assert accepted_keys(state, KEYS, OLD, NOW) == [
        AcceptedKey(3, KID, True, key(KEYS, 3)),
        AcceptedKey(3, OLD_KID, False, key(OLD, 3)),
    ]
    # Without the previous master, its key can't be derived and isn't accepted.
    assert accepted_keys(state, KEYS, None, NOW) == [AcceptedKey(3, KID, True, key(KEYS, 3))]
    assert accepted_keys(state, KEYS, OTHER, NOW) == [AcceptedKey(3, KID, True, key(KEYS, 3))]


def test_accepted_keys_after_a_master_rotation_during_a_bump() -> None:
    # The gateway may hold the old master's key(2) or key(3): both are accepted in the window.
    state = State(KID, 3, 2, Previous(2, OLD_KID, 1_000_300))
    assert accepted_keys(state, KEYS, OLD, 1_000_299.9) == [
        AcceptedKey(3, KID, True, key(KEYS, 3)),
        AcceptedKey(2, OLD_KID, False, key(OLD, 2)),
        AcceptedKey(3, OLD_KID, False, key(OLD, 3)),
    ]
    assert accepted_keys(state, KEYS, OLD, 1_000_300) == [AcceptedKey(3, KID, True, key(KEYS, 3))]
    assert accepted_keys(state, KEYS, None, NOW) == [AcceptedKey(3, KID, True, key(KEYS, 3))]


def test_accepted_keys_derive_from_the_states_master() -> None:
    assert accepted_keys(State(OLD_KID, 2, 2), KEYS, OLD, NOW) == [
        AcceptedKey(2, OLD_KID, True, key(OLD, 2))
    ]
    assert accepted_keys(State(OLD_KID, 2, 2), KEYS, None, NOW) == []


def test_accepted_keys_respect_the_floor() -> None:
    at_floor = State(KID, 4, 3, Previous(3, KID, 1_000_300))
    assert len(accepted_keys(at_floor, KEYS, None, NOW)) == 2
    below = State(KID, 4, 4, Previous(3, KID, 1_000_300))
    assert accepted_keys(below, KEYS, None, NOW) == [AcceptedKey(4, KID, True, key(KEYS, 4))]


def test_accepted_key_repr_hides_the_key() -> None:
    accepted = AcceptedKey(4, KID, True, key(KEYS, 4))
    assert KEYS.gateway_key(4) not in repr(accepted)
    assert repr(accepted) == f"AcceptedKey(generation=4, key_id='{KID}', current=True)"


def test_matching_compares_every_candidate(monkeypatch: pytest.MonkeyPatch) -> None:
    accepted = [AcceptedKey(4, KID, True, key(KEYS, 4)), AcceptedKey(3, KID, False, key(KEYS, 3))]
    assert matching(accepted, key(KEYS, 4)) is accepted[0]
    assert matching(accepted, key(KEYS, 3)) is accepted[1]
    assert matching(accepted, key(KEYS, 5)) is None
    assert matching([], key(KEYS, 4)) is None
    calls: list[bytes] = []

    def compare(a: bytes, b: bytes) -> bool:
        calls.append(b)
        return a == b

    monkeypatch.setattr(hmac, "compare_digest", compare)
    assert matching(accepted, key(KEYS, 4)) is accepted[0]
    assert calls == [key(KEYS, 4), key(KEYS, 3)]


# --- the file ----------------------------------------------------------------------------------


def _expected_mac(body: str, keys: KeySet = KEYS) -> str:
    message = b"zoeymcp/gateway-key-state/v1\n" + body.encode()
    return hmac.new(keys.config_key, message, hashlib.sha256).hexdigest()


def test_seal_format() -> None:
    body = (
        f'{{"current":3,"floor":2,"key_id":"{KID}","previous":2,"previous_key_id":"{KID}",'
        '"previous_until":1791234867,"v":1}'
    )
    mac = _expected_mac(body)
    assert (
        seal(State(KID, 3, 2, Previous(2, KID, 1791234867)), KEYS)
        == (
            f'{{"current":3,"floor":2,"key_id":"{KID}","mac":"{mac}","previous":2,'
            f'"previous_key_id":"{KID}","previous_until":1791234867,"v":1}}\n'
        ).encode()
    )
    plain = f'{{"current":1,"floor":1,"key_id":"{KID}","previous":null,"previous_key_id":null,'
    plain += '"previous_until":null,"v":1}'
    assert (
        seal(State(KID, 1, 1), KEYS)
        == (
            f'{{"current":1,"floor":1,"key_id":"{KID}","mac":"{_expected_mac(plain)}",'
            '"previous":null,"previous_key_id":null,"previous_until":null,"v":1}\n'
        ).encode()
    )


def test_seal_needs_the_states_master() -> None:
    with pytest.raises(ValueError, match=r"^the state must be sealed under its own master key$"):
        seal(State(OLD_KID, 1, 1), KEYS)


@pytest.mark.parametrize(
    "state",
    [
        State(KID, 1, 1),
        State(KID, 4, 3, Previous(3, KID, 1_000_300)),
        State(KID, 3, 3, Previous(3, OLD_KID, 1_000_300)),
    ],
)
def test_unseal_reads_what_seal_wrote(state: State) -> None:
    assert unseal(seal(state, KEYS), KEYS, None) == state
    assert unseal(seal(state, KEYS), OLD, KEYS) == state


def test_unseal_refuses_a_changed_file() -> None:
    data = seal(State(KID, 4, 3, Previous(3, KID, 1_000_300)), KEYS)
    for old, new in [(b'"current":4', b'"current":5'), (b"1000300", b"1000900")]:
        with pytest.raises(GatewayKeyError) as caught:
            unseal(data.replace(old, new), KEYS, None)
        assert str(caught.value) == TAMPERED
    assert TAMPERED == "gateway key state was tampered with, or written under another master key"


def test_unseal_refuses_a_mac_from_another_master() -> None:
    # The key ID claims the current master, but the MAC was made by another.
    document = json.loads(seal(State(OTHER.key_id, 1, 1), OTHER))
    document["key_id"] = KID
    data = dumps_canonical(document)
    with pytest.raises(GatewayKeyError, match=f"^{TAMPERED}$"):
        unseal(data, KEYS, None)


def test_unseal_names_an_unknown_master() -> None:
    data = seal(State(OLD_KID, 1, 1), OLD)
    expected = (
        f"was written under master key ID {OLD_KID}, but the master key's ID is {KID}. If you "
        "are rotating the master key, set ZOEYMCP_MASTER_KEY_PREVIOUS to the old key; deleting "
        "the file instead resets the generation floor."
    )
    for previous in (None, OTHER):
        with pytest.raises(GatewayKeyError) as caught:
            unseal(data, KEYS, previous)
        assert str(caught.value) == expected
    assert unseal(data, KEYS, OLD) == State(OLD_KID, 1, 1)


VALID: dict[str, Any] = {
    "v": 1,
    "key_id": KID,
    "current": 3,
    "floor": 2,
    "previous": 2,
    "previous_key_id": KID,
    "previous_until": 1_000_300,
}
PLAIN: dict[str, Any] = {
    **VALID,
    "floor": 3,
    "previous": None,
    "previous_key_id": None,
    "previous_until": None,
}


def signed(document: dict[str, Any], keys: KeySet = KEYS) -> bytes:
    rest = {name: value for name, value in document.items() if name != "mac"}
    return dumps_canonical({**rest, "mac": gatewaykeys._mac(rest, keys)})


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"{",
        b'{"v": 1, "v": 1}',
        b"x" * 5000,
    ],
)
def test_unseal_refuses_what_isnt_json(data: bytes) -> None:
    with pytest.raises(GatewayKeyError, match=r"^isn't a gateway key state: "):
        unseal(data, KEYS, None)


def test_unseal_limits_the_size() -> None:
    padded = signed(VALID) + b" " * (4096 - len(signed(VALID)))
    assert unseal(padded, KEYS, None) == State(KID, 3, 2, Previous(2, KID, 1_000_300))
    with pytest.raises(GatewayKeyError, match="larger than 4096 bytes"):
        unseal(padded + b" ", KEYS, None)


@pytest.mark.parametrize(
    "document",
    [
        [],
        "state",
        {name: value for name, value in VALID.items() if name != "floor"},
        {**VALID, "extra": 1},
        {**VALID, "key_id": 5},
        {**VALID, "key_id": KID[:-1]},
        {**VALID, "key_id": KID + "0"},
        {**VALID, "key_id": KID.upper()},
        {**VALID, "key_id": KID + "\n"},
    ],
)
def test_unseal_refuses_another_shape(document: Any) -> None:
    data = dumps_canonical({**document, "mac": "00"} if isinstance(document, dict) else document)
    with pytest.raises(GatewayKeyError) as caught:
        unseal(data, KEYS, None)
    assert str(caught.value) == "isn't a version-1 gateway key state"


def test_unseal_refuses_a_mac_that_isnt_text() -> None:
    with pytest.raises(GatewayKeyError, match=r"^isn't a version-1 gateway key state$"):
        unseal(dumps_canonical({**VALID, "mac": 5}), KEYS, None)
    with pytest.raises(GatewayKeyError, match=r"^isn't a version-1 gateway key state$"):
        unseal(dumps_canonical({**VALID, "mac": None}), KEYS, None)


@pytest.mark.parametrize(
    "changes",
    [
        {"v": 2},
        {"v": True},
        {"v": "1"},
        {"current": 0, "floor": 0, "previous": None, "previous_key_id": None},
        {"previous_until": None, "current": 0, "floor": 0},
        {"current": True, "floor": True, "previous": None, "previous_key_id": None},
        {
            "current": 0,
            "floor": 0,
            "previous": None,
            "previous_key_id": None,
            "previous_until": None,
        },
        {
            "current": True,
            "floor": 1,
            "previous": None,
            "previous_key_id": None,
            "previous_until": None,
        },
        {
            "current": 1,
            "floor": True,
            "previous": None,
            "previous_key_id": None,
            "previous_until": None,
        },
        {"floor": 1, "previous": True},
        {"current": "3"},
        {"floor": 2.0},
        {"floor": 0, "previous": 0},
        {"previous": None, "previous_key_id": None, "previous_until": None},
        {"previous": None},
        {"previous_key_id": None},
        {"previous_until": None},
        {"previous": None, "previous_key_id": None},
        {"previous": "2"},
        {"previous": True, "floor": True},
        {"previous_until": "1000300"},
        {"previous_until": True},
        {"previous_until": 1.5},
        {"previous_key_id": 5},
        {"previous_key_id": KID[:-1]},
        {"previous_key_id": KID + "\n"},
        {"floor": 1},
        {"floor": 3},
        {"previous": 4, "floor": 4},
        {"previous": 3, "floor": 3},
    ],
)
def test_unseal_refuses_an_inconsistent_state(changes: dict[str, Any]) -> None:
    with pytest.raises(GatewayKeyError) as caught:
        unseal(signed({**VALID, **changes}), KEYS, None)
    assert str(caught.value) == "isn't a consistent version-1 gateway key state"


@pytest.mark.parametrize(
    ("changes", "state"),
    [
        ({}, State(KID, 3, 2, Previous(2, KID, 1_000_300))),
        ({"previous_until": 0}, State(KID, 3, 2, Previous(2, KID, 0))),
        (
            {"current": 1, "floor": 1, "previous": 1, "previous_key_id": OLD_KID},
            State(KID, 1, 1, Previous(1, OLD_KID, 1_000_300)),
        ),
        (
            {"previous": 3, "floor": 3, "previous_key_id": OLD_KID},
            State(KID, 3, 3, Previous(3, OLD_KID, 1_000_300)),
        ),
    ],
)
def test_unseal_accepts_a_consistent_state(changes: dict[str, Any], state: State) -> None:
    assert unseal(signed({**VALID, **changes}), KEYS, None) == state


@pytest.mark.parametrize(
    ("changes", "state"),
    [
        ({}, State(KID, 3, 3)),
        ({"current": 1, "floor": 1}, State(KID, 1, 1)),
    ],
)
def test_unseal_accepts_a_state_without_a_previous(changes: dict[str, Any], state: State) -> None:
    assert unseal(signed({**PLAIN, **changes}), KEYS, None) == state


def test_write_atomic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    synced: list[int] = []
    real_fsync = os.fsync

    def fsync(fd: int) -> None:
        synced.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", fsync)
    path = tmp_path / "a" / "b" / STATE_FILE
    write_atomic(path, b"one")
    write_atomic(path, b"two")
    assert path.read_bytes() == b"two"
    assert sorted(p.name for p in path.parent.iterdir()) == [STATE_FILE]
    # The file each time, and on POSIX its directory too.
    assert len(synced) == (2 if sys.platform == "win32" else 4)


def test_write_atomic_uses_a_temporary_file_beside_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, Any]] = []
    real = tempfile.mkstemp

    def mkstemp(**kwargs: Any) -> tuple[int, str]:
        seen.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(tempfile, "mkstemp", mkstemp)
    write_atomic(tmp_path / STATE_FILE, b"x")
    assert seen == [{"prefix": ".gateway-key-", "dir": tmp_path}]
    assert STATE_FILE == "gateway-key.json"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX directories")
def test_write_atomic_syncs_the_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    opened: list[tuple[str, int]] = []
    real = os.open

    def open_(path: Any, flags: int, *args: Any) -> int:
        opened.append((str(path), flags))
        return real(path, flags, *args)

    monkeypatch.setattr(os, "open", open_)
    write_atomic(tmp_path / STATE_FILE, b"x")
    assert hasattr(os, "O_DIRECTORY")
    assert (str(tmp_path), os.O_RDONLY | os.O_DIRECTORY) in opened


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_write_atomic_mode(tmp_path: Path) -> None:
    write_atomic(tmp_path / STATE_FILE, b"x")
    assert stat.S_IMODE((tmp_path / STATE_FILE).stat().st_mode) == 0o600


def test_write_atomic_leaves_the_old_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / STATE_FILE
    write_atomic(path, b"old")

    def broken(src: str, dst: Path) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", broken)
    with pytest.raises(OSError, match="disk full"):
        write_atomic(path, b"new")
    assert path.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == [STATE_FILE]


def test_utc() -> None:
    assert utc(0) == "1970-01-01T00:00:00Z"
    assert utc(1_791_234_867) == "2026-10-05T21:14:27Z"


# --- loading at startup ------------------------------------------------------------------------


def load(
    tmp_path: Path,
    generation: int,
    clock: Clock,
    keys: KeySet = KEYS,
    previous: KeySet | None = None,
) -> GatewayKeys:
    return GatewayKeys.load(tmp_path, keys, previous, generation, clock=clock)


def on_disk(tmp_path: Path, keys: KeySet = KEYS) -> State:
    return unseal((tmp_path / STATE_FILE).read_bytes(), keys, None)


def test_first_start_writes_the_floor(tmp_path: Path, log_buffer: io.StringIO) -> None:
    ratchet = load(tmp_path, 2, Clock())
    assert ratchet.state == State(KID, 2, 2)
    assert on_disk(tmp_path) == State(KID, 2, 2)
    assert events(log_buffer) == []
    assert ratchet.authenticate(key(KEYS, 2)) is True
    assert ratchet.authenticate(key(KEYS, 1)) is False


def test_a_restart_on_the_same_generation_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    load(tmp_path, 2, Clock())

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    assert load(tmp_path, 2, Clock()).state == State(KID, 2, 2)


def test_a_bump_at_startup_is_written_first(tmp_path: Path, log_buffer: io.StringIO) -> None:
    load(tmp_path, 2, Clock())
    ratchet = load(tmp_path, 3, Clock(NOW + 0.5))
    expected = State(KID, 3, 2, Previous(2, KID, 1_000_300))
    assert ratchet.state == expected
    assert on_disk(tmp_path) == expected
    assert events(log_buffer) == [
        {
            "role": "vault",
            "event": "gateway_key_rotation_started",
            "generation": 3,
            "previous_until": 1_000_300,
            "master_key_changed": False,
        }
    ]


def test_a_bump_that_cant_be_written_refuses_to_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    load(tmp_path, 2, Clock())

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    with pytest.raises(GatewayKeyError) as caught:
        load(tmp_path, 3, Clock())
    assert str(caught.value) == f"can't write {tmp_path / STATE_FILE}: read-only"
    assert on_disk(tmp_path) == State(KID, 2, 2)
    with pytest.raises(GatewayKeyError, match="read-only"):
        load(tmp_path / "fresh", 1, Clock())


def test_a_lower_generation_refuses_to_start(tmp_path: Path) -> None:
    load(tmp_path, 3, Clock())
    with pytest.raises(GatewayKeyError) as caught:
        load(tmp_path, 2, Clock())
    assert str(caught.value) == (
        f"{tmp_path / STATE_FILE}: gateway_key_generation 2 is below 3: {BACKWARDS}"
    )


def test_a_tampered_file_refuses_to_start(tmp_path: Path) -> None:
    load(tmp_path, 3, Clock())
    path = tmp_path / STATE_FILE
    path.write_bytes(path.read_bytes().replace(b'"current":3', b'"current":1'))
    with pytest.raises(GatewayKeyError) as caught:
        load(tmp_path, 3, Clock())
    assert str(caught.value) == f"{path}: {TAMPERED}"


def test_an_unreadable_file_refuses_to_start(tmp_path: Path) -> None:
    (tmp_path / STATE_FILE).mkdir()
    with pytest.raises(GatewayKeyError, match=f"^can't read {_escaped(tmp_path / STATE_FILE)}: "):
        load(tmp_path, 1, Clock())


def _escaped(path: Path) -> str:
    return re.escape(str(path))


def test_a_restart_keeps_the_window_and_its_deadline(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    load(tmp_path, 2, Clock())
    load(tmp_path, 3, Clock())
    log_buffer.truncate(0)
    log_buffer.seek(0)
    ratchet = load(tmp_path, 3, Clock(NOW + 299))
    assert ratchet.state == State(KID, 3, 2, Previous(2, KID, 1_000_300))
    assert events(log_buffer) == []
    assert ratchet.authenticate(key(KEYS, 2)) is True


def test_a_restart_after_the_window_retires_it(tmp_path: Path, log_buffer: io.StringIO) -> None:
    load(tmp_path, 2, Clock())
    load(tmp_path, 3, Clock())
    ratchet = load(tmp_path, 3, Clock(NOW + 300))
    assert ratchet.state == State(KID, 3, 3)
    assert on_disk(tmp_path) == State(KID, 3, 3)
    assert events(log_buffer)[-1] == {
        "role": "vault",
        "event": "gateway_key_retired",
        "generation": 2,
        "reason": "expired",
    }
    assert ratchet.authenticate(key(KEYS, 2)) is False


def test_a_retired_key_stays_retired_across_a_restart(tmp_path: Path) -> None:
    load(tmp_path, 2, Clock())
    ratchet = load(tmp_path, 3, Clock())
    assert ratchet.authenticate(key(KEYS, 3)) is True
    restarted = load(tmp_path, 3, Clock(NOW + 1))
    assert restarted.state == State(KID, 3, 3)
    assert restarted.authenticate(key(KEYS, 2)) is False
    assert restarted.authenticate(key(KEYS, 3)) is True


def test_a_second_bump_supersedes_the_previous_key(tmp_path: Path, log_buffer: io.StringIO) -> None:
    load(tmp_path, 2, Clock())
    load(tmp_path, 3, Clock())
    ratchet = load(tmp_path, 4, Clock(NOW + 10))
    assert ratchet.state == State(KID, 4, 3, Previous(3, KID, 1_000_310))
    assert [e["event"] for e in events(log_buffer)][-2:] == [
        "gateway_key_retired",
        "gateway_key_rotation_started",
    ]
    assert events(log_buffer)[-2]["reason"] == "superseded"
    assert events(log_buffer)[-2]["generation"] == 2


def test_a_master_key_rotation(tmp_path: Path, log_buffer: io.StringIO) -> None:
    load(tmp_path, 2, Clock(), keys=OLD)
    with pytest.raises(GatewayKeyError, match="set ZOEYMCP_MASTER_KEY_PREVIOUS"):
        load(tmp_path, 2, Clock())
    ratchet = load(tmp_path, 2, Clock(NOW + 1), previous=OLD)
    expected = State(KID, 2, 2, Previous(2, OLD_KID, 1_000_301))
    assert ratchet.state == expected
    assert on_disk(tmp_path) == expected  # MAC'd under the new master now
    assert events(log_buffer)[-1] == {
        "role": "vault",
        "event": "gateway_key_rotation_started",
        "generation": 2,
        "previous_until": 1_000_301,
        "master_key_changed": True,
    }
    assert ratchet.authenticate(key(OLD, 2)) is True
    assert ratchet.authenticate(key(KEYS, 2)) is True
    assert ratchet.state == State(KID, 2, 2)
    assert ratchet.authenticate(key(OLD, 2)) is False


def test_a_master_key_rotation_and_a_bump_in_one_restart(tmp_path: Path) -> None:
    load(tmp_path, 2, Clock(), keys=OLD)
    ratchet = load(tmp_path, 3, Clock(), previous=OLD)
    assert ratchet.state == State(KID, 3, 2, Previous(2, OLD_KID, 1_000_300))
    assert ratchet.authenticate(key(OLD, 2)) is True
    assert ratchet.authenticate(key(OLD, 3)) is True
    assert ratchet.authenticate(key(KEYS, 2)) is False
    assert ratchet.authenticate(key(KEYS, 3)) is True
    assert ratchet.state == State(KID, 3, 3)
    assert ratchet.authenticate(key(OLD, 2)) is False
    assert ratchet.authenticate(key(OLD, 3)) is False


def test_a_master_key_rotation_during_a_window_keeps_it(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    load(tmp_path, 2, Clock(), keys=OLD)
    load(tmp_path, 3, Clock(), keys=OLD)
    clock = Clock(NOW + 100)
    ratchet = load(tmp_path, 3, clock, previous=OLD)
    assert ratchet.state == State(KID, 3, 2, Previous(2, OLD_KID, 1_000_300))
    assert events(log_buffer)[-1]["event"] == "gateway_key_rotation_started"
    assert events(log_buffer)[-1]["master_key_changed"] is True
    # The gateway may already hold the old master's key(3) (fetched, not used yet), or key(2).
    assert ratchet.authenticate(key(OLD, 3)) is True
    assert ratchet.authenticate(key(OLD, 2)) is True
    clock.now = NOW + 300
    assert ratchet.authenticate(key(OLD, 3)) is False
    assert ratchet.state == State(KID, 3, 3)


def test_a_second_master_key_rotation_during_a_window(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    load(tmp_path, 2, Clock(), keys=OLD)
    load(tmp_path, 2, Clock(), previous=OLD)
    ratchet = load(tmp_path, 2, Clock(NOW + 10), keys=OTHER, previous=KEYS)
    assert ratchet.state == State(OTHER_KID, 2, 2, Previous(2, KID, 1_000_310))
    assert [(e["event"], e.get("reason")) for e in events(log_buffer)][-2:] == [
        ("gateway_key_retired", "superseded"),
        ("gateway_key_rotation_started", None),
    ]
    assert ratchet.authenticate(key(KEYS, 2)) is True
    assert ratchet.authenticate(key(OLD, 2)) is False


def test_a_bump_after_the_window_closed_retires_it_as_expired(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    load(tmp_path, 2, Clock())
    load(tmp_path, 3, Clock())
    ratchet = load(tmp_path, 4, Clock(NOW + 300))
    assert ratchet.state == State(KID, 4, 3, Previous(3, KID, 1_000_600))
    assert on_disk(tmp_path) == ratchet.state
    assert [(e["event"], e.get("reason"), e["generation"]) for e in events(log_buffer)][-2:] == [
        ("gateway_key_retired", "expired", 2),
        ("gateway_key_rotation_started", None, 4),
    ]


# --- the running ratchet -----------------------------------------------------------------------


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def rotating(tmp_path: Path, clock: Clock) -> GatewayKeys:
    """Generation 3, with generation 2 accepted until NOW + 300."""
    load(tmp_path, 2, clock)
    return load(tmp_path, 3, clock)


def test_the_new_key_retires_the_previous(
    tmp_path: Path, rotating: GatewayKeys, log_buffer: io.StringIO
) -> None:
    assert rotating.authenticate(key(KEYS, 2)) is True
    assert rotating.authenticate(key(KEYS, 3)) is True
    assert rotating.state == State(KID, 3, 3)
    assert on_disk(tmp_path) == State(KID, 3, 3)
    assert events(log_buffer)[-1] == {
        "role": "vault",
        "event": "gateway_key_retired",
        "generation": 2,
        "reason": "new_key_used",
    }
    assert rotating.authenticate(key(KEYS, 2)) is False
    count = len(events(log_buffer))
    assert rotating.authenticate(key(KEYS, 3)) is True
    assert len(events(log_buffer)) == count


def test_the_window_ends_after_five_minutes(
    tmp_path: Path, rotating: GatewayKeys, clock: Clock, log_buffer: io.StringIO
) -> None:
    clock.now = NOW + 299.9
    assert rotating.authenticate(key(KEYS, 2)) is True
    clock.now = NOW + 300
    assert rotating.authenticate(key(KEYS, 2)) is False
    assert rotating.state == State(KID, 3, 3)
    assert on_disk(tmp_path) == State(KID, 3, 3)
    assert events(log_buffer)[-1]["event"] == "gateway_key_retired"
    assert events(log_buffer)[-1]["reason"] == "expired"


def test_an_expired_window_is_retired_by_any_request(
    rotating: GatewayKeys, clock: Clock, log_buffer: io.StringIO
) -> None:
    clock.now = NOW + 300
    assert rotating.authenticate(b"nope") is False
    assert rotating.state == State(KID, 3, 3)
    assert events(log_buffer)[-1]["reason"] == "expired"


def test_using_the_previous_key_is_logged_once_a_minute(
    rotating: GatewayKeys, clock: Clock, log_buffer: io.StringIO
) -> None:
    def used() -> int:
        return sum(e["event"] == "gateway_key_previous_used" for e in events(log_buffer))

    assert rotating.authenticate(key(KEYS, 2)) is True
    assert events(log_buffer)[-1] == {
        "role": "vault",
        "event": "gateway_key_previous_used",
        "generation": 2,
    }
    clock.now = NOW + 59.9
    assert rotating.authenticate(key(KEYS, 2)) is True
    assert used() == 1
    clock.now = NOW + 60
    assert rotating.authenticate(key(KEYS, 2)) is True
    assert used() == 2
    clock.now = NOW + 119.9
    assert rotating.authenticate(key(KEYS, 2)) is True
    assert used() == 2
    assert rotating.state.previous is not None


def test_a_wrong_key_changes_nothing(rotating: GatewayKeys, log_buffer: io.StringIO) -> None:
    for wrong in (key(KEYS, 1), key(KEYS, 4), key(OLD, 3), b"", key(KEYS, 3)[:-1]):
        assert rotating.authenticate(wrong) is False
    assert rotating.state == State(KID, 3, 2, Previous(2, KID, 1_000_300))
    assert events(log_buffer) == []


def test_a_retirement_that_cant_be_written(
    tmp_path: Path,
    rotating: GatewayKeys,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    log_buffer: io.StringIO,
) -> None:
    real = gatewaykeys.write_atomic

    def broken(path: Path, data: bytes) -> None:
        raise PermissionError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    assert rotating.authenticate(key(KEYS, 3)) is True
    # Memory keeps the retirement; the file is behind, and that is critical.
    assert rotating.state == State(KID, 3, 3)
    assert rotating.dirty is True
    assert rotating.authenticate(key(KEYS, 2)) is False
    assert events(log_buffer)[-1] == {
        "role": "vault",
        "event": "gateway_key_state_not_written",
        "level": "critical",
        "path": str(tmp_path / STATE_FILE),
        "error_type": "PermissionError",
    }
    assert on_disk(tmp_path).previous is not None
    rotating.tick()
    assert rotating.dirty is True
    monkeypatch.setattr(gatewaykeys, "write_atomic", real)
    rotating.tick()
    assert rotating.dirty is False
    assert on_disk(tmp_path) == State(KID, 3, 3)


def test_tick_retires_an_expired_window(
    tmp_path: Path, rotating: GatewayKeys, clock: Clock, log_buffer: io.StringIO
) -> None:
    clock.now = NOW + 299
    rotating.tick()
    assert rotating.state.previous is not None
    clock.now = NOW + 300
    rotating.tick()
    assert rotating.state == State(KID, 3, 3)
    assert on_disk(tmp_path) == State(KID, 3, 3)
    assert events(log_buffer)[-1]["reason"] == "expired"
    count = len(events(log_buffer))
    rotating.tick()
    assert len(events(log_buffer)) == count


def test_tick_at_expiry_that_cant_be_written_tries_once(
    rotating: GatewayKeys,
    clock: Clock,
    monkeypatch: pytest.MonkeyPatch,
    log_buffer: io.StringIO,
) -> None:
    attempts: list[bytes] = []

    def broken(path: Path, data: bytes) -> None:
        attempts.append(data)
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    clock.now = NOW + 300
    rotating.tick()
    assert len(attempts) == 1
    assert [e["event"] for e in events(log_buffer)].count("gateway_key_state_not_written") == 1
    assert rotating.dirty is True
    assert rotating.state == State(KID, 3, 3)


def test_tick_with_nothing_to_do_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ratchet = load(tmp_path, 1, Clock())
    written: list[bytes] = []
    monkeypatch.setattr(gatewaykeys, "write_atomic", lambda path, data: written.append(data))
    ratchet.tick()
    assert written == []


def test_retire_previous(tmp_path: Path, rotating: GatewayKeys, log_buffer: io.StringIO) -> None:
    assert rotating.retire_previous() == 2
    assert rotating.state == State(KID, 3, 3)
    assert on_disk(tmp_path) == State(KID, 3, 3)
    assert events(log_buffer)[-1] == {
        "role": "vault",
        "event": "gateway_key_retired",
        "generation": 2,
        "reason": "operator",
    }
    assert rotating.retire_previous() is None
    assert rotating.authenticate(key(KEYS, 2)) is False


def test_retire_previous_after_the_window(
    rotating: GatewayKeys, clock: Clock, log_buffer: io.StringIO
) -> None:
    clock.now = NOW + 300
    assert rotating.retire_previous() is None
    assert events(log_buffer)[-1]["reason"] == "expired"


def test_retire_previous_that_cant_be_written(
    rotating: GatewayKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    with pytest.raises(GatewayKeyError) as caught:
        rotating.retire_previous()
    assert str(caught.value) == "the retirement is kept in memory, not written to disk"
    assert rotating.state == State(KID, 3, 3)
    assert rotating.dirty is True


def test_advance_for_a_reload(tmp_path: Path, clock: Clock, log_buffer: io.StringIO) -> None:
    ratchet = load(tmp_path, 2, clock)
    assert ratchet.advance(2) is False
    clock.now = NOW + 7
    assert ratchet.advance(3) is True
    expected = State(KID, 3, 2, Previous(2, KID, 1_000_307))
    assert ratchet.state == expected
    assert on_disk(tmp_path) == expected
    assert events(log_buffer)[-1]["event"] == "gateway_key_rotation_started"
    with pytest.raises(GatewayKeyError) as caught:
        ratchet.advance(1)
    assert str(caught.value) == f"gateway_key_generation 1 is below 3: {BACKWARDS}"
    assert ratchet.state == expected


def test_advance_after_the_window_closed(
    tmp_path: Path, rotating: GatewayKeys, clock: Clock, log_buffer: io.StringIO
) -> None:
    clock.now = NOW + 300
    assert rotating.advance(4) is True
    expected = State(KID, 4, 3, Previous(3, KID, 1_000_600))
    assert rotating.state == expected
    assert on_disk(tmp_path) == expected
    assert [(e["event"], e.get("reason"), e["generation"]) for e in events(log_buffer)] == [
        ("gateway_key_retired", "expired", 2),
        ("gateway_key_rotation_started", None, 4),
    ]


def test_advance_to_the_same_generation_retires_an_expired_window(
    tmp_path: Path, rotating: GatewayKeys, clock: Clock
) -> None:
    clock.now = NOW + 300
    assert rotating.advance(3) is False
    assert rotating.state == State(KID, 3, 3)
    assert on_disk(tmp_path) == State(KID, 3, 3)


def test_advance_that_cant_be_written_changes_nothing(
    tmp_path: Path, clock: Clock, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    ratchet = load(tmp_path, 2, clock)

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    with pytest.raises(GatewayKeyError) as caught:
        ratchet.advance(3)
    assert str(caught.value) == (
        f"can't write {tmp_path / STATE_FILE}, so the new generation can't be used: read-only"
    )
    assert ratchet.state == State(KID, 2, 2)
    assert ratchet.authenticate(key(KEYS, 3)) is False
    assert events(log_buffer) == []


def test_advance_also_writes_a_pending_retirement(
    tmp_path: Path, rotating: GatewayKeys, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = gatewaykeys.write_atomic

    def broken(path: Path, data: bytes) -> None:
        raise OSError("read-only")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    assert rotating.authenticate(key(KEYS, 3)) is True
    assert rotating.dirty is True
    monkeypatch.setattr(gatewaykeys, "write_atomic", real)
    assert rotating.advance(4) is True
    assert rotating.dirty is False
    assert on_disk(tmp_path) == rotating.state


def test_info(rotating: GatewayKeys, clock: Clock) -> None:
    assert rotating.info() == {
        "generation": 3,
        "key": KEYS.gateway_key(3),
        "previous": {"generation": 2, "until": 1_000_300, "master_key": "current"},
    }
    clock.now = NOW + 300
    # Expired but not retired yet: not shown as pending.
    assert rotating.info()["previous"] is None
    assert rotating.state.previous is not None


def test_info_after_a_master_key_rotation(tmp_path: Path) -> None:
    load(tmp_path, 2, Clock(), keys=OLD)
    ratchet = load(tmp_path, 2, Clock(), previous=OLD)
    assert ratchet.info()["previous"] == {
        "generation": 2,
        "until": 1_000_300,
        "master_key": "previous",
    }


def test_info_without_the_previous_master(tmp_path: Path) -> None:
    load(tmp_path, 2, Clock(), keys=OLD)
    load(tmp_path, 2, Clock(), previous=OLD)
    # A restart inside the window, but without ZOEYMCP_MASTER_KEY_PREVIOUS: the old master's key
    # can't be derived, so it isn't accepted, and the window isn't shown as pending.
    ratchet = load(tmp_path, 2, Clock(NOW + 10))
    assert ratchet.state.previous is not None
    assert ratchet.info()["previous"] is None
    assert ratchet.authenticate(key(OLD, 2)) is False


def test_in_memory_never_writes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(path: Path, data: bytes) -> None:
        raise AssertionError("no file for an in-memory ratchet")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    clock = Clock()
    ratchet = GatewayKeys.in_memory(KEYS, 2, clock=clock)
    assert ratchet.state == State(KID, 2, 2)
    assert ratchet.advance(3) is True
    assert ratchet.retire_previous() == 2
    assert ratchet.advance(4) is True
    assert ratchet.authenticate(key(KEYS, 4)) is True
    assert ratchet.dirty is False
    assert list(tmp_path.iterdir()) == []


# --- the vault's use of it ---------------------------------------------------------------------

BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "credentials": {"api-key": {"kind": "header", "secret": "store:api-key"}},
}


def policy(generation: int, callers: list[Any] | None = None) -> Policy:
    route = {
        "name": "api",
        "prefix": "/api",
        "upstream": "https://api.example/base",
        "credential": "api-key",
        "callers": callers or ["gateway"],
        "rules": [{"methods": ["GET"], "paths": ["/v1/**"]}],
    }
    other = {**route, "name": "agent", "prefix": "/agent"}
    other["callers"] = [{"placeholder": "ph-agent-0001"}]
    return Policy.model_validate(
        {**BASE, "gateway_key_generation": generation, "routes": [route, other]}
    )


class Vault:
    def __init__(self, tmp_path: Path, generation: int, ratchet: GatewayKeys | None) -> None:
        self.echo = EchoProvider()
        store = SecretStore(tmp_path, KEYS)
        store.load()
        store.put("api-key", "sk-fake-0001", origin_binding(["https://api.example"]))
        upstream = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.echo.app()))
        self.app = VaultApp(
            policy(generation), store, KEYS, client=upstream, environ={}, gateway_keys=ratchet
        )

    async def status(self, gateway_key: bytes, prefix: str = "/api") -> int:
        transport = httpx.ASGITransport(app=self.app, client=("172.30.4.10", 40000))
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            headers = {GATEWAY_HEADER: gateway_key.decode()}
            return (await client.get(f"{prefix}/v1/x", headers=headers)).status_code


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_the_proxy_follows_the_ratchet(tmp_path: Path, log_buffer: io.StringIO) -> None:
    vault = Vault(tmp_path, 1, None)
    assert vault.app.gateway_keys.state == State(KID, 1, 1)
    assert await vault.status(key(KEYS, 1)) == 200
    assert await vault.status(key(KEYS, 2)) == 403
    vault.app.reload(policy(2))
    assert await vault.status(key(KEYS, 1)) == 200
    # A route that doesn't take the gateway: the new key isn't "used", nothing is retired.
    assert await vault.status(key(KEYS, 2), "/agent") == 403
    assert vault.app.gateway_keys.state.previous is not None
    assert await vault.status(key(KEYS, 2)) == 200
    assert await vault.status(key(KEYS, 1)) == 403
    assert len(vault.echo.received) == 3
    await vault.app.aclose()
    # No line holds a key, whole or as its derivation's base64 (G20).
    for generation in (1, 2):
        assert KEYS.gateway_key(generation)[5:] not in log_buffer.getvalue()
    assert {e["event"] for e in events(log_buffer)} >= {
        "gateway_key_rotation_started",
        "gateway_key_previous_used",
        "gateway_key_retired",
    }


@pytest.mark.anyio
async def test_a_reload_that_goes_backwards_keeps_the_policy(tmp_path: Path) -> None:
    vault = Vault(tmp_path, 2, None)
    before = vault.app.policy
    with pytest.raises(GatewayKeyError, match=BACKWARDS):
        vault.app.reload(policy(1))
    assert vault.app.policy is before
    assert await vault.status(key(KEYS, 2)) == 200
    assert await vault.status(key(KEYS, 1)) == 403
    await vault.app.aclose()


@pytest.mark.anyio
async def test_the_proxy_uses_the_persisted_ratchet(tmp_path: Path) -> None:
    load(tmp_path, 1, Clock())
    ratchet = GatewayKeys.load(tmp_path, KEYS, None, 2)
    vault = Vault(tmp_path, 2, ratchet)
    assert vault.app.gateway_keys is ratchet
    assert await vault.status(key(KEYS, 1)) == 200
    assert await vault.status(key(KEYS, 2)) == 200
    assert on_disk(tmp_path) == State(KID, 2, 2)
    await vault.app.aclose()
    # A new vault process on the same state: generation 1 stays retired.
    restarted = Vault(tmp_path, 2, GatewayKeys.load(tmp_path, KEYS, None, 2))
    assert await restarted.status(key(KEYS, 1)) == 403
    assert await restarted.status(key(KEYS, 2)) == 200
    await restarted.app.aclose()
