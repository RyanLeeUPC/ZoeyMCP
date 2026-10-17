from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import (
    STORE_FILE,
    SecretStore,
    SecretUnavailable,
    StoreError,
    canonical_origin,
    origin_binding,
    smtp_binding,
)

KEYS = KeySet.from_master(bytes(range(32)))
OTHER_KEYS = KeySet.from_master(bytes(range(1, 33)))
API = origin_binding(["https://api.example"])


def new_store(tmp_path: Path, keys: KeySet = KEYS, previous: KeySet | None = None) -> SecretStore:
    store = SecretStore(tmp_path, keys, previous)
    store.load()
    return store


def raw_file(tmp_path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((tmp_path / STORE_FILE).read_text(encoding="utf-8"))
    return data


def write_raw(tmp_path: Path, data: dict[str, Any]) -> None:
    (tmp_path / STORE_FILE).write_text(json.dumps(data), encoding="utf-8")


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("https://API.Example", "https://api.example:443"),
        ("https://api.example:8443/x?y", "https://api.example:8443"),
        ("http://api.example/", "http://api.example:80"),
        ("https://[2001:db8::1]/", "https://[2001:db8::1]:443"),
    ],
)
def test_canonical_origin(url: str, origin: str) -> None:
    assert canonical_origin(url) == origin


def test_round_trip_and_persistence(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("stats", "s3cret-value", API)
    assert store.get_for_origin("stats", "https://api.example/2.0/x").reveal() == "s3cret-value"
    reopened = new_store(tmp_path)
    assert reopened.get_for_origin("stats", "https://api.example").reveal() == "s3cret-value"


def test_file_never_contains_the_value(tmp_path: Path) -> None:
    new_store(tmp_path).put("stats", "very-distinctive-secret", API)
    assert b"very-distinctive-secret" not in (tmp_path / STORE_FILE).read_bytes()


def test_secret_repr_is_redacted(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("stats", "very-distinctive-secret", API)
    secret = store.get_for_origin("stats", "https://api.example")
    assert "very-distinctive-secret" not in repr(secret)
    assert "very-distinctive-secret" not in f"{secret}"


def test_binding_refuses_other_origins(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("stats", "v", API)
    for url in ("https://evil.example", "http://api.example", "https://api.example:8443"):
        with pytest.raises(SecretUnavailable, match="not bound to"):
            store.get_for_origin("stats", url)


def test_connector_binding_must_match_exactly(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    binding = smtp_binding("smtp.mail.example", 465, "Agent <a@mail.example>", ["p@mail.example"])
    store.put("mail-pass", "pw", binding)
    assert store.get_for_binding("mail-pass", binding).reveal() == "pw"
    widened = smtp_binding(
        "smtp.mail.example", 465, "Agent <a@mail.example>", ["p@mail.example", "x@evil.example"]
    )
    with pytest.raises(SecretUnavailable, match="constraints changed"):
        store.get_for_binding("mail-pass", widened)
    with pytest.raises(SecretUnavailable, match="not bound to"):
        store.get_for_origin("mail-pass", "https://smtp.mail.example")


def test_recipient_order_and_case_dont_matter() -> None:
    a = smtp_binding("SMTP.mail.example", 465, "f@x", ["B@x.example", "a@x.example"])
    b = smtp_binding("smtp.mail.example", 465, "f@x", ["a@x.example", "b@x.example"])
    assert a == b


def test_missing_secret(tmp_path: Path) -> None:
    with pytest.raises(SecretUnavailable, match="not in the store"):
        new_store(tmp_path).get_for_origin("absent", "https://api.example")


def test_tampered_ciphertext_fails(tmp_path: Path) -> None:
    new_store(tmp_path).put("stats", "v", API)
    data = raw_file(tmp_path)
    ct = bytearray(data["entries"]["stats"]["ciphertext"].encode())
    ct[5] = ord("A") if ct[5] != ord("A") else ord("B")
    data["entries"]["stats"]["ciphertext"] = ct.decode()
    write_raw(tmp_path, data)
    with pytest.raises(SecretUnavailable, match="failed authentication"):
        new_store(tmp_path).get_for_origin("stats", "https://api.example")


def test_ciphertext_moved_to_another_name_fails(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("stats", "stats-value", API)
    store.put("other", "other-value", API)
    data = raw_file(tmp_path)
    data["entries"]["other"] = dict(data["entries"]["stats"])
    write_raw(tmp_path, data)
    with pytest.raises(SecretUnavailable, match="failed authentication"):
        new_store(tmp_path).get_for_origin("other", "https://api.example")


def test_widening_the_binding_on_disk_fails(tmp_path: Path) -> None:
    new_store(tmp_path).put("stats", "v", API)
    data = raw_file(tmp_path)
    data["entries"]["stats"]["binding"] = origin_binding(
        ["https://api.example", "https://evil.example"]
    )
    write_raw(tmp_path, data)
    with pytest.raises(SecretUnavailable, match="failed authentication"):
        new_store(tmp_path).get_for_origin("stats", "https://evil.example")


def test_wrong_master_key_refuses_to_start(tmp_path: Path) -> None:
    new_store(tmp_path).put("stats", "v", API)
    with pytest.raises(StoreError, match="ZOEYMCP_MASTER_KEY_PREVIOUS"):
        SecretStore(tmp_path, OTHER_KEYS).load()


def test_master_key_rotation(tmp_path: Path) -> None:
    old = new_store(tmp_path)
    old.put("stats", "v1", API)
    old.put("other", "v2", API)
    rotated = SecretStore(tmp_path, OTHER_KEYS, previous=KEYS)
    assert rotated.load() == 2
    assert {e["kid"] for e in raw_file(tmp_path)["entries"].values()} == {OTHER_KEYS.key_id}
    assert (
        new_store(tmp_path, OTHER_KEYS).get_for_origin("stats", "https://api.example").reveal()
        == "v1"
    )
    with pytest.raises(StoreError):
        SecretStore(tmp_path, KEYS).load()


def test_metadata_and_delete(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("stats", "v", API)
    [meta] = store.metadata()
    assert meta.name == "stats"
    assert meta.binding == {"origins": ["https://api.example:443"]}
    assert meta.key_id == KEYS.key_id
    assert set(meta.as_dict()) == {"name", "binding", "key_id", "created", "updated"}
    assert store.delete("stats") is True
    assert store.delete("stats") is False
    assert new_store(tmp_path).names() == []


def test_replace_keeps_created_time(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("stats", "v1", API)
    created = store.metadata()[0].created
    store.put("stats", "v2", API)
    assert store.metadata()[0].created == created
    assert store.get_for_origin("stats", "https://api.example").reveal() == "v2"


@pytest.mark.parametrize(
    ("value", "binding", "message"),
    [("", API, "can't be empty"), ("x" * 70000, API, "larger than"), ("v", {}, "needs a binding")],
    ids=["empty", "too-large", "no-binding"],
)
def test_put_validation(tmp_path: Path, value: str, binding: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        new_store(tmp_path).put("stats", value, binding)


def test_corrupt_files_refuse_to_load(tmp_path: Path) -> None:
    (tmp_path / STORE_FILE).write_text("not json", encoding="utf-8")
    with pytest.raises(StoreError, match="can't read"):
        SecretStore(tmp_path, KEYS).load()
    write_raw(tmp_path, {"format": 99, "entries": {}})
    with pytest.raises(StoreError, match="format-1"):
        SecretStore(tmp_path, KEYS).load()


def test_no_temporary_files_left(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    for i in range(5):
        store.put(f"s{i}", "v", API)
    assert sorted(p.name for p in tmp_path.iterdir()) == [STORE_FILE]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_store_file_is_private(tmp_path: Path) -> None:
    new_store(tmp_path).put("stats", "v", API)
    mode = stat.S_IMODE(os.stat(tmp_path / STORE_FILE).st_mode)
    assert mode == 0o600
