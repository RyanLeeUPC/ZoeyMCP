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
    StoreWriteError,
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


BRIDGE = "unix:/run/zoeymcp-bridge-fetch/mcp.sock"


def test_a_bridges_socket_is_its_own_origin() -> None:
    """M7 design A.2: a unix: upstream is its own origin, as written; any other unix: form, or
    one no route could hold, isn't an origin at all."""
    assert canonical_origin(BRIDGE) == BRIDGE
    assert origin_binding([BRIDGE, "https://api.example"]) == {
        "origins": ["https://api.example:443", BRIDGE]
    }
    for url in (
        "unix:/run/zoeymcp-bridge-Fetch/mcp.sock",
        "unix:/run/zoeymcp-link/vault.sock",
        "unix:/run/zoeymcp-bridge-fetch/mcp.sock/mcp",
    ):
        with pytest.raises(ValueError, match="a unix: upstream is a standard-tier bridge's socket"):
            canonical_origin(url)


def test_a_secret_bound_to_a_socket_goes_only_to_that_socket(tmp_path: Path) -> None:
    """A bridge's token, stored by secret set --generate under its route's binding, is injected
    only on a route to that socket: not another bridge's, nor any URL."""
    store = new_store(tmp_path)
    store.put("bridge-fetch-token", "token-value", origin_binding([BRIDGE]))
    assert store.get_for_origin("bridge-fetch-token", BRIDGE).reveal() == "token-value"
    for other in (
        "unix:/run/zoeymcp-bridge-files/mcp.sock",
        "http://bridge-fetch-mcp:9000",
        "http://localhost",
    ):
        with pytest.raises(SecretUnavailable):
            store.get_for_origin("bridge-fetch-token", other)


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
    assert set(meta.as_dict()) == {"name", "binding", "key_id", "created", "updated", "meta"}
    assert meta.as_dict()["meta"] is None
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


# --- OAuth entries: get_for_oauth, clear meta, and the write-failure contract -------------------

TOKEN_URL = "https://accounts.example/oauth/token"


def oauth_binding() -> dict[str, Any]:
    """A fresh OAuth binding for each use, so no test can change another's."""
    return {
        "oauth": {
            "token": "https://accounts.example:443",
            "resources": ["https://api.example:443", "https://files.example:443"],
        }
    }


def oauth_meta() -> dict[str, Any]:
    return {"oauth": {"credential": "music", "source": "login", "rotations": 0, "last_error": None}}


class _FailingWrites:
    """Makes the store's atomic rename fail while ``failing`` is set."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.failing = False
        real = os.replace

        def replace(src: str, dst: str | Path) -> None:
            if self.failing:
                raise OSError(28, "No space left on device")
            real(src, dst)

        monkeypatch.setattr("zoeymcp.vault.store.os.replace", replace)


@pytest.fixture
def writes(monkeypatch: pytest.MonkeyPatch) -> _FailingWrites:
    return _FailingWrites(monkeypatch)


def test_get_for_oauth_checks_the_token_origin(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    value, binding = store.get_for_oauth("music-refresh", token_url=TOKEN_URL)
    assert value.reveal() == "rt-1"
    assert binding == oauth_binding()
    # Another path on the same origin is the same token endpoint.
    other_path, _ = store.get_for_oauth("music-refresh", token_url="https://ACCOUNTS.example:443/x")
    assert other_path.reveal() == "rt-1"
    for url in (
        "https://evil.example/oauth/token",
        "http://accounts.example/oauth/token",
        "https://accounts.example:8443/oauth/token",
        "https://api.example/oauth/token",
    ):
        origin = canonical_origin(url)
        with pytest.raises(SecretUnavailable) as caught:
            store.get_for_oauth("music-refresh", token_url=url)
        assert caught.value.reason == (
            f"not bound to token endpoint {origin}; enter it again to authorize it"
        )


def test_get_for_oauth_checks_the_resource_origin(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    for url in ("https://api.example/v1/x", "https://files.example"):
        value, _ = store.get_for_oauth("music-refresh", token_url=TOKEN_URL, resource_url=url)
        assert value.reveal() == "rt-1"
    for url in ("https://evil.example", "https://accounts.example", "http://api.example"):
        origin = canonical_origin(url)
        with pytest.raises(SecretUnavailable) as caught:
            store.get_for_oauth("music-refresh", token_url=TOKEN_URL, resource_url=url)
        assert caught.value.reason == f"not bound to {origin}; run login again to authorize it"


def test_get_for_oauth_checks_the_token_origin_first(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    with pytest.raises(SecretUnavailable) as caught:
        store.get_for_oauth(
            "music-refresh", token_url="https://evil.example/t", resource_url="https://evil.example"
        )
    assert caught.value.reason == (
        "not bound to token endpoint https://evil.example:443; enter it again to authorize it"
    )


@pytest.mark.parametrize(
    "binding",
    [
        {"oauth": {"token": "https://accounts.example:443"}},
        {"oauth": {"token": "https://accounts.example:443", "resources": None}},
        # A string would pass a substring test; only a list of origins counts.
        {
            "oauth": {
                "token": "https://accounts.example:443",
                "resources": "https://api.example:443",
            }
        },
    ],
    ids=["no-resources", "null-resources", "string-resources"],
)
def test_get_for_oauth_needs_a_list_of_resources(tmp_path: Path, binding: dict[str, Any]) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", binding)
    assert store.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-1"
    with pytest.raises(SecretUnavailable, match="run login again"):
        store.get_for_oauth(
            "music-refresh", token_url=TOKEN_URL, resource_url="https://api.example"
        )


@pytest.mark.parametrize(
    "binding",
    [
        origin_binding(["https://accounts.example"]),
        {"oauth": "https://accounts.example:443"},
        {"oauth": {"resources": ["https://api.example:443"]}},
    ],
    ids=["origins", "not-a-mapping", "no-token"],
)
def test_get_for_oauth_refuses_other_shapes(tmp_path: Path, binding: dict[str, Any]) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", binding)
    with pytest.raises(SecretUnavailable, match="not bound to token endpoint"):
        store.get_for_oauth("music-refresh", token_url=TOKEN_URL)


def test_get_for_origin_refuses_an_oauth_entry(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    for url in ("https://api.example", "https://accounts.example"):
        with pytest.raises(SecretUnavailable, match="not bound to"):
            store.get_for_origin("music-refresh", url)


def _assert_binding_unchanged(store: SecretStore) -> None:
    """The entry still has its own binding: refused for evil.example, decrypts for api.example."""
    with pytest.raises(SecretUnavailable) as caught:
        store.get_for_oauth(
            "music-refresh", token_url=TOKEN_URL, resource_url="https://evil.example"
        )
    assert caught.value.reason == (
        "not bound to https://evil.example:443; run login again to authorize it"
    )
    value, binding = store.get_for_oauth(
        "music-refresh", token_url=TOKEN_URL, resource_url="https://api.example"
    )
    assert value.reveal() == "rt-1"
    assert binding == oauth_binding()
    entry = store.entry("music-refresh")
    assert entry is not None
    assert entry.binding == oauth_binding()


def test_get_for_oauth_returns_a_copy_of_the_binding(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    _, binding = store.get_for_oauth("music-refresh", token_url=TOKEN_URL)
    binding["oauth"]["resources"].append("https://evil.example:443")
    _assert_binding_unchanged(store)


def test_put_copies_the_binding(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    given = oauth_binding()
    store.put("music-refresh", "rt-1", given)
    given["oauth"]["resources"].append("https://evil.example:443")
    given["oauth"]["token"] = "https://evil.example:443"
    _assert_binding_unchanged(store)


def test_entry_and_metadata_copy_the_binding(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    entry = store.entry("music-refresh")
    assert entry is not None
    entry.binding["oauth"]["resources"].append("https://evil.example:443")
    _assert_binding_unchanged(store)
    [listed] = store.metadata()
    listed.binding["oauth"]["resources"].append("https://evil.example:443")
    _assert_binding_unchanged(store)


def test_get_for_oauth_missing_and_tampered(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    with pytest.raises(SecretUnavailable, match="not in the store"):
        store.get_for_oauth("absent", token_url=TOKEN_URL)
    store.put("music-refresh", "rt-1", oauth_binding())
    data = raw_file(tmp_path)
    data["entries"]["music-refresh"]["binding"]["oauth"]["resources"].append(
        "https://evil.example:443"
    )
    write_raw(tmp_path, data)
    with pytest.raises(SecretUnavailable, match="failed authentication"):
        new_store(tmp_path).get_for_oauth(
            "music-refresh", token_url=TOKEN_URL, resource_url="https://evil.example"
        )


def test_entry(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    assert store.entry("music-refresh") is None
    store.put("music-refresh", "rt-1", oauth_binding(), meta=oauth_meta())
    store.put("plain", "v", API)
    entry = store.entry("music-refresh")
    assert entry is not None
    assert entry.name == "music-refresh"
    assert entry.binding == oauth_binding()
    assert entry.key_id == KEYS.key_id
    assert entry.meta == oauth_meta()
    assert entry.as_dict()["meta"] == oauth_meta()
    plain = store.entry("plain")
    assert plain is not None
    assert plain.meta is None
    assert [m.meta for m in store.metadata()] == [oauth_meta(), None]


def test_meta_round_trips_through_the_file(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding(), meta=oauth_meta())
    assert raw_file(tmp_path)["entries"]["music-refresh"]["meta"] == oauth_meta()
    reopened = new_store(tmp_path)
    entry = reopened.entry("music-refresh")
    assert entry is not None
    assert entry.meta == oauth_meta()
    assert reopened.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-1"


def test_put_meta_keep_replace_and_remove(tmp_path: Path) -> None:
    store = new_store(tmp_path)

    def meta() -> dict[str, Any] | None:
        entry = store.entry("music-refresh")
        assert entry is not None
        return entry.meta

    store.put("music-refresh", "rt-1", oauth_binding())  # KEEP on a new entry: no meta
    assert meta() is None
    assert "meta" not in raw_file(tmp_path)["entries"]["music-refresh"]
    store.put("music-refresh", "rt-2", oauth_binding())  # KEEP on an entry without meta
    assert meta() is None
    store.put("music-refresh", "rt-3", oauth_binding(), meta=oauth_meta())
    assert meta() == oauth_meta()
    store.put("music-refresh", "rt-4", oauth_binding())  # KEEP keeps it
    assert meta() == oauth_meta()
    assert raw_file(tmp_path)["entries"]["music-refresh"]["meta"] == oauth_meta()
    other = {"oauth": {"credential": "music", "source": "rotation", "rotations": 1}}
    store.put("music-refresh", "rt-5", oauth_binding(), meta=other)
    assert meta() == other
    store.put("music-refresh", "rt-6", oauth_binding(), meta=None)
    assert meta() is None
    assert "meta" not in raw_file(tmp_path)["entries"]["music-refresh"]
    assert store.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-6"


def test_update_meta(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = new_store(tmp_path)
    assert store.update_meta("absent", oauth_meta()) is False
    assert not (tmp_path / STORE_FILE).exists()
    store.put("music-refresh", "rt-1", oauth_binding())
    before = raw_file(tmp_path)["entries"]["music-refresh"]
    # A later clock, so a changed time can't hide behind the same second.
    monkeypatch.setattr("zoeymcp.vault.store._now", lambda: "2030-01-01T00:00:00Z")
    assert store.update_meta("music-refresh", oauth_meta()) is True
    after = raw_file(tmp_path)["entries"]["music-refresh"]
    assert after["meta"] == oauth_meta()
    # No re-encryption: the ciphertext, nonce and times are unchanged.
    assert {k: v for k, v in after.items() if k != "meta"} == before
    assert store.update_meta("music-refresh", None) is True
    assert raw_file(tmp_path)["entries"]["music-refresh"] == before
    assert store.update_meta("music-refresh", None) is True
    reopened = new_store(tmp_path)
    assert reopened.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-1"


def test_meta_is_copied_in_and_out(tmp_path: Path) -> None:
    store = new_store(tmp_path)
    given: dict[str, Any] = {"oauth": {"rotations": 1}}
    store.put("music-refresh", "rt-1", oauth_binding(), meta=given)
    given["oauth"]["rotations"] = 99
    entry = store.entry("music-refresh")
    assert entry is not None
    assert entry.meta == {"oauth": {"rotations": 1}}
    entry.meta["oauth"]["rotations"] = 42
    [listed] = store.metadata()
    assert listed.meta == {"oauth": {"rotations": 1}}
    listed.meta["oauth"]["rotations"] = 43
    store.update_meta("music-refresh", given)
    given["oauth"]["rotations"] = 7
    again = store.entry("music-refresh")
    assert again is not None
    assert again.meta == {"oauth": {"rotations": 99}}


@pytest.mark.parametrize(
    "meta",
    [{"x": object()}, {"x": float("nan")}, {"x": float("inf")}],
    ids=["object", "nan", "inf"],
)
def test_meta_must_be_plain_json(tmp_path: Path, meta: dict[str, Any]) -> None:
    store = new_store(tmp_path)
    with pytest.raises(ValueError, match=r"^meta must be plain JSON: "):
        store.put("music-refresh", "rt-1", oauth_binding(), meta=meta)
    assert store.entry("music-refresh") is None
    store.put("music-refresh", "rt-1", oauth_binding())
    with pytest.raises(ValueError, match=r"^meta must be plain JSON: "):
        store.update_meta("music-refresh", meta)
    entry = store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is None


def test_tampered_meta_changes_no_decision(tmp_path: Path) -> None:
    new_store(tmp_path).put("music-refresh", "rt-1", oauth_binding(), meta=oauth_meta())
    new_store(tmp_path).put("stats", "v", API)
    for meta in (
        {"oauth": {"source": "operator", "last_error": {"code": "oauth_reconsent_needed"}}},
        {"oauth": {"resources": ["https://evil.example:443"]}},
        "not a mapping",
        None,
    ):
        data = raw_file(tmp_path)
        data["entries"]["music-refresh"]["meta"] = meta
        data["entries"]["stats"]["meta"] = meta
        write_raw(tmp_path, data)
        store = new_store(tmp_path)
        value, binding = store.get_for_oauth(
            "music-refresh", token_url=TOKEN_URL, resource_url="https://api.example"
        )
        assert value.reveal() == "rt-1"
        assert binding == oauth_binding()
        with pytest.raises(SecretUnavailable):
            store.get_for_oauth(
                "music-refresh", token_url=TOKEN_URL, resource_url="https://evil.example"
            )
        assert store.get_for_origin("stats", "https://api.example").reveal() == "v"
        entry = store.entry("music-refresh")
        assert entry is not None
        assert entry.meta == (meta if isinstance(meta, dict) else None)


def test_meta_survives_master_key_rotation(tmp_path: Path) -> None:
    old = new_store(tmp_path)
    old.put("music-refresh", "rt-1", oauth_binding(), meta=oauth_meta())
    old.put("stats", "v", API)
    rotated = SecretStore(tmp_path, OTHER_KEYS, previous=KEYS)
    assert rotated.load() == 2
    entries = raw_file(tmp_path)["entries"]
    assert entries["music-refresh"]["meta"] == oauth_meta()
    assert "meta" not in entries["stats"]
    entry = new_store(tmp_path, OTHER_KEYS).entry("music-refresh")
    assert entry is not None
    assert entry.meta == oauth_meta()
    assert entry.key_id == OTHER_KEYS.key_id


def test_a_failed_put_keeps_the_new_value_in_memory(tmp_path: Path, writes: _FailingWrites) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    assert store.dirty is False
    writes.failing = True
    with pytest.raises(StoreWriteError) as caught:
        store.put("music-refresh", "rt-2", oauth_binding(), meta=oauth_meta())
    assert str(caught.value) == (
        f"can't write {tmp_path / STORE_FILE}: [Errno 28] No space left on device"
    )
    assert isinstance(caught.value, OSError)
    assert isinstance(caught.value.__cause__, OSError)
    assert store.dirty is True
    assert store.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-2"
    entry = store.entry("music-refresh")
    assert entry is not None
    assert entry.meta == oauth_meta()
    # The file still has the old value, and no temporary file is left behind.
    on_disk = new_store(tmp_path)
    assert on_disk.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-1"
    assert sorted(p.name for p in tmp_path.iterdir()) == [STORE_FILE]

    with pytest.raises(StoreWriteError):
        store.flush()
    assert store.dirty is True
    writes.failing = False
    store.flush()
    assert store.dirty is False
    reopened = new_store(tmp_path)
    assert reopened.get_for_oauth("music-refresh", token_url=TOKEN_URL)[0].reveal() == "rt-2"
    reopened_entry = reopened.entry("music-refresh")
    assert reopened_entry is not None
    assert reopened_entry.meta == oauth_meta()


def test_the_next_successful_write_saves_everything(tmp_path: Path, writes: _FailingWrites) -> None:
    store = new_store(tmp_path)
    writes.failing = True
    with pytest.raises(StoreWriteError):
        store.put("first", "v1", API)
    assert store.dirty is True
    writes.failing = False
    store.put("second", "v2", API)
    assert store.dirty is False
    assert new_store(tmp_path).names() == ["first", "second"]


def test_delete_and_update_meta_follow_the_contract(tmp_path: Path, writes: _FailingWrites) -> None:
    store = new_store(tmp_path)
    store.put("music-refresh", "rt-1", oauth_binding())
    store.put("stats", "v", API)
    writes.failing = True
    with pytest.raises(StoreWriteError):
        store.delete("stats")
    assert store.dirty is True
    assert store.names() == ["music-refresh"]
    with pytest.raises(StoreWriteError):
        store.update_meta("music-refresh", oauth_meta())
    entry = store.entry("music-refresh")
    assert entry is not None
    assert entry.meta == oauth_meta()
    assert new_store(tmp_path).names() == ["music-refresh", "stats"]
    # Nothing changes for an absent name, so nothing is written.
    assert store.delete("absent") is False
    assert store.update_meta("absent", oauth_meta()) is False
    writes.failing = False
    store.flush()
    assert store.dirty is False
    reopened = new_store(tmp_path)
    assert reopened.names() == ["music-refresh"]
    reopened_entry = reopened.entry("music-refresh")
    assert reopened_entry is not None
    assert reopened_entry.meta == oauth_meta()


def test_flush_does_nothing_when_clean(tmp_path: Path, writes: _FailingWrites) -> None:
    assert SecretStore(tmp_path, KEYS).dirty is False
    store = new_store(tmp_path)
    assert store.dirty is False
    writes.failing = True
    store.flush()
    writes.failing = False
    assert not (tmp_path / STORE_FILE).exists()
    store.put("stats", "v", API)
    writes.failing = True
    store.flush()
    assert store.dirty is False


def test_a_failed_rotation_write_refuses_to_load(tmp_path: Path, writes: _FailingWrites) -> None:
    new_store(tmp_path).put("stats", "v", API)
    writes.failing = True
    rotated = SecretStore(tmp_path, OTHER_KEYS, previous=KEYS)
    with pytest.raises(StoreError) as caught:
        rotated.load()
    assert str(caught.value) == (
        f"can't save the re-encrypted store: can't write {tmp_path / STORE_FILE}: "
        "[Errno 28] No space left on device"
    )
    assert isinstance(caught.value.__cause__, StoreWriteError)
