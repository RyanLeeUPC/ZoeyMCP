"""Pinned formats: a change here breaks every existing deployment, so it must be deliberate.

The golden store was written by the store code with a fixed master key. If these tests fail,
the on-disk store format, the key derivation or the authenticated data changed, and existing
stores would no longer decrypt.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth.protocol import encode_envelope, parse_envelope
from zoeymcp.vault.store import SecretStore, _aad, smtp_binding

GOLDEN = Path(__file__).parent / "data" / "golden-store"
MASTER = bytes(range(100, 132))


def test_key_derivation_is_pinned() -> None:
    keys = KeySet.from_master(MASTER)
    assert keys.key_id == "94229fc20fd18d94"
    assert keys.gateway_key(1) == "zgw1-FS0e74ioM9Z0FkwBv2vf7079tRI1XO84IhfzKt4rlYw"


def test_authenticated_data_is_pinned() -> None:
    aad = _aad("0123456789abcdef", "api-key", {"origins": ["https://api.example:443"]})
    assert aad == (
        b'{"binding":{"origins":["https://api.example:443"]},"format":1,'
        b'"kid":"0123456789abcdef","name":"api-key"}'
    )


def test_the_golden_store_still_decrypts(tmp_path: Path) -> None:
    shutil.copy(GOLDEN / "store.json", tmp_path / "store.json")
    store = SecretStore(tmp_path, KeySet.from_master(MASTER))
    assert store.load() == 0
    assert store.get_for_origin("api-key", "https://api.example/x").reveal() == (
        "golden-api-value-1"
    )
    binding = smtp_binding("smtp.mail.example", 465, "A <a@mail.example>", ["p@mail.example"])
    assert store.get_for_binding("mail-pass", binding).reveal() == "golden-mail-value-2"


# --- OAuth bindings, the live-slot envelope and clear meta (golden-store-m2) -------------------

GOLDEN_M2 = Path(__file__).parent / "data" / "golden-store-m2"
TOKEN_URL = "https://accounts.example/oauth/token"
SEED_SHA256 = "d452b14c214082140c7ff04aeccb8f04b5e94afda0c18a024c4740771bec137c"
CALENDAR_META = {
    "oauth": {
        "consented_at": "2026-10-17T09:00:00Z",
        "credential": "calendar",
        "granted_scope": "calendar.readonly",
        "last_error": None,
        "last_ok": "2026-10-17T09:30:00Z",
        "refresh_expires_at": None,
        "rotations": 2,
        "source": "login",
    }
}
MUSIC_META = {
    "oauth": {
        "consented_at": None,
        "credential": "music",
        "granted_scope": "user-read-currently-playing",
        "last_error": {
            "at": "2026-10-17T09:45:00Z",
            "code": "oauth_reconsent_needed",
            "error": "invalid_grant",
        },
        "last_ok": None,
        "refresh_expires_at": None,
        "rotations": 0,
        "source": "seed",
    }
}


def _golden_m2(tmp_path: Path) -> Path:
    shutil.copy(GOLDEN_M2 / "store.json", tmp_path / "store.json")
    return tmp_path


def test_oauth_authenticated_data_is_pinned() -> None:
    binding = {
        "oauth": {"token": "https://accounts.example:443", "resources": ["https://api.example:443"]}
    }
    assert _aad("0123456789abcdef", "oauth.music.live", binding) == (
        b'{"binding":{"oauth":{"resources":["https://api.example:443"],'
        b'"token":"https://accounts.example:443"}},"format":1,'
        b'"kid":"0123456789abcdef","name":"oauth.music.live"}'
    )


def test_the_m2_golden_store_still_decrypts(tmp_path: Path) -> None:
    store = SecretStore(_golden_m2(tmp_path), KeySet.from_master(MASTER))
    assert store.load() == 0
    value, binding = store.get_for_oauth(
        "calendar-refresh", token_url=TOKEN_URL, resource_url="https://calendar.example/v3"
    )
    assert value.reveal() == "golden-refresh-value-3"
    assert binding == {
        "oauth": {
            "resources": ["https://calendar.example:443"],
            "token": "https://accounts.example:443",
        }
    }
    secret, _ = store.get_for_oauth("music-client-secret", token_url=TOKEN_URL)
    assert secret.reveal() == "golden-client-value-6"
    calendar = store.entry("calendar-refresh")
    music = store.entry("oauth.music.live")
    client = store.entry("music-client-secret")
    assert calendar is not None
    assert calendar.meta == CALENDAR_META
    assert music is not None
    assert music.meta == MUSIC_META
    assert client is not None
    assert client.meta is None


def test_the_live_slot_envelope_is_pinned(tmp_path: Path) -> None:
    store = SecretStore(_golden_m2(tmp_path), KeySet.from_master(MASTER))
    store.load()
    value, _ = store.get_for_oauth(
        "oauth.music.live", token_url=TOKEN_URL, resource_url="https://music.example"
    )
    text = value.reveal()
    assert text == ('{"rt":"golden-live-value-4","seed_sha256":"' + SEED_SHA256 + '","v":1}')
    envelope = parse_envelope(value)
    assert envelope.rt.reveal() == "golden-live-value-4"
    assert envelope.seed_sha256 == SEED_SHA256
    assert encode_envelope(envelope.rt, SEED_SHA256).reveal() == text
    assert hashlib.sha256(b"golden-seed-value-5").hexdigest() == SEED_SHA256


def test_meta_survives_a_load_with_the_previous_key(tmp_path: Path) -> None:
    new_keys = KeySet.from_master(bytes(range(132, 164)))
    store = SecretStore(_golden_m2(tmp_path), new_keys, KeySet.from_master(MASTER))
    assert store.load() == 3
    raw = json.loads((tmp_path / "store.json").read_text(encoding="utf-8"))["entries"]
    assert {e["kid"] for e in raw.values()} == {new_keys.key_id}
    assert raw["calendar-refresh"]["meta"] == CALENDAR_META
    assert raw["oauth.music.live"]["meta"] == MUSIC_META
    assert "meta" not in raw["music-client-secret"]

    reopened = SecretStore(tmp_path, new_keys)
    assert reopened.load() == 0
    calendar = reopened.entry("calendar-refresh")
    assert calendar is not None
    assert calendar.meta == CALENDAR_META
    value, _ = reopened.get_for_oauth("oauth.music.live", token_url=TOKEN_URL)
    assert parse_envelope(value).seed_sha256 == SEED_SHA256
