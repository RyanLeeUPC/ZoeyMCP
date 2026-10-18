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

from mcp.types import Tool

from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.view import build_view, dump_view, parse_view
from zoeymcp.gateway.pins import PIN_TAG, project, project_and_pin
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


# --- the gateway view (M3 design D.1) ------------------------------------------------------------

# The gateway compares digests across vault restarts and upgrades (ETag, If-None-Match), and a
# gateway parses what its vault serves: the bytes and the digest are part of the link protocol.
VIEW_POLICY = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "127.0.0.1:8081", "hosts": ["localhost"]},
    "credentials": {
        "notes-key": {
            "kind": "header",
            "header": "X-API-Key",
            "format": "{secret}",
            "secret": "store:notes-key",
        }
    },
    "routes": [
        {
            "name": "notes-mcp",
            "prefix": "/notes",
            "upstream": "https://mcp.notes.example",
            "credential": "notes-key",
            "callers": ["gateway"],
            "stream": True,
            "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
        }
    ],
    "gateway": {
        "hosts": ["localhost", "127.0.0.1", "gateway", "zoeymcp.lan.example"],
        "clients": {"agent1": {"token_sha256": "sha256:" + "1" * 64, "servers": ["notes-read"]}},
        "servers": {
            "notes-read": {
                "kind": "remote",
                "route": "notes-mcp",
                "path": "/mcp",
                "era": "modern",
                "tools": {"include": ["search_notes"], "allow": ["search_notes"]},
                "review": {"search_notes": "sha256:" + "0" * 64},
                "wrap_results": True,
            },
            "mail": {"kind": "toolkit", "module": "zoeymcp.toolkits.mail"},
        },
    },
}
VIEW_DIGEST = "sha256:5e83cfb6487f79f6d92f89d4b3f9305dcd20f9934a819389811ad10a32345661"
VIEW_BYTES = (
    b'{"digest":"' + VIEW_DIGEST.encode() + b'","gateway":{"approvals":{"approver":"elicitation",'
    b'"budget_chars":3000,"timeout":300},"clients":{"agent1":{"servers":["notes-read"],'
    b'"sources":[],"token_sha256":"sha256:' + b"1" * 64 + b'"}},'
    b'"hosts":["localhost","127.0.0.1","gateway","zoeymcp.lan.example"],'
    b'"limits":{"call_timeout":300,"list_timeout":30,"max_argument_bytes":262144,'
    b'"max_concurrent_per_client":8,"max_list_bytes":4194304,"max_list_pages":32,'
    b'"max_request_bytes":1048576,"max_result_bytes":4194304,"max_schema_bytes":65536,'
    b'"max_schema_depth":32,"max_sessions_per_client":16,"max_streams_per_client":4,'
    b'"max_subschemas":512,"max_tools_per_server":512,"max_upstream_message_bytes":8388608,'
    b'"max_upstream_sessions":64,"policy_max_stale":300,"session_idle_timeout":1800,'
    b'"upstream_idle_timeout":600},"origins":[],"servers":{"mail":{"kind":"toolkit"},'
    b'"notes-read":{"call_timeout":null,"drift_check_interval":300,"enable":[],"era":"modern",'
    b'"kind":"remote","on_drift":"hide","review":{"search_notes":"sha256:' + b"0" * 64 + b'"},'
    b'"shared_session":false,"tools":{"allow":["search_notes"],"approve":[],'
    b'"include":["search_notes"]},"vault_path":"/notes/mcp","wrap_results":true}}},"v":1}'
)


def test_the_gateway_view_is_pinned() -> None:
    view = build_view(Policy.model_validate(VIEW_POLICY))
    assert view.digest == VIEW_DIGEST
    assert dump_view(view) == VIEW_BYTES


def test_the_pinned_view_still_parses() -> None:
    assert parse_view(VIEW_BYTES).digest == VIEW_DIGEST


# --- tool pins (M3 design G.1) ------------------------------------------------------------------
# Fixed wire JSON, parsed by the pinned SDK, to fixed pins. An SDK bump that changes parsing, or a
# change to the projection or the canonical form, fails here instead of showing as drift on every
# deployment's reviewed tools.

TOOL_PIN_VECTORS = {
    "minimal": (
        r'{"name":"ping","inputSchema":{"type":"object"}}',
        "sha256:926ff10c8c7e1652ed0f10860613cc3f5d36731c0668c2d458e75296a9f21237",
    ),
    "extras_and_nulls": (
        r'{"name":"get_note","title":null,"description":"Returns one note.","inputSchema":'
        r'{"type":"object","properties":{"id":{"type":"string","description":null}},'
        r'"required":["id"]},"outputSchema":null,"annotations":{"title":null,'
        r'"readOnlyHint":true,"destructiveHint":null,"audience":["user"]},"icons":[{"src":'
        r'"https://tracker.example/p.png"}],"_meta":{"k":"v"},"execution":{"taskSupport":'
        r'"optional"},"x-unknown":1}',
        "sha256:1a2ae403b438ff6d591886b7d9d450a624cca485a55868a70b8c65a0ccfc1277",
    ),
    "unicode_floats_header": (
        r'{"name":"shapes","title":"Caf\u00e9 \u65e5\u672c","description":"na\u00efve '
        r'\ud83d\ude00","inputSchema":{"type":"object","properties":{"region":{"type":'
        r'"string","x-mcp-header":"Region"},"ratio":{"type":"number","minimum":0.0,'
        r'"maximum":1.5,"multipleOf":0.25},"big":{"type":"integer","maximum":'
        r'9007199254740991,"minimum":-1e2},"label":{"enum":["caf\u00e9",null,1,1.0]}},'
        r'"additionalProperties":false},"outputSchema":{"type":"object","properties":{"v":'
        r'{"default":null,"exclusiveMinimum":1E-7}}},"annotations":{"title":"Shapes",'
        r'"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,'
        r'"openWorldHint":true}}',
        "sha256:e28b97292666aaebf9cd5f6f144fbd13211fa383530a63d09b4a28209da3859d",
    ),
}


def test_tool_pins_are_pinned() -> None:
    for name, (wire, pin) in TOOL_PIN_VECTORS.items():
        assert project_and_pin(Tool.model_validate_json(wire)).pin == pin, name


def test_the_tagged_pin_encoding_is_pinned() -> None:
    wire, pin = TOOL_PIN_VECTORS["minimal"]
    tagged = {"zoeymcp": PIN_TAG, "tool": project(Tool.model_validate_json(wire))}
    encoded = dumps_canonical(tagged)
    assert encoded == (
        b'{"tool":{"inputSchema":{"type":"object"},"name":"ping"},"zoeymcp":"tool-pin/1"}'
    )
    assert "sha256:" + hashlib.sha256(encoded).hexdigest() == pin
