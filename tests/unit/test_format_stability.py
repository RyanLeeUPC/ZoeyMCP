"""Pinned formats: a change here breaks every existing deployment, so it must be deliberate.

The golden store was written by the store code with a fixed master key. If these tests fail,
the on-disk store format, the key derivation or the authenticated data changed, and existing
stores would no longer decrypt.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from mcp.types import Tool

from tests.unit.report_model import asked_line
from zoeymcp.common import canonical, ledgerreport, pinhash
from zoeymcp.common.canonical import dumps_canonical, loads_strict
from zoeymcp.common.ledgerformat import GENESIS, line_hash
from zoeymcp.common.policy import Policy, ratchet
from zoeymcp.common.policy.view import build_view, dump_view, parse_view
from zoeymcp.gateway import pins
from zoeymcp.gateway.pins import PIN_TAG, project, project_and_pin
from zoeymcp.portal.passkeys import Passkey, PasskeyFile, fingerprint, seal, unseal
from zoeymcp.vault import policyseal
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth.protocol import encode_envelope, parse_envelope
from zoeymcp.vault.reportstore import ReportStore
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
VIEW_DIGEST = "sha256:406b556163888843ab4c0cabe22395f1175a6993f12dc0ada5045a78e6c37379"
VIEW_BYTES = (
    b'{"digest":"' + VIEW_DIGEST.encode() + b'","gateway":{"approvals":{"approver":"elicitation",'
    b'"budget_chars":3000,"cooldown":15,"max_pending_per_client":1,"max_prompts_per_hour":30,'
    b'"timeout":300},"clients":{"agent1":{"approvals":null,"servers":["notes-read"],'
    b'"sources":[],"token_sha256":"sha256:' + b"1" * 64 + b'"}},'
    b'"hosts":["localhost","127.0.0.1","gateway","zoeymcp.lan.example"],'
    b'"limits":{"call_timeout":300,"ledger_max_bytes":67108864,"list_timeout":30,'
    b'"max_argument_bytes":262144,'
    b'"max_concurrent_per_client":8,"max_list_bytes":4194304,"max_list_pages":32,'
    b'"max_request_bytes":1048576,"max_result_bytes":4194304,"max_schema_bytes":65536,'
    b'"max_schema_depth":32,"max_sessions_per_client":16,"max_streams_per_client":4,'
    b'"max_subschemas":512,"max_tools_per_server":512,"max_upstream_message_bytes":8388608,'
    b'"max_upstream_sessions":64,"policy_max_stale":300,"session_idle_timeout":1800,'
    b'"upstream_idle_timeout":600},"origins":[],"servers":{"mail":{"call_timeout":null,'
    b'"kind":"toolkit","module":"zoeymcp.toolkits.mail","on_drift":"hide","pinning":"required",'
    b'"review":{},"slots":{},"tools":{"allow":[],"approve":[],"include":[]},'
    b'"wrap_results":false},'
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


# M6 design A.3 (CR-7): a server's declined block, which an M7 policy doesn't have, is in the
# digest and the bytes only once it holds a tool, so the view above, an M7 policy's, is unchanged.
VIEW_POLICY_DECLINED: dict[str, Any] = json.loads(json.dumps(VIEW_POLICY))
VIEW_POLICY_DECLINED["gateway"]["servers"]["notes-read"]["declined"] = {
    "delete_note": "sha256:" + "2" * 64
}
VIEW_POLICY_DECLINED["gateway"]["servers"]["mail"]["declined"] = {"send_mail": "sha256:" + "3" * 64}
VIEW_DIGEST_DECLINED = "sha256:0224e86bdbba375baffe849e015be4ef1c309e0f373a6780ef86c972f1ba069c"
VIEW_BYTES_DECLINED = (
    VIEW_BYTES.replace(VIEW_DIGEST.encode(), VIEW_DIGEST_DECLINED.encode())
    .replace(
        b'"mail":{"call_timeout":null,',
        b'"mail":{"call_timeout":null,"declined":{"send_mail":"sha256:' + b"3" * 64 + b'"},',
    )
    .replace(
        b'"notes-read":{"call_timeout":null,',
        b'"notes-read":{"call_timeout":null,"declined":{"delete_note":"sha256:'
        + b"2" * 64
        + b'"},',
    )
)


def test_a_view_with_declined_tools_is_pinned() -> None:
    view = build_view(Policy.model_validate(VIEW_POLICY_DECLINED))
    assert view.digest == VIEW_DIGEST_DECLINED
    assert dump_view(view) == VIEW_BYTES_DECLINED
    assert parse_view(VIEW_BYTES_DECLINED).digest == VIEW_DIGEST_DECLINED


def test_an_empty_declined_block_leaves_the_m7_view() -> None:
    """Declined in the policy but empty: the M7 digest and bytes, which an M7 gateway parses."""
    policy: dict[str, Any] = json.loads(json.dumps(VIEW_POLICY))
    for server in policy["gateway"]["servers"].values():
        server["declined"] = {}
    view = build_view(Policy.model_validate(policy))
    assert (view.digest, dump_view(view)) == (VIEW_DIGEST, VIEW_BYTES)
    assert b"declined" not in VIEW_BYTES


# M6 design A.3, L.3 (step 18): a remote server's prompts and resources blocks are in the digest and
# the bytes only once one holds an entry, so the M7 view above is unchanged; enable always was.
VIEW_POLICY_KINDS: dict[str, Any] = json.loads(json.dumps(VIEW_POLICY))
VIEW_POLICY_KINDS["gateway"]["servers"]["notes-read"].update(
    enable=["prompts", "resources", "completions"],
    prompts={
        "include": ["summarize"],
        "review": {"summarize": "sha256:" + "4" * 64},
        "assistant": ["summarize"],
    },
    resources={
        "templates": {
            "include": ["notes://notes/{id}"],
            "review": {"notes://notes/{id}": "sha256:" + "5" * 64},
        },
        "fixed": {"declined": {"notes://index": "sha256:" + "6" * 64}},
    },
)
VIEW_DIGEST_KINDS = "sha256:1cd951b694cd02d12721e4d665549ac41ddcab6f77df553706b3540ac3026baa"
VIEW_BYTES_KINDS = (
    VIEW_BYTES.replace(VIEW_DIGEST.encode(), VIEW_DIGEST_KINDS.encode())
    .replace(b'"enable":[],', b'"enable":["prompts","resources","completions"],')
    .replace(
        b'"on_drift":"hide","review":{"search_notes"',
        b'"on_drift":"hide","prompts":{"assistant":["summarize"],"declined":{},'
        b'"include":["summarize"],"review":{"summarize":"sha256:' + b"4" * 64 + b'"}},'
        b'"resources":{"fixed":{"declined":{"notes://index":"sha256:' + b"6" * 64 + b'"},'
        b'"include":[],"review":{}},"templates":{"declined":{},"include":["notes://notes/{id}"],'
        b'"review":{"notes://notes/{id}":"sha256:' + b"5" * 64 + b'"}}},'
        b'"review":{"search_notes"',
    )
)


def test_a_view_with_prompts_and_resources_is_pinned() -> None:
    view = build_view(Policy.model_validate(VIEW_POLICY_KINDS))
    assert view.digest == VIEW_DIGEST_KINDS
    assert dump_view(view) == VIEW_BYTES_KINDS
    assert parse_view(VIEW_BYTES_KINDS).digest == VIEW_DIGEST_KINDS


def test_empty_prompts_and_resources_blocks_leave_the_m7_view() -> None:
    """Written but empty, or holding only empty sets: the M7 digest and bytes."""
    policy: dict[str, Any] = json.loads(json.dumps(VIEW_POLICY))
    policy["gateway"]["servers"]["notes-read"].update(
        prompts={"include": [], "review": {}, "declined": {}, "assistant": []},
        resources={"templates": {"include": []}, "fixed": {}},
    )
    view = build_view(Policy.model_validate(policy))
    assert (view.digest, dump_view(view)) == (VIEW_DIGEST, VIEW_BYTES)
    assert b'"prompts"' not in VIEW_BYTES
    assert b'"resources"' not in VIEW_BYTES


def test_one_entry_puts_its_whole_block_in_the_view() -> None:
    """A block is left out only while every set in it is empty: one declined fixed resource
    brings in the resources block, its empty template set too, and not the prompts block."""
    policy: dict[str, Any] = json.loads(json.dumps(VIEW_POLICY))
    policy["gateway"]["servers"]["notes-read"]["resources"] = {
        "fixed": {"declined": {"notes://index": "sha256:" + "6" * 64}}
    }
    served = canonical.loads_strict(dump_view(build_view(Policy.model_validate(policy))))
    server = served["gateway"]["servers"]["notes-read"]
    assert "prompts" not in server
    assert server["resources"] == {
        "fixed": {"declined": {"notes://index": "sha256:" + "6" * 64}, "include": [], "review": {}},
        "templates": {"declined": {}, "include": [], "review": {}},
    }
    assert served["digest"] not in (VIEW_DIGEST, VIEW_DIGEST_KINDS)


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


def test_the_shared_pin_function_gives_the_same_pins() -> None:
    """M7 F.4: the pin moved to common.pinhash, which the vault uses to check reported pins; the
    gateway's names are the same objects, so no pin anywhere changes."""
    assert (pins.pin_of, pins.PIN_TAG, pins.ProjectionError) == (
        pinhash.pin_of,
        pinhash.PIN_TAG,
        pinhash.ProjectionError,
    )
    assert pinhash.PIN_TAG == "tool-pin/1"
    for name, (wire, pin) in TOOL_PIN_VECTORS.items():
        assert pinhash.pin_of(project(Tool.model_validate_json(wire))) == pin, name


# --- prompt, resource-template and resource pins (M6 design L.2) ------------------------------
# The projection is the gateway's (step 19); these are its pins, beside the tool pins above, which
# are unchanged (CR-14). Contract 58 ties the members to the SDK's parsing. Each kind has its own
# tag and its own member, so the same projection pins differently as each kind.

PinOf = Callable[[Mapping[str, Any]], str]
KIND_PIN_VECTORS: dict[str, tuple[PinOf, dict[str, Any], str]] = {
    "prompt_minimal": (
        pinhash.prompt_pin_of,
        {"name": "summarize"},
        "sha256:2d8a96566c39e1297b8534d84369db7d7fd30246046da7a0bdd9a684070df2e5",
    ),
    "prompt_full": (
        pinhash.prompt_pin_of,
        {
            "name": "summarize",
            "title": "Caf\u00e9 \u65e5\u672c",
            "description": "Summarizes a note.\nOne paragraph.",
            "arguments": [
                {"name": "id", "title": "Note", "description": "The note's ID.", "required": True},
                {"name": "style", "required": False},
            ],
        },
        "sha256:3079d8665e90fc526731be9a0f4002a6a8496de0798ae413306be4f879c1bd16",
    ),
    "template_minimal": (
        pinhash.template_pin_of,
        {"uriTemplate": "notes://notes/{id}", "name": "note"},
        "sha256:9364d62caf0887d6bcc231ac1825b17afe79c45f485ef0a16d40379bd282f21f",
    ),
    "template_full": (
        pinhash.template_pin_of,
        {
            "uriTemplate": "notes://notes/{id}",
            "name": "note",
            "title": "A note",
            "description": "One note, by its ID.",
            "mimeType": "text/markdown",
            "annotations": {"audience": ["user", "assistant"], "priority": 0.5},
        },
        "sha256:34090964945ed534b0f3654e067e2ef114c10e428f914e93e2785312ab34a2f5",
    ),
    "resource_minimal": (
        pinhash.resource_pin_of,
        {"uri": "notes://index", "name": "index"},
        "sha256:5a57d6b0aaeeecc6bd4b75ddf51dc6d8f5179de37308b5df6244c41981b13ddd",
    ),
    "resource_full": (
        pinhash.resource_pin_of,
        {
            "uri": "notes://index",
            "name": "index",
            "title": "Index \U0001f5c2",
            "description": "Every note.",
            "mimeType": "application/json",
            # The SDK reads a priority as a float, a wire 1 included (contract 58), and canonical
            # JSON writes 1.0 and 1 apart, so the projection holds 1.0.
            "annotations": {"audience": ["assistant"], "priority": 1.0},
        },
        "sha256:32c6249fa0ebd5275a4d58ba2ef6d78b819cf59b3fea053d27439531116ba211",
    ),
}


def test_prompt_and_resource_pins_are_pinned() -> None:
    for name, (pin_of, projection, pin) in KIND_PIN_VECTORS.items():
        assert pin_of(projection) == pin, name


def test_the_kind_tags_are_pinned() -> None:
    assert (pinhash.PROMPT_PIN_TAG, pinhash.TEMPLATE_PIN_TAG, pinhash.RESOURCE_PIN_TAG) == (
        "prompt-pin/1",
        "resource-template-pin/1",
        "resource-pin/1",
    )
    encodings = {
        "prompt_minimal": b'{"prompt":{"name":"summarize"},"zoeymcp":"prompt-pin/1"}',
        "template_minimal": (
            b'{"resource_template":{"name":"note","uriTemplate":"notes://notes/{id}"},'
            b'"zoeymcp":"resource-template-pin/1"}'
        ),
        "resource_minimal": (
            b'{"resource":{"name":"index","uri":"notes://index"},"zoeymcp":"resource-pin/1"}'
        ),
    }
    for name, encoded in encodings.items():
        assert "sha256:" + hashlib.sha256(encoded).hexdigest() == KIND_PIN_VECTORS[name][2], name


def test_one_projection_pins_differently_as_each_kind() -> None:
    projection = {"name": "summarize"}
    kinds = (
        pinhash.pin_of,
        pinhash.prompt_pin_of,
        pinhash.template_pin_of,
        pinhash.resource_pin_of,
    )
    assert len({pin_of(projection) for pin_of in kinds}) == 4


@pytest.mark.parametrize(
    "pin_of",
    [pinhash.prompt_pin_of, pinhash.template_pin_of, pinhash.resource_pin_of],
    ids=["prompt", "template", "resource"],
)
def test_a_projection_with_no_canonical_form_has_no_pin(pin_of: PinOf) -> None:
    with pytest.raises(pinhash.ProjectionError) as caught:
        pin_of({"name": "n", "n": 2**53})
    assert str(caught.value) == (
        "the definition has no canonical form (an unsafe integer, a lone surrogate or too deep)"
    )
    assert isinstance(caught.value.__cause__, canonical.JSONRejected)


# --- the passkey file (M5 design D.4) ------------------------------------------------------------
# Written by the passkey code under MASTER. If these fail, the format, the MAC or K_portal changed,
# and every deployment's portal would refuse its passkey file as tampered.

GOLDEN_PASSKEYS = Path(__file__).parent / "data" / "golden-passkeys.json"


def _spki(key: ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def golden_passkeys() -> PasskeyFile:
    es256 = ec.derive_private_key(7, ec.SECP256R1()).public_key()
    eddsa = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    return PasskeyFile(
        generation=7,
        user_handle=bytes(range(32, 64)),
        credentials=(
            Passkey(
                id=bytes(range(16)),
                rp_id="localhost",
                alg=-7,
                spki=_spki(es256),
                sign_count=0,
                backup_eligible=True,
                backup_state=True,
                transports=("hybrid", "internal"),
                name="laptop",
                via="setup_code",
                origin="http://localhost:8081",
                created=1760000000,
                last_used=1760054400,
                last_regressed=None,
            ),
            Passkey(
                id=bytes(range(100, 132)),
                rp_id="zoeymcp.lan.example",
                alg=-8,
                spki=_spki(eddsa),
                sign_count=41,
                backup_eligible=False,
                backup_state=False,
                transports=("usb",),
                name="security key \u00e9",
                via="portal",
                origin="https://zoeymcp.lan.example",
                created=1760086400,
                last_used=1760140800,
                last_regressed=1760140800,
            ),
        ),
    )


def test_the_passkey_file_format_is_pinned() -> None:
    key = KeySet.from_master(MASTER).portal_key
    assert seal(golden_passkeys(), key) == GOLDEN_PASSKEYS.read_bytes()


def test_the_golden_passkey_file_still_verifies() -> None:
    key = KeySet.from_master(MASTER).portal_key
    assert unseal(GOLDEN_PASSKEYS.read_bytes(), key) == (golden_passkeys(), False)
    assert fingerprint(key, bytes(range(16))) == "06b228ec0ef3c431"


# --- the reported copy's head.json (M5 design J.4) -----------------------------------------------
# Written by the report store. If these fail, head.json's format changed, and every vault would
# rebuild its copy's head on its next start, losing a sticky refusal and dropped epochs' anchors.

GOLDEN_REPORTED_HEAD = Path(__file__).parent / "data" / "golden-reported-head.json"


def golden_copy(state_dir: Path) -> ReportStore:
    """A copy that took a chain and forked three times, restarted twice, the second restart
    dropping the first epoch."""
    clock = [1_767_276_000_000]
    store = ReportStore.open(
        state_dir, clock=lambda: clock[0], rotate_bytes=2 * 545, archive_max_bytes=4 * 545
    )

    def chain(count: int, tick: int) -> list[bytes]:
        lines: list[bytes] = []
        prev = GENESIS
        for n in range(count):
            lines.append(asked_line(n, prev, tick + n + 1))
            prev = line_hash(lines[-1])
        return lines

    def report(lines: list[bytes]) -> None:
        store.report(loads_strict(ledgerreport.encode(lines)))
        clock[0] += 1000

    report(chain(3, 0))
    report(chain(3, 100)[1:])
    store.restart()
    report(chain(4, 200)[1:])
    report(chain(3, 300)[2:])
    store.restart()
    report(chain(2, 400))
    report(chain(2, 500)[1:])
    return store


def test_the_reported_head_is_pinned(tmp_path: Path) -> None:
    golden_copy(tmp_path)
    written = (tmp_path / "ledger-reported" / "head.json").read_bytes()
    assert written == GOLDEN_REPORTED_HEAD.read_bytes()


def test_the_pinned_reported_head_still_loads(tmp_path: Path) -> None:
    store = golden_copy(tmp_path)
    head = tmp_path / "ledger-reported" / "head.json"
    head.write_bytes(GOLDEN_REPORTED_HEAD.read_bytes())
    again = ReportStore.open(tmp_path)
    assert head.read_bytes() == GOLDEN_REPORTED_HEAD.read_bytes()  # nothing rebuilt
    assert (again.state, again.held, again.refused) == (store.state, store.held, store.refused)
    assert again.archives() == store.archives()


# --- the managed policy's revision, head and anchor (M6 design D.2) -----------------------------
# Written by the seal code under MASTER with a fixed salt and nonce. If these fail, the revision's
# format, its digest, the body's encryption or associated data, a MAC context or K_policy changed,
# and every managed deployment's start would refuse its own store.

GOLDEN_POLICY_REVISION = Path(__file__).parent / "data" / "golden-policy-revision.json"
GOLDEN_POLICY_HEAD = Path(__file__).parent / "data" / "golden-policy-head.json"
GOLDEN_POLICY_ANCHOR = Path(__file__).parent / "data" / "golden-policy-anchor.json"
POLICY_DEPLOYMENT = bytes(range(16)).hex()
# The ratchet after revision 2's re-pin of search_notes, in common.policy.ratchet's plain form
# (Ratchet.as_dict, read back by ratchet.loaded below); the seal itself reads it as an object.
POLICY_RATCHET: dict[str, Any] = {
    "gateway_key_floor": 1,
    "egress_key_floor": 1,
    "retired_pins": [
        {
            "server": "notes-read",
            "kind": "tool",
            "name": "search_notes",
            "pins": ["sha256:" + "9" * 64],
        }
    ],
    "retired_clients": [],
    "retired_callers": [],
    "approved": [],
    "env": {},
}
POLICY_HEADER: dict[str, Any] = {
    "v": 1,
    "deployment": POLICY_DEPLOYMENT,
    "revision": 2,
    "parent": "sha256:" + "1" * 64,
    "created": 1_792_900_000,
    "origin": "save",
    "kind": "tool.repin",
    "author": {"by": "passkey", "fingerprint": "06b228ec0ef3c431"},
    "base": 1,
    "target": None,
    "jumped_from": None,
}
POLICY_DIGEST = "sha256:14891b953b5501855db5975f9e35492ec527b37efec7cf24dbbf6bdb2a1ba8df"
POLICY_BODY_DIGEST = "sha256:e492bd5e50ad4781986f373e1cdd077cc35dfbf7cfce4a5d1b16d130b1808eed"


def golden_policy_body() -> bytes:
    return policyseal.make_body(
        salt=bytes(range(32)),
        policy=VIEW_POLICY,
        ratchet=POLICY_RATCHET,
        seed_digest="sha256:" + "5" * 64,
        reason="golden revision",
    )


def golden_policy_revision() -> bytes:
    body = golden_policy_body()
    header = {**POLICY_HEADER, "body_digest": policyseal.body_digest(body)}
    keys = KeySet.from_master(MASTER)
    return policyseal.seal_revision(header, body, keys=keys, nonce=bytes(range(12)))


def golden_policy_head() -> bytes:
    keys = KeySet.from_master(MASTER)
    head = policyseal.Head(POLICY_DEPLOYMENT, 2, POLICY_DIGEST, 1, None, keys.key_id)
    return policyseal.seal_head(head, keys)


def golden_policy_anchor() -> bytes:
    keys = KeySet.from_master(MASTER)
    anchor = policyseal.Anchor(POLICY_DEPLOYMENT, 2, None, None, keys.key_id)
    return policyseal.seal_anchor(anchor, keys)


def test_the_policy_revision_format_is_pinned() -> None:
    assert golden_policy_revision() == GOLDEN_POLICY_REVISION.read_bytes()
    assert policyseal.body_digest(golden_policy_body()) == POLICY_BODY_DIGEST
    header = {**POLICY_HEADER, "body_digest": POLICY_BODY_DIGEST}
    assert policyseal.revision_digest(header) == POLICY_DIGEST


def test_the_golden_policy_revision_still_unseals() -> None:
    keys = KeySet.from_master(MASTER)
    found = policyseal.unseal_revision(
        GOLDEN_POLICY_REVISION.read_bytes(), keys, None, deployment=POLICY_DEPLOYMENT
    )
    assert found.digest == POLICY_DIGEST
    assert found.header == {**POLICY_HEADER, "body_digest": POLICY_BODY_DIGEST}
    assert found.body.policy == VIEW_POLICY
    assert found.body.ratchet == POLICY_RATCHET
    assert ratchet.loaded(found.body.ratchet).as_dict() == POLICY_RATCHET
    assert (found.body.salt, found.body.reason) == (bytes(range(32)), "golden revision")
    assert found.key_id == keys.key_id


def test_the_policy_head_and_anchor_formats_are_pinned() -> None:
    keys = KeySet.from_master(MASTER)
    assert golden_policy_head() == GOLDEN_POLICY_HEAD.read_bytes()
    assert golden_policy_anchor() == GOLDEN_POLICY_ANCHOR.read_bytes()
    head = policyseal.unseal_head(GOLDEN_POLICY_HEAD.read_bytes(), keys, None)
    assert (head.revision, head.digest, head.oldest) == (2, POLICY_DIGEST, 1)
    anchor = policyseal.unseal_anchor(GOLDEN_POLICY_ANCHOR.read_bytes(), keys, None)
    assert (anchor.highest, anchor.parked, anchor.retired_key_id) == (2, None, None)
