"""The gateway's view of the policy (M3 design D.1, invariant G1)."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from pydantic import ValidationError

from zoeymcp.common import canonical
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.check import check_policy
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.common.policy.view import (
    MAX_VIEW_BYTES,
    VIEW_VERSION,
    GatewayView,
    ViewError,
    build_view,
    dump_view,
    parse_view,
    view_digest,
)

Raw = dict[str, Any]
PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64
HASH_2 = "sha256:" + "2" * 64
TOKEN_1 = "zgc1-fake-token-for-agent-one-000000000000000000"


def raw_policy() -> Raw:
    return {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": "127.0.0.1:8081", "hosts": ["localhost"]},
        "credentials": {
            "notes-key": {"kind": "header", "header": "X-API-Key", "secret": "store:notes-key"}
        },
        "routes": [
            {
                "name": "notes-route",
                "prefix": "/notes",
                "upstream": "https://mcp.notes.example",
                "credential": "notes-key",
                "callers": ["gateway"],
                "stream": True,
                "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/v1/mcp"]}],
            }
        ],
        "gateway": {
            "hosts": ["localhost", "gateway.example", "::1"],
            "origins": ["https://app.example", "http://localhost:8080"],
            "limits": {"max_request_bytes": 4096, "policy_max_stale": 30},
            "approvals": {"approver": "portal", "timeout": 60, "budget_chars": 200},
            "clients": {
                "agent1": {"token": TOKEN_1, "servers": ["notes-read"]},
                "agent2": {
                    "token_sha256": HASH_2,
                    "servers": ["notes-read", "notes-write", "mail", "bridged"],
                    "sources": ["10.0.0.0/8", "::1"],
                },
            },
            "servers": {
                "notes-read": {
                    "kind": "remote",
                    "route": "notes-route",
                    "path": "/v1/mcp",
                    "tools": {"include": ["search", "get"], "allow": ["search", "get"]},
                    "review": {"search": PIN_A, "get": PIN_B},
                    "wrap_results": True,
                    "era": "modern",
                },
                "notes-write": {
                    "kind": "remote",
                    "route": "notes-route",
                    "path": "/v1/mcp",
                    "tools": {"include": ["create"], "approve": ["create"]},
                    "review": {"create": PIN_A},
                    "on_drift": "fail",
                    "shared_session": True,
                    "era": "legacy",
                    "drift_check_interval": 60,
                    "call_timeout": 3600,
                },
                "mail": {"kind": "toolkit", "module": "zoeymcp.toolkits.mail"},
                "bridged": {
                    "kind": "bridge",
                    "url": "http://bridge.example:9000/mcp",
                    "egress": ["api.bridge.example:443"],
                },
            },
        },
    }


def built(raw: Raw | None = None) -> GatewayView:
    return build_view(Policy.model_validate(raw if raw is not None else raw_policy()))


def as_raw(view: GatewayView) -> Raw:
    raw: Raw = json.loads(dump_view(view))
    return raw


def reencode(raw: Raw) -> bytes:
    """``raw`` as served, with its digest recomputed (a view the vault could have built)."""
    body = {"v": raw["v"], "gateway": raw["gateway"]}
    return canonical.dumps_canonical({**raw, "digest": canonical.digest(body)})


EXPECTED_GATEWAY: Raw = {
    "hosts": ["localhost", "gateway.example", "::1"],
    "origins": ["https://app.example", "http://localhost:8080"],
    "limits": {
        "max_request_bytes": 4096,
        "max_argument_bytes": 262144,
        "max_result_bytes": 4194304,
        "max_upstream_message_bytes": 8388608,
        "max_concurrent_per_client": 8,
        "max_streams_per_client": 4,
        "max_sessions_per_client": 16,
        "max_upstream_sessions": 64,
        "session_idle_timeout": 1800,
        "upstream_idle_timeout": 600,
        "call_timeout": 300,
        "list_timeout": 30,
        "max_list_pages": 32,
        "max_tools_per_server": 512,
        "max_list_bytes": 4194304,
        "max_schema_bytes": 65536,
        "max_schema_depth": 32,
        "max_subschemas": 512,
        "policy_max_stale": 30,
        "ledger_max_bytes": 67108864,
    },
    "approvals": {
        "approver": "portal",
        "timeout": 60,
        "budget_chars": 200,
        "cooldown": 15,
        "max_pending_per_client": 1,
        "max_prompts_per_hour": 30,
    },
    "clients": {
        "agent1": {
            "token_sha256": hash_token(TOKEN_1),
            "servers": ["notes-read"],
            "sources": [],
            "approvals": None,
        },
        "agent2": {
            "token_sha256": HASH_2,
            "servers": ["notes-read", "notes-write", "mail", "bridged"],
            "sources": ["10.0.0.0/8", "::1"],
            "approvals": None,
        },
    },
    "servers": {
        "notes-read": {
            "kind": "remote",
            "vault_path": "/notes/v1/mcp",
            "tools": {"include": ["search", "get"], "allow": ["search", "get"], "approve": []},
            "review": {"search": PIN_A, "get": PIN_B},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": True,
            "enable": [],
            "era": "modern",
            "drift_check_interval": 300,
            "call_timeout": None,
        },
        "notes-write": {
            "kind": "remote",
            "vault_path": "/notes/v1/mcp",
            "tools": {"include": ["create"], "allow": [], "approve": ["create"]},
            "review": {"create": PIN_A},
            "on_drift": "fail",
            "shared_session": True,
            "wrap_results": False,
            "enable": [],
            "era": "legacy",
            "drift_check_interval": 60,
            "call_timeout": 3600,
        },
        "mail": {
            "kind": "toolkit",
            "module": "zoeymcp.toolkits.mail",
            "tools": {"include": [], "allow": [], "approve": []},
            "pinning": "required",
            "review": {},
            "on_drift": "hide",
            "slots": {},
            "wrap_results": False,
            "call_timeout": None,
        },
        "bridged": {"kind": "bridge"},
    },
}


# --- building ----------------------------------------------------------------------------------


def test_the_view_holds_exactly_what_the_gateway_needs() -> None:
    raw = as_raw(built())
    assert raw == {
        "v": 1,
        "digest": canonical.digest({"v": 1, "gateway": EXPECTED_GATEWAY}),
        "gateway": EXPECTED_GATEWAY,
    }


def test_a_literal_token_becomes_its_hash() -> None:
    view = built()
    assert view.gateway.clients["agent1"].token_sha256 == hash_token(TOKEN_1)
    assert TOKEN_1 not in dump_view(view).decode()


def test_enable_is_carried() -> None:
    # check refuses a non-empty enable in M3; the view still says what the policy says.
    raw = raw_policy()
    raw["gateway"]["servers"]["notes-read"]["enable"] = ["resources"]
    assert built(raw).gateway.servers["notes-read"].model_dump()["enable"] == ["resources"]


@pytest.mark.parametrize("era", ["auto", "modern", "legacy"])
@pytest.mark.parametrize("on_drift", ["hide", "fail"])
def test_every_era_and_drift_choice_round_trips(era: str, on_drift: str) -> None:
    raw = raw_policy()
    raw["gateway"]["servers"]["notes-read"].update(era=era, on_drift=on_drift)
    view = built(raw)
    server = parse_view(dump_view(view)).gateway.servers["notes-read"].model_dump()
    assert (server["era"], server["on_drift"]) == (era, on_drift)


def test_without_a_gateway_section_the_view_has_the_defaults() -> None:
    raw = raw_policy()
    del raw["gateway"]
    view = built(raw)
    assert as_raw(view)["gateway"] == {
        "hosts": ["localhost", "127.0.0.1", "::1"],
        "origins": [],
        "limits": EXPECTED_GATEWAY["limits"]
        | {"max_request_bytes": 1048576, "policy_max_stale": 300},
        "approvals": {
            "approver": "elicitation",
            "timeout": 300,
            "budget_chars": 3000,
            "cooldown": 15,
            "max_pending_per_client": 1,
            "max_prompts_per_hour": 30,
        },
        "clients": {},
        "servers": {},
    }


def test_an_unknown_route_is_refused() -> None:
    raw = raw_policy()
    raw["gateway"]["servers"]["notes-read"]["route"] = "missing"
    with pytest.raises(ValueError, match=r"^gateway server 'notes-read' names an unknown route$"):
        built(raw)


def test_the_vault_path_joins_prefix_and_path() -> None:
    raw = raw_policy()
    raw["gateway"]["servers"]["notes-read"]["path"] = "/mcp/"
    raw["routes"][0]["prefix"] = "/n0"
    view = built(raw)
    assert view.gateway.servers["notes-read"].model_dump()["vault_path"] == "/n0/mcp/"


# --- the digest --------------------------------------------------------------------------------


def test_the_digest_covers_everything_else() -> None:
    view = built()
    assert view.digest == view_digest(view.gateway)
    assert view.digest == canonical.digest(
        {"v": VIEW_VERSION, "gateway": view.gateway.model_dump(mode="json")}
    )
    assert VIEW_VERSION == 1


def test_the_digest_ignores_document_order() -> None:
    raw = raw_policy()
    reordered = copy.deepcopy(raw)
    gateway = reordered["gateway"]
    gateway["clients"] = dict(reversed(gateway["clients"].items()))
    gateway["servers"] = dict(reversed(gateway["servers"].items()))
    gateway["servers"]["notes-read"]["review"] = {"get": PIN_B, "search": PIN_A}
    reordered["gateway"] = dict(reversed(gateway.items()))
    assert built(reordered).digest == built(raw).digest
    assert dump_view(built(reordered)) == dump_view(built(raw))


def _change_pin(raw: Raw) -> None:
    raw["gateway"]["servers"]["notes-read"]["review"]["get"] = PIN_A


def _change_limit(raw: Raw) -> None:
    raw["gateway"]["limits"]["call_timeout"] = 301


def _change_prefix(raw: Raw) -> None:
    raw["routes"][0]["prefix"] = "/notes2"


def _change_token(raw: Raw) -> None:
    raw["gateway"]["clients"]["agent1"]["token"] = TOKEN_1 + "x"


def _change_tool_order(raw: Raw) -> None:
    raw["gateway"]["servers"]["notes-read"]["tools"]["include"] = ["get", "search"]


@pytest.mark.parametrize(
    "change", [_change_pin, _change_limit, _change_prefix, _change_token, _change_tool_order]
)
def test_the_digest_follows_the_content(change: Any) -> None:
    raw = raw_policy()
    change(raw)
    assert built(raw).digest != built().digest


def test_secret_side_changes_leave_the_digest_alone() -> None:
    raw = raw_policy()
    raw["credentials"]["notes-key"]["secret"] = "store:other-key"
    raw["routes"][0]["upstream"] = "https://mcp2.notes.example"
    raw["admin"]["hosts"] = ["admin.example"]
    assert built(raw).digest == built().digest


def test_a_toolkit_module_is_gateway_side() -> None:
    """The gateway imports the module, so a new one is a new view."""
    raw = raw_policy()
    raw["gateway"]["servers"]["mail"]["module"] = "zoeymcp.toolkits.other"
    assert built(raw).digest != built().digest


# --- serving and parsing -----------------------------------------------------------------------


def test_the_served_form_is_canonical_and_round_trips() -> None:
    view = built()
    data = dump_view(view)
    assert data == canonical.dumps_canonical(view.model_dump(mode="json"))
    assert parse_view(data) == view


def test_size_limit_both_sides() -> None:
    data = dump_view(built())
    exact = data + b" " * (MAX_VIEW_BYTES - len(data))
    assert len(exact) == MAX_VIEW_BYTES
    assert parse_view(exact) == built()
    with pytest.raises(ViewError, match=r"^the view is larger than 8388608 bytes$"):
        parse_view(exact + b" ")
    assert MAX_VIEW_BYTES == 8 * 2**20


@pytest.mark.parametrize(
    "data",
    [b"", b"{", b'{"v": 1, "v": 1}', b"[1, NaN]", b"\xff", b"\xef\xbb\xbf{}"],
)
def test_bad_json_is_refused(data: bytes) -> None:
    with pytest.raises(ViewError, match=r"^the view is not valid JSON$"):
        parse_view(data)


def test_a_digest_mismatch_is_refused() -> None:
    raw = as_raw(built())
    raw["gateway"]["hosts"] = ["localhost"]
    with pytest.raises(ViewError, match=r"^the view's digest doesn't match its content$"):
        parse_view(canonical.dumps_canonical(raw))


def _set(path: str, value: Any) -> Any:
    def change(raw: Raw) -> None:
        *parents, last = path.split("/")
        target = raw
        for part in parents:
            target = target[part]
        target[last] = value

    return change


def _drop(path: str) -> Any:
    def change(raw: Raw) -> None:
        *parents, last = path.split("/")
        target = raw
        for part in parents:
            target = target[part]
        del target[last]

    return change


def _copy(path: str, name: str) -> Any:
    def change(raw: Raw) -> None:
        *parents, last = path.split("/")
        target = raw
        for part in parents:
            target = target[part]
        target[name] = copy.deepcopy(target[last])

    return change


REMOTE = "gateway/servers/notes-read"


@pytest.mark.parametrize(
    ("change", "location"),
    [
        (_set("v", 2), "v"),
        (_set("surprise", 1), "surprise"),
        (_set("gateway/surprise", 1), "gateway.surprise"),
        (_drop("gateway/limits"), "gateway.limits"),
        (_set("gateway/hosts", []), "gateway.hosts"),
        (_set("gateway/hosts", ["[::1]"]), "gateway.hosts"),
        (_set("gateway/hosts", ["bad host"]), "gateway.hosts"),
        (_set("gateway/origins", ["https://app.example/"]), "gateway.origins"),
        (
            _set("gateway/clients/agent1/token_sha256", "sha256:abc"),
            "gateway.clients.agent1.token_sha256",
        ),
        (_set("gateway/clients/agent1/token", TOKEN_1), "gateway.clients.agent1.token"),
        (_set("gateway/clients/agent1/sources", ["not-a-net"]), "gateway.clients.agent1.sources"),
        (_drop("gateway/clients/agent1/sources"), "gateway.clients.agent1.sources"),
        (_copy("gateway/clients/agent1", "Agent"), "gateway.clients.Agent.[key]"),
        (_set("gateway/servers/mail/module", "1x"), "gateway.servers.mail.toolkit.module"),
        (_drop("gateway/servers/mail/slots"), "gateway.servers.mail.toolkit.slots"),
        (_set("gateway/servers/mail/kind", "local"), "gateway.servers.mail"),
        (_set(f"{REMOTE}/route", "notes-route"), "gateway.servers.notes-read.remote.route"),
        (_drop(f"{REMOTE}/vault_path"), "gateway.servers.notes-read.remote.vault_path"),
        (_set(f"{REMOTE}/vault_path", "/notes"), "gateway.servers.notes-read.remote.vault_path"),
        (
            _set(f"{REMOTE}/vault_path", "https://mcp.notes.example/v1/mcp"),
            "gateway.servers.notes-read.remote.vault_path",
        ),
        (
            _set(f"{REMOTE}/vault_path", "/notes/v1/mcp?x=1"),
            "gateway.servers.notes-read.remote.vault_path",
        ),
        (_set(f"{REMOTE}/review/get", "md5:00"), "gateway.servers.notes-read.remote.review.get"),
        (_set(f"{REMOTE}/on_drift", "ignore"), "gateway.servers.notes-read.remote.on_drift"),
        (_set(f"{REMOTE}/enable", ["tasks"]), "gateway.servers.notes-read.remote.enable[0]"),
        (_set(f"{REMOTE}/era", "2025"), "gateway.servers.notes-read.remote.era"),
        (_set(f"{REMOTE}/wrap_results", "yes"), "gateway.servers.notes-read.remote.wrap_results"),
        (_drop(f"{REMOTE}/call_timeout"), "gateway.servers.notes-read.remote.call_timeout"),
        (_set("gateway/limits/max_request_bytes", 4095), "gateway.limits.max_request_bytes"),
        (_set("gateway/approvals/approver", "email"), "gateway.approvals.approver"),
    ],
)
def test_invalid_views_are_refused_by_location(change: Any, location: str) -> None:
    raw = as_raw(built())
    change(raw)
    with pytest.raises(ViewError) as info:
        parse_view(reencode(raw))
    assert str(info.value) == f"invalid view at {location}"


@pytest.mark.parametrize("digest", ["sha256:abc", "sha256:" + "A" * 64, "md5:" + "a" * 64])
def test_a_malformed_digest_is_refused(digest: str) -> None:
    raw = as_raw(built())
    raw["digest"] = digest
    with pytest.raises(ViewError, match=r"^invalid view at digest$"):
        parse_view(canonical.dumps_canonical(raw))


def test_every_location_is_named_once_in_order() -> None:
    raw = as_raw(built())
    raw["gateway"]["hosts"] = ["bad host", "also bad"]
    raw["gateway"]["origins"] = ["ftp://x.example"]
    raw["v"] = 3
    with pytest.raises(ViewError) as info:
        parse_view(reencode(raw))
    assert str(info.value) == "invalid view at gateway.hosts, gateway.origins, v"
    assert info.value.__cause__ is not None


@pytest.mark.parametrize(
    ("field", "good", "bad"),
    [
        ("drift_check_interval", [60, 86400], [59, 86401]),
        ("call_timeout", [1, 3600, None], [0, 3601]),
    ],
)
def test_server_number_bounds(field: str, good: list[Any], bad: list[Any]) -> None:
    for value in good:
        raw = as_raw(built())
        raw["gateway"]["servers"]["notes-read"][field] = value
        assert parse_view(reencode(raw)).gateway.servers["notes-read"].model_dump()[field] == value
    for value in bad:
        raw = as_raw(built())
        raw["gateway"]["servers"]["notes-read"][field] = value
        with pytest.raises(ViewError, match=f"remote.{field}$"):
            parse_view(reencode(raw))


def test_vault_path_bounds() -> None:
    longest = "/" + "p" * 63 + "/" + "s" * 1023
    for path in (longest, "/n/", "/n/a.b_c~d-e/f"):
        raw = as_raw(built())
        raw["gateway"]["servers"]["notes-read"]["vault_path"] = path
        assert (
            parse_view(reencode(raw)).gateway.servers["notes-read"].model_dump()["vault_path"]
            == path
        )
    for path in ("/" + "p" * 64 + "/mcp", "/n/" + "s" * 1024, "/N/mcp", "/n/a b", "//mcp"):
        raw = as_raw(built())
        raw["gateway"]["servers"]["notes-read"]["vault_path"] = path
        with pytest.raises(ViewError, match=r"vault_path$"):
            parse_view(reencode(raw))


def test_the_models_are_strict_and_frozen() -> None:
    view = built()
    with pytest.raises(ValidationError):
        view.gateway.clients["agent1"].servers = []  # type: ignore[misc]
    raw = as_raw(view)
    raw["gateway"]["servers"]["notes-read"]["drift_check_interval"] = "300"
    with pytest.raises(ViewError, match=r"drift_check_interval$"):
        parse_view(reencode(raw))


def test_client_approval_settings_reach_the_gateway() -> None:
    raw = raw_policy()
    settings = {"attended": True, "timeout": 30, "confirm_code": True, "renders": "plain"}
    raw["gateway"]["clients"]["agent2"]["approvals"] = settings
    view = built(raw)
    assert as_raw(view)["gateway"]["clients"]["agent2"]["approvals"] == {
        **settings,
        "budget_chars": None,
    }
    assert parse_view(dump_view(view)) == view
    assert view.gateway.clients["agent1"].approvals is None


def test_hosts_bounds() -> None:
    raw = as_raw(built())
    raw["gateway"]["hosts"] = ["localhost"]
    assert parse_view(reencode(raw)).gateway.hosts == ["localhost"]
    raw["gateway"]["hosts"] = []
    with pytest.raises(ViewError, match=r"^invalid view at gateway\.hosts$"):
        parse_view(reencode(raw))


@pytest.mark.parametrize(
    ("prefix", "path"),
    [("/" + "p" * 63, "/" + "b" * 1023), ("/" + "p" * 63, "/"), ("/n", "/")],
)
def test_every_vault_path_check_allows_builds_and_parses(prefix: str, path: str) -> None:
    # The view's VaultPath must accept whatever the schema and check let through.
    raw = raw_policy()
    raw["routes"][0]["prefix"] = prefix
    raw["routes"][0]["rules"][0]["paths"] = [path]
    raw["gateway"]["servers"]["notes-read"]["path"] = path
    raw["gateway"]["servers"]["notes-write"]["path"] = path
    raw["gateway"]["approvals"]["approver"] = "elicitation"  # check refuses others until M8
    policy = Policy.model_validate(raw)
    assert [f for f in check_policy(policy) if f.level == "error"] == []
    view = build_view(policy)
    assert view.gateway.servers["notes-read"].model_dump()["vault_path"] == prefix + path
    assert parse_view(dump_view(view)) == view


def _copy_client(name: str) -> Any:
    return _copy("gateway/clients/agent1", name)


@pytest.mark.parametrize(
    ("name", "shown"),
    [
        ("A" * 128, "A" * 128),
        ("A" * 129, "?"),
        ("a" * 10000, "?"),
        ("", "?"),
        ("Agent.1-x_y", "Agent.1-x_y"),
        ("agent\n", "?"),
        ("a b", "?"),
        ("zgc1-fake/token", "?"),
    ],
)
def test_only_short_plain_keys_are_named(name: str, shown: str) -> None:
    raw = as_raw(built())
    _copy_client(name)(raw)
    with pytest.raises(ViewError) as info:
        parse_view(reencode(raw))
    assert str(info.value) == f"invalid view at gateway.clients.{shown}.[key]"


def test_an_unknown_long_field_is_not_echoed() -> None:
    raw = as_raw(built())
    raw["gateway"]["x" * 10000] = 1
    with pytest.raises(ViewError) as info:
        parse_view(reencode(raw))
    assert str(info.value) == "invalid view at gateway.?"


def test_a_location_named_twice_is_named_once() -> None:
    raw = as_raw(built())
    for name in ("a" * 200, "a b", "Agent"):
        _copy_client(name)(raw)
    with pytest.raises(ViewError) as info:
        parse_view(reencode(raw))
    assert str(info.value) == "invalid view at gateway.clients.?.[key], gateway.clients.Agent.[key]"
