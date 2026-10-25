"""The structured diff and the direction table (M6 design H.2, O.3; DD-10, G-11; T-1, T-2, CR-4).

Every kind of change ``structured`` names (a field, a mapping entry, a route by name, a caller or
a rule by position, a name in a set, a list whole, a block replaced), with defaults filled in;
``direction`` for every row of the table both ways, every field the table calls wider whatever
the change, and the schema walk that fails on a field the table doesn't name (T-1); a re-include
as ``allow`` of a definition the ratchet's ``approved`` set holds is wider (T-2); and the design's
rows end to end, from two policies.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import BaseModel

from zoeymcp.common.policy import schema
from zoeymcp.common.policy.diff import (
    BY_INDEX,
    DIRECTIONS,
    NAME_SETS,
    Change,
    Direction,
    Op,
    direction,
    structured,
)
from zoeymcp.common.policy.ratchet import advance, initial
from zoeymcp.common.policy.schema import Policy

PIN_READ = "sha256:" + "a" * 64
PIN_WRITE = "sha256:" + "b" * 64
PIN_NEW = "sha256:" + "c" * 64
TOKEN = "sha256:" + "1" * 64

Edit = Callable[[dict[str, Any]], None]


def document() -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "managed",
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "routes": [
            {
                "name": "notes-mcp",
                "prefix": "/notes",
                "upstream": "https://mcp.notes.example",
                "credential": "notes-key",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            },
            {
                "name": "files",
                "prefix": "/files",
                "upstream": "https://api.files.example",
                "callers": [
                    "gateway",
                    {"placeholder": "ph-script-0001", "sources": ["10.0.0.0/8"]},
                ],
                "query": {"strip": ["key"], "allow": ["page"]},
                "rules": [{"methods": ["GET"], "paths": ["/{id}"], "params": {"id": ["1", "2"]}}],
            },
        ],
        "gateway": {
            "clients": {"ci": {"token_sha256": TOKEN, "sources": ["192.0.2.0/24"]}},
            "servers": {
                "notes": {
                    "kind": "remote",
                    "route": "notes-mcp",
                    "tools": {
                        "include": ["read", "write"],
                        "allow": ["read"],
                        "approve": ["write"],
                    },
                    "review": {"read": PIN_READ, "write": PIN_WRITE},
                }
            },
        },
    }


def make(*edits: Edit) -> Policy:
    raw = document()
    for edit in edits:
        edit(raw)
    return Policy.model_validate(raw)


def notes(raw: dict[str, Any]) -> dict[str, Any]:
    server: dict[str, Any] = raw["gateway"]["servers"]["notes"]
    return server


def files(raw: dict[str, Any]) -> dict[str, Any]:
    route: dict[str, Any] = raw["routes"][1]
    return route


def connector(raw: dict[str, Any]) -> None:
    raw["connectors"] = {
        "mail": {
            "kind": "smtp",
            "host": "smtp.mail.example",
            "port": 465,
            "username": "store:mail-user",
            "password": "store:mail-pass",
            "from": "agent@mail.example",
            "to": ["partner@mail.example"],
        }
    }


BASE = make()


def directions(old: Policy, new: Policy) -> list[tuple[tuple[str | int, ...], Direction]]:
    return [(change.path, direction(change)) for change in structured(old, new)]


# --- structured --------------------------------------------------------------------------------


def test_the_same_policy_has_no_changes() -> None:
    assert structured(BASE, make()) == ()


def test_a_field_changed_carries_its_model_and_its_plain_values() -> None:
    def timeout(raw: dict[str, Any]) -> None:
        raw["gateway"]["approvals"] = {"timeout": 600}

    assert structured(BASE, make(timeout)) == (
        Change(("gateway", "approvals", "timeout"), "changed", 300, 600, "Approvals", "timeout"),
    )


def test_a_field_left_out_is_the_change_to_its_default() -> None:
    def no_allow(raw: dict[str, Any]) -> None:
        del files(raw)["query"]["allow"]

    found = structured(BASE, make(no_allow))
    assert found == (
        Change(
            ("routes", "files", "query", "allow"), "changed", ["page"], None, "QueryPolicy", "allow"
        ),
    )
    assert direction(found[0]) == "wider"


def test_a_mapping_entry_added_and_removed_whole() -> None:
    added = structured(BASE, make(connector))
    assert [(c.path, c.op, c.old, c.model, c.field) for c in added] == [
        (("connectors", "mail"), "added", None, "Policy", "connectors")
    ]
    # Plain JSON by the document's names, every default filled in.
    assert added[0].new["from"] == "agent@mail.example"
    assert added[0].new["max_per_day"] == 20
    assert added[0].new["paused"] is False
    removed = structured(make(connector), BASE)
    assert [(c.path, c.op, c.new) for c in removed] == [(("connectors", "mail"), "removed", None)]
    assert removed[0].old == added[0].new


def test_keys_are_walked_in_sorted_order() -> None:
    def clients(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"] = {
            "zed": {"token_sha256": TOKEN},
            "abe": {"token_sha256": TOKEN},
        }

    assert [c.path for c in structured(BASE, make(clients))] == [
        ("gateway", "clients", "abe"),
        ("gateway", "clients", "ci"),
        ("gateway", "clients", "zed"),
    ]


def test_routes_are_compared_by_name() -> None:
    def reorder(raw: dict[str, Any]) -> None:
        raw["routes"].reverse()

    assert structured(BASE, make(reorder)) == ()

    def no_files(raw: dict[str, Any]) -> None:
        del raw["routes"][1]

    found = structured(BASE, make(no_files))
    assert [(c.path, c.op, c.model, c.field) for c in found] == [
        (("routes", "files"), "removed", "Policy", "routes")
    ]
    assert found[0].old["name"] == "files"

    def prefix(raw: dict[str, Any]) -> None:
        raw["routes"].reverse()
        raw["routes"][0]["prefix"] = "/files2"

    assert [c.path for c in structured(BASE, make(prefix))] == [("routes", "files", "prefix")]


def test_a_list_of_names_is_a_set() -> None:
    def tools(raw: dict[str, Any]) -> None:
        notes(raw)["tools"]["include"] = ["write", "zap", "list"]
        notes(raw)["tools"]["approve"] = ["write", "zap", "list"]

    found = structured(BASE, make(tools))
    path = ("gateway", "servers", "notes", "tools", "include")
    assert found[:3] == (
        Change(path, "removed", "read", None, "Tools", "include"),
        Change(path, "added", None, "list", "Tools", "include"),
        Change(path, "added", None, "zap", "Tools", "include"),
    )

    def reorder(raw: dict[str, Any]) -> None:
        notes(raw)["tools"]["include"] = ["write", "read"]

    assert structured(BASE, make(reorder)) == ()


def test_callers_and_rules_are_compared_by_position() -> None:
    def callers(raw: dict[str, Any]) -> None:
        files(raw)["callers"] = [
            {"placeholder": "ph-script-0002"},
            {"placeholder": "ph-script-0001", "sources": []},
            "gateway",
        ]

    found = structured(BASE, make(callers))
    assert [(c.path, c.op, c.model, c.field) for c in found] == [
        (("routes", "files", "callers", 0), "changed", "Route", "callers"),
        (("routes", "files", "callers", 1, "sources"), "changed", "PlaceholderCaller", "sources"),
        (("routes", "files", "callers", 2), "added", "Route", "callers"),
    ]
    assert (found[0].old, found[0].new["placeholder"]) == ("gateway", "ph-script-0002")

    def rules(raw: dict[str, Any]) -> None:
        files(raw)["rules"][0]["params"] = {"id": ["1", "2"], "page": {"regex": "[0-9]+"}}

    assert structured(BASE, make(rules)) == (
        Change(
            ("routes", "files", "rules", 0, "params", "page"),
            "added",
            None,
            {"regex": "[0-9]+"},
            "Rule",
            "params",
        ),
    )


def test_a_block_replaced_by_another_kind_is_one_change() -> None:
    def query(raw: dict[str, Any]) -> None:
        raw["credentials"]["notes-key"] = {"kind": "query", "param": "k", "secret": "store:x"}

    found = structured(BASE, make(query))
    assert [(c.path, c.op, c.model, c.field) for c in found] == [
        (("credentials", "notes-key"), "changed", "Policy", "credentials")
    ]
    assert found[0].old["kind"] == "header"
    assert found[0].new["kind"] == "query"


def test_an_optional_block_set_or_dropped_is_one_change() -> None:
    def admin(raw: dict[str, Any]) -> None:
        raw["admin"] = {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}

    admin_block = {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]}
    assert structured(BASE, make(admin)) == (
        Change(("admin",), "changed", None, admin_block, "Policy", "admin"),
    )
    assert structured(make(admin), BASE)[0].new is None


def test_other_lists_are_compared_whole() -> None:
    def hosts(raw: dict[str, Any]) -> None:
        raw["gateway"]["hosts"] = ["localhost", "gw.example"]

    assert structured(BASE, make(hosts)) == (
        Change(
            ("gateway", "hosts"),
            "changed",
            ["localhost", "127.0.0.1", "::1"],
            ["localhost", "gw.example"],
            "Gateway",
            "hosts",
        ),
    )


def test_a_pin_and_a_from_field_by_their_document_names() -> None:
    def repin(raw: dict[str, Any]) -> None:
        notes(raw)["review"]["read"] = PIN_NEW

    assert structured(BASE, make(repin)) == (
        Change(
            ("gateway", "servers", "notes", "review", "read"),
            "changed",
            PIN_READ,
            PIN_NEW,
            "RemoteServer",
            "review",
        ),
    )

    def sender(raw: dict[str, Any]) -> None:
        raw["connectors"]["mail"]["from"] = "notify@mail.example"

    # The path by the document's name, the field by the model's (as policyview.FIELDS has it).
    assert structured(make(connector), make(connector, sender)) == (
        Change(
            ("connectors", "mail", "from"),
            "changed",
            "agent@mail.example",
            "notify@mail.example",
            "SMTPConnector",
            "from_",
        ),
    )


def test_prompts_and_resources_are_walked_as_tools_are() -> None:
    """Step 18: an include and an assistant prompt are names in a set, and a template's pin a
    mapping entry, each under its own model."""

    def kinds(raw: dict[str, Any]) -> None:
        server = raw["gateway"]["servers"]["notes"]
        server["prompts"] = {"include": ["summarize"], "assistant": ["summarize"]}
        server["resources"] = {"templates": {"review": {"notes://notes/{id}": PIN_NEW}}}

    where = ("gateway", "servers", "notes")
    assert structured(BASE, make(kinds)) == (
        Change(
            (*where, "prompts", "include"), "added", None, "summarize", "PromptsPolicy", "include"
        ),
        Change(
            (*where, "prompts", "assistant"),
            "added",
            None,
            "summarize",
            "PromptsPolicy",
            "assistant",
        ),
        Change(
            (*where, "resources", "templates", "review", "notes://notes/{id}"),
            "added",
            None,
            PIN_NEW,
            "ResourceSet",
            "review",
        ),
    )


def test_the_walk_tables_name_schema_fields() -> None:
    found = models()
    for model, field in NAME_SETS | BY_INDEX:
        assert field in found[model].model_fields, (model, field)


# --- the direction table -----------------------------------------------------------------------


def models() -> dict[str, type[BaseModel]]:
    """Every pydantic model the schema module defines, by class name."""
    return {
        name: value
        for name, value in vars(schema).items()
        if isinstance(value, type)
        and issubclass(value, BaseModel)
        and value.__module__ == schema.__name__
    }


def test_every_field_of_every_schema_model_has_a_direction() -> None:
    found = models()
    assert {"Policy", "Client", "PlaceholderCaller", "SMTPConnector"} <= set(found)
    for name, model in found.items():
        if not model.model_fields:
            assert name not in DIRECTIONS, name  # a base without fields (_Model)
            continue
        assert name in DIRECTIONS, f"{name} isn't in diff.DIRECTIONS: decide its direction"
        assert set(DIRECTIONS[name]) == set(model.model_fields), name
    assert set(DIRECTIONS) <= set(found)


def test_a_change_the_table_doesnt_name_is_wider() -> None:
    assert direction(Change(("x",), "changed", 1, 2, "NotAModel", "x")) == "wider"
    assert direction(Change(("x",), "removed", 1, None, "Policy", "not_a_field")) == "wider"


# Each field the table calls wider whatever the change (a credential's, an egress field, an
# admin origin, a re-pointed route or server), and each model the diff walks into.
ALWAYS_WIDER: dict[str, tuple[str, ...]] = {
    "HeaderCredential": ("kind", "secret", "header", "format"),
    "QueryCredential": ("kind", "param", "secret"),
    "PathCredential": ("kind", "template", "secret"),
    "BasicCredential": ("kind", "username", "secret"),
    "OAuth2Credential": tuple(schema.OAuth2Credential.model_fields),
    "SMTPConnector": ("kind", "host", "port", "tls", "username", "password", "from_"),
    "PlaceholderCaller": ("placeholder", "header", "query"),
    "RegexParam": ("regex",),
    "QueryPolicy": ("force",),
    "Route": (
        "name",
        "prefix",
        "upstream",
        "credential",
        "connector",
        "stream",
        "program",
        "query",
    ),
    "RouteProgram": ("holds_secret",),
    "ClientApprovals": ("renders",),
    "Client": ("token", "token_sha256"),
    "Approvals": ("approver",),
    "_UpstreamServer": ("tools", "prompts", "resources", "era"),
    "RemoteServer": ("tools", "prompts", "resources", "era", "kind", "route", "path"),
    "ResourcesPolicy": ("templates", "fixed"),
    "ToolkitSlot": ("route",),
    "ToolkitServer": ("kind", "module", "tools"),
    "Gateway": ("approvals", "limits"),
    "Admin": ("listen", "origins"),
    "Policy": ("version", "mode", "egress_proxy", "egress_proxy_kind", "egress_proxy_acls"),
}


def flipped(op: Op) -> Op:
    if op == "added":
        return "removed"
    return "added" if op == "removed" else "changed"


Row = tuple[str, str, Op, Any, Any, Direction, Direction]


def upstream_rows(model: str) -> list[Row]:
    return [
        (model, "review", "changed", PIN_READ, PIN_NEW, "neutral", "neutral"),
        (model, "review", "added", None, PIN_READ, "neutral", "neutral"),
        (model, "declined", "added", None, PIN_READ, "neutral", "wider"),
        (model, "declined", "changed", PIN_READ, PIN_NEW, "neutral", "neutral"),
        (model, "on_drift", "changed", "fail", "hide", "wider", "narrower"),
        (model, "wrap_results", "changed", True, False, "wider", "narrower"),
        (model, "call_timeout", "changed", 30, 60, "wider", "narrower"),
        (model, "call_timeout", "changed", 30, None, "wider", "narrower"),
    ]


# (model, field, op, old, new, the direction, the direction of the reverse change)
ROWS: list[Row] = [
    ("Policy", "egress_private", "changed", [], ["db:5432"], "wider", "narrower"),
    ("Policy", "egress_private", "changed", ["a:1", "b:1"], ["b:1", "a:1"], "neutral", "neutral"),
    ("Policy", "egress_key_generation", "changed", 1, 2, "narrower", "wider"),
    ("Policy", "gateway_key_generation", "changed", 1, 2, "narrower", "wider"),
    ("Policy", "admin", "changed", None, {"listen": "x"}, "wider", "narrower"),
    ("Policy", "credentials", "added", None, {"kind": "header"}, "wider", "narrower"),
    ("Policy", "credentials", "changed", {"kind": "header"}, {"kind": "query"}, "wider", "wider"),
    ("Policy", "connectors", "added", None, {"kind": "smtp"}, "wider", "narrower"),
    ("Policy", "routes", "added", None, {"name": "r"}, "wider", "narrower"),
    ("Policy", "gateway", "changed", None, {"servers": {}}, "wider", "narrower"),
    (
        "SMTPConnector",
        "to",
        "changed",
        ["a@x.example"],
        ["a@x.example", "b@x.example"],
        "wider",
        "narrower",
    ),
    ("SMTPConnector", "max_per_day", "changed", 20, 30, "wider", "narrower"),
    ("SMTPConnector", "max_subject_chars", "changed", 150, 200, "wider", "narrower"),
    ("SMTPConnector", "max_body_chars", "changed", 2200, 3000, "wider", "narrower"),
    ("SMTPConnector", "paused", "changed", True, False, "wider", "narrower"),
    ("PlaceholderCaller", "sources", "changed", ["10.0.0.0/8"], [], "wider", "narrower"),
    ("PlaceholderCaller", "sources", "changed", ["a"], ["a", "b"], "wider", "narrower"),
    ("Rule", "methods", "changed", ["GET"], ["GET", "POST"], "wider", "narrower"),
    ("Rule", "paths", "changed", ["/a"], ["/a", "/b"], "wider", "narrower"),
    ("Rule", "params", "added", None, ["1"], "narrower", "wider"),
    ("Rule", "params", "changed", ["1"], ["1", "2"], "wider", "narrower"),
    ("Rule", "params", "changed", ["1"], {"regex": "[0-9]"}, "wider", "wider"),
    ("Rule", "params", "changed", ["regex"], {"regex": "[0-9]"}, "wider", "wider"),
    ("QueryPolicy", "strip", "changed", ["key"], [], "wider", "narrower"),
    ("QueryPolicy", "strip", "changed", ["a", "b"], ["b", "a"], "neutral", "neutral"),
    ("QueryPolicy", "allow", "changed", ["page"], None, "wider", "narrower"),
    ("QueryPolicy", "allow", "changed", [], ["page"], "wider", "narrower"),
    ("QueryPolicy", "allow", "changed", ["a", "b"], ["b", "a"], "neutral", "neutral"),
    ("Route", "callers", "added", None, {"placeholder": "p"}, "wider", "narrower"),
    ("Route", "callers", "changed", "gateway", {"placeholder": "p"}, "wider", "wider"),
    ("Route", "rules", "added", None, {"methods": ["GET"]}, "wider", "narrower"),
    ("Route", "allow_insecure_upstream", "changed", False, True, "wider", "narrower"),
    ("RouteProgram", "egress", "changed", ["a:1"], ["a:1", "b:1"], "wider", "narrower"),
    ("RouteProgram", "egress_private", "changed", [], ["a:1"], "wider", "narrower"),
    ("ClientApprovals", "attended", "changed", False, True, "wider", "narrower"),
    ("ClientApprovals", "timeout", "changed", 60, 120, "wider", "narrower"),
    ("ClientApprovals", "timeout", "changed", 60, None, "wider", "narrower"),
    ("ClientApprovals", "budget_chars", "changed", 500, None, "wider", "narrower"),
    ("ClientApprovals", "confirm_code", "changed", True, False, "wider", "narrower"),
    ("Client", "servers", "added", None, "notes", "wider", "narrower"),
    ("Client", "sources", "changed", ["192.0.2.0/24"], [], "wider", "narrower"),
    ("Client", "approvals", "changed", None, {"attended": False}, "wider", "narrower"),
    ("Approvals", "timeout", "changed", 300, 600, "wider", "narrower"),
    ("Approvals", "budget_chars", "changed", 3000, 4000, "wider", "narrower"),
    ("Approvals", "cooldown", "changed", 15, 5, "wider", "narrower"),
    ("Approvals", "max_pending_per_client", "changed", 1, 2, "wider", "narrower"),
    ("Approvals", "max_prompts_per_hour", "changed", 30, 60, "wider", "narrower"),
    ("Tools", "include", "added", None, "read", "wider", "narrower"),
    ("Tools", "allow", "added", None, "read", "wider", "narrower"),
    ("Tools", "approve", "added", None, "read", "neutral", "neutral"),
    # Prompts and resources (step 18): an include or an assistant prompt added is wider (H.2).
    ("PromptsPolicy", "include", "added", None, "summarize", "wider", "narrower"),
    ("PromptsPolicy", "assistant", "added", None, "summarize", "wider", "narrower"),
    ("PromptsPolicy", "review", "changed", PIN_READ, PIN_NEW, "neutral", "neutral"),
    ("PromptsPolicy", "review", "added", None, PIN_READ, "neutral", "neutral"),
    ("PromptsPolicy", "declined", "added", None, PIN_READ, "neutral", "wider"),
    ("PromptsPolicy", "declined", "changed", PIN_READ, PIN_NEW, "neutral", "neutral"),
    ("ResourceSet", "include", "added", None, "notes://index", "wider", "narrower"),
    ("ResourceSet", "review", "changed", PIN_READ, PIN_NEW, "neutral", "neutral"),
    ("ResourceSet", "review", "added", None, PIN_READ, "neutral", "neutral"),
    ("ResourceSet", "declined", "added", None, PIN_READ, "neutral", "wider"),
    ("ResourceSet", "declined", "changed", PIN_READ, PIN_NEW, "neutral", "neutral"),
    *upstream_rows("_UpstreamServer"),
    *upstream_rows("RemoteServer"),
    *upstream_rows("ToolkitServer"),
    ("RemoteServer", "shared_session", "changed", False, True, "wider", "narrower"),
    ("RemoteServer", "enable", "added", None, "prompts", "wider", "narrower"),
    ("RemoteServer", "drift_check_interval", "changed", 300, 60, "neutral", "neutral"),
    ("_UpstreamServer", "shared_session", "changed", False, True, "wider", "narrower"),
    ("_UpstreamServer", "enable", "added", None, "prompts", "wider", "narrower"),
    ("_UpstreamServer", "drift_check_interval", "changed", 300, 60, "neutral", "neutral"),
    ("ToolkitServer", "pinning", "changed", "required", "off", "wider", "narrower"),
    ("ToolkitServer", "slots", "added", None, {"route": "r"}, "wider", "narrower"),
    ("ToolkitSlot", "rules", "added", None, {"methods": ["GET"]}, "wider", "narrower"),
    ("ToolkitRule", "methods", "changed", ["GET"], ["GET", "POST"], "wider", "narrower"),
    ("ToolkitRule", "paths", "changed", ["/a"], ["/a", "/b"], "wider", "narrower"),
    ("ToolkitRule", "approved", "changed", False, True, "wider", "narrower"),
    ("Gateway", "clients", "added", None, {"token_sha256": TOKEN}, "wider", "narrower"),
    ("Gateway", "servers", "added", None, {"kind": "remote"}, "wider", "narrower"),
    ("Gateway", "servers", "changed", {"kind": "remote"}, {"kind": "toolkit"}, "wider", "wider"),
    (
        "Gateway",
        "hosts",
        "changed",
        ["localhost"],
        ["localhost", "gw.example"],
        "wider",
        "narrower",
    ),
    ("Gateway", "origins", "changed", [], ["https://app.example"], "wider", "narrower"),
    *(
        ("GatewayLimits", name, "changed", info.default, info.default + 1, "wider", "narrower")
        for name, info in schema.GatewayLimits.model_fields.items()
    ),
]


@pytest.mark.parametrize(("model", "field", "op", "old", "new", "forward", "backward"), ROWS)
def test_each_row_both_ways(
    model: str, field: str, op: Op, old: Any, new: Any, forward: Direction, backward: Direction
) -> None:
    assert direction(Change(("p",), op, old, new, model, field)) == forward
    assert direction(Change(("p",), flipped(op), new, old, model, field)) == backward


@pytest.mark.parametrize(
    ("model", "field"), [(model, field) for model, names in ALWAYS_WIDER.items() for field in names]
)
def test_the_fields_any_change_to_which_is_wider(model: str, field: str) -> None:
    changes: list[tuple[Op, Any, Any]] = [("changed", "a", "b"), ("added", None, "a")]
    for op, old, new in [*changes, ("removed", "a", None)]:
        assert direction(Change(("p",), op, old, new, model, field)) == "wider"


def test_the_rows_cover_the_whole_table() -> None:
    covered = {(model, field) for model, field, *_ in ROWS}
    covered |= {(model, field) for model, names in ALWAYS_WIDER.items() for field in names}
    assert covered == {(model, field) for model, rules in DIRECTIONS.items() for field in rules}


# --- the design's rows, end to end -------------------------------------------------------------


def test_approve_to_allow_is_wider() -> None:
    def moved(raw: dict[str, Any]) -> None:
        notes(raw)["tools"].update(allow=["read", "write"], approve=[])

    tools = ("gateway", "servers", "notes", "tools")
    assert directions(BASE, make(moved)) == [
        ((*tools, "allow"), "wider"),
        ((*tools, "approve"), "neutral"),
    ]
    assert {d for _, d in directions(make(moved), BASE)} == {"narrower", "neutral"}


def drop_write(raw: dict[str, Any]) -> None:
    notes(raw)["tools"].update(include=["read"], approve=[])
    del notes(raw)["review"]["write"]


def test_a_re_include_as_allow_of_an_approved_definition_is_wider() -> None:
    """T-2: dropped, then included again as allow; the ratchet's approved set still holds it,
    so the planner also names it a move, and the diff alone already calls it wider."""
    dropped = make(drop_write)
    ratchet = advance(initial(BASE), BASE, dropped, verified=frozenset())
    assert ("notes", "tool", "write") in ratchet.approved

    def reinclude(raw: dict[str, Any]) -> None:
        notes(raw)["tools"].update(include=["read", "write"], allow=["read", "write"], approve=[])

    found = dict(directions(dropped, make(reinclude)))
    tools = ("gateway", "servers", "notes", "tools")
    assert found[(*tools, "include")] == found[(*tools, "allow")] == "wider"
    assert found[("gateway", "servers", "notes", "review", "write")] == "neutral"


def test_dropping_a_tool_is_narrower() -> None:
    assert {d for _, d in directions(BASE, make(drop_write))} == {"narrower", "neutral"}


@pytest.mark.parametrize(
    "edit",
    [
        lambda raw: raw["gateway"]["clients"]["ci"].update(sources=[]),
        lambda raw: raw["gateway"]["clients"]["ci"].pop("sources"),
        lambda raw: files(raw)["callers"][1].update(sources=[]),
        lambda raw: files(raw)["query"].pop("allow"),
        lambda raw: files(raw)["query"].update(strip=[]),
        lambda raw: files(raw)["rules"][0].update(params={}),
        lambda raw: files(raw)["rules"][0]["params"].update(id=["1", "2", "3"]),
        lambda raw: files(raw).update(allow_insecure_upstream=True),
        lambda raw: notes(raw).update(shared_session=True),
        lambda raw: notes(raw).update(on_drift="hide"),
        lambda raw: notes(raw).update(route="files"),
        lambda raw: raw["routes"][0].update(credential=None),
    ],
)
def test_a_removal_that_means_any_is_wider(edit: Edit) -> None:
    """A removal is not narrower by itself (CR-4): the base's ``on_drift`` is the default
    ``hide``, so the row there is set to ``fail`` first."""

    def fail(raw: dict[str, Any]) -> None:
        notes(raw)["on_drift"] = "fail"

    found = directions(make(fail), make(fail, edit))
    assert found
    assert all(d == "wider" for _, d in found), found


def test_undoing_an_onboarding_is_narrower() -> None:
    def onboarded(raw: dict[str, Any]) -> None:
        raw["credentials"]["mail-key"] = {"kind": "header", "secret": "store:mail-key"}
        raw["routes"].append(
            {
                "name": "mail-mcp",
                "prefix": "/mail",
                "upstream": "https://mcp.mail.example",
                "credential": "mail-key",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            }
        )
        raw["gateway"]["servers"]["mail"] = {"kind": "remote", "route": "mail-mcp"}
        raw["gateway"]["clients"]["ci"]["servers"] = ["mail"]

    found = directions(make(onboarded), BASE)
    assert [path for path, _ in found] == [
        ("credentials", "mail-key"),
        ("routes", "mail-mcp"),
        ("gateway", "clients", "ci", "servers"),
        ("gateway", "servers", "mail"),
    ]
    assert {d for _, d in found} == {"narrower"}
    assert {d for _, d in directions(BASE, make(onboarded))} == {"wider"}


def test_a_structured_diff_is_deterministic() -> None:
    def many(raw: dict[str, Any]) -> None:
        raw["gateway"]["clients"]["b"] = {"token_sha256": TOKEN}
        raw["gateway"]["clients"]["a"] = {"token_sha256": TOKEN}
        notes(raw)["tools"]["include"] = ["z", "y", "read", "write"]

    first = structured(BASE, make(many))
    raw = copy.deepcopy(document())
    many(raw)
    assert structured(BASE, Policy.model_validate(raw)) == first
