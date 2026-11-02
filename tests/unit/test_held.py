"""Which tools the vault holds (M8 design A.3, O.3; MISS-1, T-1, T-2, Z7, Z20).

``held_map`` by route: an MCP route held for every server path it carries, a connector held for
its writers; ``same_hold`` for Z7's withdrawals; ``held_pairs`` and ``unheld_reach`` for the
planner's held set; and the helpers ``check`` shares (``path_key``, ``target``,
``same_credential``, ``server_paths``, ``connector_writers``). Policies are built with the schema
alone: these functions read a policy whether or not ``check`` would pass it.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest

from zoeymcp.common.policy.held import (
    HeldConnector,
    HeldPath,
    HeldRoute,
    connector_writers,
    held_map,
    held_pairs,
    lookup,
    path_key,
    same_credential,
    same_hold,
    server_paths,
    target,
    unheld_reach,
)
from zoeymcp.common.policy.match import NormalizedPath
from zoeymcp.common.policy.schema import Policy, Route

Raw = dict[str, Any]
Edit = Callable[[Raw], object]
PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64
PIN_C = "sha256:" + "c" * 64


def document() -> Raw:
    """Two servers on one MCP route at their own paths, one holding two tools, and a toolkit
    holding its send through a connector."""
    return {
        "version": 1,
        "mode": "declarative",
        "credentials": {"notes-key": {"kind": "header", "secret": "store:notes-key"}},
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": "u",
                "password": "store:mail-pass",
                "from": "a@mail.example",
                "to": ["b@mail.example"],
            }
        },
        "routes": [
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": "https://mcp.notes.example",
                "credential": "notes-key",
                "callers": ["gateway"],
                "stream": True,
                "rules": [{"methods": ["POST"], "paths": ["/mcp", "/read/"]}],
            },
            {
                "name": "mail",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            },
        ],
        "gateway": {
            "limits": {"call_timeout": 240},
            "servers": {
                "read": {
                    "kind": "remote",
                    "route": "notes",
                    "path": "/read/",
                    "tools": {"include": ["search"], "allow": ["search"]},
                },
                "write": {
                    "kind": "remote",
                    "route": "notes",
                    "tools": {
                        "include": ["write", "delete", "list"],
                        "allow": ["list"],
                        "approve": ["write", "delete"],
                        "vault_approval": ["write", "delete"],
                    },
                    "review": {"write": PIN_A, "list": PIN_B},
                },
                "kit": {
                    "kind": "toolkit",
                    "module": "example_toolkits.mail",
                    "tools": {
                        "include": ["send_note"],
                        "approve": ["send_note"],
                        "vault_approval": ["send_note"],
                    },
                    "call_timeout": 600,
                    "slots": {
                        "mail": {
                            "route": "mail",
                            "rules": [{"methods": ["POST"], "paths": ["/send"], "approved": True}],
                        }
                    },
                },
            },
        },
    }


def make(*edits: Edit) -> Policy:
    raw = document()
    for edit in edits:
        edit(raw)
    return Policy.model_validate(raw)


def servers(raw: Raw) -> Raw:
    found: Raw = raw["gateway"]["servers"]
    return found


def unheld(raw: Raw) -> None:
    for server in servers(raw).values():
        server["tools"].pop("vault_approval", None)


def another_route(**fields: Any) -> Edit:
    def edit(raw: Raw) -> None:
        raw["routes"].append(
            {
                "name": "direct",
                "prefix": "/direct",
                "upstream": "https://MCP.notes.example:443/",
                "callers": [{"placeholder": "ph-direct-000000001"}],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
                **fields,
            }
        )

    return edit


BASE = make()


# --- path keys ---------------------------------------------------------------------------------


def test_a_trailing_slash_is_a_last_empty_segment() -> None:
    assert path_key(NormalizedPath(("mcp",))) == ("mcp",)
    assert path_key(NormalizedPath(("mcp",), trailing_slash=True)) == ("mcp", "")
    assert path_key(NormalizedPath(("a", "b"), trailing_slash=True)) == ("a", "b", "")
    assert path_key(NormalizedPath(())) == ()


def test_server_paths_are_per_route_and_leave_out_a_path_the_vault_refuses() -> None:
    def bad_path(raw: Raw) -> None:
        servers(raw)["read"]["path"] = "/a b"

    assert server_paths(BASE) == {"notes": {("read", ""): ["read"], ("mcp",): ["write"]}}
    assert server_paths(make(bad_path)) == {"notes": {("mcp",): ["write"]}}
    assert server_paths(make(lambda raw: raw.pop("gateway"))) == {}


# --- the map -----------------------------------------------------------------------------------


def test_the_map_holds_each_route_by_its_servers() -> None:
    held = held_map(BASE)
    assert set(held) == {"notes", "mail"}
    assert held["notes"] == HeldRoute(
        route="notes",
        paths={
            ("read", ""): HeldPath(
                route="notes",
                path=("read", ""),
                server="read",
                tools=frozenset(),
                listed=frozenset({"search"}),
                pins={},
            ),
            ("mcp",): HeldPath(
                route="notes",
                path=("mcp",),
                server="write",
                tools=frozenset({"write", "delete"}),
                listed=frozenset({"list", "write", "delete"}),
                pins={"write": PIN_A},
            ),
        },
        names=frozenset({"write", "delete"}),
    )
    assert held["mail"] == HeldConnector(
        route="mail", writers={"kit": 600}, names=frozenset({"send_note"})
    )
    assert lookup(held, "notes") is held["notes"]
    assert lookup(held, "mail") is held["mail"]
    assert lookup(held, "other") is None


def test_a_writer_without_its_own_call_timeout_has_the_gateways() -> None:
    def defaulted(raw: Raw) -> None:
        del servers(raw)["kit"]["call_timeout"]

    held = held_map(make(defaulted))["mail"]
    assert isinstance(held, HeldConnector)
    assert held.writers == {"kit": 240}


def test_nothing_held_is_an_empty_map() -> None:
    assert held_map(make(unheld)) == {}
    assert held_map(make(lambda raw: raw.pop("gateway"))) == {}
    assert held_map(Policy.model_validate({"version": 1, "mode": "declarative"})) == {}


def test_a_route_is_held_by_any_one_server_on_it() -> None:
    def only_write(raw: Raw) -> None:
        servers(raw)["kit"]["tools"].pop("vault_approval")

    held = held_map(make(only_write))
    assert set(held) == {"notes"}

    def only_kit(raw: Raw) -> None:
        servers(raw)["write"]["tools"].pop("vault_approval")

    assert set(held_map(make(only_kit))) == {"mail"}


def test_a_path_two_servers_share_is_left_out_of_a_held_route() -> None:
    """The vault then refuses every request on it (B.1); check refuses the policy (row 3)."""

    def shared(raw: Raw) -> None:
        servers(raw)["read"]["path"] = "/mcp"

    held = held_map(make(shared))["notes"]
    assert isinstance(held, HeldRoute)
    assert held.paths == {}
    assert held.names == frozenset({"write", "delete"})


def test_a_writer_is_a_toolkit_whose_slot_on_a_connector_carries_an_approved_rule() -> None:
    def kit2(raw: Raw) -> None:
        kit = copy.deepcopy(servers(raw)["kit"])
        kit["slots"]["again"] = copy.deepcopy(kit["slots"]["mail"])
        servers(raw)["kit2"] = kit
        unapproved = copy.deepcopy(kit)
        unapproved["slots"]["mail"]["rules"][0]["approved"] = False
        del unapproved["slots"]["again"]
        servers(raw)["kit3"] = unapproved
        servers(raw)["kit4"] = {**copy.deepcopy(kit), "slots": {"n": {**kit["slots"]["mail"]}}}
        servers(raw)["kit4"]["slots"]["n"]["route"] = "notes"

    assert connector_writers(make(kit2)) == {"mail": ["kit", "kit2"]}
    assert connector_writers(make(lambda raw: raw.pop("gateway"))) == {}


# --- Z7: the same hold -------------------------------------------------------------------------


def test_a_hold_stays_while_its_server_path_tool_and_pin_do() -> None:
    old = held_map(BASE)
    assert same_hold(old, held_map(make()), ("notes", ("mcp",)), "write")
    assert same_hold(old, held_map(make()), ("notes", ("mcp",)), "delete")

    def other_tool_changed(raw: Raw) -> None:
        servers(raw)["write"]["review"]["list"] = PIN_C

    assert same_hold(old, held_map(make(other_tool_changed)), ("notes", ("mcp",)), "write")


@pytest.mark.parametrize(
    ("edit", "key", "tool"),
    [
        (
            lambda raw: servers(raw)["write"]["review"].update(write=PIN_C),
            ("notes", ("mcp",)),
            "write",
        ),
        (
            lambda raw: servers(raw)["write"]["tools"].update(vault_approval=["delete"]),
            ("notes", ("mcp",)),
            "write",
        ),
        (lambda raw: servers(raw)["write"].update(path="/v2"), ("notes", ("mcp",)), "write"),
        (unheld, ("notes", ("mcp",)), "write"),
        (
            lambda raw: servers(raw).update(renamed=servers(raw).pop("write")),
            ("notes", ("mcp",)),
            "write",
        ),
        (lambda raw: None, ("notes", ("mcp",)), "list"),
        (lambda raw: None, ("notes", ("read", "")), "write"),
        (lambda raw: None, ("notes", ("other",)), "write"),
        (lambda raw: None, ("gone", ("mcp",)), "write"),
        (lambda raw: servers(raw)["kit"].update(call_timeout=601), ("mail", ()), "send_note"),
        (lambda raw: servers(raw)["kit"]["tools"].pop("vault_approval"), ("mail", ()), "send_note"),
        (lambda raw: None, ("mail", ()), "other_tool"),
        (lambda raw: None, ("mail", ()), "write"),
        (lambda raw: None, ("notes", ()), "send_note"),
    ],
    ids=[
        "re-pinned",
        "let-go",
        "path-moved",
        "nothing-held",
        "server-renamed",
        "never-held",
        "unheld-path",
        "unknown-path",
        "unknown-route",
        "writer-deadline",
        "connector-let-go",
        "connector-other-tool",
        "connector-mcp-tool",
        "route-not-connector",
    ],
)
def test_any_other_change_withdraws_the_hold(
    edit: Edit, key: tuple[str, tuple[str, ...]], tool: str
) -> None:
    assert not same_hold(held_map(BASE), held_map(make(edit)), key, tool)


def test_a_connector_hold_stays_while_its_writers_and_tool_do() -> None:
    old = held_map(BASE)
    assert same_hold(old, held_map(make()), ("mail", ()), "send_note")

    def other_route_changed(raw: Raw) -> None:
        servers(raw)["write"]["tools"]["vault_approval"] = ["write"]

    assert same_hold(old, held_map(make(other_route_changed)), ("mail", ()), "send_note")

    # A tool held only after the change was never held: no hold of it to keep.
    def second(raw: Raw) -> None:
        kit = servers(raw)["kit"]["tools"]
        kit.update(include=["send_note", "x"], approve=["send_note", "x"])
        kit["vault_approval"] = ["send_note", "x"]

    assert not same_hold(old, held_map(make(second)), ("mail", ()), "x")
    assert same_hold(held_map(make(second)), held_map(make(second)), ("mail", ()), "x")


# --- Z20: the held set -------------------------------------------------------------------------


def test_the_held_pairs_are_the_held_tools_included_and_approved() -> None:
    assert held_pairs(BASE) == {("write", "write"), ("write", "delete"), ("kit", "send_note")}

    def stray(raw: Raw) -> None:
        servers(raw)["write"]["tools"].update(approve=["write"], include=["write", "delete"])

    assert held_pairs(make(stray)) == {("write", "write"), ("kit", "send_note")}

    def dropped(raw: Raw) -> None:
        servers(raw)["write"]["tools"].update(include=["write", "list"])

    assert held_pairs(make(dropped)) == {("write", "write"), ("kit", "send_note")}
    assert held_pairs(make(unheld)) == frozenset()
    assert held_pairs(make(lambda raw: raw.pop("gateway"))) == frozenset()


def test_nothing_is_reached_unheld_by_itself() -> None:
    assert unheld_reach(BASE) == frozenset()
    assert unheld_reach(make(unheld)) == frozenset()


@pytest.mark.parametrize(
    ("edit", "reached"),
    [
        (another_route(credential="notes-key"), {("write", "write"), ("write", "delete")}),
        (
            lambda raw: (
                raw["credentials"].update(
                    copy={"kind": "query", "param": "k", "secret": "store:notes-key"}
                ),
                another_route(credential="copy")(raw),
            ),
            {("write", "write"), ("write", "delete")},
        ),
        (
            lambda raw: servers(raw)["read"]["tools"].update(
                include=["search", "write"], allow=["search", "write"]
            ),
            {("write", "write")},
        ),
        (
            lambda raw: servers(raw)["read"]["tools"].update(
                include=["search", "delete"], allow=["search"], approve=["delete"]
            ),
            {("write", "delete")},
        ),
        (
            lambda raw: raw["routes"].append(
                {
                    "name": "mail2",
                    "prefix": "/mail2",
                    "connector": "mail-out",
                    "callers": ["gateway"],
                    "rules": [{"methods": ["POST"], "paths": ["/send"]}],
                }
            ),
            {("kit", "send_note")},
        ),
    ],
    ids=[
        "same-credential",
        "same-store-name",
        "read-lists-write",
        "read-approves-delete",
        "connector",
    ],
)
def test_what_another_route_or_server_reaches_unheld(edit: Edit, reached: set[Any]) -> None:
    """T-2: a route to the same upstream with the same credential that holds nothing, or another
    server on the held route that lists a held tool without holding it."""
    assert unheld_reach(make(edit)) == reached


def test_a_held_route_to_the_same_upstream_that_holds_the_tool_isnt_unheld() -> None:
    def held_twin(raw: Raw) -> None:
        another_route(credential="notes-key", callers=["gateway"], stream=True)(raw)
        servers(raw)["twin"] = copy.deepcopy(servers(raw)["write"])
        servers(raw)["twin"]["route"] = "direct"

    assert unheld_reach(make(held_twin)) == frozenset()

    def twin_lets_delete_go(raw: Raw) -> None:
        servers(raw)["twin"]["tools"]["vault_approval"] = ["write"]

    assert unheld_reach(make(held_twin, twin_lets_delete_go)) == {("write", "delete")}

    def twin_holds_something_else(raw: Raw) -> None:
        tools = servers(raw)["twin"]["tools"]
        tools.update(include=["other"], allow=[], approve=["other"], vault_approval=["other"])

    assert unheld_reach(make(held_twin, twin_holds_something_else)) == frozenset()


def test_a_connector_route_that_holds_the_tool_isnt_unheld() -> None:
    def second_held(raw: Raw) -> None:
        raw["routes"].append({**copy.deepcopy(raw["routes"][1]), "name": "mail2", "prefix": "/m2"})
        servers(raw)["kit"]["slots"]["again"] = {
            "route": "mail2",
            "rules": [{"methods": ["POST"], "paths": ["/send"], "approved": True}],
        }

    assert unheld_reach(make(second_held)) == frozenset()


def test_another_credential_or_another_upstream_reaches_nothing_unheld() -> None:
    assert unheld_reach(make(another_route())) == frozenset()
    assert unheld_reach(make(another_route(credential="nope"))) == frozenset()
    elsewhere = another_route(credential="notes-key", upstream="https://other.notes.example")
    assert unheld_reach(make(elsewhere)) == frozenset()


def test_a_held_server_on_an_unknown_route_reaches_nothing() -> None:
    def unknown(raw: Raw) -> None:
        servers(raw)["write"]["route"] = "missing"

    assert unheld_reach(make(unknown)) == frozenset()


# --- what a route reaches, and with what ---------------------------------------------------------


def route(**fields: Any) -> Route:
    return Route.model_validate(
        {
            "name": "r",
            "prefix": "/r",
            "callers": ["gateway"],
            "rules": [{"methods": ["GET"], "paths": ["/"]}],
            **fields,
        }
    )


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"upstream": "https://api.example"}, "https://api.example:443"),
        ({"upstream": "https://API.Example.:443/v1"}, "https://api.example:443"),
        ({"upstream": "http://api.example"}, "http://api.example:80"),
        ({"upstream": "http://api.example:8080/x"}, "http://api.example:8080"),
        ({"upstream": "https://[::1]:8443"}, "https://::1:8443"),
        ({"upstream": "https://b\u00fccher.example"}, "https://xn--bcher-kva.example:443"),
        (
            {"upstream": "unix:/run/zoeymcp-bridge-x/mcp.sock"},
            "unix:/run/zoeymcp-bridge-x/mcp.sock",
        ),
        ({"connector": "mail-out"}, "connector:mail-out"),
    ],
    ids=["https", "case-dot-path", "http", "port", "ipv6", "idn", "unix", "connector"],
)
def test_the_target_of_a_route(fields: Raw, expected: str) -> None:
    assert target(route(**fields)) == expected


def test_a_route_with_no_usable_port_has_no_target() -> None:
    broken = route(upstream="https://api.example").model_copy(update={"upstream": "https://a:x/"})
    assert target(broken) is None
    other = route(upstream="https://api.example").model_copy(update={"upstream": "ftp://a/"})
    assert target(other) is None


def credentials_policy(credentials: Raw) -> Policy:
    return Policy.model_validate({"version": 1, "mode": "declarative", "credentials": credentials})


@pytest.mark.parametrize(
    ("one", "other", "same"),
    [
        (None, None, True),
        ("a", "a", True),
        ("a", None, False),
        ("a", "b", False),
        ("a", "a-again", True),
        ("basic", "basic-user", True),
        ("oauth", "oauth-secret", True),
        ("oauth", "oauth-public", False),
        ("unknown", "a", False),
    ],
    ids=[
        "none",
        "same-name",
        "one-none",
        "different",
        "same-store",
        "basic-username",
        "oauth-refresh",
        "oauth-public-id",
        "unknown",
    ],
)
def test_two_routes_send_the_same_credential(
    one: str | None, other: str | None, same: bool
) -> None:
    oauth = {
        "kind": "oauth2",
        "token_url": "https://auth.example/token",
        "client_id": "public-client",
        "refresh_token": "store:refresh",
    }
    policy = credentials_policy(
        {
            "a": {"kind": "header", "secret": "store:a"},
            "a-again": {"kind": "path", "template": "/k/{secret}", "secret": "store:a"},
            "b": {"kind": "header", "secret": "store:b"},
            "basic": {"kind": "basic", "username": "env:USER_X", "secret": "store:pw"},
            "basic-user": {"kind": "header", "secret": "env:USER_X"},
            "oauth": oauth,
            "oauth-secret": {"kind": "query", "param": "t", "secret": "store:refresh"},
            "oauth-public": {**oauth, "refresh_token": "store:other"},
        }
    )
    assert (
        same_credential(
            policy,
            route(credential=one, upstream="https://x.example"),
            route(credential=other, upstream="https://x.example"),
        )
        is same
    )
