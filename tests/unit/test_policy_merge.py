"""Merging a fragment into a policy (M7 design H.4, O.2 ``test_policy_merge.py``; CR-14, PC-3,
OPS-16).

Mappings merge key by key; a ``replace`` path takes the fragment's value whole; ``routes`` merges
by name and ``egress_private`` as a set; any other list or scalar is replaced. The header line
carries a fragment's replace paths, so ``check --with`` merges it exactly as the vault did.
"""

from __future__ import annotations

import copy
from typing import Any

import pytest

from zoeymcp.common.policy.merge import (
    CONTAINERS,
    REPLACE_HEADER,
    MergeConflict,
    Merged,
    describe,
    merge,
    replace_line,
    replace_paths,
    replaceable,
)

PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64
ROUTE = {
    "name": "notes",
    "prefix": "/notes",
    "upstream": "https://mcp.notes.example",
    "callers": ["gateway"],
    "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
}


def base() -> dict[str, Any]:
    return {
        "version": 1,
        "mode": "declarative",
        "egress_private": ["b.lan.example:443", "a.lan.example:443"],
        "credentials": {"stats": {"kind": "query", "param": "k", "secret": "store:s"}},
        "routes": [{**ROUTE, "name": "stats", "prefix": "/stats"}],
        "gateway": {
            "hosts": ["localhost"],
            "servers": {
                "notes": {
                    "kind": "remote",
                    "route": "stats",
                    "era": "auto",
                    "tools": {"include": ["read", "write"], "allow": ["read"]},
                    "review": {"read": PIN_A, "write": PIN_B},
                }
            },
        },
    }


def merged(result: Merged | MergeConflict) -> Merged:
    assert isinstance(result, Merged), result
    return result


def test_mappings_merge_key_by_key_and_name_what_they_add() -> None:
    fragment = {
        "credentials": {"notes": {"kind": "header", "secret": "store:n"}},
        "routes": [ROUTE],
        "gateway": {"servers": {"fresh": {"kind": "remote", "route": "notes"}}},
    }
    result = merged(merge(base(), fragment))
    expected = base()
    expected["credentials"]["notes"] = {"kind": "header", "secret": "store:n"}
    expected["routes"].append(ROUTE)
    expected["gateway"]["servers"]["fresh"] = {"kind": "remote", "route": "notes"}
    assert result.data == expected
    assert result.added == (
        ("credentials", "notes"),
        ("routes", "notes"),
        ("gateway", "servers", "fresh"),
    )
    assert result.replaced == ()


def test_what_the_fragment_adds_or_replaces_is_a_copy() -> None:
    fragment: dict[str, Any] = {
        "credentials": {"notes": {"kind": "header", "extra": {"a": 1}}},
        "routes": [{**ROUTE, "rules": [{"paths": ["/mcp"]}]}],
        "gateway": {"servers": {"notes": {"review": {"read": PIN_A}}}},
        "admin": {"origins": ["http://localhost:8081"]},
    }
    kept = copy.deepcopy(fragment)
    replace = [("gateway", "servers", "notes", "review")]
    result = merged(merge(base(), fragment, replace=replace))
    result.data["credentials"]["notes"]["extra"]["a"] = 2
    result.data["routes"][-1]["rules"][0]["paths"].append("/x")
    result.data["gateway"]["servers"]["notes"]["review"]["read"] = PIN_B
    result.data["admin"]["origins"].append("x")
    assert fragment == kept


def test_neither_input_changes() -> None:
    before, fragment = base(), {"gateway": {"servers": {"notes": {"era": "modern"}}}}
    kept = copy.deepcopy(fragment)
    result = merged(merge(before, fragment))
    assert before == base()
    assert fragment == kept
    result.data["gateway"]["servers"]["notes"]["era"] = "legacy"
    assert fragment == kept


def test_a_missing_container_reports_the_names_it_adds() -> None:
    fragment = {
        "credentials": {"notes": {"kind": "header"}},
        "gateway": {"servers": {"notes": {"kind": "remote"}}, "clients": {"a": {}}},
        "connectors": {"mail": {"kind": "smtp"}},
    }
    result = merged(merge({"version": 1}, fragment))
    assert result.data == {"version": 1, **fragment}
    assert result.added == (
        ("credentials", "notes"),
        ("gateway", "servers", "notes"),
        ("gateway", "clients", "a"),
        ("connectors", "mail"),
    )
    assert {("credentials",), ("gateway",), ("gateway", "servers")} <= CONTAINERS


def test_a_new_key_outside_a_container_is_added_whole() -> None:
    result = merged(merge({"version": 1}, {"admin": {"listen": "127.0.0.1:8081"}}))
    assert result.added == (("admin",),)


def test_a_scalar_is_replaced_and_recorded_only_when_it_differs() -> None:
    fragment = {"mode": "declarative", "gateway": {"servers": {"notes": {"era": "modern"}}}}
    result = merged(merge(base(), fragment))
    assert result.data["gateway"]["servers"]["notes"]["era"] == "modern"
    assert result.replaced == (("gateway", "servers", "notes", "era"),)
    assert result.added == ()


def test_other_lists_are_replaced_whole() -> None:
    result = merged(merge(base(), {"gateway": {"hosts": ["example.org"]}}))
    assert result.data["gateway"]["hosts"] == ["example.org"]
    assert result.replaced == (("gateway", "hosts"),)


def test_without_replace_a_review_merges_key_by_key() -> None:
    """Why a review names its blocks: merged key by key, a dropped tool's pin would stay."""
    fragment = {"gateway": {"servers": {"notes": {"review": {"read": PIN_B}}}}}
    result = merged(merge(base(), fragment))
    assert result.data["gateway"]["servers"]["notes"]["review"] == {"read": PIN_B, "write": PIN_B}


def test_a_re_review_dropping_a_tool_leaves_no_stale_pin() -> None:
    """CR-14, PC-3: the review's tools and review blocks replace the policy's whole."""
    blocks = {"tools": {"include": ["read"], "allow": ["read"]}, "review": {"read": PIN_A}}
    replace = [("gateway", "servers", "notes", "tools"), ("gateway", "servers", "notes", "review")]
    result = merged(merge(base(), {"gateway": {"servers": {"notes": blocks}}}, replace=replace))
    server = result.data["gateway"]["servers"]["notes"]
    assert server == {"kind": "remote", "route": "stats", "era": "auto", **blocks}
    assert result.replaced == tuple(replace)
    assert result.added == ()


def test_a_fragment_that_names_declined_replaces_it_whole() -> None:
    """M6 design A.4: the merge takes a replace path at ``declined``, like ``tools`` and
    ``review``. No review op names it yet (``test_policy_change.py``); one that does leaves no
    stale declined entry."""
    policy = base()
    policy["gateway"]["servers"]["notes"]["declined"] = {"read": PIN_A, "old": PIN_A}
    replace = [("gateway", "servers", "notes", "declined")]
    fragment = {"gateway": {"servers": {"notes": {"declined": {"new": PIN_B}}}}}
    result = merged(merge(policy, fragment, replace=replace))
    assert result.data["gateway"]["servers"]["notes"]["declined"] == {"new": PIN_B}
    assert result.replaced == tuple(replace)
    assert replace_paths(replace_line(replace)) == tuple(replace)


def test_a_replace_path_is_recorded_even_when_equal() -> None:
    server = base()["gateway"]["servers"]["notes"]
    replace = [("gateway", "servers", "notes", "review")]
    fragment = {"gateway": {"servers": {"notes": {"review": server["review"]}}}}
    assert merged(merge(base(), fragment, replace=replace)).replaced == tuple(replace)


def test_a_replaced_credential_takes_none_of_the_old_fields() -> None:
    fragment = {"credentials": {"stats": {"kind": "header", "secret": "store:h"}}}
    result = merged(merge(base(), fragment, replace=[("credentials", "stats")]))
    assert result.data["credentials"]["stats"] == {"kind": "header", "secret": "store:h"}
    assert result.replaced == (("credentials", "stats"),)


def test_routes_merge_by_name() -> None:
    same = copy.deepcopy(base()["routes"][0])
    result = merged(merge(base(), {"routes": [same, ROUTE]}))
    assert [route["name"] for route in result.data["routes"]] == ["stats", "notes"]
    assert result.added == (("routes", "notes"),)


def test_a_route_equal_once_defaults_are_written_out_merges() -> None:
    same = {**base()["routes"][0], "stream": False, "allow_insecure_upstream": False}
    result = merged(merge(base(), {"routes": [same]}))
    assert result.data["routes"] == base()["routes"]
    assert result.added == result.replaced == ()


def test_a_route_by_an_existing_name_that_differs_is_a_conflict() -> None:
    other = {**base()["routes"][0], "prefix": "/other"}
    result = merge(base(), {"routes": [other]})
    assert result == MergeConflict(
        ("routes", "stats"),
        "route stats is in the policy already and differs from the fragment's; remove one, or "
        "give the fragment's route another name",
    )


def test_an_invalid_route_by_an_existing_name_is_a_conflict() -> None:
    other = {"name": "stats", "prefix": "nope"}
    assert isinstance(merge(base(), {"routes": [other]}), MergeConflict)


@pytest.mark.parametrize("route", [{"prefix": "/x"}, "stats", {"name": 3}])
def test_a_route_without_a_name_is_a_conflict(route: Any) -> None:
    assert merge(base(), {"routes": [route]}) == MergeConflict(
        ("routes",), "a route in the fragment has no name"
    )


def test_routes_into_a_policy_without_routes() -> None:
    result = merged(merge({"version": 1}, {"routes": [ROUTE]}))
    assert result.data["routes"] == [ROUTE]
    assert result.added == (("routes", "notes"),)


def test_routes_that_are_not_lists_are_replaced() -> None:
    result = merged(merge({"routes": {"x": 1}}, {"routes": [ROUTE]}))
    assert result.data["routes"] == [ROUTE]
    assert result.replaced == (("routes",),)
    result = merged(merge({"routes": [ROUTE]}, {"routes": "none"}))
    assert result.data["routes"] == "none"


def test_only_the_top_level_routes_merge_by_name() -> None:
    result = merged(merge({"a": {"routes": [ROUTE]}}, {"a": {"routes": [{"name": "x"}]}}))
    assert result.data == {"a": {"routes": [{"name": "x"}]}}
    assert result.replaced == (("a", "routes"),)


def test_egress_private_merges_as_a_set_in_the_bases_order() -> None:
    """OPS-16: an onboarding fragment's entry is added; the base's entries are all kept."""
    fragment = {"egress_private": ["a.lan.example:443", "c.lan.example:443", "c.lan.example:443"]}
    result = merged(merge(base(), fragment))
    assert result.data["egress_private"] == [
        "b.lan.example:443",
        "a.lan.example:443",
        "c.lan.example:443",
    ]
    assert result.added == (("egress_private", "c.lan.example:443"),)
    assert result.replaced == ()


def test_egress_private_into_a_policy_without_it() -> None:
    result = merged(merge({"version": 1}, {"egress_private": ["a.lan.example:443"]}))
    assert result.data["egress_private"] == ["a.lan.example:443"]
    assert result.added == (("egress_private", "a.lan.example:443"),)


def test_only_the_top_level_egress_private_is_a_set() -> None:
    result = merged(merge({"a": {"egress_private": ["x"]}}, {"a": {"egress_private": ["y"]}}))
    assert result.data == {"a": {"egress_private": ["y"]}}


def test_egress_private_that_is_not_a_list_is_replaced() -> None:
    result = merged(merge({"egress_private": "x"}, {"egress_private": ["y"]}))
    assert result.data["egress_private"] == ["y"]
    assert result.replaced == (("egress_private",),)


# --- the header line -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "ok"),
    [
        (("credentials", "notes"), True),
        (("gateway", "servers", "notes", "tools"), True),
        (("gateway", "servers", "notes", "review"), True),
        (("gateway", "servers", "notes", "declined"), True),
        # M6 design L.7: a review of a server enabling prompts or resources writes those too.
        (("gateway", "servers", "notes", "prompts"), True),
        (("gateway", "servers", "notes", "resources"), True),
        (("gateway", "servers", "notes", "enable"), False),
        (("credentials",), False),
        (("credentials", "Notes"), False),
        (("connectors", "notes"), False),
        (("routes", "notes"), False),
        (("gateway", "servers", "notes"), False),
        (("gateway", "servers", "notes", "era"), False),
        (("gateway", "servers", "No", "tools"), False),
        (("gateway", "clients", "notes", "tools"), False),
        (("gateway", "servers", "notes", "tools", "include"), False),
        (("x", "servers", "notes", "tools"), False),
        (("gateway", "x", "notes", "tools"), False),
        ((), False),
    ],
)
def test_only_a_credential_or_a_servers_review_blocks_are_replaceable(
    path: tuple[str, ...], ok: bool
) -> None:
    assert replaceable(path) is ok


def test_the_header_line_round_trips() -> None:
    paths = (("gateway", "servers", "notes", "tools"), ("credentials", "notes"))
    line = replace_line(paths)
    assert line == "# zoeymcp replace: gateway.servers.notes.tools credentials.notes"
    assert line.startswith(REPLACE_HEADER)
    assert replace_paths(f"# zoeymcp: title\n{line}\n# added: x\ngateway: {{}}\n") == paths


def test_replace_line_refuses_a_path_no_fragment_replaces() -> None:
    with pytest.raises(ValueError, match="a fragment can't replace routes"):
        replace_line([("routes",)])


def test_replace_paths_reads_only_the_header() -> None:
    text = (
        "        # zoeymcp: title\n"
        "\n"
        "        # zoeymcp replace: credentials.a\n"
        "        # zoeymcp replace: credentials.b credentials.c\n"
        "credentials: {}\n"
        "# zoeymcp replace: credentials.d\n"
    )
    assert replace_paths(text) == (("credentials", "a"), ("credentials", "b"), ("credentials", "c"))
    assert replace_paths("credentials: {}\n") == ()
    assert replace_paths("# zoeymcp: replace credentials.a\n") == ()


@pytest.mark.parametrize("item", ["routes", "gateway.servers.notes", "credentials.a.b", "x"])
def test_replace_paths_refuses_a_path_no_fragment_replaces(item: str) -> None:
    with pytest.raises(ValueError, match=f"the header names {item}, which a fragment can't"):
        replace_paths(f"# zoeymcp replace: credentials.a {item}\n")


@pytest.mark.parametrize(
    ("path", "said"),
    [
        (("credentials", "notes"), "credentials.notes"),
        (("routes", "notes"), "routes notes"),
        (("egress_private", "a.lan.example:443"), "egress_private a.lan.example:443"),
        (("routes",), "routes"),
        (("gateway", "servers", "notes", "tools"), "gateway.servers.notes.tools"),
        (("gateway", "routes"), "gateway.routes"),
    ],
)
def test_describe(path: tuple[str, ...], said: str) -> None:
    assert describe(path) == said
