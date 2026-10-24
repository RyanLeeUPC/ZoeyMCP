"""The attention decision (M6 design J.5; G-20, Y20, Y29): every state, ``quiet()``, a declined
tool whose pin moved, and the plain form the review report and the gateway's status carry."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

import pytest

from zoeymcp.common.policy.attention import Attention, attention, combined, loaded, quiet
from zoeymcp.common.policy.schema import Tools
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.gateway.toolkits import SelfPinned

A, B, C = ("sha256:" + digit * 64 for digit in "abc")
MEMBERS = ("drifted", "marked", "new", "changed_declined", "missing")


@dataclass(frozen=True)
class Server:
    tools: Tools
    review: Mapping[str, str] = field(default_factory=dict)
    declined: Mapping[str, str] = field(default_factory=dict)


def server(
    include: list[str], review: dict[str, str], declined: dict[str, str] | None = None
) -> Server:
    return Server(Tools(include=include, allow=include), review, declined or {})


def test_nothing_listed_and_nothing_included_is_quiet() -> None:
    found = attention({}, server([], {}), frozenset())
    assert found == Attention()
    assert quiet(found)
    assert found.as_dict() == {member: [] for member in MEMBERS}


def test_an_included_tool_at_its_pin_is_quiet() -> None:
    assert quiet(attention({"a": A}, server(["a"], {"a": A}), frozenset()))


def test_an_included_tool_at_another_pin_drifted() -> None:
    found = attention({"a": B}, server(["a"], {"a": A}), frozenset())
    assert found == Attention(drifted=("a",))
    assert not quiet(found)


def test_a_drifted_tool_with_its_mark_is_drifted_not_marked() -> None:
    found = attention({"a": B}, server(["a"], {"a": A}), frozenset({("a", A)}))
    assert found == Attention(drifted=("a",))


def test_a_mark_at_the_policys_pin_holds_a_matching_tool() -> None:
    found = attention({"a": A}, server(["a"], {"a": A}), frozenset({("a", A)}))
    assert found == Attention(marked=("a",))
    assert not quiet(found)


def test_a_mark_at_another_pin_has_cleared() -> None:
    """The policy re-pinned the tool: the mark from the old pin no longer holds."""
    assert quiet(attention({"a": B}, server(["a"], {"a": B}), frozenset({("a", A)})))


def test_a_mark_on_another_tool_holds_nothing_here() -> None:
    found = attention({"a": A}, server(["a", "b"], {"a": A, "b": B}), frozenset({("b", B)}))
    assert found == Attention(missing=("b",))


def test_a_listed_tool_neither_included_nor_declined_is_new() -> None:
    found = attention({"a": A}, server([], {}), frozenset())
    assert found == Attention(new=("a",))
    assert found.unreviewed() == ("a",)
    assert not quiet(found)


def test_a_pin_alone_doesnt_review_a_tool() -> None:
    """A pin for a tool that isn't included (only a warning in the policy) isn't a review."""
    assert attention({"a": A}, server([], {"a": A}), frozenset()) == Attention(new=("a",))


def test_a_tool_declined_at_its_pin_is_quiet() -> None:
    assert quiet(attention({"a": A}, server([], {}, {"a": A}), frozenset()))


def test_a_declined_tool_whose_pin_moved_counts_again() -> None:
    """Y20: the server changed a tool the operator left out, so nobody reviewed this one."""
    found = attention({"a": B}, server([], {}, {"a": A}), frozenset())
    assert found == Attention(changed_declined=("a",))
    assert found.unreviewed() == ("a",)
    assert not quiet(found)


def test_an_included_tool_is_never_new_or_declined() -> None:
    """Included and declined both (check refuses it, row 3): the include decides."""
    assert quiet(attention({"a": A}, server(["a"], {"a": A}, {"a": B}), frozenset()))


def test_an_included_tool_with_no_pin_is_left_to_the_review() -> None:
    """The listing reports it unreviewed and the review isn't clean; nothing here drifted."""
    assert quiet(attention({"a": A}, server(["a"], {}), frozenset()))


def test_an_included_tool_the_server_doesnt_list_is_missing() -> None:
    found = attention({}, server(["a"], {"a": A}), frozenset())
    assert found == Attention(missing=("a",))
    assert not quiet(found)


def test_an_included_tool_listed_with_no_pin_drifted() -> None:
    """Invalid or duplicate now: it no longer matches its pin, so it is hidden (or blocks the
    server under ``on_drift: fail``) until the operator acts."""
    found = attention({"a": None}, server(["a"], {"a": A}), frozenset())
    assert found == Attention(drifted=("a",))
    assert not quiet(found)
    marked = attention({"a": None}, server(["a"], {"a": A}), frozenset({("a", A)}))
    assert marked == Attention(drifted=("a",))


def test_an_included_tool_with_no_pin_either_side_is_left_to_the_review() -> None:
    assert quiet(attention({"a": None}, server(["a"], {}), frozenset()))


def test_a_tool_listed_with_no_pin_and_not_included_is_none_of_them() -> None:
    """Invalid or duplicate: the listing reports it on its own, and it can't be declined."""
    assert quiet(attention({"a": None}, server([], {}), frozenset()))
    assert quiet(attention({"a": None}, server([], {}, {"a": A}), frozenset()))


def test_every_state_at_once_each_sorted() -> None:
    listed: dict[str, str | None] = {
        "z_new": A,
        "a_new": A,
        "z_drift": B,
        "a_drift": B,
        "z_mark": A,
        "a_mark": A,
        "z_moved": B,
        "a_moved": B,
        "kept": A,
        "bad": None,
        "a_broken": None,
    }
    policy = server(
        ["z_drift", "a_drift", "z_mark", "a_mark", "z_gone", "a_gone", "a_broken"],
        {
            "z_drift": A,
            "a_drift": A,
            "z_mark": A,
            "a_mark": A,
            "z_gone": A,
            "a_gone": A,
            "a_broken": A,
        },
        {"z_moved": A, "a_moved": A, "kept": A},
    )
    found = attention(listed, policy, frozenset({("z_mark", A), ("a_mark", A)}))
    assert found == Attention(
        drifted=("a_broken", "a_drift", "z_drift"),
        marked=("a_mark", "z_mark"),
        new=("a_new", "z_new"),
        changed_declined=("a_moved", "z_moved"),
        missing=("a_gone", "z_gone"),
    )
    assert found.unreviewed() == ("a_moved", "a_new", "z_moved", "z_new")
    assert found.as_dict() == {
        "drifted": ["a_broken", "a_drift", "z_drift"],
        "marked": ["a_mark", "z_mark"],
        "new": ["a_new", "z_new"],
        "changed_declined": ["a_moved", "z_moved"],
        "missing": ["a_gone", "z_gone"],
    }


@pytest.mark.parametrize("member", MEMBERS)
def test_any_one_state_isnt_quiet(member: str) -> None:
    assert not quiet(loaded({member: ["a"]}))


def test_the_views_servers_and_a_self_pinned_toolkit_are_read_alike() -> None:
    view = ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": ["a"], "allow": ["a"], "approve": []},
            "review": {"a": A},
            "declined": {"b": B},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )
    listed: dict[str, str | None] = {"a": A, "b": B, "c": C}
    assert attention(listed, view, frozenset()) == Attention(new=("c",))
    self_pinned = SelfPinned(view.tools, {"a": A}, declined={"b": B})
    assert attention(listed, self_pinned, frozenset()) == Attention(new=("c",))


def test_the_plain_form_reads_back() -> None:
    found = Attention(drifted=("a",), new=("b", "c"), missing=("d",))
    assert loaded(found.as_dict()) == found
    assert loaded({}) == Attention()
    assert loaded({"new": ["c", "b"]}) == Attention(new=("b", "c"))  # sorted as it reads


def test_several_listings_combine_into_one() -> None:
    """A server's connections each list it: every name in any of them, once, sorted."""
    one = Attention(drifted=("b",), new=("x",))
    two = Attention(drifted=("a", "b"), marked=("m",), changed_declined=("d",), missing=("g",))
    assert combined([one, two]) == Attention(
        drifted=("a", "b"),
        marked=("m",),
        new=("x",),
        changed_declined=("d",),
        missing=("g",),
    )
    assert combined([one]) == one
    assert combined([]) == Attention()
    assert combined(iter([one, two])) == combined([two, one])
