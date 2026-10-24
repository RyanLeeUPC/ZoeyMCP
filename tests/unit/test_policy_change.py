"""The change object (M7 design H.1, O.2 ``test_policy_change.py``; M6 design G.3, J.3).

A change holds the schema's own models, so every value in it has passed its validator; its plain
form is what fragment 1 and fragment 2 load back to (E.2, E.4); ``apply`` merges it into the
running policy with the merge ``check --with`` runs, refusing a taken name (``name_taken``) and a
change the merged policy can't take (``diff_invalid``). M6: managed mode's three portal ops
(``MoveToAllow``, ``SetClientServers``, ``SetConnectorLimits``), a managed review's ``declined``
block written whole, and the portal's bounds on its ops (``portal_env_ref``,
``route_reuses_credential``), a test per op.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from zoeymcp.common.policy import Policy, check_policy, parse_policy
from zoeymcp.common.policy.change import (
    AddCredential,
    AddEgressPrivate,
    AddRoute,
    AddServer,
    ChangeRefused,
    Comment,
    MoveToAllow,
    Op,
    PolicyChange,
    SetClientServers,
    SetConnectorLimits,
    SetCredential,
    SetScope,
    SetServerReview,
    apply,
    from_portal,
    validate,
)
from zoeymcp.common.policy.schema import (
    HeaderCredential,
    OAuth2Credential,
    RemoteServer,
    Route,
    ToolkitServer,
    Tools,
)

from .conftest import EXAMPLE_POLICY

PIN_A = "sha256:" + "a" * 64
PIN_B = "sha256:" + "b" * 64
RESOURCE = "https://mcp.notes.example/mcp"
# Fragment 1's credential, as A.4 writes it, with an endpoint query (Q41).
NOTES_CREDENTIAL: dict[str, Any] = {
    "kind": "oauth2",
    "token_url": "https://auth.notes.example/oauth/token?tenant=notes",
    "authorize_url": "https://auth.notes.example/oauth/authorize",
    "issuer": "https://auth.notes.example",
    "require_iss": True,
    "revocation_url": "https://auth.notes.example/oauth/revoke",
    "resource_metadata": "https://mcp.notes.example/.well-known/oauth-protected-resource/mcp",
    "client_id": "zc_4f1c9a",
    "client_auth": "none",
    "refresh_token": "store:notes-refresh",
    "rotates": True,
    "redirect_uri": "http://127.0.0.1/callback/notes",
    "scope": "notes.read notes.write offline_access",
    "extra_params": {"resource": RESOURCE},
    "authorize_params": {"resource": RESOURCE},
}
NOTES_ROUTE: dict[str, Any] = {
    "name": "notes",
    "prefix": "/notes",
    "upstream": "https://mcp.notes.example",
    "credential": "notes",
    "callers": ["gateway"],
    "stream": True,
    "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
}
NOTES_SERVER: dict[str, Any] = {
    "kind": "remote",
    "route": "notes",
    "path": "/mcp",
    "tools": {"include": []},
}
FRAGMENT_1_TITLE = (
    "onboarding notes (1 of 2). Merge into your policy; nothing here replaces a key you have."
)


def example() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def notes_change(*, private: bool = True) -> PolicyChange:
    """Fragment 1 for a server named notes (E.2)."""
    ops: list[Any] = [
        AddCredential("notes", OAuth2Credential.model_validate(NOTES_CREDENTIAL)),
        AddRoute(Route.model_validate(NOTES_ROUTE)),
        AddServer("notes", RemoteServer.model_validate(NOTES_SERVER)),
    ]
    if private:
        ops.append(AddEgressPrivate("mcp.lan.example:443"))
    return PolicyChange(FRAGMENT_1_TITLE, tuple(ops))


def review_change(
    server: str = "broker-read", review: dict[str, str] | None = None, era: str | None = "modern"
) -> PolicyChange:
    """Fragment 2 for one server (E.4): one tool kept of the example's two."""
    tools = Tools(include=["get_quote"], allow=["get_quote"])
    pins = {"get_quote": PIN_A} if review is None else review
    return PolicyChange(
        f"review of {server} (2 of 2)", (SetServerReview(server, tools, pins, era=era),)
    )


# --- the plain form ------------------------------------------------------------------------------


def test_fragment_1s_plain_form_is_e2s() -> None:
    assert notes_change().data() == {
        "credentials": {"notes": NOTES_CREDENTIAL},
        "routes": [NOTES_ROUTE],
        "gateway": {"servers": {"notes": NOTES_SERVER}},
        "egress_private": ["mcp.lan.example:443"],
    }


def test_the_plain_form_holds_only_what_was_set_and_no_none() -> None:
    credential = OAuth2Credential(
        kind="oauth2", token_url="https://as.example/token", client_id="c", issuer=None
    )
    change = PolicyChange("t", (AddCredential("c", credential),))
    assert change.data() == {
        "credentials": {
            "c": {"kind": "oauth2", "token_url": "https://as.example/token", "client_id": "c"}
        }
    }


def test_fragment_2s_plain_form_is_e4s() -> None:
    assert review_change().data() == {
        "gateway": {
            "servers": {
                "broker-read": {
                    "tools": {"include": ["get_quote"], "allow": ["get_quote"]},
                    "review": {"get_quote": PIN_A},
                    "era": "modern",
                }
            }
        }
    }
    assert "era" not in review_change(era=None).data()["gateway"]["servers"]["broker-read"]


def test_two_servers_share_one_gateway_block() -> None:
    server = RemoteServer.model_validate(NOTES_SERVER)
    change = PolicyChange(
        "t",
        (
            AddServer("notes", server),
            SetServerReview("broker-read", Tools(), {}),
            AddEgressPrivate("a.lan.example:443"),
            AddEgressPrivate("b.lan.example:443"),
        ),
    )
    data = change.data()
    assert list(data["gateway"]["servers"]) == ["notes", "broker-read"]
    assert data["egress_private"] == ["a.lan.example:443", "b.lan.example:443"]


def test_a_header_credential_and_a_set_credential() -> None:
    header = HeaderCredential(kind="header", secret="store:bridge-fetch-token")
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    change = PolicyChange("t", (AddCredential("fetch", header), SetCredential("notes", oauth)))
    assert change.data() == {
        "credentials": {
            "fetch": {"kind": "header", "secret": "store:bridge-fetch-token"},
            "notes": NOTES_CREDENTIAL,
        }
    }


def test_replace_names_the_review_blocks_and_a_set_credential() -> None:
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    change = PolicyChange(
        "t",
        (
            AddCredential("other", oauth),
            SetServerReview("notes", Tools(), {}),
            SetCredential("notes", oauth),
            Comment("changed_was", "notes", "client_id"),
        ),
    )
    assert change.replace() == (
        ("gateway", "servers", "notes", "tools"),
        ("gateway", "servers", "notes", "review"),
        ("credentials", "notes"),
    )
    assert notes_change().replace() == ()
    # Each op's paths add to those before it, whatever its place.
    later = PolicyChange(
        "t", (SetCredential("notes", oauth), SetServerReview("notes", Tools(), {}))
    )
    assert later.replace() == (
        ("credentials", "notes"),
        ("gateway", "servers", "notes", "tools"),
        ("gateway", "servers", "notes", "review"),
    )


def test_comments_are_kept_in_order_and_hold_no_data() -> None:
    first, second = Comment("added", "notes"), Comment("suggested", "get_quote", "read-only")
    change = PolicyChange("t", (first, AddEgressPrivate("a.lan.example:443"), second))
    assert change.comments() == (first, second)
    assert change.data() == {"egress_private": ["a.lan.example:443"]}
    assert PolicyChange("t").data() == {}
    assert PolicyChange("t").comments() == ()


# --- what an op holds ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("ops", "named"),
    [
        (("cred", "cred"), "credentials.notes"),
        (("cred", "set"), "credentials.notes"),
        (("server", "review"), "gateway.servers.notes"),
        (("route", "route"), "routes notes"),
        (("private", "private"), "egress_private a.lan.example:443"),
    ],
)
def test_a_change_names_each_thing_once(ops: tuple[str, str], named: str) -> None:
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    made: dict[str, Op] = {
        "cred": AddCredential("notes", oauth),
        "set": SetCredential("notes", oauth),
        "server": AddServer("notes", RemoteServer.model_validate(NOTES_SERVER)),
        "review": SetServerReview("notes", Tools(), {}),
        "route": AddRoute(Route.model_validate(NOTES_ROUTE)),
        "private": AddEgressPrivate("a.lan.example:443"),
    }
    with pytest.raises(ValueError, match=rf"^the change names {re.escape(named)} twice$"):
        PolicyChange("t", (made[ops[0]], made[ops[1]]))


def test_comments_may_repeat_a_subject_and_a_name_may_differ_by_kind() -> None:
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    PolicyChange(
        "t",
        (
            Comment("added", "notes"),
            Comment("added", "notes"),
            AddCredential("notes", oauth),
            AddServer("notes", RemoteServer.model_validate(NOTES_SERVER)),
            AddRoute(Route.model_validate(NOTES_ROUTE)),
        ),
    )


@pytest.mark.parametrize("name", ["Notes", "", "-notes", "no tes", "notes\n", "a" * 64])
def test_a_name_is_a_policy_name(name: str) -> None:
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    server = RemoteServer.model_validate(NOTES_SERVER)
    for make in (
        lambda: AddCredential(name, oauth),
        lambda: SetCredential(name, oauth),
        lambda: AddServer(name, server),
        lambda: SetServerReview(name, Tools(), {}),
    ):
        with pytest.raises(ValueError, match="isn't a policy name"):
            make()


@pytest.mark.parametrize(
    "entry",
    [
        "MCP.lan.example:443",
        "mcp.lan.example",
        "mcp.lan.example:0",
        "a:1\n",
        443,
        b"mcp.lan.example:443",  # strict: only a str
    ],
)
def test_an_egress_private_entry_is_the_schemas(entry: Any) -> None:
    with pytest.raises(ValidationError):
        AddEgressPrivate(entry)


@pytest.mark.parametrize(
    "review",
    [
        {"get_quote": "sha256:" + "A" * 64},
        {"get_quote": "sha256:" + "a" * 63},
        {"get quote": PIN_A},
        {"get_quote": PIN_A + "\n"},
        {"get_quote": PIN_A.encode()},  # strict: only a str
    ],
)
def test_a_review_holds_tool_names_and_pins(review: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        SetServerReview("notes", Tools(), review)
    with pytest.raises(ValidationError):  # a declined block is the same map (M6 design J.3)
        SetServerReview("notes", Tools(), {}, declined=review)


@pytest.mark.parametrize("era", ["Modern", "bridge", ""])
def test_an_era_is_the_schemas(era: str) -> None:
    with pytest.raises(ValidationError):
        SetServerReview("notes", Tools(), {}, era=era)


def test_a_review_is_a_copy_no_caller_can_change() -> None:
    pins = {"get_quote": PIN_A}
    op = SetServerReview("notes", Tools(), pins, declined=pins)
    pins["cancel_order"] = PIN_B
    assert dict(op.review) == {"get_quote": PIN_A}
    assert op.declined is not None
    assert dict(op.declined) == {"get_quote": PIN_A}
    with pytest.raises(TypeError):
        op.review["x"] = PIN_B  # type: ignore[index]
    with pytest.raises(TypeError):
        op.declined["x"] = PIN_B  # type: ignore[index]
    assert SetServerReview("notes", Tools(), pins).declined is None


@pytest.mark.parametrize("subject", ["get quote", "", "a\nb", "x" * 129, "caf\u00e9", b"x"])
def test_a_comments_subject_is_a_tool_or_policy_name(subject: Any) -> None:
    with pytest.raises(ValidationError):
        Comment("added", subject)


def test_ops_are_frozen() -> None:
    op = AddEgressPrivate("a.lan.example:443")
    with pytest.raises(AttributeError):
        op.entry = "b.lan.example:443"  # type: ignore[misc]


# --- apply and validate --------------------------------------------------------------------------


def test_an_empty_change_gives_back_the_policy() -> None:
    policy = example()
    assert apply(policy, PolicyChange("t", (Comment("added", "x"),))) == policy


def test_fragment_1_adds_the_credential_route_server_and_private_entry() -> None:
    policy = example()
    merged = apply(policy, notes_change())
    assert merged.credentials["notes"] == OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    assert [route.name for route in merged.routes] == [
        *(route.name for route in policy.routes),
        "notes",
    ]
    assert merged.gateway is not None
    assert merged.gateway.servers["notes"] == RemoteServer.model_validate(NOTES_SERVER)
    assert merged.egress_private == ["mcp.lan.example:443"]
    # Nothing that was there changed.
    for name, credential in policy.credentials.items():
        assert merged.credentials[name] == credential
    assert policy.gateway is not None
    for name, server in policy.gateway.servers.items():
        assert merged.gateway.servers[name] == server
    assert merged.connectors == policy.connectors
    assert merged.admin == policy.admin


def test_validate_is_check_on_the_merged_policy() -> None:
    findings = validate(example(), notes_change())
    assert [(f.level, f.path) for f in findings] == [
        ("warning", "credentials.broker-mcp.authorize_url"),
        ("warning", "egress_private[0]"),
        ("warning", "gateway.servers.notes"),
    ]
    assert not any(f.level == "error" for f in validate(example(), notes_change(private=False)))


def test_apply_into_a_policy_without_those_blocks() -> None:
    policy = Policy.model_validate({"version": 1, "mode": "declarative"})
    merged = apply(policy, notes_change(private=False))
    assert list(merged.credentials) == ["notes"]
    assert merged.gateway is not None
    assert list(merged.gateway.servers) == ["notes"]
    # A default the policy leaves out stays unset, as check --with loads the merge.
    assert merged.model_fields_set == {"version", "mode", "credentials", "routes", "gateway"}


@pytest.mark.parametrize(
    ("op", "path"),
    [
        (
            AddCredential("broker-mcp", OAuth2Credential.model_validate(NOTES_CREDENTIAL)),
            "credentials.broker-mcp",
        ),
        (AddRoute(Route.model_validate({**NOTES_ROUTE, "name": "stats"})), "routes stats"),
        (
            AddServer("broker-read", RemoteServer.model_validate(NOTES_SERVER)),
            "gateway.servers.broker-read",
        ),
    ],
)
def test_an_add_of_a_taken_name_is_name_taken(op: Any, path: str) -> None:
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), PolicyChange("t", (op,)))
    assert (caught.value.reason, caught.value.path, caught.value.messages) == (
        "name_taken",
        path,
        (),
    )
    assert str(caught.value) == f"name_taken: {path}"


def test_a_route_equal_to_the_policys_is_still_name_taken() -> None:
    policy = example()
    same = AddRoute(policy.routes[0])
    with pytest.raises(ChangeRefused, match="name_taken: routes stats"):
        apply(policy, PolicyChange("t", (same,)))


def test_a_review_replaces_tools_and_review_whole() -> None:
    """A re-review that drops a tool leaves no stale pin (CR-14, PC-3)."""
    merged = apply(example(), review_change())
    assert merged.gateway is not None
    server = merged.gateway.servers["broker-read"]
    assert isinstance(server, RemoteServer)
    assert server.tools == Tools(include=["get_quote"], allow=["get_quote"])
    assert server.review == {"get_quote": PIN_A}
    assert server.era == "modern"
    assert server.route == "broker-mcp"


def test_a_review_keeps_the_servers_declined_block() -> None:
    """An op with no ``declined`` (M7's fragment) leaves the server's block as it is, so a
    review that includes a declined tool fails check (row 3) until the entry is deleted by hand;
    the CLI's review writes the block whole once the server has one (M6 design J.3), below."""
    raw = yaml.safe_load(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    raw["gateway"]["servers"]["broker-read"]["declined"] = {"get_news": PIN_B}
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "example")
    tools = Tools(include=["get_quote", "get_news"], allow=["get_quote", "get_news"])
    pins = {"get_quote": PIN_A, "get_news": PIN_A}
    change = PolicyChange("t", (SetServerReview("broker-read", tools, pins, era="modern"),))
    assert ("gateway", "servers", "broker-read", "declined") not in change.replace()
    merged = apply(policy, change)
    assert merged.gateway is not None
    assert merged.gateway.servers["broker-read"].declined == {"get_news": PIN_B}
    assert [(f.path, f.message) for f in validate(policy, change) if f.level == "error"] == [
        ("gateway.servers.broker-read.declined", "'get_news' is both included and declined")
    ]


def test_a_review_with_a_declined_block_replaces_it_whole() -> None:
    raw = yaml.safe_load(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    raw["gateway"]["servers"]["broker-read"]["declined"] = {"get_news": PIN_B, "old": PIN_B}
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "example")
    tools = Tools(include=["get_quote", "get_news"], allow=["get_quote", "get_news"])
    pins = {"get_quote": PIN_A, "get_news": PIN_A}
    for declined, kept in (({"other": PIN_A}, {"other": PIN_A}), ({}, {})):
        op = SetServerReview("broker-read", tools, pins, era="modern", declined=declined)
        change = PolicyChange("t", (op,))
        assert change.replace() == tuple(
            ("gateway", "servers", "broker-read", block)
            for block in ("tools", "review", "declined")
        )
        assert change.data()["gateway"]["servers"]["broker-read"]["declined"] == kept
        merged = apply(policy, change)
        assert merged.gateway is not None
        assert merged.gateway.servers["broker-read"].declined == kept
        assert [f for f in validate(policy, change) if f.level == "error"] == []


def test_a_review_without_an_era_keeps_the_servers() -> None:
    merged = apply(example(), review_change(era=None))
    assert merged.gateway is not None
    assert merged.gateway.servers["broker-read"].era == "modern"  # type: ignore[union-attr]
    merged = apply(example(), review_change("broker-trade", era=None))
    assert merged.gateway is not None
    assert merged.gateway.servers["broker-trade"].era == "auto"  # type: ignore[union-attr]


def test_a_review_of_a_toolkit_server_without_an_era() -> None:
    change = PolicyChange("t", (SetServerReview("mail", Tools(include=[]), {}),))
    merged = apply(example(), change)
    assert merged.gateway is not None
    server = merged.gateway.servers["mail"]
    assert isinstance(server, ToolkitServer)
    assert (server.tools, server.review) == (Tools(), {})


def test_a_change_the_schema_refuses_is_diff_invalid() -> None:
    # A toolkit server has no era.
    change = PolicyChange("t", (SetServerReview("mail", Tools(), {}, era="modern"),))
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), change)
    assert (caught.value.reason, caught.value.path) == ("diff_invalid", "(document)")
    assert caught.value.messages == (
        "gateway.servers.mail.toolkit.era: Extra inputs are not permitted",
    )
    two = ChangeRefused("diff_invalid", "(document)", ("a: one", "b: two"))
    assert str(two) == "diff_invalid: (document); a: one; b: two"


def test_a_portal_callback_for_an_unlisted_origin_is_diff_invalid() -> None:
    credential = {**NOTES_CREDENTIAL, "redirect_uri": "http://localhost:9999/oauth/callback/notes"}
    change = PolicyChange(
        "t", (AddCredential("notes", OAuth2Credential.model_validate(credential)),)
    )
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), change)
    assert caught.value.reason == "diff_invalid"
    (message,) = caught.value.messages
    assert message.startswith("credentials.notes.redirect_uri: ")


def test_a_review_of_a_missing_server_is_diff_invalid() -> None:
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), review_change("absent"))
    assert (caught.value.reason, caught.value.path, caught.value.messages) == (
        "diff_invalid",
        "gateway.servers.absent",
        ("the policy has no such server",),
    )
    assert (
        str(caught.value) == "diff_invalid: gateway.servers.absent; the policy has no such server"
    )
    without_gateway = Policy.model_validate({"version": 1, "mode": "declarative"})
    with pytest.raises(ChangeRefused, match=r"diff_invalid: gateway\.servers\.broker-read"):
        apply(without_gateway, review_change())


def test_a_set_credential_replaces_the_credential_whole() -> None:
    oauth = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "token_url": "https://auth.broker.example/oauth/token"}
    )
    merged = apply(example(), PolicyChange("t", (SetCredential("broker-mcp", oauth),)))
    # expected_scopes, which the new credential doesn't set, is gone, not kept.
    assert merged.credentials["broker-mcp"] == oauth
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), PolicyChange("t", (SetCredential("absent", oauth),)))
    assert (caught.value.reason, caught.value.path, caught.value.messages) == (
        "diff_invalid",
        "credentials.absent",
        ("the policy has no such credential",),
    )


def test_a_set_scope_merges_into_the_credential() -> None:
    """Health's step-up fragment (D.5, SPEC-11): only the scope changes, nothing is replaced,
    so a credential written by hand keeps every other field."""
    op = SetScope("broker-mcp", ("tools.read", "tools.call"))
    change = PolicyChange("t", (op,))
    assert op.scope == "tools.read tools.call"
    assert change.data() == {
        "credentials": {"broker-mcp": {"kind": "oauth2", "scope": "tools.read tools.call"}}
    }
    assert change.replace() == ()
    before = example().credentials["broker-mcp"]
    after = apply(example(), change).credentials["broker-mcp"]
    assert isinstance(after, OAuth2Credential)
    assert after.scope == "tools.read tools.call"
    assert after.model_dump(exclude={"scope"}) == before.model_dump(exclude={"scope"})
    assert SetScope("broker-mcp", ("a", "b"), ",").scope == "a,b"
    # Longer than the schema's scope: the merged policy refuses it.
    long = tuple(chr(97 + n) * 250 for n in range(9))
    with pytest.raises(ChangeRefused, match=r"^diff_invalid: \(document\); credentials"):
        apply(example(), PolicyChange("t", (SetScope("broker-mcp", long),)))
    for name in ("music-stats", "absent"):
        with pytest.raises(ChangeRefused) as caught:
            apply(example(), PolicyChange("t", (SetScope(name, ("a",)),)))
        assert (caught.value.reason, caught.value.path, caught.value.messages) == (
            "diff_invalid",
            f"credentials.{name}",
            ("the policy has no such oauth2 credential",),
        )
    assert isinstance(before, OAuth2Credential)
    with pytest.raises(ValueError, match=r"names credentials\.broker-mcp twice"):
        PolicyChange("t", (op, SetCredential("broker-mcp", before)))


@pytest.mark.parametrize(
    ("name", "scopes", "separator", "message"),
    [
        ("Notes", ("a",), " ", "isn't a policy name"),
        ("notes", (), " ", "^1 to 64 scopes$"),
        ("notes", tuple(f"s{n}" for n in range(65)), " ", "^1 to 64 scopes$"),
        ("notes", ("a b",), " ", "isn't a scope token"),
        ("notes", ("a,b",), ",", "isn't a scope token"),
        ("notes", ('a"b',), " ", "isn't a scope token"),
        ("notes", ("",), " ", "isn't a scope token"),
        ("notes", ("a" * 257,), " ", "isn't a scope token"),
        ("notes", ("a",), ";", "literal_error"),
    ],
)
def test_a_set_scope_holds_schema_scope_tokens(
    name: str, scopes: tuple[str, ...], separator: str, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        SetScope(name, scopes, separator)  # type: ignore[arg-type]
    assert SetScope("notes", ("a,b",)).scope == "a,b"
    assert SetScope("notes", tuple(f"s{n}" for n in range(64)), " ").scopes[-1] == "s63"
    assert SetScope("notes", ("a" * 256,)).scope == "a" * 256


def test_an_egress_private_entry_the_policy_has_is_kept_once() -> None:
    policy = apply(example(), notes_change())
    again = PolicyChange("t", (AddEgressPrivate("mcp.lan.example:443"),))
    assert apply(policy, again).egress_private == ["mcp.lan.example:443"]


def test_apply_reads_the_policy_by_its_document_names() -> None:
    """The mail connector's from: field is from_ in the model; the merge writes it back as from."""
    merged = apply(example(), notes_change())
    assert merged.connectors == example().connectors


# --- managed mode's ops (M6 design G.3) ---------------------------------------------------------

PLACE = "sha256:f317bc9db239b40a77b4c454dd6dae362008d39485fcb2359844c73cd998ef97"
CANCEL = "sha256:26c3ac15931603b2f20397630050036633fd11d56ea08bd91e52895e92313ac7"
SEND = "sha256:34aecee572ddd193955a4678774a9dc8cdd8c3a08f05f84c89e38b1c3631db32"


def test_a_move_to_allow_moves_one_included_approve_tool() -> None:
    """J3, J.4: the tool leaves approve for allow at the pin the operator was shown; nothing
    else changes, and the change has no fragment."""
    change = PolicyChange("t", (MoveToAllow("broker-trade", "tool", "cancel_order", CANCEL),))
    policy = example()
    merged = apply(policy, change)
    assert merged.gateway is not None
    assert policy.gateway is not None
    server = merged.gateway.servers["broker-trade"]
    assert server.tools == Tools(
        include=["place_order", "cancel_order"], allow=["cancel_order"], approve=["place_order"]
    )
    before = policy.gateway.servers["broker-trade"]
    assert server.model_dump(exclude={"tools"}) == before.model_dump(exclude={"tools"})
    for name, other in policy.gateway.servers.items():
        if name != "broker-trade":
            assert merged.gateway.servers[name] == other
    assert change.replace() == ()
    with pytest.raises(ValueError, match=r"^a move to allow has no fragment"):
        change.data()


def test_a_move_keeps_the_blocks_the_other_ops_replace_whole() -> None:
    """The move's own tools block adds to the paths the change replaces, so a credential set in
    the same change is still replaced whole, not merged."""
    oauth = OAuth2Credential.model_validate(
        {**NOTES_CREDENTIAL, "token_url": "https://auth.broker.example/oauth/token"}
    )
    move = MoveToAllow("broker-trade", "tool", "cancel_order", CANCEL)
    merged = apply(example(), PolicyChange("t", (SetCredential("broker-mcp", oauth), move)))
    assert merged.credentials["broker-mcp"] == oauth  # expected_scopes gone, not kept
    assert merged.gateway is not None
    assert merged.gateway.servers["broker-trade"].tools.allow == ["cancel_order"]


@pytest.mark.parametrize(
    ("op", "path", "message"),
    [
        (
            MoveToAllow("absent", "tool", "x", CANCEL),
            "gateway.servers.absent",
            "the policy has no such server",
        ),
        (
            MoveToAllow("broker-read", "tool", "get_quote", PIN_A),
            "gateway.servers.broker-read.tools",
            "get_quote isn't an included approve tool",
        ),
        (
            MoveToAllow("broker-trade", "tool", "cancel_order", PIN_A),
            "gateway.servers.broker-trade.review.cancel_order",
            "the policy pins another definition",
        ),
    ],
    ids=["no-server", "not-approve", "other-pin"],
)
def test_a_move_the_policy_cant_take_is_diff_invalid(op: Any, path: str, message: str) -> None:
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), PolicyChange("t", (op,)))
    assert (caught.value.reason, caught.value.path, caught.value.messages) == (
        "diff_invalid",
        path,
        (message,),
    )


def test_a_move_needs_the_tool_included_and_a_pin_unless_pinning_is_off() -> None:
    raw = yaml.safe_load(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    raw["gateway"]["servers"]["broker-trade"]["tools"]["include"] = ["place_order"]
    loose = parse_policy(yaml.safe_dump(raw, sort_keys=False), "example")
    op = MoveToAllow("broker-trade", "tool", "cancel_order", CANCEL)
    with pytest.raises(ChangeRefused, match="cancel_order isn't an included approve tool"):
        apply(loose, PolicyChange("t", (op,)))
    # A toolkit with pinning on holds its pin; with pinning off any reported pin is the one.
    mail = MoveToAllow("mail", "tool", "send_note", PIN_A)
    with pytest.raises(ChangeRefused, match="the policy pins another definition"):
        apply(example(), PolicyChange("t", (mail,)))
    assert apply(example(), PolicyChange("t", (replace(mail, pin=SEND),)))
    raw = yaml.safe_load(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    raw["gateway"]["servers"]["mail"]["pinning"] = "off"
    del raw["gateway"]["servers"]["mail"]["review"]
    off = parse_policy(yaml.safe_dump(raw, sort_keys=False), "example")
    merged = apply(off, PolicyChange("t", (mail,)))
    assert merged.gateway is not None
    tools = merged.gateway.servers["mail"].tools
    assert tools == Tools(include=["send_note"], allow=["send_note"])


@pytest.mark.parametrize(
    ("make", "match"),
    [
        (lambda: MoveToAllow("Notes", "tool", "x", PIN_A), "isn't a policy name"),
        (lambda: MoveToAllow("notes", "prompt", "x", PIN_A), "'prompt' isn't a kind a move"),
        (lambda: MoveToAllow("notes", "tool", "a b", PIN_A), "pattern"),
        (lambda: MoveToAllow("notes", "tool", "x", "sha256:" + "A" * 64), "pattern"),
        # strict: only a str
        (lambda: MoveToAllow("notes", "tool", b"x", PIN_A), "valid string"),  # type: ignore[arg-type]
        (lambda: MoveToAllow("notes", "tool", "x", PIN_A.encode()), "valid string"),  # type: ignore[arg-type]
        (lambda: SetClientServers("Agent", ()), "isn't a policy name"),
        (lambda: SetClientServers("agent1", ("mail", "Mail")), "isn't a policy name"),
        (
            lambda: SetClientServers("agent1", ("mail", "mail")),
            "^a client's servers name each server once$",
        ),
        (
            lambda: SetConnectorLimits("mail-out"),
            "^a connector's limits change sets one field or more$",
        ),
        (lambda: SetConnectorLimits("Mail", paused=True), "isn't a policy name"),
        (lambda: SetConnectorLimits("mail-out", max_per_day=0), "greater than or equal to 1"),
        (lambda: SetConnectorLimits("mail-out", max_per_day=10_001), "less than or equal"),
        (lambda: SetConnectorLimits("mail-out", max_subject_chars=999), "less than or equal"),
        (lambda: SetConnectorLimits("mail-out", max_body_chars=100_001), "less than or equal"),
        (lambda: SetConnectorLimits("mail-out", max_per_day=True), "valid integer"),
        (lambda: SetConnectorLimits("mail-out", paused=1), "valid boolean"),  # type: ignore[arg-type]
    ],
    ids=[
        "move-server",
        "move-kind",
        "move-name",
        "move-pin",
        "move-name-bytes",
        "move-pin-bytes",
        "client-name",
        "client-server",
        "client-twice",
        "limits-none",
        "limits-name",
        "limits-low",
        "limits-day",
        "limits-subject",
        "limits-body",
        "limits-bool",
        "limits-paused",
    ],
)
def test_the_managed_ops_hold_the_schemas_values(make: Callable[[], Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        make()


def test_set_client_servers_replaces_the_list_whole() -> None:
    """G.3, G-13: one existing client's servers, a server taken away as well as given."""
    op = SetClientServers("agent1", ["mail", "broker-read"])  # type: ignore[arg-type]
    assert op.servers == ("mail", "broker-read")
    change = PolicyChange("t", (op,))
    assert change.data() == {
        "gateway": {"clients": {"agent1": {"servers": ["mail", "broker-read"]}}}
    }
    merged = apply(example(), change)
    assert merged.gateway is not None
    client = merged.gateway.clients["agent1"]
    assert client.servers == ["mail", "broker-read"]
    assert client.sources == ["192.0.2.0/24"]  # the rest of the client kept
    emptied = apply(example(), PolicyChange("t", (SetClientServers("agent1", ()),)))
    assert emptied.gateway is not None
    assert emptied.gateway.clients["agent1"].servers == []


@pytest.mark.parametrize(
    ("op", "path", "message"),
    [
        (SetClientServers("ci", ("mail",)), "gateway.clients.ci", "the policy has no such client"),
        (
            SetClientServers("agent1", ("mail", "absent")),
            "gateway.servers.absent",
            "the policy has no such server",
        ),
        (
            SetConnectorLimits("absent", paused=True),
            "connectors.absent",
            "the policy has no such connector",
        ),
    ],
    ids=["client", "server", "connector"],
)
def test_a_managed_op_on_what_isnt_there_is_diff_invalid(op: Any, path: str, message: str) -> None:
    with pytest.raises(ChangeRefused) as caught:
        apply(example(), PolicyChange("t", (op,)))
    assert (caught.value.reason, caught.value.path, caught.value.messages) == (
        "diff_invalid",
        path,
        (message,),
    )


def test_set_client_servers_in_a_policy_without_a_gateway() -> None:
    bare = Policy.model_validate({"version": 1, "mode": "managed"})
    with pytest.raises(ChangeRefused, match=r"^diff_invalid: gateway\.clients\.agent1"):
        apply(bare, PolicyChange("t", (SetClientServers("agent1", ()),)))


def test_set_connector_limits_changes_only_its_fields() -> None:
    """F-15: the pause and the limits sit outside the password's binding; the rest is kept."""
    op = SetConnectorLimits("mail-out", paused=True, max_body_chars=900)
    assert op.limits() == {"paused": True, "max_body_chars": 900}
    change = PolicyChange("t", (op,))
    assert change.data() == {
        "connectors": {"mail-out": {"kind": "smtp", "paused": True, "max_body_chars": 900}}
    }
    assert change.replace() == ()
    before = example().connectors["mail-out"]
    after = apply(example(), change).connectors["mail-out"]
    assert (after.paused, after.max_body_chars) == (True, 900)
    kept = {"paused", "max_body_chars"}
    assert after.model_dump(exclude=kept) == before.model_dump(exclude=kept)
    unpaused = SetConnectorLimits("mail-out", paused=False, max_per_day=1, max_subject_chars=998)
    assert unpaused.limits() == {"paused": False, "max_per_day": 1, "max_subject_chars": 998}
    merged = apply(apply(example(), change), PolicyChange("t", (unpaused,)))
    assert merged.connectors["mail-out"].paused is False
    assert merged.connectors["mail-out"].max_per_day == 1


def test_each_managed_op_names_what_it_changes_once() -> None:
    move = MoveToAllow("broker-trade", "tool", "cancel_order", CANCEL)
    with pytest.raises(
        ValueError, match=r"^the change names gateway\.servers\.broker-trade twice$"
    ):
        PolicyChange("t", (move, SetServerReview("broker-trade", Tools(), {})))
    with pytest.raises(
        ValueError, match=r"^the change names gateway\.servers\.broker-trade twice$"
    ):
        PolicyChange("t", (move, MoveToAllow("broker-trade", "tool", "place_order", PLACE)))
    with pytest.raises(ValueError, match=r"^the change names gateway\.clients\.agent1 twice$"):
        PolicyChange("t", (SetClientServers("agent1", ()), SetClientServers("agent1", ("mail",))))
    with pytest.raises(ValueError, match=r"^the change names connectors\.mail-out twice$"):
        PolicyChange("t", (SetConnectorLimits("mail-out", paused=True),) * 2)
    limits = SetConnectorLimits("mail-out", paused=True)
    PolicyChange("t", (move, SetClientServers("agent1", ()), limits))


# --- a managed review writes its declined block (M6 J.3, H.4; CR-17) ----------------------------


def declined_example(declined: dict[str, str]) -> Policy:
    raw = yaml.safe_load(EXAMPLE_POLICY.read_text(encoding="utf-8"))
    raw["gateway"]["servers"]["broker-read"]["declined"] = declined
    return parse_policy(yaml.safe_dump(raw, sort_keys=False), "example")


def read_declined(policy: Policy) -> dict[str, str]:
    assert policy.gateway is not None
    return dict(policy.gateway.servers["broker-read"].declined)


def test_a_managed_review_writes_the_servers_declined_block_less_its_includes() -> None:
    """With no block of its own, the server's is written, less the tools the review includes, so
    the candidate never holds a tool both included and declined (check row 3)."""
    policy = declined_example({"get_news": PIN_B, "old": PIN_B})
    tools = Tools(include=["get_quote", "get_news"], allow=["get_quote", "get_news"])
    pins = {"get_quote": PIN_A, "get_news": PIN_A}
    change = PolicyChange("t", (SetServerReview("broker-read", tools, pins),))
    merged = apply(policy, change, managed=True)
    assert read_declined(merged) == {"old": PIN_B}
    assert [f for f in check_policy(merged) if f.level == "error"] == []
    # The same change as a fragment keeps the block (M7's fragment, M6 step 6).
    assert read_declined(apply(policy, change)) == {"get_news": PIN_B, "old": PIN_B}
    # Its own block is written less its includes; an empty one clears the server's.
    own = SetServerReview("broker-read", tools, pins, declined={"get_news": PIN_B, "new": PIN_A})
    assert read_declined(apply(policy, PolicyChange("t", (own,)), managed=True)) == {"new": PIN_A}
    cleared = PolicyChange("t", (replace(own, declined={}),))
    assert read_declined(apply(policy, cleared, managed=True)) == {}
    # A server with no block gets none, and the other ops are as they were.
    assert apply(example(), review_change(), managed=True) == apply(example(), review_change())
    assert apply(example(), notes_change(), managed=True) == apply(example(), notes_change())


# --- the portal's bounds on its ops (M6 G.3, I.3; CR-16, MISS-1) -------------------------------


@pytest.mark.parametrize(
    ("credential", "field"),
    [
        ({"kind": "header", "secret": "env:NOTES_KEY"}, "secret"),
        ({**NOTES_CREDENTIAL, "client_id": "env:NOTES_ID"}, "client_id"),
        (
            {**NOTES_CREDENTIAL, "client_auth": "post", "client_secret": "env:NOTES_SECRET"},
            "client_secret",
        ),
        ({**NOTES_CREDENTIAL, "refresh_token": "env:NOTES_REFRESH"}, "refresh_token"),
    ],
    ids=["header-secret", "client-id", "client-secret", "refresh-token"],
)
def test_a_portal_credential_takes_no_env_reference(credential: dict[str, Any], field: str) -> None:
    model: Any = (
        HeaderCredential.model_validate(credential)
        if credential["kind"] == "header"
        else OAuth2Credential.model_validate(credential)
    )
    ops: list[Any] = [AddCredential("notes", model)]
    if isinstance(model, OAuth2Credential):
        ops.append(SetCredential("notes", model))
    for op in ops:
        with pytest.raises(ChangeRefused) as caught:
            from_portal(PolicyChange("t", (op,)))
        assert (caught.value.reason, caught.value.path) == (
            "portal_env_ref",
            f"credentials.notes.{field}",
        )


def test_a_portal_credential_from_the_store_or_a_literal_client_id_passes() -> None:
    from_portal(notes_change())
    literal = OAuth2Credential.model_validate({**NOTES_CREDENTIAL, "client_id": "env:not a ref"})
    from_portal(PolicyChange("t", (SetCredential("notes", literal),)))
    header = HeaderCredential(kind="header", secret="store:notes-key")
    from_portal(PolicyChange("t", (AddCredential("notes", header),)))


@pytest.mark.parametrize(
    ("route", "with_credential"),
    [
        ({**NOTES_ROUTE, "callers": ["gateway", {"placeholder": "ph-notes-00000001"}]}, True),
        ({**NOTES_ROUTE, "callers": [{"placeholder": "ph-notes-00000001"}]}, True),
        (NOTES_ROUTE, False),
        ({**NOTES_ROUTE, "credential": "broker-mcp"}, True),
    ],
    ids=["placeholder-too", "placeholder-only", "credential-not-added", "other-credential"],
)
def test_a_portal_route_calls_as_the_gateway_with_a_credential_it_adds(
    route: dict[str, Any], with_credential: bool
) -> None:
    ops: list[Any] = [AddRoute(Route.model_validate(route))]
    if with_credential:
        ops.insert(0, AddCredential("notes", OAuth2Credential.model_validate(NOTES_CREDENTIAL)))
    with pytest.raises(ChangeRefused) as caught:
        from_portal(PolicyChange("t", tuple(ops)))
    assert (caught.value.reason, caught.value.path) == ("route_reuses_credential", "routes notes")


def test_a_portal_route_with_no_credential_passes() -> None:
    bare = {key: value for key, value in NOTES_ROUTE.items() if key != "credential"}
    from_portal(PolicyChange("t", (AddRoute(Route.model_validate(bare)),)))
    from_portal(PolicyChange("t", (MoveToAllow("broker-trade", "tool", "cancel_order", CANCEL),)))
