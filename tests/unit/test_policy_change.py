"""The change object (M7 design H.1, O.2 ``test_policy_change.py``).

A change holds the schema's own models, so every value in it has passed its validator; its plain
form is what fragment 1 and fragment 2 load back to (E.2, E.4); ``apply`` merges it into the
running policy with the merge ``check --with`` runs, refusing a taken name (``name_taken``) and a
change the merged policy can't take (``diff_invalid``).
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.common.policy.change import (
    AddCredential,
    AddEgressPrivate,
    AddRoute,
    AddServer,
    ChangeRefused,
    Comment,
    Op,
    PolicyChange,
    SetCredential,
    SetServerReview,
    apply,
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


def test_comments_are_kept_in_order_and_hold_no_data() -> None:
    first, second = Comment("added", "notes"), Comment("suggested", "get_quote", "read-only")
    change = PolicyChange("t", (first, AddEgressPrivate("a.lan.example:443"), second))
    assert change.comments() == (first, second)
    assert change.data() == {"egress_private": ["a.lan.example:443"]}
    assert PolicyChange("t").data() == {}
    assert PolicyChange("t").comments() == ()


# --- what an op holds ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ops",
    [
        ("cred", "cred"),
        ("cred", "set"),
        ("server", "review"),
        ("route", "route"),
        ("private", "private"),
    ],
)
def test_a_change_names_each_thing_once(ops: tuple[str, str]) -> None:
    oauth = OAuth2Credential.model_validate(NOTES_CREDENTIAL)
    made: dict[str, Op] = {
        "cred": AddCredential("notes", oauth),
        "set": SetCredential("notes", oauth),
        "server": AddServer("notes", RemoteServer.model_validate(NOTES_SERVER)),
        "review": SetServerReview("notes", Tools(), {}),
        "route": AddRoute(Route.model_validate(NOTES_ROUTE)),
        "private": AddEgressPrivate("a.lan.example:443"),
    }
    with pytest.raises(ValueError, match="twice"):
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


@pytest.mark.parametrize("era", ["Modern", "bridge", ""])
def test_an_era_is_the_schemas(era: str) -> None:
    with pytest.raises(ValidationError):
        SetServerReview("notes", Tools(), {}, era=era)


def test_a_review_is_a_copy_no_caller_can_change() -> None:
    pins = {"get_quote": PIN_A}
    op = SetServerReview("notes", Tools(), pins)
    pins["cancel_order"] = PIN_B
    assert dict(op.review) == {"get_quote": PIN_A}
    with pytest.raises(TypeError):
        op.review["x"] = PIN_B  # type: ignore[index]


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


def test_an_egress_private_entry_the_policy_has_is_kept_once() -> None:
    policy = apply(example(), notes_change())
    again = PolicyChange("t", (AddEgressPrivate("mcp.lan.example:443"),))
    assert apply(policy, again).egress_private == ["mcp.lan.example:443"]


def test_apply_reads_the_policy_by_its_document_names() -> None:
    """The mail connector's from: field is from_ in the model; the merge writes it back as from."""
    merged = apply(example(), notes_change())
    assert merged.connectors == example().connectors
