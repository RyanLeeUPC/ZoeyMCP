from __future__ import annotations

from typing import Any

import pytest

from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.vault.bindings import BindingError, BindingReason
from zoeymcp.vault.secretplan import (
    NOT_FOUND,
    NOT_WRITTEN,
    NOT_WRITTEN_REFUSAL,
    DeletePlan,
    OnboardPutPlan,
    PutPlan,
    Reason,
    SecretRefusal,
    binding_refusal,
    check_name,
    plan_delete,
    plan_onboard_secret,
    plan_put,
)

from .conftest import EXAMPLE_POLICY

ZWSP = chr(0x200B)
# Two bytes in UTF-8.
E_ACUTE = chr(0xE9)
STATS = {"origins": ["https://api.stats.example:443"]}
BROKER = {
    "oauth": {
        "token": "https://auth.broker.example:443",
        "resources": ["https://mcp.broker.example:443"],
    }
}
MAIL = {
    "smtp": {
        "host": "smtp.mail.example",
        "port": 465,
        "from": "Agent <agent@mail.example>",
        "to": ["partner@mail.example"],
    }
}
UNBOUND = (
    "the policy doesn't use store:unreferenced on any route or connector; "
    "pass --origin to bind it explicitly"
)


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def edited(change: Any) -> Policy:
    raw = example_policy().model_dump(by_alias=True)
    change(raw)
    return Policy.model_validate(raw)


def refusal(status: int, reason: Reason, message: str) -> SecretRefusal:
    return SecretRefusal(status, reason, message)


# --- names -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    ["a", "0", "a" * 128, "a_b.c-d", "9-x", "oauth", "oauthx.live", "my.oauth.live", "oauth-x"],
)
def test_names_that_may_be_written(name: str) -> None:
    assert check_name(name) is None


@pytest.mark.parametrize(
    "name", ["", "A", "aB", "_a", ".a", "-a", "a" * 129, "a b", "a/b", f"a{E_ACUTE}", "a:b"]
)
def test_invalid_names(name: str) -> None:
    expected = refusal(400, "invalid_name", "invalid secret name")
    assert check_name(name) == expected
    assert plan_put(name, {"value": "v-123456"}, example_policy()) == expected


def test_a_trailing_line_break_makes_a_name_invalid() -> None:
    # "$" also matches before a final "\n", so the name is matched whole (PUT /secrets/a.b%0A).
    assert check_name("a.b") is None
    assert check_name("a.b\n") == refusal(400, "invalid_name", "invalid secret name")


@pytest.mark.parametrize("name", ["oauth.", "oauth.anything", "oauth.broker-mcp.live"])
def test_vault_managed_names(name: str) -> None:
    expected = refusal(409, "vault_managed", "managed by the vault; use zoeymcp login")
    assert check_name(name) == expected
    # Before the body is looked at.
    assert plan_put(name, "not an object", example_policy()) == expected


def test_the_name_is_checked_before_the_body() -> None:
    assert plan_put("Bad", "not an object", example_policy()) == refusal(
        400, "invalid_name", "invalid secret name"
    )


# --- the body and the value --------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    ["not an object", ["value"], None, 5, {"value": "v-123456", "extra": 1}, {"other": "v"}],
)
def test_a_body_that_isnt_value_and_origins(data: Any) -> None:
    assert plan_put("music-stats", data, example_policy()) == refusal(
        400, "bad_body", "expected {value, origins?}"
    )


@pytest.mark.parametrize(
    "data",
    [{}, {"value": ""}, {"value": None}, {"value": 5}, {"origins": ["https://x.example"]}],
)
def test_an_empty_value(data: Any) -> None:
    assert plan_put("music-stats", data, example_policy()) == refusal(
        400, "empty_value", "value must be a non-empty string"
    )


@pytest.mark.parametrize(
    "value",
    ["abc\ndef", "abc\rdef", "abc\tdef", f"abc{ZWSP}def", "abc\x00", "a" * 65537],
    ids=["newline", "return", "tab", "zwsp", "nul", "too-long"],
)
def test_a_value_with_line_breaks_or_hidden_characters(value: str) -> None:
    assert plan_put("music-stats", {"value": value}, example_policy()) == refusal(
        400, "bad_value", "value has line breaks, control or invisible characters"
    )


@pytest.mark.parametrize(
    "value",
    ["a" * 65536, E_ACUTE + "a" * 65534, "x"],
    ids=["65536-chars", "65536-bytes", "short"],
)
def test_values_up_to_the_store_limit(value: str) -> None:
    plan = plan_put("music-stats", {"value": value}, example_policy())
    assert plan == PutPlan("music-stats", value, STATS, oauth=False)


def test_a_value_over_the_store_limit_in_bytes() -> None:
    # 65536 characters, 65537 bytes.
    value = E_ACUTE + "a" * 65535
    assert plan_put("music-stats", {"value": value}, example_policy()) == refusal(
        409, "value_too_large", "a secret can't be larger than 65536 bytes"
    )
    # The binding is decided first, as the store's write came after it.
    assert plan_put("unreferenced", {"value": value}, example_policy()) == refusal(
        409, "unbound", UNBOUND
    )


# --- origins -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "origins", ["https://x.example", ["https://x.example", 1], [1], {"https://x.example": 1}, 5]
)
@pytest.mark.parametrize("name", ["extra", "broker-refresh"])
def test_origins_that_arent_a_list_of_strings(origins: Any, name: str) -> None:
    # Before the OAuth check: a malformed body is a bad request for any name.
    assert plan_put(name, {"value": "v-123456", "origins": origins}, example_policy()) == (
        refusal(400, "origins_type", "origins must be a list of URLs")
    )


@pytest.mark.parametrize("name", ["broker-refresh", "broker-client-id"])
def test_origins_on_an_oauth_secret(name: str) -> None:
    data = {"value": "v-123456", "origins": ["https://auth.broker.example"]}
    assert plan_put(name, data, example_policy()) == refusal(
        409, "origins_on_oauth", "OAuth secrets are bound by the policy; drop --origin"
    )


@pytest.mark.parametrize(
    ("origins", "message"),
    [
        ([], "a binding needs at least one origin"),
        (["not a url"], "not an absolute URL: 'not a url'"),
        (["ftp://x.example"], "no default port for scheme 'ftp'"),
    ],
)
def test_origins_that_cant_be_used(origins: list[str], message: str) -> None:
    data = {"value": "v-123456", "origins": origins}
    assert plan_put("extra", data, example_policy()) == refusal(409, "bad_origins", message)


@pytest.mark.parametrize("name", ["extra", "music-stats", "mail-pass"])
def test_explicit_origins_are_the_binding(name: str) -> None:
    data = {"value": "v-123456", "origins": ["https://B.example/x", "https://b.example:443"]}
    assert plan_put(name, data, example_policy()) == PutPlan(
        name, "v-123456", {"origins": ["https://b.example:443"]}, oauth=False
    )


# --- bindings from the policy ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "binding", "oauth"),
    [
        ("music-stats", STATS, False),
        ("mail-pass", MAIL, False),
        ("mail-user", MAIL, False),
        ("broker-refresh", BROKER, True),
        ("broker-client-id", BROKER, True),
    ],
)
@pytest.mark.parametrize("origins", [{}, {"origins": None}], ids=["absent", "null"])
def test_the_policy_binds_a_secret(
    name: str, binding: dict[str, Any], oauth: bool, origins: dict[str, Any]
) -> None:
    plan = plan_put(name, {"value": "v-123456", **origins}, example_policy())
    assert plan == PutPlan(name, "v-123456", binding, oauth)
    assert isinstance(plan, PutPlan)
    assert plan.oauth is oauth


def test_an_unreferenced_secret_is_unbound() -> None:
    assert plan_put("unreferenced", {"value": "v-123456"}, example_policy()) == refusal(
        409, "unbound", UNBOUND
    )


def test_an_oauth_secret_with_no_route() -> None:
    def no_broker_route(raw: dict[str, Any]) -> None:
        raw["routes"] = [r for r in raw["routes"] if r["credential"] != "broker-mcp"]

    assert plan_put("broker-refresh", {"value": "v-123456"}, edited(no_broker_route)) == refusal(
        409,
        "no_route",
        "no route uses broker-mcp; there is nothing to bind the access tokens minted with "
        "'broker-refresh' to",
    )


def test_two_incompatible_uses() -> None:
    def shared(raw: dict[str, Any]) -> None:
        raw["credentials"]["music-stats"]["secret"] = "store:mail-pass"

    assert plan_put("mail-pass", {"value": "v-123456"}, edited(shared)) == refusal(
        409, "binding_conflict", "'mail-pass' is used both by a connector and by HTTP credentials"
    )


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("unbound", "unbound"),
        ("no_route", "no_route"),
        ("orphan_slot", "orphan_slot"),
        ("conflict", "binding_conflict"),
        ("not_oauth", "not_oauth"),
    ],
)
def test_each_binding_reason_is_a_409(reason: BindingReason, expected: Reason) -> None:
    exc = BindingError("the text", reason)
    assert binding_refusal(exc) == refusal(409, expected, "the text")


# --- plans -------------------------------------------------------------------------------------


def test_a_plan_never_shows_its_value() -> None:
    plan = plan_put("music-stats", {"value": "distinctive-value-42"}, example_policy())
    assert isinstance(plan, PutPlan)
    assert plan.value == "distinctive-value-42"
    assert "distinctive-value-42" not in repr(plan)
    assert repr(plan) == (
        "PutPlan(name='music-stats', binding={'origins': ['https://api.stats.example:443']}, "
        "oauth=False)"
    )


def seeded(raw: dict[str, Any]) -> None:
    raw["credentials"]["broker-mcp"]["refresh_token"] = "env:BROKER_REFRESH"


@pytest.mark.parametrize(
    ("name", "policy", "oauth"),
    [
        ("music-stats", example_policy(), False),
        ("broker-refresh", example_policy(), True),
        ("broker-client-id", example_policy(), True),
        # No name or prefix check: a socket delete of any name keeps working.
        ("Bad Name", example_policy(), False),
        ("oauth.broker-mcp.live", example_policy(), False),
        ("oauth.broker-mcp.live", edited(seeded), True),
        ("broker-refresh", edited(seeded), False),
    ],
)
def test_a_delete_of_any_name(name: str, policy: Policy, oauth: bool) -> None:
    plan = plan_delete(name, policy)
    assert plan == DeletePlan(name, oauth)
    assert plan.oauth is oauth


def test_the_refusals_after_a_plan() -> None:
    assert NOT_WRITTEN == "kept in memory, not written to disk; check the state volume"
    assert refusal(500, "not_written", NOT_WRITTEN) == NOT_WRITTEN_REFUSAL
    assert refusal(404, "not_found", "no such secret") == NOT_FOUND


# --- an onboarding's client secret (M7 design D.7) ----------------------------------------------

NOTES = {
    "oauth": {
        "token": "https://auth.notes.example:443",
        "resources": ["https://mcp.notes.example:443"],
    }
}
META = {
    "onboarded": "auth.notes.example",
    "resource": "https://mcp.notes.example/mcp",
    "client_id": "notes-client",
    "client_secret_expires_at": None,
}


def onboard(name: str = "notes-client-secret", value: object = "notes-secret-1", **kw: Any) -> Any:
    return plan_onboard_secret(name, value, NOTES, META, store_names=kw.get("store", ()))


def test_an_onboarding_secret_plan_carries_its_meta() -> None:
    binding, meta = dict(NOTES), dict(META)
    plan = plan_onboard_secret(
        "notes-client-secret", "notes-secret-1", binding, meta, store_names=["other"]
    )
    assert plan == OnboardPutPlan("notes-client-secret", "notes-secret-1", NOTES, META)
    assert isinstance(plan, OnboardPutPlan)
    # No running credential uses the name yet, so the store writes it, never the manager.
    assert plan.oauth is False
    # Copies: a caller's later change reaches no plan.
    binding["oauth"] = {}
    meta["client_id"] = "changed"
    assert (plan.binding, plan.meta) == (NOTES, META)
    assert "notes-secret-1" not in repr(plan)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("Notes-Secret", refusal(400, "invalid_name", "invalid secret name")),
        (
            "oauth.notes.live",
            refusal(409, "vault_managed", "managed by the vault; use zoeymcp login"),
        ),
    ],
)
def test_an_onboarding_secrets_name_is_checked(name: str, expected: SecretRefusal) -> None:
    assert onboard(name) == expected


def test_an_onboarding_secret_never_replaces_an_entry() -> None:
    """D.7 step 1: a name the store has is name_taken, whatever the value."""
    taken = refusal(409, "name_taken", "the store already has notes-client-secret")
    assert onboard(store=["notes-client-secret"]) == taken
    assert onboard(value="", store=["notes-client-secret"]) == taken
    assert isinstance(onboard(store=["notes-client-secret-2"]), OnboardPutPlan)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", refusal(400, "empty_value", "value must be a non-empty string")),
        (None, refusal(400, "empty_value", "value must be a non-empty string")),
        (
            f"abc{ZWSP}",
            refusal(400, "bad_value", "value has line breaks, control or invisible characters"),
        ),
        (
            "abc\rdef",
            refusal(400, "bad_value", "value has line breaks, control or invisible characters"),
        ),
        (
            E_ACUTE + "a" * 65535,
            refusal(409, "value_too_large", "a secret can't be larger than 65536 bytes"),
        ),
    ],
    ids=["empty", "none", "zwsp", "return", "too-large"],
)
def test_an_onboarding_secrets_value_is_checked(value: object, expected: SecretRefusal) -> None:
    assert onboard(value=value) == expected


def test_an_onboarding_secret_up_to_the_store_limit() -> None:
    value = E_ACUTE + "a" * 65534
    assert onboard(value=value) == OnboardPutPlan("notes-client-secret", value, NOTES, META)
