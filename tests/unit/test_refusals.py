"""The refusal catalogue (M5 design M.2, O.2 ``refusals``): every reason has a status and a text.

The reasons come from the deciding modules, read from their code here (the WebAuthn and secret
``Reason`` literals, every literal ``LoginError`` and ``RedirectError`` reason), so a reason added
there without a sentence here fails.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from string import Formatter
from types import ModuleType
from typing import get_args

import pytest

from zoeymcp.common.textrules import find_violations
from zoeymcp.portal import passkeys, webauthn
from zoeymcp.portal.refusals import (
    CATALOGUE,
    KEPT_IN_MEMORY,
    WEBAUTHN,
    Refusal,
    enrolment,
    reasons,
    refusal,
    secret,
    wrong_host_literal,
)
from zoeymcp.portal.refusals import login as login_refusal
from zoeymcp.vault import admin, secretplan, store
from zoeymcp.vault.oauth import login, pkce
from zoeymcp.vault.secretplan import SecretRefusal

ZWSP = chr(0x200B)
ELLIPSIS = chr(0x2026)

# M.2's statuses, as listed there.
STATUSES = {
    400: [
        "bad_json",
        "bad_body",
        "invalid_name",
        "empty_value",
        "bad_value",
        "origins_type",
        "bad_name",
        "redirect_mismatch",
        "state_mismatch",
        "duplicate_param",
        "no_code",
        "iss_mismatch",
        "provider_error",
        "exchange_failed",
        "no_refresh_token",
        "callback_not_taken",
        "bad_query",
    ],
    401: ["no_session", "passkey_refused", "setup_code_refused", "step_up_refused"],
    403: ["cross_site", "bad_origin", "scope", "not_navigation"],
    404: ["not_found", "action_unknown", "flow_unknown", "not_oauth", "ceremony_unknown"],
    405: ["method"],
    408: ["too_slow"],
    411: ["length_required"],
    413: ["too_large"],
    415: ["content_type"],
    409: [
        "changed",
        "flow_returned",
        "flow_conflict",
        "vault_managed",
        "origins_on_oauth",
        "bad_origins",
        "unbound",
        "orphan_slot",
        "binding_conflict",
        "binding_changed",
        "no_authorize_url",
        "no_route",
        "authorize_misconfigured",
        "client_id_unavailable",
        "client_secret_unavailable",
        "last_passkey",
        "not_restartable",
    ],
    421: ["wrong_host"],
    429: ["rate_limited", "too_many_flows"],
    500: ["not_written"],
    503: ["busy", "unavailable"],
}
# Beyond M.2's list: the store's byte limit (step 4b), the token manager's unknown credential,
# the shell's answer when a handler fails (step 10b), and two passkeys sharing a fingerprint
# (step 7a's holder, answered from step 12).
EXTRA = {
    "value_too_large": 409,
    "not_configured": 400,
    "internal": 500,
    "ambiguous_fingerprint": 409,
}

# M.2's quoted texts, exactly.
TEXTS = {
    "wrong_host": "This portal doesn't answer to that address. Use one listed in admin.origins; "
    "behind a proxy, pass the original Host header.",
    "cross_site": "Refused: this request didn't come from the portal's own page.",
    "bad_origin": "Refused: this request didn't come from the portal's own page.",
    "no_session": "You're signed out (the session ended, or the vault restarted). Sign in again.",
    "setup_code_refused": "That setup code isn't valid. Codes work once, for 15 minutes. If you "
    "haven't used it, someone else may have: run zoeymcp setup-code --reset.",
    "passkey_refused": "That passkey wasn't accepted here. Passkeys belong to one address: use "
    "the one you enrolled it on, or a setup code.",
    "unavailable": "The passkey file can't be verified (edited, or written under another master "
    "key). Run zoeymcp setup-code --reset with host access.",
    "busy": "Too many requests right now. Wait a moment and try again.",
    "rate_limited": "Too many requests right now. Wait a moment and try again.",
    "changed": "Something changed since you prepared this (shown below). Check it and prepare "
    "it again.",
    "action_unknown": "That confirmation, login or passkey prompt expired or was already used. "
    "Start again.",
    "flow_unknown": "That confirmation, login or passkey prompt expired or was already used. "
    "Start again.",
    "ceremony_unknown": "That confirmation, login or passkey prompt expired or was already used. "
    "Start again.",
    "last_passkey": "This is the only passkey. Enrol another first, or use zoeymcp setup-code "
    "--reset.",
    "not_written": "Not written to disk; nothing changed; check the state volume.",
    "state_mismatch": "That address belongs to another login; use the tab this login opened.",
    "flow_returned": "The provider already sent this sign-in back to the portal; confirm it here.",
    "flow_conflict": "Two different answers came back for this sign-in. Nothing was stored. "
    "Connect again.",
    "iss_mismatch": "The answer came from a different issuer; nothing was stored. Connect again.",
    "no_code": "The provider's answer had no usable code. Connect again.",
    "callback_not_taken": "The portal didn't take this sign-in. Copy this tab's address and "
    "paste it into the portal's Connect dialog, or into zoeymcp login if you started it there.",
    # G's portal column.
    "vault_managed": "Tokens for this credential come from Connect, on the Credentials page.",
    "empty_value": "Enter a value.",
    "origins_type": "Origins are a list of https URLs.",
    "origins_on_oauth": "OAuth secrets take the policy's binding.",
}
FIELDS = {
    "bad_origins": {"detail"},
    "unbound": {"name"},
    "no_route": {"detail"},
    "orphan_slot": {"detail"},
    "binding_conflict": {"detail"},
    "redirect_mismatch": {"redirect_uri"},
    "provider_error": {"error"},
    "exchange_failed": {"code"},
}


def names(text: str) -> set[str]:
    return {name for _, name, _, _ in Formatter().parse(text) if name is not None}


def literal_reasons(module: ModuleType, exception: str) -> set[str]:
    """The first argument of every ``exception(...)`` call in ``module`` that is a string, and
    the literal start of every f-string one (``exchange_failed:``)."""
    found = set()
    tree = ast.parse(inspect.getsource(module))
    # Under mutmut the source also holds every mutant of each function, named with
    # ``__mutmut_``; their arguments aren't the module's reasons.
    for parent in ast.walk(tree):
        body = getattr(parent, "body", None)
        if isinstance(body, list):
            parent.body = [  # type: ignore[attr-defined]
                child
                for child in body
                if not (
                    isinstance(child, ast.FunctionDef | ast.AsyncFunctionDef)
                    and "__mutmut_" in child.name
                )
            ]
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id != exception or not node.args:
            continue
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            found.add(first.value)
        elif isinstance(first, ast.JoinedStr):
            start = first.values[0]
            assert isinstance(start, ast.Constant)
            assert isinstance(start.value, str)
            found.add(start.value)
    return found


# --- the catalogue --------------------------------------------------------------------------------


def test_every_listed_reason_has_its_status() -> None:
    expected = {reason: status for status, listed in STATUSES.items() for reason in listed}
    expected |= EXTRA
    assert {reason: entry.status for reason, entry in CATALOGUE.items()} == expected


@pytest.mark.parametrize("reason", sorted(TEXTS))
def test_the_quoted_texts(reason: str) -> None:
    assert CATALOGUE[reason].text == TEXTS[reason]


@pytest.mark.parametrize("reason", sorted(CATALOGUE))
def test_every_text_is_one_plain_line(reason: str) -> None:
    text = CATALOGUE[reason].text
    assert text[0].isupper()
    # A sentence, or a sentence ending in what it quotes.
    assert text.endswith((".", "{error}"))
    assert not find_violations(text, max_chars=300, single_line=True, allow_tabs=False)
    assert names(text) == FIELDS.get(reason, set())


@pytest.mark.parametrize("reason", sorted(WEBAUTHN))
def test_every_webauthn_text_is_one_plain_line(reason: webauthn.Reason) -> None:
    text = WEBAUTHN[reason]
    assert text[0].isupper()
    assert text.endswith(".")
    assert not find_violations(text, max_chars=200, single_line=True, allow_tabs=False)
    assert names(text) == set()


def test_the_secret_texts_name_the_stores_limits() -> None:
    assert str(store.MAX_SECRET_BYTES) in CATALOGUE["value_too_large"].text
    assert f"There are {webauthn.MAX_PASSKEYS} passkeys" in WEBAUTHN["too_many_passkeys"]
    assert KEPT_IN_MEMORY == "Kept in memory, not written to disk; check the state volume."
    assert KEPT_IN_MEMORY.lower().rstrip(".") == secretplan.NOT_WRITTEN


def test_the_callback_reasons_share_the_page_text() -> None:
    page = TEXTS["callback_not_taken"]
    assert CATALOGUE["not_navigation"].text == page
    assert CATALOGUE["bad_query"].text == page


def test_the_catalogue_cannot_be_changed() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        CATALOGUE["busy"].status = 200  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        refusal("busy").status = 200  # type: ignore[misc]
    with pytest.raises(TypeError):
        CATALOGUE["x"] = CATALOGUE["busy"]  # type: ignore[index]
    with pytest.raises(TypeError):
        WEBAUTHN["signature"] = "x"  # type: ignore[index]


# --- every reason the deciding code gives has a text --------------------------------------------


def test_every_webauthn_reason_has_a_text() -> None:
    assert set(WEBAUTHN) == set(get_args(webauthn.Reason))


def test_every_passkey_reason_has_a_text() -> None:
    """The holder's refusals reach the portal as they are; an enrolment's two conflicts have
    their own sentences (D.3)."""
    assert set(get_args(passkeys.Reason)) <= reasons()


def test_every_secret_reason_is_catalogued() -> None:
    assert set(get_args(secretplan.Reason)) <= set(CATALOGUE)


def test_every_redirect_reason_is_catalogued() -> None:
    found = literal_reasons(pkce, "RedirectError")
    assert found == {
        "redirect_mismatch",
        "duplicate_param",
        "state_mismatch",
        "provider_error",
        "iss_mismatch",
        "no_code",
    }
    assert found <= set(CATALOGUE)


def test_every_login_reason_is_catalogued() -> None:
    found = literal_reasons(login, "LoginError")
    # The failure reasons of a client ref, and the token manager's own (tokens.client_for).
    found |= set(login._CLIENT_REFS) | {"not_configured"}
    assert "exchange_failed:" in found
    found = {reason.removesuffix(":") for reason in found}
    assert found <= set(CATALOGUE)


def test_login_reasons_have_the_sockets_statuses() -> None:
    for reason, status in admin._LOGIN_STATUS.items():
        assert CATALOGUE[reason].status == status, reason


def test_reasons_are_both_tables() -> None:
    assert reasons() == set(CATALOGUE) | set(WEBAUTHN)
    assert "key_encoding" in reasons()
    assert "wrong_host" in reasons()


# --- building a refusal -------------------------------------------------------------------------


def test_a_refusal_and_its_body() -> None:
    assert refusal("no_session") == Refusal(401, "no_session", TEXTS["no_session"])
    assert refusal("busy").body() == {"error": TEXTS["busy"], "reason": "busy"}


def test_an_unknown_reason_is_a_mistake() -> None:
    with pytest.raises(KeyError):
        refusal("no_such_reason")


def test_fields_are_filled_and_shown() -> None:
    made = refusal("redirect_mismatch", redirect_uri="https://app.example/cb")
    assert made == Refusal(
        400,
        "redirect_mismatch",
        "That isn't the address the provider sent you to; it starts with https://app.example/cb.",
    )
    hidden = refusal("provider_error", error=f"access{ZWSP}_denied\n<b>")
    assert hidden.error == "The answer said the provider refused: access[U+200B]_denied\\n<b>"
    # A field is capped at the summary limit.
    long = refusal("provider_error", error="x" * 301)
    assert long.error.endswith("x" * 300 + f"{ELLIPSIS}[+1]")
    assert refusal("provider_error", error="x" * 300).error.endswith("x" * 300)


def test_the_fields_must_be_exactly_the_texts() -> None:
    with pytest.raises(ValueError, match=r"^the text names \['redirect_uri'\], given \[\]$"):
        refusal("redirect_mismatch")
    with pytest.raises(ValueError, match=r"^the text names \[\], given \['extra'\]$"):
        refusal("no_session", extra="x")
    with pytest.raises(ValueError, match="redirect_uri"):
        refusal("redirect_mismatch", redirect_uri="x", extra="y")


def test_a_field_cannot_add_fields() -> None:
    made = refusal("provider_error", error="{redirect_uri}")
    assert made.error == "The answer said the provider refused: {redirect_uri}"


def test_exchange_failed_takes_its_code() -> None:
    made = refusal("exchange_failed:oauth_unavailable")
    assert made == Refusal(
        400,
        "exchange_failed:oauth_unavailable",
        "The provider's token endpoint didn't take the sign-in (oauth_unavailable). Connect again.",
    )
    with pytest.raises(ValueError, match="code"):
        refusal("exchange_failed")
    # Only exchange_failed carries a code.
    with pytest.raises(ValueError, match="code"):
        refusal("flow_unknown:x")


def test_more_fields_go_beside_the_text() -> None:
    made = Refusal(409, "binding_changed", "text", (("old_shown", "a"), ("new_shown", "b")))
    assert made.body() == {
        "old_shown": "a",
        "new_shown": "b",
        "error": "text",
        "reason": made.reason,
    }
    # They can't replace the text or the reason.
    clash = Refusal(400, "bad_body", "text", (("error", "x"), ("reason", "y")))
    assert clash.body() == {"error": "text", "reason": "bad_body"}
    assert refusal("busy").more == ()


@pytest.mark.parametrize(
    ("reason", "text"),
    [
        ("no_route", "The policy can't bind it: no route uses x. Fix the policy."),
        ("provider_error", "The answer said the provider refused: access_denied"),
        (
            "redirect_mismatch",
            "That isn't the address the provider sent you to; it starts with "
            "http://127.0.0.1/callback.",
        ),
        (
            "exchange_failed:oauth_client_rejected",
            "The provider's token endpoint didn't take the sign-in (oauth_client_rejected). "
            "Connect again.",
        ),
        ("flow_unknown", TEXTS["flow_unknown"]),
        ("too_many_flows", CATALOGUE["too_many_flows"].text),
    ],
)
def test_a_login_refusal_fills_what_its_text_names(reason: str, text: str) -> None:
    made = login_refusal(
        reason,
        detail="no route uses x",
        error="access_denied",
        redirect_uri="http://127.0.0.1/callback",
    )
    assert made == Refusal(CATALOGUE[reason.partition(":")[0]].status, reason, text)


def test_a_provider_error_without_a_code() -> None:
    made = login_refusal("provider_error", detail="the provider refused")
    assert made.error == "The answer said the provider refused: no error code"
    assert login_refusal("redirect_mismatch", detail="x").error.endswith("it starts with .")


def test_an_enrolment_refusal() -> None:
    assert enrolment("key_encoding") == Refusal(
        400, "key_encoding", "This authenticator's key encoding isn't supported."
    )
    assert enrolment("not_verified").error == (
        "The passkey didn't verify you with a PIN or biometrics; the vault requires it."
    )
    assert enrolment("key_mismatch").error == (
        "The browser's copy of the new key doesn't match the authenticator's. Try another browser."
    )


@pytest.mark.parametrize("reason", sorted(get_args(webauthn.Reason)))
def test_each_enrolment_status(reason: webauthn.Reason) -> None:
    made = enrolment(reason)
    conflict = reason in {"duplicate_credential", "too_many_passkeys"}
    assert made == Refusal(409 if conflict else 400, reason, WEBAUTHN[reason])


def test_a_secret_refusal_keeps_the_plans_status_and_reason() -> None:
    name = "notes-key"
    assert secret(SecretRefusal(400, "invalid_name", "invalid secret name"), name=name) == Refusal(
        400, "invalid_name", CATALOGUE["invalid_name"].text
    )
    # The binding says "not an oauth2 credential": 409, where a login answers 404.
    assert secret(SecretRefusal(409, "not_oauth", "x"), name=name).status == 409
    assert refusal("not_oauth").status == 404


def test_a_secret_refusal_names_the_secret_or_quotes_the_policy() -> None:
    unbound = secret(SecretRefusal(409, "unbound", "the policy doesn't use it"), name="notes-key")
    assert unbound.error == (
        "No route or connector uses store:notes-key, so give the origins it may be sent to."
    )
    detail = f"no route uses credential 'mail'{ZWSP}"
    for reason in ("no_route", "orphan_slot", "binding_conflict"):
        made = secret(SecretRefusal(409, reason, detail), name="x")
        assert made == Refusal(
            409,
            reason,
            "The policy can't bind it: no route uses credential 'mail'[U+200B]. Fix the policy.",
        )
    origins = secret(SecretRefusal(409, "bad_origins", "not an absolute URL: 'x'"), name="x")
    assert origins.error == "That origin can't be used: not an absolute URL: 'x'."
    named = secret(SecretRefusal(409, "unbound", "x"), name=f"a{ZWSP}")
    assert "store:a[U+200B]," in named.error


def test_a_secret_that_was_not_written_is_kept_in_memory() -> None:
    made = secret(secretplan.NOT_WRITTEN_REFUSAL, name="notes-key")
    assert made == Refusal(500, "not_written", KEPT_IN_MEMORY)
    assert refusal("not_written").error == TEXTS["not_written"]


def test_a_secret_not_found() -> None:
    assert secret(secretplan.NOT_FOUND, name="x") == Refusal(
        404, "not_found", "Nothing by that name exists here."
    )


def test_a_loopback_literal_host() -> None:
    assert wrong_host_literal("localhost:8081") == Refusal(
        421,
        "wrong_host",
        "Passkeys don't work on IP addresses. Open http://localhost:8081/ instead.",
    )
    assert wrong_host_literal("localhost").error.endswith("Open http://localhost/ instead.")
