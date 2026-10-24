"""The refusal catalogue (M5 design M.2, O.2 ``refusals``): every reason has a status and a text.

The reasons come from the deciding modules, read from their code here (the WebAuthn and secret
``Reason`` literals, every literal ``LoginError`` and ``RedirectError`` reason, and from M7 every
literal discovery and registration ``Refusal``, policy ``ChangeRefused``, ``OnboardingRefused``,
fetch error, review report ``ReportRefused`` and review job ``ReviewRefused`` reason, every way a
review job fails, and every refusal the onboarding service words itself), so a reason added there
without a sentence here fails.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from string import Formatter
from types import ModuleType
from typing import get_args

import pytest

from zoeymcp.cli import policy as policy_cli
from zoeymcp.common import reviewreport
from zoeymcp.common.policy import change, plan
from zoeymcp.common.policy.ratchet import RATCHET_MAX
from zoeymcp.common.textrules import find_violations
from zoeymcp.portal import passkeys, webauthn
from zoeymcp.portal.refusals import (
    CATALOGUE,
    KEPT_IN_MEMORY,
    WEBAUTHN,
    Refusal,
    enrolment,
    issuer_changed,
    reasons,
    refusal,
    secret,
    wrong_host_literal,
)
from zoeymcp.portal.refusals import login as login_refusal
from zoeymcp.vault import (
    admin,
    managed,
    onboard,
    onboarding,
    policystore,
    reviewjobs,
    secretplan,
    store,
)
from zoeymcp.vault.oauth import dcr, discovery, fetch, login, pkce
from zoeymcp.vault.policyseal import REVISION_MAX
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
# the shell's answer when a handler fails (step 10b), two passkeys sharing a fingerprint (step
# 7a's holder, answered from step 12), and a reported copy that can't be read (step 15: M.2's
# 503 unavailable has the passkey file's text).
EXTRA = {
    "value_too_large": 409,
    "not_configured": 400,
    "internal": 500,
    "ambiguous_fingerprint": 409,
    "copy_unavailable": 503,
}
# M7's M.2: onboarding's discovery refusals (M7 step 6), with M7's statuses.
DISCOVERY = {
    "url_invalid": 400,
    "endpoint_invalid": 502,
    "url_dollar": 502,
    "challenge_ambiguous": 502,
    "scope_invalid": 502,
    "not_protected": 409,
    "prm_not_found": 502,
    "prm_invalid": 502,
    "prm_resource_mismatch": 502,
    "dpop_required": 502,
    "as_choice_needed": 409,
    "as_unknown": 400,
    "as_metadata_not_found": 502,
    "as_metadata_invalid": 502,
    "as_issuer_mismatch": 502,
    "pkce_unsupported": 502,
    "code_flow_unsupported": 502,
}
# M7's M.2: a policy change's refusals (M7 step 7), and what the portal's ops may not hold (M6
# design G.3, N.2).
CHANGE = {
    "name_taken": 409,
    "diff_invalid": 422,
    "portal_env_ref": 403,
    "route_reuses_credential": 403,
}
# M7's M.2: an onboarding's own refusals and phase 1's requests' (M7 step 8a1).
ONBOARDING = {
    "onboarding_unknown": 404,
    "onboarding_busy": 429,
    "onboarding_options_changed": 409,
}
# M7's M.2: the onboarding service's own (M7 step 8a2), and login's check of an onboarded
# client's secret (D.7); through the built-in egress role (M7 step 17b; I.3, TI-10).
SERVICE = {
    "registration_unavailable": 409,
    "proxy_refused": 502,
    "egress_refused": 502,
    "private_needs_direct": 409,
}
# M7's M.2: a registration the vault makes (M7 step 11; D.4, X7), and a server that registers
# clients by metadata document alone.
DCR = {
    "cimd_only": 409,
    "dcr_refused": 502,
    "dcr_failed": 502,
    "dcr_redirect_changed": 502,
    "dcr_auth_unsupported": 502,
    "dcr_bad_client_id": 502,
    "dcr_bad_secret": 502,
    "dcr_grant_missing": 502,
    "dcr_answer_invalid": 502,
}
# M7's M.2: the second run's and a re-registration's (M7 step 8b; D.12, D-184).
SECOND_RUN = {"already_configured": 409, "onboarding_mismatch": 409, "reregister_by_hand": 409}
LOGIN7 = {"client_secret_binding_changed": 409}
# M7's M.2: a required iss missing from the answer (M7 step 9; D.6).
MIXUP = {"iss_missing": 400}
# A generated token for an OAuth or connector secret (M7 step 18c2; C.2, GR-27).
GENERATE = {"generate_refused": 409}
FETCH = {
    "address_refused": 502,
    "resolve_failed": 502,
    "fetch_failed": 502,
    "fetch_redirect": 502,
    "fetch_too_large": 502,
    "fetch_not_json": 502,
}
# M7's M.2: a review report the vault refuses (M7 step 12a; F.4).
REPORT = {"review_invalid": 502, "pin_mismatch": 502, "review_too_large": 413}
# M7's M.2: review jobs (M7 step 12b1; F.2), job_unknown 409 (PC-6), and a job's failures.
REVIEW = {
    "review_busy": 409,
    "review_unknown_server": 404,
    "job_unknown": 409,
    "review_failed": 502,
    "review_timeout": 504,
    "review_jobs_full": 429,
    "review_unavailable": 503,
    "review_stale": 409,
    # M6 J.4: a clear the polling gateway can't run, and one it refused (N.2).
    "clear_unsupported": 409,
    "clear_not_clean": 409,
}
# M6's N.2: a managed save the planner refuses (common/policy/plan.py; review_stale is above).
PLAN = {
    "kind_mismatch": 400,
    "allow_needs_review": 409,
    "allow_marked": 409,
    "consequential_allow": 409,
    "generation_lowered": 400,
    "pin_retired": 409,
    "rollback_revives": 409,
    "revives_client": 409,
    "revives_caller": 409,
    "env_name_new": 403,
    "env_reach_grows": 403,
    "ratchet_full": 409,
    "portal_widens": 403,
    "generation_raise_from_portal": 403,
    "summary_too_large": 413,
    "no_change": 400,
}
# M6's N.2: a managed write or a reseed the policy store didn't make (vault/policystore.py,
# steps 13a and 13c).
STORE = {"policy_write_failed": 500, "revision_out_of_range": 400, "reseed_incomplete": 500}
# A managed write's own refusals (M6 design G.6, N.2; vault/managed.py), changed and
# generation_lowered among them, catalogued already.
MANAGED = {
    "policy_not_running": 409,
    "policy_moved": 409,
    "plan_changed": 409,
    "import_refused": 400,
    "saved_not_running": 500,
}
# The host's offline seed and reseed (M6 design F.3, N.2; cli/policy.py, step 13c);
# import_refused and generation_lowered among them, catalogued already.
OFFLINE = {
    "state_as_root": 400,
    "state_locked": 409,
    "seed_declarative": 400,
    "import_declarative": 400,
    "policy_store_present": 409,
    "reseed_needs_new_ratchet": 409,
}
# The admin socket's policy routes and the host's commands on them (M6 design H, N.1, N.2;
# vault/admin.py, cli/policy.py, step 14a); import_declarative, import_refused and plan_changed
# among them, catalogued already.
SOCKET = {
    "policy_not_managed": 409,
    "base_required": 428,
    "export_other_deployment": 400,
    "import_widens": 400,
    "lockout_unconfirmed": 400,
    "nothing_to_acknowledge": 409,
    "revision_unreadable": 409,
    "revision_unknown": 409,
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
    "iss_missing": "The answer didn't name its issuer, which this provider always does; nothing "
    "was stored. Connect again.",
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
    "url_invalid": {"detail"},
    "endpoint_invalid": {"field", "detail"},
    "url_dollar": {"field"},
    "prm_invalid": {"detail"},
    "prm_resource_mismatch": {"resource", "expected"},
    "as_choice_needed": {"issuers"},
    "as_unknown": {"issuers"},
    "as_metadata_invalid": {"detail"},
    "name_taken": {"name"},
    "diff_invalid": {"detail"},
    "address_refused": {"host"},
    "resolve_failed": {"host"},
    "fetch_failed": {"host", "detail"},
    "fetch_redirect": {"host"},
    "fetch_too_large": {"host"},
    "fetch_not_json": {"host"},
    "registration_unavailable": {"host"},
    "cimd_only": {"host"},
    "dcr_refused": {"error"},
    "dcr_failed": {"detail"},
    "dcr_answer_invalid": {"detail"},
    "proxy_refused": {"host"},
    "egress_refused": {"host"},
    "already_configured": {"server", "kind"},
    "onboarding_mismatch": {"fields"},
    "reregister_by_hand": {"credential", "field", "why"},
    "review_invalid": {"detail"},
    "pin_mismatch": {"tools"},
    "review_too_large": {"detail"},
    "review_unknown_server": {"server"},
    "review_busy": {"server"},
    "review_unavailable": {"detail"},
    "review_failed": {"code"},
    "clear_unsupported": {"server"},
    "clear_not_clean": {"tools"},
    "portal_env_ref": {"detail"},
    "route_reuses_credential": {"detail"},
    **{reason: {"detail"} for reason in set(PLAN) - {"ratchet_full", "no_change"}},
    "policy_not_running": {"revision"},
    "policy_moved": {"detail"},
    "import_refused": {"detail"},
    "saved_not_running": {"revision"},
    "state_locked": {"command"},
    "policy_store_present": {"state"},
    "reseed_needs_new_ratchet": {"detail"},
    "reseed_incomplete": {"detail"},
    "export_other_deployment": {"detail"},
    "import_widens": {"detail"},
    "lockout_unconfirmed": {"detail"},
    "nothing_to_acknowledge": {"detail"},
    "revision_unreadable": {"revision"},
    "revision_unknown": {"revision"},
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
    expected |= EXTRA | DISCOVERY | CHANGE | ONBOARDING | FETCH | SERVICE | LOGIN7 | SECOND_RUN
    expected |= MIXUP | DCR | REPORT | REVIEW | GENERATE | PLAN | STORE | MANAGED | OFFLINE
    expected |= SOCKET
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


def test_a_changed_issuer_names_both_terms() -> None:
    """A paste's or a confirm's binding_changed for the issuer terms (M7 D.6): shown with the
    text alone, so the text names them, and asks for no rebind."""
    made = issuer_changed(old="issuer https://a.example, iss required", new="no issuer, iss x")
    assert made == Refusal(
        409,
        "binding_changed",
        "The policy changed this credential's issuer since the sign-in started: it was issuer "
        "https://a.example, iss required, it is now no issuer, iss x. Nothing was stored. "
        "Connect again.",
    )
    assert not find_violations(made.error, max_chars=300, single_line=True, allow_tabs=False)


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
        "iss_missing",  # M7 D.6
        "iss_mismatch",
        "no_code",
        "callback_not_taken",  # callback_state's (H.6)
    }
    assert found <= set(CATALOGUE)


def test_every_login_reason_is_catalogued() -> None:
    found = literal_reasons(login, "LoginError")
    assert set(LOGIN7) <= found
    # The failure reasons of a client ref, and the token manager's own (tokens.client_for).
    found |= set(login._CLIENT_REFS) | {"not_configured"}
    assert "exchange_failed:" in found
    found = {reason.removesuffix(":") for reason in found}
    assert found <= set(CATALOGUE)


def test_every_discovery_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to discovery's refusals; each is a literal of its Reason type."""
    found = literal_reasons(discovery, "Refusal")
    assert found == set(get_args(discovery.Reason))
    assert found == set(DISCOVERY)
    assert found <= set(CATALOGUE)


def test_every_change_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to a policy change's refusals (H.1)."""
    found = literal_reasons(change, "ChangeRefused")
    assert found == set(get_args(change.Reason))
    assert found == set(CHANGE)
    assert found <= set(CATALOGUE)


def test_every_plan_reason_is_catalogued() -> None:
    """M6 N.2: the scan widens to the planner's refusals, each a literal of its Reason type; the
    socket's own names for a revived client or caller (which reach the portal as
    rollback_revives) are catalogued too, since the admin socket answers through the catalogue."""
    found = literal_reasons(plan, "PlanRefused")
    reasons = set(get_args(plan.Reason))
    assert found <= reasons
    assert reasons == set(PLAN) | {"review_stale"}
    assert {"revives_client", "revives_caller"} == plan.HOST_ONLY
    assert reasons <= set(CATALOGUE)


def test_the_plan_texts_name_the_planners_limits() -> None:
    assert f"holds {RATCHET_MAX:,} retired entries" in CATALOGUE["ratchet_full"].text
    assert plan.HOST_NEXT in CATALOGUE["summary_too_large"].text
    assert CATALOGUE["env_name_new"] == CATALOGUE["env_reach_grows"]


def test_every_store_reason_is_catalogued() -> None:
    """M6 N.2: the scan widens to the policy store's refusals (D.9, T-4), each a literal of its
    Reason type."""
    found = literal_reasons(policystore, "StoreRefused")
    assert found == set(get_args(policystore.Reason))
    assert found == set(STORE)
    assert found <= set(CATALOGUE)


def test_every_managed_write_reason_is_catalogued() -> None:
    """M6 N.2: the scan widens to the managed write's own refusals (G.6), each a literal of its
    Reason type; the planner's and the store's pass through by their own reasons."""
    found = literal_reasons(managed, "WriteRefused")
    assert found == set(get_args(managed.Reason))
    assert found == set(MANAGED) | {"changed", "generation_lowered"}
    assert found <= set(CATALOGUE)


def test_every_offline_reason_is_catalogued() -> None:
    """M6 N.2: the scan widens to the host's commands' refusals (F.3, H), each a literal of
    their Reason type; the gate's and the generation's pass through by their own reasons, and
    the planner's, the store's and the vault's by theirs."""
    found = literal_reasons(policy_cli, "OfflineRefused")
    assert found == set(get_args(policy_cli.Reason)) | {"import_refused", "generation_lowered"}
    assert set(get_args(policy_cli.Reason)) == set(OFFLINE) | {
        "policy_not_managed",
        "base_required",
        "export_other_deployment",
        "import_widens",
        "lockout_unconfirmed",
        "plan_changed",
    }
    assert found <= set(CATALOGUE)
    assert set(policy_cli.GRANT_FLAGS) <= set(get_args(plan.Reason))


def test_every_socket_policy_reason_is_catalogued() -> None:
    """M6 N.2: the admin socket's policy routes (N.1) refuse with the catalogue's reasons: its
    own (a literal of its PolicyReason type), an import's shape's (``vault/managed.py``), and
    the managed write's, the store's and the planner's, which pass through;
    ``revision_unreadable`` and ``revision_unknown`` are the store's ``Missing``."""
    found = literal_reasons(admin, "refusal")
    assert found == set(get_args(admin.PolicyReason))
    shaped = literal_reasons(managed, "refusal")
    assert shaped == {"import_declarative", "nothing_to_acknowledge"}
    missing = set(get_args(policystore.Missing))
    assert missing == {"revision_unreadable", "revision_unknown"}
    # export_other_deployment is the CLI's own (the export header it reads, OPS-8).
    assert set(SOCKET) <= found | shaped | missing | {"export_other_deployment"}
    assert found | shaped | missing <= set(CATALOGUE)


def test_the_offline_texts_name_the_vaults_uid() -> None:
    assert "--user 10001:10001." in CATALOGUE["state_as_root"].text
    assert "--reseed." in CATALOGUE["policy_store_present"].text
    assert "--new-ratchet" in CATALOGUE["reseed_needs_new_ratchet"].text


def test_the_store_texts_name_its_limits() -> None:
    assert f"above {REVISION_MAX:,}." in CATALOGUE["revision_out_of_range"].text
    assert "--new-ratchet." in CATALOGUE["reseed_incomplete"].text


def test_every_onboarding_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to the onboarding table's refusals (D.8), name_taken among them
    (FM-10), each a literal of its Reason type."""
    found = literal_reasons(onboarding, "OnboardingRefused")
    assert found == set(get_args(onboarding.Reason))
    assert found == set(ONBOARDING) | {"name_taken"}
    assert found <= set(CATALOGUE)


def test_every_fetch_reason_is_catalogued() -> None:
    """M7 M.2: phase 1's request refusals (B.2, B.5), each a literal of its Reason type."""
    found = literal_reasons(fetch, "_error")
    assert found == set(get_args(fetch.Reason))
    assert found == set(FETCH)
    assert found <= set(CATALOGUE)


def test_every_onboarding_service_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to vault/onboard.py. Its own refusals are literal; the rest it
    passes on from discovery, the table and the fetch layer, whose types are scanned above."""
    found = literal_reasons(onboard, "refusal")
    assert found == set(SERVICE) | set(SECOND_RUN) | {
        # A registration's own (D.4; the rest pass on from dcr, scanned below).
        "cimd_only",
        "dcr_refused",
        "dcr_failed",
        "dcr_answer_invalid",
        "bad_body",
        "name_taken",
        "onboarding_unknown",
        "diff_invalid",
        "not_written",
        "address_refused",
        "resolve_failed",
        "fetch_failed",
        # The second run's checks of a stored client secret, as login words them (D.7 step 5).
        "client_secret_binding_changed",
        "no_route",
    }
    assert found <= set(CATALOGUE)


def test_every_registration_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to dcr.py, each reason a literal of its Reason type."""
    found = literal_reasons(dcr, "Refusal")
    assert found == set(get_args(dcr.Reason))
    assert found == set(DCR) - {"cimd_only"}
    assert found <= set(CATALOGUE)


def test_every_review_report_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to the review report's refusals (F.4), each a literal of its
    Reason type."""
    found = literal_reasons(reviewreport, "ReportRefused")
    assert found == set(get_args(reviewreport.Reason))
    assert found == set(REPORT)
    assert found <= set(CATALOGUE)


def test_every_review_job_reason_is_catalogued() -> None:
    """M7 M.2: the scan widens to vault/reviewjobs.py, each refusal a literal of its Reason type;
    a job's failures are the clock's, the gateway's (a clear it refused among them, M6 J.4) and
    the review report's refusals."""
    found = literal_reasons(reviewjobs, "ReviewRefused")
    assert found == set(get_args(reviewjobs.Reason))
    failures = {reason for part in get_args(reviewjobs.Failure) for reason in get_args(part)}
    own = {"review_stale", "review_timeout", "review_failed", "clear_not_clean"}
    assert failures == own | set(REPORT)
    assert found | own == set(REVIEW)
    assert found | failures <= set(CATALOGUE)


def test_the_review_texts_name_the_tables_limits() -> None:
    """Each wait a review text names is the job table's (M.6)."""
    busy = (reviewjobs.QUEUE_TTL + reviewjobs.CLAIM_DEADLINE) / 60
    assert f"(at most {busy:.0f} minutes)" in CATALOGUE["review_busy"].text
    assert f"At most {reviewjobs.REVIEW_JOBS_MAX} reviews" in CATALOGUE["review_jobs_full"].text
    assert f"within {reviewjobs.QUEUE_TTL:.0f} seconds" in CATALOGUE["review_stale"].text
    timeout = reviewjobs.CLAIM_DEADLINE / 60
    assert f"within {timeout:.0f} minutes" in CATALOGUE["review_timeout"].text
    kept = reviewjobs.RESULT_TTL / 60
    assert f"more than {kept:.0f} minutes ago" in CATALOGUE["job_unknown"].text


def test_the_busy_text_names_the_tables_limits() -> None:
    text = CATALOGUE["onboarding_busy"].text
    assert f"At most {onboarding.ONBOARDINGS_MAX} onboardings" in text
    assert f"({onboarding.ONBOARDING_TTL / 60:.0f} minutes)" in text


def test_the_options_changed_text_names_the_tables_ttl() -> None:
    """Only a blocked onboarding refuses other options (D.11), and the CLI has no cancel: the
    text says when it ends."""
    text = CATALOGUE["onboarding_options_changed"].text
    assert "stopped at your proxy" in text
    assert f"once it expires ({onboarding.ONBOARDING_TTL / 60:.0f} minutes)" in text


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
