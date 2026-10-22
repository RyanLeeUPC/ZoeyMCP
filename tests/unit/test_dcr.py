"""Pure dynamic client registration (M7 design D.4, D.6's backstop, X7; O.2 ``test_dcr.py``).

The redirect address each kind of client registers or uses, ``application_type`` by the
redirect's host whatever the scheme (an https loopback portal origin included, SPEC-6), the
authentication asked for in D.4's order, the request's exact members, and the answer checked row
by row of X7's table, each refusal reason reached here. The answer's registration access token
and URI never reach the :class:`Registration`, which hides its secret.
"""

from __future__ import annotations

import json
from dataclasses import fields, replace
from typing import Any, get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.portal.refusals import CATALOGUE
from zoeymcp.vault.oauth import dcr
from zoeymcp.vault.oauth.dcr import (
    DESCRIPTION_MAX,
    GRANT_TYPES,
    NOTES,
    PASTE_REDIRECT,
    SHARED_REDIRECT,
    Choices,
    Refusal,
    Registration,
    application_type,
    check_registration,
    client_name,
    description,
    literal_client_id,
    notes,
    redirect_for,
    registration_request,
    request_auth,
    request_body,
)
from zoeymcp.vault.oauth.discovery import Plan, Scopes

from .test_onboarding import plan

PORTAL = "https://zoeymcp.tailnet.example"
OWN = "http://127.0.0.1/callback/notes"
REQUEST: dict[str, Any] = {
    "client_name": "ZoeyMCP (notes)",
    "redirect_uris": [OWN],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
    "application_type": "native",
    "scope": "notes.read",
}


def answer(**changes: Any) -> dict[str, Any]:
    """A public client's registration answer, as an RFC 7591 server sends one."""
    found: dict[str, Any] = {
        "client_id": "issued-client-1",
        "client_id_issued_at": 1_790_000_000,
        "redirect_uris": [OWN],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    found.update(changes)
    return {key: value for key, value in found.items() if value is not None}


def with_id(client_id: object) -> dict[str, Any]:
    """An answer whose ``client_id`` is ``client_id``, or has none for None."""
    found = answer()
    del found["client_id"]
    return found if client_id is None else {**found, "client_id": client_id}


def confidential(**changes: Any) -> dict[str, Any]:
    """A confidential client's answer: a secret, by basic unless ``changes`` say otherwise."""
    found = {
        "token_endpoint_auth_method": "client_secret_basic",
        "client_secret": "issued-secret-1",
    }
    return answer(**{**found, **changes})


def basic_request() -> dict[str, Any]:
    return {**REQUEST, "token_endpoint_auth_method": "client_secret_basic"}


def refused(found: Registration | Refusal) -> Refusal:
    assert isinstance(found, Refusal)
    return found


def registered(found: Registration | Refusal) -> Registration:
    assert isinstance(found, Registration)
    return found


# --- the redirect address (D.4, DD-16, GR-3) -----------------------------------------------------


@pytest.mark.parametrize(
    ("origin", "override", "given_client", "expected"),
    [
        # The operator's own wins, whatever else is set.
        (None, "http://127.0.0.1:8765/cb", False, "http://127.0.0.1:8765/cb"),
        (PORTAL, "http://127.0.0.1:8765/cb", True, "http://127.0.0.1:8765/cb"),
        # A given client: the shared address operator-registered clients use (D-15).
        (None, None, True, SHARED_REDIRECT),
        (PORTAL, None, True, SHARED_REDIRECT),
        # A registration: the credential's own paste address, or the portal origin's callback.
        (None, None, False, OWN),
        (PORTAL, None, False, f"{PORTAL}/oauth/callback/notes"),
        ("http://localhost:8081", None, False, "http://localhost:8081/oauth/callback/notes"),
    ],
)
def test_the_redirect_address(
    origin: str | None, override: str | None, given_client: bool, expected: str
) -> None:
    assert redirect_for("notes", origin, override, given=given_client) == expected


def test_the_addresses_are_the_schemas() -> None:
    assert SHARED_REDIRECT == "http://127.0.0.1/callback"
    assert OAuth2Credential.model_fields["redirect_uri"].default == SHARED_REDIRECT
    assert PASTE_REDIRECT == "http://127.0.0.1/callback/"
    # Each address a registration makes is one a credential can hold.
    for origin in (None, PORTAL):
        address = redirect_for("notes", origin, None, given=False)
        OAuth2Credential.model_validate(
            {
                "kind": "oauth2",
                "token_url": "https://auth.notes.example/token",
                "client_id": "c",
                "redirect_uri": address,
            }
        )


@pytest.mark.parametrize(
    ("redirect", "kind"),
    [
        ("http://127.0.0.1/callback/notes", "native"),
        ("http://127.0.0.1:8765/callback", "native"),
        ("http://[::1]:8000/callback", "native"),
        ("http://localhost:8081/oauth/callback/notes", "native"),
        # SPEC-6: an https portal on a loopback origin is native too, by its host.
        ("https://localhost:8443/oauth/callback/notes", "native"),
        ("https://127.0.0.1:8443/oauth/callback/notes", "native"),
        ("https://zoeymcp.tailnet.example/oauth/callback/notes", "web"),
        ("https://10.0.0.1/cb", "web"),
        ("https://localhost.example/cb", "web"),
    ],
)
def test_application_type_by_the_redirect_host(redirect: str, kind: str) -> None:
    assert application_type(redirect) == kind


# --- the request (D.4) ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("supported", "method"),
    [
        (("none", "client_secret_basic", "client_secret_post"), "none"),
        (("client_secret_post", "client_secret_basic", "none"), "none"),
        (("client_secret_post", "client_secret_basic"), "client_secret_basic"),
        (("private_key_jwt", "client_secret_post"), "client_secret_post"),
    ],
)
def test_a_public_client_first(supported: tuple[str, ...], method: str) -> None:
    assert request_auth(supported) == method


def test_no_authentication_the_vault_speaks() -> None:
    for supported in ((), ("private_key_jwt", "tls_client_auth")):
        assert request_auth(supported) == Refusal(
            "dcr_auth_unsupported", field="token_endpoint_auth_methods_supported"
        )


def scoped(*scopes: str) -> Plan:
    return replace(plan(), scopes=Scopes(scopes, "prm", False))


def test_the_request_has_exactly_its_members() -> None:
    made = registration_request(scoped("notes.read"), Choices("notes", OWN, "none"))
    assert made == REQUEST
    assert list(made) == list(REQUEST)
    assert request_body(made) == json.dumps(REQUEST, separators=(",", ":")).encode()
    assert b" " not in request_body(made).replace(b"ZoeyMCP (notes)", b"")


def test_the_request_with_the_operators_choices() -> None:
    choices = Choices(
        "files", f"{PORTAL}/oauth/callback/files", "client_secret_post", "My agent's files"
    )
    made = registration_request(scoped("files.read", "offline_access"), choices)
    assert made == {
        "client_name": "My agent's files",
        "redirect_uris": [f"{PORTAL}/oauth/callback/files"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_post",
        "application_type": "web",
        "scope": "files.read offline_access",
    }


def test_no_scopes_no_scope_member() -> None:
    made = registration_request(scoped(), Choices("notes", OWN, "none"))
    assert "scope" not in made
    # Never a contact, logo, URI, key, statement or DPoP member (RFC 7591 6, D-19).
    assert set(made) == {
        "client_name",
        "redirect_uris",
        "grant_types",
        "response_types",
        "token_endpoint_auth_method",
        "application_type",
    }


def test_the_client_name() -> None:
    assert client_name("notes", None) == "ZoeyMCP (notes)"
    assert client_name("notes", "Mine") == "Mine"
    assert GRANT_TYPES == ("authorization_code", "refresh_token")


# --- the answer (X7) -----------------------------------------------------------------------------


def test_a_public_client() -> None:
    made = registered(check_registration(201, answer(), REQUEST))
    assert (made.client_id, made.auth, made.client_secret, made.expires_at) == (
        "issued-client-1",
        "none",
        None,
        None,
    )
    assert registered(check_registration(200, answer(), REQUEST)) == made


@pytest.mark.parametrize(
    ("method", "auth"), [("client_secret_basic", "basic"), ("client_secret_post", "post")]
)
def test_a_confidential_client(method: str, auth: str) -> None:
    found = confidential(token_endpoint_auth_method=method, client_secret_expires_at=1_800_000_000)
    made = registered(check_registration(201, found, basic_request()))
    assert (made.client_id, made.auth, made.expires_at) == ("issued-client-1", auth, 1_800_000_000)
    assert made.client_secret is not None
    assert made.client_secret.reveal() == "issued-secret-1"


def test_the_registration_holds_four_things_and_hides_its_secret() -> None:
    """D-148: the registration access token and URI are never read out of the answer."""
    found = confidential(
        registration_access_token="rat-0001",
        registration_client_uri="https://auth.notes.example/register/c1",
    )
    made = registered(check_registration(201, found, basic_request()))
    assert [f.name for f in fields(made)] == ["client_id", "auth", "client_secret", "expires_at"]
    assert repr(made) == "Registration(client_id='issued-client-1', auth='basic')"
    assert "issued-secret-1" not in repr(made) + str(made)
    assert "rat-0001" not in repr(vars(made)) + repr(made.client_secret)


def test_a_400_is_the_servers_refusal() -> None:
    said = "Bad metadata\r\nX-Injected: 1 \u202e<b>Approve</b>" + "x" * 300
    found = refused(
        check_registration(
            400, {"error": "invalid_redirect_uri", "error_description": said}, REQUEST
        )
    )
    assert (found.reason, found.values[0]) == ("dcr_refused", "invalid_redirect_uri")
    shown = found.values[1]
    assert shown.startswith("Bad metadata[U+000D] X-Injected: 1 [U+202E]<b>Approve</b>")
    assert len(shown) == 200
    assert not any(c in shown for c in "\r\n\u202e")


@pytest.mark.parametrize(
    ("body", "values"),
    [
        (None, ("no error code",)),
        ({}, ("no error code",)),
        ({"error": "not a code!"}, ("other",)),
        (
            {"error": "invalid_client_metadata", "error_description": 7},
            ("invalid_client_metadata",),
        ),
        (
            {"error": "invalid_client_metadata", "error_description": " \t "},
            ("invalid_client_metadata",),
        ),
    ],
)
def test_a_400_without_a_usable_error(body: dict[str, Any] | None, values: tuple[str, ...]) -> None:
    assert check_registration(400, body, REQUEST) == Refusal("dcr_refused", values=values)


@pytest.mark.parametrize("status", [201, 200, 202, 204, 302, 401, 403, 404, 500, 503])
def test_any_other_answer_is_its_status(status: int) -> None:
    expected = Refusal("dcr_failed", values=(str(status),))
    if status in (200, 201):
        assert check_registration(status, None, REQUEST) == expected
    else:
        assert check_registration(status, answer(), REQUEST) == expected


@pytest.mark.parametrize(
    "client_id",
    [
        None,
        7,
        "",
        "has space",
        'has"quote',
        "has\\backslash",
        "has$dollar",
        "has\u202ebidi",
        "has\ttab",
        "x" * 256,
        # A policy reads these as references to secrets the vault would send (X7).
        "store:notes-refresh",
        "env:ZOEYMCP_MASTER_KEY",
        "env:",
    ],
)
def test_a_client_id_a_policy_cant_hold(client_id: object) -> None:
    found = check_registration(201, with_id(client_id), REQUEST)
    assert found == Refusal("dcr_bad_client_id", field="client_id")
    assert not literal_client_id(client_id)


def test_a_client_id_at_its_limits() -> None:
    for client_id in ("x", "x" * 255, "a!#%&'()*+,-./:;<=>?@[]^_`{|}~", "https://client.example/x"):
        assert registered(check_registration(201, answer(client_id=client_id), REQUEST))
        assert literal_client_id(client_id)
    # A prefix that is no reference's.
    assert literal_client_id("stores:x")
    assert literal_client_id("environment:x")


@pytest.mark.parametrize(
    "redirects",
    [["https://attacker.example/callback"], [OWN, "http://127.0.0.1/callback/other"], [], OWN],
)
def test_another_redirect_address(redirects: object) -> None:
    found = check_registration(201, answer(redirect_uris=redirects), REQUEST)
    assert found == Refusal("dcr_redirect_changed", field="redirect_uris")


def test_redirect_uris_absent_is_the_ones_asked_for() -> None:
    found = answer()
    del found["redirect_uris"]
    assert registered(check_registration(201, found, REQUEST))


@pytest.mark.parametrize(
    "method", ["private_key_jwt", "tls_client_auth", "client_secret_jwt", 7, ["none"], {"a": 1}]
)
def test_an_authentication_the_vault_doesnt_speak(method: object) -> None:
    found = confidential(token_endpoint_auth_method=method)
    assert check_registration(201, found, basic_request()) == Refusal(
        "dcr_auth_unsupported", field="token_endpoint_auth_method"
    )


def test_an_absent_method_is_the_one_asked_for() -> None:
    found = confidential()
    del found["token_endpoint_auth_method"]
    assert registered(check_registration(201, found, basic_request())).auth == "basic"
    public = answer()
    del public["token_endpoint_auth_method"]
    assert registered(check_registration(201, public, REQUEST)).auth == "none"
    # Asked for none, and a secret came back with no method named: a secret too many.
    assert refused(check_registration(201, {**public, "client_secret": "s"}, REQUEST)).reason == (
        "dcr_bad_secret"
    )


@pytest.mark.parametrize(
    ("found", "request_sent"),
    [
        # A secret for a public client, none for a confidential one.
        (answer(client_secret="surprise"), REQUEST),
        (confidential(client_secret=None), basic_request()),
        # One the store can't take, or isn't a string.
        (confidential(client_secret=""), basic_request()),
        (confidential(client_secret="x" * 513), basic_request()),
        (confidential(client_secret="line\nbreak"), basic_request()),
        (confidential(client_secret="bidi\u202e"), basic_request()),
        (confidential(client_secret=12345), basic_request()),
        # The method changed to one with a secret, and none came.
        (answer(token_endpoint_auth_method="client_secret_post"), REQUEST),
    ],
)
def test_a_secret_that_doesnt_fit(found: dict[str, Any], request_sent: dict[str, Any]) -> None:
    assert check_registration(201, found, request_sent) == Refusal(
        "dcr_bad_secret", field="client_secret"
    )


def test_a_secret_at_its_limits() -> None:
    for secret in ("x", "x" * 512, "with space ~!"):
        made = registered(check_registration(201, confidential(client_secret=secret), REQUEST))
        assert made.client_secret is not None
        assert made.client_secret.reveal() == secret


@pytest.mark.parametrize(
    "grants",
    [["authorization_code"], ["refresh_token"], [], ["client_credentials", "refresh_token"]],
)
def test_the_grants_registered(grants: list[str]) -> None:
    assert check_registration(201, answer(grant_types=grants), REQUEST) == Refusal(
        "dcr_grant_missing", field="grant_types"
    )


@pytest.mark.parametrize("grants", ["authorization_code refresh_token", [1, 2], {"a": 1}])
def test_grants_of_the_wrong_type(grants: object) -> None:
    assert check_registration(201, answer(grant_types=grants), REQUEST) == Refusal(
        "dcr_answer_invalid", field="grant_types"
    )


def test_grants_absent_are_the_rfcs_default_and_noted() -> None:
    """MISS-9: kept, noted, and login's no_refresh_token refusal decides."""
    found = answer()
    del found["grant_types"]
    assert registered(check_registration(201, found, REQUEST))
    assert notes(found) == ("grant_types_absent",)
    assert notes(answer()) == ()
    assert notes(answer(grant_types=["authorization_code", "refresh_token", "x"])) == ()
    assert NOTES == {
        "grant_types_absent": "The authorization server didn't say which grants it registered, "
        "so the RFC's default, the authorization code alone, is assumed; sign-in refuses an "
        "answer with no refresh token."
    }


@pytest.mark.parametrize("expires", [-1, "1800000000", 1.5, True, False, [1]])
def test_a_malformed_expiry(expires: object) -> None:
    found = confidential(client_secret_expires_at=expires)
    assert check_registration(201, found, basic_request()) == Refusal(
        "dcr_answer_invalid", field="client_secret_expires_at"
    )


@pytest.mark.parametrize("expires", [0, 1, 1_800_000_000, 2**40])
def test_an_expiry(expires: int) -> None:
    found = confidential(client_secret_expires_at=expires)
    assert registered(check_registration(201, found, basic_request())).expires_at == expires


def test_the_checks_go_in_x7s_order() -> None:
    """Each answer below breaks two rows: the earlier row's reason is the one answered."""
    request = basic_request()
    worst = confidential(
        client_id="bad id",
        redirect_uris=["https://attacker.example/cb"],
        token_endpoint_auth_method="private_key_jwt",
        client_secret=None,
        grant_types=["authorization_code"],
        client_secret_expires_at=-1,
    )
    order = [
        ("client_id", "issued-client-1", "dcr_bad_client_id"),
        ("redirect_uris", [OWN], "dcr_redirect_changed"),
        ("token_endpoint_auth_method", "client_secret_basic", "dcr_auth_unsupported"),
        ("client_secret", "s", "dcr_bad_secret"),
        ("grant_types", ["authorization_code", "refresh_token"], "dcr_grant_missing"),
        ("client_secret_expires_at", 0, "dcr_answer_invalid"),
    ]
    for key, fixed, reason in order:
        assert refused(check_registration(201, worst, request)).reason == reason
        worst[key] = fixed
    assert registered(check_registration(201, worst, request))


def test_the_limits() -> None:
    """M.6's numbers: a client ID, a client secret, a client name, a refusal's description."""
    limits = (dcr.CLIENT_ID_MAX, dcr.CLIENT_SECRET_MAX, dcr.CLIENT_NAME_MAX, DESCRIPTION_MAX)
    assert limits == (255, 512, 64, 200)


def test_a_description_is_one_capped_line() -> None:
    assert description(None) is None
    assert description(["x"]) is None
    assert description("") is None
    assert description("  two\n\nlines\t here ") == "two lines here"
    assert len(str(description("y" * 1000))) == 200


@settings(max_examples=60, deadline=None)
@given(
    client_id=st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=260)
)
def test_every_client_id_taken_loads_in_a_policy(client_id: str) -> None:
    """X7, X10: an accepted client ID is one a credential holds as written, never a reference."""
    found = check_registration(201, with_id(client_id), REQUEST)
    if isinstance(found, Registration):
        cred = OAuth2Credential.model_validate(
            {
                "kind": "oauth2",
                "token_url": "https://auth.notes.example/token",
                "client_id": client_id,
            }
        )
        assert cred.client_id == client_id
        assert not any(c in client_id for c in ' "\\$')
        assert not client_id.startswith(("store:", "env:"))
    else:
        assert found.reason == "dcr_bad_client_id"


def test_the_reasons_are_the_catalogues() -> None:
    assert set(get_args(dcr.Reason)) <= set(CATALOGUE)
    assert {CATALOGUE[reason].status for reason in get_args(dcr.Reason)} == {502}
