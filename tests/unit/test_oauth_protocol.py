from __future__ import annotations

import base64
import json
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp import __version__
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.vault.oauth import protocol
from zoeymcp.vault.oauth.protocol import (
    CREDENTIAL_UNAVAILABLE,
    MAX_TOKEN_BODY,
    OAUTH_CLIENT_REJECTED,
    OAUTH_MISCONFIGURED,
    OAUTH_RECONSENT_NEEDED,
    OAUTH_ROTATION_LOST,
    OAUTH_UNAVAILABLE,
    OAUTH_UNSUPPORTED,
    Client,
    Envelope,
    EnvelopeError,
    Expiry,
    Failure,
    GrantKind,
    Minted,
    Outcome,
    ScopeCheck,
    SlotState,
    SourceDecision,
    TokenResponse,
    backoff_delay,
    build_client_credentials,
    build_exchange,
    build_refresh,
    check_login_scopes,
    check_refresh_scopes,
    clamp_lifetime,
    classify,
    decide_source,
    encode_envelope,
    parse_envelope,
    parse_lifetime,
    parse_retry_after,
    parse_scope,
    parse_token_body,
    safe_error_code,
    schedule,
    seed_sha256,
    transport_failure,
    valid_access_token,
    valid_refresh_token,
    with_query,
)
from zoeymcp.vault.store import Secret

TOKEN_URL = "https://accounts.example/oauth/token"
JSON = "application/json"
FORM = "application/x-www-form-urlencoded"
UA = ("user-agent", f"zoeymcp/{__version__}")
ACCEPT = ("accept", "application/json")
FORM_TYPE = ("content-type", FORM)
JSON_TYPE = ("content-type", JSON)
NOW = datetime(2026, 10, 17, 9, 0, tzinfo=UTC).timestamp()


def cred(**fields: Any) -> OAuth2Credential:
    raw: dict[str, Any] = {"kind": "oauth2", "token_url": TOKEN_URL, "client_id": "app-1"}
    raw.update(fields)
    return OAuth2Credential.model_validate(raw)


def confidential(**fields: Any) -> OAuth2Credential:
    return cred(client_secret="store:client-secret", **fields)


SECRET_CLIENT = Client("app-1", Secret("cs-value-1"))
PUBLIC_CLIENT = Client("app-1")


def test_the_named_boundaries_are_pinned() -> None:
    assert protocol.ATTEMPT_DEADLINE == 20.0
    assert protocol.CONNECT_TIMEOUT == 5.0
    assert protocol.REPLAY_DELAY == 1.0
    assert protocol.REFRESH_BUDGET == 41.0
    assert protocol.EXCHANGE_DEADLINE == 20.0
    assert protocol.DRAIN_TIMEOUT == 45.0
    assert protocol.MAX_TOKEN_BODY == 65536
    assert protocol.MIN_LIFETIME == 60
    assert protocol.MAX_LIFETIME == 86400
    assert protocol.MIN_401_AGE == 30.0
    assert protocol.BACKOFF == (5.0, 15.0, 60.0, 300.0, 900.0)
    assert protocol.JITTER == (0.9, 1.1)
    assert protocol.RETRY_AFTER_CAP == 3600.0
    assert protocol.RATE_LIMIT_DEFAULT == 60.0
    assert protocol.GRANT_WARN_DAYS == 14
    assert CREDENTIAL_UNAVAILABLE == "credential_unavailable"
    assert OAUTH_RECONSENT_NEEDED == "oauth_reconsent_needed"
    assert OAUTH_ROTATION_LOST == "oauth_rotation_lost"
    assert OAUTH_CLIENT_REJECTED == "oauth_client_rejected"
    assert OAUTH_MISCONFIGURED == "oauth_misconfigured"
    assert OAUTH_UNSUPPORTED == "oauth_unsupported"
    assert OAUTH_UNAVAILABLE == "oauth_unavailable"


def test_the_error_code_sets_are_pinned() -> None:
    assert {"invalid_grant", "bad_refresh_token", "invalid_refresh_token"} == protocol.GRANT_ERRORS
    assert {
        "invalid_client",
        "unauthorized_client",
        "incorrect_client_credentials",
    } == protocol.CLIENT_ERRORS
    assert {
        "invalid_scope",
        "invalid_target",
        "invalid_request",
        "unsupported_grant_type",
    } == protocol.CONFIG_ERRORS
    assert {"use_dpop_nonce"} == protocol.UNSUPPORTED_ERRORS
    assert {"temporarily_unavailable", "slow_down", "server_error"} == protocol.RETRY_ERRORS


# --- shapes and error codes --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("invalid_grant", "invalid_grant"),
        ("a.b-c_D9", "a.b-c_D9"),
        ("x" * 64, "x" * 64),
        ("x" * 65, "other"),
        ("", "other"),
        ("bad code", "other"),
        ("line\nbreak", "other"),
        ("caf\u00e9", "other"),
        (5, "other"),
        (["invalid_grant"], "other"),
    ],
)
def test_safe_error_code(value: object, expected: str | None) -> None:
    assert safe_error_code(value) == expected


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("a", True),
        ("!~", True),
        ("a" * 16384, True),
        ("a" * 16385, False),
        ("", False),
        ("a b", False),
        ("a\r\nb", False),
        ("a\n", False),
        ("a\x7f", False),
        ("caf\u00e9", False),
        (5, False),
        (None, False),
    ],
)
def test_valid_access_token(value: object, valid: bool) -> None:
    assert valid_access_token(value) is valid


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("a", True),
        ("a b", True),
        ("Xa", True),
        ("aX", True),
        ("a" * 8192, True),
        ("a" * 8193, False),
        ("", False),
        (" a", False),
        ("a ", False),
        (" ", False),
        ("a\tb", False),
        ("a\n", False),
        ("caf\u00e9", False),
        (5, False),
        (None, False),
    ],
)
def test_valid_refresh_token(value: object, valid: bool) -> None:
    assert valid_refresh_token(value) is valid


# --- request builders --------------------------------------------------------------------------


def test_refresh_with_basic_auth() -> None:
    request = build_refresh(confidential(scope="a b"), SECRET_CLIENT, Secret("rt-1"))
    basic = base64.b64encode(b"app-1:cs-value-1").decode()
    assert request.url == TOKEN_URL
    assert request.headers == (ACCEPT, FORM_TYPE, ("authorization", "Basic " + basic), UA)
    # Never scope on a refresh: leaving it out means the original grant.
    assert request.body == b"grant_type=refresh_token&refresh_token=rt-1"


def test_basic_auth_form_encodes_both_parts() -> None:
    client = Client("my app:1", Secret("p+%/ s\u00fc"))
    request = build_refresh(confidential(), client, Secret("rt-1"))
    expected = base64.b64encode(b"my+app%3A1:p%2B%25%2F+s%C3%BC").decode()
    assert ("authorization", "Basic " + expected) in request.headers


def test_refresh_with_post_auth() -> None:
    request = build_refresh(confidential(client_auth="post"), SECRET_CLIENT, Secret("rt 1"))
    assert request.headers == (ACCEPT, FORM_TYPE, UA)
    assert request.body == (
        b"grant_type=refresh_token&refresh_token=rt+1&client_id=app-1&client_secret=cs-value-1"
    )


def test_refresh_for_a_public_client() -> None:
    request = build_refresh(cred(), PUBLIC_CLIENT, Secret("rt-1"))
    assert request.headers == (ACCEPT, FORM_TYPE, UA)
    assert request.body == b"grant_type=refresh_token&refresh_token=rt-1&client_id=app-1"


@pytest.mark.parametrize("auth", ["basic", "post"])
def test_confidential_auth_needs_the_secret(auth: str) -> None:
    with pytest.raises(ValueError, match=r"^this client authentication needs the client secret$"):
        build_refresh(confidential(client_auth=auth), PUBLIC_CLIENT, Secret("rt-1"))


def test_repeated_extra_params_and_json_bodies() -> None:
    params = {"resource": ["https://a.example/", "https://b.example/"], "audience": "x y"}
    form = build_refresh(cred(extra_params=params), PUBLIC_CLIENT, Secret("rt-1"))
    assert form.body == (
        b"grant_type=refresh_token&refresh_token=rt-1&client_id=app-1"
        b"&resource=https%3A%2F%2Fa.example%2F&resource=https%3A%2F%2Fb.example%2F&audience=x+y"
    )
    body = build_refresh(cred(extra_params=params, token_body="json"), PUBLIC_CLIENT, Secret("r1"))
    assert body.headers == (ACCEPT, JSON_TYPE, UA)
    assert body.body == (
        b'{"audience":"x y","client_id":"app-1","grant_type":"refresh_token",'
        b'"refresh_token":"r1","resource":["https://a.example/","https://b.example/"]}'
    )


def test_post_auth_in_a_json_body() -> None:
    request = build_refresh(
        confidential(client_auth="post", token_body="json"), SECRET_CLIENT, Secret("rt-1")
    )
    assert json.loads(request.body) == {
        "grant_type": "refresh_token",
        "refresh_token": "rt-1",
        "client_id": "app-1",
        "client_secret": "cs-value-1",
    }


@pytest.mark.parametrize(
    ("credential", "name"),
    [
        (cred(extra_params={"grant_type": "password"}), "grant_type"),
        (cred(extra_params={"client_id": "other"}), "client_id"),
        (confidential(client_auth="post", extra_params={"client_secret": "x"}), "client_secret"),
        (cred(extra_params={"refresh_token": "x"}), "refresh_token"),
    ],
)
def test_extra_params_never_override_the_vault(credential: OAuth2Credential, name: str) -> None:
    client = SECRET_CLIENT if credential.client_secret else PUBLIC_CLIENT
    with pytest.raises(ValueError, match=f"extra_params can't set '{name}'; the vault sets it"):
        build_refresh(credential, client, Secret("rt-1"))


def test_token_headers_come_last_and_may_replace_the_user_agent() -> None:
    headers = {"X-Tenant": "t-1", "User-Agent": "custom/1"}
    request = build_refresh(cred(token_headers=headers), PUBLIC_CLIENT, Secret("rt-1"))
    assert request.headers == (
        ACCEPT,
        FORM_TYPE,
        ("User-Agent", "custom/1"),
        ("X-Tenant", "t-1"),
    )


@pytest.mark.parametrize("auth", ["basic", "post", "none"])
@pytest.mark.parametrize("name", ["Accept", "content-type", "Authorization", "AUTHORIZATION"])
def test_token_headers_never_override_the_vault(name: str, auth: str) -> None:
    if auth == "none":
        credential, client = cred(token_headers={name: "x"}), PUBLIC_CLIENT
    else:
        credential = confidential(client_auth=auth, token_headers={name: "x"})
        client = SECRET_CLIENT
    with pytest.raises(ValueError, match=f"^token_headers can't set '{name}'; the vault sets it$"):
        build_refresh(credential, client, Secret("rt-1"))


def test_code_exchange_sends_the_stored_redirect_uri() -> None:
    request = build_exchange(
        cred(scope="a"),
        PUBLIC_CLIENT,
        code=Secret("code-1"),
        verifier=Secret("v" * 43),
        redirect_uri="http://127.0.0.1:8976/callback",
    )
    assert request.headers == (ACCEPT, FORM_TYPE, UA)
    assert request.body == (
        b"grant_type=authorization_code&code=code-1"
        b"&redirect_uri=http%3A%2F%2F127.0.0.1%3A8976%2Fcallback"
        b"&code_verifier=" + b"v" * 43 + b"&client_id=app-1"
    )


def test_client_credentials_sends_scope_when_set() -> None:
    with_scope = confidential(grant="client_credentials", scope="read write")
    request = build_client_credentials(with_scope, SECRET_CLIENT)
    assert request.body == b"grant_type=client_credentials&scope=read+write"
    plain = build_client_credentials(confidential(grant="client_credentials"), SECRET_CLIENT)
    assert plain.body == b"grant_type=client_credentials"
    scoped = confidential(grant="client_credentials", scope="r", extra_params={"scope": "w"})
    with pytest.raises(ValueError, match="extra_params can't set 'scope'"):
        build_client_credentials(scoped, SECRET_CLIENT)


def test_a_token_request_never_shows_its_body() -> None:
    request = build_refresh(confidential(), SECRET_CLIENT, Secret("rt-value-9"))
    text = repr(request)
    assert text == (
        f"TokenRequest(url={TOKEN_URL!r}, "
        "headers=['accept', 'content-type', 'authorization', 'user-agent'])"
    )
    assert "rt-value-9" not in text
    assert "Basic" not in text


# --- endpoint queries (M7 design B.4, Q41) ------------------------------------------------------

# Every punctuation character an endpoint's query may hold, and an escape in each case.
PUNCTUATION_QUERY = "?a=-._~!()*+,:@/?&b=%2F&c=%2f"
VAULT_PARAMS = [("response_type", "code"), ("redirect_uri", "http://127.0.0.1/callback")]
ENCODED = "response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback"


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    [
        ("https://as.example/authorize", "https://as.example/authorize?" + ENCODED),
        (
            "https://as.example/authorize?tenant=t",
            "https://as.example/authorize?tenant=t&" + ENCODED,
        ),
        ("https://as.example/a?x=1&y=", "https://as.example/a?x=1&y=&" + ENCODED),
        ("https://as.example/a?tenant=a%2Fb", "https://as.example/a?tenant=a%2Fb&" + ENCODED),
        (
            "https://as.example/a" + PUNCTUATION_QUERY,
            "https://as.example/a" + PUNCTUATION_QUERY + "&" + ENCODED,
        ),
    ],
)
def test_with_query_keeps_the_endpoints_query_first(endpoint: str, expected: str) -> None:
    assert with_query(endpoint, VAULT_PARAMS) == expected


def test_with_query_refuses_a_name_the_endpoint_holds() -> None:
    with pytest.raises(ValueError, match=r"^the endpoint's query already sets 'redirect_uri'$"):
        with_query("https://as.example/a?redirect_uri=https://evil.example/", VAULT_PARAMS)
    with pytest.raises(ValueError, match=r"^the endpoint's query already sets 'response_type'$"):
        with_query("https://as.example/a?x=1&response_type=token", VAULT_PARAMS)
    # Names are compared as written.
    assert with_query("https://as.example/a?Response_Type=x", VAULT_PARAMS).endswith(ENCODED)


@pytest.mark.parametrize(
    ("endpoint", "message"),
    [
        ("https://as.example/a?", r"^an endpoint ending in a bare '\?' can't take parameters$"),
        ("https://as.example/a#", r"^an endpoint with a fragment can't take parameters$"),
        ("https://as.example/a?a=b#", r"^an endpoint with a fragment can't take parameters$"),
        ("https://as.example/a#?", r"^an endpoint with a fragment can't take parameters$"),
        ("https://as.example/a?x=1&x=2", r"^the query sets x twice$"),
        ("https://as.example/a?x=$", r"^a query may hold letters"),
    ],
)
def test_with_query_refuses_what_the_schema_refuses(endpoint: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        with_query(endpoint, VAULT_PARAMS)


def test_a_token_url_with_a_query_is_used_as_written() -> None:
    url = TOKEN_URL + PUNCTUATION_QUERY
    plain = build_refresh(cred(), PUBLIC_CLIENT, Secret("rt-1"))
    request = build_refresh(cred(token_url=url), PUBLIC_CLIENT, Secret("rt-1"))
    assert request.url == url
    assert (request.headers, request.body) == (plain.headers, plain.body)
    seen: list[tuple[bytes, bytes]] = []

    def handle(sent: httpx.Request) -> httpx.Response:
        seen.append((sent.url.raw_path, sent.content))
        return httpx.Response(200)

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        client.post(request.url, headers=list(request.headers), content=request.body)
    assert seen == [
        (b"/oauth/token" + PUNCTUATION_QUERY.encode("ascii"), plain.body),
    ]


@pytest.mark.parametrize(
    ("fields", "name"),
    [
        ({"token_url": TOKEN_URL + "?grant_type=password"}, "grant_type"),
        ({"token_url": TOKEN_URL + "?a=1&client_id=x"}, "client_id"),
        ({"token_url": TOKEN_URL + "?audience=x", "extra_params": {"audience": "y"}}, "audience"),
    ],
)
def test_a_body_field_the_token_urls_query_holds_is_refused(
    fields: dict[str, Any], name: str
) -> None:
    # Built past the schema, which refuses each of these first.
    raw: dict[str, Any] = {"kind": "oauth2", "token_url": TOKEN_URL, "client_id": "app-1"}
    credential = OAuth2Credential.model_construct(**{**raw, **fields})
    message = f"^the token_url's query sets '{name}', which the body sends$"
    with pytest.raises(ValueError, match=message):
        build_refresh(credential, PUBLIC_CLIENT, Secret("rt-1"))


# --- response parsing --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "content_type", "expected"),
    [
        (b'{"access_token":"a"}', JSON, {"access_token": "a"}),
        (b'{"access_token":"a"}', None, {"access_token": "a"}),
        (b'{"access_token":"a"}', FORM, {"access_token": "a"}),
        (b'{"n":12345678901234567890}', JSON, {"n": 12345678901234567890}),
        (b'["a"]', JSON, None),
        (b'"a"', FORM, {'"a"': ""}),
        (b'{"a":1,"a":2}', JSON, None),
        (b"<html>no</html>", "text/html", None),
        (b"access_token=a&token_type=bearer", FORM, {"access_token": "a", "token_type": "bearer"}),
        (
            b"access_token=a",
            "Application/X-WWW-Form-Urlencoded; charset=utf-8",
            {"access_token": "a"},
        ),
        (b"access_token=a", " application/x-www-form-urlencoded ;q=1", {"access_token": "a"}),
        (b"access_token=a", None, None),
        (b"access_token=a", JSON, None),
        (b"error=x&error=y", FORM, None),
        (b"a=%ff", FORM, None),
        (b"a=\xff", FORM, None),
        (b"error=", FORM, {"error": ""}),
    ],
)
def test_parse_token_body(body: bytes, content_type: str | None, expected: object) -> None:
    assert parse_token_body(body, content_type) == expected


def test_the_body_cap_is_exact() -> None:
    small = b'{"a":1}'
    assert parse_token_body(small + b" " * (MAX_TOKEN_BODY - len(small)), JSON) == {"a": 1}
    assert parse_token_body(small + b" " * (MAX_TOKEN_BODY + 1 - len(small)), JSON) is None
    form = b"a=1"
    assert parse_token_body(form + b"&" * (MAX_TOKEN_BODY - len(form)), FORM) == {"a": "1"}
    assert parse_token_body(form + b"&" * (MAX_TOKEN_BODY + 1 - len(form)), FORM) is None


@given(st.binary(max_size=300), st.sampled_from([None, JSON, FORM, "text/html"]))
def test_property_parse_token_body_never_raises(body: bytes, content_type: str | None) -> None:
    result = parse_token_body(body, content_type)
    assert result is None or isinstance(result, dict)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (3600, 3600),
        (0, 0),
        (-5, -5),
        (True, None),
        (False, None),
        ("3600", 3600),
        ("0", 0),
        ("1234567890", 1234567890),
        ("12345678901", None),
        ("", None),
        (" 3600", None),
        ("3600 ", None),
        ("-5", None),
        ("36.0", None),
        ("\u0663", None),
        (3600.0, 3600),
        (1e12, 10**12),
        (3600.5, None),
        (float("inf"), None),
        (float("nan"), None),
        (None, None),
        ([3600], None),
    ],
)
def test_parse_lifetime(value: object, expected: int | None) -> None:
    assert parse_lifetime(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [(-5, 60), (59, 60), (60, 60), (61, 61), (86399, 86399), (86400, 86400), (86401, 86400)],
)
def test_clamp_lifetime(value: int, expected: int) -> None:
    assert clamp_lifetime(value) == expected


@pytest.mark.parametrize(
    ("value", "separator", "expected"),
    [
        (None, " ", None),
        (5, " ", None),
        (["a"], " ", None),
        ("", " ", ()),
        ("a", " ", ("a",)),
        ("a b", " ", ("a", "b")),
        ("b  a b", " ", ("b", "a")),
        ("a,b", ",", ("a", "b")),
        ("a,b", " ", ("a,b",)),
    ],
)
def test_parse_scope(value: object, separator: str, expected: tuple[str, ...] | None) -> None:
    assert parse_scope(value, separator) == expected


HTTP_DATE = "Sat, 17 Oct 2026 09:01:30 GMT"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("120", 120.0),
        (" 120 ", 120.0),
        ("0", 0.0),
        ("3599", 3599.0),
        ("3600", 3600.0),
        ("3601", 3600.0),
        ("9999999999", 3600.0),
        ("12345678901", 3600.0),
        ("9" * 32, 3600.0),
        ("9" * 33, None),
        ("-5", None),
        ("1.5", None),
        ("soon", None),
        ("", None),
        (HTTP_DATE, 90.0),
        ("Sat, 17 Oct 2026 08:00:00 GMT", 0.0),
        ("Sun, 18 Oct 2026 09:00:00 GMT", 3600.0),
        ("Sat, 17 Oct 2026 09:01:30 -0000", None),
        ("Sat, 17 Oct 2026 10:01:30 +0100", 90.0),
    ],
)
def test_parse_retry_after(value: str | None, expected: float | None) -> None:
    assert parse_retry_after(value, NOW) == expected


@given(st.text(max_size=60))
def test_property_retry_after_never_raises(value: str) -> None:
    result = parse_retry_after(value, NOW)
    assert result is None or 0.0 <= result <= protocol.RETRY_AFTER_CAP


# --- classification ----------------------------------------------------------------------------

DEFAULT_CRED = cred(default_expires_in=1800)


def respond(
    status: int,
    body: dict[str, Any] | bytes,
    *,
    content_type: str | None = JSON,
    retry_after: str | None = None,
) -> TokenResponse:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return TokenResponse(status, raw, content_type, retry_after)


def run(
    response: TokenResponse,
    *,
    grant: GrantKind = "refresh_token",
    presented: str | None = "rt-1",
    replayed: bool = False,
    credential: OAuth2Credential = DEFAULT_CRED,
) -> Outcome:
    outcome = classify(
        response,
        cred=credential,
        grant=grant,
        presented=None if presented is None else Secret(presented),
        replayed=replayed,
        now=NOW,
    )
    assert (outcome.minted is None) != (outcome.failure is None)
    assert outcome.status == response.status
    return outcome


def minted(outcome: Outcome) -> Minted:
    assert outcome.failure is None
    assert outcome.minted is not None
    return outcome.minted


def failed(outcome: Outcome) -> Failure:
    assert outcome.minted is None
    assert outcome.failure is not None
    return outcome.failure


def new_rt(outcome: Outcome) -> str | None:
    return None if outcome.new_refresh_token is None else outcome.new_refresh_token.reveal()


GOOD = {"access_token": "at-1", "token_type": "Bearer", "expires_in": 3600}


def test_a_full_success() -> None:
    body = GOOD | {
        "scope": "a b",
        "refresh_token": "rt-2",
        "refresh_token_expires_in": "7200",
        "id_token": "ignored",
    }
    outcome = run(respond(200, body))
    token = minted(outcome)
    assert token.access_token.reveal() == "at-1"
    assert (token.lifetime, token.expires_in) == (3600, 3600)
    assert token.scope == ("a", "b")
    assert token.refresh_expires_in == 7200
    assert token.notes == ()
    assert new_rt(outcome) == "rt-2"


@pytest.mark.parametrize("status", [200, 201, 299])
def test_every_2xx_can_succeed(status: int) -> None:
    assert minted(run(respond(status, GOOD))).access_token.reveal() == "at-1"


@pytest.mark.parametrize("status", [199, 300, 302, 307])
def test_outside_2xx_never_succeeds(status: int) -> None:
    failure = failed(run(respond(status, GOOD)))
    assert (failure.kind, failure.code, failure.reason) == (
        "terminal",
        OAUTH_MISCONFIGURED,
        "http_status",
    )


@pytest.mark.parametrize("token_type", ["bearer", "BEARER", "Bearer"])
def test_bearer_in_any_case(token_type: str) -> None:
    assert minted(run(respond(200, GOOD | {"token_type": token_type}))).notes == ()


def test_a_missing_token_type_means_bearer() -> None:
    body = {"access_token": "at-1", "expires_in": 3600}
    assert minted(run(respond(200, body))).notes == ("token_type_missing",)


@pytest.mark.parametrize("token_type", ["DPoP", "mac", "N_A", "", 5, "bearer "])
def test_other_token_types_are_unsupported(token_type: object) -> None:
    outcome = run(respond(200, GOOD | {"token_type": token_type, "refresh_token": "rt-2"}))
    assert failed(outcome) == Failure("terminal", OAUTH_UNSUPPORTED, "token_type")
    # The successor is still saved: the provider may have retired the presented token.
    assert new_rt(outcome) == "rt-2"


@pytest.mark.parametrize("access_token", [None, "", "a b", "a\r\nX-Evil: 1", "a" * 16385, 5])
def test_a_bad_access_token_backs_off(access_token: object) -> None:
    body = {"token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-2"}
    if access_token is not None:
        body["access_token"] = access_token
    outcome = run(respond(200, body, retry_after="30"))
    assert failed(outcome) == Failure(
        "backoff", OAUTH_UNAVAILABLE, "bad_access_token", retry_after=30.0
    )
    assert new_rt(outcome) == "rt-2"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({}, None),
        ({"refresh_token": None}, None),
        ({"refresh_token": ""}, None),
        ({"refresh_token": "rt-1"}, None),
        ({"refresh_token": "rt-2"}, "rt-2"),
        ({"refresh_token": "rt 2"}, "rt 2"),
    ],
)
def test_successor_refresh_tokens(body: dict[str, Any], expected: str | None) -> None:
    outcome = run(respond(200, GOOD | body))
    assert minted(outcome).access_token.reveal() == "at-1"
    assert new_rt(outcome) == expected


@pytest.mark.parametrize("bad", [" rt-2", "rt-2 ", "rt\n2", "x" * 8193, 5, ["rt-2"], True])
def test_an_unusable_successor_is_terminal(bad: object) -> None:
    for extra in ({}, {"error": "server_error"}):
        outcome = run(respond(200, GOOD | extra | {"refresh_token": bad}))
        assert failed(outcome) == Failure("terminal", OAUTH_UNSUPPORTED, "unusable_refresh_token")
        assert outcome.new_refresh_token is None


def test_client_credentials_ignores_refresh_tokens() -> None:
    for value in ("rt-2", " bad"):
        outcome = run(
            respond(200, GOOD | {"refresh_token": value}),
            grant="client_credentials",
            presented=None,
        )
        assert minted(outcome).access_token.reveal() == "at-1"
        assert outcome.new_refresh_token is None


def test_a_code_exchange_takes_the_first_refresh_token() -> None:
    outcome = run(
        respond(200, GOOD | {"refresh_token": "rt-1"}), grant="authorization_code", presented=None
    )
    assert new_rt(outcome) == "rt-1"


def test_successors_only_come_from_2xx() -> None:
    body = {"error": "server_error", "refresh_token": "rt-2"}
    assert run(respond(500, body)).new_refresh_token is None
    assert run(respond(400, {"error": "invalid_grant", "refresh_token": " x"})).failure == Failure(
        "terminal", OAUTH_RECONSENT_NEEDED, "provider_error", "invalid_grant"
    )


@pytest.mark.parametrize(
    ("expires_in", "lifetime", "parsed", "notes"),
    [
        (3600, 3600, 3600, ()),
        ("3600", 3600, 3600, ()),
        (3600.0, 3600, 3600, ()),
        (60, 60, 60, ()),
        (59, 60, 59, ("expires_in_clamped",)),
        (5, 60, 5, ("expires_in_clamped",)),
        (-5, 60, -5, ("expires_in_clamped",)),
        (86400, 86400, 86400, ()),
        (86401, 86400, 86401, ("expires_in_clamped",)),
        (1e12, 86400, 10**12, ("expires_in_clamped",)),
        (True, 1800, None, ("expires_in_defaulted",)),
        ("soon", 1800, None, ("expires_in_defaulted",)),
        (None, 1800, None, ("expires_in_defaulted",)),
    ],
)
def test_lifetimes(
    expires_in: object, lifetime: int, parsed: int | None, notes: tuple[str]
) -> None:
    body: dict[str, Any] = {"access_token": "at-1", "token_type": "bearer"}
    if expires_in is not None:
        body["expires_in"] = expires_in
    token = minted(run(respond(200, body)))
    assert (token.lifetime, token.expires_in, token.notes) == (lifetime, parsed, notes)


def test_the_default_lifetime_is_never_clamped_or_noted_twice() -> None:
    body = {"access_token": "at-1"}
    token = minted(run(respond(200, body), credential=cred(default_expires_in=60)))
    assert (token.lifetime, token.notes) == (60, ("token_type_missing", "expires_in_defaulted"))


def test_scope_and_refresh_lifetime_parsing() -> None:
    comma = cred(scope_separator=",")
    token = minted(run(respond(200, GOOD | {"scope": "a,b"}), credential=comma))
    assert token.scope == ("a", "b")
    token = minted(run(respond(200, GOOD | {"scope": ""})))
    assert token.scope == ()
    token = minted(run(respond(200, GOOD | {"refresh_token_expires_in": 1.5})))
    assert (token.scope, token.refresh_expires_in) == (None, None)


def test_form_encoded_success() -> None:
    body = b"access_token=at-1&token_type=bearer&scope=repo%2Cgist&expires_in=28800"
    token = minted(run(respond(200, body, content_type=FORM), credential=cred(scope_separator=",")))
    assert (token.access_token.reveal(), token.lifetime, token.scope) == (
        "at-1",
        28800,
        ("repo", "gist"),
    )


@pytest.mark.parametrize(
    ("status", "body", "content_type", "retry_after", "expected"),
    [
        (
            200,
            b"<html>",
            "text/html",
            None,
            Failure("backoff", OAUTH_UNAVAILABLE, "unparseable_body"),
        ),
        (
            200,
            b"<html>",
            "text/html",
            "30",
            Failure("backoff", OAUTH_UNAVAILABLE, "unparseable_body", retry_after=30.0),
        ),
        (200, b'{"ok":false}', JSON, None, Failure("backoff", OAUTH_UNAVAILABLE, "not_ok")),
        (
            200,
            b'{"ok":false,"error":"invalid_refresh_token"}',
            JSON,
            None,
            Failure("terminal", OAUTH_RECONSENT_NEEDED, "provider_error", "invalid_refresh_token"),
        ),
        (
            200,
            b"error=bad_refresh_token",
            FORM,
            None,
            Failure("terminal", OAUTH_RECONSENT_NEEDED, "provider_error", "bad_refresh_token"),
        ),
        (
            200,
            b'{"error":"something_new"}',
            JSON,
            None,
            Failure("terminal", OAUTH_MISCONFIGURED, "http_status", "something_new"),
        ),
    ],
)
def test_2xx_errors(
    status: int,
    body: bytes,
    content_type: str,
    retry_after: str | None,
    expected: Failure,
) -> None:
    response = respond(status, body, content_type=content_type, retry_after=retry_after)
    assert failed(run(response)) == expected


def test_ok_true_and_null_error_are_success() -> None:
    assert minted(run(respond(200, GOOD | {"ok": True, "error": None}))).lifetime == 3600


@pytest.mark.parametrize(
    ("status", "error", "kind", "code", "reason"),
    [
        (400, "invalid_grant", "terminal", OAUTH_RECONSENT_NEEDED, "provider_error"),
        (403, "invalid_grant", "terminal", OAUTH_RECONSENT_NEEDED, "provider_error"),
        (429, "invalid_grant", "terminal", OAUTH_RECONSENT_NEEDED, "provider_error"),
        (400, "bad_refresh_token", "terminal", OAUTH_RECONSENT_NEEDED, "provider_error"),
        (400, "invalid_refresh_token", "terminal", OAUTH_RECONSENT_NEEDED, "provider_error"),
        (401, "invalid_client", "terminal", OAUTH_CLIENT_REJECTED, "provider_error"),
        (400, "unauthorized_client", "terminal", OAUTH_CLIENT_REJECTED, "provider_error"),
        (400, "incorrect_client_credentials", "terminal", OAUTH_CLIENT_REJECTED, "provider_error"),
        (400, "invalid_scope", "terminal", OAUTH_MISCONFIGURED, "provider_error"),
        (400, "invalid_target", "terminal", OAUTH_MISCONFIGURED, "provider_error"),
        (400, "invalid_request", "terminal", OAUTH_MISCONFIGURED, "provider_error"),
        (400, "unsupported_grant_type", "terminal", OAUTH_MISCONFIGURED, "provider_error"),
        (400, "use_dpop_nonce", "terminal", OAUTH_UNSUPPORTED, "provider_error"),
        (400, "temporarily_unavailable", "backoff", OAUTH_UNAVAILABLE, "provider_error"),
        (400, "slow_down", "backoff", OAUTH_UNAVAILABLE, "provider_error"),
        (500, "server_error", "backoff", OAUTH_UNAVAILABLE, "provider_error"),
        (401, None, "terminal", OAUTH_CLIENT_REJECTED, "http_status"),
        (401, "something_new", "terminal", OAUTH_CLIENT_REJECTED, "http_status"),
        (400, None, "terminal", OAUTH_MISCONFIGURED, "http_status"),
        (403, None, "terminal", OAUTH_MISCONFIGURED, "http_status"),
        (404, "something_new", "terminal", OAUTH_MISCONFIGURED, "http_status"),
        (499, None, "terminal", OAUTH_MISCONFIGURED, "http_status"),
        (500, None, "backoff", OAUTH_UNAVAILABLE, "http_status"),
        (503, "something_new", "backoff", OAUTH_UNAVAILABLE, "http_status"),
        (599, None, "backoff", OAUTH_UNAVAILABLE, "http_status"),
    ],
)
def test_error_classification(
    status: int, error: str | None, kind: str, code: str, reason: str
) -> None:
    body = {} if error is None else {"error": error}
    failure = failed(run(respond(status, body)))
    assert (failure.kind, failure.code, failure.reason, failure.error) == (
        kind,
        code,
        reason,
        error,
    )


def test_a_replayed_invalid_grant_means_the_rotation_was_lost() -> None:
    failure = failed(run(respond(400, {"error": "invalid_grant"}), replayed=True))
    assert failure.code == OAUTH_ROTATION_LOST
    failure = failed(run(respond(401, {"error": "invalid_client"}), replayed=True))
    assert failure.code == OAUTH_CLIENT_REJECTED


def test_invalid_grant_on_client_credentials_rejects_the_client() -> None:
    for replayed in (False, True):
        response = respond(400, {"error": "invalid_grant"})
        outcome = run(response, grant="client_credentials", presented=None, replayed=replayed)
        assert failed(outcome) == Failure(
            "terminal", OAUTH_CLIENT_REJECTED, "provider_error", "invalid_grant"
        )
    response = respond(400, {"error": "invalid_grant"}, retry_after="30")
    outcome = run(response, grant="client_credentials", presented=None)
    assert failed(outcome).retry_after is None


def test_error_text_is_filtered_and_the_description_dropped() -> None:
    body = {
        "error": "bad error <script>",
        "error_subtype": "invalid_rapt",
        "error_description": "token rt-1 is revoked",
    }
    failure = failed(run(respond(400, body)))
    assert failure == Failure(
        "terminal", OAUTH_MISCONFIGURED, "http_status", "other", "invalid_rapt"
    )
    assert "rt-1" not in repr(failure)


def test_html_errors_classify_by_status() -> None:
    failure = failed(run(respond(502, b"<html>bad gateway</html>", content_type="text/html")))
    assert failure == Failure("backoff", OAUTH_UNAVAILABLE, "http_status")


@pytest.mark.parametrize(
    ("status", "error", "header", "expected"),
    [
        (429, None, None, 60.0),
        (429, None, "120", 120.0),
        (429, None, "5", 5.0),
        (429, None, "junk", 60.0),
        (429, None, "99999", 3600.0),
        (503, None, None, None),
        (503, None, "120", 120.0),
        (503, None, HTTP_DATE, 90.0),
        (400, "slow_down", None, None),
        (400, "slow_down", "30", 30.0),
        (400, "invalid_grant", "30", None),
        (401, None, "30", None),
    ],
)
def test_retry_after(
    status: int, error: str | None, header: str | None, expected: float | None
) -> None:
    body = {} if error is None else {"error": error}
    failure = failed(run(respond(status, body, retry_after=header)))
    assert failure.retry_after == expected


def test_transport_failures_back_off() -> None:
    for reason in ("pre_send", "no_response"):
        outcome = transport_failure(reason)
        assert outcome == Outcome(None, failure=Failure("backoff", OAUTH_UNAVAILABLE, reason))


_FIELDS = st.sampled_from(
    ["access_token", "token_type", "refresh_token", "expires_in", "error", "ok", "scope"]
)
_VALUES = st.one_of(st.just("rt-1"), st.just("bearer"), st.text(max_size=20))


@given(
    st.integers(min_value=100, max_value=599),
    st.one_of(
        st.binary(max_size=200),
        st.dictionaries(
            _FIELDS,
            st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=20)),
        ).map(lambda d: json.dumps(d).encode()),
        st.dictionaries(_FIELDS, _VALUES).map(lambda d: urlencode(d).encode()),
    ),
    st.sampled_from([None, JSON, FORM, "text/html"]),
    st.sampled_from(["refresh_token", "authorization_code", "client_credentials"]),
    st.sampled_from([None, "rt-1"]),
    st.booleans(),
    st.one_of(st.none(), st.text(max_size=20)),
)
def test_property_classify_never_raises(
    status: int,
    body: bytes,
    content_type: str | None,
    grant: GrantKind,
    presented: str | None,
    replayed: bool,
    retry_after: str | None,
) -> None:
    response = respond(status, body, content_type=content_type, retry_after=retry_after)
    outcome = run(response, grant=grant, presented=presented, replayed=replayed)
    if outcome.failure is not None and outcome.failure.kind == "terminal":
        assert outcome.failure.retry_after is None
    if outcome.new_refresh_token is not None:
        assert 200 <= status < 300
        assert grant != "client_credentials"
        assert valid_refresh_token(outcome.new_refresh_token.reveal())
        assert outcome.new_refresh_token.reveal() != presented
    if outcome.minted is not None:
        assert protocol.MIN_LIFETIME <= outcome.minted.lifetime <= protocol.MAX_LIFETIME
        assert valid_access_token(outcome.minted.access_token.reveal())


# --- lifetime and skew -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("lifetime", "refresh_skew", "expected"),
    [
        (3600, 120, Expiry(1000.0 + 3480, 1000.0 + 3600, 120)),
        (60, 120, Expiry(1000.0 + 30, 1000.0 + 60, 30)),
        (61, 120, Expiry(1000.0 + 31, 1000.0 + 61, 30)),
        (240, 120, Expiry(1000.0 + 120, 1000.0 + 240, 120)),
        (238, 120, Expiry(1000.0 + 119, 1000.0 + 238, 119)),
        (3600, 0, Expiry(1000.0 + 3600, 1000.0 + 3600, 0)),
    ],
)
def test_schedule(lifetime: int, refresh_skew: int, expected: Expiry) -> None:
    assert schedule(1000.0, lifetime, refresh_skew) == expected


# --- scopes ------------------------------------------------------------------------------------


def test_login_scopes() -> None:
    assert check_login_scopes(["a", "c", "b"], ["a", "b", "d"]) == ScopeCheck(("c",), ("d",))
    assert check_login_scopes(["a", "b"], ["b", "a"]) == ScopeCheck()
    assert check_login_scopes(["a"], ["a", "b"]) == ScopeCheck((), ("b",))
    assert check_login_scopes(["z", "y"], ["a"]) == ScopeCheck(("y", "z"), ("a",))
    # Nothing expected: nothing can be checked.
    assert check_login_scopes(["a"], []) == ScopeCheck()


def test_refresh_scopes() -> None:
    assert check_refresh_scopes(["a"], ["a", "b"], ["a", "b"]) == ScopeCheck((), ("b",))
    assert check_refresh_scopes(["a", "x"], ["a"], ["a"]) == ScopeCheck(("x",), ())
    assert check_refresh_scopes(["a", "x"], ["a"], []) == ScopeCheck()
    assert check_refresh_scopes(["a"], [], ["a"]) == ScopeCheck()


def test_scope_status() -> None:
    assert ScopeCheck().status == "ok"
    assert ScopeCheck(missing=("a",)).status == "missing"
    assert ScopeCheck(unexpected=("b",)).status == "unexpected"
    assert ScopeCheck(("b",), ("a",)).status == "unexpected"


# --- seed vs live ------------------------------------------------------------------------------

SEED = "seed-value-1"
SEED_HASH = seed_sha256(SEED)
OTHER_HASH = seed_sha256("seed-value-0")


def test_seed_sha256() -> None:
    assert seed_sha256("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


@pytest.mark.parametrize(
    ("slot", "live_hash", "seed", "reseed", "expected"),
    [
        ("absent", None, None, "never", SourceDecision(None, "no_token")),
        ("absent", None, None, "on-change", SourceDecision(None, "no_token")),
        ("absent", None, SEED, "never", SourceDecision("seed", "no_live")),
        ("absent", None, SEED, "on-change", SourceDecision("seed", "no_live")),
        ("usable", SEED_HASH, None, "never", SourceDecision("live", "seed_absent")),
        ("usable", SEED_HASH, None, "on-change", SourceDecision("live", "seed_absent")),
        ("usable", OTHER_HASH, SEED, "never", SourceDecision("live", "reseed_never")),
        ("usable", None, SEED, "never", SourceDecision("live", "reseed_never")),
        ("usable", SEED_HASH, SEED, "on-change", SourceDecision("live", "seed_unchanged")),
        ("usable", OTHER_HASH, SEED, "on-change", SourceDecision("seed", "seed_changed")),
        ("usable", None, SEED, "on-change", SourceDecision("seed", "seed_changed")),
        ("unusable", SEED_HASH, SEED, "on-change", SourceDecision(None, "live_unusable")),
        ("unusable", None, SEED, "never", SourceDecision(None, "live_unusable")),
        ("unusable", None, None, "never", SourceDecision(None, "live_unusable")),
    ],
)
def test_decide_source_for_an_env_seed(
    slot: SlotState,
    live_hash: str | None,
    seed: str | None,
    reseed: str,
    expected: SourceDecision,
) -> None:
    credential = cred(refresh_token="env:MUSIC_REFRESH", reseed=reseed)
    decision = decide_source(credential, slot=slot, live_seed_sha256=live_hash, seed=seed)
    assert decision == expected


@pytest.mark.parametrize(
    ("slot", "expected"),
    [
        ("absent", SourceDecision(None, "no_token")),
        ("usable", SourceDecision("store", "store")),
        ("unusable", SourceDecision(None, "live_unusable")),
    ],
)
def test_decide_source_for_a_store_ref(slot: SlotState, expected: SourceDecision) -> None:
    for reseed in ("never", "on-change"):
        credential = cred(refresh_token="store:music-refresh", reseed=reseed)
        for seed in (None, SEED):
            decision = decide_source(credential, slot=slot, live_seed_sha256=OTHER_HASH, seed=seed)
            assert decision == expected


def test_decide_source_needs_a_refresh_token() -> None:
    credential = confidential(grant="client_credentials")
    with pytest.raises(ValueError, match=r"^this credential has no refresh token$"):
        decide_source(credential, slot="absent", live_seed_sha256=None, seed=None)


# --- the envelope ------------------------------------------------------------------------------


def test_envelope_round_trip() -> None:
    plain = encode_envelope(Secret("rt 1"), None)
    assert plain.reveal() == '{"rt":"rt 1","seed_sha256":null,"v":1}'
    hashed = encode_envelope(Secret("rt-1"), SEED_HASH)
    assert hashed.reveal() == '{"rt":"rt-1","seed_sha256":"' + SEED_HASH + '","v":1}'
    envelope = parse_envelope(hashed)
    assert (envelope.rt.reveal(), envelope.seed_sha256) == ("rt-1", SEED_HASH)
    assert parse_envelope(plain).seed_sha256 is None
    assert isinstance(envelope, Envelope)


@pytest.mark.parametrize(
    ("rt", "seed_hash", "message"),
    [
        (" rt", None, "not a valid refresh token"),
        ("", None, "not a valid refresh token"),
        ("rt-1", SEED_HASH.upper(), "seed_sha256 must be 64 lowercase hex characters"),
        ("rt-1", SEED_HASH[:-1], "seed_sha256 must be 64 lowercase hex characters"),
        ("rt-1", SEED_HASH + "0", "seed_sha256 must be 64 lowercase hex characters"),
    ],
)
def test_encode_envelope_refuses(rt: str, seed_hash: str | None, message: str) -> None:
    with pytest.raises(EnvelopeError, match=f"^{message}$"):
        encode_envelope(Secret(rt), seed_hash)


SECRET_RT = "rt-secret-77"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (SECRET_RT, "the live slot isn't JSON"),
        (
            '{"rt":"' + SECRET_RT + '","rt":"x","seed_sha256":null,"v":1}',
            "the live slot isn't JSON",
        ),
        ('["' + SECRET_RT + '"]', "the live slot doesn't hold an envelope"),
        ('{"rt":"' + SECRET_RT + '","v":1}', "the live slot doesn't hold an envelope"),
        (
            '{"rt":"' + SECRET_RT + '","seed_sha256":null,"v":1,"x":0}',
            "the live slot doesn't hold an envelope",
        ),
        ('{"rt":"' + SECRET_RT + '","seed_sha256":null,"v":2}', "unknown envelope version"),
        ('{"rt":"' + SECRET_RT + '","seed_sha256":null,"v":true}', "unknown envelope version"),
        ('{"rt":"' + SECRET_RT + '","seed_sha256":null,"v":1.0}', "unknown envelope version"),
        ('{"rt":"' + SECRET_RT + '","seed_sha256":null,"v":"1"}', "unknown envelope version"),
        ('{"rt":" ' + SECRET_RT + '","seed_sha256":null,"v":1}', "the envelope's refresh token"),
        ('{"rt":5,"seed_sha256":null,"v":1}', "the envelope's refresh token isn't valid"),
        ('{"rt":"' + SECRET_RT + '","seed_sha256":5,"v":1}', "the envelope's seed_sha256"),
        (
            '{"rt":"' + SECRET_RT + '","seed_sha256":"' + SEED_HASH.upper() + '","v":1}',
            "the envelope's seed_sha256 isn't valid",
        ),
    ],
)
def test_parse_envelope_refuses(text: str, message: str) -> None:
    with pytest.raises(EnvelopeError, match=f"^{message}") as caught:
        parse_envelope(Secret(text))
    assert SECRET_RT not in str(caught.value)
    assert caught.value.__cause__ is None


# --- backoff -----------------------------------------------------------------------------------


def low(lo: float, hi: float) -> float:
    return lo


def high(lo: float, hi: float) -> float:
    return hi


@pytest.mark.parametrize(
    ("failures", "base"), [(1, 5.0), (2, 15.0), (3, 60.0), (4, 300.0), (5, 900.0), (6, 900.0)]
)
def test_backoff_schedule_and_jitter(failures: int, base: float) -> None:
    calls: list[tuple[float, float]] = []

    def record(lo: float, hi: float) -> float:
        calls.append((lo, hi))
        return 1.0

    assert backoff_delay(failures, retry_after=None, uniform=record) == base
    assert calls == [(0.9, 1.1)]
    assert backoff_delay(failures, retry_after=None, uniform=low) == pytest.approx(base * 0.9)
    assert backoff_delay(failures, retry_after=None, uniform=high) == pytest.approx(base * 1.1)


def test_a_longer_retry_after_wins() -> None:
    assert backoff_delay(1, retry_after=60.0, uniform=high) == 60.0
    assert backoff_delay(1, retry_after=5.0, uniform=high) == pytest.approx(5.5)
    assert backoff_delay(1, retry_after=5.5, uniform=high) == pytest.approx(5.5)
    assert backoff_delay(5, retry_after=3600.0, uniform=high) == 3600.0
    assert backoff_delay(5, retry_after=0.0, uniform=low) == pytest.approx(810.0)


def test_backoff_counts_from_one() -> None:
    with pytest.raises(ValueError, match=r"^failures counts from 1$"):
        backoff_delay(0, retry_after=None, uniform=low)


@pytest.mark.parametrize(
    ("value", "field"),
    [
        (SECRET_CLIENT, "secret"),
        (protocol.TokenRequest(TOKEN_URL, (), b"x"), "body"),
        (TokenResponse(200, b"{}"), "body"),
        (Failure("backoff", OAUTH_UNAVAILABLE, "http_status"), "kind"),
        (Minted(Secret("at-1"), 60, 60, None, None), "access_token"),
        (Outcome(200, failure=Failure("backoff", OAUTH_UNAVAILABLE, "http_status")), "failure"),
        (Expiry(1.0, 2.0, 30), "refresh_at"),
        (ScopeCheck(), "missing"),
        (SourceDecision(None, "no_token"), "source"),
        (Envelope(Secret("rt-1"), None), "rt"),
    ],
)
def test_results_are_frozen(value: object, field: str) -> None:
    with pytest.raises(FrozenInstanceError):
        setattr(value, field, None)
