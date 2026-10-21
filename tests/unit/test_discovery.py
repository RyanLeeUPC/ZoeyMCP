"""Pure discovery (M7 design B.4, D.2, D.2a, D.3, D.5; O.2 ``test_discovery.py``).

The URL rule with each refusal and its reason, an endpoint's query kept byte for byte on the two
endpoints that may carry one (and accepted by the schema, so diff 1 loads) and refused on every
other URL; the two probes; the challenge parser; the protected-resource candidates, document and
resource table; the legacy candidates in D.2a's order; the authorization server's candidates and
document, with the attacker example from MCP's discovery page; scope selection; and the plan.
Every refusal reason of D.2-D.3 is reached here.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from zoeymcp import __version__
from zoeymcp.common.policy import fields
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.vault.oauth import discovery
from zoeymcp.vault.oauth.discovery import (
    CHALLENGE_MAX,
    LEGACY_LABELS,
    LEGACY_PROBE,
    MODERN_PROBE,
    NOTES,
    AsMetadata,
    Candidate,
    Challenge,
    Plan,
    Prm,
    Refusal,
    Scopes,
    as_candidates,
    as_exhausted,
    build_plan,
    check_as_metadata,
    check_prm,
    choose_issuer,
    expected_resources,
    legacy_candidates,
    moves_on,
    origin_of,
    parse_challenge,
    prm_candidates,
    prm_exhausted,
    probe_next,
    select_scopes,
    typed_url,
    untrusted_url,
)

ZWSP = chr(0x200B)
SERVER = "https://mcp.example.com/mcp"
ORIGIN = "https://mcp.example.com"
RM = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
ISSUER = "https://auth.example.com"
META_URL = "https://auth.example.com/.well-known/oauth-authorization-server"
AUTHORIZE = "https://auth.example.com/authorize?tenant=a%2Fb"
TOKEN = "https://auth.example.com:8443/token?tenant=a%2Fb&x=1:2"
REGISTER = "https://reg.example.com/register"
REVOKE = "https://auth.example.com/revoke"
# Every punctuation character an endpoint's query may hold, an escape, an empty value.
KEPT_QUERY = "tenant=a%2Fb&p=x.y_z~-!()*+,:@/?&e="
# Every printable character A.1's query rule refuses, written out rather than derived from it;
# "#" is left out because the fragment rule refuses it first.
QUERY_REFUSED = "\"$';<>[\\]^`{|}"
OMIT = object()


def as_doc(**changes: object) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "issuer": ISSUER,
        "authorization_endpoint": AUTHORIZE,
        "token_endpoint": TOKEN,
        "registration_endpoint": REGISTER,
        "revocation_endpoint": REVOKE,
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "authorization_response_iss_parameter_supported": True,
        "scopes_supported": ["notes.read", "notes.write", "offline_access"],
    }
    doc.update(changes)
    return {k: v for k, v in doc.items() if v is not OMIT}


def prm_doc(**changes: object) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "resource": SERVER,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["notes.read", "notes.write"],
        "resource_name": "Notes",
    }
    doc.update(changes)
    return {k: v for k, v in doc.items() if v is not OMIT}


def checked_as(**changes: object) -> AsMetadata:
    meta = check_as_metadata(as_doc(**changes), ISSUER)
    assert isinstance(meta, AsMetadata)
    return meta


def checked_prm(source: discovery.PrmSource = "path", **changes: object) -> Prm:
    prm = check_prm(prm_doc(**changes), source, SERVER)
    assert isinstance(prm, Prm)
    return prm


def bad(field: str, why: str, *values: str) -> Refusal:
    return Refusal("endpoint_invalid", field=field, why=why, values=values)


# --- untrusted URLs (B.4) ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://as.example.com",
        "https://as.example.com/",
        "https://as.example.com:8443/oauth/token",
        "https://AS.Example.com/a/b/",
        "https://as.example.com/a;b=c/~d",
    ],
)
def test_a_url_is_kept_as_written(url: str) -> None:
    assert untrusted_url(url, purpose="issuer") == url


def test_the_length_cap() -> None:
    base = "https://as.example.com/"
    longest = base + "a" * (fields.URL_MAX - len(base))
    assert untrusted_url(longest, purpose="x") == longest
    assert untrusted_url(longest + "a", purpose="x") == bad("x", "length")
    assert untrusted_url(42, purpose="x") == bad("x", "length")
    assert untrusted_url(None, purpose="x") == bad("x", "length")


def test_the_cap_comes_before_the_query_is_read() -> None:
    base = "https://as.example.com/token?a=$"
    url = base + "b" * (fields.URL_MAX + 1 - len(base))
    assert untrusted_url(url, purpose="token_endpoint", query="token") == bad(
        "token_endpoint", "length"
    )
    assert untrusted_url(url[:-1], purpose="token_endpoint", query="token") == bad(
        "token_endpoint", "query_invalid"
    )


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://as.example.com/a b",
        "https://as.example.com/\u00e9",
        "https://as.example.com/\t",
    ],
)
def test_only_printable_ascii(url: str) -> None:
    assert untrusted_url(url, purpose="issuer") == bad("issuer", "characters")


@pytest.mark.parametrize(
    "url",
    [
        "https://as/authorize#",
        "https://as/authorize?a=b#",
        "https://as.example.com/a#b",
        "https://as.example.com/?a=b#c",
    ],
)
@pytest.mark.parametrize("query", [None, "authorize", "token"])
def test_a_fragment_is_refused_even_empty(url: str, query: discovery.QueryFor | None) -> None:
    assert untrusted_url(url, purpose="f", query=query) == bad("f", "fragment")


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("http://as.example.com/token", "scheme must be one of: https"),
        ("ftp://as.example.com/token", "scheme must be one of: https"),
        ("https:///token", "missing host"),
        (
            "https://user@as.example.com/",
            "credentials in URLs are not allowed; use a credential reference",
        ),
        (
            "https://user:pw@as.example.com/",
            "credentials in URLs are not allowed; use a credential reference",
        ),
    ],
)
def test_the_schemas_url_rule(url: str, message: str) -> None:
    assert untrusted_url(url, purpose="issuer") == bad("issuer", "url", message)


def test_a_bad_port() -> None:
    refused = untrusted_url("https://as.example.com:99999/", purpose="issuer")
    assert isinstance(refused, Refusal)
    assert (refused.reason, refused.why) == ("endpoint_invalid", "url")
    assert refused.values[0].startswith("invalid port")


@pytest.mark.parametrize(
    "url",
    [
        "https://as.example.com:0/t",
        "https://as.example.com:/t",
        "https://as.example.com:00443/t",
        "https://as.example.com:0443/t",
    ],
)
def test_a_port_written_another_way(url: str) -> None:
    # Port 0, an empty port or a leading zero would name a host:port the plan doesn't show.
    assert untrusted_url(url, purpose="issuer") == bad("issuer", "port")
    assert typed_url(url, purpose="server") == Refusal("url_invalid", field="server", why="port")


@pytest.mark.parametrize(
    "url",
    [
        "https://as.example.com:1/t",
        "https://as.example.com:443/t",
        "https://as.example.com:65535/t",
    ],
)
def test_a_port_as_written(url: str) -> None:
    assert untrusted_url(url, purpose="issuer") == url


def test_the_port_of_an_ip_literal() -> None:
    for url in ("https://[fd00::1]/mcp", "https://[fd00::1]:8443/mcp"):
        assert typed_url(url, purpose="server", allow_private=True) == url
    for url in ("https://[fd00::1]:/mcp", "https://[fd00::1]:0/mcp", "https://[fd00::1]:08443/mcp"):
        assert typed_url(url, purpose="server", allow_private=True) == Refusal(
            "url_invalid", field="server", why="port"
        )


@pytest.mark.parametrize(
    ("url", "verdict"),
    [
        ("https://127.0.0.1/", "ip_literal"),
        ("https://[::1]/", "ip_literal"),
        ("https://[fd00::1]/mcp", "ip_literal"),
        ("https://localhost/", "single_label"),
        ("https://nas/mcp", "single_label"),
        ("https://as.internal/", "internal_suffix"),
        ("https://nas.lan:8443/", "internal_suffix"),
        ("https://as.example.123/", "numeric_label"),
        ("https://a.0x7f/", "numeric_label"),
        ("https://-bad.example.com/", "syntax"),
    ],
)
def test_the_host_rule(url: str, verdict: str) -> None:
    assert untrusted_url(url, purpose="issuer") == bad("issuer", "host", verdict)


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("/a%2Fb", "slash or backslash inside a path segment"),
        ("/a%2fb", "slash or backslash inside a path segment"),
        ("/a%5Cb", "slash or backslash inside a path segment"),
        ("/a/../b", "dot segment in path"),
        ("/a/%2e%2e/b", "dot segment in path"),
        ("/./b", "dot segment in path"),
        ("/a//b", "empty path segment"),
        ("/a%zz", "malformed percent-encoding"),
        ("/a%252F", "double percent-encoding"),
        ("/a%20b", "path segment has characters that aren't allowed"),
    ],
)
def test_the_vaults_own_path_rules(path: str, why: str) -> None:
    url = f"https://as.example.com{path}"
    assert untrusted_url(url, purpose="token_endpoint") == bad("token_endpoint", "path", why)


def test_a_dollar_anywhere_else_is_its_own_reason() -> None:
    for url in ("https://as.example.com/a$b", "https://as.example.com/$"):
        assert untrusted_url(url, purpose="x") == Refusal("url_dollar", field="x")
    # In a query it is a query character the rule refuses; in a host, a bad host.
    assert untrusted_url("https://as.example.com/t?a=$", purpose="x", query="token") == bad(
        "x", "query_invalid"
    )
    assert untrusted_url("https://a$.example.com/", purpose="x") == bad("x", "host", "syntax")


# --- an endpoint's query (Q41) ------------------------------------------------------------------


@pytest.mark.parametrize("query", ["authorize", "token"])
def test_an_endpoints_query_is_kept_byte_for_byte(query: discovery.QueryFor) -> None:
    for url in (
        f"https://as.example.com/oauth/{query}?{KEPT_QUERY}",
        "https://as.example.com/x?a=b",
        "https://as.example.com?tenant=1",
        "https://as.example.com/x?a=%2F%2f&b=%C3%A9",
    ):
        assert untrusted_url(url, purpose="endpoint", query=query) == url


def test_the_kept_queries_load_in_a_policy() -> None:
    """Diff 1 writes the two endpoints as discovery kept them: A.1's validators take them."""
    authorize = f"https://as.example.com/oauth/authorize?{KEPT_QUERY}"
    token = f"https://as.example.com/oauth/token?{KEPT_QUERY}"
    meta = checked_as(authorization_endpoint=authorize, token_endpoint=token)
    cred = OAuth2Credential(
        kind="oauth2",
        token_url=meta.token_endpoint,
        authorize_url=meta.authorization_endpoint,
        client_id="c",
    )
    assert (cred.token_url, cred.authorize_url) == (token, authorize)


@pytest.mark.parametrize(
    "query",
    [
        "a=$x",
        "a=1;b=2",
        "a='x'",
        'a="x"',
        "a=<x",
        "a=x|y",
        "a=%zz",
        "a=%",
        "",
        "a",
        "a=1&&b=2",
        "=1",
        "a%41=1",
        "a=1&a=2",
        "&".join(f"p{i}=1" for i in range(17)),
        *(f"a=1{char}" for char in QUERY_REFUSED),
    ],
)
@pytest.mark.parametrize(("field", "use"), [("authorize_url", "authorize"), ("token_url", "token")])
def test_a_query_the_rule_refuses(query: str, field: str, use: discovery.QueryFor) -> None:
    url = f"https://as.example.com/x?{query}"
    assert untrusted_url(url, purpose="e", query=use) == bad("e", "query_invalid")
    # The schema refuses it too, so nothing discovery refuses could have loaded.
    with pytest.raises(ValidationError):
        OAuth2Credential.model_validate(
            {"kind": "oauth2", "client_id": "c", "token_url": "https://as.example.com/t"}
            | {field: url}
        )


def test_sixteen_parameters_are_enough() -> None:
    url = "https://as.example.com/x?" + "&".join(f"p{i}=1" for i in range(16))
    assert untrusted_url(url, purpose="e", query="token") == url


@pytest.mark.parametrize(
    "name",
    [
        "redirect_uri",
        "scope",
        "client_id",
        "resource",
        "state",
        "request",
        "request_uri",
        "response_mode",
        "response_type",
        "code_challenge",
        "code_challenge_method",
    ],
)
def test_a_name_the_authorization_request_sets(name: str) -> None:
    url = f"https://as.example.com/authorize?tenant=1&{name}=x"
    assert untrusted_url(url, purpose="authorization_endpoint", query="authorize") == bad(
        "authorization_endpoint", "query_reserved", name
    )


@pytest.mark.parametrize(
    "name",
    [
        "grant_type",
        "code",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "redirect_uri",
        "code_verifier",
        "refresh_token",
        "client_id",
        "scope",
        "resource",
    ],
)
def test_a_name_the_token_request_sets(name: str) -> None:
    url = f"https://as.example.com/token?{name}=x"
    assert untrusted_url(url, purpose="token_endpoint", query="token") == bad(
        "token_endpoint", "query_reserved", name
    )


def test_each_endpoint_reserves_its_own_names() -> None:
    assert untrusted_url(
        "https://as.example.com/a?code_verifier=x", purpose="e", query="authorize"
    ) == ("https://as.example.com/a?code_verifier=x")
    assert untrusted_url("https://as.example.com/t?state=x", purpose="e", query="token") == (
        "https://as.example.com/t?state=x"
    )
    assert untrusted_url(
        "https://as.example.com/a?grant_type=x", purpose="e", query="authorize"
    ) == ("https://as.example.com/a?grant_type=x")


def test_a_query_on_any_other_url() -> None:
    for url in ("https://as.example.com/x?a=b", "https://as.example.com/x?"):
        assert untrusted_url(url, purpose="issuer") == bad("issuer", "query")
    # An endpoint's bare "?" is a query the rule refuses, not a missing query.
    assert untrusted_url("https://as.example.com/x?", purpose="e", query="token") == bad(
        "e", "query_invalid"
    )


QUERY_TEXT = st.one_of(
    st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=30),
    st.lists(
        st.tuples(
            st.sampled_from(["a", "b", "tenant", "code", "state", "x.y", "a%41"]),
            st.text(alphabet="az09%2F/?:@!()*+,-._~=$;'", max_size=6),
        ),
        min_size=1,
        max_size=4,
    ).map(lambda pairs: "&".join(f"{n}={v}" for n, v in pairs)),
)


@settings(max_examples=50, deadline=None)
@given(query=QUERY_TEXT)
@pytest.mark.parametrize(("field", "use"), [("authorize_url", "authorize"), ("token_url", "token")])
def test_discovery_keeps_exactly_what_the_schema_loads(
    field: str, use: discovery.QueryFor, query: str
) -> None:
    """An endpoint discovery keeps loads unchanged in a policy, and one it refuses doesn't load."""
    url = f"https://as.example.com/oauth?{query}"
    kept = untrusted_url(url, purpose="e", query=use)
    data = {"kind": "oauth2", "client_id": "c", "token_url": "https://as.example.com/t"}
    try:
        cred = OAuth2Credential.model_validate(data | {field: url})
    except ValidationError:
        assert isinstance(kept, Refusal)
    else:
        assert kept == url
        assert getattr(cred, field) == url


# --- a URL the operator types --------------------------------------------------------------------


def test_a_typed_url() -> None:
    assert typed_url(SERVER, purpose="server") == SERVER
    assert typed_url(ORIGIN, purpose="server") == ORIGIN
    assert typed_url("https://mcp.example.com/mcp?a=b", purpose="server") == Refusal(
        "url_invalid", field="server", why="query"
    )
    assert typed_url("https://mcp.example.com/$x", purpose="server") == Refusal(
        "url_invalid", field="server", why="dollar"
    )
    assert typed_url("https://10.0.0.5/mcp", purpose="server") == Refusal(
        "url_invalid", field="server", why="host", values=("ip_literal",)
    )
    assert typed_url("http://mcp.example.com/", purpose="issuer") == Refusal(
        "url_invalid", field="issuer", why="url", values=("scheme must be one of: https",)
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://192.168.1.5/mcp",
        "https://[fd00::1]/mcp",
        "https://nas/mcp",
        "https://nas.lan:8443/mcp",
        "https://localhost/mcp",
    ],
)
def test_allow_private_lets_a_typed_url_name_a_private_host(url: str) -> None:
    assert typed_url(url, purpose="server", allow_private=True) == url
    refused = typed_url(url, purpose="server")
    assert isinstance(refused, Refusal)
    assert (refused.reason, refused.why) == ("url_invalid", "host")


@pytest.mark.parametrize(
    ("url", "verdict"),
    [
        ("https://a.0x7f/mcp", "numeric_label"),
        ("https://-nas/mcp", "syntax"),
        ("https://[fe80::1%25eth0]/mcp", "ip_literal"),
    ],
)
def test_allow_private_still_refuses_a_host_that_isnt_one(url: str, verdict: str) -> None:
    assert typed_url(url, purpose="server", allow_private=True) == Refusal(
        "url_invalid", field="server", why="host", values=(verdict,)
    )


def test_the_origin() -> None:
    assert origin_of("https://MCP.example.com:8443/a/b") == "https://MCP.example.com:8443"
    assert origin_of(ORIGIN) == ORIGIN


# --- the probe (D.2) -----------------------------------------------------------------------------


def test_the_modern_probe() -> None:
    assert (
        MODERN_PROBE.body
        == (
            '{"jsonrpc":"2.0","id":0,"method":"server/discover","params":{"_meta":{'
            '"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
            '"io.modelcontextprotocol/clientInfo":{"name":"zoeymcp","version":"'
            + __version__
            + '"},"io.modelcontextprotocol/clientCapabilities":{}}}}'
        ).encode()
    )
    assert MODERN_PROBE.headers == (
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", "2026-07-28"),
        ("Mcp-Method", "server/discover"),
    )
    # A modern server checks the headers against the body before anything else.
    message = json.loads(MODERN_PROBE.body)
    headers = dict(MODERN_PROBE.headers)
    meta = message["params"]["_meta"]
    assert meta["io.modelcontextprotocol/protocolVersion"] == headers["MCP-Protocol-Version"]
    assert message["method"] == headers["Mcp-Method"]


def test_the_legacy_probe() -> None:
    assert (
        LEGACY_PROBE.body
        == (
            '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25",'
            '"capabilities":{},"clientInfo":{"name":"zoeymcp","version":"' + __version__ + '"}}}'
        ).encode()
    )
    assert LEGACY_PROBE.headers == (
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", "2025-11-25"),
    )
    message = json.loads(LEGACY_PROBE.body)
    assert (
        message["params"]["protocolVersion"] == dict(LEGACY_PROBE.headers)["MCP-Protocol-Version"]
    )


@pytest.mark.parametrize(
    ("status", "legacy_sent", "step"),
    [
        (401, False, "challenge"),
        (401, True, "challenge"),
        (400, False, "legacy"),
        (400, True, "well_known"),
        (200, False, "well_known"),
        (202, True, "well_known"),
        (403, False, "well_known"),
        (404, False, "well_known"),
        (405, False, "well_known"),
        (406, False, "well_known"),
        (500, False, "well_known"),
    ],
)
def test_what_follows_a_probe(status: int, legacy_sent: bool, step: str) -> None:
    assert probe_next(status, legacy_sent=legacy_sent) == step


@pytest.mark.parametrize(
    ("status", "next_one"),
    [
        (300, True),
        (301, True),
        (308, True),
        (399, True),
        (404, True),
        (405, True),
        (410, True),
        (200, False),
        (299, False),
        (400, False),
        (401, False),
        (403, False),
        (406, False),
        (409, False),
        (411, False),
        (500, False),
        (502, False),
    ],
)
@pytest.mark.parametrize("source", ["path", "root", "given", "origin", "heuristic"])
def test_which_answers_move_on(status: int, next_one: bool, source: str) -> None:
    assert moves_on(status, Candidate("https://x.example.com/m", source)) is next_one


@pytest.mark.parametrize(
    ("status", "next_one"),
    [(301, False), (399, False), (404, True), (405, True), (410, True), (500, False)],
)
def test_the_challenges_url_may_not_redirect(status: int, next_one: bool) -> None:
    # B.5: a 3xx is "not here" on a well-known candidate only; here the fetch is fetch_redirect.
    assert moves_on(status, Candidate(RM, "challenge")) is next_one


@pytest.mark.parametrize("status", [200, 202, 204, 299])
def test_a_server_that_answered_without_a_sign_in_is_not_protected(status: int) -> None:
    assert prm_exhausted(["u1", "u2"], probe_status=status) == Refusal("not_protected")


@pytest.mark.parametrize("status", [199, 300, 400, 401, 404, 500])
def test_no_metadata_found_names_what_was_tried(status: int) -> None:
    assert prm_exhausted(["u1", "u2"], probe_status=status) == Refusal(
        "prm_not_found", values=("u1", "u2")
    )


def test_no_authorization_server_metadata_found() -> None:
    assert as_exhausted(["u1"]) == Refusal("as_metadata_not_found", values=("u1",))


# --- the challenge (D.2) -------------------------------------------------------------------------


def test_a_bearer_challenge() -> None:
    value = (
        f'Bearer resource_metadata="{RM}", scope="files:read files:write", '
        'error="invalid_token", realm="mcp"'
    )
    assert parse_challenge([value]) == Challenge(RM, ("files:read", "files:write"), "invalid_token")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (f'bearer Resource_Metadata="{RM}"', Challenge(RM, (), None)),
        (f'BEARER  scope = "a" ,  resource_metadata="{RM}"', Challenge(RM, ("a",), None)),
        ('Basic realm="x", Bearer scope="a"', Challenge(None, ("a",), None)),
        ('Bearer scope="a", Basic realm="x", error="e"', Challenge(None, ("a",), None)),
        ('Bearer realm="x" , , scope="a",', Challenge(None, ("a",), None)),
        (', Bearer scope="a"', Challenge(None, ("a",), None)),
        ("Bearer error=invalid_token", Challenge(None, (), "invalid_token")),
        ('Bearer error="in\\valid"', Challenge(None, (), "invalid")),
        ('Bearer error="bad code!"', Challenge(None, (), "other")),
        ("Bearer", Challenge(None, (), None)),
        ("Bearer abc123==", Challenge(None, (), None)),
        ("Bearer scope=", Challenge(None, (), None)),
        ('Negotiate abc+/==, Bearer scope="a"', Challenge(None, ("a",), None)),
        ('Bearer scope=""', Challenge(None, (), None)),
        ('Bearer\tscope="a"', Challenge(None, ("a",), None)),
    ],
)
def test_the_challenge_syntax(value: str, expected: Challenge) -> None:
    assert parse_challenge([value]) == expected


@pytest.mark.parametrize(
    "value",
    [
        'Bearer scope="a',
        'Bearer scope="a\\',
        'Bearer scope="a", scope="b"',
        'Bearer scope="a", SCOPE="b"',
        'Bearer scope="\u00e9"',
        'Bearer scope="a\x01"',
        f"Bearer resource_metadata={RM}",
        'Bearer scope="a" x',
        'Bearer "a"',
        '=x, Bearer scope="a"',
        'Bearer scope="a"; x',
        "Bearer abc== x",
    ],
)
def test_an_unparsable_value_is_no_challenge(value: str) -> None:
    assert parse_challenge([value]) is None
    # The values are one list, never half-read: another value doesn't make it count.
    assert parse_challenge([value, 'Bearer scope="z"']) is None
    assert parse_challenge(['Bearer scope="z"', value]) is None


def test_a_bad_value_cant_hide_a_second_challenge() -> None:
    other = 'Bearer resource_metadata="https://b.example.com/y" junk"'
    assert parse_challenge([f'Bearer resource_metadata="{RM}"', other]) is None


def test_no_bearer_challenge() -> None:
    assert parse_challenge([]) is None
    assert parse_challenge([""]) is None
    assert parse_challenge(['Basic realm="x"', "Negotiate"]) is None


def test_the_value_cap() -> None:
    # A scope token is at most 256 characters, so the cap is shown on a realm beside one.
    head = 'Bearer scope="a", realm="'
    at_cap = head + "r" * (CHALLENGE_MAX - len(head) - 1) + '"'
    assert len(at_cap) == CHALLENGE_MAX
    assert parse_challenge([at_cap]) == Challenge(None, ("a",), None)
    over = head + "r" * (CHALLENGE_MAX - len(head)) + '"'
    assert parse_challenge([over]) is None
    assert parse_challenge([at_cap, over]) is None


def test_two_bearer_challenges_that_disagree() -> None:
    other = "https://mcp.example.com/.well-known/oauth-protected-resource"
    values = [f'Bearer resource_metadata="{RM}"', f'Bearer resource_metadata="{other}"']
    assert parse_challenge(values) == Refusal("challenge_ambiguous", values=(RM, other))
    one = f'Bearer resource_metadata="{RM}", Bearer resource_metadata="{other}"'
    assert parse_challenge([one]) == Refusal("challenge_ambiguous", values=(RM, other))
    same = [f'Bearer resource_metadata="{RM}", scope="a"', f'Bearer resource_metadata="{RM}"']
    assert parse_challenge(same) == Challenge(RM, ("a",), None)


def test_the_challenge_naming_the_metadata_gives_the_scope() -> None:
    values = ['Bearer scope="x", error="e1"', f'Bearer resource_metadata="{RM}", scope="y"']
    assert parse_challenge(values) == Challenge(RM, ("y",), None)
    assert parse_challenge(['Bearer scope="x"', 'Bearer scope="y"']) == Challenge(
        None, ("x",), None
    )


def test_the_challenges_scopes() -> None:
    sixty_four = " ".join(f"s{i}" for i in range(64))
    parsed = parse_challenge([f'Bearer scope="{sixty_four}"'])
    assert isinstance(parsed, Challenge)
    assert len(parsed.scopes) == 64
    sixty_five = sixty_four + " s64"
    assert parse_challenge([f'Bearer scope="{sixty_five}"']) == Refusal(
        "scope_invalid", why="too_many"
    )
    assert parse_challenge(['Bearer scope="a $b"']) == Refusal("scope_invalid", values=("$b",))
    assert parse_challenge(['Bearer scope="a  b"']) == Refusal("scope_invalid", values=("",))
    assert parse_challenge(['Bearer scope="a \\\\b"']) == Refusal("scope_invalid", values=("\\b",))


def test_the_challenges_metadata_url_is_checked() -> None:
    assert parse_challenge([f'Bearer resource_metadata="{RM}?a=b"']) == bad(
        "resource_metadata", "query"
    )
    assert parse_challenge(['Bearer resource_metadata="https://127.0.0.1/x"']) == bad(
        "resource_metadata", "host", "ip_literal"
    )
    assert parse_challenge(['Bearer resource_metadata="https://mcp.example.com/$x"']) == Refusal(
        "url_dollar", field="resource_metadata"
    )


# --- protected-resource metadata (D.2, D.3) ------------------------------------------------------


def test_the_challenges_url_alone() -> None:
    challenge = Challenge("https://meta.example.com/prm", (), None)
    assert prm_candidates(SERVER, challenge) == (
        Candidate("https://meta.example.com/prm", "challenge"),
    )


def test_the_well_known_candidates() -> None:
    expected = (
        Candidate(RM, "path"),
        Candidate("https://mcp.example.com/.well-known/oauth-protected-resource", "root"),
    )
    assert prm_candidates(SERVER, None) == expected
    assert prm_candidates(SERVER, Challenge(None, ("a",), None)) == expected
    assert prm_candidates("https://mcp.example.com:8443/a/b/", None) == (
        Candidate("https://mcp.example.com:8443/.well-known/oauth-protected-resource/a/b/", "path"),
        Candidate("https://mcp.example.com:8443/.well-known/oauth-protected-resource", "root"),
    )
    for server in (ORIGIN, ORIGIN + "/"):
        assert prm_candidates(server, None) == (
            Candidate("https://mcp.example.com/.well-known/oauth-protected-resource", "root"),
        )


def test_a_protected_resource_document() -> None:
    assert check_prm(prm_doc(), "path", SERVER) == Prm(
        SERVER, (ISSUER,), ("notes.read", "notes.write"), "Notes", "path"
    )
    assert check_prm(
        prm_doc(scopes_supported=OMIT, resource_name=OMIT, signed_metadata="x.y.z", other=[1]),
        "challenge",
        SERVER,
    ) == Prm(SERVER, (ISSUER,), None, None, "challenge")


@pytest.mark.parametrize(
    ("source", "resource", "ok"),
    [
        ("challenge", SERVER, True),
        ("challenge", SERVER + "/", False),
        ("challenge", ORIGIN, False),
        ("path", SERVER, True),
        ("path", SERVER + "/", False),
        ("path", ORIGIN + "/", False),
        ("path", "https://MCP.example.com/mcp", False),
        ("root", ORIGIN, True),
        ("root", ORIGIN + "/", True),
        ("root", SERVER, False),
        ("root", "https://mcp.example.com:443", False),
        ("root", "https://other.example.com", False),
    ],
)
def test_the_resource_rule(source: discovery.PrmSource, resource: str, ok: bool) -> None:
    found = check_prm(prm_doc(resource=resource), source, SERVER)
    if ok:
        assert isinstance(found, Prm)
        assert found.resource == resource
    else:
        expected = ORIGIN if source == "root" else SERVER
        assert found == Refusal(
            "prm_resource_mismatch", field="resource", values=(resource, expected)
        )


def test_the_expected_resources() -> None:
    assert expected_resources("challenge", SERVER) == (SERVER,)
    assert expected_resources("path", SERVER) == (SERVER,)
    port = "https://mcp.example.com:8443/mcp"
    assert expected_resources("root", port) == (
        "https://mcp.example.com:8443",
        "https://mcp.example.com:8443/",
    )


@pytest.mark.parametrize(
    ("doc", "refusal"),
    [
        ([], Refusal("prm_invalid", why="type")),
        ("x", Refusal("prm_invalid", why="type")),
        (prm_doc(resource=OMIT), Refusal("prm_invalid", field="resource", why="missing")),
        (prm_doc(resource=5), Refusal("prm_invalid", field="resource", why="missing")),
        (prm_doc(resource=SERVER + "?a=b"), bad("resource", "query")),
        (prm_doc(resource=SERVER + "#"), bad("resource", "fragment")),
        (
            prm_doc(authorization_servers=OMIT),
            Refusal("prm_invalid", field="authorization_servers", why="type"),
        ),
        (
            prm_doc(authorization_servers=[]),
            Refusal("prm_invalid", field="authorization_servers", why="type"),
        ),
        (
            prm_doc(authorization_servers=ISSUER),
            Refusal("prm_invalid", field="authorization_servers", why="type"),
        ),
        (
            prm_doc(authorization_servers=[ISSUER, 5]),
            Refusal("prm_invalid", field="authorization_servers", why="type"),
        ),
        (
            prm_doc(authorization_servers=[f"https://as{i}.example.com" for i in range(9)]),
            Refusal("prm_invalid", field="authorization_servers", why="type"),
        ),
        (prm_doc(authorization_servers=[ISSUER + "?a=b"]), bad("authorization_servers", "query")),
        (prm_doc(authorization_servers=[ISSUER + "#"]), bad("authorization_servers", "fragment")),
        (
            prm_doc(authorization_servers=["https://10.1.2.3"]),
            bad("authorization_servers", "host", "ip_literal"),
        ),
        (
            prm_doc(scopes_supported="notes.read"),
            Refusal("prm_invalid", field="scopes_supported", why="type"),
        ),
        (prm_doc(scopes_supported=["a b"]), Refusal("scope_invalid", values=("a b",))),
        (prm_doc(scopes_supported=["ok", "a$"]), Refusal("scope_invalid", values=("a$",))),
        (prm_doc(dpop_bound_access_tokens_required=True), Refusal("dpop_required")),
        (
            prm_doc(dpop_bound_access_tokens_required="yes"),
            Refusal("prm_invalid", field="dpop_bound_access_tokens_required", why="type"),
        ),
        (prm_doc(resource_name=5), Refusal("prm_invalid", field="resource_name", why="type")),
    ],
)
def test_a_protected_resource_document_refused(doc: object, refusal: Refusal) -> None:
    assert check_prm(doc, "path", SERVER) == refusal


def test_the_documents_lists() -> None:
    eight = [f"https://as{i}.example.com" for i in range(8)]
    assert checked_prm(authorization_servers=eight).authorization_servers == tuple(eight)
    other = "https://other.example.com/tenant"
    assert checked_prm(authorization_servers=[ISSUER, ISSUER, other]).authorization_servers == (
        ISSUER,
        other,
    )
    assert checked_prm(scopes_supported=[]).scopes_supported == ()
    assert checked_prm(dpop_bound_access_tokens_required=False).resource == SERVER


def test_the_resource_name_is_only_for_display() -> None:
    assert checked_prm(resource_name="x" * 200).resource_name == "x" * 200
    assert checked_prm(resource_name="x" * 201).resource_name == "x" * 200 + "\u2026[+1]"
    assert checked_prm(resource_name=f"No{ZWSP}tes").resource_name == "No[U+200B]tes"
    assert checked_prm(resource_name=None).resource_name is None


# --- the issuer (D.2a, D.3) ----------------------------------------------------------------------


def test_choosing_the_issuer() -> None:
    two = (ISSUER, "https://other.example.com")
    assert choose_issuer((ISSUER,), None) == ISSUER
    assert choose_issuer((ISSUER,), ISSUER) == ISSUER
    assert choose_issuer(two, None) == Refusal("as_choice_needed", values=two)
    assert choose_issuer(two, "https://other.example.com") == "https://other.example.com"
    assert choose_issuer(two, "https://third.example.com") == Refusal("as_unknown", values=two)
    assert choose_issuer((ISSUER,), ISSUER + "/") == Refusal("as_unknown", values=(ISSUER,))


def test_the_authorization_server_candidates() -> None:
    assert as_candidates("https://auth.example.com/tenant1") == (
        "https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
        "https://auth.example.com/.well-known/openid-configuration/tenant1",
        "https://auth.example.com/tenant1/.well-known/openid-configuration",
    )
    assert as_candidates("https://auth.example.com/tenant1/") == as_candidates(
        "https://auth.example.com/tenant1"
    )
    for issuer in (ISSUER, ISSUER + "/"):
        assert as_candidates(issuer) == (
            "https://auth.example.com/.well-known/oauth-authorization-server",
            "https://auth.example.com/.well-known/openid-configuration",
        )
    assert as_candidates("https://auth.example.com:8443/a/b") == (
        "https://auth.example.com:8443/.well-known/oauth-authorization-server/a/b",
        "https://auth.example.com:8443/.well-known/openid-configuration/a/b",
        "https://auth.example.com:8443/a/b/.well-known/openid-configuration",
    )


def test_the_legacy_candidates_in_order() -> None:
    assert legacy_candidates(SERVER, None) == (
        Candidate(
            "https://mcp.example.com/.well-known/oauth-authorization-server", "origin", ORIGIN
        ),
        Candidate("https://mcp.example.com/.well-known/openid-configuration", "origin", ORIGIN),
        Candidate(
            "https://mcp.example.com/.well-known/oauth-authorization-server/mcp",
            "heuristic",
            SERVER,
        ),
        Candidate(
            "https://mcp.example.com/.well-known/openid-configuration/mcp", "heuristic", SERVER
        ),
        Candidate(
            "https://mcp.example.com/mcp/.well-known/openid-configuration", "heuristic", SERVER
        ),
    )
    # Without a path the server URL adds nothing to its origin.
    for server in (ORIGIN, ORIGIN + "/"):
        assert [c.source for c in legacy_candidates(server, None)] == ["origin", "origin"]


def test_an_issuer_the_operator_gives_is_the_only_legacy_candidate() -> None:
    given = "https://auth.example.com/t"
    assert legacy_candidates(SERVER, given) == tuple(
        Candidate(url, "given", given) for url in as_candidates(given)
    )


def test_the_legacy_labels() -> None:
    assert LEGACY_LABELS == {
        "given": "the issuer you gave (MCP's pre-configured values)",
        "origin": "the server URL's origin (MCP 2025-03-26's rule)",
        "heuristic": "found by a ZoeyMCP heuristic, not by any MCP rule",
    }


# --- authorization server metadata (D.3) ---------------------------------------------------------


def test_an_authorization_server_document() -> None:
    assert check_as_metadata(as_doc(), ISSUER) == AsMetadata(
        issuer=ISSUER,
        authorization_endpoint=AUTHORIZE,
        token_endpoint=TOKEN,
        registration_endpoint=REGISTER,
        revocation_endpoint=REVOKE,
        require_iss=True,
        scopes_supported=("notes.read", "notes.write", "offline_access"),
        token_auth_methods=("none", "client_secret_basic"),
        revocation_auth_methods=None,
        notes=(),
    )


def test_the_defaults_and_the_notes() -> None:
    meta = checked_as(
        registration_endpoint=OMIT,
        revocation_endpoint=None,
        grant_types_supported=OMIT,
        token_endpoint_auth_methods_supported=OMIT,
        revocation_endpoint_auth_methods_supported=["client_secret_post"],
        authorization_response_iss_parameter_supported=OMIT,
        scopes_supported=[],
        client_id_metadata_document_supported=True,
        dpop_signing_alg_values_supported=["ES256"],
    )
    assert (meta.registration_endpoint, meta.revocation_endpoint) == (None, None)
    assert meta.token_auth_methods == ("client_secret_basic",)
    assert meta.revocation_auth_methods == ("client_secret_post",)
    assert meta.require_iss is False
    assert meta.scopes_supported is None
    assert meta.notes == ("cimd", "dpop", "iss_not_advertised")
    assert checked_as(token_endpoint_auth_methods_supported=[]).token_auth_methods == (
        "client_secret_basic",
    )
    assert checked_as(revocation_endpoint_auth_methods_supported=[]).revocation_auth_methods is None
    assert checked_as(client_id_metadata_document_supported="yes").notes == ()
    assert checked_as(client_id_metadata_document_supported=False).notes == ()
    assert checked_as(dpop_signing_alg_values_supported=[]).notes == ("dpop",)
    assert checked_as(authorization_response_iss_parameter_supported=False).notes == (
        "iss_not_advertised",
    )


def test_the_attacker_example() -> None:
    """MCP's discovery page: a document at https://attacker.example/... claiming "issuer":
    "https://honest.example" MUST be rejected."""
    issuer = "https://attacker.example"
    assert (
        as_candidates(issuer)[0]
        == "https://attacker.example/.well-known/oauth-authorization-server"
    )
    doc = as_doc(issuer="https://honest.example")
    assert check_as_metadata(doc, issuer) == Refusal(
        "as_issuer_mismatch", field="issuer", values=("https://honest.example", issuer)
    )


@pytest.mark.parametrize(
    ("named", "built"),
    [
        (ISSUER + "/", ISSUER),
        (ISSUER, ISSUER + "/"),
        ("https://AUTH.example.com", ISSUER),
        ("https://auth.example.com:443", ISSUER),
    ],
)
def test_the_issuer_is_equal_byte_for_byte(named: str, built: str) -> None:
    assert check_as_metadata(as_doc(issuer=named), built) == Refusal(
        "as_issuer_mismatch", field="issuer", values=(named, built)
    )


@pytest.mark.parametrize(
    ("changes", "refusal"),
    [
        ({"issuer": OMIT}, Refusal("as_metadata_invalid", field="issuer", why="missing")),
        ({"issuer": 5}, Refusal("as_metadata_invalid", field="issuer", why="missing")),
        (
            {"authorization_endpoint": OMIT},
            Refusal("as_metadata_invalid", field="authorization_endpoint", why="missing"),
        ),
        (
            {"authorization_endpoint": 5},
            Refusal("as_metadata_invalid", field="authorization_endpoint", why="type"),
        ),
        (
            {"token_endpoint": OMIT},
            Refusal("as_metadata_invalid", field="token_endpoint", why="missing"),
        ),
        (
            {"token_endpoint": [TOKEN]},
            Refusal("as_metadata_invalid", field="token_endpoint", why="type"),
        ),
        (
            {"authorization_endpoint": "https://auth.example.com/a?redirect_uri=x"},
            bad("authorization_endpoint", "query_reserved", "redirect_uri"),
        ),
        (
            {"token_endpoint": "https://auth.example.com/t?client_assertion=x"},
            bad("token_endpoint", "query_reserved", "client_assertion"),
        ),
        (
            {"token_endpoint": "https://auth.example.com/t?a=$"},
            bad("token_endpoint", "query_invalid"),
        ),
        (
            {"authorization_endpoint": "https://as/authorize#"},
            bad("authorization_endpoint", "fragment"),
        ),
        (
            {"token_endpoint": "https://10.0.0.1/token"},
            bad("token_endpoint", "host", "ip_literal"),
        ),
        (
            {"response_types_supported": OMIT},
            Refusal("code_flow_unsupported", field="response_types_supported"),
        ),
        (
            {"response_types_supported": []},
            Refusal("code_flow_unsupported", field="response_types_supported"),
        ),
        (
            {"response_types_supported": ["token", "id_token"]},
            Refusal("code_flow_unsupported", field="response_types_supported"),
        ),
        ({"code_challenge_methods_supported": OMIT}, Refusal("pkce_unsupported")),
        ({"code_challenge_methods_supported": []}, Refusal("pkce_unsupported")),
        ({"code_challenge_methods_supported": ["plain"]}, Refusal("pkce_unsupported")),
        ({"code_challenge_methods_supported": ["s256"]}, Refusal("pkce_unsupported")),
        (
            {"grant_types_supported": ["implicit", "client_credentials"]},
            Refusal("code_flow_unsupported", field="grant_types_supported"),
        ),
        (
            {"grant_types_supported": []},
            Refusal("code_flow_unsupported", field="grant_types_supported"),
        ),
        ({"registration_endpoint": REGISTER + "?a=b"}, bad("registration_endpoint", "query")),
        ({"registration_endpoint": REGISTER + "#"}, bad("registration_endpoint", "fragment")),
        (
            {"registration_endpoint": 5},
            Refusal("as_metadata_invalid", field="registration_endpoint", why="type"),
        ),
        ({"revocation_endpoint": REVOKE + "?a=b"}, bad("revocation_endpoint", "query")),
        (
            {"revocation_endpoint": "https://auth.example.com/re$voke"},
            Refusal("url_dollar", field="revocation_endpoint"),
        ),
        (
            {"revocation_endpoint": True},
            Refusal("as_metadata_invalid", field="revocation_endpoint", why="type"),
        ),
        (
            {"authorization_response_iss_parameter_supported": "true"},
            Refusal(
                "as_metadata_invalid",
                field="authorization_response_iss_parameter_supported",
                why="type",
            ),
        ),
        ({"scopes_supported": ["ok", 'q"uote']}, Refusal("scope_invalid", values=('q"uote',))),
        ({"scopes_supported": ["a$b"]}, Refusal("scope_invalid", values=("a$b",))),
    ],
)
def test_an_authorization_server_document_refused(
    changes: dict[str, object], refusal: Refusal
) -> None:
    assert check_as_metadata(as_doc(**changes), ISSUER) == refusal


@pytest.mark.parametrize("member", discovery._AS_LISTS)
@pytest.mark.parametrize("value", ["code S256", [1], {"a": "b"}, ["ok", None]])
def test_every_list_member_is_a_list_of_strings(member: str, value: object) -> None:
    assert check_as_metadata(as_doc(**{member: value}), ISSUER) == Refusal(
        "as_metadata_invalid", field=member, why="type"
    )


def test_not_a_document() -> None:
    docs: list[object] = [[], "x", None, 5]
    for doc in docs:
        assert check_as_metadata(doc, ISSUER) == Refusal("as_metadata_invalid", why="type")


def test_the_checks_run_in_d3s_order() -> None:
    # The issuer comes first, then the two endpoints, the code flow, PKCE and the grant types.
    assert check_as_metadata(
        as_doc(issuer="https://x.example.com", authorization_endpoint=OMIT), ISSUER
    ) == Refusal("as_issuer_mismatch", field="issuer", values=("https://x.example.com", ISSUER))
    assert check_as_metadata(
        as_doc(authorization_endpoint=OMIT, token_endpoint=5), ISSUER
    ) == Refusal("as_metadata_invalid", field="authorization_endpoint", why="missing")
    assert check_as_metadata(
        as_doc(token_endpoint=OMIT, response_types_supported=[]), ISSUER
    ) == Refusal("as_metadata_invalid", field="token_endpoint", why="missing")
    assert check_as_metadata(
        as_doc(response_types_supported=[], code_challenge_methods_supported=[]), ISSUER
    ) == Refusal("code_flow_unsupported", field="response_types_supported")
    assert check_as_metadata(
        as_doc(code_challenge_methods_supported=[], grant_types_supported=[]), ISSUER
    ) == Refusal("pkce_unsupported")
    assert check_as_metadata(
        as_doc(grant_types_supported=[], registration_endpoint=5), ISSUER
    ) == Refusal("code_flow_unsupported", field="grant_types_supported")
    assert check_as_metadata(
        as_doc(registration_endpoint=5, revocation_endpoint=5), ISSUER
    ) == Refusal("as_metadata_invalid", field="registration_endpoint", why="type")
    assert check_as_metadata(
        as_doc(revocation_endpoint=5, authorization_response_iss_parameter_supported=5), ISSUER
    ) == Refusal("as_metadata_invalid", field="revocation_endpoint", why="type")
    assert check_as_metadata(
        as_doc(authorization_response_iss_parameter_supported=5, scopes_supported=["$"]), ISSUER
    ) == Refusal(
        "as_metadata_invalid", field="authorization_response_iss_parameter_supported", why="type"
    )


# --- scopes (D.5) --------------------------------------------------------------------------------


def test_scopes_in_mcps_order() -> None:
    meta = checked_as(scopes_supported=["x", "y"])
    prm = checked_prm(scopes_supported=["p1", "p2"])
    challenge = Challenge(None, ("c1",), None)
    assert select_scopes(challenge, prm, meta) == Scopes(("c1",), "challenge", False)
    assert select_scopes(Challenge(None, (), None), prm, meta) == Scopes(("p1", "p2"), "prm", False)
    assert select_scopes(None, prm, meta) == Scopes(("p1", "p2"), "prm", False)
    # A protected resource without scopes names none: the server's list isn't a hint (RFC 9728).
    assert select_scopes(None, checked_prm(scopes_supported=[]), meta) == Scopes((), "none", False)
    assert select_scopes(None, checked_prm(scopes_supported=OMIT), meta) == Scopes(
        (), "none", False
    )
    # Without protected-resource metadata, the authorization server's list, for the operator.
    assert select_scopes(None, None, meta) == Scopes(("x", "y"), "as", False)
    assert select_scopes(challenge, None, meta) == Scopes(("c1",), "challenge", False)
    assert select_scopes(None, None, checked_as(scopes_supported=OMIT)) == Scopes((), "none", False)


def test_offline_access_is_added_when_offered() -> None:
    offered = checked_as(scopes_supported=["a", "offline_access"])
    prm = checked_prm(scopes_supported=["p"])
    assert select_scopes(None, prm, offered) == Scopes(("p", "offline_access"), "prm", True)
    assert select_scopes(None, checked_prm(scopes_supported=[]), offered) == Scopes(
        ("offline_access",), "none", True
    )
    already = checked_prm(scopes_supported=["offline_access", "p"])
    assert select_scopes(None, already, offered) == Scopes(("offline_access", "p"), "prm", False)
    assert select_scopes(None, None, offered) == Scopes(("a", "offline_access"), "as", False)
    assert select_scopes(None, prm, checked_as(scopes_supported=["a"])) == Scopes(
        ("p",), "prm", False
    )


def test_the_scopes_fit_the_policy() -> None:
    offered = checked_as(scopes_supported=["offline_access"])
    sixty_four = Challenge(None, tuple(f"s{i}" for i in range(64)), None)
    assert select_scopes(sixty_four, None, checked_as(scopes_supported=OMIT)) == Scopes(
        sixty_four.scopes, "challenge", False
    )
    assert select_scopes(sixty_four, None, offered) == Refusal("scope_invalid", why="too_many")
    # 2,048 characters with the spaces, the schema's cap; one more refuses.
    fits = Challenge(None, (*("a" * 256 for _ in range(7)), "b" * 249), None)
    assert len(" ".join(fits.scopes)) == discovery.SCOPE_TEXT_MAX
    meta = checked_as(scopes_supported=OMIT)
    scopes = select_scopes(fits, None, meta)
    assert isinstance(scopes, Scopes)
    OAuth2Credential(kind="oauth2", token_url=TOKEN, client_id="c", scope=" ".join(scopes.scopes))
    over = Challenge(None, (*fits.scopes[:-1], "b" * 250), None)
    assert select_scopes(over, None, meta) == Refusal("scope_invalid", why="too_many")


def test_a_long_list_from_the_authorization_server() -> None:
    # D.2a: the AS's list is the operator's to narrow, so a long one requests none, never refuses.
    sixty_four = [f"s{i}" for i in range(64)]
    assert select_scopes(None, None, checked_as(scopes_supported=sixty_four)) == Scopes(
        tuple(sixty_four), "as", False
    )
    many = [f"s{i}" for i in range(65)]
    assert select_scopes(None, None, checked_as(scopes_supported=many)) == Scopes(
        (), "as_too_many", False
    )
    with_offline = checked_as(scopes_supported=[*many[:-1], "offline_access"])
    assert select_scopes(None, None, with_offline) == Scopes(
        ("offline_access",), "as_too_many", True
    )
    fits = [*("a" * 256 for _ in range(7)), "b" * 249]
    assert select_scopes(None, None, checked_as(scopes_supported=fits)) == Scopes(
        tuple(fits), "as", False
    )
    long = [*fits[:-1], "b" * 250]
    assert select_scopes(None, None, checked_as(scopes_supported=long)) == Scopes(
        (), "as_too_many", False
    )
    # The challenge and the protected resource name scopes themselves: theirs still refuse.
    meta = checked_as(scopes_supported=many)
    assert select_scopes(Challenge(None, tuple(many), None), None, meta) == Refusal(
        "scope_invalid", why="too_many"
    )
    assert select_scopes(None, checked_prm(scopes_supported=many), meta) == Refusal(
        "scope_invalid", why="too_many"
    )


def test_a_plan_with_a_long_list_from_the_authorization_server() -> None:
    meta = checked_as(scopes_supported=[f"s{i}" for i in range(65)])
    plan = a_plan(prm=None, metadata=meta)
    assert isinstance(plan, Plan)
    assert dict(plan.rows())["Scopes"] == (
        "none (the authorization server lists more than a credential holds (64 scopes, 2,048 "
        "characters), so none of its list is requested: name the ones you need)"
    )


# --- the plan (D.8's discovery part) -------------------------------------------------------------


def a_plan(**changes: Any) -> Plan | Refusal:
    arguments: dict[str, Any] = {
        "challenge": None,
        "prm": checked_prm(),
        "resource_metadata": RM,
        "issuer_source": "only",
        "metadata_url": META_URL,
        "metadata": checked_as(),
    }
    arguments.update(changes)
    return build_plan(SERVER, **arguments)


def test_a_plan() -> None:
    plan = a_plan()
    assert plan == Plan(
        server_url=SERVER,
        resource=SERVER,
        resource_metadata=RM,
        resource_name="Notes",
        issuer=ISSUER,
        issuer_source="only",
        metadata_url=META_URL,
        metadata=checked_as(),
        scopes=Scopes(("notes.read", "notes.write", "offline_access"), "prm", True),
        hosts=(
            "mcp.example.com:443",
            "auth.example.com:443",
            "auth.example.com:8443",
            "reg.example.com:443",
        ),
        notes=("offline_access_added",),
    )
    assert isinstance(plan, Plan)
    assert plan.rows() == (
        ("Server", SERVER),
        ("Resource", SERVER),
        ("Resource name", "Notes"),
        ("Resource metadata", RM),
        ("Issuer", "https://auth.example.com (the one the server names)"),
        ("Issuer metadata", META_URL),
        ("Authorization endpoint", AUTHORIZE),
        ("Token endpoint", TOKEN),
        ("Registration endpoint", REGISTER),
        ("Revocation endpoint", REVOKE),
        ("Requires iss", "yes"),
        ("PKCE", "S256"),
        (
            "Scopes",
            "notes.read notes.write offline_access (from the server's protected-resource metadata)",
        ),
        (
            "Hosts",
            "mcp.example.com:443, auth.example.com:443, auth.example.com:8443, reg.example.com:443",
        ),
        (
            "Note",
            "offline_access was added: the authorization server lists it, and login needs a "
            "refresh token.",
        ),
    )


def test_a_legacy_plan() -> None:
    doc = as_doc(
        registration_endpoint=OMIT,
        revocation_endpoint=OMIT,
        authorization_response_iss_parameter_supported=False,
        scopes_supported=OMIT,
        token_endpoint="https://mcp.example.com/token",
        authorization_endpoint="https://mcp.example.com/authorize",
        issuer=SERVER,
    )
    meta = check_as_metadata(doc, SERVER)
    assert isinstance(meta, AsMetadata)
    meta_url = "https://mcp.example.com/.well-known/oauth-authorization-server/mcp"
    found = build_plan(
        SERVER,
        challenge=Challenge(None, ("a",), None),
        prm=None,
        resource_metadata=RM,
        issuer_source="heuristic",
        metadata_url=meta_url,
        metadata=meta,
    )
    assert isinstance(found, Plan)
    # The resource is the server URL as typed, and no resource_metadata is pinned (D.2a).
    assert (found.resource, found.resource_metadata, found.resource_name) == (SERVER, None, None)
    assert found.hosts == ("mcp.example.com:443",)
    assert found.notes == ("legacy", "heuristic", "iss_not_advertised")
    assert found.rows() == (
        ("Server", SERVER),
        ("Resource", SERVER),
        ("Resource metadata", "none (D.2a)"),
        ("Issuer", f"{SERVER} (found by a ZoeyMCP heuristic, not by any MCP rule)"),
        ("Issuer metadata", meta_url),
        ("Authorization endpoint", "https://mcp.example.com/authorize"),
        ("Token endpoint", "https://mcp.example.com/token"),
        ("Registration endpoint", "none"),
        ("Revocation endpoint", "none"),
        ("Requires iss", "no"),
        ("PKCE", "S256"),
        ("Scopes", "a (from the server's challenge)"),
        ("Hosts", "mcp.example.com:443"),
        ("Note", NOTES["legacy"]),
        ("Note", NOTES["heuristic"]),
        ("Note", NOTES["iss_not_advertised"]),
    )


def test_a_root_published_resource_and_a_chosen_issuer() -> None:
    plan = a_plan(prm=checked_prm("root", resource=ORIGIN + "/"), issuer_source="chosen")
    assert isinstance(plan, Plan)
    assert plan.resource == ORIGIN + "/"
    assert plan.notes == ("root_resource", "offline_access_added")
    assert dict(plan.rows())["Issuer"] == (
        "https://auth.example.com (the one you chose of those the server names)"
    )


def test_the_issuer_labels() -> None:
    for source, label in (
        ("only", "the one the server names"),
        ("given", "the issuer you gave (MCP's pre-configured values)"),
        ("origin", "the server URL's origin (MCP 2025-03-26's rule)"),
    ):
        plan = a_plan(issuer_source=source)
        assert isinstance(plan, Plan)
        assert dict(plan.rows())["Issuer"] == f"{ISSUER} ({label})"


def test_the_notes_and_scope_sources_are_pinned() -> None:
    assert NOTES == {
        "legacy": "This server publishes no protected-resource metadata; the authorization "
        "server was found without it (D.2a).",
        "heuristic": "The authorization server was found by a ZoeyMCP heuristic, not by any MCP "
        "rule. Confirm it is the one you expect.",
        "root_resource": "The server publishes its metadata for its whole origin, not for this "
        "URL.",
        "offline_access_added": "offline_access was added: the authorization server lists it, "
        "and login needs a refresh token.",
        "cimd": "The authorization server registers clients by metadata document, which ZoeyMCP "
        "doesn't support yet.",
        "dpop": "The authorization server offers DPoP; ZoeyMCP uses Bearer tokens.",
        "iss_not_advertised": "The authorization server doesn't say it sends iss with its "
        "answers, so a missing iss isn't refused.",
    }
    assert discovery.SCOPE_SOURCES == {
        "challenge": "from the server's challenge",
        "prm": "from the server's protected-resource metadata",
        "as": "from the authorization server's list, for you to narrow",
        "as_too_many": "the authorization server lists more than a credential holds (64 "
        "scopes, 2,048 characters), so none of its list is requested: name the ones you need",
        "none": "none named",
    }


def test_the_plan_lists_every_note() -> None:
    meta = checked_as(
        client_id_metadata_document_supported=True,
        dpop_signing_alg_values_supported=["ES256"],
        authorization_response_iss_parameter_supported=False,
        scopes_supported=["offline_access"],
    )
    plan = a_plan(metadata=meta, prm=checked_prm("root", resource=ORIGIN), issuer_source="origin")
    assert isinstance(plan, Plan)
    assert plan.notes == (
        "root_resource",
        "offline_access_added",
        "cimd",
        "dpop",
        "iss_not_advertised",
    )
    assert [value for label, value in plan.rows() if label == "Note"] == [
        NOTES[note] for note in plan.notes
    ]


def test_a_plan_with_too_many_scopes() -> None:
    many = Challenge(None, tuple(f"s{i}" for i in range(64)), None)
    assert a_plan(challenge=many) == Refusal("scope_invalid", why="too_many")


def test_the_hosts_the_vault_contacts() -> None:
    meta = checked_as(
        token_endpoint="https://token.example.com/t",
        registration_endpoint="https://auth.example.com:444/r",
        revocation_endpoint="https://revoke.example.com/r",
    )
    plan = a_plan(metadata=meta, resource_metadata="https://meta.example.com/prm")
    assert isinstance(plan, Plan)
    # The authorization endpoint is the browser's, never the vault's.
    assert plan.hosts == (
        "mcp.example.com:443",
        "auth.example.com:443",
        "token.example.com:443",
        "meta.example.com:443",
        "auth.example.com:444",
        "revoke.example.com:443",
    )


def test_the_rows_reveal_what_they_show() -> None:
    plan = a_plan()
    assert isinstance(plan, Plan)
    hidden = Plan(**{**plan.__dict__, "server_url": f"https://mcp{ZWSP}.example.com/mcp"})
    assert dict(hidden.rows())["Server"] == "https://mcp[U+200B].example.com/mcp"
    assert dict(hidden.rows())["Token endpoint"] == TOKEN


def test_the_limits_are_pinned() -> None:
    assert discovery.METADATA_MAX == 65536
    assert discovery.REGISTRATION_MAX == 16384
    assert CHALLENGE_MAX == 4096
    assert discovery.MAX_ISSUERS == 8


@pytest.mark.parametrize(
    "quoted", ["\t", " ", "!", "#", "[", "]", "~", '\\"', "\\\\", "\\\t", "\\ ", "\\~"]
)
def test_a_quoted_string(quoted: str) -> None:
    """Each edge of qdtext and quoted-pair (RFC 9110 5.6.4)."""
    parsed = parse_challenge([f'Bearer realm="{quoted}", scope="x", error="e{quoted}"'])
    assert parsed == Challenge(None, ("x",), "other")


def test_a_quoted_pair_is_unescaped() -> None:
    assert parse_challenge(['Bearer error="a\\b\\_c\\.d"']) == Challenge(None, (), "ab_c.d")
    assert parse_challenge(['Bearer scope="a\\:b"']) == Challenge(None, ("a:b",), None)


@pytest.mark.parametrize("quoted", ["\x7f", "\x08", "\x0a", "\\\x7f", "\\\x08", "\x22\x22\x22"])
def test_a_quoted_string_refused(quoted: str) -> None:
    assert parse_challenge([f'Bearer realm="{quoted}", scope="x"']) is None


@pytest.mark.parametrize(
    "value", ["Bearer/abc", "Bearer+x", "Bearer =x", 'Bearer , ="x"', 'Bearer scope="a", ="x"']
)
def test_what_follows_a_scheme(value: str) -> None:
    assert parse_challenge([value]) is None


def test_a_plan_with_no_scopes() -> None:
    plan = a_plan(
        prm=checked_prm(scopes_supported=OMIT), metadata=checked_as(scopes_supported=OMIT)
    )
    assert isinstance(plan, Plan)
    assert dict(plan.rows())["Scopes"] == "none (none named)"
    assert plan.notes == ()
