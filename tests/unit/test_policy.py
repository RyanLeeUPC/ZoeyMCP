"""Schema and ``check`` tests.

Most tests start from the shipped example policy, which must pass ``check`` with no errors,
and change one thing. Each must produce the expected finding: the same idea as mutation testing,
applied to the policy instead of the code.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from zoeymcp.common.policy import Finding, PolicyError, check_policy, parse_policy
from zoeymcp.common.policy.schema import (
    Client,
    Gateway,
    GatewayLimits,
    OAuth2Credential,
    RemoteServer,
    hash_token,
    param_values,
    split_scope,
)

Raw = dict[str, Any]
# agent1's token_sha256 in the example policy.
AGENT1_HASH = "sha256:8ca973db011281c88e678afeb86d1955579aed24fd7deeae43155fe7aabb0f43"


def run(raw: Raw, environ: dict[str, str] | None = None) -> list[Finding]:
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    return check_policy(policy, environ=environ)


def errors(findings: list[Finding]) -> list[str]:
    return [f"{f.path}: {f.message}" for f in findings if f.level == "error"]


def warnings(findings: list[Finding]) -> list[str]:
    return [f"{f.path}: {f.message}" for f in findings if f.level == "warning"]


def schema_errors(raw: Raw) -> list[str]:
    with pytest.raises(PolicyError) as info:
        parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    return [f"{f.path}: {f.message}" for f in info.value.findings]


def route(raw: Raw, name: str) -> Raw:
    return next(r for r in raw["routes"] if r["name"] == name)


def test_example_policy_is_clean(example_text: str) -> None:
    findings = check_policy(parse_policy(example_text, "example"))
    assert [f"{f.level} {f.path}" for f in findings] == [
        "warning credentials.broker-mcp.authorize_url",
        "warning gateway.clients.agent1.servers",
    ]


# --- schema ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda r: r.update(surprise=1), "surprise: Extra inputs are not permitted"),
        (lambda r: r.update(version=2), "version: Input should be 1"),
        (lambda r: r.update(mode="yolo"), "mode: Input should be 'managed' or 'declarative'"),
        (
            lambda r: r["credentials"]["music-stats"].update(secret="hunter2"),
            "credentials.music-stats.query.secret: String should match pattern",
        ),
        (
            lambda r: r["credentials"]["music-stats"].update(kind="magic"),
            "credentials.music-stats: Input tag 'magic' found using 'kind' does not match",
        ),
        (
            lambda r: route(r, "stats").update(upstream="ftp://api.stats.example"),
            "routes[0].upstream: Value error, scheme must be one of",
        ),
        (
            lambda r: route(r, "stats").update(upstream="https://u:p@api.stats.example"),
            "routes[0].upstream: Value error, credentials in URLs are not allowed",
        ),
        (
            lambda r: route(r, "stats").update(upstream="https://api.stats.example/?k=v"),
            "routes[0].upstream: Value error, query strings and fragments are not allowed",
        ),
        (
            lambda r: route(r, "stats").update(rules=[]),
            "routes[0].rules: List should have at least 1 item",
        ),
        (
            lambda r: route(r, "stats").update(callers=[]),
            "routes[0].callers: List should have at least 1 item",
        ),
        (
            lambda r: route(r, "stats")["rules"][0].update(methods=["TRACE"]),
            "routes[0].rules[0].methods[0]: Input should be 'GET'",
        ),
        (
            lambda r: route(r, "mail-send").update(upstream="https://x.example"),
            "routes[2]: Value error, a connector route takes no upstream or credential",
        ),
        (
            lambda r: route(r, "stats").pop("upstream"),
            "routes[0]: Value error, a route needs an upstream or a connector",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(to=["a@x.example", "A@x.example"]),
            "connectors.mail-out.to: Value error, duplicate recipient",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(to=["Partner <p@x.example>"]),
            "connectors.mail-out.to: Value error, a bare address is required",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(**{"from": "a@x.example\nBcc: e@x"}),
            "connectors.mail-out.from: Value error, line breaks and NUL are not allowed",
        ),
        (
            lambda r: r["admin"].update(listen="0.0.0.0:99999"),
            "admin.listen: Value error, invalid port",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"]["review"].update(
                get_quote="sha256:abc"
            ),
            "gateway.servers.broker-read.remote.review.get_quote: String should match pattern",
        ),
        (
            lambda r: r.update(egress_proxy="https://proxy.example:3128"),
            "egress_proxy: Value error, scheme must be one of: http",
        ),
    ],
)
def test_schema_rejects(example_raw: Raw, mutate: Callable[[Raw], object], expected: str) -> None:
    raw = copy.deepcopy(example_raw)
    mutate(raw)
    found = schema_errors(raw)
    assert any(e.startswith(expected) for e in found), found


def test_yaml_problems_are_policy_errors() -> None:
    with pytest.raises(PolicyError) as info:
        parse_policy("version: 1\nversion: 1\n", "test")
    assert "duplicate key 'version'" in info.value.findings[0].message


def test_yes_is_not_a_boolean(example_raw: Raw) -> None:
    text = yaml.safe_dump(example_raw, sort_keys=False).replace("stream: true", "stream: yes")
    with pytest.raises(PolicyError) as info:
        parse_policy(text, "test")
    assert any(
        "stream: Input should be a valid boolean" in f"{f.path}: {f.message}"
        for f in info.value.findings
    )


# --- check: one change, one finding ---------------------------------------------------------------


def _remote_route_with_placeholder(r: Raw) -> None:
    route(r, "broker-mcp")["callers"] = [{"placeholder": "ph-sandbox-broker-0001"}]


def _connector_route_with_placeholder(r: Raw) -> None:
    route(r, "mail-send")["callers"] = ["gateway", {"placeholder": "ph-sandbox-mail-00001"}]


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            _connector_route_with_placeholder,
            "routes[2].callers: a connector route must accept only the gateway",
        ),
        (
            _remote_route_with_placeholder,
            "routes[1].callers: a route used by a gateway server must accept only the gateway",
        ),
        (
            lambda r: route(r, "stats").update(upstream="http://api.stats.example"),
            "routes[0].upstream: plain http would send the credential in cleartext",
        ),
        (
            lambda r: route(r, "stats").update(
                upstream="http://api.stats.example", allow_insecure_upstream=True
            ),
            "routes[0].upstream: a credential can't be sent over plain http",
        ),
        (
            lambda r: route(r, "stats").update(credential="nope"),
            "routes[0].credential: unknown credential 'nope'",
        ),
        (
            lambda r: route(r, "mail-send").update(connector="nope"),
            "routes[2].connector: unknown connector 'nope'",
        ),
        (
            lambda r: route(r, "mail-send").update(name="stats"),
            "routes[2].name: duplicate route name (also routes[0])",
        ),
        (
            lambda r: route(r, "mail-send").update(prefix="/stats"),
            "routes[2].prefix: duplicate prefix (also routes[0])",
        ),
        (
            lambda r: route(r, "stats")["rules"][0].update(paths=["/2.0/**/x"]),
            "routes[0].rules[0].paths[0]: '/2.0/**/x': '**' is only allowed as the last segment",
        ),
        (
            lambda r: route(r, "stats")["rules"][0].update(params={"doc": ["a"]}),
            "routes[0].rules[0].params.doc: no path in this rule captures {doc}",
        ),
        (
            lambda r: route(r, "stats")["query"].update(strip=["user", "api_key"]),
            "routes[0].query: 'user' is both forced and stripped",
        ),
        (
            lambda r: route(r, "stats")["query"]["force"].update(api_key="x"),
            "routes[0].query.force: 'api_key' carries the credential",
        ),
        (
            lambda r: r["gateway"]["clients"].update(
                agent1={"token": "ph-agent1-stats-4c1f9b27", "servers": ["broker-read"]}
            ),
            "gateway.clients.agent1.token: the same value is used as a placeholder and a client"
            " token",
        ),
        (
            lambda r: r["gateway"]["clients"].update(
                agent2={"token_sha256": AGENT1_HASH, "servers": ["broker-read"]}
            ),
            "gateway.clients.agent2.token_sha256: two clients share a token",
        ),
        (
            lambda r: route(r, "broker-mcp").update(stream=False),
            "gateway.servers.broker-read.route: route 'broker-mcp' must set stream: true for MCP",
        ),
        (
            lambda r: r["gateway"]["clients"]["agent1"]["servers"].append("ghost"),
            "gateway.clients.agent1.servers: unknown server 'ghost'",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"].update(route="ghost"),
            "gateway.servers.broker-read.route: unknown route 'ghost'",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"].update(route="mail-send"),
            "gateway.servers.broker-read.route: points at a connector route",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"]["tools"]["allow"].remove("get_quote"),
            "gateway.servers.broker-read.tools: 'get_quote' is included but in neither allow nor",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-trade"]["tools"].update(
                allow=["place_order"]
            ),
            "gateway.servers.broker-trade.tools: 'place_order' is in both allow and approve",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"]["tools"]["allow"].append("extra"),
            "gateway.servers.broker-read.tools: 'extra' is classified but not in include",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"]["review"].pop("get_quote"),
            "gateway.servers.broker-read.review: 'get_quote' is included but has no review pin",
        ),
        (
            lambda r: r["credentials"]["broker-mcp"].update(
                token_url="http://auth.broker.example/t"
            ),
            "credentials.broker-mcp.token_url: the token endpoint must use https",
        ),
        (
            lambda r: r["credentials"]["broker-mcp"].pop("refresh_token"),
            "credentials.broker-mcp.refresh_token: required for the refresh_token grant",
        ),
        (
            lambda r: r["credentials"]["broker-mcp"].update(grant="client_credentials"),
            "credentials.broker-mcp.client_secret: required for the client_credentials grant",
        ),
        (
            lambda r: r["credentials"]["broker-mcp"]["extra_params"].update(grant_type="password"),
            "credentials.broker-mcp.extra_params.grant_type: set by the vault",
        ),
    ],
)
def test_check_errors(example_raw: Raw, mutate: Callable[[Raw], object], expected: str) -> None:
    raw = copy.deepcopy(example_raw)
    mutate(raw)
    found = errors(run(raw))
    assert any(e.startswith(expected) for e in found), found


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda r: r["credentials"]["music-stats"].update(secret="env:STATS_KEY"),
            "credentials.music-stats.secret: secret read from env var STATS_KEY",
        ),
        (
            lambda r: r["credentials"]["broker-mcp"].update(refresh_token="env:BROKER_SEED"),
            "credentials.broker-mcp.refresh_token: refresh token seeded from env var BROKER_SEED",
        ),
        (
            lambda r: r["credentials"]["broker-mcp"].update(reseed="on-change"),
            "credentials.broker-mcp.reseed: only meaningful for a refresh token seeded from env:",
        ),
        (
            lambda r: r["credentials"].update(spare={"kind": "header", "secret": "store:spare"}),
            "credentials.spare: not used by any route",
        ),
        (
            lambda r: route(r, "stats")["callers"][0].update(placeholder="short"),
            "routes[0].callers[0]: shorter than 16 characters",
        ),
        (
            lambda r: route(r, "stats")["rules"][0].update(paths=["/2.0/{method}"]),
            "routes[0].rules[0].paths: {method} has no constraint in params",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-read"]["review"].update(
                other="sha256:" + "0" * 64
            ),
            "gateway.servers.broker-read.review: pin for 'other', which isn't included",
        ),
    ],
)
def test_check_warnings(example_raw: Raw, mutate: Callable[[Raw], object], expected: str) -> None:
    raw = copy.deepcopy(example_raw)
    mutate(raw)
    findings = run(raw)
    assert errors(findings) == []
    found = warnings(findings)
    assert any(w.startswith(expected) for w in found), found


def test_placeholder_location(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "stats")["callers"][0]["header"] = "X-Api-Key"
    assert errors(run(raw)) == []
    route(raw, "stats")["callers"][0]["header"] = "Authorization"
    assert any("'Authorization' is reserved" in e for e in errors(run(raw)))
    route(raw, "stats")["callers"][0]["header"] = "X-ZoeyMCP-Gateway"
    assert any("is reserved" in e for e in errors(run(raw)))
    route(raw, "stats")["callers"][0].update(header="X-Api-Key", query="api_key")
    assert any("not both" in e for e in schema_errors(raw))


def test_resolve_env(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["credentials"]["music-stats"]["secret"] = "env:STATS_KEY"
    assert errors(run(raw, environ={})) == [
        "credentials.music-stats.secret: env var STATS_KEY is not set"
    ]
    assert errors(run(raw, environ={"STATS_KEY": "x"})) == []
    assert errors(run(raw)) == []


def test_toolkit_tools_need_no_classification(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"]["tools"] = {"include": ["send_note"]}
    assert errors(run(raw)) == []


# --- OAuth: schema ----------------------------------------------------------------------------

AUTHORIZE = "https://auth.example/authorize"
LIVE_HINT = (
    "the live token is kept in the store as oauth.o.live, and {effect}; "
    "zoeymcp secret delete oauth.o.live forces a re-seed"
)


def oauth(**fields: Any) -> Raw:
    """A refresh-grant credential that passes ``check`` apart from the login warning."""
    return {
        "kind": "oauth2",
        "token_url": "https://auth.example/token",
        "client_id": "client-1",
        "refresh_token": "store:o-seed",
        "rotates": True,
        **fields,
    }


def client_credentials(**fields: Any) -> Raw:
    defaults = {"grant": "client_credentials", "client_secret": "store:o-secret"}
    return oauth(**{**defaults, "refresh_token": None, "rotates": False, **fields})


def _smtp(password: str) -> Raw:
    return {
        "kind": "smtp",
        "host": "smtp.example",
        "port": 465,
        "username": "u",
        "password": password,
        "from": "a@mail.example",
        "to": ["b@mail.example"],
    }


def oauth_policy(
    credentials: dict[str, Raw],
    *,
    connectors: Raw | None = None,
    unrouted: tuple[str, ...] = (),
    upstream: str = "https://api.example",
) -> Raw:
    creds = {n: {k: v for k, v in c.items() if v is not None} for n, c in credentials.items()}
    routes = [
        {
            "name": f"r{i}",
            "prefix": f"/r{i}",
            "upstream": upstream,
            "credential": name,
            "callers": [{"placeholder": f"ph-route-{i}-0123456789"}],
            "rules": [{"methods": ["GET"], "paths": ["/x"]}],
        }
        for i, name in enumerate(creds)
        if name not in unrouted
    ]
    return {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
        "credentials": creds,
        "connectors": connectors or {},
        "routes": routes,
    }


def found(raw: Raw, environ: dict[str, str] | None = None) -> list[str]:
    return [f"{f.level} {f.path}: {f.message}" for f in run(raw, environ)]


def found_for(cred: Raw, environ: dict[str, str] | None = None) -> list[str]:
    return found(oauth_policy({"o": cred}), environ)


def schema_error_for(cred: Raw) -> list[str]:
    raw = oauth_policy({"o": cred})
    return [e.removeprefix("credentials.o.oauth2") for e in schema_errors(raw)]


def parsed(cred: Raw) -> OAuth2Credential:
    policy = parse_policy(yaml.safe_dump(oauth_policy({"o": cred})), "test")
    result = policy.credentials["o"]
    assert isinstance(result, OAuth2Credential)
    return result


def test_oauth_defaults() -> None:
    cred = parsed(oauth())
    assert cred.client_auth is None
    assert cred.token_body == "form"
    assert cred.token_headers == {}
    assert cred.scope_separator == " "
    assert cred.default_expires_in == 3600
    assert cred.grant_lifetime_days is None
    assert cred.authorize_url is None
    assert cred.authorize_params == {}
    assert cred.redirect_uri == "http://127.0.0.1/callback"
    assert cred.issuer is None


def test_effective_client_auth() -> None:
    assert parsed(oauth()).effective_client_auth == "none"
    assert parsed(oauth(client_secret="store:s")).effective_client_auth == "basic"
    assert parsed(oauth(client_secret="store:s", client_auth="post")).effective_client_auth == (
        "post"
    )
    assert parsed(oauth(client_auth="none")).effective_client_auth == "none"


def test_effective_expected_scopes() -> None:
    assert parsed(oauth()).effective_expected_scopes == []
    assert parsed(oauth(scope="a b")).effective_expected_scopes == ["a", "b"]
    assert parsed(oauth(scope="a,b", scope_separator=",")).effective_expected_scopes == [
        "a",
        "b",
    ]
    assert parsed(oauth(scope="a b", expected_scopes=["c"])).effective_expected_scopes == ["c"]


def test_scope_and_param_helpers() -> None:
    assert split_scope(None, " ") == []
    assert split_scope("a b", " ") == ["a", "b"]
    assert split_scope("a b", ",") == ["a b"]
    assert param_values("x") == ["x"]
    assert param_values(["x", "y"]) == ["x", "y"]


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"client_auth": "basic"}, ": Value error, client_auth basic needs a client_secret"),
        ({"client_auth": "post"}, ": Value error, client_auth post needs a client_secret"),
        (
            {"client_auth": "none", "client_secret": "store:s"},
            ": Value error, client_auth none takes no client_secret",
        ),
        ({"client_auth": "jwt"}, ".client_auth: Input should be 'basic', 'post' or 'none'"),
        ({"token_body": "xml"}, ".token_body: Input should be 'form' or 'json'"),
        ({"scope_separator": ";"}, ".scope_separator: Input should be ' ' or ','"),
        ({"default_expires_in": 59}, ".default_expires_in: Input should be greater than"),
        ({"default_expires_in": 86401}, ".default_expires_in: Input should be less than"),
        ({"grant_lifetime_days": 0}, ".grant_lifetime_days: Input should be greater than"),
        ({"grant_lifetime_days": 3651}, ".grant_lifetime_days: Input should be less than"),
        (
            {"extra_params": {"resource": []}},
            ".extra_params.resource.list[constrained-str]: List should",
        ),
        (
            {"extra_params": {"resource": [f"urn:x:{i}" for i in range(11)]}},
            ".extra_params.resource.list[constrained-str]: List should have at most 10 items",
        ),
        (
            {"extra_params": {"a": "x" * 2049}},
            ".extra_params.a.constrained-str: String should have at most",
        ),
        ({"extra_params": {"a": "x\ny"}}, ".extra_params: Value error, line breaks and NUL"),
        ({"extra_params": {"a": ["ok", "x\ry"]}}, ".extra_params: Value error, line breaks"),
        ({"authorize_params": {"a": "x\x00"}}, ".authorize_params: Value error, line breaks"),
        ({"token_headers": {"X-A": "x\ny"}}, ".token_headers: Value error, line breaks"),
        ({"token_headers": {"X-A": ""}}, ".token_headers.X-A: String should have at least 1"),
        ({"token_headers": {"X-A": "x" * 257}}, ".token_headers.X-A: String should have at most"),
        ({"token_headers": {"X A": "x"}}, ".token_headers.X A.[key]: String should match"),
        ({"authorize_url": "ftp://auth.example/a"}, ".authorize_url: Value error, scheme must"),
        ({"authorize_url": AUTHORIZE + "?a=b"}, ".authorize_url: Value error, query strings"),
        ({"issuer": "https://u:p@auth.example"}, ".issuer: Value error, credentials in URLs"),
        ({"issuer": "https://auth.example/#f"}, ".issuer: Value error, query strings"),
    ],
)
def test_oauth_schema_rejects(fields: Raw, expected: str) -> None:
    found_errors = schema_error_for(oauth(**fields))
    assert any(e.startswith(expected) for e in found_errors), found_errors


def test_oauth_schema_accepts_the_edges() -> None:
    cred = parsed(
        oauth(
            client_secret="store:s",
            client_auth="post",
            default_expires_in=60,
            grant_lifetime_days=1,
            extra_params={"resource": [f"urn:x:{i}" for i in range(10)], "a": "x" * 2048},
            token_headers={"X-A": "x" * 256},
            authorize_url=AUTHORIZE,
            issuer="https://auth.example",
        )
    )
    assert cred.extra_params["resource"] == [f"urn:x:{i}" for i in range(10)]
    assert parsed(oauth(default_expires_in=86400, grant_lifetime_days=3650)).default_expires_in
    assert parsed(oauth(client_secret="store:s", client_auth="basic")).client_auth == "basic"


@pytest.mark.parametrize(
    "uri",
    [
        "http://127.0.0.1/callback",
        "http://127.0.0.1:8976/callback",
        "http://127.0.0.2/cb",
        "http://[::1]/callback",
        "http://127.0.0.1",
        "https://portal.example/oauth/callback",
    ],
)
def test_redirect_uri_accepts(uri: str) -> None:
    assert parsed(oauth(redirect_uri=uri)).redirect_uri == uri


@pytest.mark.parametrize(
    ("uri", "expected"),
    [
        (
            "http://localhost/callback",
            "use 127.0.0.1; RFC 8252 section 8.3 and some providers refuse localhost",
        ),
        ("https://LOCALHOST/callback", "use 127.0.0.1"),
        ("https://localhost./cb", "use 127.0.0.1"),
        ("https://app.localhost/cb", "use 127.0.0.1"),
        ("https://app.localhost./cb", "use 127.0.0.1"),
        (
            "http://portal.example/callback",
            "http is only allowed with a loopback IP address like 127.0.0.1",
        ),
        ("http://10.0.0.1/callback", "http is only allowed with a loopback IP address"),
        ("http://127.0.0.1/callback?a=b", "query strings and fragments are not allowed"),
        ("http://127.0.0.1/callback#f", "query strings and fragments are not allowed"),
        ("http://u@127.0.0.1/callback", "credentials in URLs are not allowed"),
        ("ftp://127.0.0.1/callback", "scheme must be one of: https, http"),
        ("http://127.0.0.1:99999/callback", "invalid port"),
    ],
)
def test_redirect_uri_rejects(uri: str, expected: str) -> None:
    found_errors = schema_error_for(oauth(redirect_uri=uri))
    assert any(e.startswith(f".redirect_uri: Value error, {expected}") for e in found_errors)


@pytest.mark.parametrize(
    ("scope", "separator"),
    [
        ("read", " "),
        ("openid https://scopes.example/calendar.readonly", " "),
        ("a,b", ","),
        ("!#[]~", " "),
        ("x" * 256, " "),
        (" ".join(f"s{i}" for i in range(64)), " "),
    ],
)
def test_scope_accepts(scope: str, separator: str) -> None:
    assert parsed(oauth(scope=scope, scope_separator=separator)).scope == scope


@pytest.mark.parametrize(
    ("scope", "separator", "bad"),
    [
        ("a  b", " ", "''"),
        (" a", " ", "''"),
        ("", " ", "''"),
        ("a b", ",", "'a b'"),
        ('a"b', " ", "'a\"b'"),
        ("a\\b", " ", "'a\\\\b'"),
        ("a\tb", " ", "'a\\tb'"),
        ("a\x7fb", " ", "'a\\x7fb'"),
        ("\u00e9t\u00e9", " ", "'\u00e9t\u00e9'"),
        ("x" * 257, " ", "'" + "x" * 257 + "'"),
    ],
)
def test_scope_rejects_tokens(scope: str, separator: str, bad: str) -> None:
    expected = (
        f".scope: Value error, invalid scope {bad}: 1 to 256 printable ASCII characters, "
        "without spaces, quotes or backslashes, separated by one scope_separator"
    )
    assert expected in schema_error_for(oauth(scope=scope, scope_separator=separator))


def test_scope_count_limit() -> None:
    scope = " ".join(f"s{i}" for i in range(65))
    assert schema_error_for(oauth(scope=scope)) == [".scope: Value error, at most 64 scopes"]


def test_scope_check_survives_a_bad_separator() -> None:
    # The separator error is reported; the scope is checked with the default separator.
    assert schema_error_for(oauth(scope="a b", scope_separator=";")) == [
        ".scope_separator: Input should be ' ' or ','"
    ]
    # Only splitting on whitespace would accept this one.
    assert schema_error_for(oauth(scope="a\tb", scope_separator=";")) == [
        ".scope: Value error, invalid scope 'a\\tb': 1 to 256 printable ASCII characters, "
        "without spaces, quotes or backslashes, separated by one scope_separator",
        ".scope_separator: Input should be ' ' or ','",
    ]


# --- OAuth: check ------------------------------------------------------------------------------


def test_complete_oauth_credentials_are_clean() -> None:
    assert found_for(oauth(authorize_url=AUTHORIZE, scope="read")) == []
    assert found_for(client_credentials()) == []


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        (
            {"authorize_url": "http://auth.example/authorize", "scope": "a"},
            "error credentials.o.authorize_url: the authorization endpoint must use https",
        ),
        (
            {"issuer": "http://auth.example"},
            "error credentials.o.issuer: the issuer must use https",
        ),
        (
            {"client_id": "store:o-client", "authorize_url": AUTHORIZE, "scope": "a"},
            "error credentials.o.client_id: client IDs are public and appear in the "
            "authorization URL; write it in the policy",
        ),
    ],
)
def test_oauth_check_errors(fields: Raw, expected: str) -> None:
    assert expected in found_for(oauth(**fields))


def test_https_endpoints_and_literal_client_ids_pass() -> None:
    cred = oauth(issuer="https://auth.example", authorize_url=AUTHORIZE, scope="a")
    assert errors(run(oauth_policy({"o": cred}))) == []
    # A client ID ref is fine when nothing prints it in an authorization URL.
    assert errors(run(oauth_policy({"o": oauth(client_id="store:o-client")}))) == []


def test_client_credentials_rules() -> None:
    assert found_for(client_credentials(authorize_url=AUTHORIZE, scope="a")) == [
        "error credentials.o.authorize_url: not used by the client_credentials grant"
    ]
    assert found_for(client_credentials(grant_lifetime_days=30)) == [
        "warning credentials.o.grant_lifetime_days: not used by the client_credentials grant"
    ]
    assert found_for(client_credentials(client_auth="post")) == []
    assert found_for(client_credentials(client_secret=None, client_auth="none")) == [
        "error credentials.o.client_auth: none can't be used with the client_credentials grant",
        "error credentials.o.client_secret: required for the client_credentials grant",
    ]
    assert found_for(client_credentials(rotates=True)) == [
        "error credentials.o.rotates: client_credentials tokens don't rotate"
    ]
    assert found_for(client_credentials(refresh_token="store:o-seed")) == [
        "error credentials.o.refresh_token: not used by the client_credentials grant"
    ]


@pytest.mark.parametrize(
    "param",
    [
        "grant_type",
        "refresh_token",
        "client_id",
        "client_secret",
        "code",
        "code_verifier",
        "redirect_uri",
        "client_assertion",
        "client_assertion_type",
        "Grant_Type",
    ],
)
def test_reserved_token_params(param: str) -> None:
    assert found_for(oauth(extra_params={param: "x"})) == [
        "warning credentials.o.authorize_url: zoeymcp login can't run; enter the refresh token "
        "with secret set or seed it from env:",
        f"error credentials.o.extra_params.{param}: set by the vault; can't be overridden",
    ]


@pytest.mark.parametrize(
    "param",
    [
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "code_verifier",
        "client_secret",
        "Response_Type",
    ],
)
def test_reserved_authorize_params(param: str) -> None:
    cred = oauth(authorize_url=AUTHORIZE, scope="a", authorize_params={param: "x"})
    assert found_for(cred) == [
        f"error credentials.o.authorize_params.{param}: set by the vault; can't be overridden"
    ]


@pytest.mark.parametrize("param", ["request", "request_uri", "Request"])
def test_request_objects_are_refused(param: str) -> None:
    cred = oauth(authorize_url=AUTHORIZE, scope="a", authorize_params={param: "x"})
    assert found_for(cred) == [
        f"error credentials.o.authorize_params.{param}: request objects aren't supported; "
        "one could carry a different redirect_uri"
    ]


@pytest.mark.parametrize("param", ["scope", "Scope"])
def test_scope_goes_in_the_scope_field(param: str) -> None:
    cred = oauth(
        authorize_url=AUTHORIZE,
        scope="a",
        extra_params={param: "a"},
        authorize_params={param: "a"},
    )
    assert found_for(cred) == [
        f"error credentials.o.authorize_params.{param}: use the scope field",
        f"error credentials.o.extra_params.{param}: use the scope field",
    ]


def test_free_params_and_headers_pass() -> None:
    cred = oauth(
        authorize_url=AUTHORIZE,
        scope="a",
        extra_params={"audience": "api"},
        authorize_params={"access_type": "offline", "prompt": "consent"},
        token_headers={"Api-Version": "2024-01-01", "X-Zoey": "1", "X-ZoeyMCPish": "1"},
    )
    assert found_for(cred) == []


@pytest.mark.parametrize(
    "header",
    [
        "authorization",
        "Content-Type",
        "content-length",
        "Host",
        "accept",
        "cookie",
        "Transfer-Encoding",
        "X-ZoeyMCP-Caller",
    ],
)
def test_reserved_token_headers(header: str) -> None:
    cred = oauth(authorize_url=AUTHORIZE, scope="a", token_headers={header: "x"})
    assert found_for(cred) == [
        f"error credentials.o.token_headers.{header}: {header!r} is set by the vault"
    ]


@pytest.mark.parametrize(
    "value",
    [
        "/relative",
        "api.example",
        "https://api.example/#frag",
        "https://api.example/a b",
        "1https://api.example/",
        "https:",
        "urn:x:\x01",
    ],
)
def test_resources_must_be_absolute_uris(value: str) -> None:
    cred = oauth(
        authorize_url=AUTHORIZE,
        scope="a",
        extra_params={"resource": ["urn:example:api", value]},
        authorize_params={"resource": value},
    )
    message = f"{value!r} must be an absolute URI without a fragment (RFC 8707)"
    result = found_for(cred)
    assert f"error credentials.o.extra_params.resource: {message}" in result
    assert f"error credentials.o.authorize_params.resource: {message}" in result
    assert sum(f.startswith("error") for f in result) == 2


def test_resources_in_any_scheme_need_no_route() -> None:
    cred = oauth(
        authorize_url=AUTHORIZE,
        scope="a",
        extra_params={"resource": "urn:example:api"},
        authorize_params={"resource": "urn:example:api"},
    )
    assert found_for(cred) == []


@pytest.mark.parametrize(
    ("resource", "expected"),
    [
        ("https://api.example/mcp", []),
        ("https://API.example:443/", []),
        (
            "https://other.example/",
            ["'https://other.example/' isn't the origin of a route that uses this credential"],
        ),
        (
            "https://api.example:8443/",
            ["'https://api.example:8443/' isn't the origin of a route that uses this credential"],
        ),
        (
            "https://api.example:99999/",
            ["'https://api.example:99999/' isn't the origin of a route that uses this credential"],
        ),
        (
            "http://api.example/",
            [
                "'http://api.example/' isn't the origin of a route that uses this credential",
                "'http://api.example/' uses plain http",
            ],
        ),
    ],
)
def test_resource_origins(resource: str, expected: list[str]) -> None:
    cred = oauth(extra_params={"resource": ["urn:example:api", resource]})
    result = found_for(cred)
    assert [r for r in result if ".extra_params.resource" in r] == [
        f"warning credentials.o.extra_params.resource: {e}" for e in expected
    ]
    assert errors(run(oauth_policy({"o": cred}))) == []


def test_resource_on_the_authorization_request_too() -> None:
    hint = (
        "warning credentials.o.extra_params.resource: RFC 8707: send it on the authorization "
        "request too"
    )
    resource = {"resource": "https://api.example/"}
    assert hint in found_for(oauth(authorize_url=AUTHORIZE, scope="a", extra_params=resource))
    both = oauth(
        authorize_url=AUTHORIZE, scope="a", extra_params=resource, authorize_params={**resource}
    )
    assert found_for(both) == []
    assert hint not in found_for(oauth(extra_params=resource))


def test_refresh_grant_warnings() -> None:
    login = (
        "warning credentials.o.authorize_url: zoeymcp login can't run; enter the refresh token "
        "with secret set or seed it from env:"
    )
    rotates = (
        "warning credentials.o.rotates: public clients' refresh tokens usually rotate "
        "(RFC 9700 section 2.2.2); set rotates: true"
    )
    assert found_for(oauth()) == [login]
    assert found_for(oauth(rotates=False)) == [login, rotates]
    assert found_for(oauth(rotates=False, client_auth="none")) == [login, rotates]
    assert found_for(oauth(rotates=False, client_secret="store:s")) == [login]


def test_scope_warnings() -> None:
    unchecked = "warning credentials.o.expected_scopes: granted scopes can't be checked"
    assert found_for(oauth(authorize_url=AUTHORIZE)) == [unchecked]
    assert found_for(oauth(authorize_url=AUTHORIZE, expected_scopes=["a"])) == []
    assert found_for(oauth(authorize_url=AUTHORIZE, scope="a")) == []
    cred = oauth(authorize_url=AUTHORIZE, scope="a b,c d", expected_scopes=["a", "d"])
    assert found_for(cred) == [
        "warning credentials.o.scope: requested scope 'b,c' isn't in expected_scopes"
    ]
    cred = oauth(authorize_url=AUTHORIZE, scope="a,b", scope_separator=",", expected_scopes=["a"])
    assert found_for(cred) == [
        "warning credentials.o.scope: requested scope 'b' isn't in expected_scopes"
    ]


def test_reseed_warnings() -> None:
    only_env = "warning credentials.o.reseed: only meaningful for a refresh token seeded from env:"
    rolled_back = (
        "warning credentials.o.reseed: a changed or rolled-back env value replaces the live "
        "token; an old rotating seed is dead, and presenting it may revoke the grant"
    )
    store_seed = oauth(authorize_url=AUTHORIZE, scope="a", reseed="on-change")
    assert found_for(store_seed) == [only_env]
    assert only_env in found_for(client_credentials(reseed="on-change"))
    env_seed = oauth(authorize_url=AUTHORIZE, scope="a", refresh_token="env:SEED")
    assert rolled_back in found_for({**env_seed, "reseed": "on-change"})
    assert only_env not in found_for({**env_seed, "reseed": "on-change"})
    assert rolled_back not in found_for(env_seed)
    assert rolled_back not in found_for({**env_seed, "reseed": "on-change", "rotates": False})


def test_unused_oauth_credentials_explain_why() -> None:
    raw = oauth_policy(
        {
            "o": oauth(authorize_url=AUTHORIZE, scope="a"),
            "k": {"kind": "header", "secret": "store:k"},
        },
        unrouted=("o", "k"),
    )
    assert found(raw) == [
        "warning credentials.k: not used by any route",
        "warning credentials.o: not used by any route: login and refresh will refuse; access "
        "tokens would have no resource origins",
    ]


def test_env_seed_messages() -> None:
    cred = oauth(authorize_url=AUTHORIZE, scope="a", refresh_token="env:SEED")
    path = "warning credentials.o.refresh_token"
    never = LIVE_HINT.format(effect="a changed env value is ignored (reseed: never)")
    assert found_for(cred, environ={"SEED": "x"}) == [
        f"{path}: refresh token seeded from env var SEED: {never}"
    ]
    # N1: the seed may be removed once the live token is in the store.
    assert found_for(cred, environ={}) == [
        f"{path}: refresh token seeded from env var SEED: {never}",
        f"{path}: seed env var SEED is not set; the vault uses the live token in the store, "
        "if there is one",
    ]


def test_unset_oauth_secrets_are_still_errors() -> None:
    cred = client_credentials(client_secret="env:CLIENT_SECRET")
    assert "error credentials.o.client_secret: env var CLIENT_SECRET is not set" in found_for(
        cred, environ={}
    )
    assert errors(run(oauth_policy({"o": cred}), environ={"CLIENT_SECRET": "x"})) == []


@pytest.mark.parametrize(
    ("credentials", "connectors", "path"),
    [
        ({"o": oauth(refresh_token="store:oauth.o.live")}, None, "credentials.o.refresh_token"),
        (
            {"o": client_credentials(client_secret="store:oauth.x")},
            None,
            "credentials.o.client_secret",
        ),
        ({"k": {"kind": "header", "secret": "store:oauth.k"}}, None, "credentials.k.secret"),
        (
            {"o": client_credentials()},
            {"m": _smtp("store:oauth.m")},
            "connectors.m.password",
        ),
    ],
)
def test_vault_prefix_is_reserved(
    credentials: dict[str, Raw], connectors: Raw | None, path: str
) -> None:
    raw = oauth_policy(credentials, connectors=connectors)
    assert (
        f"error {path}: the store:oauth. prefix is reserved for entries the vault manages"
        in found(raw)
    )


def test_vault_prefix_needs_the_dot() -> None:
    raw = oauth_policy(
        {"o": oauth(refresh_token="store:oauth"), "p": oauth(refresh_token="store:oauthy.x")}
    )
    assert errors(run(raw)) == []


def test_refresh_tokens_are_not_shared() -> None:
    raw = oauth_policy({"a": oauth(), "b": oauth(), "c": oauth(refresh_token="store:c-seed")})
    message = (
        "store:o-seed is the refresh token of credentials.a.refresh_token, "
        "credentials.b.refresh_token; they would rotate it out from under each other"
    )
    assert errors(run(raw)) == [
        f"credentials.a.refresh_token: {message}",
        f"credentials.b.refresh_token: {message}",
    ]


def test_a_refresh_token_has_no_other_oauth_use() -> None:
    raw = oauth_policy({"o": oauth(refresh_token="store:s", client_secret="store:s")})
    message = (
        "store:s is the refresh token of credentials.o.refresh_token and is also used by "
        "credentials.o.client_secret; rotation would overwrite it"
    )
    assert errors(run(raw)) == [
        f"credentials.o.client_secret: {message}",
        f"credentials.o.refresh_token: {message}",
    ]


def test_a_refresh_token_is_not_another_credentials_secret() -> None:
    raw = oauth_policy(
        {
            "a": oauth(refresh_token="store:shared"),
            "b": client_credentials(client_secret="store:shared"),
            "c": client_credentials(client_id="store:shared"),
        }
    )
    message = (
        "store:shared is the refresh token of credentials.a.refresh_token and is also used by "
        "credentials.b.client_secret, credentials.c.client_id; rotation would overwrite it"
    )
    assert errors(run(raw)) == [
        f"credentials.a.refresh_token: {message}",
        f"credentials.b.client_secret: {message}",
        f"credentials.c.client_id: {message}",
    ]


def test_shared_refresh_tokens_with_another_use() -> None:
    raw = oauth_policy(
        {"a": oauth(), "b": oauth(), "c": client_credentials(client_secret="store:o-seed")}
    )
    shared = (
        "store:o-seed is the refresh token of credentials.a.refresh_token, "
        "credentials.b.refresh_token"
    )
    rotate = f"{shared}; they would rotate it out from under each other"
    overwrite = (
        f"{shared} and is also used by credentials.c.client_secret; rotation would overwrite it"
    )
    assert errors(run(raw)) == [
        f"credentials.a.refresh_token: {overwrite}",
        f"credentials.a.refresh_token: {rotate}",
        f"credentials.b.refresh_token: {overwrite}",
        f"credentials.b.refresh_token: {rotate}",
        f"credentials.c.client_secret: {overwrite}",
    ]


def test_an_oauth_secret_goes_to_one_token_endpoint() -> None:
    other = "https://other.example/token"
    raw = oauth_policy(
        {
            "a": client_credentials(client_secret="store:cs"),
            "b": client_credentials(client_secret="store:cs", token_url=other),
            "c": client_credentials(client_secret="store:c"),
        }
    )
    message = (
        "store:cs would be sent to the token endpoints https://auth.example:443, "
        "https://other.example:443; an OAuth secret is bound to one"
    )
    assert errors(run(raw)) == [
        f"credentials.a.client_secret: {message}",
        f"credentials.b.client_secret: {message}",
    ]


def test_one_token_origin_may_have_several_endpoints() -> None:
    raw = oauth_policy(
        {
            "a": client_credentials(client_secret="store:cs"),
            "b": client_credentials(
                client_secret="store:cs", token_url="https://AUTH.example:443/v2/token"
            ),
        }
    )
    assert errors(run(raw)) == []


def test_client_secrets_may_be_shared_between_oauth_credentials() -> None:
    raw = oauth_policy(
        {
            "a": client_credentials(client_id="store:client"),
            "b": client_credentials(client_id="store:client"),
        }
    )
    assert errors(run(raw)) == []


def test_oauth_secrets_are_not_static_secrets() -> None:
    raw = oauth_policy(
        {
            "a": client_credentials(client_secret="store:a-secret"),
            "o": client_credentials(),
            "k": {"kind": "header", "secret": "store:o-secret"},
        }
    )
    assert errors(run(raw)) == [
        "credentials.k.secret: store:o-secret is an OAuth secret of "
        "credentials.o.client_secret; it must never be injectable as a static secret",
        "credentials.o.client_secret: store:o-secret is also used by credentials.k.secret; "
        "an OAuth secret must never be injectable as a static secret",
    ]


def test_oauth_refs_shared_by_several_users() -> None:
    raw = oauth_policy(
        {
            "a": client_credentials(client_secret="store:shared"),
            "b": client_credentials(client_secret="store:shared"),
            "k1": {"kind": "header", "secret": "store:shared"},
            "k2": {"kind": "header", "secret": "store:shared"},
        }
    )
    also = (
        "store:shared is also used by credentials.k1.secret, credentials.k2.secret; "
        "an OAuth secret must never be injectable as a static secret"
    )
    oauth_of = (
        "store:shared is an OAuth secret of credentials.a.client_secret, "
        "credentials.b.client_secret; it must never be injectable as a static secret"
    )
    assert errors(run(raw)) == [
        f"credentials.a.client_secret: {also}",
        f"credentials.b.client_secret: {also}",
        f"credentials.k1.secret: {oauth_of}",
        f"credentials.k2.secret: {oauth_of}",
    ]


def test_oauth_refs_shared_with_connectors_and_basic_users() -> None:
    # The connector shares its name with the credential; only the path tells them apart.
    raw = oauth_policy(
        {
            "o": oauth(client_id="store:o-client"),
            "b": {"kind": "basic", "username": "store:o-client", "secret": "store:b"},
        },
        connectors={"o": _smtp("store:o-seed")},
    )
    assert errors(run(raw)) == [
        "connectors.o.password: store:o-seed is an OAuth secret of "
        "credentials.o.refresh_token; it must never be injectable as a static secret",
        "credentials.b.username: store:o-client is an OAuth secret of credentials.o.client_id; "
        "it must never be injectable as a static secret",
        "credentials.o.client_id: store:o-client is also used by credentials.b.username; "
        "an OAuth secret must never be injectable as a static secret",
        "credentials.o.refresh_token: store:o-seed is also used by connectors.o.password; "
        "an OAuth secret must never be injectable as a static secret",
    ]


def test_resource_origins_are_this_credentials_routes() -> None:
    cred = oauth(extra_params={"resource": "https://b.example/"})
    raw = oauth_policy({"a": cred, "b": oauth(refresh_token="store:b-seed")})
    raw["routes"][1]["upstream"] = "https://b.example"
    assert [w for w in warnings(run(raw)) if ".extra_params.resource" in w] == [
        "credentials.a.extra_params.resource: 'https://b.example/' isn't the origin "
        "of a route that uses this credential"
    ]


def test_resource_origins_on_plain_http() -> None:
    cred = oauth(extra_params={"resource": "http://api.example:80/"})
    raw = oauth_policy({"o": cred}, upstream="http://api.example")
    assert [w for w in warnings(run(raw)) if ".extra_params.resource" in w] == [
        "credentials.o.extra_params.resource: 'http://api.example:80/' uses plain http"
    ]


# --- gateway: clients and tokens --------------------------------------------------------------


def listed(raw: Raw, environ: dict[str, str] | None = None) -> list[str]:
    """Every finding, as ``level path: message``."""
    return found(raw, environ)


def literal_client(raw: Raw, token: str) -> None:
    raw["gateway"]["clients"]["agent1"] = {"token": token, "servers": ["broker-read"]}


def test_hash_token() -> None:
    assert hash_token("abc") == (
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_a_client_takes_its_token_in_one_form(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    agent1 = raw["gateway"]["clients"]["agent1"]
    agent1["token"] = "ph-agent1-gw-8e2d6a51c3b7"
    both = "gateway.clients.agent1: Value error, set exactly one of token and token_sha256"
    assert both in schema_errors(raw)
    agent1.pop("token")
    agent1.pop("token_sha256")
    assert both in schema_errors(raw)


def test_token_hash_of_either_form() -> None:
    hashed = Client(token_sha256=AGENT1_HASH)
    assert hashed.token_hash == AGENT1_HASH
    literal = Client(token="abc")
    assert literal.token_hash == hash_token("abc")


@pytest.mark.parametrize(
    "value",
    [
        "sha256:" + "A" * 64,
        "sha256:" + "0" * 63,
        "sha256:" + "0" * 65,
        "sha512:" + "0" * 64,
        "0" * 64,
    ],
)
def test_token_sha256_format(example_raw: Raw, value: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent1"]["token_sha256"] = value
    assert any(
        e.startswith("gateway.clients.agent1.token_sha256: String should match pattern")
        for e in schema_errors(raw)
    )


def test_literal_tokens_warn(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    literal_client(raw, "ph-agent1-gw-8e2d6a51c3b7")
    found = listed(raw)
    assert (
        "warning gateway.clients.agent1.token: anyone who reads the policy can act as this "
        "client; use token_sha256 (zoeymcp client-token)"
    ) in found
    assert not any(f.startswith("error") for f in found), found
    assert not any("anyone who reads" in f for f in listed(example_raw))


def test_short_literal_tokens_warn_but_hashes_have_no_length(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    literal_client(raw, "p" * 15)
    assert (
        "warning gateway.clients.agent1.token: shorter than 16 characters, so easy to guess"
        in listed(raw)
    )
    literal_client(raw, "p" * 16)
    assert not any("easy to guess" in f for f in listed(raw))
    assert not any("easy to guess" in f for f in listed(example_raw))


def test_two_clients_with_one_hash(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent2"] = {"token_sha256": AGENT1_HASH, "servers": ["mail"]}
    found = errors(run(raw))
    assert "gateway.clients.agent1.token_sha256: two clients share a token" in found
    assert "gateway.clients.agent2.token_sha256: two clients share a token" in found
    raw["gateway"]["clients"]["agent2"]["token_sha256"] = "sha256:" + "0" * 64
    assert errors(run(raw)) == []


def test_a_literal_token_matching_another_clients_hash(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    token = "zgc1-a-literal-token-for-agent2"
    raw["gateway"]["clients"]["agent1"]["token_sha256"] = hash_token(token)
    raw["gateway"]["clients"]["agent2"] = {"token": token, "servers": ["mail"]}
    found = errors(run(raw))
    assert found == [
        "gateway.clients.agent1.token_sha256: two clients share a token",
        "gateway.clients.agent2.token: two clients share a token",
    ]
    raw["gateway"]["clients"]["agent2"]["token"] = token + "x"
    assert errors(run(raw)) == []


def test_two_clients_with_one_literal_token(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    literal_client(raw, "ph-agent1-gw-8e2d6a51c3b7")
    raw["gateway"]["clients"]["agent2"] = {"token": "ph-agent1-gw-8e2d6a51c3b7"}
    found = errors(run(raw))
    assert "gateway.clients.agent1.token: two clients share a token" in found
    assert "gateway.clients.agent2.token: two clients share a token" in found


def test_a_placeholder_whose_hash_is_a_client_token(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent1"]["token_sha256"] = hash_token("ph-agent1-stats-4c1f9b27")
    assert errors(run(raw)) == [
        "gateway.clients.agent1.token_sha256: the same value is used as a placeholder and a "
        "client token",
        "routes[0].callers[0]: the same value is used as a placeholder and a client token",
    ]
    # Another placeholder clears the error.
    route(raw, "stats")["callers"][0]["placeholder"] = "x" * 16
    assert errors(run(raw)) == []
    # Placeholders are compared by their hash, not as text: the hex digest itself is no match.
    digest = hash_token("ph-agent1-stats-4c1f9b27").removeprefix("sha256:")
    route(raw, "stats")["callers"][0]["placeholder"] = digest
    assert errors(run(raw)) == []


def test_clients_without_servers_warn(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent1"]["servers"] = []
    found = listed(raw)
    assert "warning gateway.clients.agent1.servers: no servers: this client reaches nothing" in (
        found
    )
    assert not any("reaches nothing" in f for f in listed(example_raw))


def test_servers_this_version_does_not_serve(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["bridge1"] = {"kind": "bridge", "url": "https://bridge.example"}
    raw["gateway"]["clients"]["agent1"]["servers"] = ["broker-read", "mail", "bridge1"]
    found = [f for f in listed(raw) if f.startswith("warning gateway.clients.agent1")]
    assert found == [
        "warning gateway.clients.agent1.servers: 'bridge1' is a bridge server: "
        "not served by this version",
        "warning gateway.clients.agent1.servers: 'mail' is a toolkit server: "
        "not served by this version",
    ]


def test_unassigned_servers_warn(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent1"]["servers"] = ["broker-read", "mail"]
    found = [f for f in listed(raw) if "assigned" in f]
    assert found == ["warning gateway.servers.broker-trade: not assigned to any client"]
    assert not any("assigned" in f for f in listed(example_raw))


def test_any_client_assigns_a_server(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent1"]["servers"] = ["broker-read", "mail"]
    raw["gateway"]["clients"]["agent2"] = {
        "token_sha256": "sha256:" + "0" * 64,
        "servers": ["broker-trade"],
        "approvals": {"attended": True},  # its approve tools would draw their own warning
    }
    assert not any("assigned" in f for f in listed(raw))


# --- gateway: MCP routes ------------------------------------------------------------------------


def mcp_findings(raw: Raw, server: str = "broker-read") -> list[str]:
    prefix = f"gateway.servers.{server}."
    return [f for f in listed(raw) if f.split(" ", 1)[1].startswith(prefix)]


def test_the_example_mcp_route_is_clean(example_raw: Raw) -> None:
    assert mcp_findings(example_raw) == []
    assert mcp_findings(example_raw, "broker-trade") == []


def test_mcp_needs_post_on_the_server_path(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [{"methods": ["GET", "DELETE"], "paths": ["/mcp"]}]
    assert mcp_findings(raw) == [
        "error gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing POST /mcp"
    ]


@pytest.mark.parametrize(
    ("methods", "missing"),
    [
        (["POST", "GET"], "DELETE /mcp"),
        (["POST", "DELETE"], "GET /mcp"),
        (["POST"], "GET /mcp or DELETE /mcp"),
    ],
)
def test_legacy_servers_need_get_and_delete(
    example_raw: Raw, methods: list[str], missing: str
) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [{"methods": methods, "paths": ["/mcp"]}]
    assert mcp_findings(raw) == [
        f"warning gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing "
        f"{missing}: legacy servers use GET for notifications and DELETE to end a session"
    ]


def test_methods_may_come_from_several_rules(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["POST"], "paths": ["/mcp"]},
        {"methods": ["GET"], "paths": ["/mcp"]},
        {"methods": ["DELETE"], "paths": ["/mcp"]},
    ]
    assert mcp_findings(raw) == []


def test_mcp_routes_must_stream(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["stream"] = False
    assert mcp_findings(raw) == [
        "error gateway.servers.broker-read.route: route 'broker-mcp' must set stream: true for MCP"
    ]


def test_mcp_over_plain_http_is_refused(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    mcp = route(raw, "broker-mcp")
    mcp.update(upstream="http://mcp.broker.example", allow_insecure_upstream=True)
    mcp.pop("credential")
    raw["credentials"].pop("broker-mcp")
    found = listed(raw)
    assert (
        "error gateway.servers.broker-read.route: route 'broker-mcp' uses plain http: "
        "MCP over cleartext is refused"
    ) in found
    # The route alone would only be a warning.
    assert "warning routes[1].upstream: plain http upstream" in found


def test_rules_the_gateway_never_uses_warn(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["GET", "POST", "DELETE", "PUT"], "paths": ["/mcp", "/admin"]},
        {"methods": ["PUT"], "paths": ["/mcp"]},
    ]
    assert mcp_findings(raw) == [
        "warning gateway.servers.broker-read.route: route 'broker-mcp' also allows PUT /mcp, "
        "GET /admin, POST /admin, DELETE /admin, PUT /admin; the gateway never uses them"
    ]


def test_every_server_path_on_a_route_is_used(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-trade"]["path"] = "/trade"
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["GET", "POST", "DELETE"], "paths": ["/mcp", "/trade"]}
    ]
    assert mcp_findings(raw) == []
    assert mcp_findings(raw, "broker-trade") == []


def broad(entries: str) -> str:
    return (
        f"warning gateway.servers.broker-read.route: route 'broker-mcp' allows {entries} by "
        "pattern; the gateway only uses its servers' exact paths, so list those instead"
    )


@pytest.mark.parametrize("source", ["/mcp/**", "/**", "/*", "/{x}"])
def test_rule_patterns_reach_the_server_path(example_raw: Raw, source: str) -> None:
    # The vault matches the gateway's requests by pattern, so check does too.
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [{"methods": ["POST", "GET", "DELETE"], "paths": [source]}]
    assert mcp_findings(raw) == [broad(f"POST {source}, GET {source}, DELETE {source}")]
    assert errors(run(raw)) == []


def test_capture_params_decide_whether_a_rule_reaches(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    rule = {"methods": ["POST", "GET", "DELETE"], "paths": ["/{x}"], "params": {"x": ["mcp"]}}
    route(raw, "broker-mcp")["rules"] = [rule]
    assert mcp_findings(raw) == [broad("POST /{x}, GET /{x}, DELETE /{x}")]
    rule["params"] = {"x": ["other"]}
    assert sorted(mcp_findings(raw)) == [
        "error gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing POST /mcp",
        "warning gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing "
        "GET /mcp or DELETE /mcp: legacy servers use GET for notifications and DELETE to end a "
        "session",
        "warning gateway.servers.broker-read.route: route 'broker-mcp' also allows POST /{x}, "
        "GET /{x}, DELETE /{x}; the gateway never uses them",
    ]


def test_a_pattern_that_misses_the_server_path(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]},
        {"methods": ["POST"], "paths": ["/mcp/*"]},
    ]
    assert mcp_findings(raw) == [
        "warning gateway.servers.broker-read.route: route 'broker-mcp' also allows "
        "POST /mcp/*; the gateway never uses them"
    ]


def test_a_broad_entry_is_listed_once(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["POST"], "paths": ["/mcp", "/**"]},
        {"methods": ["POST", "GET", "DELETE"], "paths": ["/**"]},
    ]
    assert mcp_findings(raw) == [broad("POST /**, GET /**, DELETE /**")]


def test_bad_rule_patterns_on_an_mcp_route(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]},
        {"methods": ["GET"], "paths": ["/a/**/b"]},
    ]
    assert mcp_findings(raw) == [
        "warning gateway.servers.broker-read.route: route 'broker-mcp' also allows "
        "GET /a/**/b; the gateway never uses them"
    ]
    assert any(e.startswith("routes[1].rules[1].paths[0]: ") for e in errors(run(raw)))


@pytest.mark.parametrize("server_path", ["/a//b", "/./mcp", "/mcp/../x", "/*", "/{x}", "mcp"])
def test_server_paths_the_vault_refuses(example_raw: Raw, server_path: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["path"] = server_path
    assert mcp_findings(raw) == [
        "error gateway.servers.broker-read.path: must be a plain absolute path"
    ]
    assert mcp_findings(raw, "broker-trade") == []


def test_server_paths_match_exactly_as_the_vault_does(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["path"] = "/"
    route(raw, "broker-mcp")["rules"] = [
        {"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp", "/"]}
    ]
    assert mcp_findings(raw) == []
    # A trailing slash is part of the path.
    raw["gateway"]["servers"]["broker-read"]["path"] = "/mcp/"
    assert sorted(mcp_findings(raw)) == [
        "error gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing "
        "POST /mcp/",
        "warning gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing "
        "GET /mcp/ or DELETE /mcp/: legacy servers use GET for notifications and DELETE to end "
        "a session",
        "warning gateway.servers.broker-read.route: route 'broker-mcp' also allows POST /, "
        "GET /, DELETE /; the gateway never uses them",
    ]


def test_a_connector_route_gets_one_error(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["route"] = "mail-send"
    assert mcp_findings(raw) == [
        "error gateway.servers.broker-read.route: points at a connector route, not an upstream"
    ]


# --- gateway: servers ---------------------------------------------------------------------------


def bridge(**fields: Any) -> Raw:
    return {
        "kind": "bridge",
        "url": "https://bridge.example/mcp",
        "tools": {"include": ["t"], "allow": ["t"]},
        "review": {"t": "sha256:" + "1" * 64},
        **fields,
    }


@pytest.mark.parametrize("capability", ["resources", "completions", "roots"])
def test_enable_is_an_error_for_now(example_raw: Raw, capability: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["enable"] = [capability]
    raw["gateway"]["servers"]["bridge1"] = bridge(enable=[capability])
    raw["gateway"]["clients"]["agent1"]["servers"].append("bridge1")
    message = (
        "resources, prompts, completions, sampling, elicitation and roots can't be enabled "
        "yet; M3 serves tools only"
    )
    found = errors(run(raw))
    assert found == [
        f"gateway.servers.bridge1.enable: {message}",
        f"gateway.servers.broker-read.enable: {message}",
    ]


def test_unknown_capabilities_are_schema_errors(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["enable"] = ["tasks"]
    assert any(
        e.startswith(
            "gateway.servers.broker-read.remote.enable[0]: Input should be 'resources', "
            "'prompts', 'completions'"
        )
        for e in schema_errors(raw)
    )


def test_shared_sessions_warn(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["shared_session"] = True
    assert mcp_findings(raw) == [
        "warning gateway.servers.broker-read.shared_session: legacy servers only: every client "
        "shares one upstream session, so server-side state leaks between agents"
    ]


def test_tools_that_differ_only_in_case(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    server = raw["gateway"]["servers"]["broker-read"]
    server["tools"] = {
        "include": ["get_quote", "Get_Quote", "list_positions", "GET_QUOTE"],
        "allow": ["get_quote", "Get_Quote", "list_positions", "GET_QUOTE"],
    }
    server["review"].update({"Get_Quote": "sha256:" + "2" * 64, "GET_QUOTE": "sha256:" + "3" * 64})
    assert errors(run(raw)) == [
        "gateway.servers.broker-read.tools: 'GET_QUOTE', 'Get_Quote', 'get_quote' differ only "
        "in case"
    ]


def test_a_repeated_tool_is_not_a_case_clash(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["broker-read"]["tools"]["include"].append("get_quote")
    assert errors(run(raw)) == []


def test_toolkit_tools_that_differ_only_in_case(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["servers"]["mail"]["tools"] = {"include": ["send", "Send"]}
    assert errors(run(raw)) == ["gateway.servers.mail.tools: 'Send', 'send' differ only in case"]


def test_server_defaults(example_raw: Raw) -> None:
    policy = parse_policy(yaml.safe_dump(example_raw, sort_keys=False), "test")
    assert policy.gateway is not None
    server = policy.gateway.servers["broker-trade"]
    assert isinstance(server, RemoteServer)
    assert server.era == "auto"
    assert server.drift_check_interval == 300
    assert server.call_timeout is None
    assert server.enable == []
    assert policy.gateway.servers["broker-read"].era == "modern"  # type: ignore[union-attr]


@pytest.mark.parametrize(
    ("field", "low", "high"),
    [("drift_check_interval", 60, 86400), ("call_timeout", 1, 3600)],
)
def test_server_bounds(example_raw: Raw, field: str, low: int, high: int) -> None:
    raw = copy.deepcopy(example_raw)
    server = raw["gateway"]["servers"]["broker-read"]
    for good in (low, high):
        server[field] = good
        assert errors(run(raw)) == []
    for bad in (low - 1, high + 1):
        server[field] = bad
        assert any(
            e.startswith(f"gateway.servers.broker-read.remote.{field}: Input should be")
            for e in schema_errors(raw)
        )


def test_era_values(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    for era in ("auto", "modern", "legacy"):
        raw["gateway"]["servers"]["broker-read"]["era"] = era
        assert errors(run(raw)) == []
    raw["gateway"]["servers"]["broker-read"]["era"] = "2025-03-26"
    assert any(
        e.startswith("gateway.servers.broker-read.remote.era: Input should be")
        for e in schema_errors(raw)
    )


# --- gateway: hosts, origins and limits ---------------------------------------------------------


def test_gateway_defaults() -> None:
    gateway = Gateway()
    assert gateway.hosts == ["localhost", "127.0.0.1", "::1"]
    assert gateway.origins == []
    assert gateway.limits == GatewayLimits()
    assert gateway.limits.model_dump() == {
        "max_request_bytes": 2**20,
        "max_argument_bytes": 256 * 1024,
        "max_result_bytes": 4 * 2**20,
        "max_upstream_message_bytes": 8 * 2**20,
        "max_concurrent_per_client": 8,
        "max_streams_per_client": 4,
        "max_sessions_per_client": 16,
        "max_upstream_sessions": 64,
        "session_idle_timeout": 1800,
        "upstream_idle_timeout": 600,
        "call_timeout": 300,
        "list_timeout": 30,
        "max_list_pages": 32,
        "max_tools_per_server": 512,
        "max_list_bytes": 4 * 2**20,
        "max_schema_bytes": 64 * 1024,
        "max_schema_depth": 32,
        "max_subschemas": 512,
        "policy_max_stale": 300,
        "ledger_max_bytes": 64 * 2**20,
    }


@pytest.mark.parametrize("host", ["localhost", "::1", "fe80::1", "10.0.0.1", "gw.example"])
def test_gateway_hosts_accept(example_raw: Raw, host: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["hosts"] = [host]
    assert errors(run(raw)) == []


@pytest.mark.parametrize(
    ("hosts", "expected"),
    [
        ([], "gateway.hosts: List should have at least 1 item"),
        (["[::1]"], "gateway.hosts: Value error, write IPv6 addresses without brackets: '[::1]'"),
        (["gw.example:8080"], "gateway.hosts: Value error, invalid host name 'gw.example:8080'"),
        (["bad_host.example"], "gateway.hosts: Value error, invalid host name"),
        (["localhost", "-x"], "gateway.hosts: Value error, invalid host name '-x'"),
    ],
)
def test_gateway_hosts_reject(example_raw: Raw, hosts: list[str], expected: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["hosts"] = hosts
    found = schema_errors(raw)
    assert any(e.startswith(expected) for e in found), found


@pytest.mark.parametrize(
    "origin",
    [
        "http://a",
        "https://app.example",
        "https://app.example:8443",
        "http://127.0.0.1:8080",
        "http://[::1]:3000",
        "https://app.example:80",
        "http://app.example:443",
    ],
)
def test_origins_accept(example_raw: Raw, origin: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["origins"] = [origin]
    assert errors(run(raw)) == []


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("http://", "String should have at least 8 characters"),
        ("https://" + "a" * 293, "String should have at most 300 characters"),
        ("ftp://app.example", "Value error, scheme must be one of: http, https"),
        ("https://app.example/", "Value error, an origin is scheme://host[:port], with no path"),
        ("https://app.example/x", "Value error, a path is not allowed here"),
        ("https://app.example:", "Value error, an origin is scheme://host[:port], with no path"),
        ("https://app.example:0443", "Value error, an origin is scheme://host[:port]"),
        ("https://app.example?x=1", "Value error, query strings and fragments are not allowed"),
        ("https://app.example#x", "Value error, query strings and fragments are not allowed"),
        ("https://u@app.example", "Value error, credentials in URLs are not allowed"),
        ("https://App.example", "Value error, write origins in lower case"),
        ("HTTPS://app.example", "Value error, write origins in lower case"),
        ("https://bad_host.example", "Value error, invalid host name 'bad_host.example'"),
        ("https://app.example:443", "Value error, leave out the default port 443; browsers do"),
        ("http://app.example:80", "Value error, leave out the default port 80; browsers do"),
        ("https://app.example:99999", "Value error, invalid port"),
        ("https://app.example\n", "Value error, line breaks and NUL are not allowed"),
    ],
)
def test_origins_reject(example_raw: Raw, origin: str, expected: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["origins"] = ["https://ok.example", origin]
    found = schema_errors(raw)
    assert any(e.startswith("gateway.origins") and expected in e for e in found), found


def test_origin_length_bound(example_raw: Raw) -> None:
    # A host name is at most 253 characters, so no valid origin reaches 300: at 300 characters
    # only the host is refused, and the length rule starts at 301.
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["origins"] = ["https://" + "a" * 292]
    found = schema_errors(raw)
    assert any("invalid host name" in e for e in found), found
    assert not any("at most 300 characters" in e for e in found), found


LIMIT_BOUNDS = {
    "max_request_bytes": (4096, 16 * 2**20),
    "max_argument_bytes": (1024, 4 * 2**20),
    "max_result_bytes": (65536, 16 * 2**20),
    "max_upstream_message_bytes": (65536, 16 * 2**20),
    "max_concurrent_per_client": (1, 64),
    "max_streams_per_client": (1, 64),
    "max_sessions_per_client": (1, 256),
    "max_upstream_sessions": (1, 1024),
    "session_idle_timeout": (60, 86400),
    "upstream_idle_timeout": (30, 86400),
    "call_timeout": (1, 3600),
    "list_timeout": (1, 300),
    "max_list_pages": (1, 1000),
    "max_tools_per_server": (1, 10000),
    "max_list_bytes": (65536, 64 * 2**20),
    "max_schema_bytes": (1024, 2**20),
    "max_schema_depth": (4, 128),
    "max_subschemas": (16, 10000),
    "policy_max_stale": (30, 3600),
    "ledger_max_bytes": (2**20, 2**30),
}


def test_every_limit_has_bounds() -> None:
    assert set(LIMIT_BOUNDS) == set(GatewayLimits.model_fields)


@pytest.mark.parametrize("field", sorted(LIMIT_BOUNDS))
def test_limit_bounds(field: str) -> None:
    low, high = LIMIT_BOUNDS[field]
    for good in (low, high):
        assert getattr(GatewayLimits(**{field: good}), field) == good
    for bad in (low - 1, high + 1):
        with pytest.raises(ValidationError):
            GatewayLimits(**{field: bad})


def test_results_must_fit_in_an_upstream_message(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    limits = raw["gateway"]["limits"] = {
        "max_result_bytes": 2**20,
        "max_upstream_message_bytes": 2**20,
    }
    assert errors(run(raw)) == []
    limits["max_result_bytes"] = 2**20 + 1
    assert errors(run(raw)) == [
        "gateway.limits: max_result_bytes (1048577) is larger than max_upstream_message_bytes "
        "(1048576), so a result that size could never arrive"
    ]


# --- env secrets with line breaks ---------------------------------------------------------------

LINE_BREAK = (
    "credentials.music-stats.secret: env var STATS_KEY has a line break, so an upstream's echo "
    "of it in a stream can't be scrubbed"
)


@pytest.mark.parametrize("value", ["a\nb", "a\rb", "ab\r\n"])
def test_env_secrets_with_line_breaks_warn(example_raw: Raw, value: str) -> None:
    raw = copy.deepcopy(example_raw)
    raw["credentials"]["music-stats"]["secret"] = "env:STATS_KEY"
    assert LINE_BREAK in warnings(run(raw, environ={"STATS_KEY": value}))


@pytest.mark.parametrize(
    "credential",
    [
        {"kind": "header", "header": "X-API-Key", "format": "{secret}"},
        {"kind": "header"},
        {"kind": "query", "param": "key"},
        {"kind": "path", "template": "/k/{secret}"},
        {"kind": "basic", "username": "user"},
    ],
)
def test_every_injected_secret_kind_warns_on_line_breaks(credential: Raw) -> None:
    raw = oauth_policy({"c": {**credential, "secret": "env:C_KEY"}})
    found = warnings(run(raw, environ={"C_KEY": "x\ny"}))
    assert (
        "credentials.c.secret: env var C_KEY has a line break, so an upstream's echo of it in "
        "a stream can't be scrubbed"
    ) in found


def test_env_secrets_without_line_breaks(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["credentials"]["music-stats"]["secret"] = "env:STATS_KEY"
    assert not any("line break" in w for w in warnings(run(raw, environ={"STATS_KEY": "a b"})))
    # Without the environment, check can't know.
    assert not any("line break" in w for w in warnings(run(raw)))


def test_line_breaks_matter_only_for_injected_secrets(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["credentials"]["broker-mcp"]["client_id"] = "env:BROKER_ID"
    raw["credentials"]["broker-mcp"]["refresh_token"] = "env:BROKER_SEED"
    raw["connectors"]["mail-out"]["password"] = "env:MAIL_PASS"
    environ = {"BROKER_ID": "a\nb", "BROKER_SEED": "a\nb", "MAIL_PASS": "a\nb"}
    assert not any("line break" in w for w in warnings(run(raw, environ=environ)))


def test_basic_usernames_from_env_are_injected_too() -> None:
    raw = oauth_policy({"b": {"kind": "basic", "username": "env:B_USER", "secret": "store:b"}})
    found = warnings(run(raw, environ={"B_USER": "x\ny"}))
    assert (
        "credentials.b.username: env var B_USER has a line break, so an upstream's echo of it in "
        "a stream can't be scrubbed"
    ) in found


# --- approvals and the SMTP connector (M4) -------------------------------------------------------


def _agent1(raw: Raw) -> Raw:
    client: Raw = raw["gateway"]["clients"]["agent1"]
    return client


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda r: r["gateway"]["approvals"].update(approver="portal"),
            "gateway.approvals.approver: telegram and portal approvers arrive in M8",
        ),
        (
            lambda r: r["gateway"]["approvals"].update(approver="telegram"),
            "gateway.approvals.approver: telegram and portal approvers arrive in M8",
        ),
        (
            lambda r: r["gateway"]["approvals"].update(timeout=601),
            "gateway.approvals.timeout: a prompt can't outlive the client's tool call",
        ),
        (
            lambda r: (
                r["gateway"]["approvals"].update(timeout=120),
                r["gateway"].setdefault("limits", {}).update(session_idle_timeout=120),
            ),
            "gateway.approvals.timeout: must be below limits.session_idle_timeout (120)",
        ),
        (
            lambda r: _agent1(r)["approvals"].update(timeout=301),
            "gateway.clients.agent1.approvals.timeout: a client setting can only lower it",
        ),
        (
            lambda r: _agent1(r)["approvals"].update(budget_chars=3001),
            "gateway.clients.agent1.approvals.budget_chars: a client setting can only lower it",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(password="env:MAIL_PASS"),
            "connectors.mail-out.password: a connector password must come from the store",
        ),
        (
            lambda r: route(r, "mail-send")["rules"][1].update(methods=["POST", "DELETE"]),
            "routes[2].rules[1]: a connector answers only GET /config and POST /send, "
            "not DELETE /send",
        ),
        (
            lambda r: route(r, "mail-send")["rules"][0].update(paths=["/config", "/inbox"]),
            "routes[2].rules[0]: a connector answers only GET /config and POST /send, "
            "not GET /inbox",
        ),
    ],
)
def test_approval_and_connector_errors(
    example_raw: Raw, mutate: Callable[[Raw], object], expected: str
) -> None:
    raw = copy.deepcopy(example_raw)
    mutate(raw)
    found = errors(run(raw))
    assert any(e.startswith(expected) for e in found), found


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda r: r["gateway"]["approvals"].update(timeout=301),
            "gateway.approvals.timeout: some clients end a tool call sooner",
        ),
        (
            lambda r: _agent1(r).pop("approvals"),
            "gateway.clients.agent1: not attended, but assigned 'broker-trade' with approve "
            "tools: they will always be refused",
        ),
        (
            lambda r: _agent1(r)["approvals"].update(attended=False),
            "gateway.clients.agent1: not attended, but assigned 'broker-trade'",
        ),
        (
            lambda r: _agent1(r).pop("sources"),
            "gateway.clients.agent1.sources: anyone holding this client's token can make calls",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(tls="starttls"),
            "connectors.mail-out.tls: port 465 usually speaks implicit TLS",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(port=587),
            "connectors.mail-out.tls: port 587 usually speaks STARTTLS",
        ),
        (
            lambda r: r["connectors"]["mail-out"].update(paused=True),
            "connectors.mail-out.paused: sends are paused",
        ),
        (
            lambda r: r["gateway"].setdefault("limits", {}).update(call_timeout=301),
            "gateway.limits.call_timeout: an approved call may run 301 s and a stop waits for it",
        ),
        (
            lambda r: r["gateway"]["servers"]["broker-trade"].update(call_timeout=900),
            "gateway.servers.broker-trade.call_timeout: an approved call may run 900 s",
        ),
    ],
)
def test_approval_and_connector_warnings(
    example_raw: Raw, mutate: Callable[[Raw], object], expected: str
) -> None:
    raw = copy.deepcopy(example_raw)
    mutate(raw)
    findings = run(raw)
    assert errors(findings) == []
    found = warnings(findings)
    assert any(w.startswith(expected) for w in found), found


def test_quiet_approval_settings(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["approvals"].update(timeout=300)
    _agent1(raw)["approvals"].update(timeout=300, budget_chars=3000, renders="plain")
    raw["connectors"]["mail-out"].update(port=587, tls="starttls")
    # Only approve tools need the stop window, and only past 300 s.
    raw["gateway"]["servers"]["broker-read"].update(call_timeout=900)
    raw["gateway"]["servers"]["broker-trade"].update(call_timeout=300)
    findings = run(raw)
    assert errors(findings) == []
    assert len(warnings(findings)) == 2  # the example's own two


def test_an_env_connector_password_is_an_error_only(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["connectors"]["mail-out"]["password"] = "env:MAIL_PASS"
    findings = run(raw, environ={})
    on_password = [f for f in findings if f.path == "connectors.mail-out.password"]
    assert [f.level for f in on_password] == ["error"]
    # An env: username is still only a warning: the binding protects the password.
    raw["connectors"]["mail-out"]["password"] = "store:mail-pass"
    raw["connectors"]["mail-out"]["username"] = "env:MAIL_USER"
    assert errors(run(raw)) == []


def test_unattended_clients_without_approve_tools_are_quiet(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    del _agent1(raw)["approvals"]
    _agent1(raw)["servers"] = ["broker-read", "mail"]
    assert not any("not attended" in w for w in warnings(run(raw)))


def test_approval_schema_bounds() -> None:
    approvals = Gateway.model_validate({}).approvals
    assert (approvals.cooldown, approvals.max_pending_per_client) == (15, 1)
    assert approvals.max_prompts_per_hour == 30
    for field, low, high in [
        ("cooldown", 0, 3600),
        ("max_pending_per_client", 1, 16),
        ("max_prompts_per_hour", 1, 1000),
    ]:
        Gateway.model_validate({"approvals": {field: low}})
        Gateway.model_validate({"approvals": {field: high}})
        for bad in (low - 1, high + 1):
            with pytest.raises(ValidationError):
                Gateway.model_validate({"approvals": {field: bad}})


def test_client_approvals_schema() -> None:
    base = {"token_sha256": "sha256:" + "0" * 64}
    assert Client.model_validate(base).approvals is None
    client = Client.model_validate({**base, "approvals": {"attended": True}})
    assert client.approvals is not None
    assert (client.approvals.renders, client.approvals.confirm_code) == ("markdown", False)
    assert (client.approvals.timeout, client.approvals.budget_chars) == (None, None)
    for bad in (
        {},  # attended is required: the operator must say
        {"attended": True, "renders": "html"},
        {"attended": True, "timeout": 601},
        {"attended": True, "timeout": 0},
        {"attended": True, "budget_chars": 199},
        {"attended": True, "budget_chars": 20001},
    ):
        with pytest.raises(ValidationError):
            Client.model_validate({**base, "approvals": bad})


def test_smtp_connector_limits(example_raw: Raw) -> None:
    policy = parse_policy(yaml.safe_dump(example_raw, sort_keys=False), "test")
    conn = policy.connectors["mail-out"]
    assert (conn.max_subject_chars, conn.max_body_chars, conn.paused) == (150, 2200, False)
    for field, bad in [
        ("max_subject_chars", 0),
        ("max_subject_chars", 999),
        ("max_body_chars", 0),
        ("max_body_chars", 100_001),
    ]:
        broken = copy.deepcopy(example_raw)
        broken["connectors"]["mail-out"][field] = bad
        assert any(field in e for e in schema_errors(broken)), field
