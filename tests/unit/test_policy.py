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

from zoeymcp.common.policy import Finding, PolicyError, check_policy, parse_policy
from zoeymcp.common.policy.schema import OAuth2Credential, param_values, split_scope

Raw = dict[str, Any]


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
        "warning credentials.broker-mcp.authorize_url"
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
            lambda r: r["gateway"]["clients"]["agent1"].update(token="ph-agent1-stats-4c1f9b27"),
            "gateway.clients.agent1.token: the same value is used as a placeholder and a client"
            " token",
        ),
        (
            lambda r: r["gateway"]["clients"].update(agent2={"token": "ph-agent1-gw-8e2d6a51c3b7"}),
            "gateway.clients.agent2.token: two clients share a token",
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
            lambda r: route(r, "broker-mcp").update(stream=False),
            "gateway.servers.broker-read.route: route 'broker-mcp' should set stream: true",
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
