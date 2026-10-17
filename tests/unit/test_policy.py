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
    assert findings == []


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
