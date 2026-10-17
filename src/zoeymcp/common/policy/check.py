"""Semantic checks on a schema-valid policy: ``zoeymcp check`` (design R53).

Errors are policies that would be unsafe or wouldn't work; warnings are policies that work but
probably aren't what was meant, or are weaker than they could be.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from urllib.parse import urlsplit

from .findings import Finding
from .paths import PathPatternError, parse_path_pattern
from .schema import (
    BasicCredential,
    BridgeServer,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    PlaceholderCaller,
    Policy,
    QueryCredential,
    RemoteServer,
    Route,
    is_secret_ref,
)

MIN_TOKEN_LENGTH = 16
_RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "host",
        "cookie",
        "content-length",
        "content-type",
        "connection",
        "transfer-encoding",
        "proxy-authorization",
    }
)


class _Report:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def error(self, path: str, message: str) -> None:
        self.findings.append(Finding(path, "error", message))

    def warning(self, path: str, message: str) -> None:
        self.findings.append(Finding(path, "warning", message))


def check_policy(policy: Policy, *, environ: Mapping[str, str] | None = None) -> list[Finding]:
    """Return every finding for ``policy``. With ``environ``, ``env:`` references must resolve."""
    report = _Report()
    _check_secret_refs(policy, report, environ)
    _check_credentials(policy, report)
    _check_routes(policy, report)
    _check_tokens(policy, report)
    _check_gateway(policy, report)
    return sorted(set(report.findings))


# --- secrets -----------------------------------------------------------------------------------


def secret_references(policy: Policy) -> list[tuple[str, str, bool]]:
    """``(path, reference, is_seed)`` for every secret reference in the policy."""
    refs: list[tuple[str, str, bool]] = []
    for name, cred in policy.credentials.items():
        base = f"credentials.{name}"
        if isinstance(cred, HeaderCredential | QueryCredential | PathCredential | BasicCredential):
            refs.append((f"{base}.secret", cred.secret, False))
        if isinstance(cred, BasicCredential) and is_secret_ref(cred.username):
            refs.append((f"{base}.username", cred.username, False))
        if isinstance(cred, OAuth2Credential):
            if is_secret_ref(cred.client_id):
                refs.append((f"{base}.client_id", cred.client_id, False))
            if cred.client_secret is not None:
                refs.append((f"{base}.client_secret", cred.client_secret, False))
            if cred.refresh_token is not None:
                refs.append((f"{base}.refresh_token", cred.refresh_token, True))
    for name, conn in policy.connectors.items():
        base = f"connectors.{name}"
        if is_secret_ref(conn.username):
            refs.append((f"{base}.username", conn.username, False))
        refs.append((f"{base}.password", conn.password, False))
    return refs


def _check_secret_refs(policy: Policy, report: _Report, environ: Mapping[str, str] | None) -> None:
    for path, ref, is_seed in secret_references(policy):
        if not ref.startswith("env:"):
            continue
        var = ref.removeprefix("env:")
        if is_seed:
            cred = policy.credentials.get(path.split(".")[1])
            if getattr(cred, "reseed", "never") == "on-change":
                effect = "a changed env value replaces the live token (reseed: on-change)"
            else:
                effect = "a changed env value is ignored (reseed: never)"
            report.warning(
                path,
                f"refresh token seeded from env var {var}: the live token is kept in the "
                f"store, and {effect}",
            )
        else:
            report.warning(
                path,
                f"secret read from env var {var}: it isn't encrypted at rest or bound to its "
                "origins; prefer store:<name>",
            )
        if environ is not None and var not in environ:
            report.error(path, f"env var {var} is not set")


# --- credentials -------------------------------------------------------------------------------


def _check_credentials(policy: Policy, report: _Report) -> None:
    used = {r.credential for r in policy.routes if r.credential is not None}
    used_connectors = {r.connector for r in policy.routes if r.connector is not None}
    for name, cred in policy.credentials.items():
        path = f"credentials.{name}"
        if name not in used:
            report.warning(path, "not used by any route")
        if isinstance(cred, OAuth2Credential):
            _check_oauth(path, cred, report)
    for name in policy.connectors:
        if name not in used_connectors:
            report.warning(f"connectors.{name}", "not used by any route")


def _check_oauth(path: str, cred: OAuth2Credential, report: _Report) -> None:
    if urlsplit(cred.token_url).scheme != "https":
        report.error(f"{path}.token_url", "the token endpoint must use https")
    if cred.grant == "refresh_token":
        if cred.refresh_token is None:
            report.error(f"{path}.refresh_token", "required for the refresh_token grant")
    else:
        if cred.refresh_token is not None:
            report.error(f"{path}.refresh_token", "not used by the client_credentials grant")
        if cred.client_secret is None:
            report.error(f"{path}.client_secret", "required for the client_credentials grant")
        if cred.rotates:
            report.error(f"{path}.rotates", "client_credentials tokens don't rotate")
    if cred.reseed == "on-change" and not (cred.refresh_token or "").startswith("env:"):
        report.warning(f"{path}.reseed", "only meaningful for a refresh token seeded from env:")
    for param in ("grant_type", "refresh_token", "client_id", "client_secret", "code"):
        if param in cred.extra_params:
            report.error(f"{path}.extra_params.{param}", "set by the vault; can't be overridden")


# --- routes ------------------------------------------------------------------------------------


def _check_routes(policy: Policy, report: _Report) -> None:
    names: dict[str, int] = {}
    prefixes: dict[str, int] = {}
    mcp_routes = {
        s.route
        for s in (policy.gateway.servers.values() if policy.gateway else ())
        if isinstance(s, RemoteServer)
    }
    for index, route in enumerate(policy.routes):
        path = f"routes[{index}]"
        if route.name in names:
            report.error(f"{path}.name", f"duplicate route name (also routes[{names[route.name]}])")
        names.setdefault(route.name, index)
        if route.prefix in prefixes:
            report.error(
                f"{path}.prefix", f"duplicate prefix (also routes[{prefixes[route.prefix]}])"
            )
        prefixes.setdefault(route.prefix, index)
        _check_route_target(policy, path, route, report)
        _check_route_callers(path, route, route.name in mcp_routes, report)
        _check_route_rules(path, route, report)
        _check_route_query(policy, path, route, report)


def _check_route_target(policy: Policy, path: str, route: Route, report: _Report) -> None:
    if route.credential is not None and route.credential not in policy.credentials:
        report.error(f"{path}.credential", f"unknown credential {route.credential!r}")
    if route.connector is not None and route.connector not in policy.connectors:
        report.error(f"{path}.connector", f"unknown connector {route.connector!r}")
    if route.upstream is not None:
        scheme = urlsplit(route.upstream).scheme
        if scheme == "http" and not route.allow_insecure_upstream:
            report.error(
                f"{path}.upstream",
                "plain http would send the credential in cleartext; use https "
                "(or allow_insecure_upstream for a route without one)",
            )
        elif scheme == "http":
            if route.credential is not None:
                report.error(f"{path}.upstream", "a credential can't be sent over plain http")
            else:
                report.warning(f"{path}.upstream", "plain http upstream")


def _check_route_callers(path: str, route: Route, is_mcp: bool, report: _Report) -> None:
    gateway_only = all(c == "gateway" for c in route.callers)
    if route.connector is not None and not gateway_only:
        report.error(
            f"{path}.callers",
            "a connector route must accept only the gateway, so nothing else can skip approval",
        )
    if is_mcp and not gateway_only:
        report.error(
            f"{path}.callers",
            "a route used by a gateway server must accept only the gateway, "
            "so the tool filter can't be bypassed",
        )
    if route.callers.count("gateway") > 1:
        report.warning(f"{path}.callers", "gateway listed more than once")
    for index, caller in enumerate(route.callers):
        if isinstance(caller, PlaceholderCaller) and caller.header is not None:
            name = caller.header.lower()
            if name in _RESERVED_HEADERS or name.startswith("x-zoeymcp-"):
                report.error(
                    f"{path}.callers[{index}].header",
                    f"{caller.header!r} is reserved; omit header: to use Authorization: Bearer",
                )


def _check_route_rules(path: str, route: Route, report: _Report) -> None:
    for r_index, rule in enumerate(route.rules):
        r_path = f"{path}.rules[{r_index}]"
        captures: set[str] = set()
        for p_index, pattern in enumerate(rule.paths):
            try:
                parsed = parse_path_pattern(pattern)
            except PathPatternError as exc:
                report.error(f"{r_path}.paths[{p_index}]", f"{pattern!r}: {exc}")
                continue
            captures.update(parsed.captures)
        for name in rule.params:
            if name not in captures:
                report.error(f"{r_path}.params.{name}", f"no path in this rule captures {{{name}}}")
        for name in sorted(captures - set(rule.params)):
            report.warning(
                f"{r_path}.paths",
                f"{{{name}}} has no constraint in params, so it matches any segment like *",
            )
        if len(set(rule.methods)) != len(rule.methods):
            report.warning(f"{r_path}.methods", "a method is listed more than once")


def _check_route_query(policy: Policy, path: str, route: Route, report: _Report) -> None:
    query = route.query
    overlap = set(query.force) & set(query.strip)
    for name in sorted(overlap):
        report.error(f"{path}.query", f"{name!r} is both forced and stripped")
    cred = policy.credentials.get(route.credential or "")
    if isinstance(cred, QueryCredential) and cred.param in query.force:
        report.error(f"{path}.query.force", f"{cred.param!r} carries the credential")
    if query.allow is not None:
        for name in sorted(set(query.force) - set(query.allow)):
            report.warning(f"{path}.query.allow", f"forced parameter {name!r} isn't in allow")


# --- tokens and placeholders -------------------------------------------------------------------


def _check_tokens(policy: Policy, report: _Report) -> None:
    placeholders: dict[str, list[str]] = defaultdict(list)
    for index, route in enumerate(policy.routes):
        for c_index, caller in enumerate(route.callers):
            if isinstance(caller, PlaceholderCaller):
                placeholders[caller.placeholder].append(f"routes[{index}].callers[{c_index}]")
    clients: dict[str, list[str]] = defaultdict(list)
    if policy.gateway is not None:
        for name, client in policy.gateway.clients.items():
            clients[client.token].append(f"gateway.clients.{name}.token")

    for value, paths in [*placeholders.items(), *clients.items()]:
        if len(value) < MIN_TOKEN_LENGTH:
            for p in paths:
                report.warning(p, f"shorter than {MIN_TOKEN_LENGTH} characters, so easy to guess")
    for value, paths in placeholders.items():
        if value in clients:
            for p in paths + clients[value]:
                report.error(p, "the same value is used as a placeholder and a client token")
        elif len(paths) > 1:
            for p in paths:
                report.warning(p, "placeholder reused on several routes; give each client its own")
    for paths in clients.values():
        if len(paths) > 1:
            for p in paths:
                report.error(p, "two clients share a token")


# --- gateway -----------------------------------------------------------------------------------

_MCP_SERVER_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")


def _check_gateway(policy: Policy, report: _Report) -> None:
    gateway = policy.gateway
    if gateway is None:
        return
    routes = {r.name: r for r in policy.routes}
    for name, client in gateway.clients.items():
        for server_name in client.servers:
            if server_name not in gateway.servers:
                report.error(f"gateway.clients.{name}.servers", f"unknown server {server_name!r}")
    for name, server in gateway.servers.items():
        path = f"gateway.servers.{name}"
        if isinstance(server, RemoteServer):
            route = routes.get(server.route)
            if route is None:
                report.error(f"{path}.route", f"unknown route {server.route!r}")
            else:
                _check_mcp_route(path, server, route, report)
        if isinstance(server, RemoteServer | BridgeServer):
            _check_tools(
                path, server.tools.include, server.tools.allow, server.tools.approve, report
            )
            _check_pins(path, server.tools.include, server.review, report)
        else:
            _check_tools(
                path,
                server.tools.include,
                server.tools.allow,
                server.tools.approve,
                report,
                require_classification=False,
            )


def _check_mcp_route(path: str, server: RemoteServer, route: Route, report: _Report) -> None:
    if not _MCP_SERVER_PATH.match(server.path):
        report.error(f"{path}.path", "must be a plain absolute path")
    if route.connector is not None:
        report.error(f"{path}.route", "points at a connector route, not an upstream")
    if not route.stream:
        report.warning(f"{path}.route", f"route {route.name!r} should set stream: true for MCP")
    if not any("POST" in rule.methods and server.path in rule.paths for rule in route.rules):
        report.warning(
            f"{path}.path", f"route {route.name!r} has no rule allowing POST {server.path}"
        )


def _check_tools(
    path: str,
    include: list[str],
    allow: list[str],
    approve: list[str],
    report: _Report,
    *,
    require_classification: bool = True,
) -> None:
    included = set(include)
    if len(included) != len(include):
        report.warning(f"{path}.tools.include", "a tool is listed more than once")
    for tool in sorted(set(allow) & set(approve)):
        report.error(f"{path}.tools", f"{tool!r} is in both allow and approve")
    for tool in sorted((set(allow) | set(approve)) - included):
        report.error(f"{path}.tools", f"{tool!r} is classified but not in include")
    if require_classification:
        for tool in sorted(included - set(allow) - set(approve)):
            report.error(
                f"{path}.tools",
                f"{tool!r} is included but in neither allow nor approve; every tool must be "
                "classified explicitly",
            )


def _check_pins(path: str, include: list[str], review: Mapping[str, str], report: _Report) -> None:
    for tool in sorted(set(include) - set(review)):
        report.error(f"{path}.review", f"{tool!r} is included but has no review pin")
    for tool in sorted(set(review) - set(include)):
        report.warning(f"{path}.review", f"pin for {tool!r}, which isn't included")
