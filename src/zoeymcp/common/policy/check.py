"""Semantic checks on a schema-valid policy: ``zoeymcp check`` (design R53).

Errors are policies that would be unsafe or wouldn't work; warnings are policies that work but
probably aren't what was meant, or are weaker than they could be.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from collections.abc import Mapping
from urllib.parse import urlsplit

from .. import canonical
from .findings import Finding
from .match import NormalizedPath, path_matches
from .paths import PathPatternError, parse_path_pattern
from .schema import (
    Admin,
    BasicCredential,
    BridgeServer,
    Gateway,
    HeaderCredential,
    OAuth2Credential,
    PathCredential,
    PlaceholderCaller,
    Policy,
    QueryCredential,
    RemoteServer,
    Route,
    Rule,
    ToolkitRule,
    ToolkitServer,
    hash_token,
    is_secret_ref,
    param_values,
    split_scope,
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
# Store entries under this prefix belong to the vault (live refresh tokens).
_VAULT_PREFIX = "store:oauth."
# Parameters the vault sets itself on token requests and on the authorization request.
# scope, request and request_uri are refused too, with their own messages.
_TOKEN_PARAMS = frozenset(
    {
        "grant_type",
        "refresh_token",
        "client_id",
        "client_secret",
        "code",
        "code_verifier",
        "redirect_uri",
        "client_assertion",
        "client_assertion_type",
    }
)
_AUTHORIZE_PARAMS = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "code_verifier",
        "client_secret",
    }
)
_TOKEN_HEADERS = frozenset(
    {
        "authorization",
        "content-type",
        "content-length",
        "host",
        "accept",
        "cookie",
        "transfer-encoding",
    }
)
# An absolute URI without a fragment (RFC 8707 section 2), in any scheme.
_RESOURCE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^#\x00-\x20\x7f]+$")
_DEFAULT_PORTS = {"https": 443, "http": 80}
# The two endpoints of an SMTP connector route, as (method, path).
_CONNECTOR_ENDPOINTS = frozenset({("GET", "/config"), ("POST", "/send")})
# The longest approval timeout an elicitation may use: clients end a tool call sooner (§6.1).
MAX_ELICITATION_TIMEOUT = 600
# A stop waits for approved calls already running; the shipped stop windows cover this long.
STOP_WINDOW_CALL_TIMEOUT = 300
# A.2's estimate of a mail prompt's size beyond its values: C.2's fixed frame with the example's
# title and labels, the longest "In reply to" line (a MessageId is at most 250) and C.4's code line.
PROMPT_FRAME_CHARS = 200
PROMPT_REPLY_LINE_CHARS = 264
PROMPT_CODE_LINE_CHARS = 44


class _Report:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def error(self, path: str, message: str) -> None:
        self.findings.append(Finding(path, "error", message))

    def warning(self, path: str, message: str) -> None:
        self.findings.append(Finding(path, "warning", message))


def check_policy(policy: Policy, *, environ: Mapping[str, str] | None = None) -> list[Finding]:
    """Return every finding for ``policy``. With ``environ``, ``env:`` references must resolve;
    an unset refresh-token seed is only a warning, since the live token is in the store."""
    report = _Report()
    _check_secret_refs(policy, report, environ)
    _check_oauth_refs(policy, report)
    _check_credentials(policy, report)
    _check_routes(policy, report)
    _check_tokens(policy, report)
    _check_gateway(policy, report)
    if policy.admin is not None:
        _check_admin(policy.admin, report)
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
        if ref.startswith(_VAULT_PREFIX):
            report.error(path, "the store:oauth. prefix is reserved for entries the vault manages")
        if not ref.startswith("env:"):
            continue
        var = ref.removeprefix("env:")
        if path.startswith("connectors.") and path.endswith(".password"):
            report.error(
                path,
                "a connector password must come from the store, where it is bound to the "
                "connector's host, port, from and to; enter it with zoeymcp secret set",
            )
            continue
        if is_seed:
            name = path.split(".")[1]
            cred = policy.credentials.get(name)
            if getattr(cred, "reseed", "never") == "on-change":
                effect = "a changed env value replaces the live token (reseed: on-change)"
            else:
                effect = "a changed env value is ignored (reseed: never)"
            report.warning(
                path,
                f"refresh token seeded from env var {var}: the live token is kept in the "
                f"store as oauth.{name}.live, and {effect}; "
                f"zoeymcp secret delete oauth.{name}.live forces a re-seed",
            )
        else:
            report.warning(
                path,
                f"secret read from env var {var}: it isn't encrypted at rest or bound to its "
                "origins; prefer store:<name>",
            )
        if environ is not None and var not in environ:
            if is_seed:
                # The live token is in the store, so the seed may go once it has been used.
                report.warning(
                    path,
                    f"seed env var {var} is not set; the vault uses the live token in the "
                    "store, if there is one",
                )
            else:
                report.error(path, f"env var {var} is not set")
        elif environ is not None and _injected(policy, path) and _has_line_break(environ[var]):
            report.warning(
                path,
                f"env var {var} has a line break, so an upstream's echo of it in a stream "
                "can't be scrubbed",
            )


def _injected(policy: Policy, path: str) -> bool:
    """Whether the reference at ``path`` is a static secret the vault injects upstream."""
    if not path.startswith("credentials."):
        return False
    return not isinstance(policy.credentials[path.split(".")[1]], OAuth2Credential)


def _has_line_break(value: str) -> bool:
    return "\n" in value or "\r" in value


def _check_oauth_refs(policy: Policy, report: _Report) -> None:
    """OAuth secrets are used by OAuth credentials only, and go to one token endpoint.

    A refresh token is replaced in place on every rotation, so its ref has no other use at all.
    """
    oauth: dict[str, list[str]] = defaultdict(list)
    other: dict[str, list[str]] = defaultdict(list)
    refresh: dict[str, list[str]] = defaultdict(list)
    token_origins: dict[str, set[str]] = defaultdict(set)
    for path, ref, _ in secret_references(policy):
        owner = path.split(".")[1]
        cred = policy.credentials[owner] if path.startswith("credentials.") else None
        if isinstance(cred, OAuth2Credential):
            oauth[ref].append(path)
            token_origins[ref].add(_origin(cred.token_url) or cred.token_url)
            if path.endswith(".refresh_token"):
                refresh[ref].append(path)
        else:
            other[ref].append(path)
    for ref, paths in refresh.items():
        if len(paths) > 1:
            for p in paths:
                report.error(
                    p,
                    f"{ref} is the refresh token of {', '.join(paths)}; "
                    "they would rotate it out from under each other",
                )
        others = [p for p in oauth[ref] if p not in paths]
        if others:
            for p in oauth[ref]:
                report.error(
                    p,
                    f"{ref} is the refresh token of {', '.join(paths)} and is also used by "
                    f"{', '.join(others)}; rotation would overwrite it",
                )
    for ref, paths in oauth.items():
        if len(token_origins[ref]) > 1:
            for p in paths:
                report.error(
                    p,
                    f"{ref} would be sent to the token endpoints "
                    f"{', '.join(sorted(token_origins[ref]))}; an OAuth secret is bound to one",
                )
        users = other.get(ref, [])
        if not users:
            continue
        for p in paths:
            report.error(
                p,
                f"{ref} is also used by {', '.join(users)}; "
                "an OAuth secret must never be injectable as a static secret",
            )
        for p in users:
            report.error(
                p,
                f"{ref} is an OAuth secret of {', '.join(paths)}; "
                "it must never be injectable as a static secret",
            )


# --- credentials -------------------------------------------------------------------------------


def _check_credentials(policy: Policy, report: _Report) -> None:
    used = {r.credential for r in policy.routes if r.credential is not None}
    used_connectors = {r.connector for r in policy.routes if r.connector is not None}
    for name, cred in policy.credentials.items():
        path = f"credentials.{name}"
        is_oauth = isinstance(cred, OAuth2Credential)
        if name not in used:
            report.warning(
                path,
                "not used by any route: login and refresh will refuse; access tokens would "
                "have no resource origins"
                if is_oauth
                else "not used by any route",
            )
        if isinstance(cred, OAuth2Credential):
            upstreams = [r.upstream for r in policy.routes if r.credential == name and r.upstream]
            origins = {o for o in map(_origin, upstreams) if o is not None}
            _check_oauth(path, cred, origins, report)
    for name, conn in policy.connectors.items():
        path = f"connectors.{name}"
        if name not in used_connectors:
            report.warning(path, "not used by any route")
        if (conn.port, conn.tls) in ((465, "starttls"), (587, "implicit")):
            usual = "implicit TLS" if conn.port == 465 else "STARTTLS"
            report.warning(f"{path}.tls", f"port {conn.port} usually speaks {usual}")
        if conn.paused:
            report.warning(f"{path}.paused", "sends are paused")
    _check_connector_use(policy, report)


def _connector_slots(policy: Policy) -> dict[str, list[tuple[str, ToolkitServer]]]:
    """Per connector, the toolkit servers (by name) with a slot routed to it."""
    routes = {r.name: r for r in policy.routes}
    found: dict[str, list[tuple[str, ToolkitServer]]] = defaultdict(list)
    for name, server in policy.gateway.servers.items() if policy.gateway else ():
        if not isinstance(server, ToolkitServer):
            continue
        for binding in server.slots.values():
            route = routes.get(binding.route)
            if route is not None and route.connector is not None:
                found[route.connector].append((name, server))
    return found


def _check_connector_use(policy: Policy, report: _Report) -> None:
    slots = _connector_slots(policy)
    gateway = policy.gateway
    for name, conn in policy.connectors.items():
        path = f"connectors.{name}"
        if not slots.get(name):
            report.warning(path, "no toolkit slot maps a route to it")
            continue
        if gateway is None:
            continue
        values = (
            conn.max_subject_chars
            + conn.max_body_chars
            + len(conn.from_)
            + len(canonical.dumps_canonical(list(conn.to)))
        )
        for client_name, client in sorted(gateway.clients.items()):
            if client.approvals is None:
                continue
            budget = client.approvals.budget_chars or gateway.approvals.budget_chars
            code = PROMPT_CODE_LINE_CHARS if client.approvals.confirm_code else 0
            for server_name, server in slots[name]:
                if server_name not in client.servers:
                    continue
                for tool in server.tools.approve:
                    size = (
                        PROMPT_FRAME_CHARS
                        + len(client_name)
                        + len(server_name)
                        + len(tool)
                        + PROMPT_REPLY_LINE_CHARS
                        + code
                        + values
                    )
                    if size > budget:
                        report.warning(
                            path,
                            f"a message near these limits can't be approved by {client_name!r} "
                            f"(about {size} characters, budget {budget}); lower max_body_chars",
                        )
                        return


def _origin(url: str) -> str | None:
    """``scheme://host:port`` for an http(s) URL, or None when its port is invalid."""
    parts = urlsplit(url)  # lowercases the scheme and the host
    try:
        port = parts.port or _DEFAULT_PORTS[parts.scheme]
    except ValueError:
        return None
    return f"{parts.scheme}://{parts.hostname}:{port}"


def _check_oauth(path: str, cred: OAuth2Credential, origins: set[str], report: _Report) -> None:
    if urlsplit(cred.token_url).scheme != "https":
        report.error(f"{path}.token_url", "the token endpoint must use https")
    if cred.authorize_url is not None and urlsplit(cred.authorize_url).scheme != "https":
        report.error(f"{path}.authorize_url", "the authorization endpoint must use https")
    if cred.issuer is not None and urlsplit(cred.issuer).scheme != "https":
        report.error(f"{path}.issuer", "the issuer must use https")
    if is_secret_ref(cred.client_id) and cred.authorize_url is not None:
        report.error(
            f"{path}.client_id",
            "client IDs are public and appear in the authorization URL; write it in the policy",
        )
    if cred.grant == "refresh_token":
        _check_refresh_grant(path, cred, report)
    else:
        _check_client_credentials(path, cred, report)
    if cred.reseed == "on-change" and not _env_seeded(cred):
        report.warning(f"{path}.reseed", "only meaningful for a refresh token seeded from env:")
    _check_oauth_params(path, cred, report)
    _check_oauth_scopes(path, cred, report)
    _check_resources(path, cred, origins, report)


def _env_seeded(cred: OAuth2Credential) -> bool:
    return (cred.refresh_token or "").startswith("env:")


def _check_refresh_grant(path: str, cred: OAuth2Credential, report: _Report) -> None:
    if cred.refresh_token is None:
        report.error(f"{path}.refresh_token", "required for the refresh_token grant")
    if cred.authorize_url is None:
        report.warning(
            f"{path}.authorize_url",
            "zoeymcp login can't run; enter the refresh token with secret set or seed it from env:",
        )
    if not cred.rotates and cred.effective_client_auth == "none":
        report.warning(
            f"{path}.rotates",
            "public clients' refresh tokens usually rotate (RFC 9700 section 2.2.2); "
            "set rotates: true",
        )
    if cred.reseed == "on-change" and cred.rotates and _env_seeded(cred):
        report.warning(
            f"{path}.reseed",
            "a changed or rolled-back env value replaces the live token; an old rotating seed "
            "is dead, and presenting it may revoke the grant",
        )


def _check_client_credentials(path: str, cred: OAuth2Credential, report: _Report) -> None:
    grant = "the client_credentials grant"
    if cred.refresh_token is not None:
        report.error(f"{path}.refresh_token", f"not used by {grant}")
    if cred.client_secret is None:
        report.error(f"{path}.client_secret", f"required for {grant}")
    if cred.rotates:
        report.error(f"{path}.rotates", "client_credentials tokens don't rotate")
    if cred.authorize_url is not None:
        report.error(f"{path}.authorize_url", f"not used by {grant}")
    if cred.client_auth == "none":
        report.error(f"{path}.client_auth", f"none can't be used with {grant}")
    if cred.grant_lifetime_days is not None:
        report.warning(f"{path}.grant_lifetime_days", f"not used by {grant}")
    if cred.idle_expiry_days is not None:
        report.error(f"{path}.idle_expiry_days", f"not used by {grant}")


def _check_oauth_params(path: str, cred: OAuth2Credential, report: _Report) -> None:
    for param in cred.extra_params:
        if param.lower() == "scope":
            report.error(f"{path}.extra_params.{param}", "use the scope field")
        elif param.lower() in _TOKEN_PARAMS:
            report.error(f"{path}.extra_params.{param}", "set by the vault; can't be overridden")
    for param in cred.authorize_params:
        if param.lower() == "scope":
            report.error(f"{path}.authorize_params.{param}", "use the scope field")
        elif param.lower() in ("request", "request_uri"):
            report.error(
                f"{path}.authorize_params.{param}",
                "request objects aren't supported; one could carry a different redirect_uri",
            )
        elif param.lower() in _AUTHORIZE_PARAMS:
            report.error(
                f"{path}.authorize_params.{param}", "set by the vault; can't be overridden"
            )
    for header in cred.token_headers:
        name = header.lower()
        if name in _TOKEN_HEADERS or name.startswith("x-zoeymcp-"):
            report.error(f"{path}.token_headers.{header}", f"{header!r} is set by the vault")


def _check_oauth_scopes(path: str, cred: OAuth2Credential, report: _Report) -> None:
    if cred.authorize_url is not None and not cred.effective_expected_scopes:
        report.warning(f"{path}.expected_scopes", "granted scopes can't be checked")
    if cred.expected_scopes:
        expected = set(cred.expected_scopes)
        for scope in split_scope(cred.scope, cred.scope_separator):
            if scope not in expected:
                report.warning(
                    f"{path}.scope", f"requested scope {scope!r} isn't in expected_scopes"
                )


def _check_resources(path: str, cred: OAuth2Credential, origins: set[str], report: _Report) -> None:
    for field, params in (
        ("extra_params", cred.extra_params),
        ("authorize_params", cred.authorize_params),
    ):
        for value in param_values(params.get("resource", [])):
            if not _RESOURCE.match(value):
                report.error(
                    f"{path}.{field}.resource",
                    f"{value!r} must be an absolute URI without a fragment (RFC 8707)",
                )
    r_path = f"{path}.extra_params.resource"
    if "resource" not in cred.extra_params:
        return
    for value in param_values(cred.extra_params["resource"]):
        scheme = urlsplit(value).scheme
        if scheme == "http":
            report.warning(r_path, f"{value!r} uses plain http")
        if scheme in _DEFAULT_PORTS and _origin(value) not in origins:
            report.warning(
                r_path, f"{value!r} isn't the origin of a route that uses this credential"
            )
    if cred.authorize_url is not None and "resource" not in cred.authorize_params:
        report.warning(r_path, "RFC 8707: send it on the authorization request too")


# --- routes ------------------------------------------------------------------------------------


def _check_routes(policy: Policy, report: _Report) -> None:
    names: dict[str, int] = {}
    prefixes: dict[str, int] = {}
    mcp_routes = _remote_routes(policy)
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
        if route.connector is not None:
            _check_connector_rules(path, route, report)
        _check_route_query(policy, path, route, report)


def _remote_routes(policy: Policy) -> set[str]:
    """The routes remote gateway servers speak MCP through."""
    return {
        s.route
        for s in (policy.gateway.servers.values() if policy.gateway else ())
        if isinstance(s, RemoteServer)
    }


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


def _check_connector_rules(path: str, route: Route, report: _Report) -> None:
    for r_index, rule in enumerate(route.rules):
        extra = sorted(
            f"{method} {pattern}"
            for method in rule.methods
            for pattern in rule.paths
            if (method, pattern) not in _CONNECTOR_ENDPOINTS
        )
        if extra:
            report.error(
                f"{path}.rules[{r_index}]",
                f"a connector answers only GET /config and POST /send, not {', '.join(extra)}",
            )


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
    # Clients are compared by hash, so a literal token matches another client's token_sha256.
    clients: dict[str, list[str]] = defaultdict(list)
    literals: dict[str, list[str]] = defaultdict(list)
    if policy.gateway is not None:
        for name, client in policy.gateway.clients.items():
            if client.token is None:
                clients[client.token_hash].append(f"gateway.clients.{name}.token_sha256")
                continue
            path = f"gateway.clients.{name}.token"
            clients[client.token_hash].append(path)
            literals[client.token].append(path)
            report.warning(
                path,
                "anyone who reads the policy can act as this client; "
                "use token_sha256 (zoeymcp client-token)",
            )

    for value, paths in [*placeholders.items(), *literals.items()]:
        if len(value) < MIN_TOKEN_LENGTH:
            for p in paths:
                report.warning(p, f"shorter than {MIN_TOKEN_LENGTH} characters, so easy to guess")
    for value, paths in placeholders.items():
        digest = hash_token(value)
        if digest in clients:
            for p in paths + clients[digest]:
                report.error(p, "the same value is used as a placeholder and a client token")
        elif len(paths) > 1:
            for p in paths:
                report.warning(p, "placeholder reused on several routes; give each client its own")
    for paths in clients.values():
        if len(paths) > 1:
            for p in paths:
                report.error(p, "two clients share a token")


# --- the portal --------------------------------------------------------------------------------


def _check_admin(admin: Admin, report: _Report) -> None:
    first: dict[str, int] = {}
    for index, origin in enumerate(admin.origins):
        # Origins are in browser form (schema), so equal origins are equal strings.
        if origin in first:
            report.error(
                f"admin.origins[{index}]", f"duplicate origin (also admin.origins[{first[origin]}])"
            )
        first.setdefault(origin, index)
    host, port = _split_host_port(admin.listen)
    if not _loopback_or_wildcard(host):
        return  # reached by its own address, perhaps through a proxy
    ports: set[int] = set()
    for origin in admin.origins:
        parts = urlsplit(origin)
        if parts.hostname == "localhost":
            ports.add(parts.port or _DEFAULT_PORTS[parts.scheme])
    if port not in ports:
        report.warning(
            "admin.origins",
            f"no localhost origin uses admin.listen's port {port}: right only if the host "
            "publishes the portal on another port",
        )


def _split_host_port(value: str) -> tuple[str, int]:
    """``host:port`` or ``[ipv6]:port``, already checked by the schema."""
    host, _, port = value.rpartition(":")
    return host.removeprefix("[").removesuffix("]"), int(port)


def _loopback_or_wildcard(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False  # a name, such as a network alias
    return address.is_loopback or address.is_unspecified


# --- gateway -----------------------------------------------------------------------------------

_MCP_SERVER_PATH = re.compile(r"^/[A-Za-z0-9._~/-]*$")
# The methods the gateway sends on an MCP server's path.
_MCP_METHODS = ("POST", "GET", "DELETE")


def _check_gateway(policy: Policy, report: _Report) -> None:
    gateway = policy.gateway
    if gateway is None:
        return
    routes = {r.name: r for r in policy.routes}
    remote_routes = _remote_routes(policy)
    _check_clients(gateway, report)
    _check_approvals(gateway, report)
    assigned = {s for client in gateway.clients.values() for s in client.servers}
    server_paths: dict[str, list[NormalizedPath]] = defaultdict(list)
    for server in gateway.servers.values():
        if isinstance(server, RemoteServer):
            request_path = _request_path(server.path)
            if request_path is not None:
                server_paths[server.route].append(request_path)
    for name, server in gateway.servers.items():
        path = f"gateway.servers.{name}"
        if name not in assigned:
            report.warning(path, "not assigned to any client")
        if isinstance(server, RemoteServer):
            route = routes.get(server.route)
            if route is None:
                report.error(f"{path}.route", f"unknown route {server.route!r}")
            else:
                _check_mcp_route(path, server, route, server_paths[route.name], report)
        _check_stop_window(path, server, gateway.limits.call_timeout, report)
        if isinstance(server, RemoteServer | BridgeServer):
            _check_upstream_server(path, server, report)
            _check_tools(
                path, server.tools.include, server.tools.allow, server.tools.approve, report
            )
            _check_pins(path, server.tools.include, server.review, report)
        else:
            _check_toolkit(path, server, routes, remote_routes, report)
    limits = gateway.limits
    if limits.max_result_bytes > limits.max_upstream_message_bytes:
        report.error(
            "gateway.limits",
            f"max_result_bytes ({limits.max_result_bytes}) is larger than "
            f"max_upstream_message_bytes ({limits.max_upstream_message_bytes}), "
            "so a result that size could never arrive",
        )


def _check_toolkit(
    path: str,
    server: ToolkitServer,
    routes: Mapping[str, Route],
    remote_routes: set[str],
    report: _Report,
) -> None:
    _check_tools(path, server.tools.include, server.tools.allow, server.tools.approve, report)
    if server.pinning == "required":
        _check_pins(path, server.tools.include, server.review, report)
    else:  # off: pins would be ignored, so giving any is a mistake
        if server.review:
            report.error(f"{path}.review", "pins are given but pinning is off")
        report.warning(
            f"{path}.pinning",
            "definitions follow the image; a rebuild can change a tool without review",
        )
    for slot, binding in sorted(server.slots.items()):
        s_path = f"{path}.slots.{slot}"
        route = routes.get(binding.route)
        if route is None:
            report.error(f"{s_path}.route", f"unknown route {binding.route!r}")
            continue
        if any(c != "gateway" for c in route.callers):
            report.error(f"{s_path}.route", "a route a toolkit uses must accept only the gateway")
        if route.name in remote_routes:
            report.error(f"{s_path}.route", "a toolkit must not speak raw MCP to a reviewed server")
        for index, rule in enumerate(binding.rules):
            _check_toolkit_rule(f"{s_path}.rules[{index}]", rule, route, report)


def _check_toolkit_rule(path: str, rule: ToolkitRule, route: Route, report: _Report) -> None:
    for index, pattern in enumerate(rule.paths):
        try:
            parse_path_pattern(pattern)
        except PathPatternError as exc:
            report.error(f"{path}.paths[{index}]", f"{pattern!r}: {exc}")
    # Textual equality with one of the route's own rules: that rule's params then constrain
    # the captures. No containment between patterns is computed.
    for method in rule.methods:
        for pattern in rule.paths:
            if not any(method in r.methods and pattern in r.paths for r in route.rules):
                report.error(path, f"{method} {pattern}: the vault has no rule for this")
    if route.connector is not None:
        if "POST" in rule.methods and "/send" in rule.paths and not rule.approved:
            report.error(f"{path}.approved", "POST /send through a connector needs approved: true")
    elif any(m != "GET" for m in rule.methods) and not rule.approved:
        report.warning(path, "every tool of this toolkit can make this write without a prompt")
    if rule.approved and set(rule.methods) == {"GET"}:
        report.warning(f"{path}.approved", "has no effect on a GET")


def _check_stop_window(
    path: str, server: RemoteServer | BridgeServer | ToolkitServer, default: int, report: _Report
) -> None:
    timeout = server.call_timeout or default
    if server.tools.approve and timeout > STOP_WINDOW_CALL_TIMEOUT:
        where = f"{path}.call_timeout" if server.call_timeout else "gateway.limits.call_timeout"
        report.warning(
            where,
            f"an approved call may run {timeout} s and a stop waits for it, but the shipped "
            f"stop windows cover {STOP_WINDOW_CALL_TIMEOUT} s; raise stop_grace_period",
        )


def _check_clients(gateway: Gateway, report: _Report) -> None:
    for name, client in gateway.clients.items():
        path = f"gateway.clients.{name}.servers"
        if not client.servers:
            report.warning(path, "no servers: this client reaches nothing")
        for server_name in client.servers:
            server = gateway.servers.get(server_name)
            if server is None:
                report.error(path, f"unknown server {server_name!r}")
            elif isinstance(server, BridgeServer):
                report.warning(
                    path, f"{server_name!r} is a {server.kind} server: not served by this version"
                )


def _check_approvals(gateway: Gateway, report: _Report) -> None:
    approvals = gateway.approvals
    path = "gateway.approvals"
    if approvals.approver != "elicitation":
        report.error(f"{path}.approver", "telegram and portal approvers arrive in M8")
    elif approvals.timeout > MAX_ELICITATION_TIMEOUT:
        report.error(f"{path}.timeout", "a prompt can't outlive the client's tool call (§6.1)")
    elif approvals.timeout > 300:
        report.warning(
            f"{path}.timeout", "some clients end a tool call sooner; see the client notes"
        )
    if approvals.timeout >= gateway.limits.session_idle_timeout:
        report.error(
            f"{path}.timeout",
            f"must be below limits.session_idle_timeout ({gateway.limits.session_idle_timeout})",
        )
    for name, client in gateway.clients.items():
        c_path = f"gateway.clients.{name}"
        own = client.approvals
        if own is not None:
            if own.timeout is not None and own.timeout > approvals.timeout:
                report.error(f"{c_path}.approvals.timeout", "a client setting can only lower it")
            if own.budget_chars is not None and own.budget_chars > approvals.budget_chars:
                report.error(
                    f"{c_path}.approvals.budget_chars", "a client setting can only lower it"
                )
        if own is not None and own.attended:
            if not client.sources:
                report.warning(
                    f"{c_path}.sources",
                    "anyone holding this client's token can make calls and answer their "
                    "prompts, with or without confirm_code; keep the token out of the agent's "
                    "sandbox and pin a source",
                )
            continue
        asks = [
            s
            for s in client.servers
            if (server := gateway.servers.get(s)) is not None and server.tools.approve
        ]
        if asks:
            report.warning(
                c_path,
                f"not attended, but assigned {', '.join(repr(s) for s in asks)} with approve "
                "tools: they will always be refused",
            )


def _request_path(path: str) -> NormalizedPath | None:
    """A gateway server's ``path`` as the vault matches it, or ``None`` if the vault refuses it."""
    if not _MCP_SERVER_PATH.fullmatch(path):
        return None
    try:
        # The pattern above leaves out '*' and braces, so every segment is a literal.
        parsed = parse_path_pattern(path)
    except PathPatternError:
        return None
    return NormalizedPath(tuple(s.value for s in parsed.segments), parsed.trailing_slash)


def _reaches(rule: Rule, source: str, path: NormalizedPath) -> bool:
    """Whether the vault lets ``source`` (one of ``rule``'s paths) reach ``path``."""
    try:
        return path_matches(rule, source, path)
    except PathPatternError:
        return False  # reported with the route's rules


def _check_mcp_route(
    path: str,
    server: RemoteServer,
    route: Route,
    server_paths: list[NormalizedPath],
    report: _Report,
) -> None:
    """``server_paths`` are the valid paths of every gateway server on ``route``."""
    request_path = _request_path(server.path)
    if request_path is None:
        report.error(f"{path}.path", "must be a plain absolute path")
    if route.connector is not None:
        report.error(f"{path}.route", "points at a connector route, not an upstream")
        return
    if route.upstream is not None and urlsplit(route.upstream).scheme == "http":
        report.error(
            f"{path}.route", f"route {route.name!r} uses plain http: MCP over cleartext is refused"
        )
    if not route.stream:
        report.error(f"{path}.route", f"route {route.name!r} must set stream: true for MCP")
    if request_path is None:
        return
    # Rules match by pattern, exactly as the vault matches the gateway's requests.
    allowed = {
        method
        for rule in route.rules
        for source in rule.paths
        if _reaches(rule, source, request_path)
        for method in rule.methods
    }
    if "POST" not in allowed:
        report.error(
            f"{path}.path", f"route {route.name!r} has no rule allowing POST {server.path}"
        )
    missing = [f"{m} {server.path}" for m in ("GET", "DELETE") if m not in allowed]
    if missing:
        report.warning(
            f"{path}.path",
            f"route {route.name!r} has no rule allowing {' or '.join(missing)}: legacy servers "
            "use GET for notifications and DELETE to end a session",
        )
    unused: list[str] = []
    broad: list[str] = []
    for rule in route.rules:
        for source in rule.paths:
            used = any(_reaches(rule, source, p) for p in server_paths)
            # _reaches has parsed a used source. A pattern reaches more than the gateway's paths.
            pattern = used and any(s.kind != "literal" for s in parse_path_pattern(source).segments)
            for method in rule.methods:
                entry = f"{method} {source}"
                if method not in _MCP_METHODS or not used:
                    if entry not in unused:
                        unused.append(entry)
                elif pattern and entry not in broad:
                    broad.append(entry)
    if unused:
        report.warning(
            f"{path}.route",
            f"route {route.name!r} also allows {', '.join(unused)}; the gateway never uses them",
        )
    if broad:
        report.warning(
            f"{path}.route",
            f"route {route.name!r} allows {', '.join(broad)} by pattern; the gateway only uses "
            "its servers' exact paths, so list those instead",
        )


def _check_upstream_server(path: str, server: RemoteServer | BridgeServer, report: _Report) -> None:
    if server.enable:
        report.error(
            f"{path}.enable",
            "resources, prompts, completions, sampling, elicitation and roots can't be enabled "
            "yet; M3 serves tools only",
        )
    if server.shared_session:
        report.warning(
            f"{path}.shared_session",
            "legacy servers only: every client shares one upstream session, so server-side "
            "state leaks between agents",
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
    by_case: dict[str, list[str]] = defaultdict(list)
    for tool in sorted(included):
        by_case[tool.casefold()].append(tool)
    for names in by_case.values():
        if len(names) > 1:
            report.error(f"{path}.tools", f"{', '.join(map(repr, names))} differ only in case")
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
