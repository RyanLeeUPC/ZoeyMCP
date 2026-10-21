"""Onboarding by URL's decisions, as pure functions (M7 design B.4, D.2, D.2a, D.3, D.5).

Phase 1 of onboarding (``vault/onboard.py``) fetches; every decision about what it fetched is
here, so each rule is tested without a network:

- :func:`untrusted_url`: the only way a URL from the network enters the vault (B.4). A query is
  refused except on the two endpoints RFC 6749 3.1-3.2 let carry one (Q41), where it is kept
  byte for byte and may set none of the parameters the vault sets on that request.
  :func:`typed_url` is the same rule for a URL the operator types (the server URL, an issuer).
- :data:`MODERN_PROBE`, :data:`LEGACY_PROBE` and :func:`probe_next`: the two fixed POSTs that earn
  a 401 and its challenge, and what follows each answer (D.2).
- :func:`parse_challenge`: RFC 9110's ``WWW-Authenticate`` syntax, the Bearer challenges only.
  Anything unparsable is no challenge, never half-read.
- :func:`prm_candidates`, :func:`check_prm`: the protected-resource metadata and RFC 9728 3.3's
  resource rule, one exact rule per source, compared as strings.
- :func:`legacy_candidates`: D.2a's issuers for a server that publishes no such metadata.
- :func:`choose_issuer`, :func:`as_candidates`, :func:`check_as_metadata`: the authorization
  server's metadata, its ``issuer`` equal byte for byte to the issuer the URL was built from.
- :func:`select_scopes` and :func:`build_plan`: the scopes in MCP's order, and the plan the
  operator confirms (D.8's discovery part).

Nothing here does I/O or reads a clock. A refusal is a :class:`Refusal` value, never an
exception: its ``reason`` is M.2's, and the portal's catalogue (``portal/refusals.py``) words it.
Every pattern is used with ``fullmatch``.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal
from urllib.parse import urlsplit

from ... import __version__
from ...common.netguard import entry_key, untrusted_host
from ...common.policy import fields
from ...common.policy.fields import URL_MAX
from ...common.policy.match import RequestRejected, normalize_path
from ...common.policy.schema import _SCOPE_TOKEN, MAX_SCOPES, _check_url
from ...common.textrules import reveal_hidden
from ...portal.display import shown
from .protocol import safe_error_code

# --- limits (M.6) ------------------------------------------------------------------------------

METADATA_MAX: Final = 64 * 1024
REGISTRATION_MAX: Final = 16 * 1024
CHALLENGE_MAX: Final = 4 * 1024
# The most authorization servers a protected-resource document may name.
MAX_ISSUERS: Final = 8
RESOURCE_NAME_MAX: Final = 200
# The schema's cap on a credential's scope string, so the scopes chosen always load in diff 1.
SCOPE_TEXT_MAX: Final = 2048

PRM_WELL_KNOWN: Final = "/.well-known/oauth-protected-resource"
AS_WELL_KNOWN: Final = "/.well-known/oauth-authorization-server"
OIDC_WELL_KNOWN: Final = "/.well-known/openid-configuration"
PKCE_METHOD: Final = "S256"
OFFLINE_ACCESS: Final = "offline_access"

Reason = Literal[
    "url_invalid",
    "endpoint_invalid",
    "url_dollar",
    "challenge_ambiguous",
    "scope_invalid",
    "not_protected",
    "prm_not_found",
    "prm_invalid",
    "prm_resource_mismatch",
    "dpop_required",
    "as_choice_needed",
    "as_unknown",
    "as_metadata_not_found",
    "as_metadata_invalid",
    "as_issuer_mismatch",
    "pkce_unsupported",
    "code_flow_unsupported",
]
# The request an endpoint's query is for (Q41): only these two endpoints may carry one.
QueryFor = Literal["authorize", "token"]
PrmSource = Literal["challenge", "path", "root"]
IssuerSource = Literal["only", "chosen", "given", "origin", "heuristic"]
ScopeSource = Literal["challenge", "prm", "as", "as_too_many", "none"]
ProbeStep = Literal["challenge", "legacy", "well_known"]

_RESERVED: Final[Mapping[QueryFor, frozenset[str]]] = {
    "authorize": fields.AUTHORIZE_PARAMS,
    "token": fields.TOKEN_PARAMS,
}
_PRINTABLE = re.compile(r"[\x21-\x7e]+")
# A port as written: absent, or 1-65535 with no leading zero (urlsplit refuses one over 65535), so
# a URL names the host and port the plan shows, and no other spelling of them.
_PORT = re.compile(r"[1-9][0-9]{0,4}")
# A typed URL may name a private host when the operator ticks allow_private (Q4); a host browsers
# read as a number, or one with bad syntax, is refused even then.
_PRIVATE_HOST_REASONS: Final = frozenset({"ip_literal", "single_label", "internal_suffix"})


@dataclass(frozen=True)
class Refusal:
    """Why discovery stops. ``reason`` is M.2's; ``field`` names the member or URL it is about;
    ``why`` says what is wrong with it (for a URL: ``length``, ``characters``, ``fragment``,
    ``query``, ``query_invalid``, ``query_reserved``, ``url``, ``port``, ``host``, ``path`` or
    ``dollar``;
    for a document member: ``type`` or ``missing``); ``values`` are the strings it shows (the
    reserved parameter, both resources, the issuers, the candidates tried). A value from the
    network goes through ``display.shown`` where it is shown."""

    reason: Reason
    field: str = ""
    why: str = ""
    values: tuple[str, ...] = ()


# --- untrusted URLs (B.4) ----------------------------------------------------------------------


def untrusted_url(text: object, *, purpose: str, query: QueryFor | None = None) -> str | Refusal:
    """``text`` as a URL the vault may fetch or pin, unchanged, or why not (``endpoint_invalid``
    naming ``purpose``, or ``url_dollar``). ``query`` names the request an endpoint's query is for;
    without it a query is refused."""
    return _url(text, purpose, query, private_ok=False)


def typed_url(text: object, *, purpose: str, allow_private: bool = False) -> str | Refusal:
    """A URL the operator types (the server URL, an ``--issuer``): :func:`untrusted_url`'s rule
    with no query, refused as ``url_invalid``. ``allow_private`` lets the host be an IP literal,
    a single label or an internal name (Q4)."""
    url = _url(text, purpose, None, private_ok=allow_private)
    if isinstance(url, str):
        return url
    return Refusal("url_invalid", field=purpose, why=url.why or "dollar", values=url.values)


def _url(text: object, purpose: str, query: QueryFor | None, *, private_ok: bool) -> str | Refusal:
    if not isinstance(text, str) or len(text) > URL_MAX:
        return Refusal("endpoint_invalid", field=purpose, why="length")
    if not _PRINTABLE.fullmatch(text):
        return Refusal("endpoint_invalid", field=purpose, why="characters")
    # urlsplit reports a trailing "#" as no fragment and a trailing "?" as no query.
    if "#" in text:
        return Refusal("endpoint_invalid", field=purpose, why="fragment")
    if "?" in text:
        if query is None:
            return Refusal("endpoint_invalid", field=purpose, why="query")
        try:
            pairs = fields.endpoint_query(text.partition("?")[2])
        except ValueError:
            return Refusal("endpoint_invalid", field=purpose, why="query_invalid")
        for name, _ in pairs:
            if name in _RESERVED[query]:
                return Refusal(
                    "endpoint_invalid", field=purpose, why="query_reserved", values=(name,)
                )
    try:
        _check_url(text, schemes=("https",), allow_path=True, allow_query=query is not None)
    except ValueError as exc:
        return Refusal("endpoint_invalid", field=purpose, why="url", values=(str(exc),))
    parts = urlsplit(text)
    # The text after the host, past an IPv6 literal's brackets; _check_url refused user info.
    _, colon, port = parts.netloc.rpartition("]")[2].partition(":")
    if colon and not _PORT.fullmatch(port):
        return Refusal("endpoint_invalid", field=purpose, why="port")
    host = str(parts.hostname)  # _check_url refused a URL without one
    verdict = untrusted_host(host)
    allowed = verdict.allowed or (private_ok and verdict.reason in _PRIVATE_HOST_REASONS)
    if not allowed or "%" in host:  # a scoped IPv6 literal names an interface, not a host
        return Refusal("endpoint_invalid", field=purpose, why="host", values=(verdict.reason,))
    if parts.path:
        try:
            normalize_path(parts.path.encode("ascii"))
        except RequestRejected as exc:
            return Refusal("endpoint_invalid", field=purpose, why="path", values=(exc.reason,))
    if "$" in text:  # compose would read it as a variable in an inline policy (TI-1)
        return Refusal("url_dollar", field=purpose)
    return text


def origin_of(url: str) -> str:
    """``https://host[:port]`` of a URL :func:`untrusted_url` accepted, as written."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def _has_path(url: str) -> bool:
    """Whether a URL has a path beyond the ``/`` RFC 9728 3.1 drops after the host."""
    return urlsplit(url).path not in ("", "/")


# --- the probe (D.2) ---------------------------------------------------------------------------

MODERN_VERSION: Final = "2026-07-28"
LEGACY_VERSION: Final = "2025-11-25"
_CLIENT_INFO: Final = {"name": "zoeymcp", "version": __version__}


@dataclass(frozen=True)
class Probe:
    """One fixed, unauthenticated POST to the server URL: its body and every header it sends."""

    body: bytes
    headers: tuple[tuple[str, str], ...]


def _body(message: dict[str, object]) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("ascii")


# A well-formed modern request whose _meta version equals its header, so a server that checks
# headers before credentials still answers 401 with its challenge.
MODERN_PROBE: Final = Probe(
    body=_body(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "server/discover",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                    "io.modelcontextprotocol/clientInfo": _CLIENT_INFO,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        }
    ),
    headers=(
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", MODERN_VERSION),
        ("Mcp-Method", "server/discover"),
    ),
)
# Sent once, after a 400 to the modern probe: a 2025-06-18 or 2025-11-25 server refuses a version
# it doesn't know before it reads credentials.
LEGACY_PROBE: Final = Probe(
    body=_body(
        {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": LEGACY_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        }
    ),
    headers=(
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", LEGACY_VERSION),
    ),
)


def probe_next(status: int, *, legacy_sent: bool) -> ProbeStep:
    """What follows a probe's answer: a 401's challenge; one legacy probe after the first 400;
    otherwise the well-known candidates. A 2xx is no refusal: MCP doesn't require
    ``server/discover`` to be authenticated."""
    if status == 401:
        return "challenge"
    if status == 400 and not legacy_sent:
        return "legacy"
    return "well_known"


def moves_on(status: int, candidate: Candidate) -> bool:
    """Whether a metadata candidate's answer means "not here", so the next candidate is tried:
    404, 405 or 410, or a 3xx on a well-known candidate. Any other failure refuses, and a 3xx on
    the challenge's own ``resource_metadata`` URL is ``fetch_redirect`` (B.5)."""
    if 300 <= status < 400:
        return candidate.source != "challenge"
    return status in (404, 405, 410)


def prm_exhausted(tried: Sequence[str], *, probe_status: int) -> Refusal:
    """No protected-resource metadata and no legacy issuer: ``not_protected`` when the probe was
    answered without a sign-in (SPEC-1), else ``prm_not_found`` naming the URLs tried."""
    if 200 <= probe_status < 300:
        return Refusal("not_protected")
    return Refusal("prm_not_found", values=tuple(tried))


def as_exhausted(tried: Sequence[str]) -> Refusal:
    return Refusal("as_metadata_not_found", values=tuple(tried))


# --- the challenge (D.2) -----------------------------------------------------------------------

# One character each (RFC 9110 5.6.2, 5.6.4 and 11.2), matched by fullmatch, so "" (past the end)
# is in none of them. Without obs-text: a challenge is ASCII.
_TCHAR = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]")
_TOKEN68 = re.compile(r"[-._~+/0-9A-Za-z]")
_QDTEXT = re.compile(r"[\t !\x23-\x5b\x5d-\x7e]")
_QUOTED_PAIR = re.compile(r"[\t\x20-\x7e]")
_SPACE = re.compile(r"[ \t]")
_SEPARATORS = re.compile(r"[ \t,]")
# What may follow a challenge: the end of the value ("" from peek) or the next list element.
_END: Final = ("", ",")


@dataclass(frozen=True)
class Challenge:
    """What a Bearer challenge gives discovery, each part through its own rule."""

    resource_metadata: str | None
    scopes: tuple[str, ...]
    error: str | None


class _Unparsable(Exception):
    pass


class _Reader:
    """RFC 9110 11.6.1's ``WWW-Authenticate`` value, read left to right."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def peek(self, at: int = 0) -> str:
        """The character ``at`` ahead, or "" past the end, which no character class holds."""
        index = self.pos + at
        return self.text[index] if index < len(self.text) else ""

    def sees(self, chars: re.Pattern[str], at: int = 0) -> bool:
        return chars.fullmatch(self.peek(at)) is not None

    def done(self) -> bool:
        return self.pos >= len(self.text)

    def spaces(self) -> bool:
        start = self.pos
        while self.sees(_SPACE):
            self.pos += 1
        return self.pos > start

    def separators(self) -> None:
        """OWS and commas: a list may hold empty elements."""
        while self.sees(_SEPARATORS):
            self.pos += 1

    def token(self) -> str:
        start = self.pos
        while self.sees(_TCHAR):
            self.pos += 1
        if self.pos == start:
            raise _Unparsable
        return self.text[start : self.pos]

    def quoted(self) -> str:
        self.pos += 1  # the opening quote
        out: list[str] = []
        while True:
            char = self.peek()
            self.pos += 1
            if char == '"':
                return "".join(out)
            if char == "\\" and self.sees(_QUOTED_PAIR):
                out.append(self.peek())
                self.pos += 1
            elif _QDTEXT.fullmatch(char):
                out.append(char)
            else:
                raise _Unparsable

    def param_ahead(self) -> bool:
        """Whether an auth-param (``name = value``) starts here, not a token68 or a scheme. With
        no name before the "=", the caller's next read refuses the value either way."""
        at = 0
        while self.sees(_TCHAR, at):
            at += 1
        while self.sees(_SPACE, at):
            at += 1
        if self.peek(at) != "=":
            return False
        at += 1
        while self.sees(_SPACE, at):
            at += 1
        return self.peek(at) == '"' or self.sees(_TCHAR, at)

    def params(self) -> dict[str, str]:
        found: dict[str, str] = {}
        while True:
            name = self.token().lower()
            self.spaces()
            self.pos += 1  # the "=" param_ahead saw
            self.spaces()
            value = self.quoted() if self.peek() == '"' else self.token()
            if name in found:  # each name at most once per challenge (RFC 9110 11.2)
                raise _Unparsable
            found[name] = value
            self.spaces()
            if self.peek() != ",":
                return found
            comma = self.pos
            self.separators()
            if not self.param_ahead():
                self.pos = comma  # a new challenge, or the end
                return found

    def token68(self) -> None:
        start = self.pos
        while self.sees(_TOKEN68):
            self.pos += 1
        if self.pos == start:
            raise _Unparsable
        while self.peek() == "=":
            self.pos += 1


def _challenges(text: str) -> list[tuple[str, dict[str, str]]]:
    """Every challenge in one header value, its scheme in lower case; a token68 gives none."""
    reader = _Reader(text)
    found: list[tuple[str, dict[str, str]]] = []
    reader.separators()
    while not reader.done():
        scheme = reader.token().lower()
        params: dict[str, str] = {}
        if reader.spaces() and reader.peek() not in _END:
            if reader.param_ahead():
                params = reader.params()
            else:
                reader.token68()
        found.append((scheme, params))
        reader.spaces()
        if reader.peek() not in _END:
            raise _Unparsable
        reader.separators()
    return found


def _scope_tokens(tokens: Sequence[str]) -> tuple[str, ...] | Refusal:
    """Scope tokens learned from the network: the schema's token rule and no ``$`` (TI-1)."""
    for token in tokens:
        if not _SCOPE_TOKEN.fullmatch(token) or "$" in token:
            return Refusal("scope_invalid", values=(token,))
    return tuple(tokens)


def parse_challenge(values: Sequence[str]) -> Challenge | Refusal | None:
    """The Bearer challenge in a 401's ``WWW-Authenticate`` values, or None when there is none.
    The values are one list (RFC 9110 5.3): one over :data:`CHALLENGE_MAX` or that doesn't parse
    makes the whole field no challenge, never half-read, so no challenge in a bad value goes
    unseen. Two Bearer challenges naming different ``resource_metadata`` refuse; otherwise the
    one that names it (or the first) gives the scope and the error."""
    bearers: list[dict[str, str]] = []
    for value in values:
        if len(value) > CHALLENGE_MAX:
            return None
        try:
            parsed = _challenges(value)
        except _Unparsable:
            return None
        bearers.extend(params for scheme, params in parsed if scheme == "bearer")
    if not bearers:
        return None
    named = list(dict.fromkeys(p["resource_metadata"] for p in bearers if "resource_metadata" in p))
    if len(named) > 1:
        return Refusal("challenge_ambiguous", values=tuple(named))
    chosen = next((p for p in bearers if "resource_metadata" in p), bearers[0])
    resource_metadata = None
    if named:
        url = untrusted_url(named[0], purpose="resource_metadata")
        if isinstance(url, Refusal):
            return url
        resource_metadata = url
    scope = chosen.get("scope", "")
    tokens = scope.split(" ") if scope else []
    if len(tokens) > MAX_SCOPES:
        return Refusal("scope_invalid", why="too_many")
    scopes = _scope_tokens(tokens)
    if isinstance(scopes, Refusal):
        return scopes
    return Challenge(resource_metadata, scopes, safe_error_code(chosen.get("error")))


# --- protected-resource metadata (D.2, D.3) ----------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    """A metadata URL to fetch, where it comes from, and for an authorization server's
    metadata the issuer it was built from."""

    url: str
    source: str
    issuer: str | None = None


@dataclass(frozen=True)
class Prm:
    """A checked protected-resource document. ``resource_name`` is for display only, already
    through ``display.shown``."""

    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: tuple[str, ...] | None
    resource_name: str | None
    source: PrmSource


def prm_candidates(server_url: str, challenge: Challenge | None) -> tuple[Candidate, ...]:
    """The challenge's ``resource_metadata`` alone when it names one; else the path form (when
    the server URL has a path) and then the root form (RFC 9728 3.1)."""
    if challenge is not None and challenge.resource_metadata is not None:
        return (Candidate(challenge.resource_metadata, "challenge"),)
    origin = origin_of(server_url)
    root = Candidate(f"{origin}{PRM_WELL_KNOWN}", "root")
    if not _has_path(server_url):
        return (root,)
    return (Candidate(f"{origin}{PRM_WELL_KNOWN}{urlsplit(server_url).path}", "path"), root)


def expected_resources(source: PrmSource, server_url: str) -> tuple[str, ...]:
    """RFC 9728 3.3, one exact rule per source (Q23): the server URL as typed, or for the root
    form its origin in the two spellings RFC 9728's examples use."""
    if source == "root":
        origin = origin_of(server_url)
        return (origin, f"{origin}/")
    return (server_url,)


def _strings(doc: Mapping[str, object], name: str) -> tuple[str, ...] | Literal[False] | None:
    """A member that is a list of strings; None when absent or null, False when it isn't one."""
    value = doc.get(name)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return False
    return tuple(value)


def _flag(doc: Mapping[str, object], name: str) -> bool | None:
    """A boolean member, false when absent; None when it isn't a boolean."""
    value = doc.get(name, False)
    return value if isinstance(value, bool) else None


def check_prm(doc: object, source: PrmSource, server_url: str) -> Prm | Refusal:
    """A protected-resource document fetched from a ``source`` candidate for ``server_url``.
    Unknown members and ``signed_metadata`` are ignored (RFC 9728 7.9)."""
    if not isinstance(doc, dict):
        return Refusal("prm_invalid", why="type")
    resource = doc.get("resource")
    if not isinstance(resource, str):
        return Refusal("prm_invalid", field="resource", why="missing")
    checked = untrusted_url(resource, purpose="resource")
    if isinstance(checked, Refusal):
        return checked
    expected = expected_resources(source, server_url)
    if resource not in expected:
        return Refusal("prm_resource_mismatch", field="resource", values=(resource, expected[0]))
    servers = _strings(doc, "authorization_servers")
    if not servers or len(servers) > MAX_ISSUERS:
        return Refusal("prm_invalid", field="authorization_servers", why="type")
    issuers: list[str] = []
    for server in servers:
        issuer = untrusted_url(server, purpose="authorization_servers")
        if isinstance(issuer, Refusal):
            return issuer
        if issuer not in issuers:
            issuers.append(issuer)
    supported = _strings(doc, "scopes_supported")
    if supported is False:
        return Refusal("prm_invalid", field="scopes_supported", why="type")
    scopes = None if supported is None else _scope_tokens(supported)
    if isinstance(scopes, Refusal):
        return scopes
    dpop = _flag(doc, "dpop_bound_access_tokens_required")
    if dpop is None:
        return Refusal("prm_invalid", field="dpop_bound_access_tokens_required", why="type")
    if dpop:  # D-19: the vault sends Bearer tokens only
        return Refusal("dpop_required")
    name = doc.get("resource_name")
    if name is not None and not isinstance(name, str):
        return Refusal("prm_invalid", field="resource_name", why="type")
    shown_name = None if name is None else shown(name, RESOURCE_NAME_MAX)
    return Prm(resource, tuple(issuers), scopes, shown_name, source)


# --- the issuer (D.2a, D.3) --------------------------------------------------------------------

# How each legacy candidate is labelled in the plan (D.2a).
LEGACY_LABELS: Final[Mapping[str, str]] = {
    "given": "the issuer you gave (MCP's pre-configured values)",
    "origin": "the server URL's origin (MCP 2025-03-26's rule)",
    "heuristic": "found by a ZoeyMCP heuristic, not by any MCP rule",
}
ISSUER_LABELS: Final[Mapping[str, str]] = {
    "only": "the one the server names",
    "chosen": "the one you chose of those the server names",
    **LEGACY_LABELS,
}


def choose_issuer(servers: Sequence[str], named: str | None) -> str | Refusal:
    """The issuer to use (DD-9): the only one, or the one the operator named, which must be in
    the list; several and none named stops at ``as_choice_needed``, listing them."""
    if named is not None:
        return named if named in servers else Refusal("as_unknown", values=tuple(servers))
    if len(servers) > 1:
        return Refusal("as_choice_needed", values=tuple(servers))
    return servers[0]


def as_candidates(issuer: str) -> tuple[str, ...]:
    """The metadata URLs for ``issuer``, in MCP's order (2025-11-25, 2026-07-28): RFC 8414's
    path-inserted form, then OpenID Connect's two. A terminating ``/`` of the path is removed
    first (RFC 8414 3.1)."""
    origin = origin_of(issuer)
    path = urlsplit(issuer).path.removesuffix("/")
    if not path:
        return (f"{origin}{AS_WELL_KNOWN}", f"{origin}{OIDC_WELL_KNOWN}")
    return (
        f"{origin}{AS_WELL_KNOWN}{path}",
        f"{origin}{OIDC_WELL_KNOWN}{path}",
        f"{origin}{path}{OIDC_WELL_KNOWN}",
    )


def legacy_candidates(server_url: str, issuer_choice: str | None) -> tuple[Candidate, ...]:
    """D.2a's candidates for a server with no protected-resource metadata, each with the issuer
    its metadata must name: the operator's issuer alone; otherwise the server URL's origin, then
    (when it has a path) the server URL itself, a ZoeyMCP heuristic outside every MCP revision."""
    if issuer_choice is not None:
        return tuple(Candidate(url, "given", issuer_choice) for url in as_candidates(issuer_choice))
    origin = origin_of(server_url)
    found = [Candidate(url, "origin", origin) for url in as_candidates(origin)]
    if _has_path(server_url):
        found += [Candidate(url, "heuristic", server_url) for url in as_candidates(server_url)]
    return tuple(found)


# --- authorization server metadata (D.3) -------------------------------------------------------


@dataclass(frozen=True)
class AsMetadata:
    """A checked authorization server document. ``notes`` are informational: ``cimd``,
    ``dpop`` and ``iss_not_advertised``."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str | None
    revocation_endpoint: str | None
    require_iss: bool
    scopes_supported: tuple[str, ...] | None
    token_auth_methods: tuple[str, ...]
    revocation_auth_methods: tuple[str, ...] | None
    notes: tuple[str, ...]


# The list members of an authorization server document, each a list of strings when present.
_AS_LISTS: Final = (
    "response_types_supported",
    "code_challenge_methods_supported",
    "grant_types_supported",
    "token_endpoint_auth_methods_supported",
    "revocation_endpoint_auth_methods_supported",
    "scopes_supported",
)


def _endpoint(
    doc: Mapping[str, object], name: str, query: QueryFor | None = None
) -> str | Refusal | None:
    """An endpoint member through :func:`untrusted_url`; None when absent or null."""
    value = doc.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        return Refusal("as_metadata_invalid", field=name, why="type")
    return untrusted_url(value, purpose=name, query=query)


def check_as_metadata(doc: object, issuer: str) -> AsMetadata | Refusal:
    """An authorization server document fetched for ``issuer``, checked in D.3's order. A query
    is kept on the authorization and token endpoints (Q41); every other URL refuses one, and an
    invalid optional endpoint refuses rather than being dropped."""
    if not isinstance(doc, dict):
        return Refusal("as_metadata_invalid", why="type")
    named = doc.get("issuer")
    if not isinstance(named, str):
        return Refusal("as_metadata_invalid", field="issuer", why="missing")
    if named != issuer:  # RFC 8414 3.3: byte for byte, no trailing-slash leniency
        return Refusal("as_issuer_mismatch", field="issuer", values=(named, issuer))
    authorize = _endpoint(doc, "authorization_endpoint", "authorize")
    if not isinstance(authorize, str):
        return authorize or Refusal(
            "as_metadata_invalid", field="authorization_endpoint", why="missing"
        )
    token = _endpoint(doc, "token_endpoint", "token")
    if not isinstance(token, str):
        return token or Refusal("as_metadata_invalid", field="token_endpoint", why="missing")
    lists: dict[str, tuple[str, ...] | None] = {}
    for name in _AS_LISTS:
        value = _strings(doc, name)
        if value is False:
            return Refusal("as_metadata_invalid", field=name, why="type")
        lists[name] = value
    responses = lists["response_types_supported"]
    methods = lists["code_challenge_methods_supported"]
    grants = lists["grant_types_supported"]
    token_auth = lists["token_endpoint_auth_methods_supported"]
    revocation_auth = lists["revocation_endpoint_auth_methods_supported"]
    supported = lists["scopes_supported"]
    if not responses or "code" not in responses:
        return Refusal("code_flow_unsupported", field="response_types_supported")
    if not methods or PKCE_METHOD not in methods:  # MCP: absent means no PKCE, so refuse
        return Refusal("pkce_unsupported")
    if grants is not None and "authorization_code" not in grants:
        return Refusal("code_flow_unsupported", field="grant_types_supported")
    registration = _endpoint(doc, "registration_endpoint")
    if isinstance(registration, Refusal):
        return registration
    revocation = _endpoint(doc, "revocation_endpoint")
    if isinstance(revocation, Refusal):
        return revocation
    require_iss = _flag(doc, "authorization_response_iss_parameter_supported")
    if require_iss is None:
        return Refusal(
            "as_metadata_invalid",
            field="authorization_response_iss_parameter_supported",
            why="type",
        )
    scopes = None if not supported else _scope_tokens(supported)
    if isinstance(scopes, Refusal):
        return scopes
    notes = tuple(
        note
        for note, on in (
            ("cimd", doc.get("client_id_metadata_document_supported") is True),
            ("dpop", doc.get("dpop_signing_alg_values_supported") is not None),
            ("iss_not_advertised", not require_iss),
        )
        if on
    )
    return AsMetadata(
        issuer=issuer,
        authorization_endpoint=authorize,
        token_endpoint=token,
        registration_endpoint=registration,
        revocation_endpoint=revocation,
        require_iss=require_iss,
        scopes_supported=scopes,
        token_auth_methods=token_auth or ("client_secret_basic",),  # RFC 8414 2's default
        revocation_auth_methods=revocation_auth or None,
        notes=notes,
    )


# --- scopes (D.5) ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scopes:
    """The scopes to request, where they came from, and whether ``offline_access`` was added."""

    scopes: tuple[str, ...]
    source: ScopeSource
    offline_access_added: bool


def select_scopes(
    challenge: Challenge | None, prm: Prm | None, as_meta: AsMetadata
) -> Scopes | Refusal:
    """MCP's order: the challenge's ``scope``, else the protected resource's
    ``scopes_supported``, else none. Without protected-resource metadata (D.2a) the authorization
    server's ``scopes_supported`` take the second place, for the operator to narrow; a list longer
    than a credential holds is requested not at all (``as_too_many``) rather than refused, so the
    operator still sees the plan and names the scopes. ``offline_access`` is added when the
    authorization server lists it: login refuses a grant without a refresh token. The result
    fits the schema's scope field, so diff 1 loads."""
    scopes: tuple[str, ...] = ()
    source: ScopeSource = "none"
    if challenge is not None and challenge.scopes:
        scopes, source = challenge.scopes, "challenge"
    elif prm is not None and prm.scopes_supported:
        scopes, source = prm.scopes_supported, "prm"
    elif prm is None and as_meta.scopes_supported:
        scopes, source = as_meta.scopes_supported, "as"
        if not _fits(scopes):
            scopes, source = (), "as_too_many"
    offered = as_meta.scopes_supported or ()
    added = OFFLINE_ACCESS in offered and OFFLINE_ACCESS not in scopes
    if added:
        scopes = (*scopes, OFFLINE_ACCESS)
    if not _fits(scopes):
        return Refusal("scope_invalid", why="too_many")
    return Scopes(scopes, source, added)


def _fits(scopes: tuple[str, ...]) -> bool:
    """Whether scopes fit the schema's scope field: 64 tokens, 2,048 characters with spaces."""
    return len(scopes) <= MAX_SCOPES and len(" ".join(scopes)) <= SCOPE_TEXT_MAX


# --- the plan (D.8's discovery part) -----------------------------------------------------------

NOTES: Final[Mapping[str, str]] = {
    "legacy": "This server publishes no protected-resource metadata; the authorization server "
    "was found without it (D.2a).",
    "heuristic": "The authorization server was found by a ZoeyMCP heuristic, not by any MCP "
    "rule. Confirm it is the one you expect.",
    "root_resource": "The server publishes its metadata for its whole origin, not for this URL.",
    "offline_access_added": "offline_access was added: the authorization server lists it, and "
    "login needs a refresh token.",
    "cimd": "The authorization server registers clients by metadata document, which ZoeyMCP "
    "doesn't support yet.",
    "dpop": "The authorization server offers DPoP; ZoeyMCP uses Bearer tokens.",
    "iss_not_advertised": "The authorization server doesn't say it sends iss with its answers, "
    "so a missing iss isn't refused.",
}
SCOPE_SOURCES: Final[Mapping[str, str]] = {
    "challenge": "from the server's challenge",
    "prm": "from the server's protected-resource metadata",
    "as": "from the authorization server's list, for you to narrow",
    "as_too_many": "the authorization server lists more than a credential holds (64 scopes, "
    "2,048 characters), so none of its list is requested: name the ones you need",
    "none": "none named",
}


@dataclass(frozen=True)
class Plan:
    """What discovery found, for the operator to confirm: every value a validated URL, a scope
    token, or ``resource_name`` through ``display.shown``. ``hosts`` are the ``host:port`` the
    vault contacted or will contact (the browser alone opens the authorization endpoint)."""

    server_url: str
    resource: str
    resource_metadata: str | None
    resource_name: str | None
    issuer: str
    issuer_source: IssuerSource
    metadata_url: str
    metadata: AsMetadata
    scopes: Scopes
    hosts: tuple[str, ...]
    notes: tuple[str, ...]

    def rows(self) -> tuple[tuple[str, str], ...]:
        """The plan as label and value rows, each value revealed. An endpoint's query shows as
        written, byte for byte, as fragment 1 will hold it (Q41)."""
        meta = self.metadata
        found = [
            ("Server", self.server_url),
            ("Resource", self.resource),
            ("Resource metadata", self.resource_metadata or "none (D.2a)"),
            ("Issuer", f"{self.issuer} ({ISSUER_LABELS[self.issuer_source]})"),
            ("Issuer metadata", self.metadata_url),
            ("Authorization endpoint", meta.authorization_endpoint),
            ("Token endpoint", meta.token_endpoint),
            ("Registration endpoint", meta.registration_endpoint or "none"),
            ("Revocation endpoint", meta.revocation_endpoint or "none"),
            ("Requires iss", "yes" if meta.require_iss else "no"),
            ("PKCE", PKCE_METHOD),
            (
                "Scopes",
                f"{' '.join(self.scopes.scopes) or 'none'} ({SCOPE_SOURCES[self.scopes.source]})",
            ),
            ("Hosts", ", ".join(self.hosts)),
        ]
        if self.resource_name is not None:
            found.insert(2, ("Resource name", self.resource_name))
        found += [("Note", NOTES[note]) for note in self.notes]
        return tuple((label, reveal_hidden(value)) for label, value in found)


def _host_port(url: str) -> str:
    parts = urlsplit(url)
    return entry_key(str(parts.hostname), parts.port if parts.port is not None else 443)


def build_plan(
    server_url: str,
    *,
    challenge: Challenge | None,
    prm: Prm | None,
    resource_metadata: str | None,
    issuer_source: IssuerSource,
    metadata_url: str,
    metadata: AsMetadata,
) -> Plan | Refusal:
    """The plan from what discovery checked. Without protected-resource metadata (``prm`` None,
    D.2a) the resource is the server URL as typed and ``resource_metadata`` stays unset; with
    it, the resource is the document's ``resource`` exactly (D.5)."""
    scopes = select_scopes(challenge, prm, metadata)
    if isinstance(scopes, Refusal):
        return scopes
    contacted = [server_url, metadata_url, metadata.token_endpoint]
    contacted += [
        url
        for url in (resource_metadata, metadata.registration_endpoint, metadata.revocation_endpoint)
        if url is not None
    ]
    notes = [
        note
        for note, on in (
            ("legacy", prm is None),
            ("heuristic", issuer_source == "heuristic"),
            ("root_resource", prm is not None and prm.source == "root"),
            ("offline_access_added", scopes.offline_access_added),
        )
        if on
    ]
    return Plan(
        server_url=server_url,
        resource=server_url if prm is None else prm.resource,
        resource_metadata=None if prm is None else resource_metadata,
        resource_name=None if prm is None else prm.resource_name,
        issuer=metadata.issuer,
        issuer_source=issuer_source,
        metadata_url=metadata_url,
        metadata=metadata,
        scopes=scopes,
        hosts=tuple(dict.fromkeys(_host_port(url) for url in contacted)),
        notes=(*notes, *metadata.notes),
    )
