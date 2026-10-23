"""Field rules the policy schema calls (M7 design A.1, COV-2). Pure and mutation-tested, so the
decisions M7 adds to the schema are tested without putting all of ``schema.py`` in mutation.

- :func:`host_port_lower`: an ``egress_private`` entry is in lower case, since the egress role
  and the address guard compare entries as written (CR-13).
- :func:`is_squid_acl_name`: a Squid source ACL name in ``egress_proxy_acls`` (OPS-7).
- :func:`is_numeric_label` and :func:`is_mail_address`: the portal origin's last-label rule and a
  connector's mail address, moved here so they are mutation-tested (COV-2) and whole-value
  (D-138: ``$`` also matches before a final line break, so ``.match`` let one through).
- :func:`client_host`: a URL's host as the vault's HTTP client sends it (httpx's ``raw_host``),
  so the egress lists and ``check`` key a destination as the address guard does (D-190).
- :func:`endpoint_query` and :func:`check_endpoint_query`: the query a ``token_url`` or an
  ``authorize_url`` may carry (Q41). RFC 6749 3.1-3.2 say such a query MUST be kept when the
  client adds its parameters, so the vault keeps it byte for byte and puts its own after it; the
  endpoint may set none of the parameters the vault sets on that request (:data:`TOKEN_PARAMS`,
  :data:`AUTHORIZE_PARAMS`), nor one the credential's own params set.
- :func:`no_bridge_kind` and :data:`NO_BRIDGE_KIND`: a server written ``kind: bridge``, refused
  with what to write instead, since a bridge is an upstream: a remote server behind a route.
- :func:`unix_upstream`, :func:`bridge_name` and :func:`bridge_socket`: a route's ``unix:``
  upstream, a standard-tier bridge's socket (Q46). Only the one fixed form is taken, so a route
  can't name any other socket in the container (the vault's admin socket, the link socket).
- :func:`reserved_env` and :data:`VAULT_ONLY_ENV`: ZoeyMCP's own environment variables. No
  ``env:`` reference may name one (``check``, by the prefix), and the gateway refuses to start
  with the vault's three in its environment (its own ``ZOEYMCP_GATEWAY_KEY`` and the bridges'
  variables pass that check, so it names the three, not the prefix).

Every pattern here is used with ``fullmatch``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Set
from typing import Final
from urllib.parse import parse_qsl

import idna

# The longest token_url or authorize_url, query or not. Here because common can't import vault
# code; discovery (M7 design B.4) uses the same cap for every URL it learns.
URL_MAX: Final = 2048
MAX_QUERY_PARAMS: Final = 16
# RFC 3986 3.4's query characters: unreserved, a %HH escape, the sub-delims ! ( ) * + , = & and
# : @ / ?. Not "$" (compose interpolates it in an inline policy), ";" (a server that also splits on
# it would read a parameter parse_qsl doesn't) or "'" (browsers re-encode it in an https query).
# httpx and browsers send every one of these as written, so the query reaches the server unchanged.
_QUERY = re.compile(r"(?:[A-Za-z0-9._~!()*+,=&:@/?-]|%[0-9A-Fa-f]{2})+")
# The schema's QueryParam. A name is checked as written, so no escape can spell a reserved one.
_QUERY_NAME = re.compile(r"[A-Za-z0-9._~-]{1,128}")
_SQUID_ACL_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
# A host label browsers parse as a number (WHATWG URL's "ends in a number"). netguard keeps a copy,
# since the egress role may import only the standard library; test_netguard.py pins them equal.
_NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")
_ADDRESS = re.compile(r"[^@\s<>\"]{1,64}@[A-Za-z0-9.-]{1,253}")
# A standard-tier bridge's socket: its name is the launcher's bridge name pattern (C.10).
UNIX_PREFIX: Final = "unix:"
_UNIX_UPSTREAM = re.compile(r"unix:/run/zoeymcp-bridge-([a-z0-9]{1,16})/mcp\.sock")
UNIX_UPSTREAM_FORM: Final = (
    "a unix: upstream is a standard-tier bridge's socket, unix:/run/zoeymcp-bridge-<name>/mcp.sock"
)

# Every variable ZoeyMCP reads starts with this: the master keys, the policy, the gateway's key, the
# bridges' variables, and any later one.
RESERVED_ENV_PREFIX: Final = "ZOEYMCP_"
# What the gateway's environment must never hold: the vault's master keys and its policy.
VAULT_ONLY_ENV: Final = ("ZOEYMCP_MASTER_KEY", "ZOEYMCP_MASTER_KEY_PREVIOUS", "ZOEYMCP_CONFIG")

# The names the vault sets on a token request (protocol._build), resource (which onboarding sets),
# and those that compete with the client authentication the vault sends (RFC 7521, RFC 7523).
TOKEN_PARAMS: Final = frozenset(
    {
        "grant_type",
        "code",
        "redirect_uri",
        "code_verifier",
        "refresh_token",
        "client_id",
        "client_secret",
        "scope",
        "resource",
        "client_assertion",
        "client_assertion_type",
    }
)
# The names the vault sets on the authorization request (pkce.authorize_url), resource, and those
# that change how the server reads the vault's own: a request object or its URI replaces every
# parameter beside it (RFC 9101, RFC 9126), and response_mode moves the code to where the redirect
# parser refuses it or never sees it.
AUTHORIZE_PARAMS: Final = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "scope",
        "resource",
        "request",
        "request_uri",
        "response_mode",
    }
)

# The refusal of a kind: bridge server, at its kind. The route's upstream is the old url's origin
# alone: the vault appends the server's path to the upstream's, so an upstream carrying the old
# /mcp would send /mcp/mcp.
NO_BRIDGE_KIND: Final = (
    "kind: bridge is gone: a bridge is an upstream. Write kind: remote with route: <r> and "
    "path: <the old url's path>; route <r> has upstream: <the old url's scheme://host:port>, "
    "callers: [gateway], stream: true, rules allowing POST, GET and DELETE on that path, and a "
    "header credential holding the bridge's token. For plain http add allow_insecure_upstream: "
    "true; that works only to a loopback or private address or a single-label name, otherwise "
    "use https; a bridge under the standard launcher is upstream: "
    "unix:/run/zoeymcp-bridge-<name>/mcp.sock instead. Move egress to <r>'s program.egress "
    "(operations.md, 'A stdio server behind a bridge')"
)


def host_port_lower(value: str) -> str:
    """The lower-case rule for a ``host:port`` the schema has already checked."""
    if value != value.lower():
        raise ValueError("write host:port in lower case: the egress role compares it as written")
    return value


def client_host(host: str) -> str:
    """A URL's host (``urlsplit().hostname``: in lower case, without brackets) as the vault's
    HTTP client connects to it and names it in a ``CONNECT``: httpx's ``raw_host``, which writes
    an internationalized name in its IDNA 2008 ``xn--`` form, encoded as httpx encodes it. A
    name IDNA refuses stays as it is: the client can't connect to it at all."""
    if host.isascii():
        return host
    try:
        return idna.encode(host).decode("ascii")
    except idna.IDNAError:
        return host


def reserved_env(name: str) -> bool:
    """Whether ``name`` is one of ZoeyMCP's own environment variables, which no secret may come
    from. In any case: Windows reads its environment so, and ``env:zoeymcp_master_key`` there is
    the master key."""
    return name.upper().startswith(RESERVED_ENV_PREFIX)


def is_squid_acl_name(value: str) -> bool:
    return _SQUID_ACL_NAME.fullmatch(value) is not None


def is_numeric_label(label: str) -> bool:
    """Whether a host's label is one browsers read as a number (so the host is an IPv4 address)."""
    return _NUMERIC_LABEL.fullmatch(label) is not None


def is_mail_address(address: str) -> bool:
    """The address part of a mailbox, as ``email.utils.parseaddr`` returns it."""
    return _ADDRESS.fullmatch(address) is not None


def endpoint_query(query: str) -> tuple[tuple[str, str], ...]:
    """The parameters of an endpoint's query (the text after ``?``), parsed; a ``ValueError`` for
    a query this rule refuses. The text itself is never re-encoded: the caller keeps it."""
    if not _QUERY.fullmatch(query):
        raise ValueError("a query may hold letters, digits, %HH escapes and -._~!()*+,=&:@/? only")
    try:
        pairs = parse_qsl(query, strict_parsing=True, keep_blank_values=True, errors="strict")
    except ValueError:  # a pair without "=", an empty pair, an escape that isn't UTF-8
        raise ValueError("a query is name=value pairs joined by &, each escape UTF-8") from None
    if len(pairs) > MAX_QUERY_PARAMS:
        raise ValueError(f"a query has at most {MAX_QUERY_PARAMS} parameters")
    seen: set[str] = set()
    for part in query.split("&"):
        name = part.partition("=")[0]
        if not _QUERY_NAME.fullmatch(name):
            raise ValueError(
                f"query parameter {name!r}: a name is 1 to 128 letters, digits or -._~, "
                "with no escapes"
            )
        if name in seen:
            raise ValueError(f"the query sets {name} twice")
        seen.add(name)
    return tuple(pairs)


def no_bridge_kind(servers: object) -> list[str]:
    """The names of the servers written ``kind: bridge``, in the order written. Anything that
    isn't a mapping of mappings is left to the schema's own refusals."""
    if not isinstance(servers, Mapping):
        return []
    return [
        name
        for name, server in servers.items()
        if isinstance(server, Mapping) and server.get("kind") == "bridge"
    ]


def unix_upstream(value: str) -> str:
    """A route's ``unix:`` upstream: exactly ``unix:/run/zoeymcp-bridge-<name>/mcp.sock``. The
    socket is the whole upstream, with no HTTP path, query or authority: the server's ``path`` is
    the HTTP path, as for any upstream written as an origin alone."""
    if not _UNIX_UPSTREAM.fullmatch(value):
        raise ValueError(UNIX_UPSTREAM_FORM)
    return value


def bridge_name(upstream: str) -> str:
    """The bridge a ``unix:`` upstream names; a ``ValueError`` for any other upstream."""
    found = _UNIX_UPSTREAM.fullmatch(upstream)
    if found is None:
        raise ValueError(UNIX_UPSTREAM_FORM)
    return found.group(1)


def bridge_socket(name: str) -> str:
    """The socket path a bridge listens on, which the ``unix:`` upstream naming it names."""
    return f"/run/zoeymcp-bridge-{name}/mcp.sock"


def check_endpoint_query(url: str, reserved: Set[str]) -> None:
    """Refuse an endpoint whose query sets a name in ``reserved``. A URL without ``?`` passes."""
    if "?" not in url:
        return
    for name, _ in endpoint_query(url.partition("?")[2]):
        if name in reserved:
            raise ValueError(
                f"the endpoint's query sets {name}, which the vault sets on this request or "
                "which changes how the server reads the vault's parameters"
            )
