"""Field rules the policy schema calls (M7 design A.1, COV-2). Pure and mutation-tested, so the
decisions M7 adds to the schema are tested without putting all of ``schema.py`` in mutation.

- :func:`host_port_lower`: an ``egress_private`` entry is in lower case, since the egress role
  and the address guard compare entries as written (CR-13).
- :func:`is_squid_acl_name`: a Squid source ACL name in ``egress_proxy_acls`` (OPS-7).
- :func:`endpoint_query` and :func:`check_endpoint_query`: the query a ``token_url`` or an
  ``authorize_url`` may carry (Q41). RFC 6749 3.1-3.2 say such a query MUST be kept when the
  client adds its parameters, so the vault keeps it byte for byte and puts its own after it; the
  endpoint may set none of the parameters the vault sets on that request (:data:`TOKEN_PARAMS`,
  :data:`AUTHORIZE_PARAMS`), nor one the credential's own params set.

Every pattern here is used with ``fullmatch``.
"""

from __future__ import annotations

import re
from collections.abc import Set
from typing import Final
from urllib.parse import parse_qsl

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


def host_port_lower(value: str) -> str:
    """The lower-case rule for a ``host:port`` the schema has already checked."""
    if value != value.lower():
        raise ValueError("write host:port in lower case: the egress role compares it as written")
    return value


def is_squid_acl_name(value: str) -> bool:
    return _SQUID_ACL_NAME.fullmatch(value) is not None


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
