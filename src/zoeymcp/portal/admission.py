"""Admission for the portal (M5 design C.1, C.2). Pure, so each row can be tested both ways.

The shell (``portal/app.py``) gathers a request's facts, asks here in C.2's order and applies
the answer; nothing here reads a body, a clock or a table. Row 0, the in-flight gate, is the
shell's with ``limits.py``. Rows 1 to 7 are :func:`admit`, a function of the request's method,
path and headers and the policy's origins. Rows 8 to 10 decide on what the shell found in its
tables (:func:`admit_unauthenticated`, :func:`admit_session`), and row 12 is :func:`parse_body`
on the bytes the shell read under row 11's cap and deadline. **No body byte is read before row 8
or row 9 has passed.**

What each row stops (spec brief §7): a browser sends ``Sec-Fetch-Site`` to every potentially
trustworthy origin, ``same-origin`` only from the portal's own page (a page on another localhost
port is ``same-site``); a ``fetch()`` with ``POST`` or ``DELETE`` sends the page's ``Origin``,
and a form post under ``no-referrer`` sends ``null``; DNS rebinding keeps the attacker's name in
``Host``. Every header must appear exactly once, so a request can't carry two answers and have
the check read one. The vault never reads ``X-Forwarded-*`` or ``Forwarded`` (C.5).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlsplit

from ..common.canonical import JSONRejected, loads_strict
from .refusals import Refusal, refusal, wrong_host_literal
from .routes import METHODS, ROUTES, STATIC, Route, Scope, StaticFile, match

SESSION_HEADER: Final = b"x-zoeymcp-session"
JSON: Final = "application/json"

_LENGTH: Final = re.compile(r"[0-9]{1,12}")
# A Host that is an IP literal: IPv6 in brackets, IPv4 bare; an optional port.
_LITERAL: Final = re.compile(r"(\[[0-9A-Fa-f:.]+\]|[0-9.]+)(?::([0-9]{1,5}))?")

Headers = Sequence[tuple[bytes, bytes]]


@dataclass(frozen=True)
class Origin:
    """One ``admin.origins`` value, as admission uses it (C.1). ``authority`` is the one ``Host``
    it accepts; ``port`` is None for the scheme's default. The session cookie follows the public
    scheme: ``__Host-`` and ``Secure`` on https only, since Safari won't send a ``Secure`` cookie
    to ``http://localhost`` and Chrome refuses ``__Host-`` there (spec brief §7.4)."""

    origin: str
    scheme: str
    host: str
    port: int | None
    authority: str
    rp_id: str
    cookie_name: str
    secure: bool


def origin_entry(origin: str) -> Origin:
    """The entry for a policy origin, which the schema has already checked: lower case,
    ``scheme://host[:port]``, no default port, a name rather than an IP address."""
    parts = urlsplit(origin)
    host = parts.hostname or ""
    secure = parts.scheme == "https"
    suffix = "" if parts.port is None else f"-{parts.port}"
    return Origin(
        origin=origin,
        scheme=parts.scheme,
        host=host,
        port=parts.port,
        authority=parts.netloc,
        rp_id=host,
        cookie_name=f"__Host-zoeymcp{suffix}-session" if secure else f"zoeymcp{suffix}-session",
        secure=secure,
    )


def origin_entries(origins: Iterable[str]) -> tuple[Origin, ...]:
    return tuple(origin_entry(origin) for origin in origins)


@dataclass(frozen=True)
class Request:
    """The facts admission reads: the ASGI scope's ``method``, ``path`` and raw ``headers``."""

    method: str
    path: str
    headers: Headers


@dataclass(frozen=True)
class Redirect:
    """Row 1's 308 from a loopback literal to the configured ``http://localhost:<port>/``."""

    location: str


@dataclass(frozen=True)
class Static:
    """Row 3: serve this file."""

    entry: Origin
    file: StaticFile


@dataclass(frozen=True)
class Admitted:
    """An API request that passed rows 1 to 7. ``cookies``: every value of the entry's session
    cookie, in the order the request carries them; ``token``: the one ``X-ZoeyMCP-Session``, or
    None. Both are bearer halves, so neither shows in a ``repr``."""

    entry: Origin
    route: Route
    params: Mapping[str, str]
    cookies: tuple[str, ...] = field(repr=False)
    token: str | None = field(repr=False)


Decision = Refusal | Redirect | Static | Admitted


def admit(
    request: Request, entries: Sequence[Origin], routes: Iterable[Route] = ROUTES
) -> Decision:
    """C.2 rows 1 to 7, in order."""
    headers = request.headers
    hosts = values(headers, b"host")
    entry = _entry(hosts, entries)
    if entry is None:
        return _wrong_host(request, hosts, entries)
    if request.method not in METHODS:
        return refusal("method")
    if not request.path.startswith("/api/"):
        file = STATIC.get(request.path)
        if request.method == "GET" and file is not None:
            return Static(entry, file)
        return refusal("not_found")
    if values(headers, b"sec-fetch-site") != ["same-origin"]:
        return refusal("cross_site")
    origins = values(headers, b"origin")
    if (origins or request.method != "GET") and origins != [entry.origin]:
        return refusal("bad_origin")
    found = match(routes, request.method, request.path)
    if found is None:
        return refusal("not_found")
    route, params = found
    refused = _body_headers(headers, route.cap)
    if refused is not None:
        return refused
    tokens = values(headers, SESSION_HEADER)
    return Admitted(
        entry=entry,
        route=route,
        params=params,
        cookies=cookie_values(headers, entry.cookie_name),
        token=tokens[0] if len(tokens) == 1 else None,
    )


def admit_unauthenticated(*, slot: bool, token: bool) -> Refusal | None:
    """Row 8, for an unauthenticated route: the shell took one of the unauthenticated in-flight
    slots (``slot``), then a token from the global bucket (``token``)."""
    if not slot:
        return refusal("busy")
    if not token:
        return refusal("rate_limited")
    return None


def admit_session(route: Route, scope: Scope | None) -> Refusal | None:
    """Rows 9 and 10, for any other route: ``scope`` is that of the session both halves found,
    or None. One 401 for every cause, so a caller can't tell an unknown session from an expired
    one or a half-right pair."""
    if scope is None:
        return refusal("no_session")
    if scope not in route.scopes:
        return refusal("scope")
    return None


def parse_body(route: Route, raw: bytes) -> dict[str, Any] | Refusal:
    """Rows 11 and 12 on the body the shell read, up to the cap and one byte more: a JSON object
    with every key the route needs and no other."""
    if len(raw) > route.cap:
        return refusal("too_large")
    try:
        body = loads_strict(raw)
    except JSONRejected:
        return refusal("bad_json")
    if not isinstance(body, dict) or not route.body <= body.keys() <= route.body | route.optional:
        return refusal("bad_body")
    return body


def values(headers: Headers, name: bytes) -> list[str]:
    """Every value of the header ``name`` (lower case), as Latin-1, in order."""
    return [value.decode("latin-1") for key, value in headers if key.lower() == name]


def cookie_values(headers: Headers, name: str) -> tuple[str, ...]:
    """Every value of the cookie ``name``, from the raw ``Cookie`` headers, in order. A parsed
    cookie mapping keeps one of two cookies of one name (contract 39), and a neighbour on another
    localhost port can plant one beside ours, so each is kept for the session lookup to try."""
    found = []
    for header in values(headers, b"cookie"):
        for pair in header.split(";"):
            key, equals, value = pair.partition("=")
            if equals and key.strip() == name:
                found.append(value.strip())
    return tuple(found)


def _entry(hosts: list[str], entries: Sequence[Origin]) -> Origin | None:
    """Row 1: exactly one ``Host``, equal to an entry's authority with the host in any case and
    the port exact."""
    if len(hosts) != 1:
        return None
    host = hosts[0].lower()
    return next((entry for entry in entries if entry.authority == host), None)


def _wrong_host(request: Request, hosts: list[str], entries: Sequence[Origin]) -> Decision:
    """Row 1's refusal. A loopback IP literal can't be an RP ID, so its page is sent to the
    configured ``http://localhost`` origin with the same port, and anything else is told so."""
    local = _localhost(hosts[0]) if len(hosts) == 1 else None
    if local is None:
        return refusal("wrong_host")
    if request.method == "GET" and request.path == "/":
        for entry in entries:
            if entry.scheme == "http" and entry.authority == local:
                return Redirect(f"{entry.origin}/")
    return wrong_host_literal(local)


def _localhost(host: str) -> str | None:
    """``localhost`` with the port of a ``Host`` that is a loopback IP literal, else None."""
    literal = _LITERAL.fullmatch(host)
    if literal is None:
        return None
    address, port = literal.groups()
    try:
        ip = ipaddress.ip_address(address.removeprefix("[").removesuffix("]"))
    except ValueError:
        return None
    if not ip.is_loopback or (ip.version == 6) != address.startswith("["):
        return None
    return "localhost" if port is None else f"localhost:{port}"


def _body_headers(headers: Headers, cap: int) -> Refusal | None:
    """Row 7, from the headers alone: a route without a body takes none; any other takes exactly
    ``application/json`` with one ``Content-Length`` within its cap (no chunked body)."""
    lengths = values(headers, b"content-length")
    chunked = bool(values(headers, b"transfer-encoding"))
    if cap == 0:
        if chunked or lengths not in ([], ["0"]):
            return refusal("too_large")
        return None
    if values(headers, b"content-type") != [JSON]:
        return refusal("content_type")
    if chunked or len(lengths) != 1 or not _LENGTH.fullmatch(lengths[0]):
        return refusal("length_required")
    if int(lengths[0]) > cap:
        return refusal("too_large")
    return None
