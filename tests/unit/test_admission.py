"""Admission for the portal (M5 design C.1, C.2, O.2 ``admission``): every row both ways.

Requests are built as the ASGI scope gives them: raw header pairs, so a header can be missing or
doubled. Two ``Host`` headers never reach the app over the wire (h11 refuses them, contract 37);
here they are a pure case. A reference predicate written from C.2's table checks the order over
generated requests. C.7's rows for the callback, c1 to c5, are at the end.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.portal.admission import (
    NAVIGATION_SITES,
    SESSION_HEADER,
    Admitted,
    Callback,
    Decision,
    Origin,
    Redirect,
    Request,
    Static,
    admit,
    admit_callback,
    admit_session,
    admit_unauthenticated,
    binder_values,
    callback_query,
    cookie_values,
    origin_entries,
    origin_entry,
    parse_body,
    values,
)
from zoeymcp.portal.refusals import Refusal, refusal, wrong_host_literal
from zoeymcp.portal.routes import ROUTES, STATIC, Route, Scope

LOCAL = "http://localhost:8081"
TAILNET = "https://zoeymcp.tailnet.example"
PORTED = "https://vault.example.net:8443"
ENTRIES = origin_entries([LOCAL, TAILNET, PORTED])

FULL: frozenset[Scope] = frozenset({"full"})
SETUP: frozenset[Scope] = frozenset({"setup"})
BOTH: frozenset[Scope] = frozenset({"setup", "full"})
BEGIN = Route("POST", "/api/login/begin", frozenset(), 64)
FINISH = Route(
    "POST", "/api/login/finish", frozenset(), 16384, frozenset({"ceremony", "credential"})
)
SESSION = Route("GET", "/api/session", BOTH)
ENROL = Route("POST", "/api/passkeys/enrol/begin", SETUP, 4096, frozenset({"name"}))
START = Route("POST", "/api/oauth/{credential}/start", FULL, 64, optional=frozenset({"rebind"}))
CANCEL = Route("DELETE", "/api/oauth/flows/{flow}", FULL)
TABLE = (BEGIN, FINISH, SESSION, ENROL, START, CANCEL)

Value = str | list[str] | None
UNSET: Any = object()


def request(
    method: str = "POST",
    path: str = "/api/login/begin",
    *,
    host: Value = "localhost:8081",
    site: Value = "same-origin",
    origin: Value = UNSET,
    content_type: Value = UNSET,
    length: Value = UNSET,
    extra: Sequence[tuple[bytes, bytes]] = (),
) -> Request:
    """A request as the portal's own page sends it, unless told otherwise: a ``GET`` without
    ``Origin`` or a body, anything else with both. ``None`` leaves a header out; a list sends it
    once per value."""
    page = method != "GET"
    if origin is UNSET:
        origin = LOCAL if page else None
    if content_type is UNSET:
        content_type = "application/json" if page else None
    if length is UNSET:
        length = "2" if page else None
    headers: list[tuple[bytes, bytes]] = []
    for name, value in (
        (b"host", host),
        (b"sec-fetch-site", site),
        (b"origin", origin),
        (b"content-type", content_type),
        (b"content-length", length),
    ):
        for one in [value] if isinstance(value, str) else value or []:
            headers.append((name, one.encode("latin-1")))
    headers.extend(extra)
    return Request(method, path, headers)


def decide(req: Request, entries: Sequence[Origin] = ENTRIES) -> Decision:
    return admit(req, entries, TABLE)


def reason(decision: Decision) -> str:
    assert isinstance(decision, Refusal), decision
    return decision.reason


# --- C.1: origin entries ------------------------------------------------------------------------


def test_the_c1_entries() -> None:
    assert origin_entries([LOCAL, TAILNET, PORTED]) == (
        Origin(
            origin=LOCAL,
            scheme="http",
            host="localhost",
            port=8081,
            authority="localhost:8081",
            rp_id="localhost",
            cookie_name="zoeymcp-8081-session",
            secure=False,
            binder_cookie="zoeymcp-8081-cb",
        ),
        Origin(
            origin=TAILNET,
            scheme="https",
            host="zoeymcp.tailnet.example",
            port=None,
            authority="zoeymcp.tailnet.example",
            rp_id="zoeymcp.tailnet.example",
            cookie_name="__Host-zoeymcp-session",
            secure=True,
            binder_cookie="__Secure-zoeymcp-cb",
        ),
        Origin(
            origin=PORTED,
            scheme="https",
            host="vault.example.net",
            port=8443,
            authority="vault.example.net:8443",
            rp_id="vault.example.net",
            cookie_name="__Host-zoeymcp-8443-session",
            secure=True,
            binder_cookie="__Secure-zoeymcp-8443-cb",
        ),
    )


def test_a_default_port_localhost_entry() -> None:
    entry = origin_entry("http://localhost")
    assert (entry.authority, entry.port, entry.cookie_name, entry.secure) == (
        "localhost",
        None,
        "zoeymcp-session",
        False,
    )
    assert origin_entry("https://localhost:8443").cookie_name == "__Host-zoeymcp-8443-session"


def test_the_decisions_are_frozen() -> None:
    admitted = decide(request())
    assert isinstance(admitted, Admitted)
    for made in (
        ENTRIES[0],
        request(),
        Redirect("http://localhost:8081/"),
        Static(ENTRIES[0], STATIC["/"]),
        admitted,
    ):
        with pytest.raises(dataclasses.FrozenInstanceError):
            made.entry = ENTRIES[1]  # type: ignore[misc,union-attr]


# --- row 1: Host --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "origin"),
    [
        ("localhost:8081", LOCAL),
        ("LOCALHOST:8081", LOCAL),
        ("LocalHost:8081", LOCAL),
        ("zoeymcp.tailnet.example", TAILNET),
        ("ZoeyMCP.Tailnet.Example", TAILNET),
        ("vault.example.net:8443", PORTED),
    ],
)
def test_a_host_naming_an_entry_fixes_it(host: str, origin: str) -> None:
    decision = decide(request(host=host, origin=origin))
    assert isinstance(decision, Admitted)
    assert decision.entry.origin == origin


@pytest.mark.parametrize(
    "host",
    [
        None,
        ["localhost:8081", "localhost:8081"],  # two: a pure case, h11 refuses it first
        ["localhost:8081", "evil.example"],
        "localhost",  # no port against a port origin
        "localhost:8082",
        "localhost:08081",
        "localhost:",
        "localhost.:8081",
        "localhost:8081.",
        " localhost:8081",
        "zoeymcp.tailnet.example:443",  # the default port written out
        "zoeymcp.tailnet.example.",
        "vault.example.net",
        "vault.example.net:443",
        "evil.example:8081",  # DNS rebinding keeps the attacker's name
        "evil.example",
        "",
        "10.0.0.1:8081",
        "[::2]:8081",
        "[127.0.0.1]:8081",
        "::1:8081",
        "127.0.0.1:123456",
        "999.0.0.1:8081",
        "127.0.0.1.:8081",
    ],
)
def test_any_other_host_is_421(host: Value) -> None:
    assert decide(request(host=host)) == refusal("wrong_host")
    assert decide(request("GET", "/", host=host)) == refusal("wrong_host")


def test_the_host_header_name_is_matched_in_any_case() -> None:
    req = request(host=None, extra=[(b"Host", b"localhost:8081")])
    assert isinstance(decide(req), Admitted)


def test_no_entries_admit_nothing() -> None:
    assert decide(request(), ()) == refusal("wrong_host")


@pytest.mark.parametrize(
    ("host", "location"),
    [
        ("127.0.0.1:8081", "http://localhost:8081/"),
        ("127.0.0.2:8081", "http://localhost:8081/"),
        ("127.255.255.254:8081", "http://localhost:8081/"),
        ("[::1]:8081", "http://localhost:8081/"),
        ("[0:0:0:0:0:0:0:1]:8081", "http://localhost:8081/"),
    ],
)
def test_the_shell_on_a_loopback_literal_moves_to_localhost(host: str, location: str) -> None:
    assert decide(request("GET", "/", host=host)) == Redirect(location)


def test_a_literal_without_a_port_moves_to_a_default_port_origin() -> None:
    entries = origin_entries([LOCAL, "http://localhost"])
    for host in ("127.0.0.1", "[::1]"):
        assert decide(request("GET", "/", host=host), entries) == Redirect("http://localhost/")
        assert decide(request("GET", "/", host=host)) == wrong_host_literal("localhost")


@pytest.mark.parametrize(
    ("method", "path", "host", "authority"),
    [
        ("GET", "/app.js", "127.0.0.1:8081", "localhost:8081"),
        ("GET", "/api/session", "127.0.0.1:8081", "localhost:8081"),
        ("POST", "/", "127.0.0.1:8081", "localhost:8081"),
        ("POST", "/api/login/begin", "[::1]:8081", "localhost:8081"),
        ("PUT", "/", "127.0.0.1:8081", "localhost:8081"),
        ("GET", "/", "127.0.0.1:9999", "localhost:9999"),  # no such origin configured
        ("GET", "/", "127.0.0.1:99999", "localhost:99999"),
        ("GET", "/", "[::1]:8443", "localhost:8443"),
        ("GET", "/oauth/callback/github", "127.0.0.1:8081", "localhost:8081"),
    ],
)
def test_otherwise_a_loopback_literal_is_told_to_use_localhost(
    method: str, path: str, host: str, authority: str
) -> None:
    assert decide(request(method, path, host=host)) == wrong_host_literal(authority)


def test_only_an_http_localhost_origin_is_moved_to() -> None:
    entries = origin_entries(["https://localhost:8443"])
    decision = decide(request("GET", "/", host="127.0.0.1:8443"), entries)
    assert decision == wrong_host_literal("localhost:8443")


def test_two_literal_hosts_are_plain_421() -> None:
    req = request("GET", "/", host=["127.0.0.1:8081", "127.0.0.1:8081"])
    assert decide(req) == refusal("wrong_host")


# --- row 2: method ------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["PUT", "PATCH", "HEAD", "OPTIONS", "TRACE", "CONNECT", "get"])
def test_another_method_is_405(method: str) -> None:
    assert decide(request(method, "/api/login/begin")) == refusal("method")
    assert decide(request(method, "/")) == refusal("method")


# --- row 3: static files, and everything outside /api/ ------------------------------------------


@pytest.mark.parametrize("path", sorted(STATIC))
def test_a_static_file_is_served_whatever_fetch_metadata_says(path: str) -> None:
    for site in ("same-origin", "cross-site", "same-site", "none", None, ["none", "none"]):
        decision = decide(request("GET", path, site=site, origin="https://evil.example"))
        assert decision == Static(ENTRIES[0], STATIC[path])


def test_a_static_file_is_served_on_each_entry() -> None:
    decision = decide(request("GET", "/app.css", host="vault.example.net:8443"))
    assert decision == Static(ENTRIES[2], STATIC["/app.css"])


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/index.html"),
        ("GET", "/x"),
        ("GET", ""),
        ("GET", "/app.js/"),
        ("GET", "//app.js"),
        ("GET", "/api"),
        ("GET", "/API/session"),
        ("POST", "/"),
        ("DELETE", "/app.js"),
        ("POST", "/app.css"),
        ("GET", "/callback"),
        ("GET", "/oauth/callback"),
        ("POST", "/oauth/callback/github"),
        ("GET", "http://evil.example/x"),  # an absolute-form target (contract 37)
        ("GET", "/_zoeymcp/gateway/v1/view"),
    ],
)
def test_any_other_path_outside_the_api_is_404(method: str, path: str) -> None:
    assert decide(request(method, path)) == refusal("not_found")


# --- row 4: Sec-Fetch-Site ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "site",
    [
        None,
        "same-site",  # a page on another localhost port
        "none",
        "cross-site",
        "Same-Origin",
        "same-origin ",
        "",
        ["same-origin", "same-origin"],
        ["same-origin", "cross-site"],
    ],
)
def test_an_api_request_not_from_the_page_is_403(site: Value) -> None:
    assert decide(request(site=site)) == refusal("cross_site")
    assert decide(request("GET", "/api/session", site=site)) == refusal("cross_site")


def test_fetch_metadata_header_names_in_any_case() -> None:
    req = request(site=None, extra=[(b"Sec-Fetch-Site", b"same-origin")])
    assert isinstance(decide(req), Admitted)


# --- row 5: Origin ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "origin",
    [
        None,
        "null",  # a form post under no-referrer
        "http://localhost:8082",  # another port
        TAILNET,  # the other configured origin, with this Host
        "http://localhost:8081/",
        "HTTP://LOCALHOST:8081",
        "http://evil.example:8081",
        "",
        [LOCAL, LOCAL],
        [LOCAL, "null"],
    ],
)
def test_an_unsafe_api_request_needs_its_own_origin(origin: Value) -> None:
    assert decide(request(origin=origin)) == refusal("bad_origin")
    assert decide(request("DELETE", "/api/oauth/flows/abc", origin=origin)) == refusal("bad_origin")


def test_a_get_needs_no_origin_but_one_it_carries_must_match() -> None:
    assert isinstance(decide(request("GET", "/api/session", origin=None)), Admitted)
    assert isinstance(decide(request("GET", "/api/session", origin=LOCAL)), Admitted)
    for origin in ("null", TAILNET, [LOCAL, LOCAL]):
        assert decide(request("GET", "/api/session", origin=origin)) == refusal("bad_origin")


def test_the_origin_is_the_entrys() -> None:
    req = request(host="zoeymcp.tailnet.example", origin=TAILNET)
    assert isinstance(decide(req), Admitted)
    assert decide(request(host="zoeymcp.tailnet.example", origin=LOCAL)) == refusal("bad_origin")


# --- the route ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/api/login/begin"),  # a route's path, another method
        ("POST", "/api/session"),
        ("POST", "/api/nothing"),
        ("POST", "/api/"),
        ("POST", "/api/oauth/GitHub/start"),  # a parameter outside its pattern
        ("DELETE", "/api/oauth/flows/a.b"),
    ],
)
def test_an_unknown_api_route_is_404(method: str, path: str) -> None:
    assert decide(request(method, path)) == refusal("not_found")


def test_the_default_table_is_the_built_routes() -> None:
    admitted = admit(request(), ENTRIES)
    assert isinstance(admitted, Admitted)
    assert admitted.route == ROUTES[0] == BEGIN
    # A route a later step builds is 404 until then.
    assert admit(request("GET", "/api/ledger"), ENTRIES) == refusal("not_found")


# --- row 7: body headers ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content_type",
    [
        None,
        "application/json; charset=utf-8",
        "Application/JSON",
        "text/plain",
        "application/x-www-form-urlencoded",
        ["application/json", "application/json"],
    ],
)
def test_a_body_must_be_exactly_json(content_type: Value) -> None:
    assert decide(request(content_type=content_type)) == refusal("content_type")


@pytest.mark.parametrize(
    "length", [None, "", "x", "-1", "+2", " 2", "2.0", "0x10", ["2", "2"], "1" * 13]
)
def test_a_body_needs_one_plain_length(length: Value) -> None:
    assert decide(request(length=length)) == refusal("length_required")


def test_a_chunked_body_needs_a_length_too() -> None:
    chunked = [(b"transfer-encoding", b"chunked")]
    assert decide(request(length=None, extra=chunked)) == refusal("length_required")
    assert decide(request(extra=chunked)) == refusal("length_required")


@pytest.mark.parametrize(
    ("route", "path", "length", "ok"),
    [
        (BEGIN, "/api/login/begin", "64", True),
        (BEGIN, "/api/login/begin", "65", False),
        (BEGIN, "/api/login/begin", "0", True),
        (BEGIN, "/api/login/begin", "000000000064", True),
        (BEGIN, "/api/login/begin", "999999999999", False),
        (FINISH, "/api/login/finish", "16384", True),
        (FINISH, "/api/login/finish", "16385", False),
    ],
)
def test_the_length_against_the_routes_cap(route: Route, path: str, length: str, ok: bool) -> None:
    decision = decide(request(path=path, length=length))
    if ok:
        assert isinstance(decision, Admitted)
        assert decision.route == route
    else:
        assert decision == refusal("too_large")


@pytest.mark.parametrize(
    ("length", "extra", "ok"),
    [
        (None, [], True),
        ("0", [], True),
        ("1", [], False),
        (["0", "0"], [], False),
        ("", [], False),
        (None, [(b"transfer-encoding", b"chunked")], False),
        ("0", [(b"transfer-encoding", b"chunked")], False),
    ],
)
def test_a_route_without_a_body_takes_none(
    length: Value, extra: list[tuple[bytes, bytes]], ok: bool
) -> None:
    for method, path in (("GET", "/api/session"), ("DELETE", "/api/oauth/flows/abc")):
        decision = decide(request(method, path, length=length, content_type=None, extra=extra))
        if ok:
            assert isinstance(decision, Admitted)
        else:
            assert decision == refusal("too_large")


def test_a_route_without_a_body_ignores_its_content_type() -> None:
    decision = decide(request("GET", "/api/session", content_type="text/plain", length=None))
    assert isinstance(decision, Admitted)


# --- what an admitted request carries -----------------------------------------------------------


def test_an_admitted_request() -> None:
    decision = decide(
        request(
            path="/api/oauth/github/start",
            extra=[
                (b"cookie", b"zoeymcp-8081-session=abc"),
                (SESSION_HEADER, b"header-half"),
            ],
        )
    )
    assert decision == Admitted(
        entry=ENTRIES[0],
        route=START,
        params={"credential": "github"},
        cookies=("abc",),
        token="header-half",
    )


def test_the_session_halves_are_not_in_the_repr() -> None:
    decision = decide(
        request(extra=[(b"cookie", b"zoeymcp-8081-session=c00k1e"), (SESSION_HEADER, b"t0ken")])
    )
    assert isinstance(decision, Admitted)
    assert decision.cookies == ("c00k1e",)
    assert "c00k1e" not in repr(decision)
    assert "t0ken" not in repr(decision)


@pytest.mark.parametrize(
    ("headers", "token"),
    [
        ([], None),
        ([(SESSION_HEADER, b"one")], "one"),
        ([(b"X-ZoeyMCP-Session", b"one")], "one"),
        ([(SESSION_HEADER, b"one"), (SESSION_HEADER, b"one")], None),
        ([(SESSION_HEADER, b"one"), (SESSION_HEADER, b"two")], None),
        ([(SESSION_HEADER, b"")], ""),
    ],
)
def test_the_header_half_is_the_one_header(
    headers: list[tuple[bytes, bytes]], token: str | None
) -> None:
    decision = decide(request("GET", "/api/session", extra=headers))
    assert isinstance(decision, Admitted)
    assert decision.token == token


def test_the_cookie_name_is_the_entrys() -> None:
    cookies = [
        (b"cookie", b"zoeymcp-8081-session=local; __Host-zoeymcp-session=tailnet"),
        (b"cookie", b"__Host-zoeymcp-8443-session=ported"),
    ]
    for host, origin, value in (
        ("localhost:8081", LOCAL, "local"),
        ("zoeymcp.tailnet.example", TAILNET, "tailnet"),
        ("vault.example.net:8443", PORTED, "ported"),
    ):
        decision = decide(request(host=host, origin=origin, extra=cookies))
        assert isinstance(decision, Admitted)
        assert decision.cookies == (value,)


# --- contract 39: cookies from the raw header ---------------------------------------------------


NAME = "zoeymcp-8081-session"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ([], ()),
        ([b"other=1"], ()),
        ([b"zoeymcp-8081-session=a"], ("a",)),
        # A neighbour's cookie at Path=/api comes first; both are kept, in order.
        ([b"zoeymcp-8081-session=planted; zoeymcp-8081-session=ours"], ("planted", "ours")),
        ([b"zoeymcp-8081-session=a", b"zoeymcp-8081-session=b"], ("a", "b")),
        ([b"x=1;zoeymcp-8081-session=a ; y=2"], ("a",)),
        ([b"  zoeymcp-8081-session  =  a  "], ("a",)),
        ([b"zoeymcp-8081-session=a=b"], ("a=b",)),
        ([b"zoeymcp-8081-session="], ("",)),
        ([b"zoeymcp-8081-session"], ()),  # no "=": not a cookie of that name
        ([b"Zoeymcp-8081-Session=a"], ()),  # names are case sensitive
        ([b"zoeymcp-8081-session-x=a; xzoeymcp-8081-session=b"], ()),
        ([b'zoeymcp-8081-session="a"'], ('"a"',)),
        ([b";;zoeymcp-8081-session=a;;"], ("a",)),
    ],
)
def test_cookie_values(raw: list[bytes], expected: tuple[str, ...]) -> None:
    assert cookie_values([(b"cookie", value) for value in raw], NAME) == expected


def test_every_cookie_of_the_name_is_kept_for_the_lookup_to_try() -> None:
    raw = "; ".join(f"{NAME}=v{i}" for i in range(5)).encode()
    assert cookie_values([(b"cookie", raw)], NAME) == tuple(f"v{i}" for i in range(5))
    assert cookie_values([(b"Cookie", raw)], NAME)[0] == "v0"


def test_values_are_latin1_in_order() -> None:
    headers = [(b"a", b"1"), (b"b", b"x"), (b"A", b"\xe9")]
    assert values(headers, b"a") == ["1", chr(0xE9)]
    assert values(headers, b"c") == []


# --- order --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("req", "expected"),
    [
        (request("PUT", "/nowhere", host="evil.example"), "wrong_host"),  # 1 before 2
        (request("PUT", "/nowhere", site=None), "method"),  # 2 before 3
        (request("POST", "/x", site=None, origin=None), "not_found"),  # 3 before 4
        (request(site="cross-site", origin=None), "cross_site"),  # 4 before 5
        (request("POST", "/api/nothing", origin=None), "bad_origin"),  # 5 before the route
        (request("POST", "/api/nothing", content_type=None), "not_found"),  # the route before 7
        (request(content_type=None, length=None), "content_type"),  # 7: the type first
        (request(length="x", content_type="application/json"), "length_required"),
    ],
)
def test_the_rows_run_in_order(req: Request, expected: str) -> None:
    assert reason(decide(req)) == expected


# --- rows 8 to 10 -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("slot", "token", "expected"),
    [
        (False, False, "busy"),
        (False, True, "busy"),
        (True, False, "rate_limited"),
        (True, True, None),
    ],
)
def test_row_8(slot: bool, token: bool, expected: str | None) -> None:
    decision = admit_unauthenticated(slot=slot, token=token)
    assert decision == (None if expected is None else refusal(expected))


@pytest.mark.parametrize(
    ("route", "scope", "expected"),
    [
        (SESSION, None, "no_session"),
        (START, None, "no_session"),
        (ENROL, None, "no_session"),
        (SESSION, "setup", None),
        (SESSION, "full", None),
        (ENROL, "setup", None),
        (ENROL, "full", "scope"),  # a full session enrols through passkey.enrol
        (START, "setup", "scope"),
        (START, "full", None),
    ],
)
def test_rows_9_and_10(route: Route, scope: Scope | None, expected: str | None) -> None:
    decision = admit_session(route, scope)
    assert decision == (None if expected is None else refusal(expected))


def test_every_session_refusal_is_the_same_401() -> None:
    assert admit_session(SESSION, None) == Refusal(401, "no_session", refusal("no_session").error)


# --- rows 11 and 12 -----------------------------------------------------------------------------


def test_a_body_within_the_cap_parses() -> None:
    body = b'{"ceremony":"c","credential":{}}'
    assert parse_body(FINISH, body) == {"ceremony": "c", "credential": {}}
    exact = b'{"name":"' + b"n" * (4096 - 11) + b'"}'
    assert len(exact) == 4096
    assert parse_body(ENROL, exact) == {"name": "n" * 4085}
    assert parse_body(ENROL, exact[:-2] + b'n"}') == refusal("too_large")


@pytest.mark.parametrize(
    "raw",
    [b"", b"{", b"\xef\xbb\xbf{}", b'{"a":1,"a":2}', b"{}x", b"\xff", b"NaN", b'{"a":1e999}'],
)
def test_a_body_that_isnt_strict_json_is_400(raw: bytes) -> None:
    assert parse_body(BEGIN, raw) == refusal("bad_json")


@pytest.mark.parametrize(
    ("route", "raw", "ok"),
    [
        (BEGIN, b"{}", True),
        (BEGIN, b'{"x":1}', False),
        (BEGIN, b"[]", False),
        (BEGIN, b"null", False),
        (BEGIN, b'"{}"', False),
        (FINISH, b'{"ceremony":1,"credential":2}', True),
        (FINISH, b'{"ceremony":1}', False),
        (FINISH, b'{"ceremony":1,"credential":2,"extra":3}', False),
        (START, b"{}", True),
        (START, b'{"rebind":true}', True),
        (START, b'{"rebind":true,"x":1}', False),
        (START, b'{"x":1}', False),
    ],
)
def test_a_body_has_exactly_the_routes_keys(route: Route, raw: bytes, ok: bool) -> None:
    parsed = parse_body(route, raw)
    if ok:
        assert isinstance(parsed, dict)
    else:
        assert parsed == refusal("bad_body")


# --- a reference predicate over generated requests ----------------------------------------------


def reference(req: Request, entries: Sequence[Origin], routes: Sequence[Route]) -> object:
    """C.2 rows 1 to 7 as the table reads, written apart from the module."""

    def all_of(name: str) -> list[str]:
        return [v.decode("latin-1") for k, v in req.headers if k.lower() == name.encode()]

    hosts = all_of("host")
    matching = [e for e in entries if len(hosts) == 1 and hosts[0].lower() == e.authority]
    if not matching:
        return "wrong_host"
    entry = matching[0]
    if req.method not in ("GET", "POST", "DELETE"):
        return "method"
    if not req.path.startswith("/api/"):
        return "static" if req.method == "GET" and req.path in STATIC else "not_found"
    if all_of("sec-fetch-site") != ["same-origin"]:
        return "cross_site"
    origins = all_of("origin")
    if req.method in ("POST", "DELETE") and origins != [entry.origin]:
        return "bad_origin"
    if req.method == "GET" and origins and origins != [entry.origin]:
        return "bad_origin"
    route = next(
        (
            r
            for r in routes
            if r.method == req.method and r.path.replace("{credential}", "github") == req.path
        ),
        None,
    )
    if route is None:
        return "not_found"
    lengths = all_of("content-length")
    chunked = bool(all_of("transfer-encoding"))
    if route.cap == 0:
        return "admitted" if not chunked and lengths in ([], ["0"]) else "too_large"
    if all_of("content-type") != ["application/json"]:
        return "content_type"
    if chunked or len(lengths) != 1 or not lengths[0].isdigit() or len(lengths[0]) > 12:
        return "length_required"
    return "admitted" if int(lengths[0]) <= route.cap else "too_large"


def kind(decision: Decision) -> object:
    if isinstance(decision, Refusal):
        return decision.reason
    if isinstance(decision, Static):
        return "static"
    if isinstance(decision, Admitted):
        return "admitted"
    return "redirect"


def some(values: list[str]) -> st.SearchStrategy[list[str]]:
    return st.lists(st.sampled_from(values), max_size=2)


@st.composite
def requests(draw: st.DrawFn) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    for name, choices in (
        ("host", ["localhost:8081", "LOCALHOST:8081", "zoeymcp.tailnet.example", "evil.example"]),
        ("sec-fetch-site", ["same-origin", "same-site", "cross-site", "none"]),
        ("origin", [LOCAL, TAILNET, "null", "http://localhost:8082"]),
        ("content-type", ["application/json", "text/plain"]),
        ("content-length", ["0", "2", "64", "65", "x"]),
        ("transfer-encoding", ["chunked"]),
    ):
        for value in draw(some(choices)):
            headers.append((draw(st.sampled_from([name, name.title()])).encode(), value.encode()))
    method = draw(st.sampled_from(["GET", "POST", "DELETE", "PUT", "OPTIONS"]))
    path = draw(
        st.sampled_from(
            ["/", "/app.js", "/x", "/api", "/api/x"] + [r.path for r in TABLE if "{" not in r.path]
        )
        | st.just("/api/oauth/github/start")
    )
    return Request(method, path, draw(st.permutations(headers)))


@settings(max_examples=300, deadline=None)
@given(requests())
def test_admission_matches_the_reference(req: Request) -> None:
    assert kind(admit(req, ENTRIES, TABLE)) == reference(req, ENTRIES, TABLE)


# --- C.7: the callback's own rows ---------------------------------------------------------------

CALLBACK_PATH = "/oauth/callback/github"


def navigation(
    *,
    site: Value = "cross-site",
    mode: Value = "navigate",
    dest: Value = "document",
    extra: Sequence[tuple[bytes, bytes]] = (),
    method: str = "GET",
    path: str = CALLBACK_PATH,
    host: Value = "localhost:8081",
) -> Request:
    """A top-level navigation to the callback, as a provider's redirect arrives (no Origin, no
    body), unless told otherwise."""
    headers: list[tuple[bytes, bytes]] = []
    for name, value in (
        (b"host", host),
        (b"sec-fetch-site", site),
        (b"sec-fetch-mode", mode),
        (b"sec-fetch-dest", dest),
    ):
        for one in [value] if isinstance(value, str) else value or []:
            headers.append((name, one.encode("latin-1")))
    headers.extend(extra)
    return Request(method, path, headers)


def test_row_3_hands_the_callback_to_c7() -> None:
    assert decide(navigation()) == Callback(ENTRIES[0], "github")
    assert decide(navigation(host="vault.example.net:8443")) == Callback(ENTRIES[2], "github")
    # Whatever Fetch metadata says: row 3 only routes it, C.7 decides.
    assert decide(request("GET", CALLBACK_PATH, site=None)) == Callback(ENTRIES[0], "github")


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", CALLBACK_PATH),  # a form post (C.2 row 3)
        ("DELETE", CALLBACK_PATH),
        ("GET", "/oauth/callback"),
        ("GET", "/oauth/callback/"),
        ("GET", "/oauth/callback/GitHub"),  # outside NAME_PATTERN
        ("GET", "/oauth/callback/git%68ub"),  # the raw path, never decoded
        ("GET", "/oauth/callback/github/"),
        ("GET", "/oauth/callback/github/x"),
        ("GET", "/callback"),
    ],
)
def test_any_other_callback_path_or_method_is_404(method: str, path: str) -> None:
    assert decide(navigation(method=method, path=path)) == refusal("not_found")


def test_a_loopback_literal_callback_is_row_1s_421() -> None:
    assert decide(navigation(host="127.0.0.1:8081")) == wrong_host_literal("localhost:8081")


@pytest.mark.parametrize("site", ["cross-site", "same-site", "none"])
def test_c1_takes_a_navigation_from_anywhere(site: str) -> None:
    assert admit_callback(navigation(site=site)) is None
    assert frozenset({"cross-site", "same-site", "none"}) == NAVIGATION_SITES


@pytest.mark.parametrize(
    "changes",
    [
        {"site": None},
        {"site": "same-origin"},  # the portal's page never navigates there
        {"site": ["cross-site", "cross-site"]},
        {"site": "Cross-Site"},
        {"mode": None},
        {"mode": "cors"},  # a fetch
        {"mode": "no-cors"},  # an image or an embed
        {"mode": "same-origin"},
        {"mode": ["navigate", "navigate"]},
        {"dest": None},
        {"dest": "iframe"},  # a frame
        {"dest": "embed"},
        {"dest": "image"},
        {"dest": "empty"},
        {"dest": ["document", "document"]},
    ],
)
def test_c1_refuses_anything_but_one_top_level_navigation(changes: dict[str, Any]) -> None:
    assert admit_callback(navigation(**changes)) == refusal("not_navigation")


@pytest.mark.parametrize(
    "extra",
    [
        [(b"origin", b"https://evil.example")],  # a cross-origin fetch would send one
        [(b"origin", b"null")],
        [(b"origin", LOCAL.encode())],
        [(b"content-length", b"1")],
        [(b"content-length", b"0"), (b"content-length", b"0")],
        [(b"transfer-encoding", b"chunked")],
    ],
)
def test_c2_refuses_an_origin_or_a_body(extra: list[tuple[bytes, bytes]]) -> None:
    assert admit_callback(navigation(extra=extra)) == refusal("not_navigation")


def test_c2_takes_a_zero_length() -> None:
    assert admit_callback(navigation(extra=[(b"content-length", b"0")])) is None
    # Sec-Fetch-User is never read: present or not, the same answer.
    assert admit_callback(navigation(extra=[(b"sec-fetch-user", b"?1")])) is None
    assert admit_callback(navigation(extra=[(b"sec-fetch-user", b"?0")])) is None


def test_c3_is_row_8() -> None:
    assert admit_unauthenticated(slot=False, token=True) == refusal("busy")
    assert admit_unauthenticated(slot=True, token=False) == refusal("rate_limited")


@pytest.mark.parametrize(
    ("raw", "ok"),
    [
        (b"", True),
        (b"code=c&state=s", True),
        (b"a" * 4096, True),
        (b"a" * 4097, False),
        (b"state=%C3%A9", True),  # percent-encoded: ASCII as sent; the flow check decides
        (b"state=\xc3\xa9", False),  # a raw non-ASCII byte
        (b"state=\x80", False),
        (b"state=\x7f", True),
    ],
)
def test_c4_takes_the_raw_query_ascii_and_capped(raw: bytes, ok: bool) -> None:
    decided = callback_query(raw)
    if ok:
        assert decided == raw.decode("ascii")
    else:
        assert decided == refusal("bad_query")


def test_c5_gathers_the_binding_cookie_and_nothing_else() -> None:
    entry = ENTRIES[0]
    assert entry.binder_cookie == "zoeymcp-8081-cb"

    def cookies(*headers: str) -> tuple[str, ...]:
        return binder_values([(b"cookie", h.encode()) for h in headers], entry)

    assert cookies() == ()
    assert cookies("zoeymcp-8081-session=s") == ()  # no session is read here
    assert cookies("zoeymcp-8081-cb=b1") == ("b1",)
    assert cookies("zoeymcp-9000-cb=other; zoeymcp-8081-cb= b1 ") == ("b1",)
    five = "; ".join(f"zoeymcp-8081-cb=v{n}" for n in range(5))
    assert cookies(five) == ("v0", "v1", "v2", "v3")  # MAX_SESSION_COOKIES, in order
    assert cookies("zoeymcp-8081-cb=a", "zoeymcp-8081-cb=b") == ("a", "b")
    assert binder_values([], ENTRIES[1]) == ()
    assert ENTRIES[1].binder_cookie == "__Secure-zoeymcp-cb"
    assert ENTRIES[2].binder_cookie == "__Secure-zoeymcp-8443-cb"
    assert origin_entry("http://localhost").binder_cookie == "zoeymcp-cb"
