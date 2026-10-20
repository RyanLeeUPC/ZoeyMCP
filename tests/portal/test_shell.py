"""The portal's listener and shell over real sockets (M5 design B.3, C.2, C.3, O.4).

P3's ``Host`` rows and browser modes, the 308, P15's headers on every status the shell makes,
P16's connection and body rows (contract 40's cases through the real vault), P21, and P12's 404s
for ``/callback``, ``/oauth/callback`` and ``/oauth/callback/<name>`` (the last until step 14b).
The body, session and gate rows run on routes the tests add, so each row is shown on its own;
the API's own routes are tested in ``test_login.py``, ``test_setup.py`` and ``test_sessions.py``.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.browser import Browser, Cookie, head
from tests.fakes.echo import EchoProvider
from tests.fakes.harness import serve
from zoeymcp.portal.app import DRAIN_LIMIT, HEADERS, RESET_HINT, SETUP_HINT, Call, Handler, Reply
from zoeymcp.portal.limits import ADMIN_CONNECTIONS, IN_FLIGHT, IN_FLIGHT_UNAUTH, UNAUTH_BURST
from zoeymcp.portal.refusals import Refusal
from zoeymcp.portal.routes import Route, Scope
from zoeymcp.portal.sessions import Minted

from .rig import PortalRig, rig_policy, running

STATIC_DIR = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static"
PH = "ph-agent1-direct-0001"
SHORT = 0.5  # a head or body deadline, in seconds, for the slowloris cases


def assert_portal_headers(response: httpx.Response) -> None:
    """C.3's headers, exactly once each; no CORS header, no validator (P15)."""
    for name, value in HEADERS:
        assert response.headers.get_list(name.decode()) == [value.decode()], name
    assert not [k for k in response.headers if k.lower().startswith("access-control-")]
    assert "etag" not in response.headers
    assert "last-modified" not in response.headers
    assert response.status_code != 304


def refused(response: httpx.Response, status: int, reason: str) -> None:
    assert (response.status_code, response.json()["reason"]) == (status, reason)
    assert_portal_headers(response)


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path) as portal:
        yield portal


# --- the start (B.3, E.1) -----------------------------------------------------------------------


def test_the_portal_says_where_it_listens_and_that_setup_is_pending(rig: PortalRig) -> None:
    [listening] = rig.lines("portal_listening")
    assert listening["listen"] == f"127.0.0.1:{rig.portal_port}"
    assert listening["address"] == f"127.0.0.1:{rig.portal_port}"
    assert listening["origins"] == [rig.origin]
    assert [line["hint"] for line in rig.lines("setup_pending")] == [SETUP_HINT]
    assert rig.lines("setup_code_issued") == []
    assert not (rig.state / "setup.json").exists()  # no code exists until one is issued (D8)


# --- the static files (M.1) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "name", "content_type"),
    [
        ("/", "index.html", "text/html; charset=utf-8"),
        ("/app.js", "app.js", "text/javascript; charset=utf-8"),
        ("/webauthn.js", "webauthn.js", "text/javascript; charset=utf-8"),
        ("/app.css", "app.css", "text/css; charset=utf-8"),
    ],
)
def test_the_static_files(rig: PortalRig, path: str, name: str, content_type: str) -> None:
    response = rig.browser().navigate(rig.origin + path)
    assert response.status_code == 200
    assert response.headers["content-type"] == content_type
    assert response.content == (STATIC_DIR / name).read_bytes()
    assert_portal_headers(response)


def test_a_navigation_from_anywhere_gets_the_shell(rig: PortalRig) -> None:
    browser = rig.browser()
    response = browser.navigate(rig.origin + "/", initiator="https://evil.example")
    assert response.status_code == 200
    assert browser.history[-1][2]["sec-fetch-site"] == "cross-site"


def test_the_shell_never_answers_304(rig: PortalRig) -> None:
    conditional = [("If-None-Match", "*"), ("If-Modified-Since", "Mon, 01 Jan 2024 00:00:00 GMT")]
    response = rig.browser().navigate(rig.origin + "/app.css", headers=conditional)
    assert response.status_code == 200
    assert response.content == (STATIC_DIR / "app.css").read_bytes()


def test_no_other_path_and_no_percent_encoded_one(rig: PortalRig) -> None:
    browser = rig.browser()
    for path in ("/index.html", "/static/app.js", "/%61pp.js", "/app.js/", "//app.js"):
        refused(browser.navigate(rig.origin + path), 404, "not_found")


@pytest.mark.parametrize("path", ["/callback", "/oauth/callback", "/oauth/callback/google"])
def test_the_callback_paths_are_404_until_the_callback_is_built(rig: PortalRig, path: str) -> None:
    """P12: M2's default path and the callback without a name, on every origin; the named one
    until step 14b builds it. A form post to it is 404 too (C.2 row 3)."""
    browser = rig.browser()
    query = "?code=c0de&state=s7a7e"
    refused(
        browser.navigate(rig.origin + path + query, initiator="https://idp.example"),
        404,
        "not_found",
    )
    page = browser.page("https://idp.example")
    refused(page.form_post(rig.origin + path, {"code": "c0de"}), 404, "not_found")
    assert "c0de" not in rig.log.getvalue()


# --- Host (C.2 row 1, P3) -----------------------------------------------------------------------


def test_host_rows(rig: PortalRig) -> None:
    browser = rig.browser()
    port = rig.portal_port
    url = rig.origin + "/"

    def with_host(host: str, path: str = "/") -> httpx.Response:
        return browser.forge("GET", rig.origin + path, [("Host", host)])

    assert with_host(f"LocalHost:{port}").status_code == 200  # the host in any case
    refused(with_host("localhost"), 421, "wrong_host")  # no port against a port origin
    refused(with_host(f"localhost:{port + 1}"), 421, "wrong_host")
    refused(with_host(f"evil.example:{port}"), 421, "wrong_host")  # DNS rebinding
    refused(with_host(f"localhost.:{port}"), 421, "wrong_host")
    # A loopback literal: GET / is sent to the configured localhost origin, nothing else is.
    for literal in (f"127.0.0.1:{port}", f"127.1.2.3:{port}", f"[::1]:{port}"):
        moved = with_host(literal)
        assert moved.status_code == 308
        assert moved.headers["location"] == url
        assert moved.content == b""
        assert_portal_headers(moved)
        answer = with_host(literal, "/app.js")
        refused(answer, 421, "wrong_host")
        assert answer.json()["error"] == (
            f"Passkeys don't work on IP addresses. Open http://localhost:{port}/ instead."
        )
    # The literal's port must be the origin's.
    refused(with_host(f"127.0.0.1:{port + 1}"), 421, "wrong_host")


def test_a_typed_ip_literal_lands_on_localhost(rig: PortalRig) -> None:
    browser = rig.browser()
    response = browser.navigate(f"http://127.0.0.1:{rig.portal_port}/")
    assert response.status_code == 200
    assert [url for _, url, _ in browser.history] == [
        f"http://127.0.0.1:{rig.portal_port}/",
        rig.origin + "/",
    ]


def test_two_host_headers_never_reach_the_portal(rig: PortalRig) -> None:
    """Contract 37 over the real listener: uvicorn's own 400, with none of the portal's headers
    (contract 38), and nothing the portal logs."""
    host = f"Host: localhost:{rig.portal_port}"
    with rig.slowloris() as raw:
        sock = raw.connect()
        sock.sendall(head("GET / HTTP/1.1", host, host))
        answer = raw.answer(sock)
    assert answer.startswith(b"HTTP/1.1 400 ")
    assert b"content-security-policy" not in answer.lower()
    assert b"text/html" not in answer.lower()
    assert rig.lines("portal_request") == rig.lines("portal_refused") == []


# --- the browser modes (C.2 rows 2-6, P3) -------------------------------------------------------


def test_the_browser_modes_are_refused_before_any_session_lookup(rig: PortalRig) -> None:
    browser = rig.browser()
    own = browser.page(rig.origin)
    # The portal's own page reaches the session check, and has no session.
    refused(own.fetch("GET", "/api/session"), 401, "no_session")
    refused(own.fetch("POST", "/api/logout", json={}), 401, "no_session")
    # A cross-site page, and a neighbour on another localhost port (same-site, not same-origin).
    for other in ("https://evil.example", f"http://localhost:{rig.portal_port + 1}"):
        page = browser.page(other)
        refused(page.fetch("GET", rig.origin + "/api/session"), 403, "cross_site")
        refused(page.fetch("POST", rig.origin + "/api/logout", json={}), 403, "cross_site")
    # DNS rebinding: the hostile name in Host.
    rebound = browser.page(f"http://rebind.example:{rig.portal_port}")
    refused(rebound.fetch("POST", "/api/logout", json={}), 421, "wrong_host")
    # A form post from the portal's own origin: no-referrer makes its Origin null.
    refused(own.form_post("/api/logout", {"x": "1"}), 403, "bad_origin")
    # A typed address: Sec-Fetch-Site none.
    refused(browser.navigate(rig.origin + "/api/session"), 403, "cross_site")
    # Another Origin on a GET that carries one; the Origin doubled.
    refused(own.fetch("GET", "/api/session", headers=[("Origin", "null")]), 403, "bad_origin")
    # A non-browser forging every header gets as far as the session check.
    forged = [
        ("Sec-Fetch-Site", "same-origin"),
        ("Origin", rig.origin),
        ("Content-Type", "application/json"),
    ]
    refused(browser.forge("POST", rig.origin + "/api/logout", forged, b"{}"), 401, "no_session")
    assert len(rig.app.sessions) == 0


@pytest.mark.parametrize("method", ["OPTIONS", "HEAD", "PUT", "PATCH", "TRACE"])
def test_other_methods_are_405_and_no_preflight_is_answered(rig: PortalRig, method: str) -> None:
    response = rig.browser().forge(method, rig.origin + "/api/session")
    assert response.status_code == 405
    assert response.headers["allow"] == "GET, POST, DELETE"
    assert_portal_headers(response)
    if method != "HEAD":
        assert response.json()["reason"] == "method"


def test_each_listener_answers_as_itself(rig: PortalRig) -> None:
    """P3: the proxy listener answers the portal's paths as the proxy, and the portal answers
    the proxy's internal paths with its own 404."""
    browser = rig.browser()
    proxy = browser.forge("GET", f"http://127.0.0.1:{rig.proxy_port}/api/session")
    assert proxy.headers["x-zoeymcp-vault"] == "refused"
    assert proxy.status_code == 404
    page = browser.page(rig.origin)
    for path in ("/_zoeymcp/gateway/v1/view", "/_zoeymcp/gateway/v1/ledger"):
        refused(browser.navigate(rig.origin + path), 404, "not_found")
    refused(page.fetch("GET", "/_zoeymcp/gateway/v1/view"), 404, "not_found")


def test_refusals_are_logged_sparsely_and_without_the_callers_headers(rig: PortalRig) -> None:
    browser = rig.browser()
    for _ in range(5):
        refused(
            browser.forge("GET", rig.origin + "/", [("Host", "hostile-host.example")]),
            421,
            "wrong_host",
        )
    page = browser.page("https://hostile-origin.example")
    for _ in range(3):
        refused(page.fetch("POST", rig.origin + "/api/logout", json={}), 403, "cross_site")
    lines = rig.lines("portal_refused")
    assert [(line["reason"], line["status"], line["count"]) for line in lines] == [
        ("wrong_host", 421, 1),
        ("cross_site", 403, 1),
    ]
    text = rig.log.getvalue()
    assert "hostile-host" not in text
    assert "hostile-origin" not in text


# --- the routes a test adds: sessions, bodies, the gate (C.2 rows 0 and 7-12) -------------------

ECHO = Route("POST", "/api/test/echo", frozenset(), cap=64, body=frozenset({"x"}))
WHO = Route("GET", "/api/test/who", frozenset({"full"}))
HOLD = Route("POST", "/api/test/hold", frozenset({"full"}), cap=DRAIN_LIMIT, body=frozenset({"x"}))
WAIT = Route("GET", "/api/test/wait", frozenset({"full"}))
BOOM = Route("GET", "/api/test/boom", frozenset({"full"}))
SETUP_ONLY = Route("GET", "/api/test/setup", frozenset({"setup"}))
ROUTES = (ECHO, WHO, HOLD, WAIT, BOOM, SETUP_ONLY)


class Handlers:
    def __init__(self) -> None:
        self.release = threading.Event()
        self.calls: list[Call] = []

    async def echo(self, call: Call) -> Reply | Refusal:
        self.calls.append(call)
        return Reply({"x": call.body["x"] if call.body else None})

    async def who(self, call: Call) -> Reply | Refusal:
        self.calls.append(call)
        assert call.session is not None
        return Reply({"scope": call.session.scope}, headers=((b"x-test", b"1"),))

    async def wait(self, call: Call) -> Reply | Refusal:
        while not self.release.is_set():
            await asyncio.sleep(0.01)
        return Reply({})

    async def boom(self, call: Call) -> Reply | Refusal:
        raise RuntimeError("a handler's bug")

    def table(self) -> dict[Route, Handler]:
        return {
            ECHO: self.echo,
            WHO: self.who,
            HOLD: self.echo,
            WAIT: self.wait,
            BOOM: self.boom,
            SETUP_ONLY: self.who,
        }


@pytest.fixture
def handlers() -> Handlers:
    return Handlers()


def api_rig(tmp_path: Path, handlers: Handlers, **kwargs: Any) -> Any:
    return running(tmp_path, routes=ROUTES, handlers=handlers.table(), **kwargs)


def signed_in(rig: PortalRig, browser: Browser, scope: Scope = "full") -> Minted:
    """A session minted as a login would, its halves where the page keeps them."""
    minted: Minted = rig.call(
        lambda: rig.app.sessions.mint(
            origin=rig.origin,
            rp_id="localhost",
            scope=scope,
            now=time.time(),
        )
    )
    name = f"zoeymcp-{rig.portal_port}-session"
    browser.plant(Cookie(name, minted.cookie.reveal(), "localhost", "/", False, True, "strict"))
    browser.page(rig.origin).storage["session"] = minted.header.reveal()
    return minted


def same_origin(
    rig: PortalRig, browser: Browser, minted: Minted | None = None
) -> list[tuple[str, str]]:
    """What the portal's page sends, for a raw or forged request."""
    headers = [
        ("Host", f"localhost:{rig.portal_port}"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Origin", rig.origin),
    ]
    if minted is not None:
        name = f"zoeymcp-{rig.portal_port}-session"
        headers += [
            ("Cookie", f"{name}={minted.cookie.reveal()}"),
            ("X-ZoeyMCP-Session", minted.header.reveal()),
        ]
    return headers


def test_a_session_route_needs_both_halves(tmp_path: Path, handlers: Handlers) -> None:
    with api_rig(tmp_path, handlers) as rig:
        browser = rig.browser()
        page = browser.page(rig.origin)
        refused(page.fetch("GET", "/api/test/who"), 401, "no_session")
        minted = signed_in(rig, browser)
        answer = page.fetch("GET", "/api/test/who")
        assert (answer.status_code, answer.json()) == (200, {"scope": "full"})
        assert answer.headers["x-test"] == "1"
        assert_portal_headers(answer)
        # The cookie alone (as a neighbour port's page has it), and the header alone.
        refused(page.fetch("GET", "/api/test/who", session=False), 401, "no_session")
        alone = [h for h in same_origin(rig, browser, minted) if h[0] != "Cookie"]
        refused(browser.forge("GET", rig.origin + "/api/test/who", alone), 401, "no_session")
        # A setup session reaches only its own routes.
        refused(page.fetch("GET", "/api/test/setup"), 403, "scope")
        [request] = [line for line in rig.lines("portal_request") if line["route"] == WHO.path]
        assert request["session"] == minted.session.fingerprint
        assert request["status"] == 200
        assert minted.cookie.reveal() not in rig.log.getvalue()
        assert minted.header.reveal() not in rig.log.getvalue()


def test_the_body_rows(tmp_path: Path, handlers: Handlers) -> None:
    with api_rig(tmp_path, handlers, body_deadline=SHORT) as rig:
        browser = rig.browser()
        page = browser.page(rig.origin)
        at_cap = b'{"x":"' + b"a" * (64 - 8) + b'"}'
        assert len(at_cap) == 64
        answer = page.fetch(
            "POST", "/api/test/echo", content=at_cap, headers=[("Content-Type", "application/json")]
        )
        assert (answer.status_code, answer.json()) == (200, {"x": "a" * 56})
        over = at_cap[:-2] + b'a"}'
        refused(
            page.fetch(
                "POST",
                "/api/test/echo",
                content=over,
                headers=[("Content-Type", "application/json")],
            ),
            413,
            "too_large",
        )
        refused(
            page.fetch(
                "POST", "/api/test/echo", content=b"{}", headers=[("Content-Type", "text/plain")]
            ),
            415,
            "content_type",
        )
        refused(page.fetch("POST", "/api/test/echo", json={"x": 1, "y": 2}), 400, "bad_body")
        refused(
            page.fetch(
                "POST",
                "/api/test/echo",
                content=b"{x}",
                headers=[("Content-Type", "application/json")],
            ),
            400,
            "bad_json",
        )
        # A chunked body: 411, and the connection closed (the page never sends one). Only the
        # head is sent, so the close is no reset that could overtake the answer.
        with rig.slowloris() as raw:
            sock = raw.connect()
            fields = [f"{name}: {value}" for name, value in same_origin(rig, browser)]
            sock.sendall(
                head(
                    f"POST {ECHO.path} HTTP/1.1",
                    *fields,
                    "Content-Type: application/json",
                    "Transfer-Encoding: chunked",
                )
            )
            answer = raw.answer(sock)
        assert answer.startswith(b"HTTP/1.1 411 ")
        assert b"connection: close" in answer.lower()
        assert [call.body for call in handlers.calls] == [{"x": "a" * 56}]


def raw_request(
    rig: PortalRig,
    browser: Browser,
    method: str,
    path: str,
    length: int,
    minted: Minted | None = None,
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1"]
    lines += [f"{name}: {value}" for name, value in same_origin(rig, browser, minted)]
    lines += ["Content-Type: application/json", f"Content-Length: {length}"]
    return head(*lines)


def test_a_slow_body_is_408_and_closes(tmp_path: Path, handlers: Handlers) -> None:
    with api_rig(tmp_path, handlers, body_deadline=SHORT) as rig, rig.slowloris() as raw:
        browser = rig.browser()
        sock = raw.connect()
        sock.sendall(raw_request(rig, browser, "POST", ECHO.path, 64) + b'{"x":')
        started = time.monotonic()
        answer = raw.answer(sock)
        assert SHORT - 0.1 <= time.monotonic() - started < SHORT + 3
        assert answer.startswith(b"HTTP/1.1 408 ")
        assert b'"reason":"too_slow"' in answer
        assert b"connection: close" in answer.lower()
        assert handlers.calls == []


def test_a_body_without_a_session_is_refused_unread(tmp_path: Path, handlers: Handlers) -> None:
    """P2: 401 at once, before any body byte. The connection is left for h11 to drop the body
    as it comes, and closes at the head deadline; a body larger than any route takes is 413
    from its headers, and closes the connection."""
    with (
        api_rig(tmp_path, handlers, header_deadline=SHORT) as rig,
        rig.slowloris() as raw,
    ):
        browser = rig.browser()
        sock = raw.connect()
        sock.sendall(raw_request(rig, browser, "POST", HOLD.path, DRAIN_LIMIT))
        started = time.monotonic()
        answer = read_response(sock)
        assert time.monotonic() - started < 2
        assert answer.startswith(b"HTTP/1.1 401 ")
        assert b"connection: close" not in answer.lower()
        sock.sendall(b"x" * 1000)  # a slow body: dropped, never parsed or answered
        assert raw.closed(sock, SHORT + 2)
        huge = raw.connect()
        huge.sendall(raw_request(rig, browser, "POST", HOLD.path, 10 * 1024 * 1024))
        answer = raw.answer(huge)
        assert answer.startswith(b"HTTP/1.1 413 ")
        assert b"connection: close" in answer.lower()
        assert handlers.calls == []


def test_a_handler_that_fails_is_a_500_with_every_header(
    tmp_path: Path, handlers: Handlers
) -> None:
    with api_rig(tmp_path, handlers) as rig:
        browser = rig.browser()
        signed_in(rig, browser)
        refused(browser.page(rig.origin).fetch("GET", BOOM.path), 500, "internal")

        # The request is logged once the answer is sent: the client can see it first.
        def failures() -> list[dict[str, Any]]:
            return [line for line in rig.lines("portal_request") if line["status"] == 500]

        wait_until(lambda: bool(failures()))
        [line] = failures()
        assert (line["route"], line["error_type"]) == (BOOM.path, "RuntimeError")
        assert "a handler's bug" not in rig.log.getvalue()


def test_the_bucket_limits_unauthenticated_routes(tmp_path: Path, handlers: Handlers) -> None:
    with api_rig(tmp_path, handlers) as rig:
        page = rig.browser().page(rig.origin)
        answers = [page.fetch("POST", ECHO.path, json={"x": n}) for n in range(UNAUTH_BURST + 1)]
        assert [a.status_code for a in answers] == [200] * UNAUTH_BURST + [429]
        refused(answers[-1], 429, "rate_limited")
        assert answers[-1].headers["retry-after"] == "2"


def test_the_in_flight_gate(tmp_path: Path, handlers: Handlers) -> None:
    with api_rig(tmp_path, handlers) as rig:
        browser = rig.browser()
        minted = signed_in(rig, browser)
        headers = same_origin(rig, browser, minted)
        with ThreadPoolExecutor(IN_FLIGHT) as pool:
            held = [
                pool.submit(browser.forge, "GET", rig.origin + WAIT.path, headers)
                for _ in range(IN_FLIGHT)
            ]
            wait_until(lambda: rig.call(lambda: rig.app.in_flight) == (IN_FLIGHT, 0))
            busy = browser.forge("GET", rig.origin + "/")
            refused(busy, 503, "busy")
            assert busy.headers["retry-after"] == "1"
            handlers.release.set()
            assert [f.result().status_code for f in held] == [200] * IN_FLIGHT
        assert rig.call(lambda: rig.app.in_flight) == (0, 0)


def test_slow_unauthenticated_bodies_dont_stop_an_operator(
    tmp_path: Path, handlers: Handlers
) -> None:
    """P2: 8 slow bodies sent without a session hold the unauthenticated slots, and nothing
    else: a ninth is busy, and a request with a session still succeeds."""
    with api_rig(tmp_path, handlers) as rig, rig.slowloris() as raw:
        browser = rig.browser()
        for _ in range(IN_FLIGHT_UNAUTH):
            raw.connect().sendall(raw_request(rig, browser, "POST", ECHO.path, 10) + b'{"x"')
        wait_until(
            lambda: rig.call(lambda: rig.app.in_flight) == (IN_FLIGHT_UNAUTH, IN_FLIGHT_UNAUTH)
        )
        page = browser.page(rig.origin)
        refused(page.fetch("POST", ECHO.path, json={"x": 1}), 503, "busy")
        signed_in(rig, browser)
        assert page.fetch("GET", WHO.path).status_code == 200


# --- connections (B.3, contract 40, P16) --------------------------------------------------------


def test_an_idle_connection_is_closed_at_the_head_deadline(tmp_path: Path) -> None:
    with running(tmp_path, header_deadline=SHORT) as rig, rig.slowloris() as raw:
        sock = raw.connect()
        assert not raw.closed(sock, SHORT / 2)
        assert raw.closed(sock, SHORT + 2)


def test_a_trickled_head_is_closed_at_the_head_deadline(tmp_path: Path) -> None:
    with running(tmp_path, header_deadline=SHORT) as rig, rig.slowloris() as raw:
        sock = raw.connect()
        started = time.monotonic()
        request = head(
            "GET / HTTP/1.1", f"Host: localhost:{rig.portal_port}", "X-Pad: " + "a" * 200
        )
        assert not raw.trickle(sock, request, 0.02)
        assert SHORT - 0.1 <= time.monotonic() - started < SHORT + 2


def test_a_second_head_trickled_after_a_response_is_closed(tmp_path: Path) -> None:
    with running(tmp_path, header_deadline=SHORT) as rig, rig.slowloris() as raw:
        sock = raw.connect()
        host = f"Host: localhost:{rig.portal_port}"
        sock.sendall(head("GET /app.css HTTP/1.1", host))
        first = read_response(sock)
        assert first.startswith(b"HTTP/1.1 200 ")
        started = time.monotonic()
        assert not raw.trickle(sock, head("GET / HTTP/1.1", host, "X-Pad: " + "a" * 200), 0.02)
        assert time.monotonic() - started < SHORT + 2


def test_pipelined_heads_are_each_answered(rig: PortalRig) -> None:
    host = f"Host: localhost:{rig.portal_port}"
    with rig.slowloris() as raw:
        sock = raw.connect()
        sock.sendall(
            head("GET /app.css HTTP/1.1", host)
            + head("GET /app.js HTTP/1.1", host, "Connection: close")
        )
        answer = raw.answer(sock)
    assert answer.count(b"HTTP/1.1 200 ") == 2


def test_the_connection_cap_evicts_the_longest_idle(tmp_path: Path) -> None:
    with running(tmp_path, header_deadline=60) as rig, rig.slowloris() as raw:
        idle = raw.idle(ADMIN_CONNECTIONS)
        wait_until(lambda: len(rig.lines()) > 0)
        # An operator still gets in: the oldest idle connection makes way.
        assert rig.browser().navigate(rig.origin + "/").status_code == 200
        assert raw.closed(idle[0], 5)
        assert not raw.closed(idle[1], 0.2)
        extra = raw.connect()
        assert raw.closed(idle[1], 5)
        assert not raw.closed(extra, 0.2)
        assert [line["count"] for line in rig.lines("portal_connection_evicted")] == [1]


# --- P21: portal state that can't be read never stops the vault ---------------------------------


def test_a_rejected_passkey_file_and_an_unreadable_copy_leave_both_listeners_serving(
    tmp_path: Path,
) -> None:
    def spoil(state: Path) -> None:
        (state / "portal").mkdir(mode=0o700)
        (state / "portal" / "passkeys.json").write_bytes(b'{"v": 1, "tampered": true}')
        (state / "ledger-reported").write_bytes(b"not a directory")

    echo = EchoProvider()
    with serve(echo.app()) as upstream:
        route = {
            "name": "direct",
            "prefix": "/direct",
            "upstream": upstream,
            "allow_insecure_upstream": True,
            "callers": [{"placeholder": PH}],
            "rules": [{"methods": ["GET"], "paths": ["/**"]}],
        }
        with running(tmp_path, policy={"routes": [route]}, before_start=spoil) as rig:
            browser = rig.browser()
            assert browser.navigate(rig.origin + "/").status_code == 200
            proxied = browser.forge(
                "GET",
                f"http://127.0.0.1:{rig.proxy_port}/direct/ok",
                [("Authorization", f"Bearer {PH}")],
            )
            assert proxied.status_code == 200
            assert [line["hint"] for line in rig.lines("setup_pending")] == [RESET_HINT]
            assert rig.lines("passkey_store_tampered")
            assert rig.lines("ledger_reported_unavailable")
    assert [r.path for r in echo.received] == ["/ok"]


# --- reload (B.3) -------------------------------------------------------------------------------


def test_a_reload_takes_new_origins_at_once_and_ends_the_removed_ones_sessions(
    tmp_path: Path,
) -> None:
    with running(tmp_path, extra_origins=["http://localhost:9000"]) as rig:
        browser = rig.browser()
        neighbour: Minted = rig.call(
            lambda: rig.app.sessions.mint(
                origin="http://localhost:9000", rp_id="localhost", scope="full", now=time.time()
            )
        )
        kept: Minted = rig.call(
            lambda: rig.app.sessions.mint(
                origin=rig.origin, rp_id="localhost", scope="full", now=time.time()
            )
        )

        def at(host: str) -> int:
            return browser.forge("GET", rig.origin + "/", [("Host", host)]).status_code

        assert at("localhost:9000") == 200
        document = rig_policy(rig.portal_port, extra_origins=["http://localhost:9001"])
        rig.reload(document)
        assert (at("localhost:9000"), at("localhost:9001")) == (421, 200)
        ended = rig.lines("portal_session_ended")
        assert [(line["session"], line["why"]) for line in ended] == [
            (neighbour.session.fingerprint, "origin_removed")
        ]
        assert [s.id for s in rig.app.sessions.live(time.time())] == [kept.session.id]
        assert rig.lines("admin_listen_change_needs_restart") == []
        # A new address waits for a restart; the listener stays where it is.
        moved = {**document, "admin": {**document["admin"], "listen": "127.0.0.1:9002"}}
        rig.reload(moved)
        assert len(rig.lines("admin_listen_change_needs_restart")) == 1
        assert at(f"localhost:{rig.portal_port}") == 200


# --- helpers -------------------------------------------------------------------------------------


def wait_until(condition: Any, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        time.sleep(0.01)


def read_response(sock: Any) -> bytes:
    """One response with a Content-Length, read off a kept-alive connection."""
    sock.settimeout(10)
    data = b""
    while b"\r\n\r\n" not in data:
        data += sock.recv(65536)
    header, _, body = data.partition(b"\r\n\r\n")
    length = next(
        int(line.split(b":", 1)[1])
        for line in header.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    while len(body) < length:
        body += sock.recv(65536)
    return data
