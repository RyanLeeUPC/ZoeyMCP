"""The fake browser sends what browsers send (M5 design O.1): Fetch Metadata, ``Origin``, cookies
by host and ``SameSite``, the engines' cookie rules over ``http://localhost``, the session header
from ``sessionStorage``, and redirects. Checked against a recording transport, so nothing here
needs the portal."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from .browser import (
    Browser,
    Cookie,
    asgi_client,
    chain_relation,
    head,
    loopback,
    origin_of,
    relation,
    site_of,
)

PORTAL = "http://localhost:8081"


class Recorder:
    """Answers every request with ``answer`` and keeps what was sent."""

    def __init__(self, answer: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.answer = answer or (lambda request: httpx.Response(200))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.answer(request)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]


def browser(recorder: Recorder, engine: str = "chrome") -> Browser:
    return Browser(engine=engine, transport=httpx.MockTransport(recorder))  # type: ignore[arg-type]


def test_origins_sites_and_relations() -> None:
    assert origin_of("http://LocalHost:8081/x?y") == PORTAL
    assert origin_of("https://a.example:443/") == "https://a.example"
    assert origin_of("http://[::1]:80/") == "http://[::1]"
    assert site_of("https://a.b.example:8443") == ("https", "b.example")
    assert site_of("http://localhost:9000") == ("http", "localhost")
    assert relation(None, PORTAL) == "none"
    assert relation(PORTAL, PORTAL) == "same-origin"
    assert relation("http://localhost:9000", PORTAL) == "same-site"  # ports aren't sites
    assert relation("https://localhost:8081", PORTAL) == "cross-site"  # schemes are
    assert relation("https://evil.example", PORTAL) == "cross-site"
    urls = [PORTAL + "/", "https://idp.example/x", PORTAL + "/back"]
    assert chain_relation(PORTAL, urls) == "cross-site"
    assert chain_relation(PORTAL, [PORTAL + "/a", PORTAL + "/b"]) == "same-origin"
    assert chain_relation(None, urls) == "none"


def test_requests_go_to_the_bound_literal_with_the_address_bars_host() -> None:
    recorder = Recorder()
    with browser(recorder) as b:
        b.navigate(PORTAL + "/app.js?v=1")
    request = recorder.last
    assert (request.url.host, request.url.port, request.url.raw_path) == (
        "127.0.0.1",
        8081,
        b"/app.js?v=1",
    )
    assert request.headers.get_list("host") == ["localhost:8081"]
    assert loopback("vault.example", 443) == ("127.0.0.1", 443)


def test_fetch_metadata_and_origin_as_fetch_sends_them() -> None:
    recorder = Recorder()
    with browser(recorder) as b:
        own = b.page(PORTAL)
        own.fetch("GET", "/api/session")
        assert recorder.last.headers["sec-fetch-site"] == "same-origin"
        assert recorder.last.headers["sec-fetch-mode"] == "cors"
        assert recorder.last.headers["sec-fetch-dest"] == "empty"
        assert "origin" not in recorder.last.headers  # a same-origin GET
        own.fetch("POST", "/api/logout", json={})
        assert recorder.last.headers["origin"] == PORTAL
        assert recorder.last.headers["content-type"] == "application/json"
        assert recorder.last.content == b"{}"
        other = b.page("https://evil.example")
        other.fetch("GET", PORTAL + "/api/session")
        assert recorder.last.headers["sec-fetch-site"] == "cross-site"
        assert recorder.last.headers["origin"] == "https://evil.example"  # a cross-origin GET
        b.page("http://localhost:9000").fetch("GET", PORTAL + "/api/session", mode="no-cors")
        assert recorder.last.headers["sec-fetch-site"] == "same-site"
        assert "origin" not in recorder.last.headers


def test_a_form_post_under_no_referrer_sends_a_null_origin() -> None:
    recorder = Recorder()
    with browser(recorder) as b:
        b.page(PORTAL).form_post("/api/logout", {"a": "1"})
    headers = recorder.last.headers
    assert (headers["origin"], headers["sec-fetch-mode"], headers["sec-fetch-dest"]) == (
        "null",
        "navigate",
        "document",
    )
    assert headers["content-type"] == "application/x-www-form-urlencoded"
    assert recorder.last.content == b"a=1"


def test_the_session_header_comes_from_session_storage_per_origin() -> None:
    recorder = Recorder()
    with browser(recorder) as b:
        b.page(PORTAL).storage["session"] = "header-half"
        b.page(PORTAL).fetch("GET", "/api/session")
        assert recorder.last.headers["x-zoeymcp-session"] == "header-half"
        b.page(PORTAL).fetch("GET", "/api/session", session=False)
        assert "x-zoeymcp-session" not in recorder.last.headers
        b.page("http://localhost:9000").fetch("GET", PORTAL + "/api/session")
        assert "x-zoeymcp-session" not in recorder.last.headers


def set_cookie(*values: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(200, headers=[("set-cookie", v) for v in values])


def test_cookies_are_kept_by_host_ignoring_ports() -> None:
    recorder = Recorder(set_cookie("zoeymcp-8081-session=c00k; HttpOnly; SameSite=Strict; Path=/"))
    with browser(recorder) as b:
        b.page(PORTAL).fetch("POST", "/api/login/finish", json={})
        recorder.answer = lambda request: httpx.Response(200)
        neighbour = b.page("http://localhost:9000")
        neighbour.fetch("GET", "/")  # its own origin: the cookie goes with it
        assert recorder.last.headers["cookie"] == "zoeymcp-8081-session=c00k"
        [cookie] = b.cookies
        assert (cookie.host, cookie.http_only, cookie.same_site) == ("localhost", True, "strict")


def test_samesite_on_navigations() -> None:
    recorder = Recorder(
        set_cookie("strict=s; SameSite=Strict; Path=/", "lax=l; SameSite=Lax; Path=/")
    )
    with browser(recorder) as b:
        b.navigate(PORTAL + "/")
        recorder.answer = lambda request: httpx.Response(200)
        b.navigate(PORTAL + "/")  # typed: both
        assert recorder.last.headers["cookie"] == "strict=s; lax=l"
        b.navigate(PORTAL + "/", initiator="https://evil.example")  # a cross-site link: Lax only
        assert recorder.last.headers["cookie"] == "lax=l"
        b.page("https://evil.example").load(PORTAL + "/", "image")  # a cross-site subresource
        assert "cookie" not in recorder.last.headers
        assert recorder.last.headers["sec-fetch-dest"] == "image"


def test_a_redirect_through_another_site_drops_strict_cookies() -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        if request.headers["host"] == "idp.example":
            return httpx.Response(303, headers={"location": PORTAL + "/oauth/callback/x?code=1"})
        return httpx.Response(200)

    recorder = Recorder(answer)
    with browser(recorder) as b:
        b.cookies.append(Cookie("strict", "s", "localhost", "/", False, True, "strict"))
        b.cookies.append(Cookie("lax", "l", "localhost", "/", False, True, "lax"))
        b.navigate("https://idp.example/authorize", initiator=PORTAL)
    last = recorder.last
    assert last.headers["sec-fetch-site"] == "cross-site"
    assert last.headers["cookie"] == "lax=l"
    assert "origin" not in last.headers
    assert [url for _, url, _ in b.history] == [
        "https://idp.example/authorize",
        PORTAL + "/oauth/callback/x?code=1",
    ]


@pytest.mark.parametrize(
    ("engine", "kept"),
    [("chrome", ["Secure-one"]), ("firefox", ["Secure-one"]), ("safari", [])],
)
def test_the_engines_rules_for_secure_and_host_cookies_over_http(
    engine: str, kept: list[str]
) -> None:
    recorder = Recorder(
        set_cookie("Secure-one=1; Secure; Path=/", "__Host-zoeymcp-session=2; Secure; Path=/")
    )
    with browser(recorder, engine) as b:
        b.navigate(PORTAL + "/")
        assert [cookie.name for cookie in b.cookies] == kept


def test_a_host_cookie_over_https_is_kept() -> None:
    recorder = Recorder(set_cookie("__Host-zoeymcp-session=2; Secure; HttpOnly; Path=/"))
    with browser(recorder, "safari") as b:
        b.navigate("https://zoeymcp.tailnet.example/")
        assert [cookie.name for cookie in b.cookies] == ["__Host-zoeymcp-session"]
        assert recorder.last.url.scheme == "http"  # through the TLS proxy, as plain HTTP


def test_an_expired_cookie_is_removed_and_paths_order_the_header() -> None:
    recorder = Recorder(set_cookie("a=1; Path=/", "a=2; Path=/api"))
    with browser(recorder) as b:
        b.page(PORTAL).fetch("GET", "/api/x")
        recorder.answer = lambda request: httpx.Response(200)
        b.page(PORTAL).fetch("GET", "/api/x")
        assert recorder.last.headers["cookie"] == "a=2; a=1"
        recorder.answer = set_cookie("a=; Max-Age=0; Path=/api")
        b.page(PORTAL).fetch("GET", "/api/x")
        assert [(c.name, c.value, c.path) for c in b.cookies] == [("a", "1", "/")]


def test_a_forged_request_sends_exactly_its_headers() -> None:
    recorder = Recorder()
    with browser(recorder) as b:
        b.cookies.append(Cookie("strict", "s", "localhost", "/", False, True, "strict"))
        b.forge(
            "POST", PORTAL + "/api/x", [("Host", "evil.example"), ("Origin", "a"), ("Origin", "b")]
        )
    headers = recorder.last.headers
    assert headers.get_list("host") == ["evil.example"]
    assert headers.get_list("origin") == ["a", "b"]
    assert "cookie" not in headers
    assert "sec-fetch-site" not in headers


def test_head_builds_a_request_head() -> None:
    assert head("GET / HTTP/1.1", "Host: x") == b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"


def test_a_remote_origin_is_served_by_its_own_client() -> None:
    """A fake provider in process: its URL kept, no Host forced, and its redirect followed into
    the portal as one cross-site chain, Lax cookies sent and Strict ones not (C.7)."""
    provider = Recorder(
        lambda request: httpx.Response(302, headers={"location": PORTAL + "/oauth/callback/x?c=1"})
    )
    portal = Recorder()
    remote = httpx.Client(transport=httpx.MockTransport(provider))
    b = Browser(transport=httpx.MockTransport(portal), remote={"https://idp.example": remote})
    b.plant(Cookie("lax", "1", "localhost", "/oauth/callback/x", False, True, "lax"))
    b.plant(Cookie("strict", "1", "localhost", "/", False, True, "strict"))
    b.navigate("https://idp.example/authorize?s=1", initiator=PORTAL)
    assert str(provider.last.url) == "https://idp.example/authorize?s=1"
    assert portal.last.headers["sec-fetch-site"] == "cross-site"
    assert portal.last.headers["cookie"] == "lax=1"
    b.close()
    remote.close()


def test_an_asgi_client_runs_the_app_in_process() -> None:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        await send({"type": "http.response.start", "status": 201, "headers": [(b"x-a", b"1")]})
        await send({"type": "http.response.body", "body": scope["path"].encode()})

    with asgi_client(app, "https://idp.example") as client:
        answer = client.get("/authorize")
    assert (answer.status_code, answer.headers["x-a"], answer.text) == (201, "1", "/authorize")
