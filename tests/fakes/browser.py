"""A portal "browser" over httpx, and a slowloris client, for the portal tests (M5 design O.1).

:class:`Browser` sends what a browser sends, so a test can show which callers admission refuses:

- ``Host`` as the address bar has it, while the connection goes to the rig's bound IP literal
  (``address``), so no test waits on Windows trying ``::1`` for ``localhost`` first (verifier
  V49). An ``https`` origin is reached in plain HTTP the same way, as through a TLS proxy that
  passes ``Host`` (C.5).
- ``Sec-Fetch-Site``, ``-Mode`` and ``-Dest`` as Fetch Metadata computes them, ``Sec-Fetch-Site``
  over a navigation's whole redirect chain; ``Origin`` as Fetch adds it: on a cross-origin
  ``fetch()`` and on any other method than ``GET`` and ``HEAD``, and ``null`` for a form post
  from a ``no-referrer`` page.
- Cookies by host, **ignoring ports**, as browsers keep them (RFC 6265 §8.5), so a page on
  another localhost port receives the portal's cookie; ``SameSite`` as browsers apply it; the
  engines' rules for ``Secure`` and ``__Host-`` over ``http://localhost`` (``safari`` keeps no
  ``Secure`` cookie there; ``chrome`` and ``firefox`` keep one but refuse ``__Host-``).
- ``sessionStorage`` per origin: :meth:`Page.fetch` sends its ``session`` key as the
  ``X-ZoeyMCP-Session`` header, as the portal's page does (F.2).

The modes of O.1 are pages of other origins (:meth:`Browser.page`): the portal's own page, a
cross-site page, a neighbour on another localhost port, a DNS-rebinding page (a hostile name
resolving to the portal's address); a form post (:meth:`Page.form_post`); a top-level navigation
(:meth:`Browser.navigate`), typed or from a page, following redirects; a subresource
(:meth:`Page.load`); a second browser (another :class:`Browser`); and a non-browser that forges
every header (:meth:`Browser.forge`). :class:`Slowloris` holds connections idle, trickles a head
or sends a body slowly, on raw sockets.
"""

from __future__ import annotations

import email.utils
import http.cookiejar
import json as jsonlib
import socket
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal
from urllib.parse import urljoin, urlsplit

import httpx

Engine = Literal["chrome", "firefox", "safari"]
Relation = Literal["same-origin", "same-site", "cross-site", "none"]
SameSite = Literal["strict", "lax", "none"]
# Where a host and port really are: the rig's bound IP literal and port.
Address = Callable[[str, int], tuple[str, int]]

SESSION_HEADER: Final = "X-ZoeyMCP-Session"
SESSION_KEY: Final = "session"
REDIRECTS: Final = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS: Final = 20
DEFAULT_PORTS: Final = {"http": 80, "https": 443}
CRLF: Final = bytes((13, 10))


class _NoJar(http.cookiejar.CookieJar):
    """Keeps nothing, so httpx never sends a cookie the fake didn't choose."""

    def extract_cookies(self, response: Any, request: Any) -> None:
        pass

    def set_cookie(self, cookie: http.cookiejar.Cookie) -> None:
        pass


def loopback(host: str, port: int) -> tuple[str, int]:
    """Every name is the rig on ``127.0.0.1``, at the port the address bar has."""
    return "127.0.0.1", port


def origin_of(url: str) -> str:
    """``scheme://host[:port]``, lower case, without the default port."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    if port is None or port == DEFAULT_PORTS.get(parts.scheme):
        return f"{parts.scheme}://{host}"
    return f"{parts.scheme}://{host}:{port}"


def site_of(origin: str) -> tuple[str, str]:
    """The schemeful site: the scheme and the registrable domain, here the last two labels of a
    name (enough for the tests' names), or the whole host for ``localhost`` and an IP."""
    parts = urlsplit(origin)
    host = (parts.hostname or "").lower()
    labels = host.split(".")
    numeric = host.replace(".", "").isdigit() or ":" in host
    domain = host if numeric or len(labels) <= 2 else ".".join(labels[-2:])
    return parts.scheme, domain


def relation(initiator: str | None, target: str) -> Relation:
    """``Sec-Fetch-Site`` for one request from ``initiator`` (an origin; None: the user typed
    it) to the origin ``target``."""
    if initiator is None:
        return "none"
    if initiator == target:
        return "same-origin"
    return "same-site" if site_of(initiator) == site_of(target) else "cross-site"


def chain_relation(initiator: str | None, urls: Sequence[str]) -> Relation:
    """``Sec-Fetch-Site`` over a redirect chain (Fetch Metadata §2.4): the least related hop."""
    if initiator is None:
        return "none"
    order: list[Relation] = ["same-origin", "same-site", "cross-site"]
    return max((relation(initiator, origin_of(url)) for url in urls), key=order.index)


@dataclass
class Cookie:
    name: str
    value: str
    host: str
    path: str
    secure: bool
    http_only: bool
    same_site: SameSite
    created: int = 0


def _potentially_trustworthy(url: str) -> bool:
    parts = urlsplit(url)
    return parts.scheme == "https" or (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")


def _default_path(path: str) -> str:
    if not path.startswith("/") or path.count("/") == 1:
        return "/"
    return path[: path.rindex("/")]


def _path_matches(request_path: str, cookie_path: str) -> bool:
    if request_path == cookie_path:
        return True
    if not request_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or request_path[len(cookie_path)] == "/"


class Browser:
    """One browser profile: its cookie jar and its ``sessionStorage``. ``transport`` replaces
    the network (the fake's self-test)."""

    def __init__(
        self,
        *,
        engine: Engine = "chrome",
        address: Address = loopback,
        transport: httpx.BaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.engine = engine
        self.address = address
        self.cookies: list[Cookie] = []
        self.session_storage: dict[str, dict[str, str]] = {}
        # Each navigation's requests, last one last: (method, url, the headers sent).
        self.history: list[tuple[str, str, httpx.Headers]] = []
        self._created = 0
        # The jar is this class's: httpx's own would keep and send cookies by its own rules.
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            cookies=_NoJar(),
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Browser:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def page(self, origin: str) -> Page:
        """A page this browser has loaded from ``origin``."""
        return Page(self, origin_of(origin))

    def tab(self, origin: str) -> Page:
        """A page of ``origin`` in a tab of its own: the same cookie jar, but its own
        ``sessionStorage``, as each tab has."""
        page = Page(self, origin_of(origin))
        page.storage = {}
        return page

    # --- navigation ---------------------------------------------------------------------------

    def navigate(
        self,
        url: str,
        *,
        initiator: str | None = None,
        method: str = "GET",
        content: bytes | None = None,
        headers: Sequence[tuple[str, str]] = (),
        origin_header: str | None = None,
    ) -> httpx.Response:
        """A top-level navigation, typed (``initiator`` None) or from a page of ``initiator``,
        following redirects as a browser does. Returns the last answer."""
        urls = [url]
        while True:
            site = chain_relation(initiator, urls)
            sent = [
                ("Sec-Fetch-Site", site),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Dest", "document"),
                *([("Sec-Fetch-User", "?1")] if initiator is None else []),
                *headers,
            ]
            if origin_header is not None and method not in ("GET", "HEAD"):
                sent.append(("Origin", origin_header))
            response = self._send(
                method, urls[-1], sent, content, strict=site != "cross-site", lax=method == "GET"
            )
            location = response.headers.get("location")
            if response.status_code not in REDIRECTS or location is None:
                return response
            if len(urls) > MAX_REDIRECTS:
                raise RuntimeError("too many redirects")
            urls.append(urljoin(urls[-1], location))
            if response.status_code == 303 or (
                response.status_code in (301, 302) and method == "POST"
            ):
                method, content, headers = "GET", None, ()

    def forge(
        self,
        method: str,
        url: str,
        headers: Sequence[tuple[str, str]] = (),
        content: bytes | None = None,
    ) -> httpx.Response:
        """A non-browser: exactly ``headers`` (and ``Host`` unless they give one), no cookies."""
        return self._raw(method, url, list(headers), content)

    # --- the wire -------------------------------------------------------------------------------

    def _send(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        content: bytes | None,
        *,
        strict: bool,
        lax: bool,
    ) -> httpx.Response:
        jar = self._cookie_header(url, strict=strict, lax=lax)
        if jar:
            headers = [*headers, ("Cookie", jar)]
        response = self._raw(method, url, headers, content)
        self.history.append((method, url, response.request.headers))
        self._store(url, response)
        return response

    def _raw(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        content: bytes | None,
    ) -> httpx.Response:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port or DEFAULT_PORTS[parts.scheme]
        ip, real_port = self.address(host, port)
        netloc = f"[{ip}]:{real_port}" if ":" in ip else f"{ip}:{real_port}"
        target = parts._replace(scheme="http", netloc=netloc).geturl()
        if not any(name.lower() == "host" for name, _ in headers):
            headers = [("Host", parts.netloc), *headers]
        return self._client.request(method, target, headers=headers, content=content)

    def _cookie_header(self, url: str, *, strict: bool, lax: bool) -> str:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        trustworthy = _potentially_trustworthy(url) and self.engine != "safari"
        secure_ok = parts.scheme == "https" or trustworthy
        chosen = [
            cookie
            for cookie in self.cookies
            if cookie.host == host
            and _path_matches(parts.path or "/", cookie.path)
            and (secure_ok or not cookie.secure)
            and (cookie.same_site != "strict" or strict)
            and (cookie.same_site != "lax" or strict or lax)
        ]
        chosen.sort(key=lambda c: (-len(c.path), c.created))
        return "; ".join(f"{cookie.name}={cookie.value}" for cookie in chosen)

    def _store(self, url: str, response: httpx.Response) -> None:
        for header in response.headers.get_list("set-cookie"):
            self._store_one(url, header)

    def _store_one(self, url: str, header: str) -> None:
        parts = urlsplit(url)
        pair, *attributes = header.split(";")
        name, equals, value = pair.strip().partition("=")
        if not equals or not name:
            return
        path = _default_path(parts.path or "/")
        secure = http_only = False
        same_site: SameSite = "lax"
        expired = False
        has_domain = False
        for attribute in attributes:
            key, _, argument = attribute.strip().partition("=")
            key = key.lower()
            if key == "path" and argument.startswith("/"):
                path = argument
            elif key == "secure":
                secure = True
            elif key == "httponly":
                http_only = True
            elif key == "samesite" and argument.lower() in ("strict", "lax", "none"):
                same_site = argument.lower()  # type: ignore[assignment]
            elif key == "max-age":
                expired = expired or int(argument) <= 0
            elif key == "expires":
                when = email.utils.parsedate_to_datetime(argument).timestamp()
                expired = expired or when <= time.time()
            elif key == "domain":
                has_domain = True
        over_http = parts.scheme != "https"
        if secure and over_http and not (_potentially_trustworthy(url) and self.engine != "safari"):
            return  # Safari keeps no Secure cookie over http, nor anyone on a plain name
        if name.startswith("__Host-") and (not secure or path != "/" or has_domain or over_http):
            return  # Chrome and Firefox refuse __Host- over http; Safari refused Secure above
        if name.startswith("__Secure-") and not secure:
            return
        host = (parts.hostname or "").lower()
        self.cookies = [c for c in self.cookies if (c.name, c.host, c.path) != (name, host, path)]
        if expired:
            return
        self._created += 1
        self.cookies.append(
            Cookie(name, value.strip(), host, path, secure, http_only, same_site, self._created)
        )

    def plant(self, cookie: Cookie) -> None:
        """A cookie another page set, as a neighbour on another port can."""
        self._created += 1
        cookie.created = self._created
        self.cookies.append(cookie)


@dataclass
class Page:
    """A page of ``origin`` in ``browser``: its script's ``fetch()``, forms and subresources."""

    browser: Browser
    origin: str
    storage: dict[str, str] = field(init=False)

    def __post_init__(self) -> None:
        self.storage = self.browser.session_storage.setdefault(self.origin, {})

    def url(self, target: str) -> str:
        return urljoin(self.origin + "/", target)

    def fetch(
        self,
        method: str,
        target: str,
        *,
        json: Any = None,
        content: bytes | None = None,
        headers: Sequence[tuple[str, str]] = (),
        session: bool = True,
        mode: Literal["cors", "no-cors", "same-origin"] = "cors",
    ) -> httpx.Response:
        """``fetch(target, {method, credentials: "same-origin", redirect: "error"})`` as the
        portal's page calls it (C.4), with the session header from ``sessionStorage``."""
        url = self.url(target)
        site = relation(self.origin, origin_of(url))
        sent: list[tuple[str, str]] = [
            ("Sec-Fetch-Site", site),
            ("Sec-Fetch-Mode", mode),
            ("Sec-Fetch-Dest", "empty"),
        ]
        cross = site != "same-origin"
        if (cross and mode == "cors") or method not in ("GET", "HEAD"):
            sent.append(("Origin", self.origin))
        if json is not None:
            content = jsonlib.dumps(json, separators=(",", ":")).encode()
            sent.append(("Content-Type", "application/json"))
        if session and SESSION_KEY in self.storage:
            sent.append((SESSION_HEADER, self.storage[SESSION_KEY]))
        sent.extend(headers)
        # credentials: "same-origin" sends cookies only to the page's own origin.
        if cross:
            return self.browser._raw(method, url, sent, content)
        return self.browser._send(method, url, sent, content, strict=True, lax=True)

    def form_post(
        self, target: str, fields: Mapping[str, str], *, origin_header: str = "null"
    ) -> httpx.Response:
        """A ``<form method=post>`` submitted at top level. Under ``no-referrer`` its
        ``Origin`` is ``null``."""
        body = "&".join(f"{k}={v}" for k, v in fields.items()).encode()
        return self.browser.navigate(
            self.url(target),
            initiator=self.origin,
            method="POST",
            content=body,
            headers=[("Content-Type", "application/x-www-form-urlencoded")],
            origin_header=origin_header,
        )

    def link(self, target: str) -> httpx.Response:
        """A link the user follows (or a ``GET`` form): a top-level navigation from this page."""
        return self.browser.navigate(self.url(target), initiator=self.origin)

    def load(
        self, target: str, dest: Literal["iframe", "embed", "image", "script", "style"]
    ) -> httpx.Response:
        """A subresource this page embeds: an ``<iframe>`` navigates in a frame; the others are
        ``no-cors`` loads. Cookies follow ``SameSite`` against the page's site."""
        url = self.url(target)
        site = relation(self.origin, origin_of(url))
        mode = "navigate" if dest == "iframe" else "no-cors"
        sent = [("Sec-Fetch-Site", site), ("Sec-Fetch-Mode", mode), ("Sec-Fetch-Dest", dest)]
        same = site in ("same-origin", "same-site")
        return self.browser._send("GET", url, sent, None, strict=same, lax=same)


class Slowloris:
    """Raw connections to ``address`` that hold the listener: idle, a head trickled a byte at a
    time, a body sent slowly."""

    def __init__(self, address: tuple[str, int]) -> None:
        self.address = address
        self.sockets: list[socket.socket] = []

    def __enter__(self) -> Slowloris:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        for sock in self.sockets:
            sock.close()
        self.sockets.clear()

    def connect(self) -> socket.socket:
        sock = socket.create_connection(self.address, timeout=10)
        self.sockets.append(sock)
        return sock

    def idle(self, count: int) -> list[socket.socket]:
        """``count`` connections that send nothing."""
        return [self.connect() for _ in range(count)]

    @staticmethod
    def trickle(sock: socket.socket, data: bytes, every: float) -> bool:
        """Send ``data`` a byte every ``every`` seconds. False if the peer closed first."""
        for index in range(len(data)):
            try:
                sock.sendall(data[index : index + 1])
            except OSError:
                return False
            if Slowloris.closed(sock, every):
                return False
        return True

    @staticmethod
    def closed(sock: socket.socket, within: float) -> bool:
        """True if the peer closes (or resets) the connection within ``within`` seconds; any
        answer bytes read meanwhile are dropped."""
        deadline = time.monotonic() + within
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            sock.settimeout(left)
            try:
                if not sock.recv(65536):
                    return True
            except TimeoutError:
                return False
            except OSError:
                return True

    @staticmethod
    def answer(sock: socket.socket, timeout: float = 10.0) -> bytes:
        """Every byte until the peer closes."""
        sock.settimeout(timeout)
        data = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except OSError:
                return data
            if not chunk:
                return data
            data += chunk


def head(*lines: str) -> bytes:
    """A request head: the lines, each ended by CRLF, then the empty line."""
    return b"".join(line.encode("latin-1") + CRLF for line in (*lines, ""))


def statuses(responses: Iterable[httpx.Response]) -> list[int]:
    return [response.status_code for response in responses]
