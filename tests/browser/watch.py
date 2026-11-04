"""What a page must never do, recorded for every page of a test's context (D-222).

:class:`Watch` records, from every page of one browser context: each ``securitypolicyviolation``
event (a Content Security Policy or Trusted Types violation, by an init script that hands it to
Python through a binding, so a navigation loses none), each console error, each uncaught page
error, each dialog (dismissed at once: the portal never opens one) and each request. The
context's fixture calls :meth:`Watch.assert_clean` when the test ends: no violation, no dialog,
no request off loopback, and no console or page error but those the test allowed, each by a
pattern and the page it comes from (a neighbour's page of its own, say). A host a test answers in
process, by a route of its context (item 9's provider page), isn't off loopback: the request
never leaves the browser.

The init script runs outside the page's CSP (it goes through the DevTools protocol) and uses no
Trusted Types sink, so recording a violation never makes one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from playwright.sync_api import BrowserContext, ConsoleMessage, Dialog, Request, WebError

from .engines import LOOPBACK, NAMES

BINDING = "zoeyHarnessViolation"
# The browser's own request for a page's icon, which the portal doesn't serve: headless Chromium
# logs its 404 as a console error, though the page never made the request.
FAVICON = re.compile(r"status of 404 .*\(https?://[^/)]+/favicon\.ico\)$")
RECORDER = (
    "window.addEventListener('securitypolicyviolation', (event) => {"
    f" window.{BINDING}({{directive: event.violatedDirective, blocked: event.blockedURI,"
    " sample: event.sample, page: document.location.href});"
    " }, true);"
)


@dataclass
class Watch:
    violations: list[dict[str, Any]] = field(default_factory=list)
    console: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    dialogs: list[tuple[str, str]] = field(default_factory=list)
    requests: list[Request] = field(default_factory=list)
    allowed: list[tuple[re.Pattern[str], str]] = field(default_factory=list)
    answered: set[str] = field(default_factory=set)

    def attach(self, context: BrowserContext) -> None:
        """Record every page ``context`` opens from now on."""
        context.expose_binding(BINDING, self._violation)
        context.add_init_script(script=RECORDER)
        context.on("console", self._console)
        context.on("weberror", self._error)
        context.on("dialog", self._dialog)
        context.on("request", self._request)

    def _violation(self, source: Any, report: dict[str, Any]) -> None:
        self.violations.append(report)

    def _request(self, request: Request) -> None:
        self.requests.append(request)

    def _console(self, message: ConsoleMessage) -> None:
        if message.type == "error":
            page = message.page.url if message.page is not None else ""
            source = message.location.get("url", "")
            self.console.append((page, f"{message.text} ({source})" if source else message.text))

    def _error(self, error: WebError) -> None:
        page = error.page.url if error.page is not None else ""
        self.errors.append((page, str(error.error)))

    def _dialog(self, dialog: Dialog) -> None:
        self.dialogs.append((dialog.type, dialog.message))
        dialog.dismiss()

    def allow(self, pattern: str, *, on: str = "") -> None:
        """An error the test expects (a refusal's 401, a neighbour's CORS error): every console
        or page error whose text ``pattern`` finds, from a page whose address starts with
        ``on``, is allowed."""
        self.allowed.append((re.compile(pattern), on))

    def posts(self) -> list[Request]:
        return [request for request in self.requests if request.method == "POST"]

    def stray(self) -> list[str]:
        """Each request to a host that isn't a test name, loopback or answered in process."""
        hosts = {*NAMES, *LOOPBACK, *self.answered}
        return [
            request.url
            for request in self.requests
            if urlsplit(request.url).scheme in ("http", "https")
            and urlsplit(request.url).hostname not in hosts
        ]

    def unexpected(self) -> list[tuple[str, str]]:
        """The console and page errors no allowance covers, with the page each came from."""
        return [
            (page, text)
            for page, text in [*self.console, *self.errors]
            if not FAVICON.search(text)
            and not any(
                pattern.search(text) and page.startswith(on) for pattern, on in self.allowed
            )
        ]

    def problems(self) -> dict[str, list[Any]]:
        """Each kind of thing the page did that it must not, with what was seen; empty if none."""
        found: dict[str, list[Any]] = {
            "violations": self.violations,
            "dialogs": self.dialogs,
            "stray requests": self.stray(),
            "errors": self.unexpected(),
        }
        return {kind: seen for kind, seen in found.items() if seen}

    def assert_clean(self) -> None:
        problems = self.problems()
        assert problems == {}, problems
