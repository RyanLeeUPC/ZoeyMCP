"""The portal's routes (M5 design M.1). Pure data, read by the app, the sweeps and the drift checks.

The static files are a fixed map from path to file, loaded once at start: no listing, no path
joining. Every other path outside ``/api/`` is 404 (C.2 row 3).

The API table grows with the build: each of steps 11 to 15 adds the rows it builds, so a walk of
the table or a drift check against the page never meets a route that isn't built (verifier V40),
and from step 15 a test checks it equals M.1. A path parameter is checked against its pattern
before a route matches, so a handler never sees a name the policy couldn't hold.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from ..common.policy.schema import NAME_PATTERN

Method = Literal["GET", "POST", "DELETE"]
METHODS: Final = frozenset({"GET", "POST", "DELETE"})
# A session's scope: a setup session only enrols (F.2).
Scope = Literal["setup", "full"]

HTML: Final = "text/html; charset=utf-8"
JAVASCRIPT: Final = "text/javascript; charset=utf-8"
CSS: Final = "text/css; charset=utf-8"


@dataclass(frozen=True)
class StaticFile:
    """A file in ``portal/static/`` and the type it is served as."""

    name: str
    content_type: str


STATIC: Final[Mapping[str, StaticFile]] = MappingProxyType(
    {
        "/": StaticFile("index.html", HTML),
        "/app.js": StaticFile("app.js", JAVASCRIPT),
        "/webauthn.js": StaticFile("webauthn.js", JAVASCRIPT),
        "/app.css": StaticFile("app.css", CSS),
    }
)


@dataclass(frozen=True)
class Route:
    """One API route (M.1's columns).

    ``path`` is a template whose ``{name}`` segments are parameters (:data:`PARAMS`). ``scopes``
    are the sessions that reach it, none for an unauthenticated route. ``cap`` is the body cap
    in bytes, 0 for a route that takes no body; ``body`` the keys its JSON object must have and
    ``optional`` those it may have.
    """

    method: Method
    path: str
    scopes: frozenset[Scope]
    cap: int = 0
    body: frozenset[str] = frozenset()
    optional: frozenset[str] = frozenset()

    @property
    def unauthenticated(self) -> bool:
        return not self.scopes


# What a path parameter may be: a credential is a policy name; a flow or an action is the ID the
# vault gave it (base64url or hex).
PARAMS: Final[Mapping[str, re.Pattern[str]]] = MappingProxyType(
    {
        "credential": re.compile(NAME_PATTERN),
        "flow": re.compile(r"[A-Za-z0-9_-]{1,64}"),
        "action": re.compile(r"[A-Za-z0-9_-]{1,64}"),
    }
)

# Body caps in bytes (F.1, M.1): an empty object, the default, and a passkey's answer.
BODY_EMPTY: Final = 64
BODY_DEFAULT: Final = 4 * 1024
BODY_WEBAUTHN: Final = 16 * 1024

NONE: Final[frozenset[Scope]] = frozenset()
SETUP: Final[frozenset[Scope]] = frozenset({"setup"})
FULL: Final[frozenset[Scope]] = frozenset({"full"})
BOTH: Final[frozenset[Scope]] = frozenset({"setup", "full"})
_CEREMONY: Final = frozenset({"ceremony", "credential"})

# Step 11: the three unauthenticated routes, the session, enrolment by a setup session, logout
# and the session list. An enrolment a full session begins comes with step 12's passkey.enrol.
LOGIN_BEGIN: Final = Route("POST", "/api/login/begin", NONE, BODY_EMPTY)
LOGIN_FINISH: Final = Route("POST", "/api/login/finish", NONE, BODY_WEBAUTHN, _CEREMONY)
SETUP_REDEEM: Final = Route("POST", "/api/setup/redeem", NONE, BODY_DEFAULT, frozenset({"code"}))
SESSION: Final = Route("GET", "/api/session", BOTH)
LOGOUT: Final = Route("POST", "/api/logout", BOTH, BODY_EMPTY)
SESSIONS: Final = Route("GET", "/api/sessions", FULL)
END_OTHERS: Final = Route("POST", "/api/sessions/end-others", FULL, BODY_EMPTY)
ENROL_BEGIN: Final = Route(
    "POST", "/api/passkeys/enrol/begin", SETUP, BODY_DEFAULT, frozenset({"name"})
)
ENROL_FINISH: Final = Route("POST", "/api/passkeys/enrol/finish", BOTH, BODY_WEBAUTHN, _CEREMONY)

ROUTES: Final[tuple[Route, ...]] = (
    LOGIN_BEGIN,
    LOGIN_FINISH,
    SETUP_REDEEM,
    SESSION,
    LOGOUT,
    SESSIONS,
    END_OTHERS,
    ENROL_BEGIN,
    ENROL_FINISH,
)


def match(routes: Iterable[Route], method: str, path: str) -> tuple[Route, dict[str, str]] | None:
    """The route for ``method`` and ``path``, with its parameters, or None."""
    segments = path.split("/")
    for route in routes:
        template = route.path.split("/")
        if route.method != method or len(template) != len(segments):
            continue
        params = _params(template, segments)
        if params is not None:
            return route, params
    return None


def _params(template: list[str], segments: list[str]) -> dict[str, str] | None:
    params = {}
    for part, segment in zip(template, segments, strict=True):
        if part.startswith("{") and part.endswith("}"):
            name = part[1:-1]
            if not PARAMS[name].fullmatch(segment):
                return None
            params[name] = segment
        elif part != segment:
            return None
    return params
