"""The portal's routes (M5 design M.1). Pure data, read by the app, the sweeps and the drift checks.

The static files are a fixed map from path to file, loaded once at start: no listing, no path
joining. Beside them, outside ``/api/`` and outside the map, is the one other route: the OAuth
callback, ``GET /oauth/callback/<credential>`` (C.7), a provider's redirect target that no page
script names. Every other path outside ``/api/`` is 404 (C.2 row 3).

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

from ..common.policy.callback import CALLBACK_PREFIX
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
        # Step 14b: where the callback sends the tab (C.7). No script, no text from the query.
        "/callback/received": StaticFile("callback-received.html", HTML),
        "/callback/refused": StaticFile("callback-refused.html", HTML),
    }
)
# The callback's two answers: the 303's target once the flow changed, and the page a refusal
# answers in place, so the code-bearing address stays in the bar for a paste.
CALLBACK_RECEIVED: Final = "/callback/received"
CALLBACK_REFUSED: Final = "/callback/refused"
# The callback route's template, for the log (M.4): the path never shows there, nor the query.
CALLBACK: Final = CALLBACK_PREFIX + "{credential}"
_CREDENTIAL: Final = re.compile(NAME_PATTERN)


def callback_credential(path: str) -> str | None:
    """The credential a callback path names: ``/oauth/callback/`` and one segment matching
    ``NAME_PATTERN``, else None."""
    if not path.startswith(CALLBACK_PREFIX):
        return None
    name = path.removeprefix(CALLBACK_PREFIX)
    return name if _CREDENTIAL.fullmatch(name) else None


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

# Body caps in bytes (F.1, M.1): an empty object, the default, a passkey's answer, a secret
# (M1's MAX_BODY, and what POST /api/actions reads before it knows the kind) and a paste.
BODY_EMPTY: Final = 64
BODY_DEFAULT: Final = 4 * 1024
BODY_WEBAUTHN: Final = 16 * 1024
BODY_SECRET: Final = 128 * 1024
BODY_PASTE: Final = 8 * 1024

NONE: Final[frozenset[Scope]] = frozenset()
SETUP: Final[frozenset[Scope]] = frozenset({"setup"})
FULL: Final[frozenset[Scope]] = frozenset({"full"})
BOTH: Final[frozenset[Scope]] = frozenset({"setup", "full"})
_CEREMONY: Final = frozenset({"ceremony", "credential"})

# Step 11: the three unauthenticated routes, the session, enrolment by a setup session, logout
# and the session list. A full session's enrolment begins with the passkey.enrol action and
# finishes here.
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
# Step 12: the passkey list and the step-up path (F.4). Every change a full session makes is an
# action: prepared, then confirmed with a passkey; the confirm takes only the assertion.
PASSKEYS: Final = Route("GET", "/api/passkeys", FULL)
ACTIONS: Final = Route("POST", "/api/actions", FULL, BODY_SECRET, frozenset({"kind", "data"}))
CONFIRM: Final = Route(
    "POST", "/api/actions/{action}/confirm", FULL, BODY_WEBAUTHN, frozenset({"credential"})
)
CANCEL: Final = Route("DELETE", "/api/actions/{action}", FULL)
# Step 13: the secret list, names and metadata only (G). Writing and deleting are actions.
SECRETS: Final = Route("GET", "/api/secrets", FULL)
# Step 14a: health (I), the OAuth credentials and connect by paste (H.1). A start writes no
# grant (a client_credentials start is a test fetch); completing and resetting are actions.
HEALTH: Final = Route("GET", "/api/health", FULL)
OAUTH: Final = Route("GET", "/api/oauth", FULL)
OAUTH_START: Final = Route(
    "POST", "/api/oauth/{credential}/start", FULL, BODY_EMPTY, optional=frozenset({"rebind"})
)
FLOW_CANCEL: Final = Route("DELETE", "/api/oauth/flows/{flow}", FULL)
# Step 14b: a flow as its owner's connect dialog polls it, for a flow that can take the
# callback (H.6). The callback itself is outside this table (CALLBACK).
FLOW_STATUS: Final = Route("GET", "/api/oauth/flows/{flow}", FULL)

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
    PASSKEYS,
    SECRETS,
    HEALTH,
    OAUTH,
    OAUTH_START,
    FLOW_STATUS,
    FLOW_CANCEL,
    ACTIONS,
    CONFIRM,
    CANCEL,
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
