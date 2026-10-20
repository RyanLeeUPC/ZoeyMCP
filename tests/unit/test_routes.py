"""The portal's route table and static map (M5 design M.1, O.2 ``routes``).

Step 6a builds the static map and the route shape; each of steps 11 to 15 adds the rows it builds,
and step 15 checks the table equals M.1. Until then M.1's table, written here in the shape, shows
the shape can hold every row and that matching finds each one.
"""

from __future__ import annotations

import dataclasses
import re
from typing import get_args

import pytest

from zoeymcp.portal.routes import (
    BODY_DEFAULT,
    BODY_EMPTY,
    BODY_PASTE,
    BODY_SECRET,
    BODY_WEBAUTHN,
    CSS,
    HTML,
    JAVASCRIPT,
    METHODS,
    PARAMS,
    ROUTES,
    STATIC,
    Method,
    Route,
    Scope,
    StaticFile,
    match,
)

FULL: frozenset[Scope] = frozenset({"full"})
SETUP: frozenset[Scope] = frozenset({"setup"})
BOTH: frozenset[Scope] = frozenset({"setup", "full"})
KIB = 1024

# M.1's API table in the route shape.
M1 = (
    Route("POST", "/api/login/begin", frozenset(), 64),
    Route(
        "POST", "/api/login/finish", frozenset(), 16 * KIB, frozenset({"ceremony", "credential"})
    ),
    Route("POST", "/api/setup/redeem", frozenset(), 4 * KIB, frozenset({"code"})),
    Route("GET", "/api/session", BOTH),
    Route("POST", "/api/logout", BOTH, 64),
    Route("GET", "/api/sessions", FULL),
    Route("POST", "/api/sessions/end-others", FULL, 64),
    Route("POST", "/api/passkeys/enrol/begin", SETUP, 4 * KIB, frozenset({"name"})),
    Route(
        "POST", "/api/passkeys/enrol/finish", BOTH, 16 * KIB, frozenset({"ceremony", "credential"})
    ),
    Route("GET", "/api/passkeys", FULL),
    Route("GET", "/api/secrets", FULL),
    Route("GET", "/api/health", FULL),
    Route("GET", "/api/policy", FULL),
    Route("GET", "/api/oauth", FULL),
    Route("POST", "/api/oauth/{credential}/start", FULL, 64, optional=frozenset({"rebind"})),
    Route("GET", "/api/oauth/flows/{flow}", FULL),
    Route("DELETE", "/api/oauth/flows/{flow}", FULL),
    Route("GET", "/api/ledger", FULL),
    Route("POST", "/api/actions", FULL, 128 * KIB, frozenset({"kind", "data"})),
    Route("POST", "/api/actions/{action}/confirm", FULL, 16 * KIB, frozenset({"credential"})),
    Route("DELETE", "/api/actions/{action}", FULL),
)
SAMPLE = {"credential": "github", "flow": "Zm9vYmFyLWZsb3ctaWQx", "action": "0123456789abcdef"}


def test_the_static_map_is_fixed() -> None:
    assert dict(STATIC) == {
        "/": StaticFile("index.html", "text/html; charset=utf-8"),
        "/app.js": StaticFile("app.js", "text/javascript; charset=utf-8"),
        "/webauthn.js": StaticFile("webauthn.js", "text/javascript; charset=utf-8"),
        "/app.css": StaticFile("app.css", "text/css; charset=utf-8"),
    }
    assert (HTML, JAVASCRIPT, CSS) == (
        "text/html; charset=utf-8",
        "text/javascript; charset=utf-8",
        "text/css; charset=utf-8",
    )
    with pytest.raises(TypeError):
        STATIC["/x"] = StaticFile("x", HTML)  # type: ignore[index]


def test_the_table_holds_only_built_routes() -> None:
    # Each of steps 11 to 15 adds the rows it builds: step 11's are M.1's first nine, step
    # 12's the passkey list and the three action routes, step 13's the secret list, and step
    # 14a's health, the OAuth list, a flow's start and its cancel (14b adds the flow's status).
    assert (*M1[:12], *M1[13:15], M1[16], *M1[18:]) == ROUTES
    assert [r.path for r in ROUTES if r.method == "POST" and r.cap == BODY_EMPTY] == [
        "/api/login/begin",
        "/api/logout",
        "/api/sessions/end-others",
        "/api/oauth/{credential}/start",
    ]
    assert (BODY_EMPTY, BODY_DEFAULT, BODY_WEBAUTHN) == (64, 4 * KIB, 16 * KIB)
    assert (BODY_SECRET, BODY_PASTE) == (128 * KIB, 8 * KIB)


def test_the_methods_and_scopes() -> None:
    assert {"GET", "POST", "DELETE"} == METHODS
    assert get_args(Method) == ("GET", "POST", "DELETE")
    assert get_args(Scope) == ("setup", "full")


def test_the_shapes_are_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        STATIC["/"].name = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        M1[0].cap = 1  # type: ignore[misc]


@pytest.mark.parametrize("route", M1, ids=lambda r: f"{r.method} {r.path}")
def test_every_m1_route_fits_the_shape_and_matches(route: Route) -> None:
    names = re.findall(r"\{(\w+)\}", route.path)
    assert set(names) <= set(PARAMS)
    assert route.method in METHODS
    assert route.path.startswith("/api/")
    assert (route.cap == 0) == (route.method != "POST")
    path = route.path.format(**SAMPLE)
    assert match(M1, route.method, path) == (route, {name: SAMPLE[name] for name in names})


def test_m1_has_one_route_per_method_and_path() -> None:
    keys = [(route.method, route.path) for route in M1]
    assert len(keys) == len(set(keys))


def test_unauthenticated() -> None:
    assert [r.path for r in M1 if r.unauthenticated] == [
        "/api/login/begin",
        "/api/login/finish",
        "/api/setup/redeem",
    ]
    assert not Route("GET", "/api/x", SETUP).unauthenticated


def test_the_route_defaults() -> None:
    route = Route("GET", "/api/x", FULL)
    assert (route.cap, route.body, route.optional) == (0, frozenset(), frozenset())


def test_nothing_matches_an_empty_table() -> None:
    assert match((), "GET", "/api/session") is None
    assert match(ROUTES, "GET", "/api/session") == (ROUTES[3], {})
    assert match(ROUTES, "GET", "/api/secrets") == (ROUTES[10], {})
    assert match(ROUTES, "GET", "/api/health") == (ROUTES[11], {})
    assert match(ROUTES, "GET", "/api/ledger") is None  # step 15's


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/api/session"),  # another method
        ("PUT", "/api/actions/0123/confirm"),
        ("GET", "/api/session/"),  # one segment more
        ("GET", "/api/sessio"),
        ("GET", "/api"),
        ("GET", "/api/oauth/flows"),  # one segment fewer
        ("POST", "/api/oauth/github/begin"),  # a literal segment differs
        ("POST", "/api/oauth//start"),
        ("GET", "api/session"),
        ("GET", "/API/session"),
    ],
)
def test_near_misses_match_nothing(method: str, path: str) -> None:
    assert match(M1, method, path) is None


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("github", True),
        ("a", True),
        ("0-mail_box", True),
        ("a" * 63, True),
        ("a" * 64, False),
        ("GitHub", False),
        ("-github", False),
        ("_github", False),
        ("git.hub", False),
        ("github\n", False),
        ("git%20hub", False),
        ("", False),
    ],
)
def test_a_credential_is_a_policy_name(value: str, ok: bool) -> None:
    found = match(M1, "POST", f"/api/oauth/{value}/start")
    assert (found is not None) == ok
    if ok:
        assert found == (M1[14], {"credential": value})


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("Zm9v_bar-1", True),
        ("0123456789abcdef0123456789abcdef", True),
        ("x", True),
        ("A" * 64, True),
        ("A" * 65, False),
        ("", False),
        ("a.b", False),
        ("a=", False),
        ("a+b", False),
        ("ab\n", False),
    ],
)
def test_a_flow_or_action_is_an_id(value: str, ok: bool) -> None:
    assert (match(M1, "DELETE", f"/api/oauth/flows/{value}") is not None) == ok
    assert (match(M1, "POST", f"/api/actions/{value}/confirm") is not None) == ok


def test_the_first_route_that_matches_wins() -> None:
    first = Route("GET", "/api/oauth/{credential}", FULL)
    second = Route("GET", "/api/oauth/{credential}", SETUP)
    assert match((first, second), "GET", "/api/oauth/github") == (first, {"credential": "github"})
    # A route of another method is passed over, not taken.
    post = Route("POST", "/api/oauth/{credential}", FULL)
    assert match((post, second), "GET", "/api/oauth/github") == (second, {"credential": "github"})


def test_a_segment_is_a_parameter_only_in_braces() -> None:
    odd = Route("GET", "/api/{x", FULL)
    assert match((odd,), "GET", "/api/{x") == (odd, {})
    assert match((odd,), "GET", "/api/x") is None
    closed = Route("GET", "/api/x}", FULL)
    assert match((closed,), "GET", "/api/x}") == (closed, {})


def test_every_parameter_of_a_path_is_returned() -> None:
    both = Route("GET", "/api/oauth/{credential}/flows/{flow}", FULL)
    assert match((both,), "GET", "/api/oauth/github/flows/abc") == (
        both,
        {"credential": "github", "flow": "abc"},
    )
    assert match((both,), "GET", "/api/oauth/github/flows/a.c") is None
    assert match((both,), "GET", "/api/oauth/GitHub/flows/abc") is None
