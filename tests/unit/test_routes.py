"""The portal's route table and static map (M5 design M.1, O.2 ``routes``; M7 design K.2).

Step 6a built the static map and the route shape, and each of steps 11 to 15 added the rows it
built. From step 15 the table is M.1's, written here in the shape, and from M7 step 14a M.1's
with K.2's, the route table M7 publishes (fold-in R27), before the step-up rows: the table equals
them, and matching finds each row.
"""

from __future__ import annotations

import dataclasses
import re
from typing import get_args

import pytest

from zoeymcp.portal.routes import (
    BODY_CHOICES,
    BODY_DEFAULT,
    BODY_EMPTY,
    BODY_PASTE,
    BODY_SECRET,
    BODY_WEBAUTHN,
    CALLBACK,
    CALLBACK_RECEIVED,
    CALLBACK_REFUSED,
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
    callback_credential,
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
)
# M.1's step-up routes, the table's last rows.
ACTION_ROWS = (
    Route("POST", "/api/actions", FULL, 128 * KIB, frozenset({"kind", "data"})),
    Route("POST", "/api/actions/{action}/confirm", FULL, 16 * KIB, frozenset({"credential"})),
    Route("DELETE", "/api/actions/{action}", FULL),
)
# M7 K.2's table: the MCP servers section.
DISCOVER_KEYS = frozenset(
    {
        "credential",
        "route",
        "server",
        "issuer",
        "scope",
        "client_id",
        "client_auth",
        "redirect_uri",
        "client_name",
    }
)
K2 = (
    Route("GET", "/api/servers", FULL),
    Route("POST", "/api/onboard/discover", FULL, 4 * KIB, frozenset({"url"}), DISCOVER_KEYS),
    Route("GET", "/api/onboard/{onboarding}", FULL),
    Route("POST", "/api/onboard/{onboarding}/fragment", FULL, 64, optional=frozenset({"indent"})),
    Route("DELETE", "/api/onboard/{onboarding}", FULL),
    Route("POST", "/api/review/{server}", FULL, 64),
    Route("GET", "/api/review/jobs/{job}", FULL),
    Route(
        "POST",
        "/api/review/jobs/{job}/diff",
        FULL,
        512 * KIB,
        frozenset({"include", "allow", "approve"}),
        frozenset({"indent"}),
    ),
)
TABLE = (*M1, *K2, *ACTION_ROWS)
SAMPLE = {
    "credential": "github",
    "flow": "Zm9vYmFyLWZsb3ctaWQx",
    "action": "0123456789abcdef",
    "onboarding": "o32x0000000000000000000000000000000000000001",
    "job": "jQx_-000000000000000000000000000000000000001",
    "server": "notes",
}


def test_the_static_map_is_fixed() -> None:
    assert dict(STATIC) == {
        "/": StaticFile("index.html", "text/html; charset=utf-8"),
        "/app.js": StaticFile("app.js", "text/javascript; charset=utf-8"),
        "/webauthn.js": StaticFile("webauthn.js", "text/javascript; charset=utf-8"),
        "/app.css": StaticFile("app.css", "text/css; charset=utf-8"),
        "/callback/received": StaticFile("callback-received.html", "text/html; charset=utf-8"),
        "/callback/refused": StaticFile("callback-refused.html", "text/html; charset=utf-8"),
    }
    assert (CALLBACK_RECEIVED, CALLBACK_REFUSED) == ("/callback/received", "/callback/refused")
    assert (HTML, JAVASCRIPT, CSS) == (
        "text/html; charset=utf-8",
        "text/javascript; charset=utf-8",
        "text/css; charset=utf-8",
    )
    with pytest.raises(TypeError):
        STATIC["/x"] = StaticFile("x", HTML)  # type: ignore[index]


def test_the_table_is_m1s_with_k2s() -> None:
    # Steps 11 to 15 each added the rows they built (verifier V40); step 15's were the policy
    # view and the ledger, the last of M.1's. M7's step 14a added K.2's, before the actions.
    assert ROUTES == TABLE
    assert [r.path for r in ROUTES if r.method == "POST" and r.cap == BODY_EMPTY] == [
        "/api/login/begin",
        "/api/logout",
        "/api/sessions/end-others",
        "/api/oauth/{credential}/start",
        "/api/onboard/{onboarding}/fragment",
        "/api/review/{server}",
    ]
    assert (BODY_EMPTY, BODY_DEFAULT, BODY_WEBAUTHN) == (64, 4 * KIB, 16 * KIB)
    assert (BODY_SECRET, BODY_PASTE, BODY_CHOICES) == (128 * KIB, 8 * KIB, 512 * KIB)


def test_k2_takes_no_private_discovery() -> None:
    """TI-3: a discovery with allow_private goes through the action, so the route's body has
    no such key; and K.2's rows all need a full session."""
    discover = next(r for r in ROUTES if r.path == "/api/onboard/discover")
    assert "allow_private" not in discover.body | discover.optional
    assert all(route.scopes == FULL for route in K2)
    assert [r for r in ROUTES if r.cap == BODY_CHOICES] == [K2[-1]]


def test_the_methods_and_scopes() -> None:
    assert {"GET", "POST", "DELETE"} == METHODS
    assert get_args(Method) == ("GET", "POST", "DELETE")
    assert get_args(Scope) == ("setup", "full")


def test_the_shapes_are_frozen() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        STATIC["/"].name = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        M1[0].cap = 1  # type: ignore[misc]


@pytest.mark.parametrize("route", TABLE, ids=lambda r: f"{r.method} {r.path}")
def test_every_route_fits_the_shape_and_matches(route: Route) -> None:
    names = re.findall(r"\{(\w+)\}", route.path)
    assert set(names) <= set(PARAMS)
    assert route.method in METHODS
    assert route.path.startswith("/api/")
    assert (route.cap == 0) == (route.method != "POST")
    path = route.path.format(**SAMPLE)
    assert match(TABLE, route.method, path) == (route, {name: SAMPLE[name] for name in names})


def test_the_table_has_one_route_per_method_and_path() -> None:
    keys = [(route.method, route.path) for route in TABLE]
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
    assert match(ROUTES, "GET", "/api/policy") == (ROUTES[12], {})
    assert match(ROUTES, "GET", "/api/ledger") == (ROUTES[17], {})
    assert match(ROUTES, "GET", "/api/servers") == (ROUTES[18], {})


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
    ("method", "path", "route", "params"),
    [
        # A literal segment where a parameter could be: each method finds its own route.
        ("POST", "/api/onboard/discover", K2[1], {}),
        ("GET", "/api/onboard/discover", K2[2], {"onboarding": "discover"}),
        ("DELETE", "/api/onboard/discover", K2[4], {"onboarding": "discover"}),
        ("POST", "/api/review/jobs", K2[5], {"server": "jobs"}),
        ("GET", "/api/review/jobs/j1", K2[6], {"job": "j1"}),
        ("POST", "/api/review/jobs/j1/diff", K2[7], {"job": "j1"}),
    ],
)
def test_the_k2_routes_match_by_method_and_length(
    method: str, path: str, route: Route, params: dict[str, str]
) -> None:
    assert match(ROUTES, method, path) == (route, params)


@pytest.mark.parametrize(
    "path",
    [
        "/api/review/Notes",  # a server is a policy name
        "/api/review/-notes",
        "/api/review/" + "a" * 64,
        "/api/review/jobs/j.1/diff",  # a job is the vault's ID
        "/api/review/jobs/" + "j" * 65 + "/diff",
        "/api/onboard/a%2Fb/fragment",
        "/api/onboard/" + "o" * 65 + "/fragment",
        "/api/review/jobs/j1/diff/",
    ],
)
def test_a_k2_parameter_outside_its_pattern_matches_nothing(path: str) -> None:
    assert match(ROUTES, "POST", path) is None


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
def test_a_flow_action_onboarding_or_job_is_an_id(value: str, ok: bool) -> None:
    assert (match(TABLE, "DELETE", f"/api/oauth/flows/{value}") is not None) == ok
    assert (match(TABLE, "POST", f"/api/actions/{value}/confirm") is not None) == ok
    assert (match(TABLE, "DELETE", f"/api/onboard/{value}") is not None) == ok
    assert (match(TABLE, "GET", f"/api/review/jobs/{value}") is not None) == ok


def test_the_parameters() -> None:
    assert set(PARAMS) == {"credential", "flow", "action", "onboarding", "job", "server"}
    assert PARAMS["server"].pattern == PARAMS["credential"].pattern
    assert PARAMS["onboarding"].pattern == PARAMS["job"].pattern == PARAMS["flow"].pattern


def test_the_first_route_that_matches_wins() -> None:
    first = Route("GET", "/api/oauth/{credential}", FULL)
    second = Route("GET", "/api/oauth/{credential}", SETUP)
    assert match((first, second), "GET", "/api/oauth/github") == (first, {"credential": "github"})
    # A route of another method is passed over, not taken.
    post = Route("POST", "/api/oauth/{credential}", FULL)
    assert match((post, second), "GET", "/api/oauth/github") == (second, {"credential": "github"})


# --- the callback, beside the static map (C.7) ----------------------------------------------------


def test_the_callback_route_is_outside_the_api_table() -> None:
    """A provider's redirect target that no page script names, so it isn't in ROUTES; its
    template is what the log names, never the path or the query (M.4)."""
    assert CALLBACK == "/oauth/callback/{credential}"
    assert not any(route.path.startswith("/oauth/") for route in ROUTES)
    assert CALLBACK_RECEIVED in STATIC
    assert CALLBACK_REFUSED in STATIC


@pytest.mark.parametrize(
    ("path", "credential"),
    [
        ("/oauth/callback/github", "github"),
        ("/oauth/callback/a", "a"),
        ("/oauth/callback/0-mail_box", "0-mail_box"),
        ("/oauth/callback/" + "a" * 63, "a" * 63),
        ("/oauth/callback/" + "a" * 64, None),
        ("/oauth/callback/GitHub", None),
        ("/oauth/callback/-github", None),
        ("/oauth/callback/git.hub", None),
        ("/oauth/callback/github/", None),
        ("/oauth/callback/github/x", None),
        ("/oauth/callback/github\n", None),
        ("/oauth/callback/git%68ub", None),  # the raw path: never decoded
        ("/oauth/callback/", None),
        ("/oauth/callback", None),
        ("/callback", None),
        ("/x/oauth/callback/github", None),
        ("/OAUTH/callback/github", None),
    ],
)
def test_a_callback_path_names_one_credential(path: str, credential: str | None) -> None:
    assert callback_credential(path) == credential


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
