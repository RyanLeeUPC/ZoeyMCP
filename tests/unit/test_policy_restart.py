"""The restart classifier (M6 design I.2, O.3; D-193, D-47, D-61; Y16): every row, raised and
lowered, the startup comparisons repeating until a restart, and everything else live."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest

from zoeymcp.common.policy.restart import (
    ALLOWLIST_PATH,
    ALLOWLIST_TEXT,
    BRIDGE_TEXT,
    EGRESS_KEY_TEXT,
    GATEWAY_KEY_TEXT,
    LIMIT_TEXT,
    LISTEN_TEXT,
    PROXY_TEXT,
    Effect,
    Started,
    classify,
)
from zoeymcp.common.policy.schema import Policy
from zoeymcp.vault import gatewaykeys

LISTEN = "127.0.0.1:8081"  # the example's admin.listen
PROXY = "http://proxy.stack.example:3128"
STARTED = Started(
    egress_proxy=None, egress_proxy_kind="own", admin_listen=LISTEN, bridges=frozenset()
)
BRIDGE = "unix:/run/zoeymcp-bridge-notes/mcp.sock"

Edit = Callable[[dict[str, Any]], None]


@pytest.fixture
def make(example_raw: dict[str, Any]) -> Callable[..., Policy]:
    """The example, with each edit applied to a copy of its mapping."""

    def build(*edits: Edit) -> Policy:
        raw = copy.deepcopy(example_raw)
        for edit in edits:
            edit(raw)
        return Policy.model_validate(raw)

    return build


def setting(key: str, value: Any) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        if value is None:
            raw.pop(key, None)
        else:
            raw[key] = value

    return edit


def limit(name: str, value: int) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["gateway"].setdefault("limits", {})[name] = value

    return edit


def no_gateway(raw: dict[str, Any]) -> None:
    del raw["gateway"]


def listen(value: str | None) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        if value is None:
            del raw["admin"]
        else:
            raw["admin"]["listen"] = value

    return edit


def route(name: str, upstream: str) -> Edit:
    def edit(raw: dict[str, Any]) -> None:
        raw["routes"].append(
            {
                "name": name,
                "prefix": f"/{name}",
                "upstream": upstream,
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            }
        )

    return edit


def token_at(url: str) -> Edit:
    """A second oauth2 credential, like the example's, whose token endpoint is ``url``."""

    def edit(raw: dict[str, Any]) -> None:
        raw["credentials"]["second"] = {**raw["credentials"]["broker-mcp"], "token_url": url}

    return edit


def started(**changes: Any) -> Started:
    fields = {
        "egress_proxy": STARTED.egress_proxy,
        "egress_proxy_kind": STARTED.egress_proxy_kind,
        "admin_listen": STARTED.admin_listen,
        "bridges": STARTED.bridges,
        **changes,
    }
    return Started(**fields)


def test_the_texts_are_the_designs() -> None:
    """Fixed wording (I.2's table), pinned here once; each row's test compares the constant."""
    assert PROXY_TEXT == (
        "the vault's HTTP clients keep the proxy they started with: restart the vault"
    )
    assert LISTEN_TEXT == "the portal keeps listening where it started: restart the vault"
    assert LIMIT_TEXT == (
        "the gateway's session manager keeps the limit it started with: restart the gateway for "
        "the higher value; a lower one applies now"
    )
    assert EGRESS_KEY_TEXT == (
        "write the egress role's new key (zoeymcp egress-key) and restart the role: the old key "
        "is refused at once"
    )
    assert ALLOWLIST_TEXT == (
        "your proxy's allowlist is out of date: check --emit-egress-allowlist --check"
    )
    assert ALLOWLIST_PATH == "(egress allowlist)"


def test_the_same_policy_is_live(make: Callable[..., Policy]) -> None:
    assert classify(make(), make(), STARTED) == ()


def test_a_change_to_anything_else_is_live(make: Callable[..., Policy]) -> None:
    def other(raw: dict[str, Any]) -> None:
        raw["routes"][0]["rules"][0]["paths"] = ["/3.0/**"]
        raw["admin"]["origins"] = ["http://localhost:8081"]
        raw["gateway"]["hosts"] = ["localhost"]
        raw["gateway"]["clients"]["agent1"]["servers"] = ["mail"]

    new = make(other, limit("call_timeout", 600), limit("max_result_bytes", 8 * 2**20))
    assert classify(make(), new, STARTED) == ()


# --- the vault's startup values ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("at_start", "running", "new", "named"),
    [
        (None, None, PROXY, True),
        (PROXY, PROXY, None, True),
        (PROXY, PROXY, "http://other-proxy:3128", True),
        (PROXY, PROXY, PROXY, False),
        (None, None, None, False),
        # Against the startup value, not the running policy's: again until the restart...
        (None, PROXY, PROXY, True),
        # ...and a change back names nothing.
        (None, PROXY, None, False),
    ],
)
def test_an_egress_proxy_change_needs_a_vault_restart(
    make: Callable[..., Policy],
    at_start: str | None,
    running: str | None,
    new: str | None,
    named: bool,
) -> None:
    old = make(setting("egress_proxy", running))
    found = classify(old, make(setting("egress_proxy", new)), started(egress_proxy=at_start))
    effect = Effect("vault_restart", "egress_proxy", PROXY_TEXT)
    assert found == ((effect,) if named else ())


@pytest.mark.parametrize(
    ("at_start", "new", "named"),
    [
        ("own", "role", True),
        ("role", "own", True),
        ("role", "role", False),
        ("own", "own", False),
    ],
)
def test_an_egress_proxy_kind_change_needs_a_vault_restart(
    make: Callable[..., Policy], at_start: str, new: str, named: bool
) -> None:
    at = started(egress_proxy=PROXY, egress_proxy_kind=at_start)
    old = make(setting("egress_proxy", PROXY), setting("egress_proxy_kind", at_start))
    policy = make(setting("egress_proxy", PROXY), setting("egress_proxy_kind", new))
    effect = Effect("vault_restart", "egress_proxy_kind", PROXY_TEXT)
    assert classify(old, policy, at) == ((effect,) if named else ())


def test_both_proxy_settings_are_named_each(make: Callable[..., Policy]) -> None:
    new = make(setting("egress_proxy", PROXY), setting("egress_proxy_kind", "role"))
    assert classify(make(), new, STARTED) == (
        Effect("vault_restart", "egress_proxy", PROXY_TEXT),
        Effect("vault_restart", "egress_proxy_kind", PROXY_TEXT),
    )


@pytest.mark.parametrize(
    ("at_start", "new", "named"),
    [
        (LISTEN, "127.0.0.1:8082", True),
        (LISTEN, None, True),  # the block removed: the listener stays until a restart
        (None, LISTEN, True),  # a block added to a vault started without a portal
        (LISTEN, LISTEN, False),
        (None, None, False),
    ],
)
def test_an_admin_listen_change_needs_a_vault_restart(
    make: Callable[..., Policy], at_start: str | None, new: str | None, named: bool
) -> None:
    old = make(listen(at_start))
    found = classify(old, make(listen(new)), started(admin_listen=at_start))
    assert found == ((Effect("vault_restart", "admin.listen", LISTEN_TEXT),) if named else ())


def test_the_listen_is_compared_with_the_start_not_the_running_policy(
    make: Callable[..., Policy],
) -> None:
    moved = make(listen("127.0.0.1:8082"))
    effect = Effect("vault_restart", "admin.listen", LISTEN_TEXT)
    assert classify(moved, moved, STARTED) == (effect,)
    assert classify(moved, make(), STARTED) == ()


# --- the gateway's startup limits -------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "default"), [("max_request_bytes", 2**20), ("session_idle_timeout", 1800)]
)
@pytest.mark.parametrize(("step", "named"), [(1, True), (0, False), (-1, False)])
def test_a_raised_session_limit_needs_a_gateway_restart(
    make: Callable[..., Policy], name: str, default: int, step: int, named: bool
) -> None:
    """Raised: the session manager keeps the start's value. Lowered: the gateway's own checks
    apply it now."""
    old = make(limit(name, default))
    found = classify(old, make(limit(name, default + step)), STARTED)
    effect = Effect("gateway_restart", f"gateway.limits.{name}", LIMIT_TEXT)
    assert found == ((effect,) if named else ())


def test_both_limits_raised_are_named_each(make: Callable[..., Policy]) -> None:
    new = make(limit("max_request_bytes", 2**21), limit("session_idle_timeout", 3600))
    assert classify(make(), new, STARTED) == (
        Effect("gateway_restart", "gateway.limits.max_request_bytes", LIMIT_TEXT),
        Effect("gateway_restart", "gateway.limits.session_idle_timeout", LIMIT_TEXT),
    )


def test_a_policy_without_a_gateway_has_the_default_limits(make: Callable[..., Policy]) -> None:
    assert classify(make(no_gateway), make(), STARTED) == ()
    assert classify(make(), make(no_gateway), STARTED) == ()
    raised = make(limit("max_request_bytes", 2**20 + 1))
    effect = Effect("gateway_restart", "gateway.limits.max_request_bytes", LIMIT_TEXT)
    assert classify(make(no_gateway), raised, STARTED) == (effect,)
    lowered = make(limit("session_idle_timeout", 1799))
    assert classify(make(no_gateway), lowered, STARTED) == ()


# --- the key generations ----------------------------------------------------------------------


@pytest.mark.parametrize(("new", "named"), [(3, True), (2, False), (1, False)])
def test_a_raised_gateway_key_generation_is_delivered(
    make: Callable[..., Policy], new: int, named: bool
) -> None:
    old = make(setting("gateway_key_generation", 2))
    found = classify(old, make(setting("gateway_key_generation", new)), STARTED)
    text = "give the gateway key(3) within 5 minutes (zoeymcp gateway-key), or it is refused"
    assert GATEWAY_KEY_TEXT.format(generation=3) == text
    assert found == (
        (Effect("redeliver_gateway_key", "gateway_key_generation", text),) if named else ()
    )


def test_the_gateway_key_text_names_the_window() -> None:
    assert gatewaykeys.WINDOW == 5 * 60


@pytest.mark.parametrize(("new", "named"), [(3, True), (2, False), (1, False)])
def test_a_raised_egress_key_generation_is_delivered(
    make: Callable[..., Policy], new: int, named: bool
) -> None:
    old = make(setting("egress_key_generation", 2))
    found = classify(old, make(setting("egress_key_generation", new)), STARTED)
    effect = Effect("redeliver_egress_key", "egress_key_generation", EGRESS_KEY_TEXT)
    assert found == ((effect,) if named else ())


# --- the operator's proxy allowlist -----------------------------------------------------------

REEMIT = Effect("reemit_proxy_allowlist", ALLOWLIST_PATH, ALLOWLIST_TEXT)


@pytest.mark.parametrize(
    "edit",
    [
        route("files", "https://files.lan.example"),  # a new destination
        token_at("https://auth.files.example/token"),
        setting("egress_private", ["api.stats.example:443"]),  # private now
        setting("routes", None),  # every route gone
    ],
)
def test_a_changed_vault_list_outdates_your_proxys_allowlist(
    make: Callable[..., Policy], edit: Edit
) -> None:
    own = setting("egress_proxy", PROXY)
    at = started(egress_proxy=PROXY)
    assert classify(make(own), make(own, edit), at) == (REEMIT,)


def scraper(egress: list[str]) -> Edit:
    """A route whose program lists ``egress``: a source of its own."""

    def edit(raw: dict[str, Any]) -> None:
        route("scraper", "https://scraper.example")(raw)
        raw["routes"][-1]["program"] = {"egress": egress}

    return edit


def acls(names: dict[str, str]) -> Edit:
    return setting("egress_proxy_acls", names)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        # A route program's own list: the same file, so --check fails on it too.
        (scraper(["c.example:443"]), scraper(["c.example:443", "d.example:443"])),
        (scraper(["c.example:443"]), scraper(["c.example:8443"])),
        # The Squid form's source ACL names.
        (acls({}), acls({"vault": "stack_vault_net"})),
        (acls({"vault": "stack_vault_net"}), acls({"vault": "other_net"})),
    ],
)
def test_any_source_or_acl_name_check_compares_outdates_it(
    make: Callable[..., Policy], before: Edit, after: Edit
) -> None:
    own = setting("egress_proxy", PROXY)
    at = started(egress_proxy=PROXY)
    assert classify(make(own, before), make(own, after), at) == (REEMIT,)


def test_an_acl_name_for_no_source_outdates_nothing(make: Callable[..., Policy]) -> None:
    """No form names a source the lists don't have."""
    own = setting("egress_proxy", PROXY)
    at = started(egress_proxy=PROXY)
    assert classify(make(own), make(own, acls({"scraper": "stack_scraper_net"})), at) == ()


def test_a_route_moved_to_plain_http_outdates_it(make: Callable[..., Policy]) -> None:
    own = setting("egress_proxy", PROXY)
    at = started(egress_proxy=PROXY)
    https = make(own, route("files", "https://files.lan.example:8443"))
    http = make(own, route("files", "http://files.lan.example:8443"))
    assert classify(https, http, at) == (REEMIT,)


def test_a_change_the_lists_dont_show_outdates_nothing(make: Callable[..., Policy]) -> None:
    """A token endpoint at a host the vault already reaches adds a reason, which no emitted
    form shows."""
    own = setting("egress_proxy", PROXY)
    at = started(egress_proxy=PROXY)
    same_host = token_at("https://api.stats.example/oauth/token")
    assert classify(make(own), make(own, same_host), at) == ()


@pytest.mark.parametrize(
    ("proxy", "kind"),
    [
        (None, None),  # no proxy: no allowlist to keep
        (PROXY, "role"),  # the egress role fetches its lists from the vault
    ],
)
def test_without_your_own_proxy_there_is_no_allowlist_to_redo(
    make: Callable[..., Policy], proxy: str | None, kind: str | None
) -> None:
    settings = (setting("egress_proxy", proxy), setting("egress_proxy_kind", kind))
    at = started(egress_proxy=proxy, egress_proxy_kind=kind or "own")
    new = make(*settings, route("files", "https://files.lan.example"))
    assert classify(make(*settings), new, at) == ()


def test_the_new_policys_proxy_decides(make: Callable[..., Policy]) -> None:
    """A proxy set in the same change: its allowlist is new, and out of date if the vault's list
    changed too."""
    files = route("files", "https://files.lan.example")
    new = make(setting("egress_proxy", PROXY), files)
    assert classify(make(), new, STARTED) == (
        Effect("vault_restart", "egress_proxy", PROXY_TEXT),
        REEMIT,
    )


# --- bridges ----------------------------------------------------------------------------------


def test_a_route_to_a_bridge_not_started_names_it(make: Callable[..., Policy]) -> None:
    new = make(route("notes", BRIDGE))
    text = "the launcher didn't start bridge notes: add --bridge notes and recreate the container"
    assert BRIDGE_TEXT.format(name="notes") == text
    assert classify(make(), new, STARTED) == (Effect("start_bridge", "routes[3].upstream", text),)
    # Against the start: again on the next change, until the bridge runs.
    assert classify(new, new, STARTED) == (Effect("start_bridge", "routes[3].upstream", text),)


def test_a_started_bridge_names_nothing(make: Callable[..., Policy]) -> None:
    new = make(route("notes", BRIDGE))
    assert classify(make(), new, started(bridges=frozenset({"notes"}))) == ()
    assert classify(make(), new, started(bridges=frozenset({"other"}))) != ()


def test_each_route_to_a_missing_bridge_is_named(make: Callable[..., Policy]) -> None:
    new = make(route("notes", BRIDGE), route("files", "unix:/run/zoeymcp-bridge-files/mcp.sock"))
    found = classify(make(), new, started(bridges=frozenset({"files"})))
    assert [(effect.kind, effect.path) for effect in found] == [
        ("start_bridge", "routes[3].upstream")
    ]


def test_a_bridge_route_isnt_in_your_proxys_list(make: Callable[..., Policy]) -> None:
    own = setting("egress_proxy", PROXY)
    at = started(egress_proxy=PROXY, bridges=frozenset({"notes"}))
    assert classify(make(own), make(own, route("notes", BRIDGE)), at) == ()


# --- order ------------------------------------------------------------------------------------


def test_effects_come_in_the_tables_order(make: Callable[..., Policy]) -> None:
    new = make(
        setting("egress_proxy", PROXY),
        setting("egress_proxy_kind", "own"),
        listen("127.0.0.1:8082"),
        limit("max_request_bytes", 2**21),
        limit("session_idle_timeout", 3600),
        setting("gateway_key_generation", 2),
        setting("egress_key_generation", 2),
        route("notes", BRIDGE),
        route("files", "https://files.lan.example"),
    )
    at = started(egress_proxy_kind="role")
    assert [(effect.kind, effect.path) for effect in classify(make(), new, at)] == [
        ("vault_restart", "egress_proxy"),
        ("vault_restart", "egress_proxy_kind"),
        ("vault_restart", "admin.listen"),
        ("gateway_restart", "gateway.limits.max_request_bytes"),
        ("gateway_restart", "gateway.limits.session_idle_timeout"),
        ("redeliver_gateway_key", "gateway_key_generation"),
        ("redeliver_egress_key", "egress_key_generation"),
        ("reemit_proxy_allowlist", ALLOWLIST_PATH),
        ("start_bridge", "routes[3].upstream"),
    ]
