"""Credential health (M5 design I): every finding both ways, bindings judged by effect, the
connector journal summed up, and the meta-derived ``last_failure`` and ``idle`` (D-23, D-20).
M7 (design J, step 10b): a stored client secret held to D.7 step 5 as login holds it (D-185),
``resource_metadata_changed``, the challenged scope and its ``widen_scope`` fragment, and an
onboarding's secret waiting for its credential; (step 11) a registered client's secret near or
past its expiry, on the wall clock; (step 16) the address guard's refusals, ``address_refused``;
(step 17b) an egress role that stopped fetching its lists, ``egress_allowlist_stale`` (COV-7);
(step 18d) the bridges' routes: ``program_unconfined``, ``loopback_bridge_route``,
``bridge_socket_unknown`` and ``program_secret_unflagged`` (C.10, Q46). M6 (design M.5, step 7):
the ``gateway`` section from the gateway's status report: ``tools_unreviewed``, ``drift_marked``,
``server_blocked``, ``server_listing_invalid`` and ``gateway_status_stale``; (step 13b) the
``policy`` section from the policy store's state, in managed and declarative mode.

:func:`assess` takes clear metadata only, so nothing here has a value to decrypt; the admin
socket's test checks that against a store whose decryption raises.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.attention import Attention
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault import health
from zoeymcp.vault.bindings import BindingError, client_secret_rebound, oauth_binding
from zoeymcp.vault.connectors.sendjournal import DAY_MS, Journal
from zoeymcp.vault.health import (
    DISPLAY_ONLY,
    ONBOARDING_SUFFIXES,
    REGRESSION_DAYS,
    STALE_SECONDS,
    Bridges,
    Inputs,
    LedgerCopy,
    PasskeyState,
    PolicyState,
    Sends,
    assess,
    failure_text,
    idle,
    idle_text,
    judge,
    last_failure,
    parse_time,
    sends,
)
from zoeymcp.vault.internal import ALLOWLIST_MAX_STALE
from zoeymcp.vault.statusreport import GatewayStatus, ServerStatus
from zoeymcp.vault.statusreport import Report as StatusReport
from zoeymcp.vault.store import EntryMeta, origin_binding, smtp_binding

TOKEN_URL = "https://accounts.example/token"
OTHER_TOKEN_URL = "https://login.other.example/token"
AUTHORIZE_URL = "https://accounts.example/authorize"
API = "https://api.example/v1"
API_ORIGIN = "https://api.example:443"
OTHER = "https://other.example/v2"
OTHER_ORIGIN = "https://other.example:443"
EXTRA_ORIGIN = "https://extra.example:443"
NOW = 1_790_000_000.0  # 2026-09-21T14:13:20Z
DAY = 86400
BASE: dict[str, Any] = {"version": 1, "mode": "declarative"}
MAIL: dict[str, Any] = {
    "kind": "smtp",
    "host": "smtp.mail.example",
    "port": 465,
    "username": "env:MAIL_USER",
    "password": "store:mail-pass",
    "from": "Agent <agent@mail.example>",
    "to": ["partner@mail.example"],
    "max_per_day": 20,
}
MAIL_BINDING = smtp_binding("smtp.mail.example", 465, "Agent <agent@mail.example>", MAIL["to"])


def make_policy(
    credentials: Mapping[str, Mapping[str, Any]],
    routes: Mapping[str, Sequence[str]] | None = None,
    connectors: Mapping[str, Mapping[str, Any]] | None = None,
) -> Policy:
    """Each credential gets a route per upstream; by default one, to ``API``."""
    route_list: list[dict[str, Any]] = []
    for name in credentials:
        for upstream in (routes or {}).get(name, (API,)):
            index = len(route_list)
            route_list.append(
                {
                    "name": f"r{index}",
                    "prefix": f"/r{index}",
                    "upstream": upstream,
                    "credential": name,
                    "callers": [{"placeholder": f"ph-agent{index}-direct-0001"}],
                    "rules": [{"methods": ["GET"], "paths": ["/**"]}],
                }
            )
    for name in connectors or {}:
        route_list.append(
            {
                "name": f"send-{name}",
                "prefix": f"/send-{name}",
                "connector": name,
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            }
        )
    return Policy.model_validate(
        {
            **BASE,
            "routes": route_list,
            "credentials": dict(credentials),
            "connectors": dict(connectors or {}),
        }
    )


def header(ref: str = "store:notes-key") -> dict[str, Any]:
    return {"kind": "header", "secret": ref}


def spotify(**fields: Any) -> dict[str, Any]:
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": TOKEN_URL,
        "authorize_url": AUTHORIZE_URL,
        "client_id": "store:music-id",
        "client_secret": "store:music-secret",
        "refresh_token": "store:music-refresh",
    }
    cred.update(fields)
    return cred


def machine(**fields: Any) -> dict[str, Any]:
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": TOKEN_URL,
        "grant": "client_credentials",
        "client_id": "store:machine-id",
        "client_secret": "store:machine-secret",
    }
    cred.update(fields)
    return cred


def entry(name: str, binding: Mapping[str, Any], meta: Any = None) -> EntryMeta:
    return EntryMeta(
        name, dict(binding), "kid", "2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z", meta
    )


def status(credential: str = "music", **fields: Any) -> dict[str, Any]:
    """An item of ``LoginService.status()`` with nothing to report."""
    item: dict[str, Any] = {
        "credential": credential,
        "state": "idle",
        "code": None,
        "action": None,
        "meta": None,
        "last_ok_ago": None,
        "reconsent_due": None,
        "scopes": None,
        "upstream": None,
        "resource_metadata": None,
        "last_failure": None,
        "idle": None,
    }
    item.update(fields)
    return item


def report(
    policy: Policy,
    entries: Sequence[EntryMeta] = (),
    env: Sequence[str] = (),
    oauth: Sequence[Mapping[str, Any]] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    return assess(Inputs(policy, entries, frozenset(env), oauth, **fields))


def one(found: dict[str, Any], section: str = "credentials") -> dict[str, Any]:
    [item] = found[section]
    result: dict[str, Any] = item
    return result


def codes(item: Mapping[str, Any]) -> list[str]:
    return [f["code"] for f in item["findings"]]


def finding(
    code: str, level: str, text: str, action: Mapping[str, str] | None, *, advisory: bool = False
) -> dict[str, Any]:
    return {
        "code": code,
        "level": level,
        "advisory": advisory,
        "text": text,
        "action": None if action is None else dict(action),
    }


SPOTIFY_ENTRIES = (
    entry("music-id", oauth_binding(TOKEN_URL, [API])),
    entry("music-secret", oauth_binding(TOKEN_URL, [API])),
    entry("music-refresh", oauth_binding(TOKEN_URL, [API])),
)


# --- the whole report --------------------------------------------------------------------------


def test_a_healthy_deployment() -> None:
    policy = make_policy({"notes": header(), "music": spotify()}, connectors={"mail": MAIL})
    entries = [
        entry("notes-key", origin_binding([API])),
        *SPOTIFY_ENTRIES,
        entry("mail-pass", MAIL_BINDING),
    ]
    meta = {"oauth": {"source": "login", "consented_at": "2026-09-01T00:00:00Z", "rotations": 2}}
    found = report(
        policy,
        entries,
        env=["MAIL_USER"],
        oauth=[status(state="ok", meta=meta["oauth"], last_ok_ago=60)],
        sends={
            "mail": Sends(3, 0, {"state": "sent", "at": "2026-09-21T13:00:00Z", "smtp_code": 250})
        },
    )
    assert found["summary"] == {"error": 0, "warning": 0, "info": 0}
    assert found["credentials"] == [
        {
            "name": "notes",
            "kind": "header",
            "level": "ok",
            "routes": ["r0"],
            "refs": [{"ref": "store:notes-key", "present": True, "binding": "ok"}],
            "findings": [],
        },
        {
            "name": "music",
            "kind": "oauth2",
            "level": "ok",
            "routes": ["r1"],
            "refs": [
                {"ref": "store:music-id", "present": True, "binding": "ok"},
                {"ref": "store:music-secret", "present": True, "binding": "ok"},
                {"ref": "store:music-refresh", "present": True, "binding": "ok"},
            ],
            "oauth": {
                "state": "ok",
                "code": None,
                "source": "login",
                "consented_at": "2026-09-01T00:00:00Z",
                "rotations": 2,
                "last_ok_ago": 60,
                "display_only": list(DISPLAY_ONLY),
            },
            "findings": [],
        },
    ]
    assert found["connectors"] == [
        {
            "name": "mail",
            "level": "ok",
            "paused": False,
            "sent_24h": 3,
            "max_per_day": 20,
            "last": {"state": "sent", "at": "2026-09-21T13:00:00Z", "smtp_code": 250},
            "refs": [
                {"ref": "env:MAIL_USER", "present": True, "binding": None},
                {"ref": "store:mail-pass", "present": True, "binding": "ok"},
            ],
            "findings": [],
        }
    ]
    assert found["store"] == {"entries": 5, "level": "ok", "findings": []}
    assert DISPLAY_ONLY == ("source", "consented_at", "rotations", "last_ok_ago")


def test_the_summary_counts_every_section_and_the_worst_level_wins() -> None:
    policy = make_policy(
        {"notes": header(), "files": header("store:files-key")},
        connectors={"mail": {**MAIL, "paused": True}},
    )
    entries = [
        entry("notes-key", origin_binding([API, OTHER])),
        entry("files-key", origin_binding([OTHER])),
        entry("old", origin_binding([API])),
    ]
    found = report(policy, entries, env=["MAIL_USER"], persisted=False)
    # notes: wider (info); files: changed (error); mail: missing (error), paused (info);
    # store: unreferenced (info), degraded (error).
    assert found["summary"] == {"error": 3, "warning": 0, "info": 3}
    assert [c["level"] for c in found["credentials"]] == ["info", "error"]
    assert found["connectors"][0]["level"] == "error"
    assert found["store"]["level"] == "error"
    oauth = make_policy({"music": spotify()})
    stale = report(oauth, SPOTIFY_ENTRIES, oauth=[status(upstream={"code": "x", "at": "t"})])
    assert one(stale)["level"] == "warning"
    assert stale["summary"] == {"error": 0, "warning": 1, "info": 0}


def test_nothing_in_the_policy() -> None:
    assert report(make_policy({})) == {
        "summary": {"error": 0, "warning": 0, "info": 0},
        "credentials": [],
        "connectors": [],
        "store": {"entries": 0, "level": "ok", "findings": []},
        "egress": {"level": "ok", "findings": []},
    }


# --- references --------------------------------------------------------------------------------


def test_a_store_reference_with_no_entry() -> None:
    found = one(report(make_policy({"notes": header()})))
    assert found["refs"] == [{"ref": "store:notes-key", "present": False, "binding": None}]
    assert found["findings"] == [
        finding(
            "missing",
            "error",
            "store:notes-key has no entry",
            {"kind": "set_secret", "credential": "notes", "ref": "store:notes-key"},
        )
    ]


@pytest.mark.parametrize(
    ("fields", "action"),
    [
        ({}, {"kind": "connect", "credential": "music"}),
        (
            {"authorize_url": None},
            {"kind": "set_secret", "credential": "music", "ref": "store:music-refresh"},
        ),
    ],
)
def test_a_refresh_token_with_no_entry_is_renewed(
    fields: dict[str, Any], action: dict[str, str]
) -> None:
    found = one(report(make_policy({"music": spotify(**fields)}), SPOTIFY_ENTRIES[:2]))
    assert found["findings"] == [
        finding("missing", "error", "store:music-refresh has no entry", action)
    ]


def test_an_env_reference() -> None:
    policy = make_policy({"notes": header("env:NOTES_KEY")})
    unset = one(report(policy))
    assert unset["refs"] == [{"ref": "env:NOTES_KEY", "present": False, "binding": None}]
    assert unset["findings"] == [
        finding(
            "env_unset",
            "error",
            "env NOTES_KEY isn't set",
            {"kind": "restart", "credential": "notes", "ref": "env:NOTES_KEY"},
        )
    ]
    found = one(report(policy, env=["NOTES_KEY"]))
    assert found["refs"] == [{"ref": "env:NOTES_KEY", "present": True, "binding": None}]
    assert found["findings"] == []


def test_a_basic_credential_has_two_references() -> None:
    policy = make_policy(
        {"files": {"kind": "basic", "username": "env:FILES_USER", "secret": "store:files"}}
    )
    found = one(report(policy, [entry("files", origin_binding([API]))]))
    assert found["refs"] == [
        {"ref": "store:files", "present": True, "binding": "ok"},
        {"ref": "env:FILES_USER", "present": False, "binding": None},
    ]
    assert codes(found) == ["env_unset"]
    literal = make_policy(
        {"files": {"kind": "basic", "username": "agent", "secret": "store:files"}}
    )
    assert one(report(literal, [entry("files", origin_binding([API]))]))["refs"] == [
        {"ref": "store:files", "present": True, "binding": "ok"}
    ]


# --- bindings, judged by effect (verifier V9) --------------------------------------------------

WIDER = "store:notes-key is bound to more than the policy uses; it works"
CHANGED = "store:notes-key isn't bound to a use the policy makes now; the vault refuses that use"
SET_NOTES = {"kind": "set_secret", "credential": "notes", "ref": "store:notes-key"}


@pytest.mark.parametrize(
    ("routes", "binding", "verdict"),
    [
        ((API,), origin_binding([API]), "ok"),
        ((API, OTHER), origin_binding([API, OTHER]), "ok"),
        # An explicit --origin, or a route removed since: it works.
        ((API,), origin_binding([API, OTHER]), "wider"),
        ((), origin_binding([API]), "wider"),
        # A route added since: the vault refuses it.
        ((API, OTHER), origin_binding([API]), "changed"),
        ((API,), origin_binding([OTHER]), "changed"),
        # Another kind of binding is no origins at all.
        ((API,), MAIL_BINDING, "changed"),
        ((API,), oauth_binding(TOKEN_URL, [API]), "changed"),
        ((API,), {"origins": "https://api.example:443"}, "changed"),
        ((API,), {"origins": [API_ORIGIN, 7]}, "ok"),
        # No route sends it anywhere, so nothing is refused.
        ((), MAIL_BINDING, "ok"),
    ],
)
def test_a_static_binding(routes: tuple[str, ...], binding: dict[str, Any], verdict: str) -> None:
    policy = make_policy({"notes": header()}, {"notes": routes})
    found = one(report(policy, [entry("notes-key", binding)]))
    assert found["refs"] == [{"ref": "store:notes-key", "present": True, "binding": verdict}]
    expected = {
        "ok": [],
        "wider": [finding("binding_wider", "info", WIDER, SET_NOTES)],
        "changed": [finding("binding_changed", "error", CHANGED, SET_NOTES)],
    }[verdict]
    assert found["findings"] == expected


def test_an_explicit_binding_is_told_apart_from_a_stale_one() -> None:
    """A secret two credentials share: each use is judged on its own."""
    policy = make_policy(
        {"notes": header(), "files": header()}, {"notes": (API,), "files": (OTHER,)}
    )
    covers_notes = report(policy, [entry("notes-key", origin_binding([API, EXTRA_ORIGIN]))])
    notes, files = covers_notes["credentials"]
    assert notes["refs"][0]["binding"] == "ok"
    assert files["refs"][0]["binding"] == "changed"
    covers_both = report(policy, [entry("notes-key", origin_binding([API, OTHER, EXTRA_ORIGIN]))])
    assert [c["refs"][0]["binding"] for c in covers_both["credentials"]] == ["wider", "wider"]


@pytest.mark.parametrize(
    ("binding", "verdict"),
    [
        (MAIL_BINDING, "ok"),
        (
            smtp_binding(
                "smtp.mail.example", 465, "Agent <agent@mail.example>", ["x@mail.example"]
            ),
            "changed",
        ),
        (
            smtp_binding("smtp.mail.example", 587, "Agent <agent@mail.example>", MAIL["to"]),
            "changed",
        ),
        (origin_binding(["https://smtp.mail.example"]), "changed"),
    ],
)
def test_a_connector_binding_must_be_exact(binding: dict[str, Any], verdict: str) -> None:
    policy = make_policy({}, connectors={"mail": MAIL})
    found = one(report(policy, [entry("mail-pass", binding)], env=["MAIL_USER"]), "connectors")
    assert found["refs"][1] == {"ref": "store:mail-pass", "present": True, "binding": verdict}
    if verdict == "ok":
        assert found["findings"] == []
    else:
        assert found["findings"] == [
            finding(
                "binding_changed",
                "error",
                "store:mail-pass isn't bound to a use the policy makes now; the vault refuses "
                "that use",
                {"kind": "set_secret", "connector": "mail", "ref": "store:mail-pass"},
            )
        ]


def test_a_connector_reference_with_no_entry() -> None:
    policy = make_policy({}, connectors={"mail": MAIL})
    found = one(report(policy, env=["MAIL_USER"]), "connectors")
    assert found["findings"] == [
        finding(
            "missing",
            "error",
            "store:mail-pass has no entry",
            {"kind": "set_secret", "connector": "mail", "ref": "store:mail-pass"},
        )
    ]
    unset = one(report(policy, [entry("mail-pass", MAIL_BINDING)]), "connectors")
    assert unset["findings"] == [
        finding(
            "env_unset",
            "error",
            "env MAIL_USER isn't set",
            {"kind": "restart", "connector": "mail", "ref": "env:MAIL_USER"},
        )
    ]


@pytest.mark.parametrize(
    ("name", "binding", "verdict"),
    [
        # The refresh token and its access tokens: every route's origin.
        ("music-refresh", oauth_binding(TOKEN_URL, [API, OTHER]), "ok"),
        ("music-refresh", oauth_binding(TOKEN_URL, [API]), "changed"),
        ("music-refresh", oauth_binding(TOKEN_URL, [API, OTHER, EXTRA_ORIGIN]), "wider"),
        ("music-refresh", oauth_binding(OTHER_TOKEN_URL, [API, OTHER]), "changed"),
        ("music-refresh", origin_binding([API, OTHER]), "changed"),
        ("music-refresh", {"oauth": "x"}, "changed"),
        ("music-refresh", {"oauth": {"token": "https://accounts.example:443"}}, "changed"),
        # A client ID of a refresh grant: only its token endpoint is checked. Its client
        # secret is held to D.7 step 5 instead (test_a_client_secret_is_held_as_login_holds_it).
        ("music-id", oauth_binding(TOKEN_URL, [API]), "ok"),
        ("music-id", oauth_binding(TOKEN_URL, [EXTRA_ORIGIN]), "ok"),
        ("music-id", oauth_binding(OTHER_TOKEN_URL, [API, OTHER]), "changed"),
    ],
)
def test_an_oauth_binding(name: str, binding: dict[str, Any], verdict: str) -> None:
    policy = make_policy({"music": spotify()}, {"music": (API, OTHER)})
    exact = oauth_binding(TOKEN_URL, [API, OTHER])
    entries = [
        entry(n, binding if n == name else exact)
        for n in ("music-id", "music-secret", "music-refresh")
    ]
    found = one(report(policy, entries))
    rows = {row["ref"]: row["binding"] for row in found["refs"]}
    assert rows == {
        "store:music-id": "ok",
        "store:music-secret": "ok",
        "store:music-refresh": "ok",
        f"store:{name}": verdict,
    }
    renew = {"kind": "connect", "credential": "music"}
    action = (
        renew
        if name == "music-refresh"
        else {
            "kind": "set_secret",
            "credential": "music",
            "ref": f"store:{name}",
        }
    )
    expected = {
        "ok": [],
        "wider": [
            finding(
                "binding_wider",
                "info",
                f"store:{name} is bound to more than the policy uses; it works",
                action,
            )
        ],
        "changed": [
            finding(
                "binding_changed",
                "error",
                f"store:{name} isn't bound to a use the policy makes now; the vault refuses "
                "that use",
                action,
            )
        ],
    }[verdict]
    assert found["findings"] == expected


@pytest.mark.parametrize(
    ("name", "binding", "verdict"),
    [
        ("machine-secret", oauth_binding(TOKEN_URL, [API]), "ok"),
        # A client_credentials secret bounds the access tokens.
        ("machine-secret", oauth_binding(TOKEN_URL, [OTHER]), "changed"),
        ("machine-secret", oauth_binding(TOKEN_URL, [API, OTHER]), "wider"),
        # Its client ID is checked against the token endpoint only.
        ("machine-id", oauth_binding(TOKEN_URL, [OTHER]), "ok"),
        ("machine-id", oauth_binding(OTHER_TOKEN_URL, [API]), "changed"),
    ],
)
def test_a_client_credentials_binding(name: str, binding: dict[str, Any], verdict: str) -> None:
    policy = make_policy({"machine": machine()})
    exact = oauth_binding(TOKEN_URL, [API])
    entries = [entry(n, binding if n == name else exact) for n in ("machine-id", "machine-secret")]
    found = one(report(policy, entries))
    rows = {row["ref"]: row["binding"] for row in found["refs"]}
    assert rows[f"store:{name}"] == verdict
    if verdict != "ok":
        [only] = found["findings"]
        assert only["action"] == {
            "kind": "set_secret",
            "credential": "machine",
            "ref": f"store:{name}",
        }


# --- a stored client secret (M7 design D.7 step 5; D-185) ---------------------------------------

RESOURCE = "https://mcp.music.example/mcp"
REGISTER_AGAIN = {
    "kind": "onboard_again",
    "credential": "music",
    "command": f"zoeymcp login --mcp {RESOURCE} --reregister",
}
SET_SECRET = {"kind": "set_secret", "credential": "music", "ref": "store:music-secret"}
REFUSED_TEXT = (
    "store:music-secret was stored for another token endpoint or other server origins than the "
    "policy has now; login refuses it"
)


@pytest.mark.parametrize(
    ("binding", "refused"),
    [
        (oauth_binding(TOKEN_URL, [API, OTHER]), False),
        # Token endpoint right, but the routes differ: judge alone said ok.
        (oauth_binding(TOKEN_URL, [EXTRA_ORIGIN]), True),
        # A route added since it was stored.
        (oauth_binding(TOKEN_URL, [API]), True),
        # A route removed since: wider covers every use, but login wants it exact.
        (oauth_binding(TOKEN_URL, [API, OTHER, EXTRA_ORIGIN]), True),
        # Another token endpoint: one finding, the one login refuses with, not binding_changed.
        (oauth_binding(OTHER_TOKEN_URL, [API, OTHER]), True),
        (origin_binding([API, OTHER]), True),
    ],
)
def test_a_client_secret_is_held_as_login_holds_it(binding: dict[str, Any], refused: bool) -> None:
    """Health reports what login refuses as client_secret_binding_changed, from the same
    function (bindings.client_secret_rebound)."""
    policy = make_policy({"music": spotify()}, {"music": (API, OTHER)})
    exact = oauth_binding(TOKEN_URL, [API, OTHER])
    entries = [
        entry("music-id", exact),
        entry("music-secret", binding),
        entry("music-refresh", exact),
    ]
    found = one(report(policy, entries))
    rows = {row["ref"]: row["binding"] for row in found["refs"]}
    assert rows["store:music-secret"] == ("changed" if refused else "ok")
    expected = [finding("client_secret_binding_changed", "error", REFUSED_TEXT, SET_SECRET)]
    assert found["findings"] == (expected if refused else [])
    held = {e.name: e for e in entries}
    cred = policy.credentials["music"]
    assert isinstance(cred, OAuth2Credential)
    rebound = client_secret_rebound(policy, cred, held.get)
    if refused:
        assert rebound is not None
        assert (rebound.name, rebound.old, rebound.new) == ("music-secret", binding, exact)
    else:
        assert rebound is None


@pytest.mark.parametrize(
    ("upstreams", "stored", "action"),
    [
        # Another token endpoint: a re-registration stores the binding the policy derives.
        ((RESOURCE,), oauth_binding(OTHER_TOKEN_URL, [RESOURCE]), REGISTER_AGAIN),
        # A route added: a re-registration would store the server's origin alone again.
        ((RESOURCE, API), oauth_binding(TOKEN_URL, [RESOURCE]), SET_SECRET),
        # Routed elsewhere than the resource it names.
        ((API,), oauth_binding(OTHER_TOKEN_URL, [API]), SET_SECRET),
    ],
)
def test_an_onboarded_client_secret_is_registered_again_when_that_clears_it(
    upstreams: tuple[str, ...], stored: dict[str, Any], action: dict[str, Any]
) -> None:
    """--reregister stores the secret under fragment 1's binding (onboard._binding): the token
    endpoint and the server's origin. It is offered only when that is what the policy derives."""
    cred = spotify(extra_params={"resource": RESOURCE}, authorize_params={"resource": RESOURCE})
    policy = make_policy({"music": cred}, {"music": upstreams})
    exact = oauth_binding(TOKEN_URL, upstreams)
    entries = [
        entry("music-id", exact),
        entry("music-secret", stored),
        entry("music-refresh", exact),
    ]
    found = one(report(policy, entries))
    assert found["findings"] == [
        finding("client_secret_binding_changed", "error", REFUSED_TEXT, action)
    ]


def test_a_second_credential_naming_the_secret_changes_its_binding() -> None:
    policy = make_policy(
        {"music": spotify(), "radio": spotify(refresh_token="store:radio-refresh")},
        {"music": (API,), "radio": (OTHER,)},
    )
    entries = [
        entry("music-id", oauth_binding(TOKEN_URL, [API, OTHER])),
        entry("music-secret", oauth_binding(TOKEN_URL, [API])),
        entry("music-refresh", oauth_binding(TOKEN_URL, [API])),
        entry("radio-refresh", oauth_binding(TOKEN_URL, [OTHER])),
    ]
    found = report(policy, entries)
    assert [codes(item) for item in found["credentials"]] == [
        ["client_secret_binding_changed"],
        ["client_secret_binding_changed"],
    ]


@pytest.mark.parametrize(
    "cred",
    [
        # No login: a refresh token given by other means, or the client_credentials grant, whose
        # secret also bounds the access tokens (test_a_client_credentials_binding).
        spotify(authorize_url=None),
        machine(client_secret="store:music-secret"),
        # The grant alone: login fetches a client_credentials token, whatever authorize_url says.
        machine(client_secret="store:music-secret", authorize_url=AUTHORIZE_URL),
        # Not from the store.
        spotify(client_secret="env:MUSIC_SECRET"),
    ],
)
def test_only_a_stored_client_secret_that_logs_in_is_held_to_it(cred: dict[str, Any]) -> None:
    policy = make_policy({"music": cred})
    stale = entry("music-secret", oauth_binding(TOKEN_URL, [EXTRA_ORIGIN]))
    entries = [*SPOTIFY_ENTRIES[::2], entry("machine-id", oauth_binding(TOKEN_URL, [API])), stale]
    found = one(report(policy, entries, env=["MUSIC_SECRET"]))
    assert "client_secret_binding_changed" not in codes(found)


def test_a_client_secret_the_policy_cant_bind_or_that_is_missing() -> None:
    no_route = make_policy({"music": spotify()}, {"music": ()})
    found = one(report(no_route, SPOTIFY_ENTRIES))
    assert codes(found) == ["no_route"] * 3
    missing = one(report(make_policy({"music": spotify()}), SPOTIFY_ENTRIES[::2]))
    assert codes(missing) == ["missing"]
    none: dict[str, EntryMeta] = {}
    unset = OAuth2Credential.model_validate(spotify())
    assert client_secret_rebound(make_policy({"music": spotify()}), unset, none.get) is None
    # A secret from env: is never looked up, whatever the store holds.
    from_env = spotify(client_secret="env:MUSIC_SECRET")
    stale = entry("music-secret", oauth_binding(TOKEN_URL, [EXTRA_ORIGIN]))
    assert (
        client_secret_rebound(
            make_policy({"music": from_env}),
            OAuth2Credential.model_validate(from_env),
            lambda name: stale,
        )
        is None
    )


def test_a_policy_that_cant_bind_a_name() -> None:
    """The code is BindingError's reason, as the secret write would refuse it (G)."""
    conflict = make_policy(
        {"notes": header("store:shared")}, connectors={"mail": {**MAIL, "password": "store:shared"}}
    )
    found = report(conflict, [entry("shared", MAIL_BINDING)], env=["MAIL_USER"])
    text = "'shared' is used both by a connector and by HTTP credentials"
    assert one(found)["refs"] == [
        {"ref": "store:shared", "present": True, "binding": "binding_conflict"}
    ]
    assert one(found)["findings"] == [
        finding("binding_conflict", "error", text, {"kind": "fix_policy", "credential": "notes"})
    ]
    assert one(found, "connectors")["findings"] == [
        finding("binding_conflict", "error", text, {"kind": "fix_policy", "connector": "mail"})
    ]
    no_route = make_policy({"music": spotify()}, {"music": ()})
    found = one(report(no_route, SPOTIFY_ENTRIES))
    assert [r["binding"] for r in found["refs"]] == ["no_route"] * 3
    assert found["findings"][0] == finding(
        "no_route",
        "error",
        "no route uses music; there is nothing to bind the access tokens minted with 'music-id' to",
        {"kind": "fix_policy", "credential": "music"},
    )


def test_judge_names_its_verdict() -> None:
    policy = make_policy({"notes": header()}, connectors={"mail": MAIL})
    needs = frozenset({API_ORIGIN})
    assert judge(policy, entry("notes-key", origin_binding([API])), needs) == "ok"
    assert judge(policy, entry("notes-key", MAIL_BINDING), needs) == "changed"
    assert judge(policy, entry("notes-key", MAIL_BINDING), None) == "ok"
    assert judge(policy, entry("mail-pass", MAIL_BINDING), None) == "ok"
    with pytest.raises(BindingError) as caught:
        judge(make_policy({"music": spotify()}, {"music": ()}), SPOTIFY_ENTRIES[0], None)
    assert caught.value.reason == "no_route"


# --- env seeds and live slots ------------------------------------------------------------------

SEEDED = {"refresh_token": "env:MUSIC_SEED"}
LIVE = "oauth.music.live"


def test_a_seed_never_used_and_unset() -> None:
    policy = make_policy({"music": spotify(**SEEDED)})
    found = one(report(policy, SPOTIFY_ENTRIES[:2]))
    assert found["refs"][2:] == [
        {"ref": "env:MUSIC_SEED", "present": False, "binding": None},
        {"ref": f"store:{LIVE}", "present": False, "binding": None},
    ]
    assert found["findings"] == [
        finding(
            "env_unset",
            "error",
            "env MUSIC_SEED isn't set, and there is no live refresh token",
            {"kind": "connect", "credential": "music"},
        )
    ]
    by_hand = make_policy({"music": spotify(authorize_url=None, **SEEDED)})
    [only] = one(report(by_hand, SPOTIFY_ENTRIES[:2]))["findings"]
    assert only["action"] == {"kind": "restart", "credential": "music", "ref": "env:MUSIC_SEED"}


def test_a_seed_not_yet_promoted() -> None:
    policy = make_policy({"music": spotify(**SEEDED)})
    found = one(report(policy, SPOTIFY_ENTRIES[:2], env=["MUSIC_SEED"]))
    assert found["refs"][2:] == [
        {"ref": "env:MUSIC_SEED", "present": True, "binding": None},
        {"ref": f"store:{LIVE}", "present": False, "binding": None},
    ]
    assert found["findings"] == []


@pytest.mark.parametrize(
    ("reseed", "text"),
    [
        ("never", "env MUSIC_SEED is ignored: the live refresh token is used (reseed: never)"),
        ("on-change", "env MUSIC_SEED is ignored until its value changes (reseed: on-change)"),
    ],
)
def test_a_seed_set_while_a_live_slot_exists(reseed: str, text: str) -> None:
    policy = make_policy({"music": spotify(reseed=reseed, **SEEDED)})
    entries = [*SPOTIFY_ENTRIES[:2], entry(LIVE, oauth_binding(TOKEN_URL, [API]))]
    found = one(report(policy, entries, env=["MUSIC_SEED"]))
    assert found["refs"][2:] == [
        {"ref": "env:MUSIC_SEED", "present": True, "binding": None},
        {"ref": f"store:{LIVE}", "present": True, "binding": "ok"},
    ]
    assert found["findings"] == [finding("seed_ignored", "info", text, None)]
    # The seed may be removed once it has been promoted.
    assert one(report(policy, entries))["findings"] == []


def test_a_live_slot_is_judged_like_the_grant() -> None:
    policy = make_policy({"music": spotify(**SEEDED)}, {"music": (API, OTHER)})
    entries = [
        entry("music-id", oauth_binding(TOKEN_URL, [API])),
        # Exact, or login would refuse it too (D.7 step 5).
        entry("music-secret", oauth_binding(TOKEN_URL, [API, OTHER])),
        entry(LIVE, oauth_binding(TOKEN_URL, [API])),
    ]
    found = one(report(policy, entries))
    assert found["refs"][3] == {"ref": f"store:{LIVE}", "present": True, "binding": "changed"}
    assert found["findings"] == [
        finding(
            "binding_changed",
            "error",
            f"store:{LIVE} isn't bound to a use the policy makes now; the vault refuses that use",
            {"kind": "connect", "credential": "music"},
        )
    ]


# --- the store -------------------------------------------------------------------------------


def test_entries_nothing_uses() -> None:
    policy = make_policy({"music": spotify(**SEEDED), "notes": header("env:NOTES")})
    entries = [
        entry("music-id", oauth_binding(TOKEN_URL, [API])),
        entry(LIVE, oauth_binding(TOKEN_URL, [API])),
        entry("oauth.gone.live", oauth_binding(TOKEN_URL, [API])),
        entry("old-key", origin_binding([API])),
    ]
    store = report(policy, entries)["store"]
    assert store == {
        "entries": 4,
        "level": "info",
        "findings": [
            finding(
                "orphan_slot",
                "info",
                "oauth.gone.live: no credential keeps its live refresh token here",
                {"kind": "delete_secret", "secret": "oauth.gone.live"},
            ),
            finding(
                "unreferenced",
                "info",
                "nothing in the policy uses store:old-key",
                {"kind": "delete_secret", "secret": "old-key"},
            ),
        ],
    }
    # A live slot is used only while its credential is seeded.
    unseeded = make_policy({"music": spotify()})
    assert codes(report(unseeded, [entry(LIVE, {"oauth": {}})])["store"]) == ["orphan_slot"]


ONBOARDED = {
    "onboarded": "auth.notes.example",
    "resource": "https://mcp.notes.example/mcp",
    "client_id": "client-1",
    "client_secret_expires_at": None,
}


def test_an_onboardings_secret_waits_for_its_credential() -> None:
    """D.7 step 6: a secret (or a public client's ID) stored before fragment 1 was committed.
    The wording comes from clear meta, so it is advisory; the code, level and action stay."""
    entries = [
        entry("notes-client-secret", oauth_binding(TOKEN_URL, [API]), ONBOARDED),
        entry("files-client-id", oauth_binding(TOKEN_URL, [API]), ONBOARDED),
        # Another name, no onboarded meta, or meta of the wrong type: the usual words.
        entry("notes-key", origin_binding([API]), ONBOARDED),
        entry("mail-client-secret", oauth_binding(TOKEN_URL, [API]), {"resource": "x"}),
        entry("old-client-secret", oauth_binding(TOKEN_URL, [API]), {"onboarded": 1}),
        entry("-client-id", oauth_binding(TOKEN_URL, [API]), ONBOARDED),
    ]
    store = report(make_policy({}), entries)["store"]
    waiting = "is waiting for its credential: commit onboarding fragment 1 for"
    assert store["findings"][:2] == [
        finding(
            "unreferenced",
            "info",
            f"store:notes-client-secret {waiting} notes, or delete it",
            {"kind": "delete_secret", "secret": "notes-client-secret"},
            advisory=True,
        ),
        finding(
            "unreferenced",
            "info",
            f"store:files-client-id {waiting} files, or delete it",
            {"kind": "delete_secret", "secret": "files-client-id"},
            advisory=True,
        ),
    ]
    assert [(f["text"], f["advisory"]) for f in store["findings"][2:]] == [
        (f"nothing in the policy uses store:{e.name}", False) for e in entries[2:]
    ]
    assert ONBOARDING_SUFFIXES == ("-client-secret", "-client-id")
    # Once the policy names it, nothing.
    named = make_policy({"notes": header("store:notes-client-secret")})
    assert report(named, entries[:1])["store"]["findings"] == []


def test_health_reads_no_clock_for_an_onboarding() -> None:
    """FM-28's monotonic half: onboardings expire on the table's monotonic clock
    (test_onboarding.py), and health judges nothing of one by the wall clock. An entry no
    credential names yet isn't judged by its client_secret_expires_at: the expiry codes are a
    committed credential's (test_a_registered_clients_secret_expiry)."""
    long_ago = {**ONBOARDED, "client_secret_expires_at": 1}
    old = EntryMeta(
        "notes-client-secret",
        oauth_binding(TOKEN_URL, [API]),
        "kid",
        "1971-01-01T00:00:00Z",
        "1971-01-01T00:00:00Z",
        long_ago,
    )
    new = entry("notes-client-secret", oauth_binding(TOKEN_URL, [API]), ONBOARDED)
    assert report(make_policy({}), [old]) == report(make_policy({}), [new])
    assert report(make_policy({}), [old], wall=NOW) == report(make_policy({}), [new], wall=NOW)
    assert codes(report(make_policy({}), [old])["store"]) == ["unreferenced"]


def registered_client(expires: object) -> tuple[Policy, list[EntryMeta]]:
    """A committed credential whose client secret a registration stored (D.7 step 4's meta),
    its server's URL as its resource, as onboarding writes it."""
    cred = spotify(extra_params={"resource": RESOURCE}, authorize_params={"resource": RESOURCE})
    policy = make_policy({"music": cred}, {"music": (RESOURCE,)})
    exact = oauth_binding(TOKEN_URL, [RESOURCE])
    meta = {**ONBOARDED, "client_secret_expires_at": expires}
    return policy, [
        entry("music-id", exact),
        entry("music-secret", exact, meta),
        entry("music-refresh", exact),
    ]


@pytest.mark.parametrize(
    ("expires", "expected"),
    [
        (int(NOW) + 14 * DAY + 1, []),
        (int(NOW) + 14 * DAY, ["client_secret_expiring"]),
        (int(NOW) + 1, ["client_secret_expiring"]),
        (int(NOW), ["client_secret_expired"]),
        (int(NOW) - DAY, ["client_secret_expired"]),
        (1, ["client_secret_expired"]),
        # 0 is never (RFC 7591 3.2.1); anything else that isn't a positive integer, nothing.
        (0, []),
        (None, []),
        (-5, []),
        (True, []),
        (str(int(NOW)), []),
        (NOW - DAY, []),
        # Far off: no time is formatted for it.
        (10**30, []),
    ],
)
def test_a_registered_clients_secret_expiry(expires: object, expected: list[str]) -> None:
    """M7 J, D.7 step 7, FM-28's wall-clock half: judged on ``wall``, from clear meta."""
    policy, entries = registered_client(expires)
    assert codes(one(report(policy, entries, wall=NOW))) == expected
    # Without a wall clock, never.
    assert codes(one(report(policy, entries))) == []


def test_the_expiry_findings() -> None:
    """Both advisory (clear meta), with onboarding again as the action, which names the
    command; a credential without its server's URL as a resource gets secret set instead."""
    policy, entries = registered_client(int(NOW) + 3 * DAY)
    [expiring] = one(report(policy, entries, wall=NOW))["findings"]
    assert expiring == finding(
        "client_secret_expiring",
        "warning",
        "store:music-secret expires at 2026-09-24T14:13:20Z: register a new client before then",
        REGISTER_AGAIN,
        advisory=True,
    )
    [expired] = one(report(policy, entries, wall=NOW + 4 * DAY))["findings"]
    assert expired == finding(
        "client_secret_expired",
        "error",
        "store:music-secret expired at 2026-09-24T14:13:20Z: the provider refuses this client now",
        REGISTER_AGAIN,
        advisory=True,
    )
    unnamed = make_policy({"music": spotify()}, {"music": (RESOURCE,)})
    [by_hand] = one(report(unnamed, entries, wall=NOW))["findings"]
    assert (by_hand["code"], by_hand["action"]) == ("client_secret_expiring", SET_SECRET)
    # A client secret from the environment has no entry to read an expiry from.
    from_env = make_policy(
        {"music": spotify(client_secret="env:MUSIC_SECRET")}, {"music": (RESOURCE,)}
    )
    assert codes(one(report(from_env, entries, ["MUSIC_SECRET"], wall=NOW))) == []


def test_a_store_that_cant_be_written() -> None:
    store = report(make_policy({}), persisted=False)["store"]
    assert store["findings"] == [
        finding(
            "degraded",
            "error",
            "degraded (not persisted): the store can't be written",
            {"kind": "check_volume"},
        )
    ]


# --- OAuth states ------------------------------------------------------------------------------


def oauth_findings(
    fields: Mapping[str, Any], cred: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    policy = make_policy({"music": dict(cred or spotify())})
    found = report(policy, SPOTIFY_ENTRIES, oauth=[status(**fields)])
    result: list[dict[str, Any]] = one(found)["findings"]
    return result


CONNECT = {"kind": "connect", "credential": "music"}
RESET = {"kind": "reset", "credential": "music"}


def test_a_terminal_or_backoff_state() -> None:
    action = {"kind": "fix_policy", "credential": "music"}
    assert oauth_findings(
        {"state": "terminal", "code": "oauth_misconfigured", "action": action}
    ) == [
        finding("terminal", "error", "no token calls until you act (oauth_misconfigured)", action)
    ]
    wait = {"kind": "wait", "credential": "music"}
    assert oauth_findings({"state": "backoff", "code": "oauth_unavailable", "action": wait}) == [
        finding(
            "backoff",
            "warning",
            "a failure (oauth_unavailable); a request after the backoff tries again",
            wait,
        )
    ]
    assert oauth_findings({"state": "terminal", "code": "oauth_unsupported"})[0]["action"] is None
    assert oauth_findings({"state": "ok"}) == []


def test_warnings_from_the_meta_are_advisory() -> None:
    fields = {
        "reconsent_due": "2026-10-01T00:00:00Z",
        "scopes": {"unexpected": ["admin", "root"], "missing": ["read"]},
        "last_failure": {"code": "oauth_reconsent_needed", "at": "2026-09-20T00:00:00Z"},
        "idle": {"days": 171, "limit": 180},
    }
    assert oauth_findings(fields) == [
        finding(
            "reconsent_due",
            "warning",
            "re-consent due by 2026-10-01T00:00:00Z",
            CONNECT,
            advisory=True,
        ),
        finding(
            "unexpected_scopes",
            "warning",
            "unexpected scopes granted: admin root",
            CONNECT,
            advisory=True,
        ),
        finding(
            "missing_scopes", "warning", "expected scopes not granted: read", CONNECT, advisory=True
        ),
        finding(
            "last_failure",
            "warning",
            "last attempt failed: oauth_reconsent_needed at 2026-09-20T00:00:00Z",
            RESET,
            advisory=True,
        ),
        finding(
            "idle",
            "warning",
            "unused for 171 days; the provider drops unused grants after 180",
            CONNECT,
            advisory=True,
        ),
    ]
    assert oauth_findings({"scopes": {"unexpected": [], "missing": []}}) == []


def test_an_upstreams_insufficient_scope_is_since_the_vault_started() -> None:
    upstream = {"code": "upstream_insufficient_scope", "at": "2026-09-21T10:00:00Z"}
    assert oauth_findings({"upstream": upstream}) == [
        finding(
            "insufficient_scope",
            "warning",
            "an upstream said the token lacks a scope at 2026-09-21T10:00:00Z "
            "(since the vault started)",
            CONNECT,
        )
    ]


def scope_findings(
    asked: Sequence[str] | None, cred: Mapping[str, Any] | None = None
) -> list[dict[str, Any]]:
    upstream: dict[str, Any] = {"code": "upstream_insufficient_scope", "at": "2026-09-21T10:00:00Z"}
    if asked is not None:
        upstream["scopes"] = list(asked)
    return oauth_findings({"upstream": upstream}, cred or spotify(scope="read"))


SAID = "an upstream said the token lacks a scope at 2026-09-21T10:00:00Z (since the vault started)"
WIDENED = (
    "# zoeymcp: widen the scope of music\n"
    "credentials:\n"
    '  "music":\n'
    '    kind: "oauth2"\n'
    '    scope: "read write admin"\n'
)


def test_a_challenged_scope_is_widened_by_a_fragment() -> None:
    """SPEC-11: the union of the committed scope and the challenged one, committed tokens
    first, as a fragment that merges into the credential and keeps the rest of it; then
    connect (the CLI's words)."""
    [found] = scope_findings(["write", "read", "admin"])
    assert found == finding(
        "insufficient_scope",
        "warning",
        f"{SAID}; it asked for write read admin",
        {
            "kind": "widen_scope",
            "credential": "music",
            "scope": "read write admin",
            "fragment": WIDENED,
        },
    )
    policy = make_policy({"music": spotify(scope="read", expected_scopes=["read"])})
    fragment = load_mapping(WIDENED)
    assert replace_paths(WIDENED) == ()
    base = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    merged = merge(base, fragment)
    assert isinstance(merged, Merged)
    widened = Policy.model_validate(merged.data).credentials["music"]
    assert isinstance(widened, OAuth2Credential)
    original = policy.credentials["music"]
    assert widened.scope == "read write admin"
    assert widened.model_dump(exclude={"scope"}) == original.model_dump(exclude={"scope"})


@pytest.mark.parametrize(
    ("asked", "cred", "widened_to"),
    [
        # Nothing new asked for: sign in again, as before.
        (["read"], spotify(scope="read"), None),
        # The credential's own separator.
        (["write"], spotify(scope="read,list", scope_separator=","), "read,list,write"),
        # A token holding that separator would split into two: no fragment.
        (["a,b"], spotify(scope="read", scope_separator=","), None),
        # No scope yet: the challenged one.
        (["read", "read"], spotify(), "read"),
        # More than the schema's 64 scopes, or longer than its 2048 characters.
        ([f"s{n}" for n in range(64)], spotify(scope="read"), None),
        ([chr(97 + n) * 250 for n in range(9)], spotify(scope="read"), None),
    ],
)
def test_a_challenged_scope_the_credential_cant_take_is_signed_in_for(
    asked: list[str], cred: dict[str, Any], widened_to: str | None
) -> None:
    [found] = scope_findings(asked, cred)
    assert found["text"] == f"{SAID}; it asked for {' '.join(asked)}"
    if widened_to is None:
        assert found["action"] == CONNECT
    else:
        assert (found["action"]["kind"], found["action"]["scope"]) == ("widen_scope", widened_to)


def test_a_challenge_without_a_scope_says_what_it_did() -> None:
    expected = [finding("insufficient_scope", "warning", SAID, CONNECT)]
    assert scope_findings(None) == expected
    assert scope_findings([]) == expected


PRM = "https://mcp.music.example/.well-known/oauth-protected-resource/mcp"
MOVED = "https://auth.music.example/.well-known/oauth-protected-resource"


@pytest.mark.parametrize(
    ("cred", "named", "action"),
    [
        (
            spotify(resource_metadata=PRM, extra_params={"resource": RESOURCE}),
            MOVED,
            REGISTER_AGAIN,
        ),
        # A credential written by hand, with no resource to onboard again by.
        (spotify(resource_metadata=PRM), MOVED, {"kind": "fix_policy", "credential": "music"}),
        # The same URL (a reload took the new one), or nothing pinned (D.2a): nothing.
        (spotify(resource_metadata=PRM), PRM, None),
        (spotify(), MOVED, None),
        (spotify(resource_metadata=PRM), None, None),
    ],
)
def test_a_resource_metadata_other_than_the_credentials(
    cred: dict[str, Any], named: str | None, action: dict[str, str] | None
) -> None:
    moved = None if named is None else {"url": named, "at": "2026-09-21T10:00:00Z"}
    found = oauth_findings({"resource_metadata": moved}, cred)
    if action is None:
        assert found == []
        return
    assert found == [
        finding(
            "resource_metadata_changed",
            "warning",
            "a 401 on its route named other protected-resource metadata than its "
            "resource_metadata at 2026-09-21T10:00:00Z (since the vault started): the server "
            "may have moved its authorization; the vault never registers again by itself",
            action,
        )
    ]


@pytest.mark.parametrize(
    ("cred", "action"),
    [
        (spotify(), CONNECT),
        (
            spotify(authorize_url=None),
            {"kind": "set_secret", "credential": "music", "ref": "store:music-refresh"},
        ),
        (
            spotify(authorize_url=None, **SEEDED),
            {"kind": "restart", "credential": "music", "ref": "env:MUSIC_SEED"},
        ),
        (machine(), RESET),
    ],
)
def test_a_new_grant_is_got_as_the_hints_say(cred: dict[str, Any], action: dict[str, str]) -> None:
    # After the references' findings: this credential's entries aren't all there.
    found = oauth_findings({"reconsent_due": "2026-10-01T00:00:00Z"}, cred)[-1]
    assert (found["code"], found["action"]) == ("reconsent_due", action)


def test_the_oauth_block_shows_only_well_typed_meta() -> None:
    policy = make_policy({"music": spotify()})
    meta = {"source": 5, "consented_at": ["x"], "rotations": True}
    found = one(
        report(policy, SPOTIFY_ENTRIES, oauth=[status(meta=meta, state="backoff", code="c")])
    )
    assert found["oauth"] == {
        "state": "backoff",
        "code": "c",
        "source": None,
        "consented_at": None,
        "rotations": None,
        "last_ok_ago": None,
        "display_only": list(DISPLAY_ONLY),
    }
    # Without a token manager, or for another credential, there is no OAuth view.
    assert "oauth" not in one(report(policy, SPOTIFY_ENTRIES))
    assert "oauth" not in one(report(policy, SPOTIFY_ENTRIES, oauth=[status("other")]))
    static = make_policy({"notes": header()})
    assert "oauth" not in one(report(static, oauth=[status("notes")]))


# --- the address guard's refusals (M7 design B.2, J) ---------------------------------------------

AT = "2026-09-21T10:00:00Z"
HINT = "list {} in egress_private if this destination is meant to be private"
FIX = {"kind": "fix_policy", "credential": "music"}


def refusal(purpose: str, host: str, port: int = 443, verdict: str = "private") -> dict[str, Any]:
    """An item of ``LoginService.refused()``."""
    return {"purpose": purpose, "host": host, "port": port, "verdict": verdict, "at": AT}


def refused_text(call: str, key: str, verdict: str = "private") -> str:
    return (
        f"{call} at {key} was refused at {AT} (since the vault started): its name resolved to "
        f"an address the guard refuses ({verdict}); {HINT.format(key)}"
    )


def guard_policy(private: Sequence[str] = (), **music: Any) -> Policy:
    """music (oauth2, a route to API) and notes (a header credential, a route to OTHER)."""
    policy = make_policy({"music": spotify(**music), "notes": header()}, routes={"notes": (OTHER,)})
    return policy.model_copy(update={"egress_private": list(private)})


def refused_findings(policy: Policy, *refused: Mapping[str, Any]) -> dict[str, list[str]]:
    found = report(policy, refused=refused)
    return {
        item["name"]: [f["text"] for f in item["findings"] if f["code"] == "address_refused"]
        for item in found["credentials"]
    }


def test_a_refused_token_endpoint_is_an_error_with_the_line_to_add() -> None:
    found = report(guard_policy(), refused=[refusal("token", "accounts.example")])
    music = next(item for item in found["credentials"] if item["name"] == "music")
    assert [f for f in music["findings"] if f["code"] == "address_refused"] == [
        finding(
            "address_refused",
            "error",
            refused_text("the token endpoint", "accounts.example:443"),
            FIX,
        )
    ]
    assert music["level"] == "error"
    assert found["summary"]["error"] >= 1


@pytest.mark.parametrize(
    ("refused", "music", "notes"),
    [
        # Each purpose against its own destination, and only the credential's own.
        (
            refusal("route", "api.example"),
            [refused_text("a route's upstream", "api.example:443")],
            [],
        ),
        (
            refusal("route", "other.example", verdict="loopback"),
            [],
            [refused_text("a route's upstream", "other.example:443", "loopback")],
        ),
        (
            refusal("revocation", "accounts.example", 8443),
            [refused_text("the revocation endpoint", "accounts.example:8443")],
            [],
        ),
        # Another purpose's destination, another port, or no longer the policy's: nothing.
        (refusal("token", "api.example"), [], []),
        (refusal("route", "accounts.example"), [], []),
        (refusal("revocation", "accounts.example"), [], []),
        (refusal("token", "accounts.example", 8443), [], []),
        (refusal("token", "gone.example"), [], []),
        (refusal("discovery", "accounts.example"), [], []),
    ],
)
def test_each_refusal_belongs_to_the_credential_whose_destination_it_was(
    refused: dict[str, Any], music: list[str], notes: list[str]
) -> None:
    policy = guard_policy(revocation_url="https://accounts.example:8443/revoke")
    assert refused_findings(policy, refused) == {"music": music, "notes": notes}


def test_a_revocation_refusal_needs_a_revocation_endpoint() -> None:
    found = refused_findings(guard_policy(), refusal("revocation", "accounts.example"))
    assert found == {"music": [], "notes": []}


def test_a_reload_that_lists_the_destination_ends_the_finding() -> None:
    refused = [refusal("token", "accounts.example"), refusal("route", "api.example")]
    listed = guard_policy(private=["accounts.example:443"])
    assert refused_findings(listed, *refused) == {
        "music": [refused_text("a route's upstream", "api.example:443")],
        "notes": [],
    }
    both = guard_policy(private=["accounts.example:443", "api.example:443"])
    assert refused_findings(both, *refused) == {"music": [], "notes": []}


def test_an_ipv6_destination_is_matched_as_egress_private_writes_it() -> None:
    policy = guard_policy(token_url="https://[fd00::5]:8443/token")
    found = refused_findings(policy, refusal("token", "fd00::5", 8443))
    assert found["music"] == [refused_text("the token endpoint", "[fd00::5]:8443")]


def test_no_refusals_no_findings() -> None:
    assert refused_findings(guard_policy()) == {"music": [], "notes": []}


def test_an_idn_destination_is_matched_as_the_guard_sees_it() -> None:
    """The guard is given the URL's IDNA-encoded host, so the refusal names the ``xn--`` form,
    the one egress_private can list; the decoded name would match nothing."""
    policy = guard_policy(token_url="https://bücher.example/token")
    found = refused_findings(policy, refusal("token", "xn--bcher-kva.example"))
    assert found["music"] == [refused_text("the token endpoint", "xn--bcher-kva.example:443")]
    listed = policy.model_copy(update={"egress_private": ["xn--bcher-kva.example:443"]})
    assert refused_findings(listed, refusal("token", "xn--bcher-kva.example"))["music"] == []


def test_a_trailing_dot_destination_is_matched_without_its_dot() -> None:
    policy = guard_policy(token_url="https://accounts.example./token")
    found = refused_findings(policy, refusal("token", "accounts.example."))
    assert found["music"] == [refused_text("the token endpoint", "accounts.example:443")]
    listed = policy.model_copy(update={"egress_private": ["accounts.example:443"]})
    assert refused_findings(listed, refusal("token", "accounts.example."))["music"] == []


FILES = "https://files.lan.example/v1"
RULES = [{"methods": ["GET"], "paths": ["/**"]}]


def egress_policy(private: Sequence[str] = (), files: str = FILES) -> Policy:
    """music (oauth2, a route to API), and files, a route to ``files`` with no credential."""
    routes: list[dict[str, Any]] = [
        {"name": "r0", "prefix": "/r0", "upstream": API, "credential": "music"},
        {"name": "files", "prefix": "/files", "upstream": files},
    ]
    for index, route in enumerate(routes):
        route.update(callers=[{"placeholder": f"ph-agent{index}-direct-0001"}], rules=RULES)
    return Policy.model_validate(
        {
            **BASE,
            "egress_private": list(private),
            "routes": routes,
            "credentials": {"music": spotify()},
        }
    )


def test_a_refused_route_with_no_credential_is_the_egress_sections() -> None:
    """No credential's section can hold it, so the egress section does, naming the route."""
    found = report(egress_policy(), refused=[refusal("route", "files.lan.example")])
    text = refused_text("route files's upstream", "files.lan.example:443")
    assert found["egress"] == {
        "level": "error",
        "findings": [
            finding("address_refused", "error", text, {"kind": "fix_policy", "route": "files"})
        ],
    }
    assert found["summary"]["error"] == report(egress_policy())["summary"]["error"] + 1
    [music] = found["credentials"]
    assert [f for f in music["findings"] if f["code"] == "address_refused"] == []


@pytest.mark.parametrize(
    "refused",
    [
        [],
        # The credential's route, or a call that isn't a route's, at the same destination.
        [refusal("route", "api.example")],
        [refusal("token", "files.lan.example"), refusal("revocation", "files.lan.example")],
        # Another port, or a destination no route has now.
        [refusal("route", "files.lan.example", 8443)],
        [refusal("route", "gone.lan.example")],
    ],
)
def test_the_egress_section_holds_only_a_refused_route_with_no_credential(
    refused: list[dict[str, Any]],
) -> None:
    found = report(egress_policy(), refused=refused)
    assert found["egress"] == {"level": "ok", "findings": []}


def test_a_reload_that_lists_or_moves_the_route_ends_its_egress_finding() -> None:
    refused = [refusal("route", "files.lan.example")]
    assert report(egress_policy(), refused=refused)["egress"]["level"] == "error"
    listed = egress_policy(private=["files.lan.example:443"])
    assert report(listed, refused=refused)["egress"]["findings"] == []
    moved = egress_policy(files="https://files.example/v1")
    assert report(moved, refused=refused)["egress"]["findings"] == []


def test_an_egress_route_is_matched_as_the_guard_sees_it() -> None:
    """IDN and IPv6 upstreams: the key is the IDNA-encoded host, and an IPv6 one in brackets."""
    idn = egress_policy(files="https://bücher.lan.example/v1")
    found = report(idn, refused=[refusal("route", "xn--bcher-kva.lan.example")])
    [item] = found["egress"]["findings"]
    assert item["text"] == refused_text("route files's upstream", "xn--bcher-kva.lan.example:443")
    literal = egress_policy(files="https://[fd00::7]:8443/v1")
    found = report(literal, refused=[refusal("route", "fd00::7", 8443)])
    [item] = found["egress"]["findings"]
    assert item["text"] == refused_text("route files's upstream", "[fd00::7]:8443")


# --- the egress role's fetches (M7 design J, COV-7) ---------------------------------------------

CHECK_ROLE = {"kind": "check_egress_role"}


def stale_text(minutes: int) -> str:
    return (
        f"the egress role hasn't fetched its allowlists for {minutes} min: its lists go stale "
        "after 300 s, and then it refuses every new tunnel"
    )


@pytest.mark.parametrize(
    ("ago", "findings"),
    [
        # No role has asked since the vault started and none is expected (egress_proxy_kind
        # own, or no egress_proxy): nothing to judge. A role never admitted (its key refused) is
        # measured from its first request, and with kind role one that never asked from the
        # vault's start (test_egress_endpoint.py).
        (None, []),
        (0.0, []),
        (299.9, []),
        (300.0, []),
        (300.5, [finding("egress_allowlist_stale", "warning", stale_text(5), CHECK_ROLE)]),
        (359.0, [finding("egress_allowlist_stale", "warning", stale_text(5), CHECK_ROLE)]),
        (3600.0, [finding("egress_allowlist_stale", "warning", stale_text(60), CHECK_ROLE)]),
    ],
)
def test_an_egress_role_that_stopped_fetching(
    ago: float | None, findings: list[dict[str, Any]]
) -> None:
    found = report(make_policy({}), egress_fetched_ago=ago)
    assert found["egress"] == {"level": "warning" if findings else "ok", "findings": findings}
    assert found["summary"]["warning"] == len(findings)
    assert ALLOWLIST_MAX_STALE == 300


def test_a_stale_role_follows_the_refused_routes() -> None:
    """One section: the guard's refusals first, then the role, the worst level winning."""
    found = report(
        egress_policy(), refused=[refusal("route", "files.lan.example")], egress_fetched_ago=301
    )
    assert codes(found["egress"]) == ["address_refused", "egress_allowlist_stale"]
    assert found["egress"]["level"] == "error"
    assert found["summary"]["warning"] == report(egress_policy())["summary"]["warning"] + 1


# --- the bridges' routes (M7 design C.10, J, step 18d) ------------------------------------------

MCP_RULES = [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}]
STANDARD = Bridges(link=True)
UNCONFINED = (
    "nothing in the standard tier confines this program: it can reach every listener in the "
    "container, the host's network and the internet"
)


def bridge_policy(
    upstreams: Mapping[str, str],
    programs: Mapping[str, dict[str, Any]] | None = None,
    served: bool = True,
) -> Policy:
    """A route per name with its own token, plain http only where it is, each a gateway
    server's (so a local MCP route) when ``served``, and with ``programs`` its program block."""
    routes: list[dict[str, Any]] = []
    for name, upstream in upstreams.items():
        route: dict[str, Any] = {
            "name": name,
            "prefix": f"/{name}",
            "upstream": upstream,
            "allow_insecure_upstream": upstream.startswith("http:"),
            "credential": name,
            "callers": ["gateway"],
            "stream": True,
            "rules": MCP_RULES,
        }
        if name in (programs or {}):
            route["program"] = (programs or {})[name]
        routes.append(route)
    return Policy.model_validate(
        {
            **BASE,
            "credentials": {name: header(f"store:{name}-token") for name in upstreams},
            "routes": routes,
            "gateway": {
                "servers": {name: {"kind": "remote", "route": name} for name in upstreams}
                if served
                else {}
            },
        }
    )


def egress_findings(policy: Policy, bridges: Bridges) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = report(policy, bridges=bridges)["egress"]["findings"]
    return findings


def fix(route: str) -> dict[str, str]:
    return {"kind": "fix_policy", "route": route}


def unconfined(route: str) -> dict[str, Any]:
    return finding("program_unconfined", "info", f"route {route}: {UNCONFINED}", None)


def loopback(route: str, key: str) -> dict[str, Any]:
    text = (
        f"route {route}: any process in this container can listen on {key} first and receive "
        "this route's token; a bridge under the launcher listens on "
        "unix:/run/zoeymcp-bridge-<name>/mcp.sock"
    )
    return finding("loopback_bridge_route", "error", text, fix(route))


def unknown(route: str, bridge: str) -> dict[str, Any]:
    text = f"route {route}: the route answers 502: no bridge {bridge} runs in this container"
    return finding("bridge_socket_unknown", "error", text, fix(route))


def unflagged(route: str) -> dict[str, Any]:
    text = (
        f"route {route}: this route's program holds a real secret, and check can't warn about it "
        "until program.holds_secret is set"
    )
    return finding("program_secret_unflagged", "warning", text, fix(route))


ROUTES = {
    "sock": "unix:/run/zoeymcp-bridge-fetch/mcp.sock",
    "lit": "http://127.0.0.1:9000",
    "lh": "http://localhost:9000",
    "prog": "https://api.example",
    "lan": "http://10.0.0.5:9000",
    "plain": "https://other.example",
}


def test_program_unconfined_with_the_link_socket_only() -> None:
    """A program block, a unix: upstream, a local MCP route to loopback: each unconfined in the
    standard tier; a private address or an ordinary route isn't."""
    policy = bridge_policy(ROUTES, {"prog": {"holds_secret": False}})
    named = Bridges(link=True, named=frozenset({"fetch"}))
    assert egress_findings(policy, named) == [
        unconfined("sock"),
        unconfined("lit"),
        loopback("lit", "127.0.0.1:9000"),
        unconfined("lh"),
        loopback("lh", "localhost:9000"),
        unconfined("prog"),
    ]
    found = report(policy, bridges=named)
    assert found["egress"]["level"] == "error"
    assert found["summary"]["info"] == report(policy)["summary"]["info"] + 4
    # The hardened tier: nothing here is unconfined, and no launcher named the socket's bridge.
    assert egress_findings(policy, Bridges()) == [unknown("sock", "fetch")]
    assert egress_findings(policy, Bridges(named=frozenset({"fetch"}))) == []


@pytest.mark.parametrize(
    ("upstream", "key"),
    [
        ("http://127.0.0.1:9000", "127.0.0.1:9000"),
        ("http://127.8.0.1", "127.8.0.1:80"),
        ("http://[::1]:9000", "[::1]:9000"),
        ("http://LocalHost:9000", "localhost:9000"),
    ],
)
def test_a_loopback_bridge_route(upstream: str, key: str) -> None:
    policy = bridge_policy({"fetch": upstream})
    assert egress_findings(policy, STANDARD) == [unconfined("fetch"), loopback("fetch", key)]
    assert egress_findings(policy, Bridges()) == []


@pytest.mark.parametrize(
    ("upstream", "loopback"),
    [
        ("http://localhost:1", True),
        ("http://a.localhost:1", True),
        ("http://a.LOCALHOST:1", True),
        ("http://127.0.0.1:1", True),
        ("http://[::1]:1", True),
        ("http://[::ffff:127.0.0.9]:1", True),
        ("http://localhost.example:1", False),
        ("http://notlocalhost:1", False),
        ("http://10.0.0.1:1", False),
        ("http://[::ffff:10.0.0.1]:1", False),
        ("http://[fd00::1]:1", False),
        ("http://bridge-fetch-mcp:1", False),
    ],
)
def test_what_is_loopback(upstream: str, loopback: bool) -> None:
    """CR-B8: localhost and every name under it, as row 7b reads them."""
    assert health._loopback(upstream) is loopback


def test_a_mapped_loopback_literal_is_loopback() -> None:
    policy = bridge_policy({"fetch": "http://[::ffff:127.0.0.1]:9000"})
    assert codes(report(policy, bridges=STANDARD)["egress"]) == [
        "program_unconfined",
        "loopback_bridge_route",
    ]


@pytest.mark.parametrize(
    "upstream",
    ["http://10.0.0.5:9000", "http://[fd00::5]:9000", "http://bridge-fetch-mcp:9000"],
)
def test_a_local_route_off_loopback_isnt_squattable(upstream: str) -> None:
    assert egress_findings(bridge_policy({"fetch": upstream}), STANDARD) == []


def test_only_a_local_mcp_route_is_a_loopback_bridge_route() -> None:
    """Not a gateway server's route, so not a local MCP route: the vault sends it as any route."""
    policy = bridge_policy({"fetch": "http://127.0.0.1:9000"}, served=False)
    assert egress_findings(policy, STANDARD) == []
    # A program block on it is still unconfined.
    policy = bridge_policy({"fetch": "http://127.0.0.1:9000"}, {"fetch": {}}, served=False)
    assert egress_findings(policy, STANDARD) == [unconfined("fetch")]


def test_bridge_socket_unknown() -> None:
    policy = bridge_policy(
        {
            "fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock",
            "notes": "unix:/run/zoeymcp-bridge-notes/mcp.sock",
        }
    )
    # Named: nothing but the unconfined program.
    both = Bridges(link=True, named=frozenset({"fetch", "notes"}))
    assert egress_findings(policy, both) == [unconfined("fetch"), unconfined("notes")]
    # An unknown name.
    one = Bridges(link=True, named=frozenset({"fetch", "other"}))
    assert egress_findings(policy, one) == [
        unconfined("fetch"),
        unconfined("notes"),
        unknown("notes", "notes"),
    ]
    # Any unix: upstream without --bridge, in either tier.
    assert egress_findings(policy, STANDARD) == [
        unconfined("fetch"),
        unknown("fetch", "fetch"),
        unconfined("notes"),
        unknown("notes", "notes"),
    ]
    assert egress_findings(policy, Bridges()) == [
        unknown("fetch", "fetch"),
        unknown("notes", "notes"),
    ]


@pytest.mark.parametrize(
    ("program", "bridges", "flagged"),
    [
        (None, Bridges(True, frozenset({"fetch"}), frozenset({"fetch"})), True),
        ({}, Bridges(True, frozenset({"fetch"}), frozenset({"fetch"})), True),
        ({"holds_secret": False}, Bridges(True, frozenset({"fetch"}), frozenset({"fetch"})), True),
        ({"holds_secret": True}, Bridges(True, frozenset({"fetch"}), frozenset({"fetch"})), False),
        # Its ARGS hold no --secret-env.
        (None, Bridges(True, frozenset({"fetch"}), frozenset({"notes"})), False),
        # The hardened tier has no such bridge.
        (None, Bridges(False, frozenset({"fetch"}), frozenset({"fetch"})), False),
    ],
)
def test_program_secret_unflagged(
    program: dict[str, Any] | None, bridges: Bridges, flagged: bool
) -> None:
    programs = {} if program is None else {"fetch": program}
    policy = bridge_policy({"fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock"}, programs)
    found = egress_findings(policy, bridges)
    assert (unflagged("fetch") in found) is flagged
    if flagged:
        assert found == [unconfined("fetch"), unflagged("fetch")]
        assert report(policy, bridges=bridges)["egress"]["level"] == "warning"


def test_a_secret_bridge_flags_only_its_own_route() -> None:
    policy = bridge_policy(
        {
            "fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock",
            "notes": "unix:/run/zoeymcp-bridge-notes/mcp.sock",
            "lit": "http://127.0.0.1:9000",
        }
    )
    bridges = Bridges(True, frozenset({"fetch", "notes"}), frozenset({"notes"}))
    assert codes(report(policy, bridges=bridges)["egress"]) == [
        "program_unconfined",
        "program_unconfined",
        "program_secret_unflagged",
        "program_unconfined",
        "loopback_bridge_route",
    ]


def test_the_routes_follow_the_refusals_and_precede_the_role() -> None:
    policy = bridge_policy({"fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock"})
    found = report(policy, bridges=STANDARD, egress_fetched_ago=301)
    assert codes(found["egress"]) == [
        "program_unconfined",
        "bridge_socket_unknown",
        "egress_allowlist_stale",
    ]
    assert Inputs(policy, (), frozenset()).bridges == Bridges(False, frozenset(), frozenset())


# --- connectors --------------------------------------------------------------------------------


def connector_findings(connector: Mapping[str, Any], summed: Sends | None) -> list[dict[str, Any]]:
    policy = make_policy({}, connectors={"mail": dict(connector)})
    found = report(
        policy,
        [entry("mail-pass", MAIL_BINDING)],
        env=["MAIL_USER"],
        sends={} if summed is None else {"mail": summed},
    )
    result: list[dict[str, Any]] = one(found, "connectors")["findings"]
    return result


def test_a_paused_connector() -> None:
    assert connector_findings({**MAIL, "paused": True}, None) == [
        finding(
            "paused",
            "info",
            "paused in the policy: every send is refused",
            {"kind": "fix_policy", "connector": "mail"},
        )
    ]


@pytest.mark.parametrize(
    ("limit", "sent", "near"),
    [(20, 15, False), (20, 16, True), (20, 20, True), (1000, 799, False), (1000, 800, True)],
)
def test_a_connector_near_its_limit(limit: int, sent: int, near: bool) -> None:
    """At 80% of max_per_day."""
    found = connector_findings({**MAIL, "max_per_day": limit}, Sends(sent, 0, None))
    if near:
        assert found == [
            finding(
                "near_limit",
                "warning",
                f"{sent} of {limit} sends in the last 24 hours",
                {"kind": "wait", "connector": "mail"},
            )
        ]
    else:
        assert found == []


def test_sends_with_an_unknown_outcome() -> None:
    assert connector_findings(MAIL, Sends(0, 2, None)) == [
        finding(
            "unknown_sends",
            "warning",
            "2 send(s) in the last 24 hours with an unknown outcome",
            {"kind": "check_mailbox", "connector": "mail"},
        )
    ]


def test_a_connector_whose_journal_wasnt_read() -> None:
    policy = make_policy({}, connectors={"mail": MAIL})
    found = one(report(policy, [entry("mail-pass", MAIL_BINDING)], env=["MAIL_USER"]), "connectors")
    assert (found["sent_24h"], found["last"], found["findings"]) == (None, None, [])


KEY = "key-0000000000000001"
HMAC = "hmac-sha256:" + "0" * 64
T0 = 1_790_000_000_000


def journal(*records: dict[str, Any]) -> Journal:
    rebuilt = Journal()
    for record in records:
        rebuilt.apply(record)
    return rebuilt


def sending(key: str, ts: int) -> dict[str, Any]:
    return {"kind": "sending", "key": key, "ts": ts, "req_hmac": HMAC}


def test_sends_sums_up_the_journal() -> None:
    assert sends(Journal(), T0) == Sends(0, 0, None)
    rebuilt = journal(
        sending("a" * 16, T0 - DAY_MS - 5000),
        {"kind": "unknown", "key": "a" * 16, "ts": T0 - DAY_MS, "phase": "vault_restarted"},
        sending("b" * 16, T0 - 3000),
        {"kind": "unknown", "key": "b" * 16, "ts": T0 - DAY_MS + 1, "phase": "data"},
        sending("c" * 16, T0 - 2000),
        {"kind": "sent", "key": "c" * 16, "ts": T0 - 1000, "message_id": "<m@x>", "smtp_code": 250},
    )
    # The first unknown ended exactly 24 hours ago: out of the window.
    assert sends(rebuilt, T0) == Sends(
        2, 1, {"state": "sent", "at": "2026-09-21T14:13:19Z", "smtp_code": 250}
    )


def test_the_last_send_may_still_be_running_or_have_failed() -> None:
    running = journal(sending("a" * 16, T0 - 1000), sending("b" * 16, T0 - 60_000))
    assert sends(running, T0).last == {
        "state": "sending",
        "at": "2026-09-21T14:13:19Z",
        "smtp_code": None,
    }
    failed = journal(
        sending("a" * 16, T0 - 5000),
        {
            "kind": "failed",
            "key": "a" * 16,
            "ts": T0,
            "phase": "auth",
            "code": "x",
            "smtp_code": 535,
        },
    )
    assert sends(failed, T0).last == {
        "state": "failed",
        "at": "2026-09-21T14:13:20Z",
        "smtp_code": 535,
    }
    unknown = journal(
        sending("a" * 16, T0 - 5000),
        {"kind": "unknown", "key": "a" * 16, "ts": T0, "phase": "data"},
    )
    assert sends(unknown, T0).last == {
        "state": "unknown",
        "at": "2026-09-21T14:13:20Z",
        "smtp_code": None,
    }


# --- last_failure and idle (D-23, D-20) --------------------------------------------------------

FAILED_AT = "2026-09-20T10:00:00Z"


@pytest.mark.parametrize(
    ("state", "meta", "expected"),
    [
        (
            "idle",
            {"last_error": {"code": "oauth_reconsent_needed", "at": FAILED_AT}},
            "oauth_reconsent_needed",
        ),
        (
            "ok",
            {"last_error": {"code": "a_b", "at": FAILED_AT}, "last_ok": "2026-09-20T09:59:59Z"},
            "a_b",
        ),
        ("idle", {"last_error": {"code": "Bad-Code", "at": FAILED_AT}}, None),
        ("idle", {"last_error": {"code": 7, "at": FAILED_AT}}, None),
        ("idle", {"last_error": {"code": "x" * 65, "at": FAILED_AT}}, None),
        ("idle", {"last_error": {"at": FAILED_AT}}, None),
    ],
)
def test_a_failure_after_the_last_success(
    state: str, meta: dict[str, Any], expected: str | None
) -> None:
    assert last_failure(state, meta) == {"code": expected, "at": FAILED_AT}


@pytest.mark.parametrize(
    ("state", "meta"),
    [
        ("backoff", {"last_error": {"code": "x", "at": FAILED_AT}}),
        ("terminal", {"last_error": {"code": "x", "at": FAILED_AT}}),
        ("idle", {}),
        ("idle", {"last_error": None}),
        ("idle", {"last_error": "oauth_unavailable"}),
        ("idle", {"last_error": {"code": "x"}}),
        ("idle", {"last_error": {"code": "x", "at": "yesterday"}}),
        ("idle", {"last_error": {"code": "x", "at": FAILED_AT}, "last_ok": FAILED_AT}),
        ("idle", {"last_error": {"code": "x", "at": FAILED_AT}, "last_ok": "2026-09-21T00:00:00Z"}),
    ],
)
def test_no_failure_to_show(state: str, meta: dict[str, Any]) -> None:
    assert last_failure(state, meta) is None


def test_a_failure_time_is_shown_as_the_vault_writes_one() -> None:
    meta = {"last_error": {"code": "x", "at": "2026-09-20T12:00:00.5+02:00"}}
    assert last_failure("idle", meta) == {"code": "x", "at": "2026-09-20T10:00:00Z"}
    assert (
        failure_text({"code": None, "at": FAILED_AT})
        == f"last attempt failed: no code at {FAILED_AT}"
    )


def oauth_cred(**fields: Any) -> OAuth2Credential:
    found = make_policy({"music": spotify(**fields)}).credentials["music"]
    assert isinstance(found, OAuth2Credential)
    return found


@pytest.mark.parametrize(
    ("limit", "unused", "expected"),
    [
        (180, 166 * DAY, None),
        (180, 166 * DAY + 1, {"days": 166, "limit": 180}),
        (180, 171 * DAY + 5, {"days": 171, "limit": 180}),
        (15, DAY, None),
        (15, DAY + 1, {"days": 1, "limit": 15}),
        # Under the warning window: any time unused is reported.
        (10, 0, None),
        (10, 1, {"days": 0, "limit": 10}),
    ],
)
def test_idle(limit: int, unused: int, expected: dict[str, int] | None) -> None:
    last_ok = "2026-09-21T14:13:20Z"
    assert parse_time(last_ok) == NOW
    assert idle(oauth_cred(idle_expiry_days=limit), {"last_ok": last_ok}, NOW + unused) == expected


def test_idle_needs_a_limit_and_a_last_success() -> None:
    assert idle(oauth_cred(), {"last_ok": "2020-01-01T00:00:00Z"}, NOW) is None
    assert idle(oauth_cred(idle_expiry_days=30), {}, NOW) is None
    assert idle(oauth_cred(idle_expiry_days=30), {"last_ok": 5}, NOW) is None
    assert idle_text({"days": 3, "limit": 30}) == (
        "unused for 3 days; the provider drops unused grants after 30"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-09-21T14:13:20Z", NOW),
        ("2026-09-21T16:13:20+02:00", NOW),
        ("1970-01-01T00:00:00Z", 0.0),
        ("1969-12-31T23:59:59Z", None),
        ("2026-09-21T13:33:20", None),
        ("not a time", None),
        (NOW, None),
        (None, None),
    ],
)
def test_parse_time(value: object, expected: float | None) -> None:
    assert parse_time(value) == expected


# --- passkeys (I.1) ------------------------------------------------------------------------------

UNAVAILABLE_TEXT = (
    "the passkey file can't be verified (edited, or written under another master key); "
    "portal login is off"
)
SINGLE = finding(
    "passkey_single",
    "info",
    "only one passkey is enrolled: add a second, so losing one doesn't lock you out",
    {"kind": "add_passkey"},
)
COUNTER = finding(
    "passkey_counter",
    "warning",
    "a passkey's signature counter went back in the last 30 days: the authenticator may have "
    "been copied",
    {"kind": "review_passkeys"},
)


def test_without_a_portal_there_is_no_passkeys_section() -> None:
    assert "passkeys" not in report(make_policy({}))


@pytest.mark.parametrize(
    ("state", "level", "findings"),
    [
        (PasskeyState(0), "ok", []),
        (PasskeyState(2), "ok", []),
        (PasskeyState(1), "info", [SINGLE]),
        (PasskeyState(2, regressed_ago=0), "warning", [COUNTER]),
        (PasskeyState(2, regressed_ago=30 * DAY - 1), "warning", [COUNTER]),
        (PasskeyState(2, regressed_ago=30 * DAY), "ok", []),
        (PasskeyState(1, regressed_ago=DAY), "warning", [COUNTER, SINGLE]),
    ],
)
def test_the_passkeys(state: PasskeyState, level: str, findings: list[dict[str, Any]]) -> None:
    assert report(make_policy({}), passkeys=state)["passkeys"] == {
        "count": state.count,
        "level": level,
        "findings": findings,
    }
    assert REGRESSION_DAYS == 30


def test_an_unverifiable_passkey_file_hides_the_rest() -> None:
    found = report(make_policy({}), passkeys=PasskeyState(1, unavailable=True, regressed_ago=0))
    assert found["passkeys"] == {
        "count": None,
        "level": "error",
        "findings": [
            finding("passkeys_unavailable", "error", UNAVAILABLE_TEXT, {"kind": "reset_passkeys"})
        ],
    }
    assert found["summary"] == {"error": 1, "warning": 0, "info": 0}


def test_the_summary_counts_the_passkeys() -> None:
    state = PasskeyState(1, regressed_ago=0)
    found = report(make_policy({}), persisted=False, passkeys=state)
    assert found["summary"] == {"error": 1, "warning": 1, "info": 1}
    assert list(found) == ["summary", "credentials", "connectors", "store", "egress", "passkeys"]


# --- the reported ledger's copy (M5 design J.4) --------------------------------------------------

READ_LEDGER = {"kind": "read_ledger"}
CHECK_GATEWAY = {"kind": "check_gateway"}
REFUSED_TAIL = ": reports are refused until the chain is restarted"


def copy(state: str = "ok", head_seq: int | None = 9, **fields: Any) -> LedgerCopy:
    values: dict[str, Any] = {"reported_ago": 12, "uptime": 3600, **fields}
    return LedgerCopy(state, head_seq, **values)


@pytest.mark.parametrize(
    ("state", "level", "findings"),
    [
        (copy(), "ok", []),
        (copy(reported_ago=300), "ok", []),
        (
            copy(reported_ago=301),
            "warning",
            [
                finding(
                    "ledger_copy_stale",
                    "warning",
                    "no report from the gateway for 5 min",
                    CHECK_GATEWAY,
                )
            ],
        ),
        # Never asked since the vault started: counted from the start.
        (copy(reported_ago=None, uptime=300), "ok", []),
        (
            copy(reported_ago=None, uptime=3600),
            "warning",
            [
                finding(
                    "ledger_copy_stale",
                    "warning",
                    "no report from the gateway for 60 min",
                    CHECK_GATEWAY,
                )
            ],
        ),
        (
            copy(head_seq=None),
            "info",
            [finding("ledger_copy_none", "info", "no report from the gateway yet", CHECK_GATEWAY)],
        ),
        (
            copy("fork", reported_ago=None),
            "error",
            [
                finding(
                    "ledger_copy_refused",
                    "error",
                    "the gateway's ledger no longer extends the copy (a fork)" + REFUSED_TAIL,
                    READ_LEDGER,
                )
            ],
        ),
        (
            copy("gap"),
            "error",
            [
                finding(
                    "ledger_copy_refused",
                    "error",
                    "the gateway's report skipped records the copy doesn't hold (a gap)"
                    + REFUSED_TAIL,
                    READ_LEDGER,
                )
            ],
        ),
        (
            copy("full", head_seq=None),
            "error",
            [
                finding(
                    "ledger_copy_refused",
                    "error",
                    "the copy is full and holds nothing received long enough ago to prune"
                    + REFUSED_TAIL,
                    READ_LEDGER,
                )
            ],
        ),
        (
            copy(broken_at=4),
            "error",
            [
                finding(
                    "ledger_copy_broken",
                    "error",
                    "the copy's files stop chaining at seq 4 (damaged or edited)",
                    READ_LEDGER,
                )
            ],
        ),
        (
            copy("unavailable", None, broken_at=4),
            "error",
            [
                finding(
                    "ledger_copy_unavailable",
                    "error",
                    "the vault can't read its copy of the gateway's ledger; reports are refused",
                    {"kind": "check_volume"},
                )
            ],
        ),
    ],
)
def test_the_ledger_copy(state: LedgerCopy, level: str, findings: list[dict[str, Any]]) -> None:
    assert report(make_policy({}), ledger_copy=state)["ledger_copy"] == {
        "state": state.state,
        "head_seq": state.head_seq,
        "reported_ago": state.reported_ago,
        "broken_at": state.broken_at,
        "level": level,
        "findings": findings,
    }
    assert STALE_SECONDS == 300


def test_the_summary_counts_the_ledger_copy() -> None:
    found = report(make_policy({}), ledger_copy=copy("fork", broken_at=2))
    assert found["summary"] == {"error": 2, "warning": 0, "info": 0}
    assert list(found)[-1] == "ledger_copy"
    assert "ledger_copy" not in report(make_policy({}))


# --- the gateway's status (M6 design K.1, M.5; Y21, Y29, T-7) ------------------------------------

PIN_A, PIN_B = ("sha256:" + digit * 64 for digit in "ab")
VIEW = "sha256:" + "cd" * 32
REVIEW_NOTES = {"kind": "review", "server": "notes"}


def gateway_policy(on_drift: str = "hide", fetch_on_drift: str = "hide") -> Policy:
    """Two gateway servers: notes, a remote server over https, and fetch, a bridge."""
    policy = bridge_policy(
        {"notes": "https://mcp.notes.example", "fetch": "unix:/run/zoeymcp-bridge-fetch/mcp.sock"}
    )
    raw = policy.model_dump(mode="json", exclude_defaults=True, by_alias=True)
    raw["gateway"]["servers"]["notes"]["on_drift"] = on_drift
    raw["gateway"]["servers"]["fetch"]["on_drift"] = fetch_on_drift
    return Policy.model_validate(raw)


def server_status(**fields: Any) -> ServerStatus:
    values: dict[str, Any] = {
        "kind": "remote",
        "state": ("ready",),
        "era": "modern",
        "included": 2,
        "exposed": 2,
    }
    return ServerStatus(**{**values, **fields})


def gateway(
    servers: Mapping[str, ServerStatus] | None = None,
    age: float = 10.0,
    policy: Policy | None = None,
    **report_fields: Any,
) -> dict[str, Any]:
    status = GatewayStatus(
        None
        if servers is None
        else StatusReport(view=VIEW, started=1, servers=dict(servers), **report_fields),
        age,
    )
    section: dict[str, Any] = report(policy or gateway_policy(), gateway_status=status)["gateway"]
    return section


def test_no_gateway_section_without_a_status_or_a_gateway() -> None:
    assert "gateway" not in report(gateway_policy())
    status = GatewayStatus(None, 0.0)
    assert "gateway" not in report(make_policy({}), gateway_status=status)
    found = report(gateway_policy(), gateway_status=status)
    assert list(found)[-1] == "gateway"


def test_a_quiet_gateway() -> None:
    section = gateway({"notes": server_status(), "fetch": server_status()})
    assert (section["level"], section["findings"]) == ("ok", [])
    assert (section["reported_ago"], section["view"]) == (10, VIEW)
    assert [row["name"] for row in section["servers"]] == ["fetch", "notes"]
    notes = section["servers"][1]
    assert notes == {
        "name": "notes",
        "kind": "remote",
        "bridge": False,
        "state": ["ready"],
        "era": "modern",
        "attention": {
            "drifted": [],
            "marked": [],
            "new": [],
            "changed_declined": [],
            "missing": [],
        },
        "blocked": False,
        "invalid": [],
        "unnamed": 0,
    }
    assert section["servers"][0]["bridge"] is True


def test_tools_nobody_reviewed() -> None:
    """J.5: the new tools and the declined ones that changed, through the one decision; counted,
    not named, since the upstream chose the names (M.5)."""
    entry = server_status(
        unreviewed=(("purge", PIN_A), ("echo", PIN_B), ("share", PIN_A)),
        declined_changed=("echo",),
    )
    section = gateway({"notes": entry})
    assert section["findings"] == [
        finding(
            "tools_unreviewed",
            "warning",
            "notes lists 3 tools nobody reviewed",
            REVIEW_NOTES,
        )
    ]
    assert section["servers"][0]["attention"]["new"] == ["purge", "share"]
    assert section["servers"][0]["attention"]["changed_declined"] == ["echo"]
    one_tool = gateway({"notes": server_status(unreviewed=(("purge", PIN_A),))})
    assert one_tool["findings"][0]["text"] == "notes lists 1 tool nobody reviewed"


def test_drifted_marked_and_missing_tools_are_one_finding() -> None:
    entry = server_status(drift=("a",), marked=("b", "c"), missing=("d",))
    [found] = gateway({"notes": entry})["findings"]
    assert found == finding(
        "drift_marked",
        "warning",
        "notes: included tools 1 changed since the review (a); 2 hidden by a drift mark (b, c); "
        "1 no longer listed (d)",
        REVIEW_NOTES,
    )
    for fields, text in (
        ({"drift": ("a",)}, "notes: included tools 1 changed since the review (a)"),
        ({"marked": ("b",)}, "notes: included tools 1 hidden by a drift mark (b)"),
        ({"missing": ("d",)}, "notes: included tools 1 no longer listed (d)"),
    ):
        [only] = gateway({"notes": server_status(**fields)})["findings"]
        assert only["text"] == text


def test_a_long_list_names_ten() -> None:
    names = tuple(f"t{n:02}" for n in range(12))
    [found] = gateway({"notes": server_status(drift=names)})["findings"]
    assert found["text"] == (
        "notes: included tools 12 changed since the review ("
        + ", ".join(names[:10])
        + " and 2 more)"
    )
    [ten] = gateway({"notes": server_status(drift=names[:10])})["findings"]
    assert ten["text"].endswith("(" + ", ".join(names[:10]) + ")")


@pytest.mark.parametrize(
    ("on_drift", "fields", "blocked"),
    [
        ("fail", {"drift": ("a",), "blocked": True}, True),
        # A held mark on a tool no longer listed, or an included tool listed invalid.
        ("fail", {"missing": ("a",), "blocked": True}, True),
        ("fail", {"blocked": True}, True),
        # The gateway's word, not the vault's reading of the lists or of the policy.
        ("fail", {"drift": ("a",)}, False),
        ("fail", {"marked": ("a",)}, False),
        ("hide", {"blocked": True}, True),
    ],
)
def test_a_blocked_server(on_drift: str, fields: dict[str, Any], blocked: bool) -> None:
    section = gateway({"notes": server_status(**fields)}, policy=gateway_policy(on_drift))
    assert section["servers"][0]["blocked"] is blocked
    found = [f for f in section["findings"] if f["code"] == "server_blocked"]
    expected = finding(
        "server_blocked",
        "warning",
        "notes is blocked (on_drift: fail): none of its tools are served",
        REVIEW_NOTES,
    )
    assert found == ([expected] if blocked else [])


def test_a_listing_it_cant_name() -> None:
    """T-7: counted, not named; an included tool listed invalid is drifted, named once there."""
    entry = server_status(drift=("list_notes",), invalid=("list_notes", "odd"), invalid_unnamed=2)
    section = gateway({"notes": entry})
    assert codes(section) == ["drift_marked", "server_listing_invalid"]
    assert section["findings"][1] == finding(
        "server_listing_invalid",
        "warning",
        "notes lists 1 tool the gateway can't serve; others' names aren't valid, so they are "
        "counted, not named",
        REVIEW_NOTES,
    )
    assert section["servers"][0]["invalid"] == ["odd"]
    assert section["servers"][0]["unnamed"] == 2
    only_drifted = gateway({"notes": server_status(drift=("a",), invalid=("a",))})
    assert codes(only_drifted) == ["drift_marked"]
    unnamed = "notes lists tools whose names aren't valid; they are counted, not named"
    for fields, text in (
        ({"invalid": ("odd", "other")}, "notes lists 2 tools the gateway can't serve"),
        ({"duplicate_unnamed": 1}, unnamed),
        ({"invalid_unnamed": 1}, unnamed),
        ({"dropped": 3}, unnamed),
    ):
        [found] = gateway({"notes": server_status(**fields)})["findings"]
        assert (found["code"], found["text"]) == ("server_listing_invalid", text)


def test_a_server_whose_status_was_refused() -> None:
    section = gateway({"fetch": server_status()}, refused_servers=("notes",))
    assert section["findings"] == [
        finding(
            "server_listing_invalid",
            "warning",
            "notes: the gateway's status for it isn't one the vault reads",
            REVIEW_NOTES,
        )
    ]
    assert [row["name"] for row in section["servers"]] == ["fetch"]
    # A refused server ends only its own row: the next one still reads.
    first = gateway({"notes": server_status(drift=("a",))}, refused_servers=("fetch",))
    assert codes(first) == ["server_listing_invalid", "drift_marked"]
    assert [row["name"] for row in first["servers"]] == ["notes"]
    unnamed = gateway({}, unnamed_servers=2)
    assert unnamed["findings"] == [
        finding(
            "server_listing_invalid",
            "warning",
            "the gateway's status names 2 server(s) by names that aren't policy names; they are "
            "left out",
            {"kind": "check_gateway"},
        )
    ]


def test_a_server_the_policy_no_longer_has_is_left_out() -> None:
    section = gateway({"gone": server_status(drift=("a",)), "notes": server_status()})
    assert (section["findings"], [row["name"] for row in section["servers"]]) == ([], ["notes"])


@pytest.mark.parametrize(
    ("age", "minutes"), [(180.0, None), (180.5, 3), (3600.0, 60), (1e9, 16666666)]
)
def test_a_gateway_that_stopped_reporting(age: float, minutes: int | None) -> None:
    """Info only: a stale status isn't a decision (Y21); none since the vault started counts
    from its start."""
    for servers in (None, {"notes": server_status()}):
        section = gateway(servers, age=age)
        expected = (
            []
            if minutes is None
            else [
                finding(
                    "gateway_status_stale",
                    "info",
                    f"the gateway hasn't reported its status for {minutes} minutes",
                    {"kind": "check_gateway"},
                )
            ]
        )
        assert section["findings"] == expected
    assert gateway(None, age=30.0)["reported_ago"] is None
    assert health.STATUS_STALE == 180


def test_a_gateway_still_on_an_older_view() -> None:
    """M.5, FM-18 (step 15a): past the grace, ``vault/managed.py`` says the gateway is behind,
    with the revision whose view it runs when this vault installed it; info only (Y21)."""
    status = GatewayStatus(StatusReport(view=VIEW, started=1, servers={}), 10.0)

    def found(state: PolicyState) -> list[dict[str, Any]]:
        section = report(gateway_policy(), gateway_status=status, policy_state=state)["gateway"]
        listed: list[dict[str, Any]] = section["findings"]
        return listed

    action = {"kind": "check_gateway"}
    assert found(PolicyState("managed", revision=5)) == []
    assert found(PolicyState("managed", revision=5, gateway_revision=4)) == []
    behind = PolicyState("managed", revision=5, gateway_behind=True, gateway_revision=4)
    assert found(behind) == [
        finding(
            "gateway_view_behind",
            "info",
            "the gateway is still on revision 4, not revision 5",
            action,
        )
    ]
    older = PolicyState("managed", revision=5, gateway_behind=True)
    assert found(older) == [
        finding(
            "gateway_view_behind",
            "info",
            "the gateway is still on an older view, not revision 5",
            action,
        )
    ]


def test_a_toolkits_row_reads_the_gateways_blocked() -> None:
    """A toolkit is blocked as the gateway says (a ``pinning: off`` one never is there)."""
    raw = gateway_policy().model_dump(mode="json", exclude_defaults=True, by_alias=True)
    raw["gateway"]["servers"]["kit"] = {
        "kind": "toolkit",
        "module": "examples.kit",
        "pinning": "off",
        "on_drift": "fail",
    }
    raw["gateway"]["servers"]["pinned"] = {
        "kind": "toolkit",
        "module": "examples.kit",
        "on_drift": "fail",
    }
    policy = Policy.model_validate(raw)
    toolkit = {"kind": "toolkit", "state": ("loaded",), "era": None, "marked": ("a",)}
    servers = {"kit": server_status(**toolkit), "pinned": server_status(**toolkit, blocked=True)}
    section = gateway(servers, policy=policy)
    assert [(row["name"], row["blocked"], row["bridge"]) for row in section["servers"]] == [
        ("kit", False, False),
        ("pinned", True, False),
    ]


# --- prompts and resources in the gateway's status (D-216) -------------------------------------

TEMPLATE = "notes://notes/{id}"


def enabling(*enable: str, toolkit: bool = False) -> Policy:
    """The gateway policy with notes enabling ``enable``; with ``toolkit``, a toolkit ``kit``."""
    raw = gateway_policy("fail").model_dump(mode="json", exclude_defaults=True, by_alias=True)
    raw["gateway"]["servers"]["notes"]["enable"] = list(enable)
    if toolkit:
        raw["gateway"]["servers"]["kit"] = {
            "kind": "toolkit",
            "module": "examples.kit",
            "on_drift": "fail",
        }
    return Policy.model_validate(raw)


def test_each_kind_raises_the_tools_findings() -> None:
    """``tools_unreviewed`` and ``drift_marked`` fire per kind the gateway reports, after the
    tools' own, the text naming the kind: what nobody reviewed counted, the included entries
    that drifted, are marked or are missing named (M.5, Y13); no new code."""
    kinds = {
        "prompt": Attention(new=("a", "b"), changed_declined=("c",), drifted=("summarize",)),
        "resource_template": Attention(drifted=(TEMPLATE,), new=("notes://x/{y}",)),
        "resource": Attention(marked=("notes://index",), missing=("notes://a", "notes://b")),
    }
    entry = server_status(drift=("echo",), kinds=kinds)
    section = gateway({"notes": entry}, policy=enabling("prompts", "resources"))
    assert [(f["code"], f["text"]) for f in section["findings"]] == [
        ("drift_marked", "notes: included tools 1 changed since the review (echo)"),
        ("tools_unreviewed", "notes lists 3 prompts nobody reviewed"),
        ("drift_marked", "notes: included prompts 1 changed since the review (summarize)"),
        ("tools_unreviewed", "notes lists 1 resource template nobody reviewed"),
        (
            "drift_marked",
            f"notes: included resource templates 1 changed since the review ({TEMPLATE})",
        ),
        (
            "drift_marked",
            "notes: included resources 1 hidden by a drift mark (notes://index); 2 no longer "
            "listed (notes://a, notes://b)",
        ),
    ]
    assert all(f["action"] == REVIEW_NOTES for f in section["findings"])
    assert all(f["level"] == "warning" for f in section["findings"])


def test_each_kinds_count_is_its_own_noun() -> None:
    for kind, one, more in (
        ("prompt", "1 prompt", "2 prompts"),
        ("resource_template", "1 resource template", "2 resource templates"),
        ("resource", "1 resource", "2 resources"),
    ):
        for names, words in ((("a",), one), (("a", "b"), more)):
            entry = server_status(kinds={kind: Attention(new=names)})
            [found] = gateway({"notes": entry})["findings"]
            assert found["text"] == f"notes lists {words} nobody reviewed"


def test_a_quiet_kind_raises_nothing() -> None:
    kinds = {"prompt": Attention(), "resource": Attention()}
    section = gateway({"notes": server_status(kinds=kinds)}, policy=enabling("prompts"))
    assert (section["level"], section["findings"]) == ("ok", [])


@pytest.mark.parametrize(
    ("enable", "served"),
    [
        (("prompts",), "tools, prompts or resources are"),
        (("resources",), "tools, prompts or resources are"),
        (("prompts", "resources", "completions"), "tools, prompts or resources are"),
        (("completions",), "tools are"),  # completions list nothing of their own
        ((), "tools are"),
    ],
)
def test_a_blocked_server_that_enables_a_kind(enable: tuple[str, ...], served: str) -> None:
    """Q20 (a): ``on_drift: fail`` blocks every kind, and the text says so for a server that
    enables one."""
    section = gateway({"notes": server_status(blocked=True)}, policy=enabling(*enable))
    [found] = [f for f in section["findings"] if f["code"] == "server_blocked"]
    assert found["text"] == f"notes is blocked (on_drift: fail): none of its {served} served"


def test_a_blocked_toolkit_serves_no_tool() -> None:
    toolkit = {"kind": "toolkit", "state": ("loaded",), "era": None, "blocked": True}
    section = gateway({"kit": server_status(**toolkit)}, policy=enabling("prompts", toolkit=True))
    [found] = section["findings"]
    assert found["text"] == "kit is blocked (on_drift: fail): none of its tools are served"


def test_a_row_carries_kinds_and_offered_only_when_reported() -> None:
    """Each kind's decision in the row's ``kinds``, and what the upstream offers beyond tools in
    ``offered`` (the true flags), each only when the gateway reported it: a tools-only row is
    as before (``test_a_quiet_gateway``)."""
    offered = {"completions": False, "logging": True, "prompts": True, "resources": True}
    kinds = {"prompt": Attention(new=("a",)), "resource": Attention()}
    entry = server_status(kinds=kinds, offered=offered)
    [row] = [r for r in gateway({"notes": entry})["servers"] if r["name"] == "notes"]
    assert row["kinds"] == {
        "prompt": Attention(new=("a",)).as_dict(),
        "resource": Attention().as_dict(),
    }
    assert row["offered"] == ["logging", "prompts", "resources"]
    none = server_status(offered=dict.fromkeys(offered, False))
    [bare] = gateway({"notes": none})["servers"]
    assert (bare["offered"], "kinds" in bare) == ([], False)
    [plain] = gateway({"notes": server_status()})["servers"]
    assert "offered" not in plain
    assert "kinds" not in plain


def test_the_summary_counts_the_gateway() -> None:
    status = GatewayStatus(
        StatusReport(
            view=VIEW,
            started=1,
            servers={
                "notes": server_status(unreviewed=(("a", PIN_A),), drift=("b",), blocked=True)
            },
        ),
        200.0,
    )
    policy = gateway_policy("fail")
    without = report(policy)["summary"]
    found = report(policy, gateway_status=status)
    assert found["summary"] == {
        "error": without["error"],
        "warning": without["warning"] + 3,
        "info": without["info"] + 1,
    }
    assert found["gateway"]["level"] == "warning"


# --- the policy store (M6 design M.5, step 13b) ------------------------------------------------

EMPTY = Policy.model_validate({"version": 1, "mode": "managed"})
IGNORED_NEXT = (
    "Remove ZOEYMCP_CONFIG; or accept it as it is, without applying it: zoeymcp policy import "
    "--from-env --baseline-only; or apply it: zoeymcp policy import --from-env (the plan shows "
    "what it undoes)"
)


def policy_section(state: PolicyState) -> dict[str, Any]:
    section: dict[str, Any] = report(EMPTY, policy_state=state)["policy"]
    return section


def test_no_store_no_policy_section() -> None:
    """A declarative deployment that never ran managed has no store: its report is as before."""
    assert "policy" not in report(EMPTY)


def test_a_managed_head_running_as_saved_is_quiet() -> None:
    assert policy_section(PolicyState("managed", revision=4)) == {
        "mode": "managed",
        "revision": 4,
        "level": "ok",
        "findings": [],
    }


def test_every_managed_finding() -> None:
    """M.5's managed rows, in order, each with its text and action; the summary counts them."""
    state = PolicyState(
        "managed",
        revision=9,
        oldest=3,
        not_running=9,
        seed_ignored="changed",
        restart_needed=(("admin.listen", "the portal keeps listening where it started"),),
        unreadable=(4, 6),
        quarantine=3,
    )
    found = report(EMPTY, policy_state=state)
    section = found["policy"]
    assert section["level"] == "error"
    assert [
        (f["code"], f["level"], f["text"], f["action"], f["advisory"]) for f in section["findings"]
    ] == [
        (
            "policy_not_running",
            "error",
            "revision 9 is saved but not running: send SIGHUP to the vault or restart it",
            {"kind": "reload_vault"},
            False,
        ),
        (
            "policy_seed_ignored",
            "warning",
            "ZOEYMCP_CONFIG has changed since the policy was seeded from it and is ignored: the "
            f"policy is revision 9. {IGNORED_NEXT}",
            {"kind": "import_from_env"},
            False,
        ),
        (
            "policy_restart_needed",
            "warning",
            "admin.listen: the portal keeps listening where it started",
            None,
            False,
        ),
        (
            "revisions_unreadable",
            "warning",
            "revisions 4, 6 failed to verify and are in quarantine: rollback to them is refused",
            None,
            False,
        ),
        (
            "policy_quarantine_kept",
            "info",
            "3 file(s) in /state/policy/quarantine: delete them once you don't need them",
            None,
            False,
        ),
    ]
    assert found["summary"] == {"error": 1, "warning": 3, "info": 1}


@pytest.mark.parametrize(
    ("reason", "said"),
    [
        ("changed", "has changed since the policy was seeded from it"),
        ("unreadable", "doesn't load"),
        ("fails_check", "fails check"),
    ],
    ids=["changed", "unreadable", "fails_check"],
)
def test_the_seed_ignored_text_says_why(reason: str, said: str) -> None:
    [finding] = policy_section(PolicyState("managed", revision=2, seed_ignored=reason))["findings"]
    assert finding[
        "text"
    ] == f"ZOEYMCP_CONFIG {said} and is ignored: the policy is revision 2. " + (IGNORED_NEXT)


def test_a_parked_store_and_what_the_declarative_policy_revives() -> None:
    """F.4, T-16: the parked store is information; what the running declarative policy brings
    back that the parked ratchet retired is a warning naming each, by its grant subject."""
    state = PolicyState(
        "declarative", revision=9, oldest=2, revived=("client:agent2", "pin:notes/tool/list")
    )
    section = policy_section(state)
    assert (section["mode"], section["revision"], section["level"]) == ("declarative", 9, "warning")
    assert [(f["code"], f["level"], f["text"], f["action"]) for f in section["findings"]] == [
        (
            "policy_store_parked",
            "info",
            "revisions 2-9 are kept and unused while the mode is declarative; to return, set "
            "mode: managed: the policy you run then becomes revision 10",
            None,
        ),
        (
            "policy_declarative_revives",
            "warning",
            "the declarative policy brings back client:agent2, pin:notes/tool/list, which "
            "managed mode had removed",
            {"kind": "fix_policy"},
        ),
    ]


def test_a_parked_store_counts_from_revision_one_by_default() -> None:
    [finding] = policy_section(PolicyState("declarative", revision=1))["findings"]
    assert finding["text"].startswith("revisions 1-1 are kept")


def test_a_store_a_declarative_start_couldnt_read() -> None:
    section = policy_section(PolicyState("declarative", unverified="key_unknown", quarantine=1))
    assert [(f["code"], f["level"], f["text"]) for f in section["findings"]] == [
        (
            "policy_store_unverified",
            "warning",
            "the policy store doesn't verify (key_unknown): a return to managed will refuse",
        ),
        (
            "policy_quarantine_kept",
            "info",
            "1 file(s) in /state/policy/quarantine: delete them once you don't need them",
        ),
    ]
    assert section["revision"] is None


def test_the_declarative_findings_are_declaratives_only() -> None:
    """A managed state never says parked, revived or unverified, whatever it holds."""
    state = PolicyState("managed", revision=3, revived=("client:a",), unverified="tampered")
    assert policy_section(state)["findings"] == []


def test_the_restore_witness_findings() -> None:
    """K.3, J11, T-5: the head behind what the gateway applied, and another deployment the
    gateway saw first, each an error (health has no critical level) acknowledged on the host;
    the command is the plain one unless the vault names its exec form; both come before the
    seed's."""
    state = PolicyState(
        "managed",
        revision=27,
        witness_behind=31,
        witness_other=40,
        seed_ignored="changed",
    )
    section = policy_section(state)
    assert section["level"] == "error"
    findings = [(f["code"], f["level"], f["action"]) for f in section["findings"]]
    assert findings == [
        ("policy_behind_witness", "error", {"kind": "acknowledge_restore"}),
        ("policy_deployment_changed", "error", {"kind": "acknowledge_restore"}),
        ("policy_seed_ignored", "warning", {"kind": "import_from_env"}),
    ]
    behind, other = (f["text"] for f in section["findings"][:2])
    assert behind == (
        "the gateway has applied revision 31; this vault holds 27. Was the state volume "
        "restored? Removed clients and moves back to approve since 27 are undone. Re-apply them "
        "(import your latest export: it restores clients, classifications and declines, not "
        "pins), review again each server Home lists as drifted, then acknowledge: zoeymcp policy "
        "acknowledge-restore"
    )
    assert other == (
        "the gateway has seen revision 40 of another deployment of this vault, and this one is "
        "at revision 27. Was /state deleted? Everything removed since the seed is "
        "back. Restore /state from one backup, or import your latest export, then acknowledge: "
        "zoeymcp policy acknowledge-restore"
    )
    fresh = PolicyState("managed", revision=1, witness_other=31, acknowledge="X")
    [finding] = policy_section(fresh)["findings"]
    assert finding["text"].endswith(
        "and this one starts at 1. Was /state deleted? Everything "
        "removed since the seed is back. Restore /state from one "
        "backup, or import your latest export, then acknowledge: X"
    )
    assert report(EMPTY, policy_state=state)["summary"]["error"] == 2
