"""Credential health (M5 design I): every finding both ways, bindings judged by effect, the
connector journal summed up, and the meta-derived ``last_failure`` and ``idle`` (D-23, D-20).

:func:`assess` takes clear metadata only, so nothing here has a value to decrypt; the admin
socket's test checks that against a store whose decryption raises.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.vault.bindings import BindingError, oauth_binding
from zoeymcp.vault.connectors.sendjournal import DAY_MS, Journal
from zoeymcp.vault.health import (
    DISPLAY_ONLY,
    REGRESSION_DAYS,
    STALE_SECONDS,
    Inputs,
    LedgerCopy,
    PasskeyState,
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
        # A client ID or secret of a refresh grant: only its token endpoint is checked.
        ("music-id", oauth_binding(TOKEN_URL, [API]), "ok"),
        ("music-secret", oauth_binding(TOKEN_URL, [EXTRA_ORIGIN]), "ok"),
        ("music-secret", oauth_binding(OTHER_TOKEN_URL, [API, OTHER]), "changed"),
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
        entry("music-secret", oauth_binding(TOKEN_URL, [API])),
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
    assert list(found) == ["summary", "credentials", "connectors", "store", "passkeys"]


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
