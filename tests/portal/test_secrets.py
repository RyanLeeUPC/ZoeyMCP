"""The Secrets area, over the real API (M5 design G, F.4, P10, D-07, D-10).

Secrets are write-only: ``GET /api/secrets`` lists names and metadata, and ``secret.put`` and
``secret.delete`` are actions, planned and confirmed with a passkey. Both decide with
``vault/secretplan.py`` and write with ``vault/secretops.py``, as the admin socket's
``PUT/DELETE /secrets/{name}`` do, so a secret written through either gets the same binding and
the same refusals (P10), and the portal keeps M2's OAuth protections (D-10): an OAuth secret
takes the policy's binding and refuses origins, a vault-managed name is refused, and a binding
that moves shows in the summary, or as ``409 changed`` when it moves between prepare and confirm.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from zoeymcp.portal.refusals import KEPT_IN_MEMORY
from zoeymcp.vault.admin import AdminApp
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, SecretUnavailable

from .flows import issue, redeem, set_up, status_reason
from .rig import PortalRig, rig_policy, running
from .test_stepup import confirm, prepare, prepared, step_up

VALUE = "lfm-0123456789-distinctive"
OTHER_VALUE = "lfm-9876543210-distinctive"
STATS = "https://api.stats.example"
STATS_BINDING = {"origins": ["https://api.stats.example:443"]}
BROKER_BINDING = {
    "oauth": {
        "token": "https://auth.broker.example:443",
        "resources": ["https://mcp.broker.example:443"],
    }
}
MAIL_BINDING = {
    "smtp": {
        "host": "smtp.mail.example",
        "port": 465,
        "from": "agent@mail.example",
        "to": ["partner@mail.example"],
    }
}


def policy(stats: str = STATS) -> dict[str, Any]:
    """A static secret on a route, an OAuth credential's client ID and refresh token, and an
    SMTP connector's password; ``stats`` is the static secret's upstream."""
    return {
        "credentials": {
            "music-stats": {"kind": "query", "param": "api_key", "secret": "store:music-stats"},
            "broker-mcp": {
                "kind": "oauth2",
                "token_url": "https://auth.broker.example/oauth/token",
                "client_id": "store:broker-client-id",
                "refresh_token": "store:broker-refresh",
                "rotates": True,
            },
        },
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "smtp.mail.example",
                "port": 465,
                "username": "store:mail-user",
                "password": "store:mail-pass",
                "from": "agent@mail.example",
                "to": ["partner@mail.example"],
                "max_per_day": 20,
            }
        },
        "routes": [
            {
                "name": "stats",
                "prefix": "/stats",
                "upstream": stats,
                "credential": "music-stats",
                "callers": [{"placeholder": "ph-agent1-stats-0001"}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            },
            {
                "name": "broker-mcp",
                "prefix": "/broker",
                "upstream": "https://mcp.broker.example",
                "credential": "broker-mcp",
                "callers": [{"placeholder": "ph-agent1-broker-0001"}],
                "rules": [{"methods": ["GET", "POST"], "paths": ["/mcp"]}],
            },
            {
                "name": "mail-send",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/send"]}],
            },
        ],
    }


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path, policy=policy()) as portal:
        yield portal


@pytest.fixture
def signed_in(rig: PortalRig) -> tuple[Page, SoftAuthenticator]:
    authenticator = SoftAuthenticator()
    page = rig.browser().page(rig.origin)
    set_up(rig, page, authenticator)
    return page, authenticator


def store(rig: PortalRig) -> SecretStore:
    return rig.vault.app.tokens.store


def socket(rig: PortalRig, method: str, path: str, body: Any = None) -> httpx.Response:
    """The admin socket's answer, as ``zoeymcp secret set|delete`` gets it: an ``AdminApp``
    over the vault's own store, token manager and policy, run on the vault's loop."""
    vault = rig.vault
    admin = AdminApp(
        store(rig),
        KeySet.from_text(rig.environ["ZOEYMCP_MASTER_KEY"]),
        lambda: vault.app.policy,
        vault.setup,
        vault.app.tokens,
        vault.login,
    )

    async def ask() -> httpx.Response:
        transport = httpx.ASGITransport(app=admin.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(method, path, json=body)

    return asyncio.run_coroutine_threadsafe(ask(), rig.loop).result(30)


def put(page: Page, authenticator: SoftAuthenticator, **data: Any) -> httpx.Response:
    return step_up(page, authenticator, "secret.put", data)


def delete(page: Page, authenticator: SoftAuthenticator, name: str) -> httpx.Response:
    return step_up(page, authenticator, "secret.delete", {"name": name})


def binding(rig: PortalRig, name: str) -> dict[str, Any] | None:
    entry = store(rig).entry(name)
    return None if entry is None else entry.binding


def events(rig: PortalRig, *names: str) -> list[dict[str, Any]]:
    return [
        {k: v for k, v in line.items() if k not in ("ts", "role")}
        for line in rig.lines()
        if line["event"] in names
    ]


# --- the list (G) -------------------------------------------------------------------------------


def test_the_list_shows_names_and_metadata_never_a_value(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, authenticator = signed_in
    assert page.fetch("GET", "/api/secrets").json() == {"secrets": []}
    assert put(page, authenticator, name="music-stats", value=VALUE).status_code == 200
    assert put(page, authenticator, name="broker-refresh", value=OTHER_VALUE).status_code == 200
    # A live slot the vault keeps for a credential seeded from env: (put here by hand).
    store(rig).put("oauth.broker-mcp.live", "rt-live-distinctive", BROKER_BINDING)
    answer = page.fetch("GET", "/api/secrets")
    assert answer.status_code == 200
    listed = answer.json()["secrets"]
    assert [s["name"] for s in listed] == ["broker-refresh", "music-stats", "oauth.broker-mcp.live"]
    assert {tuple(sorted(s)) for s in listed} == {
        (
            "binding_shown",
            "created",
            "key_id",
            "live_slot",
            "name",
            "name_shown",
            "updated",
        )
    }
    stats = listed[1]
    assert stats["binding_shown"] == "sent to https://api.stats.example:443"
    assert stats["created"].endswith(" UTC")
    assert listed[0]["binding_shown"] == (
        "token endpoint https://auth.broker.example:443, its access tokens used at "
        "https://mcp.broker.example:443"
    )
    assert [s["live_slot"] for s in listed] == [False, False, True]
    # Never a value, a length or a hash of one, nor the clear meta the token manager wrote.
    for value in (VALUE, OTHER_VALUE, "rt-live-distinctive"):
        assert value not in answer.text
    assert "operator" not in answer.text  # the OAuth secret's meta.source


def test_a_setup_session_reaches_neither_the_list_nor_the_actions(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    assert redeem(page, issue(rig)).status_code == 200
    assert status_reason(page.fetch("GET", "/api/secrets")) == (403, "scope")
    data = {"name": "music-stats", "value": VALUE}
    assert status_reason(prepare(page, "secret.put", data)) == (403, "scope")
    assert store(rig).names() == []


# --- set, replace, delete (F.4) -----------------------------------------------------------------


def test_set_replace_and_delete_each_after_a_step_up(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, authenticator = signed_in
    held = prepared(page, "secret.put", {"name": "music-stats", "value": VALUE})
    assert held["summary"] == [
        ["Store", "music-stats"],
        ["Bound to", "sent to https://api.stats.example:443"],
        ["Replaces", "nothing: no secret has this name yet"],
    ]
    assert store(rig).names() == []  # preparing changes nothing
    body = authenticator.get(held["options"], page.origin).body()
    answer = confirm(page, held["action"], body)
    assert answer.status_code == 200, answer.text
    assert answer.json()["secret"]["binding_shown"] == "sent to https://api.stats.example:443"
    assert binding(rig, "music-stats") == STATS_BINDING
    secret = store(rig).get_for_origin("music-stats", f"{STATS}/2.0/x")
    assert secret.reveal() == VALUE
    # Replacing says what it replaces.
    held = prepared(page, "secret.put", {"name": "music-stats", "value": OTHER_VALUE})
    assert held["summary"][:2] == [
        ["Store", "music-stats"],
        ["Bound to", "sent to https://api.stats.example:443"],
    ]
    label, replaced = held["summary"][2]
    assert label == "Replaces"
    assert replaced.startswith("the value set at 20")
    assert replaced.endswith(" UTC")
    assert len(held["summary"]) == 3  # the binding stays
    body = authenticator.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], body).status_code == 200
    assert store(rig).get_for_origin("music-stats", STATS).reveal() == OTHER_VALUE
    # Deleting.
    held = prepared(page, "secret.delete", {"name": "music-stats"})
    assert [label for label, _ in held["summary"]] == ["Delete", "Bound to", "Set at"]
    assert held["summary"][1] == ["Bound to", "sent to https://api.stats.example:443"]
    body = authenticator.get(held["options"], page.origin).body()
    answer = confirm(page, held["action"], body)
    assert answer.json() == {"name": "music-stats", "deleted": True}
    assert store(rig).names() == []
    assert events(rig, "secret_set", "secret_deleted") == [
        {"event": "secret_set", "name": "music-stats", "binding": STATS_BINDING, "via": "portal"},
        {"event": "secret_set", "name": "music-stats", "binding": STATS_BINDING, "via": "portal"},
        {"event": "secret_deleted", "name": "music-stats", "via": "portal"},
    ]
    kinds = [line["action"] for line in rig.lines("step_up_confirmed")]
    assert kinds == ["secret.put", "secret.put", "secret.delete"]
    # The value is in no log line and no answer the page saw.
    log = rig.log.getvalue()
    for value in (VALUE, OTHER_VALUE):
        assert value not in log


def test_the_value_is_bound_to_the_confirm(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """The step-up's challenge commits to the held data, value included (F.3): preparing another
    value replaces the action, and the first one's assertion confirms nothing."""
    page, authenticator = signed_in
    first = prepared(page, "secret.put", {"name": "music-stats", "value": VALUE})
    second = prepared(page, "secret.put", {"name": "music-stats", "value": OTHER_VALUE})
    assert first["summary"] == second["summary"]  # the value is never shown
    body = authenticator.get(first["options"], page.origin).body()
    assert status_reason(confirm(page, second["action"], body)) == (401, "step_up_refused")
    assert store(rig).names() == []
    assert VALUE not in rig.log.getvalue()


# --- the same rules as the socket (P10) ---------------------------------------------------------

CASES = [
    ("music-stats", {"value": VALUE}, 200),
    ("music-stats", {"value": VALUE, "origins": ["https://x.example"]}, 200),
    ("broker-refresh", {"value": VALUE}, 200),
    ("broker-client-id", {"value": VALUE}, 200),
    ("mail-pass", {"value": VALUE}, 200),
    ("unreferenced", {"value": VALUE, "origins": ["https://x.example"]}, 200),
    ("unreferenced", {"value": VALUE}, 409),
    ("broker-refresh", {"value": VALUE, "origins": ["https://auth.broker.example"]}, 409),
    ("music-stats", {"value": VALUE, "origins": ["not a url"]}, 409),
    ("music-stats", {"value": VALUE, "origins": []}, 409),
    ("music-stats", {"value": VALUE, "origins": "https://x.example"}, 400),
    ("music-stats", {"value": ""}, 400),
    ("music-stats", {"value": "abc\ndef"}, 400),
    ("music-stats", {"value": 7}, 400),
    ("music-stats", {"value": "x" * 70_000}, 400),
    ("oauth.broker-mcp.live", {"value": VALUE}, 409),
    ("UPPER", {"value": VALUE}, 400),
]
REASONS = {
    ("unreferenced", 409): "unbound",
    ("broker-refresh", 409): "origins_on_oauth",
    ("music-stats", 409): "bad_origins",
    ("oauth.broker-mcp.live", 409): "vault_managed",
    ("UPPER", 400): "invalid_name",
}


@pytest.mark.parametrize(("name", "data", "status"), CASES)
def test_the_same_secret_through_the_socket_and_the_portal(
    rig: PortalRig,
    signed_in: tuple[Page, SoftAuthenticator],
    name: str,
    data: dict[str, Any],
    status: int,
) -> None:
    page, authenticator = signed_in
    by_socket = socket(rig, "PUT", f"/secrets/{name}", data)
    assert by_socket.status_code == status, by_socket.text
    through_socket = binding(rig, name)
    if status == 200:
        assert socket(rig, "DELETE", f"/secrets/{name}").status_code == 200
    assert store(rig).names() == []
    if status == 200:
        answer = put(page, authenticator, name=name, **data)
        assert answer.status_code == 200, answer.text
        assert binding(rig, name) == through_socket
        assert through_socket in (STATS_BINDING, BROKER_BINDING, MAIL_BINDING) or (
            through_socket == {"origins": ["https://x.example:443"]}
        )
        line = rig.lines("secret_set")[-1]
        assert (line["via"], line["binding"]) == ("portal", through_socket)
        assert [x["via"] for x in rig.lines("secret_set")] == ["socket", "portal"]
        return
    # Refused at the plan, before any prompt, with the socket's status.
    answer = prepare(page, "secret.put", {"name": name, **data})
    assert answer.status_code == status, answer.text
    reason = answer.json()["reason"]
    assert reason == REASONS.get((name, status), reason)
    assert len(rig.app.actions) == 0
    assert store(rig).names() == []
    assert VALUE not in answer.text


def test_the_portal_words_the_refusals_for_the_page(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, _ = signed_in

    def refused(**data: Any) -> dict[str, Any]:
        answer: dict[str, Any] = prepare(page, "secret.put", data).json()
        return answer

    assert refused(name="unreferenced", value=VALUE) == {
        "error": "No route or connector uses store:unreferenced, so give the origins it may be "
        "sent to.",
        "reason": "unbound",
    }
    assert refused(name="broker-refresh", value=VALUE, origins=["https://x.example"]) == {
        "error": "OAuth secrets take the policy's binding.",
        "reason": "origins_on_oauth",
    }
    assert refused(name="oauth.broker-mcp.live", value=VALUE)["error"] == (
        "Tokens for this credential come from Connect, on the Credentials page."
    )
    assert refused(name="music-stats", value="")["reason"] == "empty_value"
    assert refused(name=7, value=VALUE) == {
        "error": "The request didn't have the expected fields.",
        "reason": "bad_body",
    }
    assert refused(name="music-stats")["reason"] == "bad_body"  # the registry's keys
    assert refused(name="music-stats", value=VALUE, extra=1)["reason"] == "bad_body"


def test_a_failed_write_is_kept_in_memory_through_either(
    rig: PortalRig,
    signed_in: tuple[Page, SoftAuthenticator],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """P10: ``not_written`` on a state directory that refuses writes, the change kept in memory
    and said so, through the socket and the portal alike."""
    page, authenticator = signed_in

    def refuse(src: str, dst: str | Path) -> None:
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr("zoeymcp.vault.store.os.replace", refuse)
    for name in ("music-stats", "broker-refresh"):
        by_socket = socket(rig, "PUT", f"/secrets/{name}", {"value": VALUE})
        assert by_socket.status_code == 500
        answer = put(page, authenticator, name=name, value=OTHER_VALUE)
        assert status_reason(answer) == (500, "not_written")
        assert answer.json()["error"] == KEPT_IN_MEMORY
        assert store(rig).names() == [name]
        answer = delete(page, authenticator, name)
        assert status_reason(answer) == (500, "not_written")
        assert name not in store(rig).names()
    assert store(rig).dirty
    failed = [line for line in rig.lines() if line.get("persisted") is False]
    assert [(line["event"], line["via"]) for line in failed] == [
        ("secret_set", "socket"),
        ("secret_set", "portal"),
        ("secret_deleted", "portal"),
    ] * 2
    monkeypatch.setattr("zoeymcp.vault.store.os.replace", os.replace)


# --- M2's OAuth protections in the portal (D-10) ------------------------------------------------


def test_an_oauth_secret_takes_the_policy_binding_and_is_never_static(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, authenticator = signed_in
    held = prepared(page, "secret.put", {"name": "broker-refresh", "value": VALUE})
    assert held["summary"][1] == [
        "Bound to",
        "token endpoint https://auth.broker.example:443, its access tokens used at "
        "https://mcp.broker.example:443",
    ]
    body = authenticator.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], body).status_code == 200
    assert binding(rig, "broker-refresh") == BROKER_BINDING
    # Written by the token manager, which marks the entry as the operator's.
    entry = store(rig).entry("broker-refresh")
    assert entry is not None
    assert entry.meta == {
        "oauth": {"source": "operator", "consented_at": None, "credential": "broker-mcp"}
    }
    # It can't be read as a static secret, even for its own token endpoint.
    for url in ("https://auth.broker.example/oauth/token", "https://mcp.broker.example/mcp"):
        with pytest.raises(SecretUnavailable):
            store(rig).get_for_origin("broker-refresh", url)
    # No origins on an OAuth name, and no vault-managed name, to write or to delete.
    data = {"name": "broker-refresh", "value": VALUE, "origins": ["https://mcp.broker.example"]}
    assert status_reason(prepare(page, "secret.put", data)) == (409, "origins_on_oauth")
    store(rig).put("oauth.broker-mcp.live", "rt-live-distinctive", BROKER_BINDING)
    data = {"name": "oauth.broker-mcp.live"}
    assert status_reason(prepare(page, "secret.delete", data)) == (409, "vault_managed")
    assert "oauth.broker-mcp.live" in store(rig).names()  # the socket may delete it; not here


def test_a_binding_that_moves_is_shown_before_the_prompt(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    """A secret stored with explicit origins and entered again without them takes the policy's
    binding: the summary shows both (Q32 keeps explicit origins allowed for any static name)."""
    page, authenticator = signed_in
    answer = put(
        page, authenticator, name="music-stats", value=VALUE, origins=["https://x.example"]
    )
    assert answer.status_code == 200, answer.text
    held = prepared(page, "secret.put", {"name": "music-stats", "value": VALUE})
    labels = dict(held["summary"])
    assert labels["Bound to"] == "sent to https://api.stats.example:443"
    assert labels["Bound until now"] == "sent to https://x.example:443"
    body = authenticator.get(held["options"], page.origin).body()
    assert confirm(page, held["action"], body).status_code == 200
    assert binding(rig, "music-stats") == STATS_BINDING


def test_a_reload_that_moves_the_binding_between_prepare_and_confirm_is_changed(
    tmp_path: Path,
) -> None:
    """P6's reload case: the confirm plans again against the running policy."""
    with running(tmp_path, policy=policy()) as rig:
        authenticator = SoftAuthenticator()
        page = rig.browser().page(rig.origin)
        set_up(rig, page, authenticator)
        held = prepared(page, "secret.put", {"name": "music-stats", "value": VALUE})
        rig.reload(rig_policy(rig.portal_port, **policy(stats="https://api2.stats.example")))
        body = authenticator.get(held["options"], page.origin).body()
        answer = confirm(page, held["action"], body)
        assert status_reason(answer) == (409, "changed")
        assert answer.json()["was"] == held["summary"]
        assert ["Bound to", "sent to https://api2.stats.example:443"] in answer.json()["now"]
        assert store(rig).names() == []
        line = rig.lines("action_changed")[-1]
        assert (line["action"], line["reason"]) == ("secret.put", "changed")
        # Prepared again, it stores with the new binding.
        assert put(page, authenticator, name="music-stats", value=VALUE).status_code == 200
        assert binding(rig, "music-stats") == {"origins": ["https://api2.stats.example:443"]}


# --- deleting -----------------------------------------------------------------------------------


def test_what_a_delete_refuses_before_any_prompt(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, _ = signed_in

    def refused(name: Any) -> tuple[int, str]:
        return status_reason(prepare(page, "secret.delete", {"name": name}))

    assert refused("music-stats") == (404, "not_found")
    assert refused("UPPER") == (400, "invalid_name")
    assert refused("music-stats\n") == (400, "invalid_name")
    assert refused(7) == (400, "bad_body")
    assert refused("oauth.anything") == (409, "vault_managed")
    assert len(rig.app.actions) == 0


def test_a_secret_deleted_meanwhile_is_not_found_at_confirm(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, authenticator = signed_in
    assert put(page, authenticator, name="music-stats", value=VALUE).status_code == 200
    held = prepared(page, "secret.delete", {"name": "music-stats"})
    assert socket(rig, "DELETE", "/secrets/music-stats").status_code == 200
    body = authenticator.get(held["options"], page.origin).body()
    answer = confirm(page, held["action"], body)
    assert status_reason(answer) == (404, "not_found")
    line = rig.lines("action_changed")[-1]
    assert (line["action"], line["reason"]) == ("secret.delete", "not_found")
    assert [x["via"] for x in rig.lines("secret_deleted")] == ["socket"]


def test_an_oauth_secret_is_deleted_through_the_token_manager(
    rig: PortalRig, signed_in: tuple[Page, SoftAuthenticator]
) -> None:
    page, authenticator = signed_in
    assert put(page, authenticator, name="broker-refresh", value=VALUE).status_code == 200
    answer = delete(page, authenticator, "broker-refresh")
    assert answer.json() == {"name": "broker-refresh", "deleted": True}
    assert store(rig).names() == []
    resets = [line for line in rig.lines("oauth_cache_reset") if line["reason"] == "secret_delete"]
    assert resets
    assert json.dumps(rig.lines("secret_deleted")[-1]).count("portal") == 1
