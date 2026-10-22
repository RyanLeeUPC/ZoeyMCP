"""Mix-up in the portal's Connect, over the real API (M7 design D.6, X6; fold-in C21's unit half).

Two credentials, each at its own authorization server that advertises RFC 9207's ``iss``, as an
onboarding writes them (``issuer`` and ``require_iss: true``). One credential's answer pasted
onto the other's flow is refused before the passkey prompt: by its ``iss`` when the two share the
default paste address, and by the address itself when each has its own (the backstop). A
mismatched answer never shows the provider's text, and a reload that changes the issuer between
the start and the paste ends the paste. The portal-level rows with two DCR credentials and the
callback's are step 15's.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx
import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.fakes.oauth_server import AuthSwitch, FakeAuthServer
from zoeymcp.vault import app as vault_app

from .flows import set_up, status_reason
from .rig import PortalRig, rig_policy, running
from .test_stepup import prepare, step_up

REDIRECT = "http://127.0.0.1/callback"
NAMES = ("notes", "tasks")
MISMATCH = "The answer came from a different issuer; nothing was stored. Connect again."
MISSING = (
    "The answer didn't name its issuer, which this provider always does; nothing was stored. "
    "Connect again."
)


def issuer(name: str) -> str:
    return f"https://auth.{name}.example"


def credential(name: str, **changes: Any) -> dict[str, Any]:
    """A public client with PKCE, as fragment 1 writes one (A.4)."""
    cred: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": f"{issuer(name)}/token",
        "authorize_url": f"{issuer(name)}/authorize",
        "client_id": f"{name}-client",
        "client_auth": "none",
        "rotates": True,
        "refresh_token": f"store:{name}-refresh",
        "scope": f"{name}.read",
        "issuer": issuer(name),
        "require_iss": True,
    }
    cred.update(changes)
    return {key: value for key, value in cred.items() if value is not None}


def policy(**changes: dict[str, Any]) -> dict[str, Any]:
    """Both credentials, each with its route; ``changes`` per credential name."""
    return {
        "credentials": {name: credential(name, **changes.get(name, {})) for name in NAMES},
        "routes": [
            {
                "name": name,
                "prefix": f"/{name}",
                "upstream": f"https://api.{name}.example",
                "credential": name,
                "callers": [{"placeholder": f"ph-agent1-{name}-0001"}],
                "rules": [{"methods": ["GET"], "paths": ["/**"]}],
            }
            for name in NAMES
        ],
    }


@dataclass
class World:
    rig: PortalRig
    fakes: dict[str, FakeAuthServer]
    page: Page
    passkey: SoftAuthenticator

    def approve(self, name: str, url: str) -> str:
        """Play the browser at ``name``'s authorization server: the address it is sent to."""

        async def browse() -> str:
            transport = httpx.ASGITransport(app=self.fakes[name].app())
            async with httpx.AsyncClient(transport=transport) as browser:
                response = await browser.get(url)
            assert response.status_code == 302, response.text
            location: str = response.headers["location"]
            return location

        return asyncio.run(browse())

    def reload(self, **changes: dict[str, Any]) -> None:
        self.rig.reload(rig_policy(self.rig.portal_port, **policy(**changes)))


def fakes() -> dict[str, FakeAuthServer]:
    return {
        name: FakeAuthServer(
            time.time,
            client_id=f"{name}-client",
            auth="none",
            rotate=True,
            scopes=(f"{name}.read",),
            issuer=issuer(name),
            iss_supported=True,
            prefix=f"fake-{name}",
        )
        for name in NAMES
    }


def serving(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **changes: Any) -> Iterator[World]:
    servers = fakes()
    apps = {f"auth.{name}.example": server.app() for name, server in servers.items()}

    async def by_host(scope: Any, receive: Any, send: Any) -> None:
        host = dict(scope["headers"])[b"host"].decode().split(":")[0]
        await apps[host](scope, receive, send)

    monkeypatch.setattr(
        vault_app,
        "_token_client",
        lambda _: httpx.AsyncClient(transport=httpx.ASGITransport(app=by_host)),
    )
    with running(tmp_path, policy=policy(**changes)) as rig:
        passkey = SoftAuthenticator()
        page = rig.browser().page(rig.origin)
        set_up(rig, page, passkey)
        yield World(rig, servers, page, passkey)


@pytest.fixture
def world(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    """Both credentials on the shared default paste address (a given client's, D.4)."""
    yield from serving(tmp_path, monkeypatch)


@pytest.fixture
def own_addresses(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[World]:
    """Each credential on its own paste address, as every registration M7 makes (DD-16)."""
    changes = {name: {"redirect_uri": f"{REDIRECT}/{name}"} for name in NAMES}
    for world in serving(tmp_path, monkeypatch, **changes):
        for name in NAMES:
            world.fakes[name].registered_redirect = f"{REDIRECT}/{name}"
        yield world


def started(page: Page, name: str) -> dict[str, Any]:
    answer = page.fetch("POST", f"/api/oauth/{name}/start", json={})
    assert answer.status_code == 200, answer.text
    data: dict[str, Any] = answer.json()
    return data


def with_state(url: str, state: str) -> str:
    parts = urlsplit(url)
    pairs = dict(parse_qsl(parts.query))
    pairs["state"] = state
    return parts._replace(query=urlencode(pairs)).geturl()


def state_of(url: str) -> str:
    return dict(parse_qsl(urlsplit(url).query))["state"]


def complete_data(flow: str, pasted: str, name: str = "notes") -> dict[str, Any]:
    return {"credential": name, "flow": flow, "redirect_url": pasted}


def crossed(world: World) -> tuple[dict[str, Any], str]:
    """A notes login, and the answer tasks' server gives for it: the mix-up's swap, tasks'
    authorization request carrying notes' ``state``."""
    notes = started(world.page, "notes")
    tasks = started(world.page, "tasks")
    hijacked = with_state(tasks["authorize_url"], state_of(notes["authorize_url"]))
    return notes, world.approve("tasks", hijacked)


def test_another_credentials_answer_is_refused_by_its_iss(world: World) -> None:
    notes, answer = crossed(world)
    assert dict(parse_qsl(urlsplit(answer).query))["iss"] == issuer("tasks")
    refused = prepare(world.page, "oauth.complete", complete_data(notes["flow"], answer))
    assert (refused.status_code, refused.json()) == (
        400,
        {"error": MISMATCH, "reason": "iss_mismatch"},
    )
    assert len(world.rig.app.actions) == 0  # nothing held, so no prompt
    assert [fake.calls for fake in world.fakes.values()] == [[], []]
    # notes' own answer still completes, at notes' server only.
    own = world.approve("notes", notes["authorize_url"])
    done = step_up(world.page, world.passkey, "oauth.complete", complete_data(notes["flow"], own))
    assert done.status_code == 200, done.text
    assert (len(world.fakes["notes"].calls), world.fakes["tasks"].calls) == (1, [])


def test_each_credentials_own_address_is_the_backstop(own_addresses: World) -> None:
    world = own_addresses
    notes, answer = crossed(world)
    assert answer.startswith(f"{REDIRECT}/tasks?")
    refused = prepare(world.page, "oauth.complete", complete_data(notes["flow"], answer))
    assert (refused.status_code, refused.json()) == (
        400,
        {
            "error": "That isn't the address the provider sent you to; it starts with "
            f"{REDIRECT}/notes.",
            "reason": "redirect_mismatch",
        },
    )
    assert [fake.calls for fake in world.fakes.values()] == [[], []]


def test_a_wrong_iss_on_an_error_shows_no_provider_text(world: World) -> None:
    fake = world.fakes["notes"]
    fake.answer = "error"
    fake.error_description = "Sign in again at https://evil.example"
    fake.switches.add(AuthSwitch.ISS_WRONG_ON_ERROR)
    notes = started(world.page, "notes")
    answer = world.approve("notes", notes["authorize_url"])
    assert "error_description=" in answer
    refused = prepare(world.page, "oauth.complete", complete_data(notes["flow"], answer))
    # Only the reason and its text: no description_shown, no provider error code.
    assert (refused.status_code, refused.json()) == (
        400,
        {"error": MISMATCH, "reason": "iss_mismatch"},
    )
    assert "evil" not in world.rig.log.getvalue()
    assert "access_denied" not in world.rig.log.getvalue()
    # Not the provider's answer, so the flow stays (a provider's error would have ended it).
    again = prepare(world.page, "oauth.complete", complete_data(notes["flow"], answer))
    assert status_reason(again) == (400, "iss_mismatch")


def test_an_answer_without_its_required_iss_is_refused(world: World) -> None:
    fake = world.fakes["notes"]
    fake.answer = "error"
    fake.switches.add(AuthSwitch.ISS_MISSING)
    notes = started(world.page, "notes")
    answer = world.approve("notes", notes["authorize_url"])
    refused = prepare(world.page, "oauth.complete", complete_data(notes["flow"], answer))
    assert (refused.status_code, refused.json()) == (
        400,
        {"error": MISSING, "reason": "iss_missing"},
    )
    assert fake.error_description not in world.rig.log.getvalue()


def test_a_reload_between_start_and_paste_ends_the_paste(world: World) -> None:
    """SPEC-2: the flow keeps the issuer it started with; a policy that no longer names it
    refuses the answer before it is read, whatever its iss."""
    notes, answer = crossed(world)
    world.reload(notes={"issuer": None, "require_iss": None})
    refused = prepare(world.page, "oauth.complete", complete_data(notes["flow"], answer))
    assert status_reason(refused) == (409, "binding_changed")
    body = refused.json()
    old, new = f"issuer {issuer('notes')}, iss required", "no issuer, iss not required"
    assert (body["old_shown"], body["new_shown"]) == (old, new)
    # The paste's dialog shows the text alone, so the text names both terms, and asks for no
    # rebind: there is no new binding to accept.
    assert body["error"] == (
        f"The policy changed this credential's issuer since the sign-in started: it was {old}, "
        f"it is now {new}. Nothing was stored. Connect again."
    )
    assert [fake.calls for fake in world.fakes.values()] == [[], []]
