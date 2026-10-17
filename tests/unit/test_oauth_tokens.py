"""Effect tests for the token manager (design D.2-D.5, D.9, D.10, D.12-D.15; invariants I1-I7).

The token endpoint is the stateful fake authorization server over ``ASGITransport``, or a
``MockTransport`` where a test needs a transport error. The clock, ``sleep`` and the jitter are
fakes, so nothing really waits.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import itertools
import json
import os
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.oauth_server import MISSING, FakeAuthServer, google_style, spotify_style
from zoeymcp.common.canonical import dumps_canonical
from zoeymcp.common.policy import Policy
from zoeymcp.vault import logs
from zoeymcp.vault.bindings import live_slot, oauth_binding
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.oauth import tokens
from zoeymcp.vault.oauth.protocol import (
    CREDENTIAL_UNAVAILABLE,
    MIN_401_AGE,
    OAUTH_CLIENT_REJECTED,
    OAUTH_MISCONFIGURED,
    OAUTH_RECONSENT_NEEDED,
    OAUTH_ROTATION_LOST,
    OAUTH_UNAVAILABLE,
    OAUTH_UNSUPPORTED,
    Client,
    Failure,
    Minted,
    TokenRequest,
    encode_envelope,
    parse_envelope,
    seed_sha256,
)
from zoeymcp.vault.oauth.tokens import (
    UPSTREAM_INSUFFICIENT_SCOPE,
    BindingChanged,
    Grant,
    OAuthUnavailable,
    TokenManager,
    fingerprint,
    slot_key,
)
from zoeymcp.vault.request import oauth_client_variants, secret_variants
from zoeymcp.vault.store import KEEP, Secret, SecretStore, StoreWriteError

pytestmark = pytest.mark.anyio

KEYS = KeySet.from_master(bytes(range(32)))
TOKEN_URL = "https://accounts.example/token"
API = "https://api.example/v1"
API_ORIGIN = "https://api.example:443"
OTHER = "https://other.example/v2"
OTHER_ORIGIN = "https://other.example:443"
NOW = datetime(2026, 10, 17, 9, 0, tzinfo=UTC).timestamp()
SPOTIFY_ID = "0123456789abcdef0123456789abcdef"
GOOGLE_ID = "000000000000-example.apps.googleusercontent.com"
GOOGLE_SECRET = "fake-google-client-secret"

BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# --- rig ---------------------------------------------------------------------------------------


class FakeClock:
    def __init__(self) -> None:
        self.mono = 1000.0
        self.wall = NOW
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.mono

    def time(self) -> float:
        return self.wall

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += seconds

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.advance(seconds)
        await asyncio.sleep(0)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


def make_policy(
    credential: Mapping[str, Any],
    *,
    name: str = "music",
    upstreams: tuple[str, ...] = (API,),
) -> Policy:
    routes = [
        {
            "name": f"r{index}",
            "prefix": f"/r{index}",
            "upstream": upstream,
            "credential": name,
            "callers": [{"placeholder": f"ph-agent{index}-direct-0001"}],
            "rules": [{"methods": ["GET"], "paths": ["/**"]}],
        }
        for index, upstream in enumerate(upstreams)
    ]
    credentials = {name: {"kind": "oauth2", "token_url": TOKEN_URL, **credential}}
    return Policy.model_validate({**BASE, "routes": routes, "credentials": credentials})


def spotify_cred(**fields: Any) -> dict[str, Any]:
    cred: dict[str, Any] = {
        "client_id": SPOTIFY_ID,
        "client_auth": "none",
        "rotates": True,
        "refresh_token": "store:music-refresh",
    }
    cred.update(fields)
    return cred


def google_cred(**fields: Any) -> dict[str, Any]:
    cred: dict[str, Any] = {
        "client_id": GOOGLE_ID,
        "client_secret": "store:google-secret",
        "client_auth": "post",
        "refresh_token": "store:music-refresh",
    }
    cred.update(fields)
    return cred


class Captured:
    def __init__(self) -> None:
        self.stream = io.StringIO()

    @property
    def text(self) -> str:
        return self.stream.getvalue()

    def events(self, kind: str) -> list[dict[str, Any]]:
        lines = [json.loads(line) for line in self.text.splitlines()]
        return [line for line in lines if line["event"] == kind]


@pytest.fixture
def captured() -> Iterator[Captured]:
    capture = Captured()
    logs.set_stream(capture.stream)
    try:
        yield capture
    finally:
        logs.set_stream(None)


class FailingWrites:
    """Makes the store's atomic rename fail while ``failing`` is set."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.failing = False
        real = os.replace

        def replace(src: str, dst: str | Path) -> None:
            if self.failing:
                raise OSError(28, "No space left on device")
            real(src, dst)

        monkeypatch.setattr("zoeymcp.vault.store.os.replace", replace)


@pytest.fixture
def writes(monkeypatch: pytest.MonkeyPatch) -> FailingWrites:
    return FailingWrites(monkeypatch)


class Rig:
    def __init__(
        self,
        tmp_path: Path,
        clock: FakeClock,
        server: FakeAuthServer,
        policy: Policy,
        *,
        env: Mapping[str, str] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        store: SecretStore | None = None,
    ) -> None:
        self.tmp_path = tmp_path
        self.clock = clock
        self.server = server
        self.policy = policy
        self.store = store or SecretStore(tmp_path, KEYS)
        self.store.load()
        self.transport = transport or httpx.ASGITransport(app=server.app())
        self.client = httpx.AsyncClient(transport=self.transport)
        self.jitter = 1.0
        self.uniform_calls: list[tuple[float, float]] = []
        self.env = {k: Secret(v) for k, v in (env or {}).items()}
        self.manager = self.new_manager()

    def new_manager(self) -> TokenManager:
        manager = TokenManager(
            self.store,
            self.client,
            clock=self.clock.monotonic,
            wall=self.clock.time,
            sleep=self.clock.sleep,
            uniform=self.uniform,
        )
        manager.configure(self.policy, self.env)
        return manager

    def uniform(self, low: float, high: float) -> float:
        self.uniform_calls.append((low, high))
        return self.jitter

    def seed(self, name: str = "music-refresh", resources: tuple[str, ...] = (API,)) -> str:
        token = self.server.issue_grant()
        self.store.put(name, token, oauth_binding(TOKEN_URL, resources))
        return token

    def put_client_secret(self, name: str = "google-secret", value: str = GOOGLE_SECRET) -> None:
        self.store.put(name, value, oauth_binding(TOKEN_URL, [API]))

    async def grant(self, credential: str = "music", upstream: str = API) -> Grant:
        return await self.manager.grant_for(credential, upstream)

    async def refused(self, credential: str = "music", upstream: str = API) -> OAuthUnavailable:
        with pytest.raises(OAuthUnavailable) as caught:
            await self.manager.grant_for(credential, upstream)
        return caught.value

    async def settle(self) -> None:
        """Let refreshes started in the background finish."""
        while tasks := [s.task for s in self.manager._slots.values() if s.task is not None]:
            await asyncio.gather(*tasks)

    def stored(self, name: str = "music-refresh") -> str:
        return self.store.get_for_oauth(name, token_url=TOKEN_URL)[0].reveal()

    def on_disk(self, name: str = "music-refresh") -> str:
        fresh = SecretStore(self.tmp_path, KEYS)
        fresh.load()
        return fresh.get_for_oauth(name, token_url=TOKEN_URL)[0].reveal()

    def status(self) -> dict[str, Any]:
        found: dict[str, Any] = self.manager.status()[0]
        return found

    @property
    def calls(self) -> int:
        return len(self.server.calls)


def spotify_rig(tmp_path: Path, clock: FakeClock, **fields: Any) -> Rig:
    return Rig(tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred(**fields)))


def google_rig(tmp_path: Path, clock: FakeClock, **fields: Any) -> Rig:
    rig = Rig(tmp_path, clock, google_style(clock.time), make_policy(google_cred(**fields)))
    rig.put_client_secret()
    return rig


def raising(*steps: type[BaseException] | httpx.Response) -> tuple[httpx.MockTransport, list[int]]:
    """A transport that raises (or answers) each step in turn, repeating the last one."""
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        step = steps[min(len(calls), len(steps)) - 1]
        if isinstance(step, httpx.Response):
            return step
        if issubclass(step, httpx.RequestError):
            raise step("simulated", request=request)
        raise step()

    return httpx.MockTransport(handler), calls


def ok_response(**fields: Any) -> httpx.Response:
    body = {"access_token": "fake-at-mock", "token_type": "Bearer", "expires_in": 3600, **fields}
    return httpx.Response(200, json=body)


# --- access tokens -----------------------------------------------------------------------------


async def test_first_use_refreshes_and_the_token_is_cached(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    assert rig.server.refresh_calls[0].refresh_token == first
    assert grant.resources == frozenset({API_ORIGIN})
    assert grant.serial == 1
    assert grant.minted_at == clock.mono
    assert grant.hard_expiry == clock.mono + 3600
    assert grant.refresh_at == clock.mono + 3600 - 120
    # Rotated and saved.
    assert rig.stored() == rig.server.active_refresh_token() != first
    again = await rig.grant()
    assert again is grant
    assert rig.calls == 1
    line = captured.events("oauth_refresh")[0]
    assert line["trigger"] == "first_use"
    assert line["token_source"] == "store"
    assert line["reason"] == "store"
    assert line["outcome"] == "ok"
    assert line["attempt"] == 1
    assert line["replayed"] is False
    assert line["rotated"] is True
    assert line["http_status"] == 200
    assert line["skew"] == 120
    assert line["lifetime"] == 3600


async def test_a_refresh_at_expiry_is_triggered_and_logged_as_such(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    clock.advance(3600 - 120 - 0.001)
    assert await rig.grant() is grant
    assert rig.calls == 1
    clock.advance(0.001)
    # The old token is still usable: it is served while the refresh runs.
    assert await rig.grant() is grant
    await rig.settle()
    newer = await rig.grant()
    assert newer.serial == grant.serial + 1
    assert rig.calls == 2
    assert captured.events("oauth_refresh")[1]["trigger"] == "expiry"


async def test_a_token_is_not_served_at_its_hard_expiry(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    rig.server.fail_next(5, 503)
    clock.advance(3600 - 120)
    assert await rig.grant() is grant
    await rig.settle()
    clock.advance(119.999)
    assert await rig.grant() is grant
    clock.advance(0.001)
    refused = await rig.refused()
    assert refused.code == OAUTH_UNAVAILABLE


async def test_an_unknown_credential_is_unavailable(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    refused = await rig.refused("nope")
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "not_configured")
    assert rig.calls == 0


async def test_single_flight_with_fifty_waiters(tmp_path: Path, clock: FakeClock) -> None:
    """I2: one refresh in flight per slot."""
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiters = [asyncio.create_task(rig.grant()) for _ in range(50)]
    await rig.server.arrived()
    gate.set()
    grants = await asyncio.gather(*waiters)
    assert {g.serial for g in grants} == {1}
    assert rig.calls == 1


async def test_cancelling_the_triggering_caller_still_commits(
    tmp_path: Path, clock: FakeClock
) -> None:
    """I5: the refresh belongs to the manager, not to the caller."""
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    gate = rig.server.hold()
    caller = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    gate.set()
    await rig.settle()
    successor = rig.server.active_refresh_token()
    assert successor is not None
    assert successor != first
    assert rig.stored() == successor
    assert rig.on_disk() == successor
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    assert rig.calls == 1


class SpyStore(SecretStore):
    """Records each write, with what the manager had cached at that moment."""

    def __init__(self, path: Path, keys: KeySet) -> None:
        super().__init__(path, keys)
        self.events: list[tuple[str, str, object]] = []
        self.watch: Callable[[], object] = lambda: None

    def put(
        self,
        name: str,
        value: str,
        binding: Mapping[str, Any],
        *,
        meta: Any = KEEP,
    ) -> None:
        self.events.append(("put", value, self.watch()))
        super().put(name, value, binding, meta=meta)


async def test_the_store_write_happens_before_the_token_is_published(
    tmp_path: Path, clock: FakeClock
) -> None:
    """I3: persist before publish, and before any waiter returns."""
    spy = SpyStore(tmp_path, KEYS)
    server = spotify_style(clock.time)
    rig = Rig(tmp_path, clock, server, make_policy(spotify_cred()), store=spy)
    rig.seed()
    spy.events.clear()
    spy.watch = lambda: rig.manager._cache.get("music")
    returned: list[Grant] = []

    async def waiter() -> None:
        grant = await rig.grant()
        spy.events.append(("returned", grant.token.reveal(), None))
        returned.append(grant)

    gate = server.hold()
    tasks = [asyncio.create_task(waiter()) for _ in range(3)]
    await server.arrived()
    gate.set()
    await asyncio.gather(*tasks)
    kinds = [kind for kind, _, _ in spy.events]
    assert kinds == ["put", "returned", "returned", "returned"]
    _, value, cached_then = spy.events[0]
    assert value == server.active_refresh_token()
    assert cached_then is None
    assert rig.manager._cache["music"] is returned[0]

    # The same order on a later refresh: the old token is cached, the new one is not yet.
    old = returned[0]
    clock.advance(3600)
    spy.events.clear()
    newer = await rig.grant()
    assert spy.events[0][0] == "put"
    assert spy.events[0][2] is old
    assert newer.serial == old.serial + 1


async def test_a_successor_is_saved_even_with_rotates_false(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """I3 applies whatever ``rotates`` says (D.6)."""
    rig = google_rig(tmp_path, clock)
    first = rig.seed()
    await rig.grant()
    assert rig.stored() == first
    assert captured.events("oauth_rotation_observed") == []
    rig.server.rotate_next()
    clock.advance(3600)
    await rig.grant()
    assert rig.stored() == rig.server.active_refresh_token() != first
    assert [e["credential"] for e in captured.events("oauth_rotation_observed")] == ["music"]
    assert captured.events("oauth_rotation_missing") == []


async def test_rotation_missing_is_logged_for_a_rotating_credential(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.omit_refresh_every = 1
    first = rig.seed()
    await rig.grant()
    assert rig.stored() == first
    missing = captured.events("oauth_rotation_missing")
    assert [(m["credential"], m["slot"]) for m in missing] == [("music", "music-refresh")]
    assert captured.events("oauth_rotation_observed") == []


async def test_ten_rotations_never_reuse_a_token(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    for _ in range(10):
        await rig.grant()
        assert rig.on_disk() == rig.server.active_refresh_token()
        clock.advance(3600)
    presented = [c.refresh_token for c in rig.server.refresh_calls]
    assert len(set(presented)) == 10
    assert all(c.status == 200 for c in rig.server.calls)


# --- store write failures ----------------------------------------------------------------------


async def test_a_failed_write_keeps_the_successor_and_the_next_refresh_presents_it(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, captured: Captured
) -> None:
    """I4, I5: memory keeps the new token; a later write saves it."""
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    writes.failing = True
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    successor = rig.server.active_refresh_token()
    assert rig.stored() == successor != first
    assert rig.store.dirty
    assert rig.on_disk() == first
    failed = captured.events("oauth_persist_failed")
    assert failed[0]["level"] == "critical"
    assert failed[0]["slot"] == "music-refresh"
    assert failed[0]["error_type"] == "StoreWriteError"
    assert rig.status()["persisted"] is False

    clock.advance(3600)
    await rig.grant()
    assert rig.server.refresh_calls[1].refresh_token == successor
    assert rig.server.calls[1].status == 200

    writes.failing = False
    clock.advance(3600)
    await rig.grant()
    assert captured.events("oauth_persist_recovered") != []
    assert not rig.store.dirty
    assert rig.on_disk() == rig.server.active_refresh_token()
    assert rig.status()["persisted"] is True


async def test_a_failed_write_is_an_error_without_rotates(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, captured: Captured
) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    rig.server.rotate_next()
    writes.failing = True
    await rig.grant()
    assert captured.events("oauth_persist_failed")[0]["level"] == "error"


async def test_a_flush_that_fails_again_is_logged_and_the_refresh_goes_on(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    writes.failing = True
    await rig.grant()
    clock.advance(3600)
    await rig.grant()
    assert captured.events("oauth_persist_recovered") == []
    flush_failures = [e for e in captured.events("oauth_persist_failed") if e["slot"] is None]
    assert flush_failures[0]["level"] == "critical"
    assert rig.calls == 2


# --- attempts: pre-send vs maybe-sent (I6) -----------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.PoolTimeout,
        httpx.ProxyError,
        httpx.UnsupportedProtocol,
    ],
)
async def test_a_pre_send_failure_is_one_attempt(
    tmp_path: Path, clock: FakeClock, captured: Captured, error: type[Exception]
) -> None:
    transport, calls = raising(error)
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    refused = await rig.refused()
    assert len(calls) == 1
    assert clock.sleeps == []
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "pre_send")
    line = captured.events("oauth_refresh")[0]
    assert (line["attempt"], line["replayed"], line["outcome"]) == (1, False, "backoff")


@pytest.mark.parametrize(
    "error",
    [
        httpx.WriteError,
        httpx.WriteTimeout,
        httpx.ReadError,
        httpx.ReadTimeout,
        httpx.RemoteProtocolError,
        TimeoutError,
        RuntimeError,
    ],
)
async def test_a_maybe_sent_failure_gets_exactly_one_replay(
    tmp_path: Path, clock: FakeClock, captured: Captured, error: type[Exception]
) -> None:
    transport, calls = raising(error)
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    refused = await rig.refused()
    assert len(calls) == 2
    assert clock.sleeps == [1.0]
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "no_response")
    line = captured.events("oauth_refresh")[0]
    assert (line["attempt"], line["replayed"]) == (2, True)


async def test_a_pre_send_failure_on_the_replay_ends_the_refresh(
    tmp_path: Path, clock: FakeClock
) -> None:
    transport, calls = raising(httpx.ReadError, httpx.ConnectError, ok_response())
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    refused = await rig.refused()
    assert len(calls) == 2
    assert refused.reason == "no_response"


async def test_the_replay_can_succeed(tmp_path: Path, clock: FakeClock, captured: Captured) -> None:
    transport, calls = raising(httpx.ReadTimeout, ok_response(refresh_token="fake-rt-mock"))
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    grant = await rig.grant()
    assert grant.token.reveal() == "fake-at-mock"
    assert len(calls) == 2
    assert rig.stored() == "fake-rt-mock"
    # Expiry is measured from when the replay was sent, after the one-second wait.
    assert grant.hard_expiry == 1001.0 + 3600
    line = captured.events("oauth_refresh")[0]
    assert (line["attempt"], line["replayed"], line["outcome"]) == (2, True, "ok")


async def test_a_lost_answer_within_the_grace_window_is_recovered(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.grace_seconds = 10
    rig.seed()
    rig.server.drop_after_processing = 1
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    assert rig.calls == 2
    assert rig.stored() == rig.server.active_refresh_token()


async def test_a_lost_answer_without_grace_is_rotation_lost(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.drop_after_processing = 1
    refused = await rig.refused()
    assert refused.code == OAUTH_ROTATION_LOST
    assert rig.calls == 2
    for _ in range(5):
        assert (await rig.refused()).code == OAUTH_ROTATION_LOST
    assert rig.calls == 2


# --- what a 2xx can carry ----------------------------------------------------------------------


async def test_the_successor_from_a_dpop_answer_is_saved(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    rig.server.token_type = "DPoP"
    refused = await rig.refused()
    assert refused.code == OAUTH_UNSUPPORTED
    assert rig.stored() == rig.server.active_refresh_token() != first
    meta = rig.store.entry("music-refresh")
    assert meta is not None
    assert meta.meta is not None
    assert meta.meta["oauth"]["last_error"]["code"] == OAUTH_UNSUPPORTED
    assert rig.manager._cache == {}


async def test_an_unusable_refresh_token_is_terminal_and_the_old_one_is_never_resent(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    rig.server.bad_refresh_token_shape = True
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (OAUTH_UNSUPPORTED, "unusable_refresh_token")
    assert rig.stored() == first
    for _ in range(100):
        await rig.refused()
    assert rig.calls == 1


async def test_a_carriage_return_in_an_access_token_is_never_used(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.crlf_token = True
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "bad_access_token")
    # The successor in the same answer was still saved.
    assert rig.stored() == rig.server.active_refresh_token()


async def test_a_body_over_the_cap_is_not_parsed(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    rig.server.huge_body = True
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "unparseable_body")
    assert rig.stored() == first


async def test_a_body_at_the_cap_is_parsed(tmp_path: Path, clock: FakeClock) -> None:
    body = json.dumps({"access_token": "fake-at-cap", "token_type": "Bearer"}).encode()
    padded = body[:-1] + b"," + b'"p":"' + b"x" * (65536 - len(body) - 7) + b'"}'
    assert len(padded) == 65536
    transport, _ = raising(httpx.Response(200, content=padded))
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    assert (await rig.grant()).token.reveal() == "fake-at-cap"


async def test_a_redirect_from_the_token_endpoint_is_not_followed(
    tmp_path: Path, clock: FakeClock
) -> None:
    main = spotify_style(clock.time)
    elsewhere = spotify_style(clock.time)
    main.redirect_token = "https://elsewhere.example/token"
    apps = {"accounts.example": main.app(), "elsewhere.example": elsewhere.app()}

    class Dispatch(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            app = apps[request.url.host]
            return await httpx.ASGITransport(app=app).handle_async_request(request)

    rig = Rig(tmp_path, clock, main, make_policy(spotify_cred()), transport=Dispatch())
    # A client that follows redirects: the manager's own guard must hold anyway.
    rig.client = httpx.AsyncClient(transport=Dispatch(), follow_redirects=True)
    rig.manager = rig.new_manager()
    rig.seed()
    refused = await rig.refused()
    assert refused.code == OAUTH_MISCONFIGURED
    assert len(main.calls) == 1
    assert elsewhere.calls == []


async def test_the_lifetime_floor_is_sixty_seconds(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.expires_in = 5
    rig.seed()
    grant = await rig.grant()
    assert grant.hard_expiry == clock.mono + 60
    assert grant.refresh_at == clock.mono + 30
    clock.advance(29.999)
    assert await rig.grant() is grant
    assert rig.calls == 1


async def test_a_missing_expires_in_uses_the_default(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, default_expires_in=600)
    rig.server.expires_in = MISSING
    rig.seed()
    grant = await rig.grant()
    assert grant.hard_expiry == clock.mono + 600


# --- failures: terminal and backoff ------------------------------------------------------------


async def test_terminal_states_make_no_calls_and_each_clearing_action_reenables(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """I6: terminal failures stop all token calls until the operator acts."""
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.revoke()
    refused = await rig.refused()
    assert (refused.code, refused.retry_after) == (OAUTH_RECONSENT_NEEDED, None)
    for _ in range(100):
        assert (await rig.refused()).code == OAUTH_RECONSENT_NEEDED
    assert rig.calls == 1
    assert [e["code"] for e in captured.events("oauth_terminal")] == [OAUTH_RECONSENT_NEEDED]
    assert rig.status()["state"] == "terminal"

    # oauth reset: one more try.
    assert rig.manager.reset("music") is True
    assert rig.manager.reset("nope") is False
    await rig.refused()
    assert rig.calls == 2
    await rig.refused()
    assert rig.calls == 2

    # secret set of the refresh token.
    token = rig.server.issue_grant()
    await rig.manager.replace_secret("music-refresh", token)
    await rig.grant()
    assert rig.calls == 3

    # secret delete: nothing is left to present, so no call either.
    rig.server.revoke()
    rig.manager._cache.clear()
    await rig.refused()
    calls = rig.calls
    assert await rig.manager.forget("music-refresh") is True
    assert (await rig.refused()).reason == "no_token"
    assert rig.calls == calls
    # A reload with changed settings and a restart are covered below.


async def test_a_reload_with_a_changed_fingerprint_clears_a_terminal_state(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.revoke()
    await rig.refused()
    await rig.refused()
    assert rig.calls == 1
    assert rig.manager.configure(rig.policy, {}) == []
    await rig.refused()
    assert rig.calls == 1
    changed = make_policy(spotify_cred(refresh_skew=60))
    assert rig.manager.configure(changed, {}) == ["music"]
    assert captured.events("oauth_cache_reset")[-1]["reason"] == "reload"
    await rig.refused()
    assert rig.calls == 2


async def test_a_restart_allows_one_attempt(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.revoke()
    await rig.refused()
    rig.manager = rig.new_manager()
    await rig.refused()
    await rig.refused()
    assert rig.calls == 2


async def test_commit_login_clears_a_terminal_state(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.revoke()
    await rig.refused()
    minted = Minted(Secret("fake-at-login"), 3600, 3600, None, None)
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret(rig.server.issue_grant()),
        minted=minted,
        sent_at=clock.mono,
        rebind=False,
    )
    assert (await rig.grant()).token.reveal() == "fake-at-login"
    assert rig.status()["state"] == "ok"
    assert rig.calls == 1


@pytest.mark.parametrize(
    ("jitter", "expected"),
    [(0.9, [4.5, 13.5, 54.0, 270.0, 810.0, 810.0]), (1.1, [5.5, 16.5, 66.0, 330.0, 990.0, 990.0])],
)
async def test_the_backoff_schedule(
    tmp_path: Path, clock: FakeClock, jitter: float, expected: list[float]
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.jitter = jitter
    rig.seed()
    rig.server.fail_next(100, 503)
    delays = []
    for delay in expected:
        refused = await rig.refused()
        assert refused.retry_after == pytest.approx(delay)
        delays.append(refused.retry_after)
        calls = rig.calls
        clock.advance(delay - 0.001)
        assert (await rig.refused()).retry_after == pytest.approx(0.001)
        assert rig.calls == calls
        clock.advance(0.001)
    assert rig.uniform_calls == [(0.9, 1.1)] * len(expected)
    assert rig.status()["failures"] == len(expected)
    assert rig.status()["state"] == "backoff"


async def test_retry_after_wins_when_longer(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.fail_next(1, 503, retry_after="120")
    assert (await rig.refused()).retry_after == 120.0
    rig.server.fail_next(1, 429, retry_after="1")
    clock.advance(120)
    assert (await rig.refused()).retry_after == pytest.approx(15.0)


async def test_a_bare_429_waits_the_default(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.fail_next(1, 429)
    assert (await rig.refused()).retry_after == 60.0


async def test_a_success_clears_the_backoff(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.fail_next(2, 500)
    await rig.refused()
    clock.advance(5)
    await rig.refused()
    clock.advance(15)
    await rig.grant()
    status = rig.status()
    assert (status["state"], status["failures"], status["code"]) == ("ok", 0, None)
    rig.server.fail_next(1, 500)
    clock.advance(3600)
    # The count started over: the first backoff again.
    assert (await rig.refused()).retry_after == 5.0


@pytest.mark.parametrize(
    ("shape", "code"),
    [
        ("rfc", OAUTH_RECONSENT_NEEDED),
        ("status_403", OAUTH_RECONSENT_NEEDED),
        ("status_200", OAUTH_RECONSENT_NEEDED),
        ("form", OAUTH_RECONSENT_NEEDED),
        ("echo", OAUTH_RECONSENT_NEEDED),
        ("html", OAUTH_MISCONFIGURED),
        ("ok_false", OAUTH_RECONSENT_NEEDED),
    ],
)
async def test_error_shapes_are_classified(
    tmp_path: Path, clock: FakeClock, captured: Captured, shape: Any, code: str
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.error_shape = shape
    presented = rig.seed()
    rig.server.revoke()
    assert (await rig.refused()).code == code
    # The provider's description (which may echo the token) is never logged.
    assert presented not in captured.text
    assert "expired or revoked" not in captured.text


async def test_a_rejected_client_is_terminal(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    rig.server.client_secret = "fake-other-secret"
    assert (await rig.refused()).code == OAUTH_CLIENT_REJECTED
    await rig.refused()
    assert rig.calls == 1


async def test_a_cached_token_is_served_through_a_terminal_state(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    rig.server.revoke()
    clock.advance(3600 - 120)
    assert await rig.grant() is grant
    await rig.settle()
    assert rig.status()["state"] == "terminal"
    clock.advance(100)
    assert await rig.grant() is grant
    assert rig.calls == 2
    clock.advance(20)
    assert (await rig.refused()).code == OAUTH_RECONSENT_NEEDED
    assert rig.calls == 2


# --- prepare: what is presented (seed vs live, D.5) --------------------------------------------


def seeded_rig(
    tmp_path: Path, clock: FakeClock, seed: str | None, **fields: Any
) -> tuple[Rig, str]:
    server = spotify_style(clock.time)
    env = {}
    if seed is not None:
        env["MUSIC_REFRESH"] = server.issue_grant() if seed == "issue" else seed
    pol = make_policy(spotify_cred(refresh_token="env:MUSIC_REFRESH", **fields))
    rig = Rig(tmp_path, clock, server, pol, env=env)
    return rig, env.get("MUSIC_REFRESH", "")


async def test_an_env_seed_is_promoted_to_the_live_slot(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig, seed = seeded_rig(tmp_path, clock, "issue")
    await rig.grant()
    assert rig.server.refresh_calls[0].refresh_token == seed
    slot = live_slot("music")
    envelope = parse_envelope(Secret(rig.stored(slot)))
    assert envelope.rt.reveal() == rig.server.active_refresh_token()
    assert envelope.seed_sha256 == seed_sha256(seed)
    entry = rig.store.entry(slot)
    assert entry is not None
    assert entry.binding == oauth_binding(TOKEN_URL, [API])
    assert entry.meta is not None
    assert entry.meta["oauth"]["source"] == "seed"
    assert entry.meta["oauth"]["rotations"] == 1
    line = captured.events("oauth_refresh")[0]
    assert (line["token_source"], line["reason"]) == ("seed", "no_live")
    assert captured.events("oauth_seed_promoted")[0]["slot"] == slot

    clock.advance(3600)
    await rig.grant()
    assert rig.server.refresh_calls[1].refresh_token == envelope.rt.reveal()
    line = captured.events("oauth_refresh")[1]
    assert (line["token_source"], line["reason"]) == ("live", "reseed_never")
    # Rotation keeps the seed hash.
    again = parse_envelope(Secret(rig.stored(slot)))
    assert again.seed_sha256 == seed_sha256(seed)


async def test_a_non_rotating_seed_is_promoted_as_it_is(tmp_path: Path, clock: FakeClock) -> None:
    rig, seed = seeded_rig(tmp_path, clock, "issue", rotates=False)
    rig.server.rotate = False
    await rig.grant()
    envelope = parse_envelope(Secret(rig.stored(live_slot("music"))))
    assert envelope.rt.reveal() == seed
    meta = rig.store.entry(live_slot("music"))
    assert meta is not None
    assert meta.meta is not None
    assert meta.meta["oauth"]["rotations"] == 0


async def test_a_failed_seed_is_not_promoted(tmp_path: Path, clock: FakeClock) -> None:
    rig, _ = seeded_rig(tmp_path, clock, "fake-unknown-seed")
    assert (await rig.refused()).code == OAUTH_RECONSENT_NEEDED
    assert rig.store.entry(live_slot("music")) is None


@pytest.mark.parametrize(
    ("reseed", "changed", "presented", "reason"),
    [
        ("never", True, "live", "reseed_never"),
        ("on-change", False, "live", "seed_unchanged"),
        ("on-change", True, "seed", "seed_changed"),
    ],
)
async def test_a_live_slot_and_a_seed(
    tmp_path: Path,
    clock: FakeClock,
    captured: Captured,
    reseed: str,
    changed: bool,
    presented: str,
    reason: str,
) -> None:
    server = spotify_style(clock.time)
    first_seed = server.issue_grant()
    live = server.issue_grant()
    seed = server.issue_grant() if changed else first_seed
    pol = make_policy(spotify_cred(refresh_token="env:MUSIC_REFRESH", reseed=reseed))
    rig = Rig(tmp_path, clock, server, pol, env={"MUSIC_REFRESH": seed})
    value = encode_envelope(Secret(live), seed_sha256(first_seed))
    meta = {"oauth": {"rotations": 7, "consented_at": "2026-01-01T00:00:00Z"}}
    rig.store.put(live_slot("music"), value.reveal(), oauth_binding(TOKEN_URL, [API]), meta=meta)
    await rig.grant()
    entry = rig.store.entry(live_slot("music"))
    assert entry is not None
    assert entry.meta is not None
    if presented == "seed":
        # A promotion starts the slot's history over.
        assert entry.meta["oauth"]["source"] == "seed"
        assert entry.meta["oauth"]["rotations"] == 1
        assert entry.meta["oauth"]["consented_at"] is None
    else:
        assert entry.meta["oauth"]["source"] == "rotation"
        assert entry.meta["oauth"]["rotations"] == 8
        assert entry.meta["oauth"]["consented_at"] == "2026-01-01T00:00:00Z"
    expected = live if presented == "live" else seed
    assert server.refresh_calls[0].refresh_token == expected
    line = captured.events("oauth_refresh")[0]
    assert (line["token_source"], line["reason"]) == (presented, reason)
    envelope = parse_envelope(Secret(rig.stored(live_slot("music"))))
    expected_hash = seed_sha256(seed) if presented == "seed" else seed_sha256(first_seed)
    assert envelope.seed_sha256 == expected_hash


async def test_a_live_slot_without_a_seed_is_used(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig, _ = seeded_rig(tmp_path, clock, None)
    live = rig.server.issue_grant()
    value = encode_envelope(Secret(live), None)
    rig.store.put(live_slot("music"), value.reveal(), oauth_binding(TOKEN_URL, [API]))
    await rig.grant()
    assert rig.server.refresh_calls[0].refresh_token == live
    assert captured.events("oauth_refresh")[0]["reason"] == "seed_absent"


async def test_deleting_the_live_slot_reseeds(tmp_path: Path, clock: FakeClock) -> None:
    rig, seed = seeded_rig(tmp_path, clock, "issue", rotates=False)
    rig.server.rotate = False
    await rig.grant()
    assert await rig.manager.forget(live_slot("music")) is True
    assert rig.manager._cache == {}
    await rig.grant()
    assert [c.refresh_token for c in rig.server.refresh_calls] == [seed, seed]


async def test_no_token_anywhere_makes_no_call(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig, _ = seeded_rig(tmp_path, clock, None)
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "no_token")
    await rig.refused()
    assert rig.calls == 0
    line = captured.events("oauth_refresh")[0]
    assert (line["attempt"], line["outcome"], line["code"]) == (
        0,
        "terminal",
        "credential_unavailable",
    )


async def test_a_missing_store_entry_makes_no_call(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "no_token")
    assert rig.calls == 0


async def test_a_refused_live_slot_never_falls_back_to_the_seed(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig, _ = seeded_rig(tmp_path, clock, "issue")
    live = rig.server.issue_grant()
    value = encode_envelope(Secret(live), None)
    # Bound to another token endpoint: get_for_oauth refuses it.
    other = oauth_binding("https://elsewhere.example/token", [API])
    rig.store.put(live_slot("music"), value.reveal(), other)
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "live_unusable")
    assert rig.calls == 0


async def test_a_live_slot_that_is_not_an_envelope_is_unusable(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig, _ = seeded_rig(tmp_path, clock, "issue")
    rig.store.put(live_slot("music"), "fake-not-json", oauth_binding(TOKEN_URL, [API]))
    assert (await rig.refused()).reason == "live_unusable"
    assert rig.calls == 0


async def test_a_seed_that_is_not_a_valid_token_is_refused(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig, _ = seeded_rig(tmp_path, clock, " fake-padded ")
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "seed_unusable")
    assert rig.calls == 0


async def test_a_seed_without_a_route_to_bind_is_refused(tmp_path: Path, clock: FakeClock) -> None:
    rig, _ = seeded_rig(tmp_path, clock, "issue")
    rig.manager.configure(
        make_policy(spotify_cred(refresh_token="env:MUSIC_REFRESH"), upstreams=()), rig.env
    )
    # Promotion derives the live slot's binding, and with no route there's nothing to bind to.
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "no_route")
    assert rig.calls == 0


async def test_a_tampered_store_entry_is_unusable(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    path = rig.store.path
    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"]["music-refresh"]["binding"]["oauth"]["resources"].append(OTHER_ORIGIN)
    path.write_text(json.dumps(document), encoding="utf-8")
    rig.store.load()
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "live_unusable")
    assert rig.calls == 0


# --- bindings at use (I1) ----------------------------------------------------------------------


async def test_a_route_outside_the_anchor_binding_gets_nothing(
    tmp_path: Path, clock: FakeClock
) -> None:
    pol = make_policy(spotify_cred(), upstreams=(API, OTHER))
    rig = Rig(tmp_path, clock, spotify_style(clock.time), pol)
    rig.seed(resources=(API,))
    refused = await rig.refused(upstream=OTHER)
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "route_not_bound")
    assert rig.calls == 0
    assert rig.status()["state"] == "idle"
    grant = await rig.grant()
    assert grant.resources == frozenset({API_ORIGIN})
    # With a cached token, the token's own resources refuse it.
    assert (await rig.refused(upstream=OTHER)).reason == "route_not_bound"
    clock.advance(3600 - 120)
    assert (await rig.refused(upstream=OTHER)).reason == "route_not_bound"
    assert rig.calls == 1


async def test_a_rotation_keeps_the_existing_binding(tmp_path: Path, clock: FakeClock) -> None:
    pol = make_policy(spotify_cred(), upstreams=(API, OTHER))
    rig = Rig(tmp_path, clock, spotify_style(clock.time), pol)
    rig.seed(resources=(API,))
    await rig.grant()
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.binding == oauth_binding(TOKEN_URL, [API])


async def test_the_grant_carries_the_anchor_resources(tmp_path: Path, clock: FakeClock) -> None:
    pol = make_policy(spotify_cred(), upstreams=(API, OTHER))
    rig = Rig(tmp_path, clock, spotify_style(clock.time), pol)
    rig.seed(resources=(API, OTHER))
    grant = await rig.grant(upstream=OTHER)
    assert grant.resources == frozenset({API_ORIGIN, OTHER_ORIGIN})
    assert await rig.grant(upstream=API) is grant


# --- the 401 path (D.10) -----------------------------------------------------------------------


async def test_a_401_on_a_fresh_token_is_suppressed(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    clock.advance(MIN_401_AGE - 0.001)
    assert rig.manager.rejected("music", grant) == "suppressed"
    assert await rig.grant() is grant
    clock.advance(0.001)
    assert rig.manager.rejected("music", grant) == "invalidated"
    newer = await rig.grant()
    assert newer.serial == grant.serial + 1
    assert rig.calls == 2


async def test_the_401_rule_holds_against_alternating_answers(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """Whatever the upstream answers in between, 401 refreshes are 30 s apart (I6)."""
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    refreshed_at = [clock.mono]
    await rig.grant()
    for step in range(80):
        clock.advance(7.5)
        grant = await rig.grant()
        # The upstream alternates: a 200 on even steps, a 401 on odd ones.
        if step % 2 and rig.manager.rejected("music", grant) == "invalidated":
            await rig.grant()
            refreshed_at.append(clock.mono)
    gaps = [b - a for a, b in itertools.pairwise(refreshed_at)]
    # Every 401 lands 15 s after the last; the one at exactly 30 s refreshes.
    assert gaps == [MIN_401_AGE] * 20
    assert rig.calls == len(refreshed_at)
    assert captured.events("oauth_refresh")[-1]["trigger"] == "upstream_401"


async def test_a_stale_serial_reuses_the_newer_token(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    clock.advance(MIN_401_AGE)
    assert rig.manager.rejected("music", grant) == "invalidated"
    newer = await rig.grant()
    # A second request that used the old token gets the newer one, with no refresh.
    assert rig.manager.rejected("music", grant) == "reused_newer"
    assert await rig.grant() is newer
    assert rig.calls == 2


async def test_a_401_with_nothing_cached_reuses(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    rig.manager._cache.clear()
    assert rig.manager.rejected("music", grant) == "reused_newer"
    assert rig.manager.rejected("nope", grant) == "reused_newer"


# --- reload (D.13) -----------------------------------------------------------------------------


async def test_a_reload_during_a_refresh_saves_the_token_and_skips_publishing(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    changed = make_policy(spotify_cred(refresh_skew=60))
    assert rig.manager.configure(changed, {}) == ["music"]
    gate.set()
    with pytest.raises(OAuthUnavailable) as caught:
        await waiter
    assert (caught.value.code, caught.value.reason) == (OAUTH_UNAVAILABLE, "reloaded")
    successor = rig.server.active_refresh_token()
    assert rig.stored() == successor != first
    assert rig.manager._cache == {}
    assert rig.calls == 1
    rig.server.gate = None
    grant = await rig.grant()
    assert rig.server.refresh_calls[1].refresh_token == successor
    assert rig.server.access_ok(grant.token.reveal())


async def test_a_reload_without_changes_keeps_the_cache(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    assert rig.manager.configure(make_policy(spotify_cred()), {}) == []
    assert await rig.grant() is grant
    assert rig.calls == 1


async def test_a_reload_that_moves_a_route_changes_the_fingerprint(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    moved = make_policy(spotify_cred(), upstreams=(OTHER,))
    assert rig.manager.configure(moved, {}) == ["music"]
    refused = await rig.refused(upstream=OTHER)
    assert refused.reason == "route_not_bound"
    assert grant.epoch == 1
    assert rig.calls == 1


async def test_a_removed_credential_is_dropped(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    await rig.grant()
    empty = Policy.model_validate({**BASE, "routes": [], "credentials": {}})
    assert rig.manager.configure(empty, {}) == []
    assert (await rig.refused()).reason == "not_configured"
    assert rig.manager._slots == {}
    # Added back, it starts from a new epoch.
    rig.manager.configure(rig.policy, {})
    grant = await rig.grant()
    assert grant.epoch == 2
    assert rig.calls == 2


def test_fingerprints_and_slot_keys() -> None:
    pol = make_policy(spotify_cred())
    cred = pol.credentials["music"]
    assert not isinstance(cred, dict)
    one = fingerprint(cred, frozenset({API_ORIGIN}))  # type: ignore[arg-type]
    assert one == fingerprint(cred, frozenset({API_ORIGIN}))  # type: ignore[arg-type]
    assert one != fingerprint(cred, frozenset({OTHER_ORIGIN}))  # type: ignore[arg-type]
    # The origins are sorted, so a set's iteration order never changes the fingerprint.
    origins = [f"https://api{n}.example:443" for n in (5, 2, 7, 0, 3, 6, 1, 4)]
    document = {"credential": cred.model_dump(mode="json"), "origins": sorted(origins)}
    expected = hashlib.sha256(dumps_canonical(document)).hexdigest()
    assert fingerprint(cred, frozenset(origins)) == expected  # type: ignore[arg-type]
    assert fingerprint(cred, frozenset(reversed(origins))) == expected  # type: ignore[arg-type]
    seeded = make_policy(spotify_cred(refresh_token="env:X")).credentials["music"]
    cc = make_policy(
        {"client_id": "app", "client_secret": "env:S", "grant": "client_credentials"}
    ).credentials["music"]
    assert slot_key("music", cred) == "music-refresh"  # type: ignore[arg-type]
    assert slot_key("music", seeded) == "oauth.music.live"  # type: ignore[arg-type]
    assert slot_key("music", cc) == "cc:music"  # type: ignore[arg-type]


# --- writers wait for the slot (I2) ------------------------------------------------------------


async def test_replace_secret_waits_for_the_refresh_in_flight(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    writer = asyncio.create_task(rig.manager.replace_secret("music-refresh", "fake-rt-operator"))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not writer.done()
    assert rig.stored() != "fake-rt-operator"
    gate.set()
    await waiter
    binding = await writer
    assert binding == oauth_binding(TOKEN_URL, [API])
    assert rig.stored() == "fake-rt-operator"
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta == {
        "oauth": {"source": "operator", "consented_at": None, "credential": "music"}
    }
    assert rig.manager._cache == {}
    assert captured.events("oauth_cache_reset")[-1]["reason"] == "secret_set"


async def test_forget_waits_for_the_refresh_in_flight(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    writer = asyncio.create_task(rig.manager.forget("music-refresh"))
    for _ in range(5):
        await asyncio.sleep(0)
    assert not writer.done()
    gate.set()
    await waiter
    assert await writer is True
    assert rig.store.entry("music-refresh") is None
    assert rig.manager._cache == {}
    assert await rig.manager.forget("music-refresh") is False


async def test_replace_secret_of_a_client_secret_clears_its_users(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    rig.server.client_secret = "fake-rotated-secret"
    assert (await rig.refused()).code == OAUTH_CLIENT_REJECTED
    await rig.manager.replace_secret("google-secret", "fake-rotated-secret")
    await rig.grant()
    assert rig.calls == 2


async def test_replace_secret_refuses_names_it_does_not_manage(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    with pytest.raises(ValueError, match="managed by the vault"):
        await rig.manager.replace_secret("oauth.music.live", "fake")
    with pytest.raises(ValueError, match=r"no oauth2 credential uses store:other"):
        await rig.manager.replace_secret("other", "fake")


async def test_replace_secret_write_failure_still_clears(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    await rig.grant()
    writes.failing = True
    with pytest.raises(StoreWriteError):
        await rig.manager.replace_secret("music-refresh", "fake-rt-operator")
    assert rig.stored() == "fake-rt-operator"
    assert rig.manager._cache == {}


# --- login commit (E.3) ------------------------------------------------------------------------


def minted(token: str = "fake-at-login", scope: tuple[str, ...] | None = None) -> Minted:  # noqa: S107
    return Minted(Secret(token), 3600, 3600, scope, 86400)


async def test_commit_login_stores_and_caches(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(scope=("user-top-read",)),
        sent_at=clock.mono - 1,
        rebind=False,
    )
    assert result.persisted is True
    assert result.slot == "music-refresh"
    assert result.binding == oauth_binding(TOKEN_URL, [API])
    assert result.consented_at == "2026-10-17T09:00:00Z"
    assert result.grant.hard_expiry == clock.mono - 1 + 3600
    assert rig.stored() == "fake-rt-login"
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    meta = entry.meta["oauth"]
    assert meta["source"] == "login"
    assert meta["consented_at"] == "2026-10-17T09:00:00Z"
    assert meta["rotations"] == 0
    assert meta["granted_scope"] == "user-top-read"
    assert meta["refresh_expires_at"] == "2026-10-18T09:00:00Z"
    assert (await rig.grant()) is result.grant
    assert rig.calls == 0


async def test_an_upstream_scope_complaint_shows_until_a_login(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    assert rig.status()["upstream"] is None
    clock.advance(60)
    rig.manager.note_upstream("music", UPSTREAM_INSUFFICIENT_SCOPE)
    assert rig.status()["upstream"] == {
        "code": "upstream_insufficient_scope",
        "at": "2026-10-17T09:01:00Z",
    }
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono,
        rebind=False,
    )
    assert rig.status()["upstream"] is None


async def test_commit_login_refuses_a_changed_binding_without_rebind(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed(resources=(OTHER,))
    with pytest.raises(BindingChanged) as caught:
        await rig.manager.commit_login(
            "music",
            refresh_token=Secret("fake-rt-login"),
            minted=minted(),
            sent_at=clock.mono,
            rebind=False,
        )
    assert caught.value.old == oauth_binding(TOKEN_URL, [OTHER])
    assert caught.value.new == oauth_binding(TOKEN_URL, [API])
    assert rig.stored() != "fake-rt-login"
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono,
        rebind=True,
    )
    assert rig.stored() == "fake-rt-login"


async def test_commit_login_with_an_env_seed_records_its_hash(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig, seed = seeded_rig(tmp_path, clock, "fake-rt-seed")
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono,
        rebind=False,
    )
    envelope = parse_envelope(Secret(rig.stored(live_slot("music"))))
    assert envelope.rt.reveal() == "fake-rt-login"
    assert envelope.seed_sha256 == seed_sha256(seed)


async def test_commit_login_without_a_seed_has_no_hash(tmp_path: Path, clock: FakeClock) -> None:
    rig, _ = seeded_rig(tmp_path, clock, None)
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono,
        rebind=False,
    )
    assert parse_envelope(Secret(rig.stored(live_slot("music")))).seed_sha256 is None


async def test_commit_login_with_a_failed_write_is_active_but_not_persisted(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites
) -> None:
    rig = spotify_rig(tmp_path, clock)
    writes.failing = True
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono,
        rebind=False,
    )
    assert result.persisted is False
    assert rig.stored() == "fake-rt-login"
    assert (await rig.grant()) is result.grant


async def test_commit_login_refuses_what_it_cannot_commit(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    with pytest.raises(ValueError, match="not an oauth2 credential with a refresh grant"):
        await rig.manager.commit_login(
            "nope", refresh_token=Secret("fake-rt"), minted=minted(), sent_at=0, rebind=False
        )
    with pytest.raises(ValueError, match="not a valid refresh token"):
        await rig.manager.commit_login(
            "music", refresh_token=Secret(" fake "), minted=minted(), sent_at=0, rebind=False
        )


async def test_commit_login_waits_for_the_refresh_in_flight(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    login = asyncio.create_task(
        rig.manager.commit_login(
            "music",
            refresh_token=Secret("fake-rt-login"),
            minted=minted(),
            sent_at=clock.mono,
            rebind=False,
        )
    )
    for _ in range(5):
        await asyncio.sleep(0)
    assert not login.done()
    gate.set()
    await waiter
    await login
    # Login wrote last, so its token wins over the rotation.
    assert rig.stored() == "fake-rt-login"


# --- client_credentials (D.15) -----------------------------------------------------------------


def cc_rig(tmp_path: Path, clock: FakeClock, secret: str = "store:cc-secret") -> Rig:  # noqa: S107
    server = FakeAuthServer(
        clock.time, client_id="app-cc", client_secret="fake-cc-secret", auth="basic"
    )
    cred = {"client_id": "app-cc", "client_secret": secret, "grant": "client_credentials"}
    env = {"CC_SECRET": "fake-cc-secret"}
    return Rig(tmp_path, clock, server, make_policy(cred, name="svc"), env=env)


async def test_client_credentials(tmp_path: Path, clock: FakeClock) -> None:
    rig = cc_rig(tmp_path, clock)
    rig.store.put("cc-secret", "fake-cc-secret", oauth_binding(TOKEN_URL, [API]))
    grant = await rig.grant("svc")
    assert rig.server.calls[0].grant_type == "client_credentials"
    assert rig.server.calls[0].auth == "basic"
    assert rig.server.access_ok(grant.token.reveal())
    assert rig.store.names() == ["cc-secret"]
    assert set(oauth_client_variants("app-cc", "fake-cc-secret")) <= set(grant.variants)
    assert rig.manager.status()[0]["slot"] == "cc:svc"
    # Health goes on the client secret's entry.
    entry = rig.store.entry("cc-secret")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["last_error"] is None


async def test_client_credentials_with_an_env_secret_bind_to_the_policy(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = cc_rig(tmp_path, clock, secret="env:CC_SECRET")
    grant = await rig.grant("svc")
    assert grant.resources == frozenset({API_ORIGIN})


async def test_client_credentials_unavailable_secret(tmp_path: Path, clock: FakeClock) -> None:
    rig = cc_rig(tmp_path, clock)
    refused = await rig.refused("svc")
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "client_secret_unavailable")
    assert rig.calls == 0


async def test_client_credentials_outside_the_binding(tmp_path: Path, clock: FakeClock) -> None:
    rig = cc_rig(tmp_path, clock)
    rig.store.put("cc-secret", "fake-cc-secret", oauth_binding(TOKEN_URL, [OTHER]))
    assert (await rig.refused("svc")).reason == "route_not_bound"
    assert rig.calls == 0


async def test_client_credentials_rejected(tmp_path: Path, clock: FakeClock) -> None:
    rig = cc_rig(tmp_path, clock)
    rig.store.put("cc-secret", "fake-other-secret", oauth_binding(TOKEN_URL, [API]))
    assert (await rig.refused("svc")).code == OAUTH_CLIENT_REJECTED


async def test_a_client_id_ref_is_resolved(tmp_path: Path, clock: FakeClock) -> None:
    server = FakeAuthServer(clock.time, client_id="app-ref", auth="none", rotate=True)
    pol = make_policy(spotify_cred(client_id="env:CLIENT_ID"))
    rig = Rig(tmp_path, clock, server, pol, env={"CLIENT_ID": "app-ref"})
    rig.seed()
    await rig.grant()
    assert server.calls[0].params["client_id"] == "app-ref"


async def test_a_missing_client_id_ref_makes_no_call(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(
        tmp_path,
        clock,
        spotify_style(clock.time),
        make_policy(spotify_cred(client_id="store:client-id")),
    )
    rig.seed()
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "client_id_unavailable")
    assert rig.calls == 0


async def test_a_missing_client_secret_makes_no_call(tmp_path: Path, clock: FakeClock) -> None:
    rig = Rig(tmp_path, clock, google_style(clock.time), make_policy(google_cred()))
    rig.seed()
    assert (await rig.refused()).reason == "client_secret_unavailable"
    assert rig.calls == 0


async def test_a_request_that_cannot_be_built_is_misconfigured(
    tmp_path: Path, clock: FakeClock
) -> None:
    pol = make_policy(spotify_cred(extra_params={"grant_type": "other"}))
    rig = Rig(tmp_path, clock, spotify_style(clock.time), pol)
    rig.seed()
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (OAUTH_MISCONFIGURED, "request")
    assert rig.calls == 0


# --- health and meta (B.3) ---------------------------------------------------------------------


class MetaSpy(SecretStore):
    def __init__(self, path: Path, keys: KeySet) -> None:
        super().__init__(path, keys)
        self.meta_writes: list[dict[str, Any] | None] = []

    def update_meta(self, name: str, meta: Mapping[str, Any] | None) -> bool:
        self.meta_writes.append(None if meta is None else dict(meta))
        return super().update_meta(name, meta)


async def test_meta_is_written_on_transitions_only(tmp_path: Path, clock: FakeClock) -> None:
    spy = MetaSpy(tmp_path, KEYS)
    server = google_style(clock.time)
    rig = Rig(tmp_path, clock, server, make_policy(google_cred()), store=spy)
    rig.put_client_secret()
    rig.seed()
    await rig.grant()
    assert len(spy.meta_writes) == 1
    first = spy.meta_writes[0]
    assert first is not None
    assert first["oauth"]["credential"] == "music"
    assert first["oauth"]["last_ok"] == "2026-10-17T09:00:00Z"
    assert first["oauth"]["last_error"] is None
    assert first["oauth"]["granted_scope"] == "https://www.googleapis.com/auth/calendar.readonly"
    clock.advance(3600)
    await rig.grant()
    assert len(spy.meta_writes) == 1
    server.fail_next(2, 503)
    clock.advance(3600)
    await rig.refused()
    assert len(spy.meta_writes) == 2
    error = spy.meta_writes[1]
    assert error is not None
    assert error["oauth"]["last_error"]["code"] == OAUTH_UNAVAILABLE
    assert error["oauth"]["last_ok"] == "2026-10-17T09:00:00Z"
    clock.advance(5)
    await rig.refused()
    assert len(spy.meta_writes) == 2
    clock.advance(15)
    await rig.grant()
    assert len(spy.meta_writes) == 3
    # last_ok again only a day after it was last written.
    clock.advance(86400 - 0.001)
    rig.manager._cache.clear()
    await rig.grant()
    assert len(spy.meta_writes) == 3
    clock.advance(0.001)
    rig.manager._cache.clear()
    await rig.grant()
    assert len(spy.meta_writes) == 4


@pytest.mark.parametrize("rotations", ["many", True, 4.0, None, [1]])
async def test_tampered_meta_changes_no_decision(
    tmp_path: Path, clock: FakeClock, rotations: object
) -> None:
    rig = spotify_rig(tmp_path, clock)
    first = rig.seed()
    rig.store.update_meta(
        "music-refresh",
        {"oauth": {"rotations": rotations, "source": "login", "last_error": 7, "extra": [1]}},
    )
    grant = await rig.grant()
    assert rig.server.refresh_calls[0].refresh_token == first
    assert rig.server.access_ok(grant.token.reveal())
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["rotations"] == 1
    assert entry.meta["oauth"]["source"] == "rotation"
    assert entry.meta["oauth"]["last_error"] is None
    assert "extra" not in entry.meta["oauth"]


async def test_meta_that_is_not_an_object_is_ignored(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.store.update_meta("music-refresh", {"oauth": "x"})
    assert rig.status()["meta"] is None
    await rig.grant()
    assert rig.stored() == rig.server.active_refresh_token()
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["rotations"] == 1


@pytest.mark.parametrize("style", ["rotating", "non_rotating"])
async def test_meta_the_store_would_refuse_never_stops_a_write(
    tmp_path: Path, clock: FakeClock, captured: Captured, style: str
) -> None:
    """B.3: meta is outside the AAD, so an edited state file must not cost a rotated token."""
    rig = spotify_rig(tmp_path, clock) if style == "rotating" else google_rig(tmp_path, clock)
    first = rig.seed()
    path = rig.store.path
    document = json.loads(path.read_text(encoding="utf-8"))
    document["entries"]["music-refresh"]["meta"] = {
        "oauth": {
            "note": float("nan"),
            "granted_scope": float("inf"),
            "rotations": 3,
            "consented_at": "2026-01-01T00:00:00Z",
        }
    }
    # json.dumps writes NaN and Infinity, which the store's own writes refuse.
    path.write_text(json.dumps(document), encoding="utf-8")
    rig.store.load()
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    meta = entry.meta["oauth"]
    if style == "rotating":
        # The successor went through put.
        assert rig.stored() == rig.on_disk() == rig.server.active_refresh_token() != first
        assert meta["rotations"] == 4
    else:
        # Only the health went through update_meta.
        assert rig.stored() == first
        assert meta["rotations"] == 3
    assert not rig.store.dirty
    assert "note" not in meta
    assert meta["last_ok"] == "2026-10-17T09:00:00Z"
    assert meta["consented_at"] == "2026-01-01T00:00:00Z"
    assert rig.status()["state"] == "ok"
    assert captured.events("oauth_refresh_error") == []


async def test_rotations_are_counted(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.store.update_meta("music-refresh", {"oauth": {"rotations": 4, "consented_at": "x"}})
    await rig.grant()
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["rotations"] == 5
    assert entry.meta["oauth"]["consented_at"] == "x"


async def test_status(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    assert rig.status()["state"] == "idle"
    rig.seed()
    await rig.grant()
    clock.advance(100)
    status = rig.status()
    assert status["credential"] == "music"
    assert status["grant"] == "refresh_token"
    assert status["slot"] == "music-refresh"
    assert status["state"] == "ok"
    assert status["refreshing"] is False
    assert status["access_expires_in"] == pytest.approx(3500)
    assert status["retry_in"] is None
    assert (status["code"], status["reason"]) == (None, None)
    assert status["meta"]["source"] == "rotation"
    rig.server.fail_next(1, 503)
    clock.advance(3500)
    await rig.refused()
    status = rig.status()
    assert (status["state"], status["code"], status["reason"], status["retry_in"]) == (
        "backoff",
        OAUTH_UNAVAILABLE,
        "http_status",
        5.0,
    )
    assert status["access_expires_in"] is None
    assert json.dumps(rig.manager.status())
    clock.advance(4.5)
    assert rig.status()["retry_in"] == 0.5
    clock.advance(1)
    assert rig.status()["retry_in"] == 0.0


async def test_status_of_an_expired_token(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    await rig.grant()
    clock.advance(3600 - 0.001)
    assert rig.status()["state"] == "ok"
    clock.advance(0.001)
    status = rig.status()
    assert (status["state"], status["access_expires_in"]) == ("idle", None)


# --- scopes (D.8) ------------------------------------------------------------------------------


async def test_a_narrower_or_wider_grant_is_flagged_on_refresh(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock, scope="user-read-currently-playing user-top-read")
    rig.seed()
    await rig.grant()
    assert captured.events("oauth_scope_narrowed") == []
    rig.server.granted_scopes = ("user-top-read",)
    clock.advance(3600)
    await rig.grant()
    narrowed = captured.events("oauth_scope_narrowed")
    assert [(n["scopes"], n["at"]) for n in narrowed] == [
        (["user-read-currently-playing"], "refresh")
    ]
    assert captured.events("oauth_refresh")[-1]["scope_status"] == "missing"
    rig.server.granted_scopes = ("user-top-read", "playlist-modify-private")
    clock.advance(3600)
    await rig.grant()
    unexpected = captured.events("oauth_scope_unexpected")
    assert [u["scopes"] for u in unexpected] == [["playlist-modify-private"]]
    assert captured.events("oauth_refresh")[-1]["scope_status"] == "unexpected"


# --- shutdown, scrubbing and secrecy (I5, I7) --------------------------------------------------


async def test_aclose_waits_for_the_refresh_in_flight(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    closing = asyncio.create_task(rig.manager.aclose())
    for _ in range(5):
        await asyncio.sleep(0)
    assert not closing.done()
    gate.set()
    await closing
    assert rig.on_disk() == rig.server.active_refresh_token()
    await waiter
    # No new refresh starts once closing: a usable token is still served.
    clock.advance(3600 - 120)
    await rig.grant()
    assert rig.calls == 1
    clock.advance(120)
    assert (await rig.refused()).reason == "no_grant"


async def test_aclose_saves_a_dirty_store(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    writes.failing = True
    await rig.grant()
    assert rig.store.dirty
    writes.failing = False
    await rig.manager.aclose()
    assert not rig.store.dirty
    assert rig.on_disk() == rig.server.active_refresh_token()
    assert [e["slot"] for e in captured.events("oauth_persist_recovered")] == [None]


async def test_aclose_with_nothing_to_do(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    await rig.manager.aclose()
    assert (await rig.refused()).reason == "no_grant"


async def test_the_scrub_set(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    rig.server.rotate_next(2)
    first = await rig.grant()
    clock.advance(3600)
    second = await rig.grant()
    current_rt = rig.stored()
    expected = (
        set(secret_variants(second.token.reveal()))
        | set(secret_variants(first.token.reveal()))
        | set(secret_variants(current_rt))
        | set(oauth_client_variants(GOOGLE_ID, GOOGLE_SECRET))
    )
    assert set(second.variants) == expected
    assert list(second.variants) == sorted(second.variants, key=len, reverse=True)
    assert "variants" not in repr(second)
    assert second.token.reveal() not in repr(second)


async def test_an_internal_error_never_escapes_the_task(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    class Broken(SecretStore):
        def put(
            self, name: str, value: str, binding: Mapping[str, Any], *, meta: Any = KEEP
        ) -> None:
            if value.startswith("fake-spotify-rt-2"):
                raise RuntimeError("disk on fire")
            super().put(name, value, binding, meta=meta)

    server = spotify_style(clock.time)
    rig = Rig(tmp_path, clock, server, make_policy(spotify_cred()), store=Broken(tmp_path, KEYS))
    rig.seed()
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "internal_error")
    assert captured.events("oauth_refresh_error")[0]["error_type"] == "RuntimeError"
    assert rig.manager._slots["music-refresh"].task is None


async def test_nothing_secret_is_logged(
    tmp_path: Path, clock: FakeClock, captured: Captured, writes: FailingWrites
) -> None:
    """I7: no token, client secret or provider text in any log line."""
    rig = google_rig(tmp_path, clock)
    rig.server.error_shape = "echo"
    seen = [rig.seed(), GOOGLE_SECRET]
    rig.server.rotate_next(3)
    for _ in range(3):
        grant = await rig.grant()
        seen += [grant.token.reveal(), rig.stored()]
        clock.advance(3600)
    writes.failing = True
    await rig.grant()
    rig.server.revoke()
    clock.advance(3600)
    await rig.refused()
    status = json.dumps(rig.manager.status())
    for value in seen:
        assert value not in captured.text
        assert value not in status
    assert "expired or revoked" not in captured.text


def test_the_module_constants() -> None:
    assert tokens.META_OK_INTERVAL == 86400.0
    assert tokens.CC_PREFIX == "cc:"
    assert tokens.MAX_REFRESH_EXPIRES_IN == 100 * 365 * 86400
    assert set(tokens.PRE_SEND) == {
        httpx.ConnectError,
        httpx.ConnectTimeout,
        httpx.PoolTimeout,
        httpx.ProxyError,
        httpx.UnsupportedProtocol,
    }


def test_oauth_unavailable_and_binding_changed() -> None:
    error = OAuthUnavailable("oauth_unavailable", "pre_send", retry_after=5.0)
    assert (error.code, error.reason, error.retry_after) == ("oauth_unavailable", "pre_send", 5.0)
    assert str(error) == "oauth_unavailable: pre_send"
    assert OAuthUnavailable("c", "r").retry_after is None
    changed = BindingChanged({"a": 1}, {"b": 2})
    assert (changed.old, changed.new, changed.reason) == ({"a": 1}, {"b": 2}, "binding_changed")
    assert "--rebind" in str(changed)


async def test_grant_for_before_configure_is_unavailable(tmp_path: Path) -> None:
    store = SecretStore(tmp_path, KEYS)
    store.load()
    async with httpx.AsyncClient() as client:
        manager = TokenManager(store, client)
        with pytest.raises(OAuthUnavailable):
            await manager.grant_for("music", API)
        with pytest.raises(ValueError, match="no oauth2 credential"):
            await manager.replace_secret("music-refresh", "fake")


# --- exact log lines, request details and remaining branches -----------------------------------


def without_ts(event: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in event.items() if k != "ts"}


async def test_the_refresh_log_lines(tmp_path: Path, clock: FakeClock, captured: Captured) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.server.expires_in = 5
    rig.seed()
    await rig.grant()
    assert without_ts(captured.events("oauth_refresh")[0]) == {
        "event": "oauth_refresh",
        "credential": "music",
        "slot": "music-refresh",
        "grant": "refresh_token",
        "trigger": "first_use",
        "token_source": "store",
        "reason": "store",
        "attempt": 1,
        "replayed": False,
        "http_status": 200,
        "outcome": "ok",
        "code": None,
        "error": None,
        "error_subtype": None,
        "failure_reason": None,
        "rotated": True,
        "rotates": True,
        "expires_in": 5,
        "lifetime": 60,
        "lifetime_clamped": True,
        "skew": 30,
        "scope_status": "ok",
        "notes": ["expires_in_clamped"],
        "duration_ms": 0.0,
    }
    rig.server.revoke()
    clock.advance(60)
    await rig.refused()
    assert without_ts(captured.events("oauth_refresh")[1]) == {
        "event": "oauth_refresh",
        "credential": "music",
        "slot": "music-refresh",
        "grant": "refresh_token",
        "trigger": "expiry",
        "token_source": "store",
        "reason": "store",
        "attempt": 1,
        "replayed": False,
        "http_status": 400,
        "outcome": "terminal",
        "code": OAUTH_RECONSENT_NEEDED,
        "error": "invalid_grant",
        "error_subtype": None,
        "failure_reason": "provider_error",
        "rotated": False,
        "rotates": True,
        "expires_in": None,
        "lifetime": None,
        "lifetime_clamped": False,
        "skew": None,
        "scope_status": None,
        "notes": [],
        "duration_ms": 0.0,
    }
    assert [without_ts(e) for e in captured.events("oauth_terminal")] == [
        {"event": "oauth_terminal", "credential": "music", "code": OAUTH_RECONSENT_NEEDED}
    ]


async def test_the_duration_is_measured(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    transport, _ = raising(httpx.ReadError, ok_response())
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    await rig.grant()
    assert captured.events("oauth_refresh")[0]["duration_ms"] == 1000.0


async def test_the_other_log_lines(
    tmp_path: Path, clock: FakeClock, captured: Captured, writes: FailingWrites
) -> None:
    rig, _ = seeded_rig(tmp_path, clock, "issue")
    await rig.grant()
    assert [without_ts(e) for e in captured.events("oauth_seed_promoted")] == [
        {"event": "oauth_seed_promoted", "credential": "music", "slot": "oauth.music.live"}
    ]
    rig.server.fail_next(1, 503, retry_after="30")
    clock.advance(3600)
    await rig.refused()
    assert [without_ts(e) for e in captured.events("oauth_backoff")] == [
        {
            "event": "oauth_backoff",
            "credential": "music",
            "failures": 1,
            "retry_in": 30.0,
            "retry_after": 30.0,
        }
    ]
    writes.failing = True
    clock.advance(30)
    await rig.grant()
    assert [without_ts(e) for e in captured.events("oauth_persist_failed")] == [
        {
            "event": "oauth_persist_failed",
            "credential": "music",
            "slot": "oauth.music.live",
            "error_type": "StoreWriteError",
            "level": "critical",
        }
    ]
    writes.failing = False
    rig.server.omit_refresh_every = 1
    clock.advance(3600)
    await rig.grant()
    assert [without_ts(e) for e in captured.events("oauth_persist_recovered")] == [
        {"event": "oauth_persist_recovered", "slot": None}
    ]
    assert [without_ts(e) for e in captured.events("oauth_rotation_missing")] == [
        {"event": "oauth_rotation_missing", "credential": "music", "slot": "oauth.music.live"}
    ]


async def test_the_rotation_observed_line(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    rig.server.rotate_next()
    await rig.grant()
    assert [without_ts(e) for e in captured.events("oauth_rotation_observed")] == [
        {"event": "oauth_rotation_observed", "credential": "music", "slot": "music-refresh"}
    ]


async def test_a_retry_after_date_counts_from_the_wall_clock(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    when = datetime.fromtimestamp(clock.wall + 120, UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")
    rig.server.fail_next(1, 503, retry_after=when)
    assert (await rig.refused()).retry_after == 120.0


async def test_the_token_request_as_sent(tmp_path: Path, clock: FakeClock) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return ok_response()

    rig = Rig(
        tmp_path,
        clock,
        spotify_style(clock.time),
        make_policy(spotify_cred()),
        transport=httpx.MockTransport(handler),
    )
    token = rig.seed()
    await rig.grant()
    [request] = seen
    assert request.method == "POST"
    assert str(request.url) == TOKEN_URL
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert request.headers["accept"] == "application/json"
    assert request.extensions["timeout"] == {
        "connect": 5.0,
        "read": 20.0,
        "write": 20.0,
        "pool": 20.0,
    }
    assert request.content == (
        f"grant_type=refresh_token&refresh_token={token}&client_id={SPOTIFY_ID}".encode()
    )


async def test_the_trigger_after_a_401_is_used_once(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    grant = await rig.grant()
    clock.advance(MIN_401_AGE)
    assert rig.manager.rejected("music", grant) == "invalidated"
    await rig.grant()
    clock.advance(3600)
    await rig.grant()
    await rig.settle()
    triggers = [e["trigger"] for e in captured.events("oauth_refresh")]
    assert triggers == ["first_use", "upstream_401", "expiry"]


async def test_a_credential_removed_during_a_refresh(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    empty = Policy.model_validate({**BASE, "routes": [], "credentials": {}})
    rig.manager.configure(empty, {})
    # The slot outlives the configuration while its task runs.
    assert "music-refresh" in rig.manager._slots
    gate.set()
    with pytest.raises(OAuthUnavailable) as caught:
        await waiter
    assert caught.value.reason == "reloaded"
    assert rig.stored() == rig.server.active_refresh_token()


async def test_a_refresh_grant_without_a_refresh_token_makes_no_call(
    tmp_path: Path, clock: FakeClock
) -> None:
    pol = make_policy(spotify_cred(refresh_token=None))
    rig = Rig(tmp_path, clock, spotify_style(clock.time), pol)
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "no_token")
    assert rig.calls == 0
    assert rig.status()["slot"] == "oauth.music.live"


async def test_a_first_rotation_records_no_consent(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    # Times in meta are whole seconds.
    clock.wall += 0.5
    await rig.grant()
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta == {
        "oauth": {
            "credential": "music",
            "source": "rotation",
            "rotations": 1,
            "consented_at": None,
            "last_ok": "2026-10-17T09:00:00Z",
            "last_error": None,
            "granted_scope": "user-read-currently-playing user-top-read",
            "refresh_expires_at": None,
        }
    }


async def test_display_fields_are_carried_when_a_response_omits_them(
    tmp_path: Path, clock: FakeClock
) -> None:
    transport, _ = raising(
        ok_response(refresh_token="fake-rt-a", scope="one two", refresh_token_expires_in=100),
        ok_response(refresh_token="fake-rt-b"),
    )
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    await rig.grant()
    clock.advance(3600)
    await rig.grant()
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    meta = entry.meta["oauth"]
    assert meta["granted_scope"] == "one two"
    assert meta["refresh_expires_at"] == "2026-10-17T09:01:40Z"
    assert meta["last_ok"] == "2026-10-17T10:00:00Z"
    assert meta["rotations"] == 2


async def test_the_last_error_fields(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    await rig.grant()
    rig.server.revoke()
    clock.advance(3600)
    await rig.refused()
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["last_error"] == {
        "code": OAUTH_RECONSENT_NEEDED,
        "error": "invalid_grant",
        "at": "2026-10-17T10:00:00Z",
    }
    assert entry.meta["oauth"]["last_ok"] == "2026-10-17T09:00:00Z"
    status = rig.status()
    assert (status["state"], status["code"], status["error"]) == (
        "terminal",
        OAUTH_RECONSENT_NEEDED,
        "invalid_grant",
    )
    assert status["retry_in"] is None


async def test_a_rotating_slot_writes_its_health_with_the_token(
    tmp_path: Path, clock: FakeClock
) -> None:
    spy = MetaSpy(tmp_path, KEYS)
    server = spotify_style(clock.time)
    rig = Rig(tmp_path, clock, server, make_policy(spotify_cred()), store=spy)
    rig.seed()
    await rig.grant()
    clock.advance(3600)
    await rig.grant()
    assert spy.meta_writes == []
    server.fail_next(1, 503)
    clock.advance(3600)
    await rig.refused()
    assert len(spy.meta_writes) == 1
    clock.advance(5)
    await rig.grant()
    # The rotation carried the health back to ok.
    assert len(spy.meta_writes) == 1


async def test_status_while_refreshing(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    assert rig.status()["refreshing"] is True
    gate.set()
    await waiter
    assert rig.status()["refreshing"] is False


def test_resources_of_a_binding() -> None:
    assert tokens._resources(oauth_binding(TOKEN_URL, [API])) == frozenset({API_ORIGIN})
    assert tokens._resources({"oauth": {"resources": [API_ORIGIN, 7]}}) == frozenset({API_ORIGIN})
    assert tokens._resources({"oauth": {"resources": API_ORIGIN}}) == frozenset()
    assert tokens._resources({"oauth": "x"}) == frozenset()
    assert tokens._resources({}) == frozenset()


# --- login, more -------------------------------------------------------------------------------


async def test_login_scopes_are_the_base_for_the_next_refresh(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock, scope="user-read-currently-playing user-top-read")
    token = rig.server.issue_grant()
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret(token),
        minted=minted(scope=("user-read-currently-playing", "user-top-read")),
        sent_at=clock.mono,
        rebind=False,
    )
    rig.server.granted_scopes = ("user-top-read",)
    clock.advance(3600)
    await rig.grant()
    narrowed = captured.events("oauth_scope_narrowed")
    assert [without_ts(n) for n in narrowed] == [
        {
            "event": "oauth_scope_narrowed",
            "credential": "music",
            "scopes": ["user-read-currently-playing"],
            "at": "refresh",
        }
    ]
    assert captured.events("oauth_cache_reset")[0]["reason"] == "login"


async def test_login_without_granted_scopes_uses_the_requested_ones(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = spotify_rig(tmp_path, clock, scope="user-read-currently-playing user-top-read")
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret(rig.server.issue_grant()),
        minted=minted(scope=None),
        sent_at=clock.mono,
        rebind=False,
    )
    rig.server.granted_scopes = ("user-read-currently-playing",)
    clock.advance(3600)
    await rig.grant()
    assert [n["scopes"] for n in captured.events("oauth_scope_narrowed")] == [["user-top-read"]]


async def test_login_health_needs_no_meta_write_on_the_next_refresh(
    tmp_path: Path, clock: FakeClock
) -> None:
    spy = MetaSpy(tmp_path, KEYS)
    server = google_style(clock.time)
    rig = Rig(tmp_path, clock, server, make_policy(google_cred()), store=spy)
    rig.put_client_secret()
    await rig.manager.commit_login(
        "music",
        refresh_token=Secret(server.issue_grant()),
        minted=minted(),
        sent_at=clock.mono,
        rebind=False,
    )
    clock.advance(3600)
    await rig.grant()
    assert spy.meta_writes == []


async def test_login_of_a_client_credentials_credential_is_refused(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = cc_rig(tmp_path, clock)
    with pytest.raises(ValueError, match="refresh grant"):
        await rig.manager.commit_login(
            "svc", refresh_token=Secret("fake-rt"), minted=minted(), sent_at=0, rebind=False
        )


async def test_login_without_a_usable_client_secret_still_commits(
    tmp_path: Path, clock: FakeClock
) -> None:
    rig = Rig(tmp_path, clock, google_style(clock.time), make_policy(google_cred()))
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono,
        rebind=False,
    )
    expected = set(secret_variants("fake-at-login")) | set(secret_variants("fake-rt-login"))
    assert set(result.grant.variants) == expected


# --- client_credentials, more ------------------------------------------------------------------


async def test_client_credentials_details(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = cc_rig(tmp_path, clock, secret="env:CC_SECRET")
    await rig.grant("svc")
    line = captured.events("oauth_refresh")[0]
    assert (line["token_source"], line["reason"], line["scope_status"]) == (
        None,
        "client_credentials",
        None,
    )
    assert rig.manager.status()[0]["meta"] is None


async def test_client_credentials_that_cannot_be_built(tmp_path: Path, clock: FakeClock) -> None:
    server = FakeAuthServer(clock.time, client_id="app-cc", client_secret="fake-cc-secret")
    cred = {
        "client_id": "app-cc",
        "client_secret": "env:CC_SECRET",
        "grant": "client_credentials",
        "extra_params": {"grant_type": "other"},
    }
    rig = Rig(tmp_path, clock, server, make_policy(cred, name="svc"), env={"CC_SECRET": "fake-x"})
    assert (await rig.refused("svc")).reason == "request"
    assert rig.calls == 0


async def test_client_credentials_with_an_unavailable_client_id(
    tmp_path: Path, clock: FakeClock
) -> None:
    server = FakeAuthServer(clock.time, client_id="app-cc", client_secret="fake-cc-secret")
    cred = {
        "client_id": "env:CC_ID",
        "client_secret": "env:CC_SECRET",
        "grant": "client_credentials",
    }
    rig = Rig(tmp_path, clock, server, make_policy(cred, name="svc"), env={"CC_SECRET": "fake-x"})
    assert (await rig.refused("svc")).reason == "client_id_unavailable"
    assert rig.calls == 0


async def test_a_client_id_from_the_store(tmp_path: Path, clock: FakeClock) -> None:
    server = FakeAuthServer(clock.time, client_id="app-stored", auth="none", rotate=True)
    pol = make_policy(spotify_cred(client_id="store:client-id"))
    rig = Rig(tmp_path, clock, server, pol)
    rig.store.put("client-id", "app-stored", oauth_binding(TOKEN_URL, [API]))
    rig.seed()
    await rig.grant()
    assert server.calls[0].params["client_id"] == "app-stored"


# --- review follow-ups: odd token endpoint numbers ---------------------------------------------


@pytest.mark.parametrize(
    "seconds",
    [10**12, 1e12, -(10**12), 2**53, 10**18, -1],
    ids=["1e12", "float_1e12", "minus_1e12", "2_53", "1e18", "minus_1"],
)
async def test_a_refresh_lifetime_no_date_can_show_never_stops_the_write(
    tmp_path: Path, clock: FakeClock, captured: Captured, seconds: float
) -> None:
    """I3, I4: a display field never stands between a successor and the store."""
    transport, _ = raising(
        ok_response(refresh_token="fake-rt-successor", refresh_token_expires_in=seconds)
    )
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    grant = await rig.grant()
    assert grant.token.reveal() == "fake-at-mock"
    assert rig.stored() == rig.on_disk() == "fake-rt-successor"
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["refresh_expires_at"] is None
    assert captured.events("oauth_refresh_error") == []


@pytest.mark.parametrize(
    ("seconds", "shown"),
    [
        (0, "2026-10-17T09:00:00Z"),
        (100 * 365 * 86400, "2126-09-23T09:00:00Z"),
        (100 * 365 * 86400 + 1, None),
    ],
)
async def test_the_refresh_lifetime_shown_in_meta_is_bounded(
    tmp_path: Path, clock: FakeClock, seconds: int, shown: str | None
) -> None:
    rig = spotify_rig(tmp_path, clock)
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=Minted(Secret("fake-at-login"), 3600, 3600, None, seconds),
        sent_at=clock.mono,
        rebind=False,
    )
    assert result.persisted is True
    assert rig.on_disk() == "fake-rt-login"
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["refresh_expires_at"] == shown


async def test_login_with_a_lifetime_no_date_can_show_still_stores(
    tmp_path: Path, clock: FakeClock
) -> None:
    """The code behind a login is spent: its tokens must be kept whatever else came back."""
    rig = spotify_rig(tmp_path, clock)
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=Minted(Secret("fake-at-login"), 3600, 3600, None, 10**12),
        sent_at=clock.mono,
        rebind=False,
    )
    assert result.persisted is True
    assert rig.on_disk() == "fake-rt-login"
    assert (await rig.grant()) is result.grant


@pytest.mark.parametrize("rotates", [False, True])
async def test_an_echoed_refresh_token_is_not_a_rotation(
    tmp_path: Path, clock: FakeClock, captured: Captured, rotates: bool
) -> None:
    """D.7: a refresh token equal to the one presented is no rotation."""
    spy = SpyStore(tmp_path, KEYS)
    presented: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        return ok_response(refresh_token=presented[0])

    pol = make_policy(spotify_cred(rotates=rotates))
    server = spotify_style(clock.time)
    rig = Rig(tmp_path, clock, server, pol, transport=httpx.MockTransport(handler), store=spy)
    presented.append(rig.seed())
    rig.store.update_meta("music-refresh", {"oauth": {"rotations": 3}})
    spy.events.clear()
    await rig.grant()
    assert spy.events == []
    assert rig.stored() == presented[0]
    assert captured.events("oauth_refresh")[0]["rotated"] is False
    assert captured.events("oauth_rotation_observed") == []
    assert len(captured.events("oauth_rotation_missing")) == (1 if rotates else 0)
    entry = rig.store.entry("music-refresh")
    assert entry is not None
    assert entry.meta is not None
    assert entry.meta["oauth"]["rotations"] == 3


# --- review follow-ups: reload, deadlines, cancellation ----------------------------------------


async def test_a_reload_keeps_the_slot_clean_when_the_old_refresh_fails(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """D.13: failures are cleared by a reload, and the refresh in flight can't bring one back."""
    rig = google_rig(tmp_path, clock)
    rig.seed()
    rig.server.client_secret = "fake-other-secret"
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    assert rig.manager.configure(make_policy(google_cred(refresh_skew=60)), {}) == ["music"]
    gate.set()
    with pytest.raises(OAuthUnavailable) as caught:
        await waiter
    assert caught.value.reason == "reloaded"
    status = rig.status()
    assert (status["state"], status["code"], status["failures"]) == ("idle", None, 0)
    assert captured.events("oauth_terminal") == []
    assert captured.events("oauth_refresh")[0]["code"] == OAUTH_CLIENT_REJECTED
    # The operator fixed the client: the next request tries.
    rig.server.gate = None
    rig.server.client_secret = GOOGLE_SECRET
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    assert rig.calls == 2


async def test_a_reload_keeps_the_slot_clean_after_an_internal_error(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    class Broken(SecretStore):
        def put(
            self, name: str, value: str, binding: Mapping[str, Any], *, meta: Any = KEEP
        ) -> None:
            raise RuntimeError("disk on fire")

    server = spotify_style(clock.time)
    store = Broken(tmp_path, KEYS)
    rig = Rig(tmp_path, clock, server, make_policy(spotify_cred()), store=store)
    SecretStore.put(store, "music-refresh", server.issue_grant(), oauth_binding(TOKEN_URL, [API]))
    gate = server.hold()
    waiter = asyncio.create_task(rig.grant())
    await server.arrived()
    rig.manager.configure(make_policy(spotify_cred(refresh_skew=60)), {})
    gate.set()
    with pytest.raises(OAuthUnavailable):
        await waiter
    assert captured.events("oauth_refresh_error")[0]["error_type"] == "RuntimeError"
    assert rig.status()["state"] == "idle"
    server.gate = None
    await rig.refused()
    assert rig.calls == 2


async def test_the_attempt_deadline_ends_a_call_that_never_answers(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Waiters have no timeout of their own, so each attempt has one (D.3, D.4)."""
    monkeypatch.setattr(tokens, "ATTEMPT_DEADLINE", 0.01)
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    rig.server.hold()  # never released
    refused = await rig.refused()
    # The deadline is a maybe-sent failure: one replay, then no_response.
    assert rig.calls == 2
    assert clock.sleeps == [1.0]
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "no_response")
    assert rig.manager._slots["music-refresh"].task is None


async def test_aclose_stops_waiting_after_the_drain_timeout(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(tokens, "DRAIN_TIMEOUT", 0.01)
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    writes.failing = True
    with pytest.raises(StoreWriteError):
        rig.store.put("other", "fake-other", oauth_binding(TOKEN_URL, [API]))
    writes.failing = False
    async with asyncio.timeout(5):
        await rig.manager.aclose()
    task = rig.manager._slots["music-refresh"].task
    assert task is not None
    assert not task.done()
    # The dirty store was saved even so.
    assert not rig.store.dirty
    gate.set()
    await waiter
    await rig.settle()


async def test_a_cancelled_refresh_task_frees_the_slot(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    gate = rig.server.hold()
    waiter = asyncio.create_task(rig.grant())
    await rig.server.arrived()
    task = rig.manager._slots["music-refresh"].task
    assert task is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert rig.manager._slots["music-refresh"].task is None
    gate.set()
    rig.server.gate = None
    grant = await rig.grant()
    assert rig.server.access_ok(grant.token.reveal())
    assert rig.calls == 2


# --- review follow-ups: the body cap -----------------------------------------------------------


def at_cap_body() -> bytes:
    body = json.dumps({"access_token": "fake-at-cap", "token_type": "Bearer"}).encode()
    padded = body[:-1] + b"," + b'"p":"' + b"x" * (65536 - len(body) - 7) + b'"}'
    assert len(padded) == 65536
    return padded


def streamed(chunks: list[bytes], pulled: list[int]) -> httpx.MockTransport:
    """Answers with ``chunks`` one at a time, counting how many were read."""

    def handler(request: httpx.Request) -> httpx.Response:
        async def body() -> AsyncIterator[bytes]:
            for chunk in chunks:
                pulled.append(len(chunk))
                yield chunk

        return httpx.Response(200, content=body(), headers={"content-type": "application/json"})

    return httpx.MockTransport(handler)


async def test_one_byte_over_the_cap_is_refused_and_reading_stops(
    tmp_path: Path, clock: FakeClock
) -> None:
    pulled: list[int] = []
    transport = streamed([at_cap_body()] + [b" "] * 1000, pulled)
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    first = rig.seed()
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (OAUTH_UNAVAILABLE, "unparseable_body")
    assert pulled == [65536, 1]
    assert rig.stored() == first


async def test_a_streamed_body_at_the_cap_is_parsed(tmp_path: Path, clock: FakeClock) -> None:
    pulled: list[int] = []
    body = at_cap_body()
    transport = streamed([body[:40000], body[40000:]], pulled)
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    assert (await rig.grant()).token.reveal() == "fake-at-cap"
    assert pulled == [40000, 25536]


async def test_a_long_body_is_not_read_to_the_end(tmp_path: Path, clock: FakeClock) -> None:
    pulled: list[int] = []
    transport = streamed([b"x" * 1024] * 1024, pulled)
    rig = Rig(
        tmp_path, clock, spotify_style(clock.time), make_policy(spotify_cred()), transport=transport
    )
    rig.seed()
    assert (await rig.refused()).reason == "unparseable_body"
    # 64 KiB is not past the cap; the 65th chunk is.
    assert len(pulled) == 65


# --- review follow-ups: scrubbing --------------------------------------------------------------


async def test_the_scrub_set_keeps_the_previous_token_after_a_401(
    tmp_path: Path, clock: FakeClock
) -> None:
    """D.11: the previous access token stays scrubbed though the 401 dropped it from the cache."""
    rig = spotify_rig(tmp_path, clock)
    rig.seed()
    first = await rig.grant()
    clock.advance(MIN_401_AGE)
    assert rig.manager.rejected("music", first) == "invalidated"
    second = await rig.grant()
    assert second.token.reveal() != first.token.reveal()
    assert set(secret_variants(first.token.reveal())) <= set(second.variants)
    # Only the one before: the token two refreshes back is gone.
    clock.advance(MIN_401_AGE)
    assert rig.manager.rejected("music", second) == "invalidated"
    third = await rig.grant()
    assert set(secret_variants(second.token.reveal())) <= set(third.variants)
    assert not set(secret_variants(first.token.reveal())) & set(third.variants)


async def test_login_with_a_client_secret_scrubs_it(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(),
        sent_at=clock.mono - 1,
        rebind=False,
    )
    variants = set(result.grant.variants)
    assert set(oauth_client_variants(GOOGLE_ID, GOOGLE_SECRET)) <= variants
    assert set(secret_variants("fake-rt-login")) <= variants
    assert set(secret_variants("fake-at-login")) <= variants
    # Expiry counts from the send, age from the commit.
    assert result.grant.minted_at == clock.mono
    assert result.grant.hard_expiry == clock.mono - 1 + 3600


# --- review follow-ups: health writes, shared names, seeds -------------------------------------


async def test_a_failed_health_write_keeps_the_outcome(
    tmp_path: Path, clock: FakeClock, writes: FailingWrites, captured: Captured
) -> None:
    rig = google_rig(tmp_path, clock)
    rig.seed()
    await rig.grant()
    writes.failing = True
    rig.server.revoke()
    clock.advance(3600)
    refused = await rig.refused()
    assert refused.code == OAUTH_RECONSENT_NEEDED
    failed = captured.events("oauth_persist_failed")
    assert [(f["slot"], f["level"]) for f in failed] == [("music-refresh", "error")]
    assert captured.events("oauth_refresh_error") == []
    assert captured.events("oauth_refresh")[-1]["code"] == OAUTH_RECONSENT_NEEDED
    assert rig.status()["state"] == "terminal"


async def test_replace_secret_of_a_stored_client_id(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    server = FakeAuthServer(clock.time, client_id="app-stored", auth="none", rotate=True)
    rig = Rig(tmp_path, clock, server, make_policy(spotify_cred(client_id="store:client-id")))
    rig.seed()
    assert (await rig.refused()).reason == "client_id_unavailable"
    assert rig.status()["state"] == "terminal"
    binding = await rig.manager.replace_secret("client-id", "app-stored")
    assert binding == oauth_binding(TOKEN_URL, [API])
    assert captured.events("oauth_cache_reset")[-1]["credential"] == "music"
    await rig.grant()
    assert rig.calls == 1
    assert server.calls[0].params["client_id"] == "app-stored"


def shared_secret_policy() -> Policy:
    """Two credentials with one client secret, each with its own route and refresh token."""
    routes = [
        {
            "name": name,
            "prefix": f"/{name}",
            "upstream": upstream,
            "credential": name,
            "callers": [{"placeholder": f"ph-{name}-direct-000001"}],
            "rules": [{"methods": ["GET"], "paths": ["/**"]}],
        }
        for name, upstream in (("music", API), ("cal", OTHER))
    ]
    credentials = {
        name: {"kind": "oauth2", "token_url": TOKEN_URL, **google_cred(refresh_token=ref)}
        for name, ref in (("music", "store:music-refresh"), ("cal", "store:cal-refresh"))
    }
    return Policy.model_validate({**BASE, "routes": routes, "credentials": credentials})


async def test_replace_secret_shared_by_two_credentials_clears_both(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    rig = Rig(tmp_path, clock, google_style(clock.time), shared_secret_policy())
    rig.put_client_secret()
    rig.seed("music-refresh", (API,))
    rig.seed("cal-refresh", (OTHER,))
    await rig.grant("music", API)
    await rig.grant("cal", OTHER)
    rig.server.client_secret = "fake-rotated-secret"
    clock.advance(3600)
    assert (await rig.refused("music", API)).code == OAUTH_CLIENT_REJECTED
    assert (await rig.refused("cal", OTHER)).code == OAUTH_CLIENT_REJECTED
    assert rig.calls == 4

    binding = await rig.manager.replace_secret("google-secret", "fake-rotated-secret")
    assert binding == oauth_binding(TOKEN_URL, [API, OTHER])
    assert rig.manager._cache == {}
    assert [s["state"] for s in rig.manager.status()] == ["idle", "idle"]
    resets = [e for e in captured.events("oauth_cache_reset") if e["reason"] == "secret_set"]
    assert [e["credential"] for e in resets] == ["cal", "music"]
    entry = rig.store.entry("google-secret")
    assert entry is not None
    # Two users: the meta names neither.
    assert entry.meta == {"oauth": {"source": "operator", "consented_at": None}}
    await rig.grant("music", API)
    await rig.grant("cal", OTHER)
    assert rig.calls == 6


async def test_a_changed_seed_that_fails_never_falls_back_to_the_live_slot(
    tmp_path: Path, clock: FakeClock
) -> None:
    """D.5: after a failed seed, the old live token is never presented, not even after reset."""
    server = spotify_style(clock.time)
    first_seed = server.issue_grant()
    live = server.issue_grant()
    pol = make_policy(spotify_cred(refresh_token="env:MUSIC_REFRESH", reseed="on-change"))
    rig = Rig(tmp_path, clock, server, pol, env={"MUSIC_REFRESH": "fake-rt-unknown-seed"})
    value = encode_envelope(Secret(live), seed_sha256(first_seed))
    rig.store.put(live_slot("music"), value.reveal(), oauth_binding(TOKEN_URL, [API]))
    refused = await rig.refused()
    assert refused.code == OAUTH_RECONSENT_NEEDED
    await rig.refused()
    assert rig.calls == 1
    assert rig.stored(live_slot("music")) == value.reveal()
    assert rig.manager.reset("music") is True
    assert (await rig.refused()).code == OAUTH_RECONSENT_NEEDED
    presented = [c.refresh_token for c in server.refresh_calls]
    assert presented == ["fake-rt-unknown-seed", "fake-rt-unknown-seed"]
    assert rig.stored(live_slot("music")) == value.reveal()


async def test_a_client_secret_bound_to_another_token_endpoint_is_unavailable(
    tmp_path: Path, clock: FakeClock, captured: Captured
) -> None:
    """I1 for the client secret: its binding names the one token endpoint it may go to."""
    rig = Rig(tmp_path, clock, google_style(clock.time), make_policy(google_cred()))
    other = oauth_binding("https://elsewhere.example/token", [API])
    rig.store.put("google-secret", GOOGLE_SECRET, other)
    rig.seed()
    refused = await rig.refused()
    assert (refused.code, refused.reason) == (CREDENTIAL_UNAVAILABLE, "client_secret_unavailable")
    assert rig.calls == 0
    assert GOOGLE_SECRET not in captured.text


# --- what login uses (design E) ----------------------------------------------------------------


async def test_the_policy_and_store_login_reads(tmp_path: Path, clock: FakeClock) -> None:
    store = SecretStore(tmp_path, KEYS)
    manager = TokenManager(store, httpx.AsyncClient())
    assert manager.store is store
    with pytest.raises(RuntimeError, match=r"^configure\(\) hasn't been called$"):
        _ = manager.policy
    rig = spotify_rig(tmp_path / "rig", clock)
    assert rig.manager.policy is rig.policy


async def test_client_for(tmp_path: Path, clock: FakeClock) -> None:
    rig = google_rig(tmp_path, clock)
    client = rig.manager.client_for("music")
    assert isinstance(client, Client)
    assert client.client_id == GOOGLE_ID
    assert client.secret is not None
    assert client.secret.reveal() == GOOGLE_SECRET
    assert rig.manager.client_for("nope") == Failure(
        "terminal", CREDENTIAL_UNAVAILABLE, "not_configured"
    )
    rig.store.delete("google-secret")
    assert rig.manager.client_for("music") == Failure(
        "terminal", CREDENTIAL_UNAVAILABLE, "client_secret_unavailable"
    )


async def test_reset_logs_its_reason(tmp_path: Path, clock: FakeClock, captured: Captured) -> None:
    rig = spotify_rig(tmp_path, clock)
    assert rig.manager.reset("music") is True
    assert rig.manager.reset("music", reason="login") is True
    assert rig.manager.reset("nope", reason="login") is False
    lines = [(e["credential"], e["reason"]) for e in captured.events("oauth_cache_reset")]
    assert lines == [("music", "reset"), ("music", "login")]


async def test_post_sends_with_the_deadline(tmp_path: Path, clock: FakeClock) -> None:
    timeouts: list[dict[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200, json={"ok": True}, headers={"retry-after": "7"})

    rig = Rig(
        tmp_path,
        clock,
        spotify_style(clock.time),
        make_policy(spotify_cred()),
        transport=httpx.MockTransport(handler),
    )
    request = TokenRequest(TOKEN_URL, (("accept", "application/json"),), b"x=1")
    answer = await rig.manager.post(request)
    assert (answer.status, answer.retry_after) == (200, "7")
    assert json.loads(answer.body) == {"ok": True}
    await rig.manager.post(request, deadline=7.5)
    assert timeouts == [
        {"connect": 5.0, "read": 20.0, "write": 20.0, "pool": 20.0},
        {"connect": 5.0, "read": 7.5, "write": 7.5, "pool": 7.5},
    ]


async def test_post_reads_the_attempt_deadline_when_called(
    tmp_path: Path, clock: FakeClock, monkeypatch: pytest.MonkeyPatch
) -> None:
    reads: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        reads.append(request.extensions["timeout"]["read"])
        return httpx.Response(200)

    rig = Rig(
        tmp_path,
        clock,
        spotify_style(clock.time),
        make_policy(spotify_cred()),
        transport=httpx.MockTransport(handler),
    )
    monkeypatch.setattr(tokens, "ATTEMPT_DEADLINE", 3.25)
    await rig.manager.post(TokenRequest(TOKEN_URL, (), b""))
    assert reads == [3.25]


async def test_post_gives_up_at_the_deadline(tmp_path: Path, clock: FakeClock) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(5)
        return httpx.Response(200)

    rig = Rig(
        tmp_path,
        clock,
        spotify_style(clock.time),
        make_policy(spotify_cred()),
        transport=httpx.MockTransport(handler),
    )
    request = TokenRequest(TOKEN_URL, (), b"")
    with pytest.raises(TimeoutError):
        await rig.manager.post(request, deadline=0.05)


async def test_a_login_commit_reports_what_it_stored(tmp_path: Path, clock: FakeClock) -> None:
    rig = spotify_rig(tmp_path, clock, grant_lifetime_days=2, scope="a b")
    result = await rig.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=minted(scope=None),
        sent_at=clock.mono,
        rebind=False,
    )
    assert result.granted_scopes == ("a", "b")
    assert result.refresh_expires_at == "2026-10-18T09:00:00Z"
    assert result.grant_expires_at == "2026-10-19T09:00:00Z"
    assert result.seed_present is False
    other = spotify_rig(tmp_path / "other", clock)
    result = await other.manager.commit_login(
        "music",
        refresh_token=Secret("fake-rt-login"),
        minted=Minted(Secret("fake-at-login"), 3600, 3600, ("x",), None),
        sent_at=clock.mono,
        rebind=False,
    )
    assert result.granted_scopes == ("x",)
    assert result.refresh_expires_at is None
    assert result.grant_expires_at is None


async def test_a_login_commit_says_whether_an_env_seed_is_set(
    tmp_path: Path, clock: FakeClock
) -> None:
    for directory, seed, present in (("a", "fake-rt-seed", True), ("b", None, False)):
        rig, _ = seeded_rig(tmp_path / directory, clock, seed)
        result = await rig.manager.commit_login(
            "music",
            refresh_token=Secret("fake-rt-login"),
            minted=minted(),
            sent_at=clock.mono,
            rebind=False,
        )
        assert result.seed_present is present
