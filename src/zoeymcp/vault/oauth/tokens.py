"""The token manager: access tokens on demand, one refresh at a time (design D.2-D.5).

Each credential has a slot: its refresh token's store entry, its live slot when it's seeded from
``env:``, or ``cc:<credential>`` for the client_credentials grant. A refresh runs as a task the
manager owns, and every caller waits on it through :func:`asyncio.shield`, so cancelling a caller
never cancels a refresh. At most one task runs per slot, and everything that writes a slot waits
for it first (I2, I5).

The commit after a token call never awaits. Any new refresh token is written to the store before
the access token from the same response is cached or returned (I3). If the write fails, the store
keeps the new token in memory, so the next refresh presents it (I4).

There is no copy of a refresh token outside the store, and no background refresh: a refresh
happens when a request needs a token. Clocks, ``sleep`` and the jitter are injected.

A token endpoint the address guard refuses (M7 design B.2) fails ``oauth_unavailable`` with the
reason ``address_refused``: nothing was sent, so there is no replay. The manager keeps every
guard refusal of the vault's route, token and revocation calls since start, for health (J).
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import random
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final, Literal

import httpx

from ...common.canonical import dumps_canonical
from ...common.policy.schema import OAuth2Credential, Policy, is_secret_ref, split_scope
from .. import logs
from ..bindings import VAULT_PREFIX, derive_binding, live_slot
from ..netclient import ADDRESS_REFUSED, AddressRefused
from ..request import oauth_client_variants, secret_variants
from ..store import Secret, SecretStore, SecretUnavailable, StoreWriteError, canonical_origin
from .protocol import (
    ATTEMPT_DEADLINE,
    CONNECT_TIMEOUT,
    CREDENTIAL_UNAVAILABLE,
    DRAIN_TIMEOUT,
    MAX_TOKEN_BODY,
    MIN_401_AGE,
    OAUTH_MISCONFIGURED,
    OAUTH_UNAVAILABLE,
    REPLAY_DELAY,
    Client,
    EnvelopeError,
    Failure,
    Minted,
    Outcome,
    RevocationMaterial,
    ScopeCheck,
    SlotState,
    TokenRequest,
    TokenResponse,
    TokenSource,
    backoff_delay,
    build_client_credentials,
    build_refresh,
    check_refresh_scopes,
    classify,
    decide_source,
    encode_envelope,
    parse_envelope,
    schedule,
    seed_sha256,
    transport_failure,
    valid_refresh_token,
)

# How often a healthy slot's last_ok is written to its clear meta.
META_OK_INTERVAL: Final = 86400.0
CC_PREFIX: Final = "cc:"
# An upstream said the access token lacks a scope (design D.10). Shown by status, never decides.
UPSTREAM_INSUFFICIENT_SCOPE: Final = "upstream_insufficient_scope"
# The longest refresh_token_expires_in shown in meta. Beyond it no date is shown: a token
# endpoint's number must never stop the write that saves a new refresh token.
MAX_REFRESH_EXPIRES_IN: Final = 100 * 365 * 86400

# The display fields carried from an entry's meta into its next write, with the types each may
# have. The meta is clear text anyone with the file can edit, so everything else is dropped.
_CARRIED: Final[Mapping[str, tuple[type, ...]]] = {
    "source": (str,),
    "consented_at": (str, type(None)),
    "rotations": (int,),
    "granted_scope": (str, type(None)),
    "refresh_expires_at": (str, type(None)),
    "last_ok": (str, type(None)),
}

# The request never left: presenting the same token again is safe. Every other failure may
# have reached the token endpoint, and gets the one replay.
PRE_SEND: Final = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.PoolTimeout,
    httpx.ProxyError,
    httpx.UnsupportedProtocol,
)

Trigger = Literal["expiry", "first_use", "upstream_401", "login"]
Rejection = Literal["reused_newer", "invalidated", "suppressed"]
Clock = Callable[[], float]
Sleep = Callable[[float], Awaitable[None]]
Uniform = Callable[[float, float], float]


class OAuthUnavailable(Exception):
    """No access token for this request. ``code`` is the stable code for the 502 body."""

    def __init__(self, code: str, reason: str, *, retry_after: float | None = None) -> None:
        self.code = code
        self.reason = reason
        self.retry_after = retry_after
        super().__init__(f"{code}: {reason}")


class BindingChanged(Exception):
    """Login would change the slot's binding, and ``rebind`` wasn't given."""

    reason = "binding_changed"

    def __init__(self, old: dict[str, Any], new: dict[str, Any]) -> None:
        self.old = old
        self.new = new
        super().__init__("the policy binds this grant differently; pass --rebind to accept")


@dataclass(frozen=True)
class Grant:
    """An access token and where it may go. Times are on the monotonic clock."""

    token: Secret
    serial: int
    minted_at: float
    refresh_at: float
    hard_expiry: float
    resources: frozenset[str]
    epoch: int
    # Every form of the access token, the previous one, the refresh token and the client secret.
    variants: tuple[bytes, ...] = field(repr=False)


@dataclass(frozen=True)
class LoginCommit:
    slot: str
    binding: dict[str, Any]
    persisted: bool
    consented_at: str
    grant: Grant
    # The scopes granted, or the requested ones when the response didn't say.
    granted_scopes: tuple[str, ...] = ()
    refresh_expires_at: str | None = None
    # consented_at plus grant_lifetime_days, when the policy sets it.
    grant_expires_at: str | None = None
    # An env seed is set, and the live slot now records it as superseded.
    seed_present: bool = False


@dataclass
class _Slot:
    task: asyncio.Task[None] | None = None
    failure: Failure | None = None
    retry_at: float = 0.0
    failures: int = 0
    # Set by an upstream 401, for the next refresh's log line.
    trigger: Trigger | None = None
    # The health last written to the slot's meta: "ok" or a code.
    meta_state: str | None = None
    meta_ok_at: float = -math.inf


@dataclass(frozen=True)
class _Config:
    name: str
    cred: OAuth2Credential
    slot: str
    resources: frozenset[str]
    fingerprint: str
    epoch: int


@dataclass(frozen=True)
class _Prepared:
    """Everything one refresh needs, read from the store before the task starts."""

    request: TokenRequest
    client: Client
    presented: Secret | None
    source: TokenSource | None
    reason: str
    resources: frozenset[str]
    # The entry holding the refresh token, and the binding a successor is written with.
    entry: str | None
    binding: dict[str, Any]
    envelope: bool
    seed_hash: str | None
    # The entry that carries the slot's clear meta.
    meta_entry: str | None


def slot_key(name: str, cred: OAuth2Credential) -> str:
    """The slot of a credential: its refresh token's entry, its live slot, or ``cc:<name>``."""
    if cred.grant == "client_credentials":
        return CC_PREFIX + name
    ref = cred.refresh_token or ""
    if ref.startswith("store:"):
        return ref.removeprefix("store:")
    return live_slot(name)


def fingerprint(cred: OAuth2Credential, origins: frozenset[str]) -> str:
    """Changes when the credential's settings or its route origins change."""
    document = {"credential": cred.model_dump(mode="json"), "origins": sorted(origins)}
    return hashlib.sha256(dumps_canonical(document)).hexdigest()


def _iso(wall: float) -> str:
    return (
        datetime.fromtimestamp(wall, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def _iso_after(wall: float, seconds: int) -> str | None:
    """The time ``seconds`` after ``wall``, or ``None`` for a lifetime that makes no sense."""
    if not 0 <= seconds <= MAX_REFRESH_EXPIRES_IN:
        return None
    return _iso(wall + seconds)


def _resources(binding: Mapping[str, Any]) -> frozenset[str]:
    oauth = binding.get("oauth")
    found = oauth.get("resources") if isinstance(oauth, dict) else None
    if not isinstance(found, list):
        return frozenset()
    return frozenset(r for r in found if isinstance(r, str))


def _checked(grant: Grant, origin: str) -> Grant:
    if origin not in grant.resources:
        raise OAuthUnavailable(CREDENTIAL_UNAVAILABLE, "route_not_bound")
    return grant


async def _read_capped(response: httpx.Response, limit: int) -> bytes:
    """The body, read until it ends or passes ``limit`` bytes: an oversized one shows as such."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size > limit:
            break
    return b"".join(chunks)


class TokenManager:
    """Access tokens for the policy's oauth2 credentials. Call :meth:`configure` first."""

    def __init__(
        self,
        store: SecretStore,
        client: httpx.AsyncClient,
        *,
        clock: Clock = time.monotonic,
        wall: Clock = time.time,
        sleep: Sleep = asyncio.sleep,
        uniform: Uniform = random.uniform,
    ) -> None:
        self._store = store
        self._client = client
        self._clock = clock
        self._wall = wall
        self._sleep = sleep
        self._uniform = uniform
        self._policy: Policy | None = None
        self._env: dict[str, Secret] = {}
        self._configs: dict[str, _Config] = {}
        self._epochs: dict[str, int] = {}
        self._slots: dict[str, _Slot] = {}
        self._cache: dict[str, Grant] = {}
        # The last access token minted per credential, for the next grant's scrub set. It stays
        # when the cache entry is dropped.
        self._previous: dict[str, Secret] = {}
        self._granted: dict[str, tuple[str, ...]] = {}
        # The last thing an upstream said about a credential's token, for status.
        self._upstream: dict[str, dict[str, Any]] = {}
        # The last resource_metadata a 401 named other than the credential's (M7 design J).
        self._resource_metadata: dict[str, dict[str, str]] = {}
        # The guard's refusals since start, by purpose and host:port (M7 design J).
        self._refused: dict[tuple[str, str, int], dict[str, Any]] = {}
        self._serial = 0
        self._closing = False

    @property
    def policy(self) -> Policy:
        """The policy of the last :meth:`configure`."""
        return self._require_policy()

    @property
    def store(self) -> SecretStore:
        return self._store

    # --- configuration -------------------------------------------------------------------------

    def configure(self, policy: Policy, env: Mapping[str, Secret]) -> list[str]:
        """Take a new policy (startup and reload). Synchronous: slots and tasks survive it.

        A credential whose settings or route origins changed gets a new epoch: its cached token
        is dropped and its failures are cleared. A task in flight still saves any new refresh
        token, but its access token isn't published. Returns the credentials that were reset.
        """
        self._policy = policy
        self._env = dict(env)
        configs: dict[str, _Config] = {}
        reset: list[str] = []
        for name, cred in policy.credentials.items():
            if not isinstance(cred, OAuth2Credential):
                continue
            origins = frozenset(
                canonical_origin(r.upstream)
                for r in policy.routes
                if r.credential == name and r.upstream is not None
            )
            digest = fingerprint(cred, origins)
            old = self._configs.get(name)
            if old is not None and old.fingerprint == digest:
                configs[name] = old
                continue
            epoch = self._epochs.get(name, 0) + 1
            self._epochs[name] = epoch
            key = slot_key(name, cred)
            configs[name] = _Config(name, cred, key, origins, digest, epoch)
            self._slots.setdefault(key, _Slot())
            if old is not None:
                reset.append(name)
                self._cache.pop(name, None)
                self._clear_failure(self._slots[key])
                logs.event("oauth_cache_reset", credential=name, reason="reload")
        for name in set(self._configs) - set(configs):
            self._cache.pop(name, None)
        self._configs = configs
        used = {cfg.slot for cfg in configs.values()}
        for key in list(self._slots):
            if key not in used and self._slots[key].task is None:
                del self._slots[key]
        return sorted(reset)

    # --- access tokens -------------------------------------------------------------------------

    async def grant_for(self, credential: str, route_upstream: str) -> Grant:
        """An access token for a request to ``route_upstream`` (design D.3).

        A still-valid cached token is served during backoff and terminal states until it expires.
        Otherwise this waits for the slot's refresh, starting one if it's allowed. Raises
        :class:`OAuthUnavailable`.
        """
        cfg = self._configs.get(credential)
        if cfg is None:
            raise OAuthUnavailable(CREDENTIAL_UNAVAILABLE, "not_configured")
        origin = canonical_origin(route_upstream)
        slot = self._slots[cfg.slot]
        # The cache only holds grants of the current epoch: configure drops the rest, and a
        # refresh that outlived its epoch doesn't publish.
        token = self._cache.get(credential)
        now = self._clock()
        if token is not None and now < token.refresh_at:
            return _checked(token, origin)
        if slot.task is None and not self._closing and self._allowed(slot, now):
            self._start(cfg, slot, origin, had_token=token is not None)
        if token is not None and now < token.hard_expiry:
            return _checked(token, origin)
        task = slot.task
        if task is None:
            raise self._unavailable(slot, now)
        await asyncio.shield(task)
        current = self._configs.get(credential)
        if current is None or current.epoch != cfg.epoch:
            raise OAuthUnavailable(OAUTH_UNAVAILABLE, "reloaded")
        token = self._cache.get(credential)
        now = self._clock()
        if token is not None and now < token.hard_expiry:
            return _checked(token, origin)
        raise self._unavailable(slot, now)

    def rejected(self, credential: str, used: Grant) -> Rejection:
        """The upstream answered 401 to ``used`` (design D.10).

        ``reused_newer``: the cache already holds another token (or none), so retry with it.
        ``suppressed``: the token is younger than ``MIN_401_AGE``; don't refresh.
        ``invalidated``: the token was dropped, so the next request refreshes.
        """
        current = self._cache.get(credential)
        if current is None or current.serial != used.serial:
            return "reused_newer"
        if self._clock() - current.minted_at < MIN_401_AGE:
            return "suppressed"
        del self._cache[credential]
        self._slots[self._configs[credential].slot].trigger = "upstream_401"
        return "invalidated"

    def note_upstream(self, credential: str, code: str, *, scopes: Sequence[str] = ()) -> None:
        """Record what an upstream said about the credential's token, for :meth:`status`, with
        the scope tokens its challenge asked for, already cleaned and bounded (M7 design D.5).

        Memory only: a caller can make the upstream say it on every request. A login clears it.
        """
        said: dict[str, Any] = {"code": code, "at": _iso(self._wall())}
        if scopes:
            said["scopes"] = list(scopes)
        self._upstream[credential] = said

    def note_resource_metadata(self, credential: str, url: str) -> None:
        """Record that a 401 on the credential's route named ``url`` as its protected-resource
        metadata, for :meth:`status` and health's ``resource_metadata_changed`` (M7 design J).

        Memory only, like :meth:`note_upstream`; a login doesn't clear it, since only onboarding
        again changes what the credential was registered for. Health compares it with the
        credential's ``resource_metadata`` of the running policy, so a reload that takes the new
        URL ends the finding.
        """
        self._resource_metadata[credential] = {"url": url, "at": _iso(self._wall())}

    def note_refused(self, purpose: str, host: str, port: int, verdict: str) -> None:
        """Record that the address guard refused a ``purpose`` call (``route``, ``token`` or
        ``revocation``) to ``host``:``port``, for :meth:`refused` and health's
        ``address_refused`` (M7 design J). Memory only, the latest of each kept: health judges it
        against the running policy, so a reload that lists the destination ends the finding."""
        key = (purpose, host, port)
        self._refused[key] = {
            "purpose": purpose,
            "host": host,
            "port": port,
            "verdict": verdict,
            "at": _iso(self._wall()),
        }

    def refused(self) -> list[dict[str, Any]]:
        """The guard's refusals since start, as :meth:`note_refused` kept them, in order."""
        return [self._refused[key] for key in sorted(self._refused)]

    # --- writers -------------------------------------------------------------------------------

    async def replace_secret(self, name: str, value: str) -> dict[str, Any]:
        """``secret set`` of a name an oauth2 credential uses. Returns the binding.

        Waits for the slots that use it, then writes with no await in between. Raises
        :class:`StoreWriteError` after clearing caches: memory holds the new value.
        """
        if name.startswith(VAULT_PREFIX):
            raise ValueError(f"{name!r} is managed by the vault; use zoeymcp login")
        users = await self._quiesce(lambda: self._users(name))
        if not users:
            raise ValueError(f"no oauth2 credential uses store:{name}")
        binding = derive_binding(self._require_policy(), name)
        meta: dict[str, Any] = {"source": "operator", "consented_at": None}
        if len(users) == 1:
            meta["credential"] = users[0].name
        try:
            self._store.put(name, value, binding, meta={"oauth": meta})
        finally:
            self._reset(users, "secret_set")
        return binding

    async def forget(
        self, name: str, *, take_revocation: bool = True
    ) -> tuple[bool, RevocationMaterial | None]:
        """``secret delete`` of an OAuth secret or a live slot. Returns whether it existed and,
        with ``take_revocation``, what revoking the refresh token it held needs (M7 design D.9).

        The material is read after the refreshes in flight and before the delete, with no await
        in between, so a rotation that completed meanwhile is the token revoked, not the one it
        superseded (CR-5). There is none for a client ID or secret, a credential without
        ``revocation_url``, or a slot the token endpoint's binding doesn't vouch for.
        """
        users = await self._quiesce(lambda: self._users(name))
        material = self._revocation(name, users) if take_revocation else None
        try:
            return self._store.delete(name), material
        finally:
            self._reset(users, "secret_delete")

    async def commit_login(
        self,
        credential: str,
        *,
        refresh_token: Secret,
        minted: Minted,
        sent_at: float,
        rebind: bool,
    ) -> LoginCommit:
        """Store a grant from a code exchange and cache its access token (design E.3).

        Raises :class:`BindingChanged` when the binding differs and ``rebind`` is false, and
        ``BindingError`` when the policy can't bind it. A failed store write still activates
        the grant in memory; the result says ``persisted: False``.
        """

        def users() -> list[_Config]:
            cfg = self._configs.get(credential)
            return [] if cfg is None else [cfg]

        found = await self._quiesce(users)
        if not found or found[0].cred.grant != "refresh_token":
            raise ValueError(f"{credential!r} is not an oauth2 credential with a refresh grant")
        cfg = found[0]
        if not valid_refresh_token(refresh_token.reveal()):
            raise ValueError("not a valid refresh token")
        binding = derive_binding(self._require_policy(), cfg.slot)
        existing = self._store.entry(cfg.slot)
        if existing is not None and existing.binding != binding and not rebind:
            raise BindingChanged(existing.binding, binding)
        wall = self._wall()
        consented_at = _iso(wall)
        value = refresh_token
        seed = None
        if self._seeded(cfg):
            seed = self._env.get(self._env_name(cfg))
            seed_hash = None if seed is None else seed_sha256(seed.reveal())
            value = encode_envelope(refresh_token, seed_hash)
        ok_fields = self._ok_fields(cfg, minted, wall, {})
        meta = {
            "credential": credential,
            "source": "login",
            "consented_at": consented_at,
            "rotations": 0,
            **ok_fields,
        }
        persisted = True
        try:
            self._store.put(cfg.slot, value.reveal(), binding, meta={"oauth": meta})
        except StoreWriteError as exc:
            persisted = False
            self._persist_failed(cfg, cfg.slot, exc)
        slot = self._slots[cfg.slot]
        self._clear_failure(slot)
        now = self._clock()
        slot.meta_state, slot.meta_ok_at = "ok", now
        client = self._client_for(cfg)
        grant = self._publish(
            cfg,
            minted,
            sent_at=sent_at,
            now=now,
            resources=_resources(binding),
            refresh_token=refresh_token,
            client=client if isinstance(client, Client) else None,
        )
        # No scope in the response: the requested ones. An empty one grants nothing (D.7).
        granted = minted.scope
        if granted is None:
            granted = tuple(split_scope(cfg.cred.scope, cfg.cred.scope_separator))
        self._granted[credential] = granted
        self._upstream.pop(credential, None)
        logs.event("oauth_cache_reset", credential=credential, reason="login")
        days = cfg.cred.grant_lifetime_days
        return LoginCommit(
            cfg.slot,
            binding,
            persisted,
            consented_at,
            grant,
            granted_scopes=granted,
            refresh_expires_at=ok_fields["refresh_expires_at"],
            grant_expires_at=None if days is None else _iso(wall + days * 86400),
            seed_present=seed is not None,
        )

    def reset(self, credential: str, *, reason: str = "reset") -> bool:
        """``oauth reset``: clear the failure state, so the next request tries once.

        A client_credentials login that worked does the same, with ``reason`` ``login``.
        """
        cfg = self._configs.get(credential)
        if cfg is None:
            return False
        self._clear_failure(self._slots[cfg.slot])
        logs.event("oauth_cache_reset", credential=credential, reason=reason)
        return True

    def client_for(self, credential: str) -> Client | Failure:
        """The client ID and secret ``credential``'s token requests send (login uses them).

        A secret from the store must be bound to the credential's token endpoint.
        """
        cfg = self._configs.get(credential)
        if cfg is None:
            return Failure("terminal", CREDENTIAL_UNAVAILABLE, "not_configured")
        return self._client_for(cfg)

    # --- health and shutdown -------------------------------------------------------------------

    def status(self) -> list[dict[str, Any]]:
        """Per credential: state, code, timings and the slot's clear meta. Never a value."""
        now = self._clock()
        result = []
        for name, cfg in sorted(self._configs.items()):
            slot = self._slots[cfg.slot]
            live = self._cache.get(name)
            failure = slot.failure
            state: str
            if failure is not None:
                state = failure.kind
            else:
                state = "ok" if live is not None and now < live.hard_expiry else "idle"
            retry_in = None
            if failure is not None and failure.kind == "backoff":
                retry_in = max(0.0, slot.retry_at - now)
            expires_in = None
            if live is not None and now < live.hard_expiry:
                expires_in = live.hard_expiry - now
            meta_entry = self._meta_entry(cfg)
            entry = self._store.entry(meta_entry) if meta_entry is not None else None
            meta = entry.meta.get("oauth") if entry is not None and entry.meta else None
            result.append(
                {
                    "credential": name,
                    "grant": cfg.cred.grant,
                    "slot": cfg.slot,
                    "state": state,
                    "refreshing": slot.task is not None,
                    "code": failure.code if failure is not None else None,
                    "reason": failure.reason if failure is not None else None,
                    "error": failure.error if failure is not None else None,
                    "failures": slot.failures,
                    "retry_in": retry_in,
                    "access_expires_in": expires_in,
                    "persisted": not self._store.dirty,
                    "meta": meta if isinstance(meta, dict) else None,
                    "upstream": self._upstream.get(name),
                    "resource_metadata": self._resource_metadata.get(name),
                }
            )
        return result

    async def aclose(self) -> None:
        """Wait up to ``DRAIN_TIMEOUT`` for refreshes in flight, then save a dirty store."""
        self._closing = True
        tasks = [slot.task for slot in self._slots.values() if slot.task is not None]
        if tasks:
            await asyncio.wait(tasks, timeout=DRAIN_TIMEOUT)
        if self._store.dirty:
            self._flush()

    # --- the refresh ---------------------------------------------------------------------------

    def _allowed(self, slot: _Slot, now: float) -> bool:
        failure = slot.failure
        if failure is None:
            return True
        return failure.kind == "backoff" and now >= slot.retry_at

    def _unavailable(self, slot: _Slot, now: float) -> OAuthUnavailable:
        failure = slot.failure
        if failure is None:
            return OAuthUnavailable(OAUTH_UNAVAILABLE, "no_grant")
        retry_after = max(0.0, slot.retry_at - now) if failure.kind == "backoff" else None
        return OAuthUnavailable(failure.code, failure.reason, retry_after=retry_after)

    def _start(self, cfg: _Config, slot: _Slot, origin: str, *, had_token: bool) -> None:
        """Read what the refresh needs and start its task. Synchronous, like every writer."""
        if self._store.dirty:
            self._flush()
        trigger: Trigger = slot.trigger or ("expiry" if had_token else "first_use")
        prepared = self._prepare(cfg, origin)
        slot.trigger = None
        if isinstance(prepared, Failure):
            # Nothing was sent: no token, a refused slot, or a request that can't be built.
            self._fail(cfg, slot, prepared, self._clock())
            self._log_refresh(
                cfg,
                trigger=trigger,
                source=None,
                reason=prepared.reason,
                attempts=0,
                replayed=False,
                outcome=Outcome(None, failure=prepared),
                started=self._clock(),
            )
            return
        slot.task = asyncio.get_running_loop().create_task(
            self._run(cfg, slot, prepared, trigger), name=f"oauth-refresh:{cfg.name}"
        )

    def _prepare(self, cfg: _Config, origin: str) -> _Prepared | Failure:
        """Decide the token to present and build the request (design D.4, D.5).

        A route whose origin the grant isn't bound to is refused here, for that caller only.
        """
        cred = cfg.cred
        if cred.grant == "client_credentials":
            return self._prepare_client_credentials(cfg, origin)
        if cred.refresh_token is None:
            return Failure("terminal", CREDENTIAL_UNAVAILABLE, "no_token")
        seeded = self._seeded(cfg)
        seed = self._env.get(self._env_name(cfg)) if seeded else None
        state, value, binding = self._read_slot(cfg)
        live_hash: str | None = None
        presented: Secret | None = value
        if seeded and value is not None:
            try:
                envelope = parse_envelope(value)
            except EnvelopeError:
                # decide_source refuses an unusable slot, so nothing of it is presented.
                state = "unusable"
            else:
                presented, live_hash = envelope.rt, envelope.seed_sha256
        decision = decide_source(
            cred,
            slot=state,
            live_seed_sha256=live_hash,
            seed=seed.reveal() if seed is not None else None,
        )
        if decision.source is None:
            return Failure("terminal", CREDENTIAL_UNAVAILABLE, decision.reason)
        seed_hash = live_hash
        if decision.source == "seed":
            assert seed is not None  # noqa: S101 - decide_source picks the seed only when set
            if not valid_refresh_token(seed.reveal()):
                return Failure("terminal", CREDENTIAL_UNAVAILABLE, "seed_unusable")
            try:
                binding = derive_binding(self._require_policy(), cfg.slot)
            except ValueError:
                return Failure("terminal", CREDENTIAL_UNAVAILABLE, "no_route")
            presented, seed_hash = seed, seed_sha256(seed.reveal())
        # Set for any source: by the slot, or by the seed above.
        assert presented is not None  # noqa: S101
        assert binding is not None  # noqa: S101
        resources = _resources(binding)
        if origin not in resources:
            raise OAuthUnavailable(CREDENTIAL_UNAVAILABLE, "route_not_bound")
        client = self._client_for(cfg)
        if isinstance(client, Failure):
            return client
        try:
            request = build_refresh(cred, client, presented)
        except ValueError:
            return Failure("terminal", OAUTH_MISCONFIGURED, "request")
        return _Prepared(
            request=request,
            client=client,
            presented=presented,
            source=decision.source,
            reason=decision.reason,
            resources=resources,
            entry=cfg.slot,
            binding=binding,
            envelope=seeded,
            seed_hash=seed_hash,
            meta_entry=cfg.slot,
        )

    def _prepare_client_credentials(self, cfg: _Config, origin: str) -> _Prepared | Failure:
        """The client secret is the grant's anchor: its binding bounds the access tokens."""
        cred = cfg.cred
        resources = cfg.resources
        ref = cred.client_secret or ""
        if ref.startswith("store:"):
            try:
                _, binding = self._store.get_for_oauth(
                    ref.removeprefix("store:"), token_url=cred.token_url
                )
            except SecretUnavailable:
                return Failure("terminal", CREDENTIAL_UNAVAILABLE, "client_secret_unavailable")
            resources = _resources(binding)
        if origin not in resources:
            raise OAuthUnavailable(CREDENTIAL_UNAVAILABLE, "route_not_bound")
        client = self._client_for(cfg)
        if isinstance(client, Failure):
            return client
        try:
            request = build_client_credentials(cred, client)
        except ValueError:
            return Failure("terminal", OAUTH_MISCONFIGURED, "request")
        return _Prepared(
            request=request,
            client=client,
            presented=None,
            source=None,
            reason="client_credentials",
            resources=resources,
            entry=None,
            binding={},
            envelope=False,
            seed_hash=None,
            meta_entry=self._meta_entry(cfg),
        )

    def _read_slot(self, cfg: _Config) -> tuple[SlotState, Secret | None, dict[str, Any] | None]:
        """The slot's entry, checked against the token endpoint (the binding authenticates it)."""
        if self._store.entry(cfg.slot) is None:
            return "absent", None, None
        try:
            value, binding = self._store.get_for_oauth(cfg.slot, token_url=cfg.cred.token_url)
        except SecretUnavailable:
            return "unusable", None, None
        return "usable", value, binding

    def _client_for(self, cfg: _Config) -> Client | Failure:
        cred = cfg.cred
        client_id = cred.client_id
        if is_secret_ref(client_id):
            resolved = self._resolve(cfg, client_id)
            if resolved is None:
                return Failure("terminal", CREDENTIAL_UNAVAILABLE, "client_id_unavailable")
            client_id = resolved.reveal()
        secret = None
        if cred.client_secret is not None:
            secret = self._resolve(cfg, cred.client_secret)
            if secret is None:
                return Failure("terminal", CREDENTIAL_UNAVAILABLE, "client_secret_unavailable")
        return Client(client_id, secret)

    def _resolve(self, cfg: _Config, ref: str) -> Secret | None:
        if ref.startswith("env:"):
            return self._env.get(ref.removeprefix("env:"))
        try:
            value, _ = self._store.get_for_oauth(
                ref.removeprefix("store:"), token_url=cfg.cred.token_url
            )
        except SecretUnavailable:
            return None
        return value

    async def _run(self, cfg: _Config, slot: _Slot, prep: _Prepared, trigger: Trigger) -> None:
        """The refresh task. It never raises: the outcome goes to the cache or the slot."""
        started = self._clock()
        try:
            outcome, attempts, replayed, sent_at = await self._call(cfg, prep)
            scopes = self._commit(cfg, slot, prep, outcome, sent_at=sent_at)
            self._log_refresh(
                cfg,
                trigger=trigger,
                source=prep.source,
                reason=prep.reason,
                attempts=attempts,
                replayed=replayed,
                outcome=outcome,
                started=started,
                scopes=scopes,
            )
        except Exception as exc:
            if self._current(cfg):
                failure = Failure("backoff", OAUTH_UNAVAILABLE, "internal_error")
                self._fail(cfg, slot, failure, self._clock())
            logs.event("oauth_refresh_error", credential=cfg.name, error_type=type(exc).__name__)
        finally:
            slot.task = None

    async def _call(self, cfg: _Config, prep: _Prepared) -> tuple[Outcome, int, bool, float]:
        """The token call, with one replay after an ambiguous failure (I6).

        Returns the outcome, the number of attempts, whether the last one was a replay, and when
        it was sent.
        """
        sent_at = self._clock()
        try:
            response = await self.post(prep.request)
        except AddressRefused:
            return transport_failure(ADDRESS_REFUSED), 1, False, sent_at
        except PRE_SEND:
            return transport_failure("pre_send"), 1, False, sent_at
        except Exception:
            response = None
        if response is not None:
            return self._classify(cfg, prep, response, replayed=False), 1, False, sent_at
        await self._sleep(REPLAY_DELAY)
        sent_at = self._clock()
        try:
            response = await self.post(prep.request)
        except Exception:
            return transport_failure("no_response"), 2, True, sent_at
        return self._classify(cfg, prep, response, replayed=True), 2, True, sent_at

    async def post(self, request: TokenRequest, *, deadline: float | None = None) -> TokenResponse:
        """One POST through the token client, within ``deadline`` seconds (login uses it too).

        The default is ``ATTEMPT_DEADLINE``, read at call time. Redirects are never followed;
        the body is read until it passes the cap. A refusal by the address guard is logged and
        kept (:meth:`note_refused`), then raised: nothing was sent.
        """
        if deadline is None:
            deadline = ATTEMPT_DEADLINE
        async with asyncio.timeout(deadline):
            outgoing = self._client.build_request(
                "POST",
                request.url,
                headers=list(request.headers),
                content=request.body,
                timeout=httpx.Timeout(deadline, connect=CONNECT_TIMEOUT),
            )
            try:
                response = await self._client.send(outgoing, stream=True, follow_redirects=False)
            except AddressRefused as exc:
                verdict = exc.verdict.reason
                logs.event(
                    "address_refused",
                    purpose="token",
                    host=exc.host,
                    port=exc.port,
                    verdict=verdict,
                )
                self.note_refused("token", exc.host, exc.port, verdict)
                raise
            try:
                body = await _read_capped(response, MAX_TOKEN_BODY)
            finally:
                await response.aclose()
        return TokenResponse(
            response.status_code,
            body,
            response.headers.get("content-type"),
            response.headers.get("retry-after"),
        )

    def _classify(
        self, cfg: _Config, prep: _Prepared, response: TokenResponse, *, replayed: bool
    ) -> Outcome:
        return classify(
            response,
            cred=cfg.cred,
            grant=cfg.cred.grant,
            presented=prep.presented,
            replayed=replayed,
            now=self._wall(),
        )

    def _commit(
        self, cfg: _Config, slot: _Slot, prep: _Prepared, outcome: Outcome, *, sent_at: float
    ) -> ScopeCheck | None:
        """Save any successor, then publish or record the failure. Never awaits (I3)."""
        now = self._clock()
        wall = self._wall()
        minted = outcome.minted
        successor = outcome.new_refresh_token
        current = prep.presented
        scopes = None
        wrote_meta = False
        promote = prep.source == "seed" and minted is not None
        if prep.entry is not None and (successor is not None or promote):
            current = successor or prep.presented
            assert current is not None  # noqa: S101 - a refresh grant always presents one
            self._save(cfg, prep, current, outcome, wall)
            wrote_meta = True
        if successor is not None and not cfg.cred.rotates:
            logs.event("oauth_rotation_observed", credential=cfg.name, slot=cfg.slot)
        if minted is not None and successor is None and cfg.cred.rotates:
            logs.event("oauth_rotation_missing", credential=cfg.name, slot=cfg.slot)

        if minted is not None:
            self._publish(
                cfg,
                minted,
                sent_at=sent_at,
                now=now,
                resources=prep.resources,
                refresh_token=current,
                client=prep.client,
            )
            self._clear_failure(slot)
            scopes = self._check_scopes(cfg, minted)
            state = "ok"
        else:
            assert outcome.failure is not None  # noqa: S101 - an outcome has one or the other
            # After a reload changed the credential, the failure belongs to the old settings:
            # the slot keeps the clean state the reload gave it (D.13).
            if self._current(cfg):
                self._fail(cfg, slot, outcome.failure, now)
            state = outcome.failure.code
        self._note_health(cfg, slot, prep, outcome, state, now=now, wall=wall, wrote=wrote_meta)
        return scopes

    def _save(
        self, cfg: _Config, prep: _Prepared, token: Secret, outcome: Outcome, wall: float
    ) -> None:
        """Write the refresh token now current, with the binding the slot keeps or gets."""
        assert prep.entry is not None  # noqa: S101 - only refresh grants save
        value = encode_envelope(token, prep.seed_hash) if prep.envelope else token
        base = {} if prep.source == "seed" else self._oauth_meta(prep.entry)
        rotated = outcome.new_refresh_token is not None
        meta: dict[str, Any] = {**base, "credential": cfg.name}
        if prep.source == "seed":
            meta.update(source="seed", consented_at=None, rotations=1 if rotated else 0)
        else:
            meta.update(source="rotation", rotations=base.get("rotations", 0) + 1)
        meta.setdefault("consented_at", None)
        if outcome.minted is not None:
            meta.update(self._ok_fields(cfg, outcome.minted, wall, base))
        elif outcome.failure is not None:
            meta["last_error"] = self._error_fields(outcome.failure, wall)
        try:
            self._store.put(prep.entry, value.reveal(), prep.binding, meta={"oauth": meta})
        except StoreWriteError as exc:
            # Memory holds it: the next refresh presents it, and a later write saves it.
            self._persist_failed(cfg, prep.entry, exc)
        if prep.source == "seed":
            logs.event("oauth_seed_promoted", credential=cfg.name, slot=prep.entry)

    def _publish(
        self,
        cfg: _Config,
        minted: Minted,
        *,
        sent_at: float,
        now: float,
        resources: frozenset[str],
        refresh_token: Secret | None,
        client: Client | None,
    ) -> Grant:
        """Build the grant, and cache it only if the credential wasn't reloaded meanwhile."""
        expiry = schedule(sent_at, minted.lifetime, cfg.cred.refresh_skew)
        previous = self._previous.get(cfg.name)
        variants = set(secret_variants(minted.access_token.reveal()))
        if previous is not None:
            variants.update(secret_variants(previous.reveal()))
        if refresh_token is not None:
            variants.update(secret_variants(refresh_token.reveal()))
        if client is not None and client.secret is not None:
            variants.update(oauth_client_variants(client.client_id, client.secret.reveal()))
        self._serial += 1
        grant = Grant(
            token=minted.access_token,
            serial=self._serial,
            minted_at=now,
            refresh_at=expiry.refresh_at,
            hard_expiry=expiry.hard_expiry,
            resources=resources,
            epoch=cfg.epoch,
            variants=tuple(sorted(variants, key=len, reverse=True)),
        )
        if self._current(cfg):
            self._cache[cfg.name] = grant
            self._previous[cfg.name] = minted.access_token
        return grant

    def _current(self, cfg: _Config) -> bool:
        """No reload has changed or removed the credential since ``cfg`` was read."""
        current = self._configs.get(cfg.name)
        return current is not None and current.epoch == cfg.epoch

    def _check_scopes(self, cfg: _Config, minted: Minted) -> ScopeCheck | None:
        """Compare a refresh's granted scopes with the last ones (design D.8). Never blocks."""
        if minted.scope is None:
            return None
        previous = self._granted.get(cfg.name, ())
        check = check_refresh_scopes(minted.scope, previous, cfg.cred.effective_expected_scopes)
        if check.missing:
            logs.event(
                "oauth_scope_narrowed",
                credential=cfg.name,
                scopes=list(check.missing),
                at="refresh",
            )
        if check.unexpected:
            logs.event(
                "oauth_scope_unexpected",
                credential=cfg.name,
                scopes=list(check.unexpected),
                at="refresh",
            )
        self._granted[cfg.name] = minted.scope
        return check

    def _fail(self, cfg: _Config, slot: _Slot, failure: Failure, now: float) -> None:
        """Record a failure: a terminal one stops token calls, a transient one backs off."""
        slot.failures += 1
        if failure.kind == "backoff":
            delay = backoff_delay(
                slot.failures, retry_after=failure.retry_after, uniform=self._uniform
            )
            slot.retry_at = now + delay
            logs.event(
                "oauth_backoff",
                credential=cfg.name,
                failures=slot.failures,
                retry_in=round(delay, 3),
                retry_after=failure.retry_after,
            )
        else:
            # Logged once per transition: a terminal state makes no more attempts until cleared.
            logs.event("oauth_terminal", credential=cfg.name, code=failure.code)
        slot.failure = failure

    @staticmethod
    def _clear_failure(slot: _Slot) -> None:
        slot.failure = None
        slot.failures = 0
        slot.retry_at = 0.0

    def _reset(self, users: list[_Config], reason: str) -> None:
        for cfg in users:
            self._cache.pop(cfg.name, None)
            self._clear_failure(self._slots[cfg.slot])
            logs.event("oauth_cache_reset", credential=cfg.name, reason=reason)

    async def _quiesce(self, select: Callable[[], list[_Config]]) -> list[_Config]:
        """Wait until no slot of the selected credentials has a refresh in flight.

        The caller then acts with no await in between, so no refresh can start meanwhile.
        """
        while True:
            users = select()
            tasks = [t for cfg in users if (t := self._slots[cfg.slot].task) is not None]
            if not tasks:
                return users
            # This never cancels them. Another refresh may start meanwhile, so look again.
            await asyncio.wait(tasks)

    def _revocation(self, name: str, users: list[_Config]) -> RevocationMaterial | None:
        """The material to revoke the refresh token in slot ``name``: the first credential that
        keeps its grant there and names a ``revocation_url``."""
        for cfg in users:
            url = cfg.cred.revocation_url
            # A client_credentials slot is cc:<name>, which no secret's name can be.
            if cfg.slot != name or url is None:
                continue
            state, value, binding = self._read_slot(cfg)
            if state != "usable":
                return None
            assert value is not None  # noqa: S101 - a usable slot has a value and a binding
            assert binding is not None  # noqa: S101
            if self._seeded(cfg):
                try:
                    value = parse_envelope(value).rt
                except EnvelopeError:
                    return None
            client = self._client_for(cfg)
            if isinstance(client, Failure):
                return None
            return RevocationMaterial(
                credential=cfg.name,
                url=url,
                token_origin=binding["oauth"]["token"],
                auth=cfg.cred.effective_client_auth,
                client=client,
                refresh_token=value,
            )
        return None

    def _users(self, name: str) -> list[_Config]:
        """The credentials whose slot is ``name`` or that reference ``store:<name>``."""
        ref = f"store:{name}"
        return [
            cfg
            for _, cfg in sorted(self._configs.items())
            if cfg.slot == name
            # A store: refresh token is the slot itself.
            or ref in (cfg.cred.client_id, cfg.cred.client_secret)
        ]

    # --- health --------------------------------------------------------------------------------

    def _note_health(
        self,
        cfg: _Config,
        slot: _Slot,
        prep: _Prepared,
        outcome: Outcome,
        state: str,
        *,
        now: float,
        wall: float,
        wrote: bool,
    ) -> None:
        """Write the slot's meta on a change of state, and ``last_ok`` at most once a day."""
        due = state != slot.meta_state or (
            state == "ok" and now - slot.meta_ok_at >= META_OK_INTERVAL
        )
        if wrote:
            due = False
        elif due and prep.meta_entry is not None:
            base = self._oauth_meta(prep.meta_entry)
            meta: dict[str, Any] = {**base, "credential": cfg.name}
            if outcome.minted is not None:
                meta.update(self._ok_fields(cfg, outcome.minted, wall, base))
            elif outcome.failure is not None:
                meta["last_error"] = self._error_fields(outcome.failure, wall)
            try:
                self._store.update_meta(prep.meta_entry, {"oauth": meta})
            except StoreWriteError as exc:
                self._persist_failed(cfg, prep.meta_entry, exc)
        if wrote or due:
            slot.meta_state = state
            if state == "ok":
                slot.meta_ok_at = now

    def _ok_fields(
        self, cfg: _Config, minted: Minted, wall: float, base: Mapping[str, Any]
    ) -> dict[str, Any]:
        fields: dict[str, Any] = {"last_ok": _iso(wall), "last_error": None}
        if minted.scope is not None:
            fields["granted_scope"] = cfg.cred.scope_separator.join(minted.scope)
        else:
            fields["granted_scope"] = base.get("granted_scope")
        if minted.refresh_expires_in is not None:
            fields["refresh_expires_at"] = _iso_after(wall, minted.refresh_expires_in)
        else:
            fields["refresh_expires_at"] = base.get("refresh_expires_at")
        return fields

    @staticmethod
    def _error_fields(failure: Failure, wall: float) -> dict[str, Any]:
        return {"code": failure.code, "error": failure.error, "at": _iso(wall)}

    def _oauth_meta(self, name: str) -> dict[str, Any]:
        """The display fields of the entry's ``meta.oauth`` to carry forward. Never decides.

        Only known fields of the right type are kept, so a tampered meta can't make the store
        refuse the write that saves a new refresh token.
        """
        entry = self._store.entry(name)
        found = entry.meta.get("oauth") if entry is not None and entry.meta else None
        if not isinstance(found, dict):
            return {}
        return {
            key: value
            for key, value in found.items()
            if key in _CARRIED and type(value) in _CARRIED[key]
        }

    def _meta_entry(self, cfg: _Config) -> str | None:
        if cfg.cred.grant == "refresh_token":
            return cfg.slot
        ref = cfg.cred.client_secret or ""
        return ref.removeprefix("store:") if ref.startswith("store:") else None

    # --- helpers -------------------------------------------------------------------------------

    @staticmethod
    def _seeded(cfg: _Config) -> bool:
        return (cfg.cred.refresh_token or "").startswith("env:")

    @staticmethod
    def _env_name(cfg: _Config) -> str:
        return (cfg.cred.refresh_token or "").removeprefix("env:")

    def _require_policy(self) -> Policy:
        if self._policy is None:
            raise RuntimeError("configure() hasn't been called")
        return self._policy

    def _flush(self) -> None:
        try:
            self._store.flush()
        except StoreWriteError as exc:
            logs.event(
                "oauth_persist_failed", slot=None, error_type=type(exc).__name__, level="critical"
            )
        else:
            logs.event("oauth_persist_recovered", slot=None)

    def _persist_failed(self, cfg: _Config, entry: str, exc: StoreWriteError) -> None:
        logs.event(
            "oauth_persist_failed",
            credential=cfg.name,
            slot=entry,
            error_type=type(exc).__name__,
            level="critical" if cfg.cred.rotates else "error",
        )

    def _log_refresh(
        self,
        cfg: _Config,
        *,
        trigger: Trigger,
        source: TokenSource | None,
        reason: str,
        attempts: int,
        replayed: bool,
        outcome: Outcome,
        started: float,
        scopes: ScopeCheck | None = None,
    ) -> None:
        minted, failure = outcome.minted, outcome.failure
        logs.event(
            "oauth_refresh",
            credential=cfg.name,
            slot=cfg.slot,
            grant=cfg.cred.grant,
            trigger=trigger,
            token_source=source,
            reason=reason,
            attempt=attempts,
            replayed=replayed,
            http_status=outcome.status,
            outcome="ok" if minted is not None else (failure.kind if failure else None),
            code=failure.code if failure is not None else None,
            error=failure.error if failure is not None else None,
            error_subtype=failure.subtype if failure is not None else None,
            failure_reason=failure.reason if failure is not None else None,
            rotated=outcome.new_refresh_token is not None,
            rotates=cfg.cred.rotates,
            expires_in=minted.expires_in if minted is not None else None,
            lifetime=minted.lifetime if minted is not None else None,
            lifetime_clamped=minted is not None and "expires_in_clamped" in minted.notes,
            skew=min(cfg.cred.refresh_skew, minted.lifetime // 2) if minted is not None else None,
            scope_status=scopes.status if scopes is not None else None,
            notes=list(minted.notes) if minted is not None else [],
            duration_ms=round((self._clock() - started) * 1000, 1),
        )
