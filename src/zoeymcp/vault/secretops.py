"""Carrying out a secret plan (M5 design G): the store and token-manager writes, and their logs.

The I/O half of :mod:`.secretplan`, apart so mutation testing covers only the decisions. A
secret an oauth2 credential uses is written and deleted through the token manager, which first
waits for any refresh of that slot (design D.12). If the store can't write its file, the change
is kept in memory and the answer is ``not_written`` (B.4). An onboarding's client secret (an
:class:`~.secretplan.OnboardPutPlan`, M7 design D.7) is written by the store with its plan's
``meta``; nothing reads that ``meta`` to refuse or inject. A re-registration that fails after
its write puts the entry it replaced back as it was (:func:`restore`).

A delete of a refresh token's slot whose credential names a ``revocation_url`` revokes the token
it held once the delete has committed (M7 design D.9, X18): best effort, one request, at most
:data:`REVOKE_TIMEOUT` seconds, no redirect, in a task of the :class:`Revoker`, so the delete's
answer never waits for it. Its client is guarded (``netclient``) with the running policy's
``egress_private`` as its exceptions (TI-11). Nothing is revoked on a replace, a re-login or a
reset (D-157), nor for a client secret.

``secret_set`` and ``secret_deleted`` say which interface asked, in ``via``; ``oauth_revoked``
gives a revocation's outcome (``ok``, ``refused``, ``failed`` or ``timeout``) and status, never
the token or the body.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any, Final, Literal

import anyio
import httpx

from . import logs
from .bindings import BindingError
from .netclient import AddressRefused
from .oauth.protocol import RevocationMaterial, build_revocation
from .oauth.tokens import TokenManager
from .secretplan import (
    NOT_FOUND,
    NOT_WRITTEN_REFUSAL,
    DeletePlan,
    OnboardPutPlan,
    PutPlan,
    SecretRefusal,
    binding_refusal,
)
from .store import KEEP, EntryMeta, Secret, SecretStore, StoreWriteError

Via = Literal["socket", "portal"]
# What a delete's answer says of revocation (M.1): a task was started, or nothing is sent.
Revocation = Literal["requested", "none"]
Outcome = Literal["ok", "refused", "failed", "timeout"]

# One revocation's limit, in seconds (M.6).
REVOKE_TIMEOUT: Final = 10.0
# The most of a revocation's answer read, only to count it; nothing of it is kept.
_ANSWER_MAX: Final = 64 * 1024


class Revoker:
    """The revocations after committed deletes: one task each, on ``client``, a guarded client
    that follows no redirect (M7 design B.2). ``proxied`` says it goes through
    ``egress_proxy``, for the ``discovery_fetch`` line's ``via``; ``refused`` keeps a refusal by
    the address guard for health (the token manager's ``note_refused``, M7 design J);
    ``timeout`` is for tests."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        proxied: bool = False,
        refused: Callable[[str, str, int, str], None] | None = None,
        timeout: float = REVOKE_TIMEOUT,
    ) -> None:
        self._client = client
        self._via = "proxy" if proxied else "direct"
        self._refused = refused
        self._timeout = timeout
        self._tasks: set[asyncio.Task[None]] = set()

    def request(self, material: RevocationMaterial) -> None:
        """Start the revocation; it never raises, and nothing waits for it."""
        task = asyncio.get_running_loop().create_task(
            self._revoke(material), name=f"oauth-revoke:{material.credential}"
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def wait(self) -> None:
        """Until every revocation started so far has ended (tests)."""
        while self._tasks:
            await asyncio.wait(set(self._tasks))

    async def aclose(self) -> None:
        """At shutdown: the revocations in flight get their own limit, then the rest are
        cancelled. A crash loses them: the delete had committed, so the grant may stay live (N)."""
        if self._tasks:
            _, pending = await asyncio.wait(set(self._tasks), timeout=self._timeout)
            for task in pending:
                task.cancel()
            # They unwind before the caller closes the client they run on.
            await asyncio.gather(*pending, return_exceptions=True)

    async def _revoke(self, material: RevocationMaterial) -> None:
        """The task. It never raises: the outcome goes to the log."""
        outcome: Outcome
        try:
            outcome, status = await self._send(material)
        except Exception:
            outcome, status = "failed", None
        logs.event("oauth_revoked", credential=material.credential, outcome=outcome, status=status)

    async def _send(self, material: RevocationMaterial) -> tuple[Outcome, int | None]:
        try:
            request = build_revocation(material)
        except ValueError:
            # Not the token origin (TI-2), or no client secret to authenticate with: nothing sent.
            return "refused", None
        built = self._client.build_request(
            "POST", request.url, headers=list(request.headers), content=request.body
        )
        # The host as the guard sees it (IDNA-encoded, lower case), as oauth/fetch.py writes it.
        host, port = built.url.raw_host.decode("ascii").lower(), built.url.port or 443
        status: int | None = None
        size = 0
        started = time.monotonic()
        try:
            with anyio.fail_after(self._timeout):
                response = await self._client.send(built, stream=True, follow_redirects=False)
                try:
                    status = response.status_code
                    size = await _counted(response)
                finally:
                    await response.aclose()
        except AddressRefused as exc:
            logs.event(
                "address_refused",
                purpose="revocation",
                host=exc.host,
                port=exc.port,
                verdict=exc.verdict.reason,
            )
            if self._refused is not None:
                self._refused("revocation", exc.host, exc.port, exc.verdict.reason)
            return "refused", None
        except (TimeoutError, httpx.TimeoutException):
            return "timeout", None
        except httpx.HTTPError:
            return "failed", None
        finally:
            # Every attempt, as fetch.py's: no status when no answer came.
            logs.event(
                "discovery_fetch",
                fetch_kind="revoke",  # "kind" is the logger's own argument
                host=host,
                port=port,
                status=status,
                bytes=size,
                ms=int((time.monotonic() - started) * 1000),
                via=self._via,
            )
        # RFC 7009 2.2: a token the server doesn't know is a 200 too.
        return ("ok" if status == 200 else "failed"), status


async def _counted(response: httpx.Response) -> int:
    """How many bytes of the answer arrived, reading at most a little past :data:`_ANSWER_MAX`."""
    size = 0
    async for chunk in response.aiter_raw():
        size += len(chunk)
        if size > _ANSWER_MAX:
            break
    return size


async def put(
    store: SecretStore, tokens: TokenManager | None, plan: PutPlan | OnboardPutPlan, *, via: Via
) -> dict[str, Any] | SecretRefusal:
    """Write a planned secret. Returns the binding it was stored with, or the refusal."""
    try:
        if plan.oauth and tokens is not None:
            # The manager derives the binding again, from the policy it runs.
            binding = await tokens.replace_secret(plan.name, plan.value)
        else:
            binding = plan.binding
            meta = plan.meta if isinstance(plan, OnboardPutPlan) else KEEP
            store.put(plan.name, plan.value, binding, meta=meta)
    except StoreWriteError as exc:
        logs.event(
            "secret_set", name=plan.name, persisted=False, error_type=type(exc).__name__, via=via
        )
        return NOT_WRITTEN_REFUSAL
    except BindingError as exc:
        return binding_refusal(exc)
    except ValueError as exc:
        # The manager runs no oauth2 credential that uses the name: its policy moved since the
        # plan.
        return SecretRefusal(409, "not_oauth", str(exc))
    logs.event("secret_set", name=plan.name, binding=binding, via=via)
    return binding


async def restore(
    store: SecretStore, entry: EntryMeta, value: Secret, *, via: Via
) -> SecretRefusal | None:
    """Put an entry back as it was before a write replaced it: its value, binding and ``meta``
    (M7 design OPS-3, OPS-5). Returns the refusal, or ``None`` once it is back."""
    try:
        store.put(entry.name, value.reveal(), entry.binding, meta=entry.meta)
    except StoreWriteError as exc:
        logs.event(
            "secret_set", name=entry.name, persisted=False, error_type=type(exc).__name__, via=via
        )
        return NOT_WRITTEN_REFUSAL
    logs.event("secret_set", name=entry.name, binding=entry.binding, via=via)
    return None


async def delete(
    store: SecretStore,
    tokens: TokenManager | None,
    plan: DeletePlan,
    *,
    via: Via,
    revoker: Revoker | None = None,
) -> SecretRefusal | Revocation:
    """Delete a planned secret. Returns the refusal or, once it is gone, whether a revocation
    was requested. Without ``revoker`` nothing is revoked (an onboarding's own client secret)."""
    material: RevocationMaterial | None = None
    try:
        if plan.oauth and tokens is not None:
            existed, material = await tokens.forget(plan.name, take_revocation=revoker is not None)
        else:
            existed = store.delete(plan.name)
    except StoreWriteError as exc:
        logs.event(
            "secret_deleted",
            name=plan.name,
            persisted=False,
            error_type=type(exc).__name__,
            via=via,
        )
        return NOT_WRITTEN_REFUSAL
    if not existed:
        return NOT_FOUND
    logs.event("secret_deleted", name=plan.name, via=via)
    # Only now: a delete the store couldn't write revokes nothing (N).
    if material is None or revoker is None:
        return "none"
    revoker.request(material)
    return "requested"
