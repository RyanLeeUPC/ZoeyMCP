"""Fetching the gateway's view of the policy from the vault (M3 design D.2, D.3).

The gateway long-polls ``/_zoeymcp/gateway/v1/view`` with ``If-None-Match`` and ``?wait=25``:
the vault answers 200 with a new view as soon as the digest changes, or 304 after 25 s. Each 200
or 304 is contact. With no contact for ``limits.policy_max_stale``, the view is stale, and every
agent request gets 503 until contact resumes: revocation can't lapse while the vault is away.

A view the gateway can't parse (from a newer vault, say) is refused and the last good one stays.
Failures back off 1, 2, 4 ... 30 s, jittered. SIGHUP asks for a fetch at once.
"""

from __future__ import annotations

import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import anyio
import httpx2

from ..common.policy.view import GatewayView, ViewError, parse_view
from . import logs
from .vaultlink import VIEW_PATH

WAIT = 25
BACKOFF_START = 1.0
BACKOFF_MAX = 30.0


@dataclass(frozen=True)
class Snapshot:
    """One applied view. A request keeps the snapshot it started with."""

    view: GatewayView
    applied_at: float


Apply = Callable[[Snapshot, Snapshot | None], Awaitable[None]]


def backoff(failures: int, jitter: float) -> float:
    """1, 2, 4 ... 30 s, times ``jitter`` (0.5 to 1.5)."""
    return min(BACKOFF_MAX, BACKOFF_START * float(2 ** max(0, failures - 1))) * jitter


class PolicyClient:
    def __init__(
        self,
        http: httpx2.AsyncClient,
        apply: Apply,
        *,
        clock: Callable[[], float] = time.monotonic,
        wait: int = WAIT,
    ) -> None:
        self._http = http
        self._apply = apply
        self._clock = clock
        self._wait = wait
        self.snapshot: Snapshot | None = None
        self.last_contact: float | None = None
        self._failures = 0
        # Made in run(): an anyio event needs the loop it will be used on.
        self._wake: anyio.Event | None = None
        self._stale_reported = False

    # --- freshness ------------------------------------------------------------------------

    def age(self) -> float | None:
        """Seconds since the last 200 or 304, or None before the first."""
        if self.last_contact is None:
            return None
        return self._clock() - self.last_contact

    def fresh(self) -> Snapshot | None:
        """The current snapshot, if contact is recent enough to serve from it."""
        snapshot, age = self.snapshot, self.age()
        if snapshot is None or age is None:
            return None
        if age > snapshot.view.gateway.limits.policy_max_stale:
            if not self._stale_reported:
                self._stale_reported = True
                logs.event("policy_stale", age_s=round(age, 1))
            return None
        return snapshot

    # --- fetching ---------------------------------------------------------------------------

    def refresh(self) -> None:
        """Fetch now (SIGHUP, the control pipe's HUP)."""
        if self._wake is not None:
            self._wake.set()

    async def fetch_once(self, wait: int | None = None) -> bool:
        """One request. Returns whether it was contact (a 200 with a usable view, or a 304)."""
        headers = {}
        if self.snapshot is not None:
            headers["if-none-match"] = f'"{self.snapshot.view.digest}"'
        seconds = self._wait if wait is None else wait
        params = {"wait": str(seconds)} if seconds and self.snapshot is not None else {}
        try:
            response = await self._http.get(VIEW_PATH, headers=headers, params=params)
        except Exception as exc:  # every failure is the same to the caller
            logs.event("policy_fetch_failed", error_type=type(exc).__name__)
            return False
        if response.status_code == 304 and self.snapshot is not None:
            self._contact()
            return True
        if response.status_code != 200:
            logs.event("policy_fetch_failed", status=response.status_code)
            return False
        try:
            view = parse_view(response.content)
        except ViewError as exc:
            logs.event("policy_refused", reason=str(exc))
            return False
        previous = self.snapshot
        snapshot = Snapshot(view, self._clock())
        self.snapshot = snapshot
        self._contact()
        if previous is None or previous.view.digest != view.digest:
            logs.event(
                "policy_applied",
                digest=view.digest,
                clients=len(view.gateway.clients),
                servers=len(view.gateway.servers),
            )
            await self._apply(snapshot, previous)
        return True

    def _contact(self) -> None:
        self.last_contact = self._clock()
        self._failures = 0
        if self._stale_reported:
            self._stale_reported = False
            logs.event("policy_fresh")

    async def run(self) -> None:
        """Fetch for ever: long polls while things work, backoff while they don't."""
        self._wake = anyio.Event()
        while True:
            if await self.fetch_once():
                if self._wake.is_set():
                    self._wake = anyio.Event()
                continue
            self._failures += 1
            delay = backoff(self._failures, random.uniform(0.5, 1.5))  # noqa: S311 - jitter
            logs.event("policy_retry", retry_in=round(delay, 1))
            with anyio.move_on_after(delay):
                await self._wake.wait()
            self._wake = anyio.Event()
