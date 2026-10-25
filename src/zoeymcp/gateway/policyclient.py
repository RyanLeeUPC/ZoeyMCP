"""Fetching the gateway's view of the policy from the vault (M3 design D.2, D.3).

The gateway long-polls ``/_zoeymcp/gateway/v1/view`` with ``If-None-Match`` and ``?wait=25``:
the vault answers 200 with a new view as soon as the digest changes, or 304 after 25 s. Each 200
or 304 is contact. With no contact for ``limits.policy_max_stale``, the view is stale, and every
agent request gets 503 until contact resumes: revocation can't lapse while the vault is away.

A view the gateway can't parse (from a newer vault, say) is refused and the last good one stays.
Failures back off 1, 2, 4 ... 30 s, jittered. SIGHUP asks for a fetch at once.

The vault states its mode beside every view answer, the 200 and the 304, in the header
``x-zoeymcp-policy-mode`` (M6 design K.3, G.9). The client keeps the last one it read with
contact as :attr:`PolicyClient.mode`, ``unknown`` before its first view, so the gateway's
status and review answers can tell the CLI in its container, which has no vault socket, that the
deployment is managed. An answer without a mode it knows keeps the last.

A managed vault states its head beside the mode, in ``x-zoeymcp-policy-revision`` (K.3, CR-9).
With a :class:`Witness`, the client hands each statement it reads with contact to it: the
restore witness keeps the highest revision seen of each deployment in ``policy-seen.json``
(:mod:`.witness`), logs ``policy_deployment_seen`` for a new deployment beside others (warning)
and ``policy_revision_regressed`` (critical, once per regression) for a revision below the one
it holds, and the status report carries what it holds. The view is applied either way.
"""

from __future__ import annotations

import random
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import anyio
import httpx2

from ..common import files
from ..common.policy.view import (
    MODE_HEADER,
    REVISION_HEADER,
    GatewayView,
    PolicyMode,
    ViewError,
    parse_view,
)
from . import logs, witness
from .vaultlink import VIEW_PATH

WAIT = 25
BACKOFF_START = 1.0
BACKOFF_MAX = 30.0
# The modes a view answer may state; anything else keeps the last.
STATED: Final[Mapping[str, PolicyMode]] = {"managed": "managed", "declarative": "declarative"}


@dataclass(frozen=True)
class Snapshot:
    """One applied view. A request keeps the snapshot it started with."""

    view: GatewayView
    applied_at: float


Apply = Callable[[Snapshot, Snapshot | None], Awaitable[None]]


class Witness:
    """The restore witness's file in the gateway's state (K.3): what :mod:`.witness` decides,
    kept in memory and written atomically on each change. ``wall`` dates a new deployment."""

    def __init__(
        self,
        path: Path,
        found: witness.Seen | None = None,
        *,
        wall: Callable[[], float] = time.time,
    ) -> None:
        self._path = path
        self.seen = found or witness.Seen()
        self._wall = wall
        # The last regression logged, so a long poll that states it again every 25 s logs once.
        self._regressed: witness.Regressed | None = None

    @classmethod
    def load(cls, state_dir: Path) -> Witness:
        """The file in ``state_dir``, or an empty witness without one. Raises
        :class:`~.witness.WitnessError` for a file that can't be read or used."""
        path = state_dir / witness.FILE
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return cls(path)
        except OSError as exc:
            raise witness.WitnessError(f"can't read {path.name}: {exc.strerror}") from exc
        return cls(path, witness.loads(data))

    def note(self, header: str | None) -> None:
        """A view answer's revision header, read with contact."""
        stated = witness.stated(header)
        if stated is None:
            return
        old = self.seen
        found = witness.seen(old, stated, int(self._wall()))
        if isinstance(found, witness.Regressed):
            if found != self._regressed:
                self._regressed = found
                logs.event(
                    "policy_revision_regressed",
                    level="critical",
                    deployment=found.deployment[:8],
                    seen=found.seen,
                    now=found.now,
                )
            return
        if found is old:
            return
        if stated.deployment not in old.deployments:
            logs.event(
                "policy_deployment_seen",
                level="warning" if old.deployments else "info",
                deployment=stated.deployment[:8],
            )
        self.seen = found
        try:
            files.write_atomic(self._path, witness.dumps(found), prefix=".policy-seen-")
        except OSError as exc:
            # The record still holds in memory, and the next change writes it whole again.
            logs.event("policy_seen_not_written", level="warning", error=exc.strerror or "error")


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
        witness: Witness | None = None,
    ) -> None:
        self._http = http
        self._apply = apply
        self._clock = clock
        self._wait = wait
        self.witness = witness
        self.snapshot: Snapshot | None = None
        # The vault's mode, read with the snapshot and on each 304 after it.
        self.mode: PolicyMode = "unknown"
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
            self._read_mode(response)
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
        self._read_mode(response)
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

    def _read_mode(self, response: httpx2.Response) -> None:
        self.mode = STATED.get(response.headers.get(MODE_HEADER, ""), self.mode)
        if self.witness is not None:
            self.witness.note(response.headers.get(REVISION_HEADER))

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
