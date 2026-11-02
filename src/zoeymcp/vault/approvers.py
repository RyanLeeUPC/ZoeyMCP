"""The vault's approver surfaces, and the hub that shows a hold on each (M8 design D.1, D.3, D.4).

A :class:`Surface` is one place a human decides: the portal's queue (passive: the queue lists the
open holds, step 15) or Telegram (it sends and edits messages, step 14). D-38's later back ends
implement the same interface: render through :mod:`~zoeymcp.common.approvaltext`, bind the
decision to the hold's id and text digest, one named egress source, a ``SecretRef``.

:class:`ApproverHub` shows each hold on every surface it names that is installed here, closes it
on every one of them when it ends (the decision itself comes back through
``VaultApp.decide``, where the first valid one wins, D.4), and passes on the saturation notice
(D.3). A surface that fails is logged by its error type and never stops the hold or another
surface: each call is bounded by :data:`EDIT_GRACE`, so a surface that hangs delays nothing for
longer. A show that fails or overruns that bound is :class:`Unconfirmed`, not a refusal: a
surface's show returns once the hold is queued for it, and retries its own delivery until the
hold's deadline (G.3, G.4), so the hold waits on and, decided nowhere, expires at its deadline
(fail closed, J8). Only a surface's own :class:`NotShown` (a text it can't carry) refuses a hold
that no surface shows.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Iterable
from dataclasses import dataclass
from typing import Final, Literal, Protocol

from . import logs
from .holds import SATURATION_WINDOW, Hold

SurfaceName = Literal["telegram", "portal"]
# The longest the vault waits on one surface's show, close or notice, and on all of their edits
# at its stop (M8 design I.2, M.3).
EDIT_GRACE: Final = 5.0
# D.3's notice, sent at most once per SATURATION_WINDOW to each surface.
NOTICE: Final = (
    "The approval queue is full: {count} requests were refused in the last "
    f"{int(SATURATION_WINDOW // 60)} minutes. Nothing was sent."
)


@dataclass(frozen=True)
class Shown:
    """The surface shows the hold, and may decide it."""

    surface: SurfaceName


@dataclass(frozen=True)
class NotShown:
    """The surface itself says it can't show the hold (G.4: a text Telegram can't carry, or one
    it returned changed): ``code`` says why, with the status the vault refuses with when no
    surface shows it (M.2)."""

    surface: SurfaceName
    code: str
    status: int


@dataclass(frozen=True)
class Unconfirmed:
    """The surface's show failed or overran :data:`EDIT_GRACE` (logged): it may still deliver
    the hold, so the hold waits on to its deadline (G.3)."""

    surface: SurfaceName


class Surface(Protocol):
    """One approver surface (D.1)."""

    @property
    def name(self) -> SurfaceName: ...

    async def show(self, hold: Hold) -> Shown | NotShown: ...

    async def approved(self, hold: Hold) -> None: ...

    async def close(self, hold: Hold, outcome: str) -> None: ...

    async def notice(self, text: str) -> None: ...


class ApproverHub:
    """The surfaces installed in this vault, by name."""

    def __init__(self, surfaces: Iterable[Surface] = ()) -> None:
        self._surfaces: dict[SurfaceName, Surface] = {}
        for surface in surfaces:
            self.install(surface)

    def install(self, surface: Surface) -> None:
        """Show holds on ``surface`` from now on, in place of any of its name."""
        self._surfaces[surface.name] = surface

    def remove(self, name: SurfaceName) -> None:
        self._surfaces.pop(name, None)

    @property
    def names(self) -> frozenset[SurfaceName]:
        return frozenset(self._surfaces)

    async def show(self, hold: Hold) -> list[Shown | NotShown | Unconfirmed]:
        """Show ``hold`` on each of its surfaces installed here, at once; one installed nowhere
        is shown nowhere (an empty list)."""
        named = [self._surfaces[name] for name in sorted(hold.surfaces) if name in self._surfaces]
        return list(await asyncio.gather(*(self._show(surface, hold) for surface in named)))

    async def approved(self, hold: Hold) -> None:
        """Tell each of ``hold``'s surfaces it was approved (``hold.via`` says where) and its
        ``decided accept`` is on disk: its forward starts (G.6's first edit, "Sending...")."""
        named = [self._surfaces[name] for name in sorted(hold.surfaces) if name in self._surfaces]
        await asyncio.gather(*(self._call(s, "approved", s.approved(hold)) for s in named))

    async def close(self, hold: Hold, outcome: str) -> None:
        """Close ``hold`` on each of its surfaces: ``outcome`` is its end state (``done`` for a
        forward, with the forward's outcome, ``ok``, ``tool_error``, ``upstream_error`` or
        ``unknown``, in ``hold.detail``; a withdrawal's reason is there too), and ``hold.via`` the
        surface that decided it (G.6's last edit)."""
        named = [self._surfaces[name] for name in sorted(hold.surfaces) if name in self._surfaces]
        await asyncio.gather(*(self._call(s, "close", s.close(hold, outcome)) for s in named))

    async def notice(self, count: int) -> None:
        """Tell every surface that ``count`` holds were refused by a cap (D.3)."""
        text = NOTICE.format(count=count)
        surfaces = list(self._surfaces.values())
        await asyncio.gather(*(self._call(s, "notice", s.notice(text)) for s in surfaces))

    async def _show(self, surface: Surface, hold: Hold) -> Shown | NotShown | Unconfirmed:
        try:
            async with asyncio.timeout(EDIT_GRACE):
                return await surface.show(hold)
        except Exception as exc:  # a surface never stops the hold, nor refuses it by failing
            logs.event(
                "approver_surface_failed",
                surface=surface.name,
                call="show",
                error_type=type(exc).__name__,
                level="warning",
            )
            return Unconfirmed(surface.name)

    @staticmethod
    async def _call(surface: Surface, call: str, work: Awaitable[None]) -> None:
        try:
            async with asyncio.timeout(EDIT_GRACE):
                await work
        except Exception as exc:  # a surface never stops the hold
            logs.event(
                "approver_surface_failed",
                surface=surface.name,
                call=call,
                error_type=type(exc).__name__,
                level="warning",
            )
