"""The self-test's stand-in approver surface (M8 design I.5, O.1).

A self-test runs the vault on the operator's real policy, so a case on a tool the vault holds is
held there, as it would be in production. No real surface is started: no Telegram client is
built and nothing reaches the Bot API (Z22), and the portal's queue isn't there. The stand-in
takes each surface's place instead, under each name, and **decides nothing**: it records each
hold it is shown, once, with the text the vault rendered, and the runner withdraws the hold
(the case's outcome ``held``), so nothing is ever forwarded.
"""

from __future__ import annotations

import asyncio
from typing import Final

from ..vault.approvers import ApproverHub, Shown, SurfaceName
from ..vault.holds import Hold

NAMES: Final[tuple[SurfaceName, ...]] = ("telegram", "portal")


class StandIn:
    """Every hold any of its surfaces was shown, by id, in order. :meth:`hub` is the approver
    hub a self-test's vault shows holds on."""

    def __init__(self) -> None:
        self._shown: dict[str, Hold] = {}
        self._changed = asyncio.Event()

    def hub(self) -> ApproverHub:
        """A hub with the stand-in under every surface's name, so a hold is shown here whichever
        surfaces the policy enables."""
        return ApproverHub(_Surface(name, self) for name in NAMES)

    @property
    def shown(self) -> list[Hold]:
        return list(self._shown.values())

    def note(self, hold: Hold) -> None:
        if hold.id not in self._shown:
            self._shown[hold.id] = hold
            changed, self._changed = self._changed, asyncio.Event()
            changed.set()

    async def beyond(self, count: int) -> Hold:
        """The hold shown after the first ``count``, once there is one."""
        while len(self._shown) <= count:
            await self._changed.wait()
        return self.shown[count]


class _Surface:
    """One surface's place: it shows, and does nothing else (D.1's interface)."""

    def __init__(self, name: SurfaceName, stand_in: StandIn) -> None:
        self._name: SurfaceName = name
        self._stand_in = stand_in

    @property
    def name(self) -> SurfaceName:
        return self._name

    async def show(self, hold: Hold) -> Shown:
        self._stand_in.note(hold)
        return Shown(self._name)

    async def approved(self, hold: Hold) -> None:
        """Never: the stand-in decides nothing."""

    async def close(self, hold: Hold, outcome: str) -> None:
        """Nothing to edit."""

    async def notice(self, text: str) -> None:
        """Nothing to tell."""
