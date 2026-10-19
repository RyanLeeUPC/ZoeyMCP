"""Send-once accounting for an accepted plan (M4 design G.3). Pure.

After an accept, a tool's body may send each of the plan's writes once, exactly as frozen, in any
order. A write is claimed before it is sent, so two concurrent sends of one write can't both go.
A claim is never given back: a send that failed is not retried by the SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ..common.approvaltext import Plan, Write

Claim = Literal["ok", "not_in_plan", "already_sent"]


@dataclass
class SendLedger:
    """Which of an accepted plan's writes were sent. ``plan`` is ``None`` for a call with no
    accepted plan, so every claim is refused."""

    plan: Plan | None
    _sent: set[int] = field(default_factory=set)

    def claim(self, write: Write) -> Claim:
        """Claim ``write`` for sending: ``ok`` once, for a write of the plan itself (the same
        object, with the same digest), then ``already_sent``."""
        if self.plan is None:
            return "not_in_plan"
        for index, planned in enumerate(self.plan.writes):
            if planned is write and planned.digest == write.digest:
                if index in self._sent:
                    return "already_sent"
                self._sent.add(index)
                return "ok"
        return "not_in_plan"

    @property
    def unsent(self) -> tuple[Write, ...]:
        if self.plan is None:
            return ()
        return tuple(w for i, w in enumerate(self.plan.writes) if i not in self._sent)
