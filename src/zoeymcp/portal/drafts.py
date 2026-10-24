"""Drafts: a managed review save, held between the review screen and its step-up (M6 design G.4,
J.3; Y7, Y8). Pure, mutation-tested.

A review save can name hundreds of tools, more than ``POST /api/actions`` reads before it knows
the kind (F-19). So the page never sends a change in an action: in managed mode the review diff
route builds the change from the done job's report and the operator's choices, plans it, and
:meth:`Drafts.hold`\\s it as a :class:`Draft`, one per session (a new one replaces it), for
:data:`DRAFT_TTL`, in memory only; its answer (:func:`answer`) is ``{draft, base, kind, summary}``,
``kind`` being the planner's required kind, and the action is then ``prepare(kind, {"draft",
"base"})``. A draft of another session, or an expired one, answers as an unknown one
(``draft_unknown``).

A draft keeps what its report showed beside the change (:func:`facts`, :class:`Facts`), so the
planner reads the same evidence at prepare and at confirm (G.5, Y8): the pins the review
verified, the tools it showed drifted, the definition of every tool the change classifies
``allow`` at a (classification, pin) the policy the review ran under doesn't hold, the shared
rule's suggestion for each tool it re-pins (Q8), the toolkit's consequential tools and the tools
the report showed marked. ``facts`` refuses, as ``reviewchange.definitions`` does, a name in
``allow`` whose definition at its pin the report doesn't hold, one the report shows marked and a
consequential one. Logging a draft raises: it holds the change.
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from ..common.logs import refuse_type
from ..common.policy.change import PolicyChange, SetServerReview
from ..common.policy.ratchet import DefKey
from ..common.policy.reviewchange import AllowRefused, Lines, definitions, listed, suggested
from ..common.policy.reviewchange import verified as verified_pins
from ..common.suggest import Suggestion
from .sessions import RandomBytes, new_id

DRAFT_TTL: Final = 300.0
MAX_DRAFTS_PER_SESSION: Final = 1


@dataclass(frozen=True)
class Facts:
    """What a draft's report showed, for the planner (G.5's ``PlanInput`` fields of the same
    names; ``marked`` is the report's, which the caller joins with the gateway's latest
    status)."""

    verified: frozenset[tuple[DefKey, str]] = frozenset()
    drifted: frozenset[DefKey] = frozenset()
    definitions: Mapping[DefKey, Lines] = field(default_factory=dict)
    suggested: Mapping[DefKey, Suggestion | None] = field(default_factory=dict)
    consequential: frozenset[DefKey] = frozenset()
    marked: frozenset[DefKey] = frozenset()


def _key(report: Mapping[str, Any], entry: Mapping[str, Any]) -> DefKey:
    return (report["server"], entry.get("kind", "tool"), entry["name"])


def facts(report: Mapping[str, Any], op: SetServerReview) -> Facts | AllowRefused:
    """The evidence ``op``, built from ``report``, rests on (J.3), or the first name in
    ``allow`` the report can't stand behind."""
    found = definitions(report, op)
    if isinstance(found, AllowRefused):
        return found
    entries = listed(report).values()
    return Facts(
        verified=verified_pins(report, op),
        drifted=frozenset(_key(report, e) for e in entries if e["state"] == "drift"),
        definitions=found,
        suggested={
            _key(report, e): suggested(e)
            for e in entries
            if e["state"] == "drift" and op.review.get(e["name"]) == e["pin"]
        },
        consequential=frozenset(_key(report, e) for e in entries if e.get("consequential") is True),
        marked=frozenset(_key(report, e) for e in entries if e["state"] == "marked"),
    )


def the_review(change: PolicyChange) -> SetServerReview | None:
    """The server's review a review save's change holds (``reviewchange.fragment``'s op, after
    its comments), or None."""
    return next((op for op in change.ops if isinstance(op, SetServerReview)), None)


@dataclass(frozen=True, repr=False)
class Draft:
    """A held review save: its session, the head revision it was planned on (``base``), the
    change, the job and the digest of the report it was built from, the kind the planner
    requires, what the report showed, and when it expires."""

    id: str
    session: str
    base: int
    change: PolicyChange
    job: str
    report_digest: str
    kind: str
    facts: Facts
    expires: float

    def __repr__(self) -> str:
        return f"Draft(kind={self.kind}, base={self.base}, expires={self.expires})"


refuse_type(Draft)


def answer(draft: Draft, summary: list[list[str]]) -> dict[str, Any]:
    """The review diff route's managed answer (G.4): the draft, its base, the kind to prepare
    and the plan's summary."""
    return {"draft": draft.id, "base": draft.base, "kind": draft.kind, "summary": summary}


class Drafts:
    """Every held draft, in memory only: at most one per session."""

    def __init__(self, random: RandomBytes = secrets.token_bytes) -> None:
        self._random = random
        self._by_session: dict[str, Draft] = {}

    def __len__(self) -> int:
        return len(self._by_session)

    def hold(
        self,
        *,
        session: str,
        base: int,
        change: PolicyChange,
        job: str,
        report_digest: str,
        kind: str,
        facts: Facts,
        now: float,
    ) -> Draft:
        """Hold a planned review save for :data:`DRAFT_TTL`, replacing the session's earlier
        draft."""
        draft = Draft(
            id=new_id(self._random),
            session=session,
            base=base,
            change=change,
            job=job,
            report_digest=report_digest,
            kind=kind,
            facts=facts,
            expires=now + DRAFT_TTL,
        )
        self._by_session[session] = draft
        return draft

    def get(self, draft_id: str, *, session: str, now: float) -> Draft | None:
        """The session's live draft, if it is this ID. Another session's, an expired one or an
        unknown one is None (``draft_unknown``); it stays held until it is replaced or swept."""
        draft = self._by_session.get(session)
        if draft is None or draft.id != draft_id or draft.expires <= now:
            return None
        return draft

    def drop(self, draft_id: str, *, session: str) -> None:
        """Drop the session's draft once it is saved, if it is this ID."""
        draft = self._by_session.get(session)
        if draft is not None and draft.id == draft_id:
            del self._by_session[session]

    def drop_session(self, session: str) -> None:
        """Drop the draft of a session that ended."""
        self._by_session.pop(session, None)

    def sweep(self, now: float) -> None:
        """Drop expired drafts, and the changes they hold."""
        for draft in [d for d in self._by_session.values() if d.expires <= now]:
            del self._by_session[draft.session]
