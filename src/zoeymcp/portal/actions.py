"""Pending actions: the step-up path (M5 design F.3, F.4). Pure, so each rule can be tested.

Every change the portal makes runs from an action the vault holds (P6). ``POST /api/actions``
checks the request against the registry (:data:`KINDS`), runs the kind's plan, and
:meth:`Actions.prepare` stores the action with its plan and a fresh nonce, replacing the
session's earlier one. ``POST /api/actions/{id}/confirm`` :meth:`~Actions.take`\\s it out of the
table before the assertion is checked, so it is single use whatever happens next; the caller
then verifies the assertion against :attr:`Action.challenge`, plans again, and refuses with
``409 changed`` when :func:`changed` says the plan moved.

The challenge commits to the action's ID and kind, the session, the origin and the digest of the
held data (F.3), so one confirmation can't confirm another action, nor the same one with other
data. Every method takes ``now``, and the random bytes come from an injected function.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any, Final, Literal

from ..common.canonical import digest
from ..common.logs import refuse_type
from .routes import BODY_DEFAULT, BODY_PASTE, BODY_SECRET, DISCOVER_KEYS
from .sessions import NONCE_BYTES, RandomBytes, challenge, new_id

ACTION_TTL: Final = 300.0
MAX_ACTIONS_PER_SESSION: Final = 1
MAX_ACTIONS_BODY: Final = BODY_SECRET  # read before the kind is known (M.1)
STEP_UP_TAG: Final = b"zoeymcp/webauthn/step-up/v1\n"


# --- the registry ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Kind:
    """One kind of action: its body cap (M.1) and the keys of its ``data`` (F.4). The kind's
    plan and run are the caller's; later milestones add kinds here without changing the
    mechanism."""

    name: str
    cap: int
    required: frozenset[str]
    optional: frozenset[str] = frozenset()


_DEFAULT_CAP: Final = BODY_DEFAULT  # one definition of each of M.1's caps, in routes.py
KINDS: Final[dict[str, Kind]] = {
    kind.name: kind
    for kind in (
        Kind("secret.put", BODY_SECRET, frozenset({"name", "value"}), frozenset({"origins"})),
        Kind("secret.delete", _DEFAULT_CAP, frozenset({"name"})),
        # A paste (redirect_url), or returned: true after a callback (H.6); the plan takes one.
        Kind(
            "oauth.complete",
            BODY_PASTE,
            frozenset({"credential", "flow"}),
            frozenset({"redirect_url", "returned"}),
        ),
        Kind("oauth.reset", _DEFAULT_CAP, frozenset({"credential"})),
        Kind("passkey.enrol", _DEFAULT_CAP, frozenset({"name"})),
        Kind("passkey.rename", _DEFAULT_CAP, frozenset({"credential", "name"})),
        Kind("passkey.remove", _DEFAULT_CAP, frozenset({"credential"})),
        Kind("ledger.restart", _DEFAULT_CAP, frozenset()),
        # M7 K.3: a discovery that lifts the address guard for the typed host:port (TI-3), whose
        # run is the discovery itself; and registering a client, or storing a given one's secret,
        # whose run sends the registration or writes the secret, then makes fragment 1.
        Kind(
            "onboard.discover_private",
            _DEFAULT_CAP,
            frozenset({"url", "allow_private"}),
            DISCOVER_KEYS,
        ),
        Kind(
            "onboard.register", BODY_SECRET, frozenset({"onboarding"}), frozenset({"client_secret"})
        ),
        # M6 J.4: clearing a server's drift marks un-hides its tools, so it is stepped up (Y27);
        # its run queues a clear job, which the gateway runs only if every included tool matches.
        Kind("tool.clear", _DEFAULT_CAP, frozenset({"server"})),
        # M6 G.3, G.4, M.3: a managed review save, held as a draft by the review diff route, is
        # prepared by its ID and the revision it was planned on; tool.repin is one whose diff
        # only re-pins. tool.allow is one tool moved from approve to allow: from a server's page
        # by the tool and the pin the operator was shown, or a draft whose only change it is.
        Kind("policy.save", _DEFAULT_CAP, frozenset({"draft", "base"})),
        Kind("tool.repin", _DEFAULT_CAP, frozenset({"draft", "base"})),
        Kind(
            "tool.allow",
            _DEFAULT_CAP,
            frozenset({"base"}),
            frozenset({"server", "kind", "name", "pin", "draft"}),
        ),
        # M6 H.3, M.3: a managed rollback, from the Policy page, to a kept revision, planned on
        # the head revision the page showed.
        Kind("policy.rollback", _DEFAULT_CAP, frozenset({"base", "revision"})),
    )
}
# tool.allow's two forms of data (M6 J.4, M.3): its optional keys come all from one.
ALLOW_FORMS: Final = (frozenset({"server", "kind", "name", "pin"}), frozenset({"draft"}))


@dataclass(frozen=True)
class Request:
    kind: Kind
    data: dict[str, Any]


@dataclass(frozen=True)
class ActionRefusal:
    status: int
    reason: Literal["bad_body", "too_large"]


def parse_request(body: dict[str, Any], size: int) -> Request | ActionRefusal:
    """Check a ``{kind, data}`` body (its keys already checked, C.2 row 12) of ``size`` bytes
    against the registry: a known kind, within its cap, and ``data`` an object with the kind's
    keys. The values are the plan's to check."""
    kind = KINDS.get(body["kind"]) if isinstance(body["kind"], str) else None
    if kind is None:
        return ActionRefusal(400, "bad_body")
    if size > kind.cap:
        return ActionRefusal(413, "too_large")
    data = body["data"]
    if (
        not isinstance(data, dict)
        or not kind.required <= data.keys() <= kind.required | kind.optional
    ):
        return ActionRefusal(400, "bad_body")
    return Request(kind, data)


# --- held data and the action ---------------------------------------------------------------------


class HeldData:
    """An action's ``data`` (a secret value, a pasted address), held for at most
    :data:`ACTION_TTL`. Its ``repr`` hides it; logging it raises."""

    __slots__ = ("_value",)

    def __init__(self, value: Any) -> None:
        self._value = value

    def reveal(self) -> Any:
        return self._value

    def digest(self) -> str:
        """``sha256:`` and the hex SHA-256 of the canonical JSON (F.3)."""
        return digest(self._value)

    def __repr__(self) -> str:
        return "HeldData(<hidden>)"

    __str__ = __repr__


refuse_type(HeldData)


@dataclass(frozen=True, repr=False)
class Action:
    """A prepared action. ``plan`` is what the kind's plan returned (its summary and what will
    run); logging the action raises, since the plan can hold the data too."""

    id: str
    kind: str
    data: HeldData
    plan: Any
    session: str
    origin: str
    nonce: bytes
    expires: float

    def binding(self) -> dict[str, Any]:
        return {
            "action": self.id,
            "kind": self.kind,
            "origin": self.origin,
            "session": self.session,
            "data": self.data.digest(),
        }

    @property
    def challenge(self) -> bytes:
        return challenge(STEP_UP_TAG, self.nonce, self.binding())

    def __repr__(self) -> str:
        return f"Action(kind={self.kind}, expires={self.expires})"


refuse_type(Action)


def changed(action: Action, plan: Any) -> bool:
    """Whether planning again at confirm gives another plan (``409 changed``, F.4 step 3).

    Plans compare by equality, so a plan type leaves out of it anything that differs between
    two runs over the same state (a time-based name, say), or every confirm would be refused.
    """
    return bool(action.plan != plan)


class Actions:
    """Every pending action, in memory only: at most one per session (P6, P22)."""

    def __init__(self, random: RandomBytes = secrets.token_bytes) -> None:
        self._random = random
        self._by_session: dict[str, Action] = {}

    def __len__(self) -> int:
        return len(self._by_session)

    def pending(self, session: str, now: float) -> Action | None:
        """The session's live action, if it has one."""
        action = self._by_session.get(session)
        return action if action is not None and action.expires > now else None

    def prepare(
        self, *, kind: str, data: Any, plan: Any, session: str, origin: str, now: float
    ) -> Action:
        """Hold a planned action for :data:`ACTION_TTL`, replacing the session's earlier one."""
        action = Action(
            id=new_id(self._random),
            kind=kind,
            data=HeldData(data),
            plan=plan,
            session=session,
            origin=origin,
            nonce=self._random(NONCE_BYTES),
            expires=now + ACTION_TTL,
        )
        self._by_session[session] = action
        return action

    def take(self, action_id: str, *, session: str, origin: str, now: float) -> Action | None:
        """Remove and return the session's action, before its assertion is checked, if it is
        this ID, of this origin and live. Another session's or origin's answers as an unknown
        one and stays."""
        action = self._by_session.get(session)
        if action is None or action.id != action_id or action.origin != origin:
            return None
        del self._by_session[session]
        return action if action.expires > now else None

    def cancel(self, action_id: str, *, session: str, origin: str, now: float) -> bool:
        """``DELETE /api/actions/{id}``: whether a live action of the session was dropped."""
        return self.take(action_id, session=session, origin=origin, now=now) is not None

    def drop_session(self, session: str) -> None:
        """Drop the action of a session that ended."""
        self._by_session.pop(session, None)

    def sweep(self, now: float) -> None:
        """Drop expired actions, and the data they hold."""
        for action in [a for a in self._by_session.values() if a.expires <= now]:
            del self._by_session[action.session]
