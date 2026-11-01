"""A scripted operator at the portal's approvals queue (M8 design O.1, H.2, H.3).

:class:`QueueApprover` drives the queue as the page's script will, over ``browser.py``'s
:class:`~tests.fakes.browser.Page` (its session header, its ``Origin``, its cookies) and
``authenticator.py``'s passkeys: it lists the queue (``GET /api/approvals``, the badge's ``GET
/api/approvals/count``), opens one hold (``GET /api/approvals/{approval}``: its composed text and
that text's SHA-256, checked against the text), prepares ``approval.decide`` bound to that digest
(``POST /api/actions``), answers the step-up's passkey prompt and confirms it (``POST
/api/actions/{action}/confirm``), and denies with its session alone (``POST
/api/approvals/{approval}/deny``, the digest in the body). Every POST body names its keys
literally (M6's 88f3ae4 rule).

:class:`ApproverSwitch` makes it misbehave the ways H.3 refuses: a digest of another text (a stale
view), a deny without the session, ``decision: "deny"`` through the step-up kind, or an extra key
in the action's data. Nothing here imports the portal; the routes' answers are read only for the
fields named here.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any, Final

import httpx

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page

QUEUE: Final = "/api/approvals"
COUNT: Final = "/api/approvals/count"
ACTIONS: Final = "/api/actions"
KIND: Final = "approval.decide"
# The text a stale view would hold (STALE_DIGEST).
STALE_TEXT: Final = "Approval request 0000000000000000: a text the queue no longer shows"


class ApproverSwitch(enum.StrEnum):
    """One misbehaviour of the scripted operator (H.3's refusals)."""

    # Prepare and deny with the digest of another text, as a tab opened before a change would.
    STALE_DIGEST = "stale_digest"
    # Deny without the session header.
    NO_SESSION = "no_session"
    # Prepare approval.decide with decision "deny" (deny has its own route).
    DECIDE_DENY = "decide_deny"
    # Prepare approval.decide with one more key in its data.
    EXTRA_KEY = "extra_key"


def text_sha256(text: str) -> str:
    """The digest the queue binds a decision to: SHA-256 of the composed text, lowercase hex."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Queue:
    """``GET /api/approvals``: the two lists, as answered."""

    waiting: list[dict[str, Any]]
    decided: list[dict[str, Any]]


@dataclass
class QueueApprover:
    """The operator in ``page``, with the passkey ``authenticator`` holds."""

    page: Page
    authenticator: SoftAuthenticator
    switches: set[ApproverSwitch] = field(default_factory=set)
    # Each prepare's answer, oldest first.
    prepared: list[dict[str, Any]] = field(default_factory=list)

    def queue(self) -> Queue:
        answer = self.page.fetch("GET", QUEUE)
        assert answer.status_code == 200, answer.text
        body = answer.json()
        return Queue(list(body["waiting"]), list(body["decided"]))

    def count(self) -> int:
        answer = self.page.fetch("GET", COUNT)
        assert answer.status_code == 200, answer.text
        return int(answer.json()["count"])

    def show(self, approval: str) -> dict[str, Any]:
        """One hold, opened: its composed text and digest, its state."""
        answer = self.page.fetch("GET", f"{QUEUE}/{approval}")
        assert answer.status_code == 200, answer.text
        shown: dict[str, Any] = answer.json()
        return shown

    def digest_of(self, shown: dict[str, Any]) -> str:
        """The digest this operator sends for what it was shown: the route's own, as the page
        sends it, once it is checked against the text (a route whose digest isn't its text's
        fails here, not as a refused decision)."""
        if ApproverSwitch.STALE_DIGEST in self.switches:
            return text_sha256(STALE_TEXT)
        digest = str(shown["text_sha256"])
        assert digest == text_sha256(str(shown["text"])), shown
        return digest

    def prepare(self, approval: str) -> httpx.Response:
        """Open the hold, then prepare ``approval.decide`` for the text it showed."""
        digest = self.digest_of(self.show(approval))
        decision = "deny" if ApproverSwitch.DECIDE_DENY in self.switches else "approve"
        data: dict[str, Any] = {"approval": approval, "text_sha256": digest, "decision": decision}
        if ApproverSwitch.EXTRA_KEY in self.switches:
            data = {**data, "all": True}
        answer = self.page.fetch("POST", ACTIONS, json={"kind": KIND, "data": data})
        if answer.status_code == 200:
            self.prepared.append(answer.json())
        return answer

    def confirm(self, prepared: dict[str, Any]) -> httpx.Response:
        """Answer the prepared action's passkey prompt and confirm it, as the dialog does."""
        assertion = self.authenticator.get(prepared["options"], self.page.origin).body()
        return self.page.fetch(
            "POST", f"{ACTIONS}/{prepared['action']}/confirm", json={"credential": assertion}
        )

    def approve(self, approval: str) -> httpx.Response:
        """Prepare, assert and confirm; a refused prepare is the answer."""
        prepared = self.prepare(approval)
        if prepared.status_code != 200:
            return prepared
        return self.confirm(prepared.json())

    def deny(self, approval: str) -> httpx.Response:
        """Deny with the session alone, bound to the text shown."""
        digest = self.digest_of(self.show(approval))
        session = ApproverSwitch.NO_SESSION not in self.switches
        return self.page.fetch(
            "POST", f"{QUEUE}/{approval}/deny", json={"text_sha256": digest}, session=session
        )
