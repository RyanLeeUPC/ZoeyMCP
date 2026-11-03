"""S20, J4, J7: the portal's Approvals queue, end to end (M8 design H, O.5; Z16, G-11, MISS-8).

The real vault and its portal run as ``tests/portal/rig.py`` runs them, with a policy (lit: M8's
fields are dark until step 18) whose ``shop`` server's ``place_order`` the vault holds, on a
local MCP route to ``tests/gateway/holdrig.py``'s echo upstream, and ``approvers.portal`` (and,
where a test races the surfaces, ``approvers.telegram`` with a scripted surface in its place).
A held call reaches the vault's proxy listener as the gateway sends it, with the gateway's key
and the held marker (``wait=pending``, ``block_seconds`` 0, so it answers pending at once and
the hold waits detached). The operator is ``tests/fakes/approver.py``'s scripted queue approver,
over the fake browser and authenticator:

- approve with a passkey (J4): the count, Home's item, the row, the hold opened (its text whole
  and that text's digest), the plan (the whole text and Approve's sentence, no relative time),
  one forward with the credential, and Decided recently's "approved here ...; sent: ok";
- deny with a session (J7, Q14 (a)): nothing sent, the other surface's message closed, Decided
  recently, a late deny or read told it was decided here;
- a stale decision (S20): another text's digest, no session, a deny through the step-up kind, a
  key too many, an unknown approval: each refused with its own reason, nothing decided;
- both surfaces racing (S20, J4): Telegram first, and Telegram between the prepare and the
  confirm, each answered ``already_decided`` naming Telegram; one forward each;
- a save prepared in another tab, replaced and named in the dialog (H.3, G-11);
- hostile strings (S12's way): markup and quotes are text in the answer, a hidden character is
  refused before anyone is asked;
- a policy change withdraws the hold: the plan refuses ``withdrawn``;
- the queue's reads leave the session's idle clock where it was; a deny moves it (MISS-8).
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from tests.dark import lit
from tests.fakes.approver import ApproverSwitch, QueueApprover, text_sha256
from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.fakes.harness import serve
from tests.gateway import holdrig
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.portal.app import REPLACED
from zoeymcp.portal.approvalsview import APPROVE_SENTENCE
from zoeymcp.vault.app import GATEWAY_HEADER
from zoeymcp.vault.approvers import PortalQueue, Shown, SurfaceName
from zoeymcp.vault.holds import Hold, Via
from zoeymcp.vault.store import origin_binding

from .flows import prepared_action, set_up, status_reason
from .rig import Clock, PortalRig, running

BOUND = 30.0
SHOP = "/shop/mcp"
UNKNOWN = "A" * 16


def document(upstream: str, *, telegram: bool) -> dict[str, Any]:
    """The rig's policy beside its admin block: ``place_order`` held by the vault on a local MCP
    route, client ``agent1`` attended, the portal's queue, and with ``telegram`` the Telegram
    approver too."""
    approvers: dict[str, Any] = {"portal": {}, "block_seconds": 0}
    if telegram:
        operator = holdrig.OPERATOR_ID
        approvers["telegram"] = {
            "bot_token": "store:approver-bot",
            "user_id": operator,
            "chat_id": operator,
        }
    return {
        "credentials": {"shop-key": {"kind": "header", "secret": "store:shop-key"}},
        "routes": [
            {
                "name": "shop",
                "prefix": "/shop",
                "upstream": f"{upstream}/base",
                "allow_insecure_upstream": True,
                "stream": True,
                "credential": "shop-key",
                "callers": ["gateway"],
                "rules": [{"methods": ["POST"], "paths": ["/mcp"]}],
            }
        ],
        "approvers": approvers,
        "gateway": {
            "clients": {
                "agent1": {
                    "token_sha256": hash_token("zgc1-agent1-token"),
                    "servers": ["shop"],
                    "approvals": {"attended": True, "renders": "plain"},
                }
            },
            "servers": {
                "shop": {
                    "kind": "remote",
                    "route": "shop",
                    "path": "/mcp",
                    "tools": {
                        "include": ["place_order"],
                        "approve": ["place_order"],
                        "vault_approval": ["place_order"],
                    },
                    "review": {"place_order": holdrig.PIN},
                }
            },
        },
    }


class Watched:
    """The vault's own portal queue as the hub shows holds on it, with a condition a test waits
    on, so a wait for Decided recently wakes on the close it waits for (``holdrig.Surface``'s
    way: nothing sleeps). It stands in the hub's ``portal`` place and hands every call on to the
    vault's queue, which the portal reads; a reload installs the vault's queue again."""

    def __init__(self, queue: PortalQueue) -> None:
        self.queue = queue
        self._changed = threading.Condition()

    @property
    def name(self) -> SurfaceName:
        return "portal"

    async def show(self, hold: Hold) -> Shown:
        return await self.queue.show(hold)

    async def approved(self, hold: Hold) -> None:
        await self.queue.approved(hold)

    async def close(self, hold: Hold, outcome: str) -> None:
        await self.queue.close(hold, outcome)
        with self._changed:
            self._changed.notify_all()

    async def notice(self, text: str) -> None:
        await self.queue.notice(text)

    def wait_closed(self, approval: str) -> None:
        """Wait in this thread until the queue has closed ``approval`` (bounded)."""

        def closed() -> bool:
            return any(ended.id == approval for ended in self.queue.closed())

        with self._changed:
            if not self._changed.wait_for(closed, BOUND):
                raise TimeoutError(f"the queue never closed {approval}")


@dataclass
class Queue:
    """The running rig, its upstream, the operator, the vault's queue as the hub sees it and,
    racing, the other surface."""

    rig: PortalRig
    upstream: holdrig.Upstream
    page: Page
    authenticator: SoftAuthenticator
    watched: Watched
    telegram: holdrig.Surface | None

    def approver(self, *switches: ApproverSwitch, page: Page | None = None) -> QueueApprover:
        return QueueApprover(page or self.page, self.authenticator, set(switches))

    def held(self, ref: str, arguments: Any = None) -> httpx.Response:
        """A held call as the gateway sends it (its key, the marker), answered pending."""
        sent = holdrig.headers(held=holdrig.marker(ref, wait="pending"))
        sent[GATEWAY_HEADER] = self.rig.vault.app._keys.gateway_key(1)
        url = f"http://127.0.0.1:{self.rig.proxy_port}{SHOP}"
        return httpx.post(url, content=holdrig.call(arguments=arguments), headers=sent, timeout=30)

    def waiting(self, ref: str, arguments: Any = None) -> dict[str, Any]:
        """Hold a call, and its row as the queue lists it."""
        answer = self.held(ref, arguments)
        assert answer.status_code == 409, answer.text
        [row] = [row for row in self.approver().queue().waiting if row["ref"] == ref]
        return row

    def decided(self, approval: str, words: str) -> dict[str, Any]:
        """Decided recently's row for ``approval`` once the queue has closed it, saying ``words``
        (a forward's outcome arrives after the decision, with the close)."""
        self.watched.wait_closed(approval)
        [row] = [r for r in self.approver().queue().decided if r["approval"] == approval]
        assert words in row["outcome_shown"], row
        return row

    def decide(self, approval: str, via: Via, digest: str) -> Any:
        """Another surface's decision, as its press reaches ``VaultApp.decide``."""
        app = self.rig.vault.app
        return self.rig.call(lambda: app.decide(approval, "approve", via, digest))


@contextmanager
def queue_rig(
    tmp_path: Path, *, telegram: bool = False, clock: Clock | None = None
) -> Iterator[Queue]:
    upstream = holdrig.Upstream()
    with lit(), serve(upstream.app()) as url:
        policy = document(url, telegram=telegram)
        with running(tmp_path, policy=policy, clock=clock) as rig:
            secrets = rig.app.secrets
            assert secrets is not None
            binding = origin_binding([url])
            rig.call(lambda: secrets.store.put("shop-key", holdrig.SECRET, binding))
            hub, own = rig.vault.app.hub, rig.vault.app.queue
            assert own is not None
            watched = Watched(own)
            rig.call(lambda: hub.install(watched))
            scripted = None
            if telegram:
                # The other surface, scripted: its presses reach the vault's decide.
                scripted = holdrig.Surface("telegram")
                rig.call(lambda: hub.install(scripted))
            page = rig.browser().page(rig.origin)
            authenticator = SoftAuthenticator()
            set_up(rig, page, authenticator)
            yield Queue(rig, upstream, page, authenticator, watched, scripted)


def decide(page: Page, approval: str, digest: str) -> httpx.Response:
    """``approval.decide``'s prepare for a hold the page may no longer list."""
    data = {"approval": approval, "text_sha256": digest, "decision": "approve"}
    return page.fetch("POST", "/api/actions", json={"kind": "approval.decide", "data": data})


def attention(page: Page) -> dict[str, Any]:
    answer = page.fetch("GET", "/api/attention")
    assert answer.status_code == 200, answer.text
    found: dict[str, Any] = answer.json()
    return found


# --- approve, deny (J4, J7) ---------------------------------------------------------------------


def test_approve_with_a_passkey(tmp_path: Path) -> None:
    with queue_rig(tmp_path) as queue:
        approver = queue.approver()
        assert approver.count() == 0
        assert attention(queue.page)["approvals"] is None
        row = queue.waiting("00000000000000a1")
        approval = row["approval"]
        assert (row["how_shown"], row["server_shown"], row["tool_shown"]) == (
            "Held by the vault",
            "shop",
            "place_order",
        )
        assert (row["client_shown"], row["surfaces"], row["telegram_shown"]) == (
            "agent1",
            ["portal"],
            None,
        )
        assert row["deadline_shown"].endswith(" UTC")
        assert approver.count() == 1
        home = attention(queue.page)
        assert home["shown"] is True
        assert home["approvals"]["text_shown"].startswith(
            "1 approval waiting: it must be answered by "
        )
        assert home["approvals"]["action"] == {"kind": "approvals"}
        # The hold opened: its composed text whole, and that text's digest (the fake checks it).
        shown = approver.show(approval)
        assert shown["state"] == "waiting"
        assert shown["text"].startswith("Approval request 00000000000000a1")
        assert shown["text_sha256"] == text_sha256(shown["text"])
        assert "\n".join("".join(line) for line in shown["text_lines"]) == shown["text"]
        assert '"item": "kettle"' in shown["text"]
        # The plan: the whole text and Approve's sentence, before the passkey.
        prepared = approver.prepare(approval)
        assert prepared.status_code == 200, prepared.text
        summary = dict(map(tuple, prepared.json()["summary"]))
        assert summary["The request, whole"] == shown["text"]
        assert summary["Approve"] == APPROVE_SENTENCE
        assert summary["Answer by"] == row["deadline_shown"]
        assert prepared.json()["replaced"] is None
        assert queue.upstream.posts() == []
        confirmed = approver.confirm(prepared.json())
        assert confirmed.status_code == 200, confirmed.text
        assert confirmed.json() == {"approval": approval, "state": "approved"}
        done = queue.decided(approval, "sent: ok")
        assert done["outcome_shown"].startswith("approved here ")
        assert done["state"] == "done"
        [(_, _, sent, _)] = queue.upstream.received
        assert sent["authorization"] == f"Bearer {holdrig.SECRET}"
        assert approver.count() == 0
        assert attention(queue.page)["approvals"] is None
        # The step-up is logged before the decision (H.3), and the decision names the portal.
        lines = queue.rig.lines()
        confirmed_at = next(
            i for i, line in enumerate(lines) if line["event"] == "step_up_confirmed"
        )
        decided_at = next(
            i
            for i, line in enumerate(lines)
            if line["event"] == "approval_decided" and line.get("via") == "portal"
        )
        assert confirmed_at < decided_at
        assert lines[confirmed_at]["action"] == "approval.decide"
        # Decided once: a second approval is told so, and so is a read of it.
        again = decide(queue.page, approval, shown["text_sha256"])
        assert status_reason(again) == (409, "already_decided")
        opened = queue.page.fetch("GET", f"/api/approvals/{approval}")
        assert status_reason(opened) == (409, "already_decided")
        assert again.json()["error"].startswith("Already decided in the portal at ")


def test_deny_with_a_session(tmp_path: Path) -> None:
    with queue_rig(tmp_path, telegram=True) as queue:
        assert queue.telegram is not None
        approver = queue.approver()
        row = queue.waiting("00000000000000b1")
        approval = row["approval"]
        shown = approver.show(approval)
        assert row["surfaces"] == ["portal", "telegram"]
        # The vault's own Telegram surface never sent it (no token): the row says so (G.3).
        assert row["telegram_shown"] == "not delivered to Telegram"
        denied = approver.deny(approval)
        assert denied.status_code == 200, denied.text
        assert denied.json() == {"approval": approval, "state": "denied"}
        decided = queue.decided(approval, "nothing was sent")
        assert decided["outcome_shown"].startswith("denied here ")
        # The other surface's message is closed with the portal's decision (G.6).
        telegram = queue.telegram
        telegram.wait(lambda: (approval, "denied") in telegram.closed)
        [ended] = [hold for hold in telegram.ended if hold.id == approval]
        assert ended.via == "portal"
        assert queue.upstream.posts() == []
        digest = {"text_sha256": shown["text_sha256"]}
        late = queue.page.fetch("POST", f"/api/approvals/{approval}/deny", json=digest)
        assert status_reason(late) == (409, "already_decided")
        assert late.json()["error"].startswith("Already decided in the portal at ")
        assert late.json()["error"].endswith(": denied.")
        opened = queue.page.fetch("GET", f"/api/approvals/{approval}")
        assert status_reason(opened) == (409, "already_decided")


def test_a_stale_decision_decides_nothing(tmp_path: Path) -> None:
    with queue_rig(tmp_path) as queue:
        approval = queue.waiting("00000000000000c1")["approval"]
        stale = queue.approver(ApproverSwitch.STALE_DIGEST)
        assert status_reason(stale.prepare(approval)) == (409, "digest_changed")
        assert status_reason(stale.deny(approval)) == (409, "digest_changed")
        unsigned = queue.approver(ApproverSwitch.NO_SESSION)
        assert status_reason(unsigned.deny(approval)) == (401, "no_session")
        through = queue.approver(ApproverSwitch.DECIDE_DENY)
        assert status_reason(through.prepare(approval)) == (400, "bad_body")
        extra = queue.approver(ApproverSwitch.EXTRA_KEY)
        assert status_reason(extra.prepare(approval)) == (400, "bad_body")
        page = queue.page
        for answer in (
            page.fetch("GET", f"/api/approvals/{UNKNOWN}"),
            page.fetch("POST", f"/api/approvals/{UNKNOWN}/deny", json={"text_sha256": "x"}),
            decide(page, UNKNOWN, "x"),
        ):
            assert status_reason(answer) == (404, "approval_unknown")
        typed = page.fetch("POST", f"/api/approvals/{approval}/deny", json={"text_sha256": 1})
        assert status_reason(typed) == (400, "bad_body")
        # Still waiting, nothing sent, and an honest operator can still decide it.
        assert [row["approval"] for row in queue.approver().queue().waiting] == [approval]
        assert queue.upstream.posts() == []
        assert queue.approver().deny(approval).status_code == 200


def test_both_surfaces_racing(tmp_path: Path) -> None:
    """S20, J4: the first valid decision wins (D.4); the portal is told Telegram's, before the
    passkey, and at the confirm when Telegram decided in between. One forward each."""
    with queue_rig(tmp_path, telegram=True) as queue:
        approver = queue.approver()
        first = queue.approver().show(queue.waiting("00000000000000d1")["approval"])
        assert queue.decide(first["approval"], "telegram", first["text_sha256"]).hold.via == (
            "telegram"
        )
        refused = decide(queue.page, first["approval"], first["text_sha256"])
        assert status_reason(refused) == (409, "already_decided")
        assert refused.json()["error"].startswith("Already decided in Telegram at ")
        assert refused.json()["error"].endswith(": approved.")
        second = queue.approver().show(queue.waiting("00000000000000d2")["approval"])
        prepared = approver.prepare(second["approval"])
        assert prepared.status_code == 200, prepared.text
        queue.decide(second["approval"], "telegram", second["text_sha256"])
        late = approver.confirm(prepared.json())
        assert status_reason(late) == (409, "already_decided")
        assert "in Telegram" in late.json()["error"]
        queue.decided(second["approval"], "sent: ok")
        queue.decided(first["approval"], "sent: ok")
        assert len(queue.upstream.posts()) == 2


def test_a_save_in_another_tab_is_replaced(tmp_path: Path) -> None:
    """H.3, G-11: one prepared action per session, so the approval's prepare in one tab
    cancels the change another tab prepared, and its dialog says so first; the reverse too."""
    with queue_rig(tmp_path) as queue:
        approval = queue.waiting("00000000000000e1")["approval"]
        other = queue.page.browser.page(queue.rig.origin)  # another tab of the session
        [passkey] = other.fetch("GET", "/api/passkeys").json()["passkeys"]
        rename = {"credential": passkey["fingerprint"], "name": "desk"}
        saved = prepared_action(other, "passkey.rename", rename)
        prepared = queue.approver().prepare(approval)
        assert prepared.status_code == 200, prepared.text
        assert prepared.json()["replaced"] == "passkey.rename"
        assert prepared.json()["summary"][0] == [
            "Replaced",
            REPLACED.format(kind="passkey.rename"),
        ]
        assert prepared.json()["summary"][1] == ["Approval request", "00000000000000e1"]
        assertion = queue.authenticator.get(saved["options"], other.origin).body()
        cancelled = other.fetch(
            "POST", f"/api/actions/{saved['action']}/confirm", json={"credential": assertion}
        )
        assert status_reason(cancelled) == (404, "action_unknown")
        again = prepared_action(other, "passkey.rename", rename)
        assert again["replaced"] == "approval.decide"
        assert again["summary"][0][1] == (
            "This replaces the approval.decide you prepared in another tab; it was cancelled."
        )


# --- what the queue shows (S12's way), and what ends a hold -------------------------------------


def test_hostile_strings_are_text(tmp_path: Path) -> None:
    with queue_rig(tmp_path) as queue:
        markup = "<img src=x onerror=alert(1)></pre>\"'&amp;"
        approval = queue.waiting("00000000000000f1", {"note": markup})["approval"]
        answer = queue.page.fetch("GET", f"/api/approvals/{approval}")
        assert answer.headers["content-type"] == "application/json"
        shown = answer.json()
        assert json.dumps(markup)[1:-1] in shown["text"]  # the arguments' JSON, as it is
        assert shown["text_sha256"] == text_sha256(shown["text"])
        # A hidden character is refused before anyone is asked: nothing is listed for it.
        hidden = queue.held("00000000000000f2", {"note": "a\u202eb"})
        assert hidden.status_code == 422, hidden.text
        assert [row["ref"] for row in queue.approver().queue().waiting] == ["00000000000000f1"]


def test_a_policy_change_withdraws_the_hold(tmp_path: Path) -> None:
    with queue_rig(tmp_path) as queue:
        approval = queue.waiting("0000000000000a01")["approval"]
        changed = json.loads(queue.rig.policy_file.read_bytes())
        changed["gateway"]["servers"]["shop"]["tools"]["vault_approval"] = []
        queue.rig.reload(changed)
        withdrawn = decide(queue.page, approval, "x")
        assert status_reason(withdrawn) == (409, "withdrawn")
        decided = queue.decided(approval, "the policy changed")
        assert decided["outcome_shown"].endswith("the policy changed; nothing was sent")
        assert queue.upstream.posts() == []


def test_the_queues_reads_leave_the_idle_clock(tmp_path: Path) -> None:
    """MISS-8: an open queue tab polls its lists and its badge every few seconds; those reads,
    and opening a hold, never move the session's idle clock, so the session idles out as if
    nobody were there. A deny is a change, and moves it."""
    clock = Clock()
    with queue_rig(tmp_path, clock=clock) as queue:
        approval = queue.waiting("0000000000000b01")["approval"]
        app = queue.rig.app

        def seen() -> float:
            [session] = app.sessions.live(clock.wall())
            return session.last_seen

        before = seen()
        clock.advance(600)
        approver = queue.approver()
        approver.queue()
        approver.count()
        approver.show(approval)
        assert seen() == before
        assert approver.deny(approval).status_code == 200
        assert seen() > before + 599
