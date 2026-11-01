"""The scripted queue approver sends what the queue's page will, and each switch misbehaves.

The portal's queue arrives in step 15, so a stand-in answers here: the routes of M8 design H.2 and
H.3, keeping only what the approver needs (the session, the ``Origin``, each body's exact keys,
the digest binding, the step-up's challenge), in process through ``browser.asgi_client``.
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .approver import (
    ACTIONS,
    COUNT,
    KIND,
    QUEUE,
    STALE_TEXT,
    ApproverSwitch,
    QueueApprover,
    text_sha256,
)
from .authenticator import (
    SoftAuthenticator,
    b64url,
    b64url_decode,
    creation_options,
    request_options,
)
from .browser import SESSION_HEADER, SESSION_KEY, Browser, asgi_client

ORIGIN = "http://localhost:8081"
SESSION = "fake-session-token-0001"
HOLD = "AAAAAAAAAAAAAAAA"
OTHER = "BBBBBBBBBBBBBBBB"
TEXT = "Approval request 0123456789abcdef: notes \u2192 delete_note\nid: 7\nend of request"
APPROVE_SENTENCE = "Approve runs this one call, exactly as shown."


class StandIn:
    """The queue's routes, as H.2 and H.3 shape them, over two waiting holds."""

    def __init__(self, credentials: list[bytes]) -> None:
        self.credentials = credentials
        self.holds = {
            HOLD: {"approval": HOLD, "server": "notes", "tool": "delete_note", "text": TEXT},
            OTHER: {"approval": OTHER, "server": "notes", "tool": "send_note", "text": "Other"},
        }
        self.states = dict.fromkeys(self.holds, "waiting")
        self.challenges: dict[str, tuple[bytes, str]] = {}
        # A route whose digest isn't its text's (the approver must fail loudly).
        self.lying = False
        # Each POST's path and body, as sent.
        self.posted: list[tuple[str, Any]] = []

    def app(self) -> Starlette:
        return Starlette(
            routes=[
                Route(COUNT, self.count, methods=["GET"]),
                Route(QUEUE, self.queue, methods=["GET"]),
                Route(QUEUE + "/{approval}", self.show, methods=["GET"]),
                Route(QUEUE + "/{approval}/deny", self.deny, methods=["POST"]),
                Route(ACTIONS, self.prepare, methods=["POST"]),
                Route(ACTIONS + "/{action}/confirm", self.confirm, methods=["POST"]),
            ]
        )

    def admitted(self, request: Request) -> JSONResponse | None:
        if request.headers.get(SESSION_HEADER) != SESSION:
            return refusal(401, "no_session")
        if request.method == "POST" and request.headers.get("origin") != ORIGIN:
            return refusal(403, "origin")
        return None

    async def body(self, request: Request) -> Any:
        body = json.loads(await request.body())
        self.posted.append((request.url.path, body))
        return body

    def rows(self, state: str) -> list[dict[str, Any]]:
        return [
            {key: hold[key] for key in ("approval", "server", "tool")}
            for name, hold in self.holds.items()
            if (self.states[name] == "waiting") == (state == "waiting")
        ]

    async def count(self, request: Request) -> JSONResponse:
        refused = self.admitted(request)
        return refused or JSONResponse({"count": len(self.rows("waiting"))})

    async def queue(self, request: Request) -> JSONResponse:
        refused = self.admitted(request)
        return refused or JSONResponse(
            {"waiting": self.rows("waiting"), "decided": self.rows("decided")}
        )

    async def show(self, request: Request) -> JSONResponse:
        refused = self.admitted(request)
        if refused is not None:
            return refused
        hold = self.holds[request.path_params["approval"]]
        name = str(hold["approval"])
        return JSONResponse(
            {
                "approval": name,
                "text": hold["text"],
                "text_sha256": text_sha256("not " + hold["text"] if self.lying else hold["text"]),
                "state": self.states[name],
            }
        )

    def moved(self, name: str, digest: Any) -> JSONResponse | None:
        if self.states.get(name) != "waiting":
            return refusal(409, "already_decided")
        if digest != text_sha256(self.holds[name]["text"]):
            return refusal(409, "digest_changed")
        return None

    async def deny(self, request: Request) -> JSONResponse:
        refused = self.admitted(request)
        if refused is not None:
            return refused
        body = await self.body(request)
        if not isinstance(body, dict) or sorted(body) != ["text_sha256"]:
            return refusal(400, "bad_body")
        name = request.path_params["approval"]
        refused = self.moved(name, body["text_sha256"])
        if refused is not None:
            return refused
        self.states[name] = "denied"
        return JSONResponse({"state": "denied"})

    async def prepare(self, request: Request) -> JSONResponse:
        refused = self.admitted(request)
        if refused is not None:
            return refused
        body = await self.body(request)
        data = body.get("data") if isinstance(body, dict) else None
        if (
            body.get("kind") != KIND
            or not isinstance(data, dict)
            or sorted(data) != ["approval", "decision", "text_sha256"]
            or data["decision"] != "approve"
        ):
            return refusal(400, "bad_body")
        refused = self.moved(data["approval"], data["text_sha256"])
        if refused is not None:
            return refused
        action, challenge = secrets.token_hex(8), secrets.token_bytes(32)
        self.challenges[action] = (challenge, data["approval"])
        hold = self.holds[data["approval"]]
        options = request_options(challenge, allow=self.credentials)
        summary = [["Text", hold["text"]], ["Server", hold["server"]], ["", APPROVE_SENTENCE]]
        return JSONResponse(
            {"action": action, "kind": KIND, "summary": summary, "options": options}
        )

    async def confirm(self, request: Request) -> JSONResponse:
        refused = self.admitted(request)
        if refused is not None:
            return refused
        body = await self.body(request)
        held = self.challenges.pop(request.path_params["action"], None)
        if held is None or sorted(body) != ["credential"]:
            return refusal(400, "bad_body")
        client_data = json.loads(b64url_decode(body["credential"]["client_data_json"]))
        challenge, name = held
        if client_data != {
            "type": "webauthn.get",
            "challenge": b64url(challenge),
            "origin": ORIGIN,
            "crossOrigin": False,
        }:
            return refusal(403, "step_up_refused")
        self.states[name] = "approved"
        return JSONResponse({"state": "approved"})


def refusal(status: int, reason: str) -> JSONResponse:
    return JSONResponse({"error": reason.replace("_", " "), "reason": reason}, status_code=status)


@pytest.fixture
def world() -> Iterator[tuple[StandIn, QueueApprover]]:
    authenticator = SoftAuthenticator()
    options = creation_options(secrets.token_bytes(32), b"operator")
    created = authenticator.create(options, ORIGIN)
    queue = StandIn([created.id])
    with Browser(remote={ORIGIN: asgi_client(queue.app(), ORIGIN)}) as browser:
        page = browser.page(ORIGIN)
        page.storage[SESSION_KEY] = SESSION
        yield queue, QueueApprover(page, authenticator)


def test_it_lists_counts_and_opens(world: tuple[StandIn, QueueApprover]) -> None:
    queue, approver = world
    listed = approver.queue()
    assert [row["approval"] for row in listed.waiting] == [HOLD, OTHER]
    assert listed.decided == []
    assert approver.count() == 2
    shown = approver.show(HOLD)
    assert (shown["text"], shown["text_sha256"]) == (TEXT, text_sha256(TEXT))
    assert queue.posted == []


def test_it_approves_with_a_step_up(world: tuple[StandIn, QueueApprover]) -> None:
    queue, approver = world
    answer = approver.approve(HOLD)
    assert answer.status_code == 200, answer.text
    assert answer.json() == {"state": "approved"}
    [prepared] = approver.prepared
    assert prepared["summary"][0] == ["Text", TEXT]
    (prepare_path, prepare_body), (confirm_path, confirm_body) = queue.posted
    assert prepare_path == ACTIONS
    assert prepare_body == {
        "kind": KIND,
        "data": {"approval": HOLD, "text_sha256": text_sha256(TEXT), "decision": "approve"},
    }
    assert confirm_path == f"{ACTIONS}/{prepared['action']}/confirm"
    assert sorted(confirm_body["credential"]) == [
        "authenticator_data",
        "client_data_json",
        "id",
        "signature",
        "user_handle",
    ]
    assert [row["approval"] for row in approver.queue().decided] == [HOLD]
    assert approver.count() == 1


def test_it_denies_with_its_session_alone(world: tuple[StandIn, QueueApprover]) -> None:
    queue, approver = world
    answer = approver.deny(OTHER)
    assert answer.json() == {"state": "denied"}
    assert queue.posted == [(f"{QUEUE}/{OTHER}/deny", {"text_sha256": text_sha256("Other")})]
    assert approver.prepared == []
    assert queue.challenges == {}


def test_a_decided_hold_is_refused(world: tuple[StandIn, QueueApprover]) -> None:
    _, approver = world
    assert approver.deny(HOLD).status_code == 200
    again = approver.approve(HOLD)
    assert (again.status_code, again.json()["reason"]) == (409, "already_decided")


def test_a_digest_that_isnt_the_texts_fails_loudly(world: tuple[StandIn, QueueApprover]) -> None:
    queue, approver = world
    queue.lying = True
    with pytest.raises(AssertionError):
        approver.approve(HOLD)
    with pytest.raises(AssertionError):
        approver.deny(HOLD)
    assert queue.posted == []


def stale(approver: QueueApprover) -> list[tuple[int, str]]:
    return [reason_of(approver.approve(HOLD)), reason_of(approver.deny(HOLD))]


def no_session(approver: QueueApprover) -> list[tuple[int, str]]:
    return [reason_of(approver.deny(HOLD))]


def approve_hold(approver: QueueApprover) -> list[tuple[int, str]]:
    return [reason_of(approver.approve(HOLD))]


def reason_of(answer: Any) -> tuple[int, str]:
    return answer.status_code, str(answer.json()["reason"])


def decide(digest: str, decision: str, **extra: Any) -> tuple[str, Any]:
    """A prepare of ``approval.decide`` for ``HOLD``, as posted."""
    data = {"approval": HOLD, "text_sha256": digest, "decision": decision, **extra}
    return ACTIONS, {"kind": KIND, "data": data}


STALE = text_sha256(STALE_TEXT)
DIGEST = text_sha256(TEXT)
# Each switch: what to do, the refusals it meets, and what it posted (its own misbehaviour).
SWITCHES: dict[
    ApproverSwitch,
    tuple[Callable[[QueueApprover], Any], list[tuple[int, str]], list[tuple[str, Any]]],
] = {
    ApproverSwitch.STALE_DIGEST: (
        stale,
        [(409, "digest_changed"), (409, "digest_changed")],
        [decide(STALE, "approve"), (f"{QUEUE}/{HOLD}/deny", {"text_sha256": STALE})],
    ),
    # Refused before its body is read.
    ApproverSwitch.NO_SESSION: (no_session, [(401, "no_session")], []),
    ApproverSwitch.DECIDE_DENY: (approve_hold, [(400, "bad_body")], [decide(DIGEST, "deny")]),
    ApproverSwitch.EXTRA_KEY: (
        approve_hold,
        [(400, "bad_body")],
        [decide(DIGEST, "approve", all=True)],
    ),
}


def test_the_switch_table_covers_every_switch() -> None:
    assert set(SWITCHES) == set(ApproverSwitch)


@pytest.mark.parametrize("switch", list(ApproverSwitch), ids=[s.value for s in ApproverSwitch])
def test_each_switch(world: tuple[StandIn, QueueApprover], switch: ApproverSwitch) -> None:
    queue, approver = world
    approver.switches = {switch}
    act, expected, posted = SWITCHES[switch]
    assert act(approver) == expected
    assert queue.posted == posted
    assert queue.states[HOLD] == "waiting"
    assert approver.prepared == []
