"""The vault hold (M8 design B.1, B.3, B.5-B.8; Z1-Z9, Z23; J2-J3's vault half).

A real vault holds calls on a route that carries a ``vault_approval`` tool, in front of an echo
upstream, with a scripted surface deciding (``tests/gateway/holdrig.py``). Every test runs over
both links (TCP with the gateway key, and the link socket on Linux; D-72's required part):

- what the vault forwards once approved is the canonical form of what it rendered, with the
  credential added only then (Z1, Z2), and nothing goes upstream before;
- every request it can't read with exactly one meaning is refused with its rule's code and
  nothing goes upstream (FM-1 to FM-7, FM-22, FM-31, FM-32, FM-35, FM-36, FM-40);
- deny, expire and withdraw send nothing and write one ending each (FM-10); two answers make one
  forward, and a late one is refused by what happened (FM-11, Z6);
- the caller's leaving: at 2025-11-25 its cancel arrives as a notification the vault consumes
  (FM-29), at 2026-07-28 the dropped stream is the cancel (FM-30), and after an approval the
  forward finishes and its answer is kept, scrubbed (FM-13, FM-33);
- the block, then pending (Z23); a toolkit's write blocks for its tool's ``call_timeout`` less
  30 s; a flood is bounded and told once (FM-19); a policy change withdraws what it no longer
  holds as it was (Z7's rows);
- a stop drains a forward approved just before it (I.2), and a surface that fails leaves the hold
  waiting to its deadline (G.3, J8);
- (step 11) a forward that fails after its approval is refused with the approval's headers too
  (C.2); and the collect path (E.2, F.5): a result handed over once, to its client on its server
  only (T34), a call's status and a withdrawal's reason, the client's own calls (Q46), how a call
  ended across a restart (F.5 step 4), and the body's rules.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import io
import json
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal

import anyio
import httpx
import pytest

from tests.gateway.holdrig import (
    BOUND,
    EPOCH,
    LINKS,
    MODERN,
    OTHER_PIN,
    PIN,
    SECRET,
    SENDER,
    TO,
    Answer,
    HoldRig,
    call,
    headers,
    marker,
)
from tests.gateway.rig import until
from zoeymcp.common import canonical
from zoeymcp.common.mcpwire import PROTOCOL_VERSION_META
from zoeymcp.common.resultstore import (
    MAX_CLIENT_RECORDS,
    Collected,
    PendingCall,
    Status,
    Unknown,
)
from zoeymcp.vault import app as vault_app
from zoeymcp.vault import heldcommit, logs
from zoeymcp.vault.admin import HealthReader
from zoeymcp.vault.approvers import NOTICE, NotShown
from zoeymcp.vault.heldcommit import read_answer
from zoeymcp.vault.holds import MAX_PER_TOOL, Decided, DecideRefusal, Hold
from zoeymcp.vault.request import SSEScrubber

pytestmark = pytest.mark.anyio
REF_A, REF_B, REF_C, REF_D = (f"00000000000000b{n}" for n in "abcd")
SHOP = "/shop/mcp"
COLLECT = "/_zoeymcp/gateway/v1/approvals/collect"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


def modern(ref: str, *, wait: str = "block") -> tuple[bytes, dict[str, str]]:
    """A held call at 2026-07-28, its routing headers equal to its body (E12)."""
    body = call(meta={PROTOCOL_VERSION_META: MODERN})
    sent = headers(
        version=MODERN,
        held=marker(ref, wait=wait),
        **{"mcp-method": "tools/call", "mcp-name": "place_order"},
    )
    return body, sent


async def refused(
    rig: HoldRig,
    http: Any,
    body: bytes,
    sent: dict[str, str],
    status: int,
    code: str,
    path: str = SHOP,
) -> dict[str, Any]:
    """``body`` is refused with ``status`` and ``code``, the vault's own answer; nothing reached
    the upstream or a surface."""
    response = await http.post(path, content=body, headers=sent)
    assert response.status_code == status, response.text
    assert response.headers["x-zoeymcp-vault"] == "refused"
    answer: dict[str, Any] = response.json()
    assert answer["code"] == code
    assert rig.upstream.posts() == []
    assert rig.surface.shown == []
    return answer


def pending(ref: str, now: int) -> PendingCall:
    """A pending record of agent1's, as the vault opens one for a ``wait=pending`` hold."""
    return PendingCall(
        ref=ref,
        client="agent1",
        server="shop",
        tool="place_order",
        holder="vault",
        args_digest="a",
        text_sha256="0" * 64,
        surfaces=frozenset({"portal"}),
        asked_ms=now,
        deadline_ms=now + 3_600_000,
        status="pending",
    )


def mail(ref: str, *, number: int = 1) -> tuple[bytes, dict[str, str]]:
    body = canonical.dumps_canonical(
        {"expect_from": SENDER, "expect_to": TO, "subject": "Hi", "body": "Hello there"}
    )
    return body, {"content-type": "application/json", "idempotency-key": f"{ref}.{number}"}


# --- approved: the bytes rendered are the bytes forwarded (Z1, Z2) -------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_forwarded_bytes_are_the_rendered_bytes(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    rig = HoldRig(tmp_path, link=link)
    arguments = {"qty": 2, "item": "kettle", "note": "two, please"}
    # Admissible, but not canonical: its members in another order, and spaces.
    body = (
        b'{"params": {"arguments": {"qty": 2, "note": "two, please", "item": "kettle"},'
        b' "name": "place_order"}, "id": 1, "method": "tools/call", "jsonrpc": "2.0"}'
    )
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, body, headers(held=marker(REF_A)))
                [hold] = await rig.surface.holds(1)
                assert rig.upstream.received == []  # nothing goes upstream before the approval
                assert (hold.ref, hold.client, hold.server, hold.tool) == (
                    REF_A,
                    "agent1",
                    "shop",
                    "place_order",
                )
                text = hold.text.value
                assert "Client (reported by the gateway): agent1" in text
                assert "Tool: shop \N{RIGHTWARDS ARROW} place_order (pin sha256:cccc" in text
                assert canonical.render_for_approval(arguments) in text
                assert isinstance(await rig.decide(hold), Decided)
            await rig.settled()
            assert rig.kinds(REF_A) == [
                ("asked", None),
                ("decided", "accept"),
                ("outcome", "ok"),
            ]
    response = answer.response
    assert response is not None
    assert response.status_code == 200
    assert response.headers["x-zoeymcp-approval"] == "approved"
    assert response.headers["x-zoeymcp-held-ref"] == REF_A
    assert "x-zoeymcp-vault" not in response.headers
    [(method, path, sent, forwarded)] = rig.upstream.received
    assert (method, path) == ("POST", "/base/mcp")
    expected = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "place_order", "arguments": arguments},
    }
    assert forwarded == canonical.dumps_canonical(expected)
    assert canonical.digest(json.loads(forwarded)["params"]["arguments"]) == canonical.digest(
        arguments
    )
    assert sent["authorization"] == f"Bearer {SECRET}"  # the credential, only now
    assert not any(name.startswith("x-zoeymcp-") for name in sent)
    [held] = events(log, "approval_held")
    assert (held["ref"], held["server"], held["tool"], held["wait"]) == (
        REF_A,
        "shop",
        "place_order",
        "block",
    )
    assert held["surfaces"] == ["portal"]
    assert [r.fields.get("via") for r in rig.records() if r.kind == "decided"] == ["portal"]


@pytest.mark.parametrize("link", LINKS)
async def test_an_unmarked_call_is_held_with_a_minted_ref(tmp_path: Path, link: str) -> None:
    """B.3: no marker (a stale view, or a compromised gateway), still held: the vault mints the
    ref, and the client is shown as not reported."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers())
                [hold] = await rig.surface.holds(1)
                assert hold.client is None
                assert len(hold.ref) == 16
                assert "Client (not reported)" in hold.text.value
                assert isinstance(await rig.decide(hold, "deny"), Decided)
            await rig.settled()
            [asked] = [r for r in rig.records() if r.kind == "asked"]
            assert (asked.ref, asked.fields["client"]) == (hold.ref, "-")
    assert answer.json()["code"] == "approval_declined"
    assert rig.upstream.received == []


# --- what the vault can't read unambiguously (B.2; FM-1 to FM-7, FM-22, FM-32, FM-35) ------------


@pytest.mark.parametrize("link", LINKS)
async def test_batch(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        await refused(rig, http, b"[" + call() + b"]", headers(), 400, "held_batch")


@pytest.mark.parametrize("link", LINKS)
async def test_disguised_type(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    sent = {**headers(), "content-type": "text/plain"}
    async with rig.running() as http:
        await refused(rig, http, call(), sent, 415, "held_content_type")


@pytest.mark.parametrize("link", LINKS)
async def test_encoded(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    sent = headers(**{"content-encoding": "gzip"})
    async with rig.running() as http:
        await refused(rig, http, call(), sent, 400, "held_content_encoding")


@pytest.mark.parametrize("link", LINKS)
async def test_mcp_name_disagrees(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    sent = headers(**{"mcp-name": "cancel_order"})
    async with rig.running() as http:
        await refused(rig, http, call(), sent, 400, "held_header_mismatch")


@pytest.mark.parametrize("link", LINKS)
async def test_param_headers(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    sent = headers(**{"mcp-param-item": "kettle"})
    async with rig.running() as http:
        await refused(rig, http, call(), sent, 400, "held_param_headers")


@pytest.mark.parametrize("link", LINKS)
async def test_method_case(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        answer = await refused(
            rig, http, call(method="Tools/call"), headers(), 400, "held_method_case"
        )
    assert answer["pointer"] == "/method"


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    "token",
    [b"1.50", b"-0", b"1e3", b"0.10000000000000001"],
    ids=["trailing-zero", "minus-zero", "exponent", "excess-precision"],
)
async def test_numbers(tmp_path: Path, link: str, token: bytes) -> None:
    rig = HoldRig(tmp_path, link=link)
    body = (
        b'{"id":1,"jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"qty":'
        + token
        + b'},"name":"place_order"}}'
    )
    async with rig.running() as http:
        answer = await refused(rig, http, body, headers(), 400, "held_number")
    assert answer["pointer"] == "/params/arguments/qty"  # a pointer, never the value


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("name", ["Place_Order", "\uff50lace_order"], ids=["case", "full-width"])
async def test_name_variant(tmp_path: Path, link: str, name: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        await refused(rig, http, call(name), headers(), 400, "held_name_variant")


@pytest.mark.parametrize("link", LINKS)
async def test_extra_header_and_query(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        for extra in ({"x-account": "other"}, {"idempotency-key": "k-0123456789abcdef"}):
            await refused(rig, http, call(), headers(**extra), 400, "held_header_extra")
        await refused(rig, http, call(), headers(), 400, "held_query", f"{SHOP}?param=1")


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    "name",
    ["refund", "place\u200border", "place\u00adorder"],
    ids=["declined", "zero-width", "soft-hyphen"],
)
async def test_unlisted_name(tmp_path: Path, link: str, name: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        await refused(rig, http, call(name), headers(), 400, "held_unlisted")


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("where", ["finished", "open", "pending", "chain-open"])
async def test_ref_reused(tmp_path: Path, link: str, where: str) -> None:
    """FM-36, E19: a marker naming a ref the vault held and finished, holds now, keeps a pending
    record of (the result store), or asked on its chain with no ending yet is refused, nothing
    asked or sent."""
    rig = HoldRig(tmp_path, link=link)
    sent = headers(held=marker(REF_A))
    if where == "pending":
        rig.app.results.open(rig.now_ms(), pending(REF_A, rig.now_ms()))
    elif where == "chain-open":
        await rig.chain.write(
            "asked",
            REF_A,
            critical=True,
            client="agent1",
            server="shop",
            tool="place_order",
            where="vault",
            era="legacy",
            args=rig.chain.digest({}),
            pin=PIN,
            text=rig.chain.text_digest("Approval request"),
            chars=16,
            writes=0,
            expires=rig.now_ms() + 3_600_000,
        )
        assert REF_A in rig.chain.open
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            if where in ("pending", "chain-open"):
                assert not rig.app.holds.knows(REF_A)  # the store's or the chain's half alone
                response = await http.post(SHOP, content=call(), headers=sent)
            else:
                answer = Answer()
                async with anyio.create_task_group() as group:
                    group.start_soon(answer.post, http, SHOP, call(), sent)
                    [hold] = await rig.surface.holds(1)
                    if where == "open":
                        response = await http.post(SHOP, content=call(id=2), headers=sent)
                    await rig.decide(hold, "deny")
                await rig.settled()
                if where == "finished":
                    response = await http.post(SHOP, content=call(), headers=sent)
    assert response.status_code == 409
    assert response.json()["code"] == "held_ref_reused"
    assert len(rig.surface.shown) == (1 if where in ("finished", "open") else 0)
    assert rig.upstream.received == []


@pytest.mark.parametrize("link", LINKS)
async def test_held_by_route(tmp_path: Path, link: str) -> None:
    """FM-31: held on the server's exact path; anywhere else on the route a broad rule admits,
    ``held_path``; on a sibling server's path the held name isn't listed."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        for path in (f"{SHOP}/", "/shop/elsewhere", "/shop/mcp/deeper"):
            await refused(rig, http, call(), headers(), 404, "held_path", path)
        await refused(rig, http, call(), headers(), 400, "held_unlisted", "/shop/notes")


@pytest.mark.parametrize("link", LINKS)
async def test_get_and_delete_pass(tmp_path: Path, link: str) -> None:
    """FM-40: a legacy session's GET stream and its DELETE pass as today, with the credential;
    a marker on them is ``view_stale``, as on any call the vault doesn't hold (Z5)."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        for method in ("GET", "DELETE"):
            response = await http.request(method, SHOP, headers={"mcp-session-id": "s-1"})
            assert (response.status_code, response.text) == (200, "listening")
            stale = await http.request(method, SHOP, headers={"x-zoeymcp-held": marker(REF_A)})
            assert stale.status_code == 409
            assert stale.json()["code"] == "view_stale"
        # A call the vault doesn't hold passes as received; with a marker, it is stale.
        listing = call("list_items", {})
        response = await http.post(SHOP, content=listing, headers=headers())
        assert response.status_code == 200
        marked = headers(held=marker(REF_B))
        stale = await http.post(SHOP, content=listing, headers=marked)
        assert (stale.status_code, stale.json()["code"]) == (409, "view_stale")
    assert [(m, p) for m, p, _, _ in rig.upstream.received] == [
        ("GET", "/base/mcp"),
        ("DELETE", "/base/mcp"),
        ("POST", "/base/mcp"),
    ]
    assert rig.upstream.received[2][3] == listing  # the bytes as received
    assert all(
        sent["authorization"] == f"Bearer {SECRET}" for _, _, sent, _ in rig.upstream.received
    )
    assert rig.surface.shown == []


# --- endings (FM-10, FM-11; Z6) -------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("ending", ["deny", "expire", "withdraw"])
async def test_terminal_states(tmp_path: Path, link: str, ending: str) -> None:
    """FM-10: nothing reaches the upstream; one decision and one outcome on the chain each."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(REF_A)))
                [hold] = await rig.surface.holds(1)
                if ending == "deny":
                    await rig.decide(hold, "deny")
                elif ending == "expire":
                    await rig.later(121)  # past the block: a wait=block hold expires
                else:
                    await rig.reload(held=())
            await rig.settled()
            records = [r for r in rig.records() if r.ref == REF_A]
    code, decision, via, detail = {
        "deny": ("approval_declined", "decline", "portal", None),
        "expire": ("approval_expired", "timeout", "none", None),
        "withdraw": ("approval_withdrawn", "withdrawn", "none", "changed"),
    }[ending]
    assert answer.json()["code"] == code
    assert [r.kind for r in records] == ["asked", "decided", "outcome"]
    assert (records[1].fields["decision"], records[1].fields["via"]) == (decision, via)
    assert (records[2].fields["outcome"], records[2].fields["detail"]) == ("not_sent", detail)
    assert rig.upstream.received == []
    state = {"deny": "denied", "expire": "expired", "withdraw": "withdrawn"}[ending]
    assert rig.surface.closed == [(hold.id, state)]


@pytest.mark.parametrize("link", LINKS)
async def test_two_answers_one_forward(tmp_path: Path, link: str) -> None:
    """FM-11: Telegram and the portal approve at once, and a double tap: the first wins, the
    others are told it was decided, and the call goes upstream once."""
    rig = HoldRig(tmp_path, link=link, surfaces=("portal", "telegram"))
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(REF_A)))
                await rig.surfaces["telegram"].holds(1)
                [hold] = await rig.surface.holds(1)
                assert hold.surfaces == frozenset({"portal", "telegram"})

                def both() -> list[Any]:
                    return [
                        rig.app.decide(hold.id, "approve", via, hold.text_sha256)
                        for via in ("portal", "telegram", "portal")
                    ]

                first, second, third = await rig.on_vault(both)
            await rig.settled()
    assert isinstance(first, Decided)
    assert second == DecideRefusal("already_decided", "portal", first.hold.decided_at)
    assert third == second
    assert answer.json()["result"]["isError"] is False
    assert len(rig.upstream.posts()) == 1
    for surface in rig.surfaces.values():
        assert surface.closed == [(hold.id, "done")]
        # G.6: told of the approval and where it was decided, then of the forward's outcome.
        [approved] = surface.approvals
        assert (approved.id, approved.state, approved.via) == (hold.id, "approved", "portal")
        [ended] = surface.ended
        assert (ended.state, ended.detail, ended.via) == ("done", "ok", "portal")


@pytest.mark.parametrize("link", LINKS)
async def test_late_answer_refused(tmp_path: Path, link: str) -> None:
    """Z6: a decision after the call ran is ``already_decided``; one after it expired is
    ``expired``; one with another text's digest, or from a surface it isn't shown on, refused."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            for ref, ends in ((REF_A, "approve"), (REF_B, "expire")):
                answer = Answer()
                async with anyio.create_task_group() as group:
                    group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(ref)))
                    shown = await rig.surface.holds(1 if ref == REF_A else 2)
                    hold = shown[-1]
                    changed = await rig.decide(hold, digest="0" * 64)
                    assert changed == DecideRefusal("digest_changed")
                    elsewhere = await rig.decide(hold, via="telegram")
                    assert elsewhere == DecideRefusal("unknown")
                    if ends == "approve":
                        await rig.decide(hold)
                    else:
                        await rig.later(121)
                await rig.settled()
                late = await rig.decide(hold)
                assert isinstance(late, DecideRefusal)
                assert late.reason == ("already_decided" if ends == "approve" else "expired")
    assert len(rig.upstream.posts()) == 1


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("order", ["approve-first", "deny-first", "withdraw-first"])
async def test_concurrent_race(tmp_path: Path, link: str, order: str) -> None:
    """FM-11, G-20: 20 decides and withdraws on the vault's loop at once. Exactly one of
    "forwarded once" and "not sent" happens, with one decision and one outcome on the chain."""
    rig = HoldRig(tmp_path, link=link, surfaces=("portal", "telegram"))
    first = order.removesuffix("-first")
    kinds = ["approve", "deny", "withdraw"]
    start = kinds.index(first)
    moves = ((kinds[start:] + kinds[:start]) * 7)[:20]
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(REF_A)))
                [hold] = await rig.surface.holds(1)

                def race() -> list[Any]:
                    found: list[Any] = []
                    for index, move in enumerate(moves):
                        via: Literal["portal", "telegram"] = ("portal", "telegram")[index % 2]
                        if move == "withdraw":
                            rig.app.stop_holds()
                            found.append(None)
                        else:
                            decision: Literal["approve", "deny"] = (
                                "approve" if move == "approve" else "deny"
                            )
                            found.append(rig.app.decide(hold.id, decision, via, hold.text_sha256))
                    return found

                results = await rig.on_vault(race)
            await rig.settled()
    taken = [result for result in results if isinstance(result, Decided)]
    assert len(taken) == (0 if first == "withdraw" else 1)
    forwarded = len(rig.upstream.posts())
    assert forwarded == (1 if first == "approve" else 0)
    assert [kind for kind, _ in rig.kinds(REF_A)] == ["asked", "decided", "outcome"]
    code = answer.response.json().get("code") if answer.response is not None else None
    assert (
        code
        == {"approve": None, "deny": "approval_declined", "withdraw": "approval_withdrawn"}[first]
    )
    if first == "withdraw":
        assert answer.json()["reason"] == "shutdown"  # the vault's stop names itself (step 17)


# --- the caller's leaving (B.6; FM-13, FM-29, FM-30, FM-33; Z23) ---------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_legacy_cancel_withdraws(tmp_path: Path, link: str) -> None:
    """FM-29: at 2025-11-25 the agent's cancel is a notification on its own POST, while the
    original stays open: the vault consumes it (202, nothing forwarded) and withdraws the hold;
    a later approval is refused, and nothing is sent. A cancel naming no held request passes."""
    rig = HoldRig(tmp_path, link=link)
    session = {"mcp-session-id": "s-1"}
    cancel = canonical.dumps_canonical(
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 7}}
    )
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                sent = headers(held=marker(REF_A), **session)
                group.start_soon(answer.post, http, SHOP, call(id=7), sent)
                [hold] = await rig.surface.holds(1)
                # Another session's cancel of that id names nothing held here: it passes.
                other = await http.post(
                    SHOP, content=cancel, headers=headers(**{"mcp-session-id": "s-2"})
                )
                assert other.status_code == 200
                consumed = await http.post(SHOP, content=cancel, headers=headers(**session))
                assert (consumed.status_code, consumed.content) == (202, b"")
            await rig.settled()
            late = await rig.decide(hold)
    assert answer.json()["code"] == "approval_withdrawn"
    assert "reason" not in answer.json()  # the gateway names no stream_lost (step 16)
    assert late == DecideRefusal("withdrawn")
    assert rig.upstream.posts() == [cancel]  # only the other session's
    assert rig.kinds(REF_A) == [
        ("asked", None),
        ("decided", "stream_lost"),
        ("outcome", "not_sent"),
    ]


@pytest.mark.parametrize("link", LINKS)
async def test_a_shared_place_is_cancelled_whole(tmp_path: Path, link: str) -> None:
    """FM-29, B.1 step 5: two held calls with no session may carry one JSON-RPC id; one's ending
    leaves the other's place, and a cancel of that id withdraws every hold still there and is
    never forwarded."""
    rig = HoldRig(tmp_path, link=link)
    cancel = canonical.dumps_canonical(
        {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 7}}
    )
    other = headers(held=marker(REF_B, client="agent2"))
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            first, second = Answer(), Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(first.post, http, SHOP, call(id=7), headers(held=marker(REF_A)))
                [one] = await rig.surface.holds(1)
                group.start_soon(second.post, http, SHOP, call(id=7), other)
                await rig.surface.holds(2)
                await rig.decide(one, "deny")
                await first.done.wait()
                consumed = await http.post(SHOP, content=cancel, headers=headers())
                assert (consumed.status_code, consumed.content) == (202, b"")
            await rig.settled()
    assert first.json()["code"] == "approval_declined"
    assert second.json()["code"] == "approval_withdrawn"
    assert rig.kinds(REF_B)[1:] == [("decided", "stream_lost"), ("outcome", "not_sent")]
    assert rig.upstream.received == []


@pytest.mark.parametrize("link", LINKS)
async def test_a_withdrawal_names_its_reason(tmp_path: Path, link: str) -> None:
    """Step 10's deviation 18, vault side (M8 step 16, K.3): a waiting request's
    ``approval_withdrawn`` names its reason from a closed set, ``operator`` for the host's
    withdraw (via host on the chain) and ``changed`` for a policy change, so the gateway gives
    each its own text."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            first, second = Answer(), Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(first.post, http, SHOP, call(), headers(held=marker(REF_A)))
                await rig.surface.holds(1)
                other = headers(held=marker(REF_B, client="agent2"))
                group.start_soon(second.post, http, SHOP, call(id=2), other)
                await rig.surface.holds(2)
                withdrawn = await rig.on_vault(
                    lambda: rig.app.withdraw_by_host(lambda hold: hold.ref == REF_A)
                )
                assert [hold.ref for hold in withdrawn] == [REF_A]
                await first.done.wait()
                await rig.reload(held=())  # place_order leaves vault_approval
            await rig.settled()
    assert (first.json()["code"], first.json()["reason"]) == ("approval_withdrawn", "operator")
    assert (second.json()["code"], second.json()["reason"]) == ("approval_withdrawn", "changed")
    decided = {r.ref: r.fields for r in rig.records() if r.kind == "decided"}
    assert (decided[REF_A]["decision"], decided[REF_A]["via"]) == ("withdrawn", "host")
    assert (decided[REF_B]["decision"], decided[REF_B]["via"]) == ("withdrawn", "none")
    assert rig.upstream.received == []


async def _dropped(rig: HoldRig, http: Any, body: bytes, sent: dict[str, str]) -> Hold:
    """Send ``body``, wait for its hold, then drop the request (its connection closes)."""
    answer = Answer()
    async with anyio.create_task_group() as group:
        group.start_soon(answer.post, http, SHOP, body, sent)
        [hold] = await rig.surface.holds(1)
        group.cancel_scope.cancel()
    return hold


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("wait", ["block", "pending"])
async def test_modern_cancel_withdraws(tmp_path: Path, link: str, wait: str) -> None:
    """FM-30: at 2026-07-28 a dropped request stream is the cancel: withdrawn (``stream_lost``),
    nothing sent; a ``wait=pending`` hold doesn't detach."""
    rig = HoldRig(tmp_path, link=link)
    body, sent = modern(REF_A, wait=wait)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            hold = await _dropped(rig, http, body, sent)
            await until(lambda: rig.app.holds.get(hold.id) is None, BOUND)
            await rig.settled()
            record = rig.app.results.peek(rig.now_ms(), REF_A, "agent1")
    if wait == "pending":  # its record opened before it was asked, and ends withdrawn
        assert isinstance(record, Status)
        assert record.status == "withdrawn"
    else:
        assert record == Unknown()
    assert rig.kinds(REF_A) == [
        ("asked", None),
        ("decided", "stream_lost"),
        ("outcome", "not_sent"),
    ]
    assert rig.upstream.received == []


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("kind", ["mcp", "toolkit"])
async def test_caller_gone_withdraws(tmp_path: Path, link: str, kind: str) -> None:
    """Z23: a blocking hold ends with its caller; a toolkit's send is modern-style for this (its
    dropped request is its cancel, B.7), at any era."""
    rig = HoldRig(tmp_path, {"mail": True}, link=link)
    if kind == "mcp":
        body, sent = modern(REF_A)
        path = SHOP
    else:
        body, sent = mail(REF_A)
        sent["x-zoeymcp-held"] = marker(REF_A, tool="send_mail")
        path = "/mail/send"
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, path, body, sent)
                [hold] = await rig.surface.holds(1)
                group.cancel_scope.cancel()
            await until(lambda: rig.app.holds.get(hold.id) is None, BOUND)
            await rig.settled()
    assert rig.kinds(REF_A)[1:] == [("decided", "stream_lost"), ("outcome", "not_sent")]
    assert rig.upstream.received == []
    assert rig.mail == []


@pytest.mark.parametrize("link", LINKS)
async def test_departure_after_approval(tmp_path: Path, link: str) -> None:
    """FM-13: the caller leaves after the approval: the forward reads the answer to its end, its
    outcome is on the chain, and the answer goes to the result store for the reported client."""
    rig = HoldRig(tmp_path, link=link)
    gate = rig.upstream.gate = threading.Event()
    body, sent = modern(REF_A)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, body, sent)
                [hold] = await rig.surface.holds(1)
                await rig.decide(hold)
                await anyio.to_thread.run_sync(lambda: rig.upstream.answering.wait(BOUND))
                group.cancel_scope.cancel()
            await until(lambda: rig.app.results.knows(REF_A), BOUND)
            gate.set()
            await until(lambda: rig.app.holds.get(hold.id) is None, BOUND)
            await rig.settled()
            kept = await rig.on_vault(
                lambda: rig.app.results.collect(rig.now_ms(), REF_A, "agent1")
            )
    assert rig.kinds(REF_A) == [("asked", None), ("decided", "accept"), ("outcome", "ok")]
    assert isinstance(kept, Collected)
    assert kept.result.status == 200
    assert json.loads(kept.result.body)["result"]["content"][0]["text"] == "done"
    assert len(rig.upstream.posts()) == 1


@pytest.mark.parametrize("link", LINKS)
async def test_detached_answer_scrubbed(tmp_path: Path, link: str) -> None:
    """FM-33: a hold that detached answers ``approval_pending`` with its deadline; approved, its
    forward runs with no caller, and the upstream's echo of the injected credential is scrubbed
    before the result store keeps it."""
    rig = HoldRig(tmp_path, {"block_seconds": 0}, link=link)
    rig.upstream.echo = True
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            response = await http.post(
                SHOP, content=call(), headers=headers(held=marker(REF_A, wait="pending"))
            )
            assert (response.status_code, response.json()["code"]) == (409, "approval_pending")
            assert response.json()["ref"] == REF_A
            assert response.json()["deadline"].endswith("+00:00")
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold)
            await until(lambda: rig.app.holds.get(hold.id) is None, BOUND)
            await rig.settled()
            kept = await rig.on_vault(
                lambda: rig.app.results.collect(rig.now_ms(), REF_A, "agent1")
            )
            other = await rig.on_vault(
                lambda: rig.app.results.collect(rig.now_ms(), REF_A, "agent2")
            )
    assert isinstance(kept, Collected)
    assert SECRET.encode() not in kept.result.body
    assert b"[REDACTED]" in kept.result.body
    assert other == Unknown()  # bound to its client (T34)
    assert rig.kinds(REF_A)[-1] == ("outcome", "ok")
    [(_, _, forwarded, _)] = rig.upstream.received
    assert forwarded["authorization"] == f"Bearer {SECRET}"


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("wait", ["pending", "block"])
async def test_block_then_pending(tmp_path: Path, link: str, wait: str) -> None:
    """Z23: past ``block_seconds`` undecided, a ``wait=pending`` hold answers pending and lives
    on to its deadline; a ``wait=block`` one expires."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                sent = headers(held=marker(REF_A, wait=wait))
                group.start_soon(answer.post, http, SHOP, call(), sent)
                [hold] = await rig.surface.holds(1)
                assert hold.block_until - hold.asked_at == 120
                await rig.later(60)
                assert rig.app.holds.get(hold.id) is not None  # not yet
                await rig.later(61)
            if wait == "pending":
                assert answer.json()["code"] == "approval_pending"
                live = rig.app.holds.get(hold.id)
                assert live is not None
                assert live.detached
                await rig.later(3600)  # its deadline: expired, with no caller
            await rig.settled()
    code = {"pending": "approval_pending", "block": "approval_expired"}[wait]
    assert answer.json()["code"] == code
    assert rig.kinds(REF_A)[1:] == [("decided", "timeout"), ("outcome", "not_sent")]
    assert rig.upstream.received == []


@pytest.mark.parametrize("link", LINKS)
async def test_no_room_for_a_pending_record_asks_nobody(tmp_path: Path, link: str) -> None:
    """F.2, D.3: a ``wait=pending`` hold's pending record opens before anyone is asked, so a
    result store with no room for its client refuses it ``held_busy``: nothing on the chain, a
    surface or the upstream."""
    rig = HoldRig(tmp_path, link=link)
    for number in range(MAX_CLIENT_RECORDS):
        rig.app.results.open(rig.now_ms(), pending(f"{number:016x}", rig.now_ms()))
    sent = headers(held=marker(REF_A, wait="pending"))
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            await refused(rig, http, call(), sent, 429, "held_busy")
            await rig.settled()
    assert rig.kinds(REF_A) == []


# --- connectors and toolkits (B.7) ----------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize("tool", ["send_mail", None], ids=["tool", "no-tool"])
async def test_toolkit_block_is_the_tools(tmp_path: Path, link: str, tool: str | None) -> None:
    """B.7, G-25: a held send blocks for its toolkit tool's ``call_timeout`` less 30 s, from the
    vault's policy (100 - 30); with no tool named, ``approvers.block_seconds``. Approved, the send
    runs as today, once, and its key's ref is the chain's."""
    rig = HoldRig(tmp_path, {"mail": True}, link=link)
    body, sent = mail(REF_A)
    sent["x-zoeymcp-held"] = marker(REF_A, tool=tool)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, "/mail/send", body, sent)
                [hold] = await rig.surface.holds(1)
                assert hold.block_until - hold.asked_at == (70 if tool else 120)
                assert (hold.server, hold.tool) == (
                    ("mailer", "send_mail") if tool else ("mail-out", "send")
                )
                assert "Mail through mail-out" in hold.text.value
                assert "Subject: Hi" in hold.text.value
                await rig.decide(hold)
            await rig.settled()
            # One held write per call: the call's second write, and its ref again.
            for again in (mail(REF_A, number=2), mail(REF_A)):
                second = await http.post("/mail/send", content=again[0], headers=again[1])
                assert (second.status_code, second.json()["code"]) == (409, "held_second_write")
            config = await http.get("/mail/config", headers={"x-zoeymcp-held": marker(REF_B)})
            assert config.json()["code"] == "view_stale"
    response = answer.response
    assert response is not None
    assert response.status_code == 200
    assert response.headers["x-zoeymcp-approval"] == "approved"
    assert len(rig.mail) == 1
    outcome = [r for r in rig.records() if r.ref == REF_A][-1]
    assert (outcome.fields["outcome"], outcome.fields["detail"]) == ("ok", "sent")
    assert outcome.fields["writes_sent"] == 1


# --- a flood (D.3; FM-19) ------------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_flood_is_bounded(tmp_path: Path, link: str, log: io.StringIO) -> None:
    """FM-19: past the per-tool cap every hold is refused ``held_capacity``, nothing asked; the
    saturation is logged and the surfaces told once per window."""
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answers = [Answer() for _ in range(MAX_PER_TOOL)]
            async with anyio.create_task_group() as group:
                for answer in answers:
                    group.start_soon(answer.post, http, SHOP, call(), headers())
                await rig.surface.holds(MAX_PER_TOOL)
                for _ in range(2):
                    over = await http.post(SHOP, content=call(), headers=headers())
                    assert (over.status_code, over.json()["code"]) == (429, "held_capacity")
                await rig.stop()
            await rig.settled()
    assert [answer.json()["code"] for answer in answers] == ["approval_withdrawn"] * MAX_PER_TOOL
    assert len(rig.surface.shown) == MAX_PER_TOOL
    assert rig.surface.notices == [NOTICE.format(count=1)]
    [saturated] = events(log, "approvals_saturated")
    assert (saturated["refused"], saturated["level"]) == (1, "error")
    health = HealthReader(
        rig.store, lambda: rig.app.policy, chain=rig.chain, saturated=rig.app.saturated
    )
    [finding] = health.report()["approvals"]["findings"]
    assert (finding["code"], finding["level"]) == ("approvals_saturated", "error")
    assert finding["text"].startswith("2 held call(s) refused")
    assert rig.upstream.received == []


# --- a change withdraws what it no longer holds as it was (B.5; Z7) -----------------------------


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    "change",
    [
        {"held": ()},
        {"held": (), "allow": ("list_items", "place_order")},
        {"pins": {"place_order": OTHER_PIN, "cancel_order": PIN, "list_items": PIN}},
        {"surfaces": ("telegram",)},
        {"timeout": 1800},
        {"block_seconds": 60},
        {"attended": False},
    ],
    ids=[
        "vault-approval-off",
        "moved-to-allow",
        "re-pinned",
        "approvers-changed",
        "timeout-lowered",
        "block-changed",
        "client-flags",
    ],
)
async def test_change_withdraws(tmp_path: Path, link: str, change: dict[str, Any]) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                sent = headers(held=marker(REF_A))
                group.start_soon(answer.post, http, SHOP, call(), sent)
                [kept] = await rig.surface.holds(1)
                await rig.reload(cooldown=30)  # a change that holds it as it was keeps it
                assert rig.app.holds.get(kept.id) is not None
                await rig.reload(**change)
            await rig.settled()
    assert answer.json()["code"] == "approval_withdrawn"
    assert rig.kinds(REF_A)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    [outcome] = [r for r in rig.records() if r.ref == REF_A and r.kind == "outcome"]
    assert outcome.fields["detail"] == "changed"
    assert rig.upstream.received == []


# --- what a forward's answer was (B.8) and who shows a hold (D.1) --------------------------------
# (Its outcome, read by common/heldresult.py, is tested in tests/unit/test_heldresult.py.)


@pytest.mark.parametrize(("status", "outcome"), [(200, "unknown"), (500, "upstream_error")])
async def test_an_event_too_large_to_scrub_is_lost(
    monkeypatch: pytest.MonkeyPatch, status: int, outcome: str
) -> None:
    """B.6, B.8: an answer the scrubber can't take whole (an event over its limit) is dropped as
    a too-large one is, so the waiting caller gets 502 ``held_result_too_large`` and never an
    empty success; a 2xx's outcome is unknown (the call may have run)."""
    small = functools.partial(SSEScrubber, max_event_bytes=16)
    monkeypatch.setattr(heldcommit, "SSEScrubber", small)
    upstream = httpx.Response(
        status,
        headers={"content-type": "text/event-stream"},
        content=b"data: " + b"x" * 64 + b"\n\n",
    )
    answer = await read_answer(upstream, [b"sk-secret"], 1)
    assert (answer.too_large, answer.body, answer.outcome) == (True, b"", outcome)


class Broken:
    """A surface that fails at everything."""

    name = "portal"

    async def show(self, hold: Hold) -> Any:
        raise RuntimeError("down")

    async def approved(self, hold: Hold) -> None:
        raise RuntimeError("down")

    async def close(self, hold: Hold, outcome: str) -> None:
        raise RuntimeError("down")

    async def notice(self, text: str) -> None:
        raise RuntimeError("down")


class TooLong(Broken):
    """A surface that says it can't carry the text (G.4)."""

    name = "telegram"

    async def show(self, hold: Hold) -> Any:
        return NotShown("telegram", "telegram_too_long", 422)

    async def close(self, hold: Hold, outcome: str) -> None:
        pass


@pytest.mark.parametrize("link", LINKS)
async def test_a_failing_surface_leaves_the_hold_waiting(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    """G.3, J8: a surface whose show fails (or overruns its bound) may still deliver the hold, so
    the hold waits on; decided nowhere, it expires at its end, and nothing is sent."""
    rig = HoldRig(tmp_path, link=link)
    rig.app.hub.install(Broken())  # type: ignore[arg-type]
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(REF_A)))
                await until(lambda: events(log, "approver_surface_failed"), BOUND)
                live = rig.app.holds.by_ref(REF_A)
                assert live is not None
                assert live.state == "held"
                await rig.later(121)  # past its block: a wait=block hold expires
            await rig.settled()
    assert answer.json()["code"] == "approval_expired"
    assert rig.kinds(REF_A)[1:] == [("decided", "timeout"), ("outcome", "not_sent")]
    failed = events(log, "approver_surface_failed")
    assert [(f["call"], f["error_type"]) for f in failed] == [
        ("show", "RuntimeError"),
        ("close", "RuntimeError"),
    ]
    assert rig.upstream.received == []


@pytest.mark.parametrize("link", LINKS)
async def test_a_text_no_surface_can_carry_is_refused(tmp_path: Path, link: str) -> None:
    """G.4: every surface saying it can't show the hold refuses it with that surface's code,
    and nothing waits for an answer nobody can give; nothing is sent."""
    rig = HoldRig(tmp_path, link=link, surfaces=("telegram",))
    rig.app.hub.install(TooLong())  # type: ignore[arg-type]
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            response = await http.post(SHOP, content=call(), headers=headers(held=marker(REF_A)))
            await rig.settled()
    assert (response.status_code, response.json()["code"]) == (422, "telegram_too_long")
    assert rig.kinds(REF_A)[1:] == [("decided", "withdrawn"), ("outcome", "not_sent")]
    assert rig.upstream.received == []


@pytest.mark.parametrize("link", LINKS)
async def test_stop_waits_for_an_approval_being_recorded(
    tmp_path: Path, link: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """I.2, Z9: approved just before the stop, a hold whose ``decided accept`` is still being
    written isn't in the registry yet; the stop's drain waits for it to enter, then for its
    forward, whose outcome reaches the chain. (No grace for the endings here, so a drain that
    didn't wait would be over at once.)"""
    rig = HoldRig(tmp_path, link=link)
    monkeypatch.setattr(vault_app, "EDIT_GRACE", 0)
    write = rig.chain.write
    gates: list[asyncio.Event] = []

    async def slow(kind: Any, ref: str | None, *, critical: bool, **fields: Any) -> Any:
        if kind == "decided" and fields.get("decision") == "accept":
            gate = asyncio.Event()
            gates.append(gate)
            await gate.wait()
        return await write(kind, ref, critical=critical, **fields)

    monkeypatch.setattr(rig.chain, "write", slow)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(REF_A)))
                [hold] = await rig.surface.holds(1)

                def approve_then_stop() -> asyncio.Future[None]:
                    decided = rig.app.decide(hold.id, "approve", "portal", hold.text_sha256)
                    assert isinstance(decided, Decided)
                    rig.app.stop_holds()
                    return asyncio.ensure_future(rig.app.drain_holds())

                drained = await rig.on_vault(approve_then_stop)
                await until(lambda: gates, BOUND)
                assert not drained.done()  # it waits for the forward to enter the registry
                await rig.on_vault(gates[0].set)
            await until(drained.done, BOUND)
            await rig.settled()
    assert rig.kinds(REF_A) == [("asked", None), ("decided", "accept"), ("outcome", "ok")]
    assert answer.json()["result"]["isError"] is False
    assert len(rig.upstream.posts()) == 1


# --- a forward that fails after its approval (C.2; step 10's deviation 17) ------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_a_failed_forward_still_says_approved(tmp_path: Path, link: str) -> None:
    """The upstream answers the approved forward with a redirect, which the vault never
    follows: its refusal carries the approval's headers, and the outcome its chain says
    (``upstream_error``), so the gateway records the call approved as it ended."""
    rig = HoldRig(tmp_path, link=link)
    rig.upstream.redirect = True
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            answer = Answer()
            async with anyio.create_task_group() as group:
                group.start_soon(answer.post, http, SHOP, call(), headers(held=marker(REF_A)))
                [hold] = await rig.surface.holds(1)
                await rig.decide(hold)
            await rig.settled()
    response = answer.response
    assert response is not None
    assert response.status_code == 502
    assert response.headers["x-zoeymcp-vault"] == "refused"
    assert response.headers["x-zoeymcp-approval"] == "approved"
    assert response.headers["x-zoeymcp-held-ref"] == REF_A
    assert response.json()["outcome"] == "upstream_error"
    assert rig.kinds(REF_A)[1:] == [("decided", "accept"), ("outcome", "upstream_error")]
    assert len(rig.upstream.posts()) == 1


@pytest.mark.parametrize("link", LINKS)
async def test_a_refusal_before_any_approval_says_nothing_of_one(tmp_path: Path, link: str) -> None:
    rig = HoldRig(tmp_path, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            response = await http.post(SHOP, content=b"[]", headers=headers(held=marker(REF_A)))
    assert response.headers["x-zoeymcp-vault"] == "refused"
    assert "x-zoeymcp-approval" not in response.headers
    assert "x-zoeymcp-held-ref" not in response.headers
    assert "outcome" not in response.json()


# --- collecting a held call's result (E.2, F.5) -----------------------------------------------


async def collect(
    http: Any, ref: str | None, *, client: str = "agent1", server: str = "shop"
) -> dict[str, Any]:
    """The collect path's answer for ``ref`` (None: the client's own calls on ``server``)."""
    body: dict[str, str] = {"epoch": EPOCH, "client": client, "server": server}
    if ref is not None:
        body["ref"] = ref
    sent = {"content-type": "application/json"}
    response = await http.post(COLLECT, content=canonical.dumps_canonical(body), headers=sent)
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    found: dict[str, Any] = response.json()
    assert found["v"] == 1
    return found


@pytest.mark.parametrize("link", LINKS)
async def test_collect_hands_the_result_over_once(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    """F.5: a call that answered pending, approved with nobody waiting: its result once, with the
    id of the request it answers; then its status, ``collected``. Another client, or another
    server, reads it as unknown, and takes nothing (T34, Z17)."""
    rig = HoldRig(tmp_path, {"block_seconds": 0}, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            sent = headers(held=marker(REF_A, wait="pending"))
            response = await http.post(SHOP, content=call(id="call-7"), headers=sent)
            assert response.json()["code"] == "approval_pending"
            waiting = await collect(http, REF_A)
            [hold] = await rig.surface.holds(1)
            await rig.decide(hold)
            await until(lambda: rig.app.holds.get(hold.id) is None, BOUND)
            await rig.settled()
            other_client = await collect(http, REF_A, client="agent2")
            other_server = await collect(http, REF_A, server="notes")
            first = await collect(http, REF_A)
            again = await collect(http, REF_A)
            listed = await collect(http, None)
            none_listed = await collect(http, None, client="agent2")
    assert (waiting["state"], waiting["outcome"], waiting["collected"]) == ("pending", None, False)
    assert waiting["tool"] == "place_order"
    assert waiting["deadline"].endswith("+00:00")
    assert "result" not in waiting
    assert other_client == {"v": 1, "ref": REF_A, "state": "unknown"}
    assert other_server == other_client
    assert (first["state"], first["outcome"]) == ("done", "ok")
    result = first["result"]
    assert (result["status"], result["content_type"], result["request_id"]) == (
        200,
        "application/json",
        "call-7",
    )
    answered = json.loads(base64.b64decode(result["body"]))
    assert answered["result"]["content"][0]["text"] == "done"
    assert (again["state"], again["collected"]) == ("done", True)
    assert "result" not in again
    [row] = listed["calls"]
    assert (row["ref"], row["tool"], row["state"], row["collected"]) == (
        REF_A,
        "place_order",
        "done",
        True,
    )
    assert "result" not in row
    assert none_listed == {"v": 1, "calls": []}
    assert [e["ref"] for e in events(log, "approval_collected")] == [REF_A]


@pytest.mark.parametrize("link", LINKS)
async def test_collect_names_a_withdrawals_reason(tmp_path: Path, link: str) -> None:
    """F.5 step 7: a pending call a policy change withdrew says so, with its reason."""
    rig = HoldRig(tmp_path, {"block_seconds": 0}, link=link)
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            sent = headers(held=marker(REF_A, wait="pending"))
            await http.post(SHOP, content=call(), headers=sent)
            await rig.surface.holds(1)
            await rig.reload(held=())
            await rig.settled()
            found = await collect(http, REF_A)
    assert (found["state"], found["detail"], found["outcome"]) == ("withdrawn", "changed", None)
    assert "restarted" not in found


@pytest.mark.parametrize("link", LINKS)
async def test_collect_after_a_restart_says_how_the_call_ended(tmp_path: Path, link: str) -> None:
    """F.5 step 4, J10: after a restart the result store is empty, and the chain's recent
    endings say how each call ended, to its own client only: one approved and run before (its
    result lost with the process), and one the restart ended unsent."""
    first = HoldRig(tmp_path, link=link)
    chain = first.chain
    asked = {
        "client": "agent1",
        "server": "shop",
        "tool": "place_order",
        "where": "vault",
        "era": "modern",
        "args": chain.digest({"item": "kettle"}),
        "pin": PIN,
        "text": chain.text_digest("t"),
        "chars": 1,
        "writes": 0,
        "expires": HoldRig.now_ms() + 3_600_000,
    }
    for ref in (REF_A, REF_B):
        await chain.write("asked", ref, critical=True, **asked)
    await chain.write("decided", REF_A, critical=True, decision="accept", waited_ms=1, via="portal")
    await chain.write(
        "outcome",
        REF_A,
        critical=True,
        outcome="ok",
        detail=None,
        writes_sent=0,
        writes_unknown=0,
    )
    rig = HoldRig(tmp_path, link=link)  # a new vault process on the same chain
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            ran = await collect(http, REF_A)
            unsent = await collect(http, REF_B)
            other = await collect(http, REF_A, client="agent2")
            again = await collect(http, REF_A)
    assert ran == {"v": 1, "ref": REF_A, "state": "done", "detail": "ok", "restarted": True}
    assert unsent == {
        "v": 1,
        "ref": REF_B,
        "state": "withdrawn",
        "detail": "restart",
        "restarted": True,
    }
    assert other == {"v": 1, "ref": REF_A, "state": "unknown"}
    assert again == ran  # no result to hand over, so nothing is used up


@pytest.mark.parametrize("link", LINKS)
@pytest.mark.parametrize(
    ("body", "sent", "status", "code"),
    [
        (b"{}", {"content-type": "application/json"}, 400, "invalid"),
        (b"not json", {"content-type": "application/json"}, 400, "invalid"),
        (b'{"epoch":"0123456789ab","client":"agent1","server":"shop","ref":"x"}', {}, 400, None),
        (b"{}", {"content-type": "text/plain"}, 415, "content_type"),
        (b"{" + b" " * 1024 + b"}", {"content-type": "application/json"}, 413, "too_large"),
    ],
    ids=["no-fields", "not-json", "bad-ref", "content-type", "too-large"],
)
async def test_collect_refuses_a_body_it_cant_read(
    tmp_path: Path, link: str, body: bytes, sent: dict[str, str], status: int, code: str | None
) -> None:
    rig = HoldRig(tmp_path, link=link)
    sent = {"content-type": "application/json", **sent}
    async with rig.running() as http:
        with anyio.fail_after(BOUND):
            response = await http.post(COLLECT, content=body, headers=sent)
            queried = await http.post(
                COLLECT + "?ref=x", content=b"{}", headers={"content-type": "application/json"}
            )
            got = await http.get(COLLECT)
    assert response.status_code == status, response.text
    assert response.json().get("code") == (code or "invalid")
    assert queried.status_code == 400
    assert (got.status_code, got.headers["allow"]) == (405, "POST")
