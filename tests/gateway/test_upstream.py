"""The upstream runtime against the fake MCP server through a real vault (M3 design F, G.3-G.5).

Every test runs the fake and a real vault on threads, and the gateway's upstream pool in the
test's loop, so each request crosses the egress filter, the vault's route and its checks.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import anyio
import httpx2
import pytest
from mcp.shared.exceptions import MCPError
from mcp.types import TextContent, Tool

from tests.fakes.mcp_server import BackChannel, Drift, McpFake, Switch
from tests.gateway.rig import (
    CLIENTS,
    KEYS,
    SERVER,
    Clock,
    deployment,
    pin_of_fake,
    pool_for,
    until,
)
from zoeymcp.gateway import upstream
from zoeymcp.gateway.connstate import Phase
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.pins import project_and_pin
from zoeymcp.gateway.policyclient import PolicyClient, Snapshot
from zoeymcp.gateway.upstream import NotAdmitted, UpstreamError
from zoeymcp.gateway.vaultlink import KeySource, parse_link, view_client


async def settle() -> None:
    for _ in range(5):
        await anyio.sleep(0.05)


pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def review(fake: McpFake, names: list[str] = TOOLS) -> dict[str, str]:
    return {name: pin_of_fake(fake, name) for name in names}


def text(result: object) -> str:
    content = result.content  # type: ignore[attr-defined]
    assert isinstance(content[0], TextContent)
    return content[0].text


@pytest.mark.parametrize("era", ["auto", "legacy"])
async def test_connect_list_and_call(tmp_path: Path, era: str) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era=era) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            evaluation = await pool.wait_ready(connection)
            assert sorted(evaluation.exposed) == sorted(TOOLS)
            result = await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
            assert text(result) == "hi"
            assert connection.era == ("legacy" if era == "legacy" else "modern")
    [call] = fake.calls
    assert (call.name, call.arguments) == ("echo", {"text": "hi"})
    assert {item.path for item in fake.received} == {"/mcp"}


# --- drift (G8) ------------------------------------------------------------------------------


async def announced_until(fake: McpFake, condition: Callable[[], object]) -> None:
    """Wait for ``condition``, announcing ``list_changed`` again every 2 s until it holds.

    The fake announces a drift once, 50 ms after the listing. A modern connection's listen stream
    (or a legacy one's GET stream) that a slow runner opens later misses it, and the next timer
    listing is minutes away. A received announcement is acted on in milliseconds, so a repeat only
    stands in for a lost one.
    """
    with anyio.fail_after(10):
        while not condition():
            with anyio.move_on_after(2):
                await until(condition, timeout=3)
            if not condition():
                await anyio.to_thread.run_sync(fake.announce)


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Listings may follow each other at once."""
    monkeypatch.setattr(upstream, "COALESCE", 0.0)


@pytest.mark.parametrize("era", ["auto", "legacy"])
async def test_drift_announced_by_list_changed_hides_and_marks(
    tmp_path: Path, era: str, quick: None
) -> None:
    fake = McpFake(drift=Drift("description", after=1, notify=True))
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era=era) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            await announced_until(fake, lambda: pool.marks.for_server(SERVER))
            assert pool.marks.for_server(SERVER) == {("echo", pin_of_fake(fake, "echo"))}
            with pytest.raises(NotAdmitted):
                await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
            # Other tools are still served.
            assert (
                text(await pool.call(SERVER, deployed.server, CLIENTS[0], "add", {"a": 1, "b": 2}))
                == "3"
            )
    assert [call.name for call in fake.calls] == ["add"]
    [drift] = deployed.events("tool_drift")
    assert (drift["tool"], drift["pinned"]) == ("echo", pin_of_fake(fake, "echo"))
    assert drift["changed"] == ["description"]
    assert deployed.events("drift_marked") == [
        {**deployed.events("drift_marked")[0], "server": SERVER, "tool": "echo"}
    ]


async def test_a_flip_back_stays_hidden(tmp_path: Path, quick: None) -> None:
    fake = McpFake(drift=Drift("description", after=1, notify=True, flip_back_after=1))
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            await until(lambda: fake.lists >= 3)
            await until(lambda: connection.state.phase is Phase.READY)
            assert connection.tools
            assert connection.state.evaluation is not None
            # The listing matches the review again, but the mark holds.
            assert "echo" not in connection.state.evaluation.exposed
            with pytest.raises(NotAdmitted):
                await pool.admit(connection, "echo")
    # ...and survives a restart of the gateway.
    assert DriftMarks.load(deployed.state).for_server(SERVER) == {
        ("echo", pin_of_fake(fake, "echo"))
    }


async def test_silent_drift_is_caught_by_the_timer(
    tmp_path: Path, quick: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(upstream.Connection, "relist_interval", lambda self: 0.2)
    fake = McpFake(drift=Drift("parameter", after=1, notify=False))
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            await until(lambda: pool.marks.for_server(SERVER))
    assert fake.announced == 0
    assert [line["trigger"] for line in deployed.events("listing")][:2] == ["connect", "timer"]


async def test_per_session_drift_is_caught_on_that_session(tmp_path: Path, quick: None) -> None:
    fake = McpFake(switches={Switch.PER_SESSION})
    # The review is of what the first session sees.
    pinned = {name: pin_of_fake(fake, name) for name in TOOLS}
    first = fake.tools_for(None, 1)
    echo = next(tool for tool in first if tool["name"] == "echo")
    echo["description"] += " Session 1."
    pinned["echo"] = project_and_pin(Tool.model_validate(echo)).pin
    with deployment(tmp_path, fake, include=TOOLS, review=pinned, era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            one = pool.connection(SERVER, deployed.server, CLIENTS[0])
            assert "echo" in (await pool.wait_ready(one)).exposed
            two = pool.connection(SERVER, deployed.server, CLIENTS[1])
            assert one is not two
            assert "echo" not in (await pool.wait_ready(two)).exposed
            # One connection's drift hides the tool for every client of the server.
            with pytest.raises(NotAdmitted, match="marked"):
                await pool.admit(one, "echo")
    assert len({item.issued_session_id for item in fake.requests("initialize")}) == 2


async def test_a_new_session_id_is_a_change_signal(tmp_path: Path, quick: None) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            listings = fake.lists

            request = httpx2.Request("POST", "http://vault.invalid/notes/mcp")
            response = httpx2.Response(200, headers={"mcp-session-id": "another-session"})
            connection.noted(request, response)
            assert connection.state.phase is Phase.STALE
            with pytest.raises(NotAdmitted):
                # STALE: the call waits for the re-listing, which here goes on the old session.
                await pool.admit(connection, "nope")
            await until(lambda: fake.lists > listings)
    assert deployed.events("upstream_session_changed")


# --- sessions, idle, cancellation (F.4, F.6) --------------------------------------------------


async def test_an_expired_session_reconnects_and_the_call_is_retried_once(tmp_path: Path) -> None:
    fake = McpFake(session_404_after=1)
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            call = pool.call
            assert (
                text(await call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "1"})) == "1"
            )
            assert (
                text(await call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "2"})) == "2"
            )
    assert len(fake.requests("initialize")) == 2
    assert [item.status for item in fake.requests("tools/call")] == [200, 404, 200]
    assert [line["reason"] for line in deployed.events("upstream_closed")][:1] == [
        "session_expired"
    ]


async def test_an_idle_connection_closes_with_a_delete(tmp_path: Path) -> None:
    fake = McpFake()
    clock = Clock()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed, clock=clock) as pool:
            await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
            [connection] = pool.connections()
            pool.reap()
            assert connection.running  # not idle yet
            clock.advance(deployed.view.gateway.limits.upstream_idle_timeout + 1)
            pool.reap()
            with anyio.fail_after(10):
                await connection.done.wait()
            assert connection.state.phase is Phase.CLOSED
            pool.reap()
            assert pool.connections() == []
    assert [item.method for item in fake.received].count("DELETE") == 1


async def test_a_held_connection_is_not_idle(tmp_path: Path) -> None:
    fake = McpFake()
    clock = Clock()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed, clock=clock) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            connection.holds += 1
            clock.advance(10_000)
            pool.reap()
            assert connection.running


@pytest.mark.parametrize("era", ["auto", "legacy"])
async def test_cancelling_a_call_cancels_it_upstream(tmp_path: Path, era: str) -> None:
    fake = McpFake()
    arguments = {"steps": 200, "interval": 0.05}
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era=era) as deployed:
        async with pool_for(deployed) as pool:
            async with anyio.create_task_group() as group:
                group.start_soon(pool.call, SERVER, deployed.server, CLIENTS[0], "slow", arguments)
                await until(lambda: any(call.name == "slow" for call in fake.calls))
                group.cancel_scope.cancel()
            assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)


async def test_a_call_past_its_deadline_times_out_and_is_cancelled(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        policy = deployed.server.model_copy(update={"call_timeout": 1})
        async with pool_for(deployed) as pool:
            with pytest.raises(UpstreamError) as raised:
                await pool.call(
                    SERVER, policy, CLIENTS[0], "slow", {"steps": 200, "interval": 0.05}
                )
            assert raised.value.outcome == "timeout"
            assert await anyio.to_thread.run_sync(fake.cancelled.wait, 5)


async def test_progress_is_relayed_as_numbers(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.INJECT_PROGRESS})
    seen: list[tuple[float, float | None]] = []

    async def sink(progress: float, total: float | None) -> None:
        seen.append((progress, total))

    arguments = {"steps": 2, "interval": 0.2}
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            await pool.call(SERVER, deployed.server, CLIENTS[0], "slow", arguments, progress=sink)
    assert seen
    assert all(isinstance(value, float | int) for value, _ in seen)


# --- what fails closed (G16, G14, G9, G10) -----------------------------------------------------


@pytest.mark.parametrize(
    ("switch", "reason"), [(Switch.ENDLESS_CURSOR, "pages"), (Switch.REPEAT_CURSOR, "cursor_loop")]
)
async def test_listing_limits_fail_closed(tmp_path: Path, switch: Switch, reason: str) -> None:
    fake = McpFake(switches={switch})
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            with pytest.raises(NotAdmitted, match="failed"):
                await pool.wait_ready(connection)
            assert connection.state.phase is Phase.FAILED
            with pytest.raises(NotAdmitted):
                await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "x"})
    assert [line["reason"] for line in deployed.events("server_list_failed")][:1] == [reason]
    assert fake.calls == []


async def test_too_many_tools_fail_closed(tmp_path: Path) -> None:
    fake = McpFake()
    limits = {"max_tools_per_server": 2}
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), limits=limits) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            with pytest.raises(NotAdmitted):
                await pool.wait_ready(connection)
    assert [line["reason"] for line in deployed.events("server_list_failed")] == ["tools"]


async def test_an_unsupported_upstream_version_is_refused(tmp_path: Path) -> None:
    fake = McpFake(switches={Switch.UNSUPPORTED_VERSION})
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            with pytest.raises(NotAdmitted):
                await pool.wait_ready(connection)
    assert fake.requests("tools/list") == []


async def test_a_redirect_is_refused_and_never_followed(tmp_path: Path) -> None:
    fake = McpFake(redirect="/mail/send")
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            with pytest.raises(UpstreamError):
                await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
    assert {item.path for item in fake.received} == {"/mcp"}
    assert deployed.events("vault_refused")


async def test_a_call_the_pipeline_didnt_register_is_blocked(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            assert connection.client is not None
            with pytest.raises(MCPError):  # the connection ends
                await connection.client.call_tool("echo", {"text": "unvalidated"})
    assert fake.calls == []
    assert [line["reason"] for line in deployed.events("upstream_request_blocked")] == [
        "tools/call not registered by the pipeline"
    ]


async def test_a_legacy_server_request_gets_an_error_and_reaches_no_one(tmp_path: Path) -> None:
    fake = McpFake(back_channel="sampling")
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
    [answer] = fake.answers
    assert answer.outcome.startswith("error")
    assert deployed.events("upstream_request_refused")


@pytest.mark.parametrize("kind", ["sampling", "elicit_form", "elicit_url", "state_only"])
async def test_a_modern_input_required_is_refused(tmp_path: Path, kind: BackChannel) -> None:
    fake = McpFake(back_channel=kind)
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            with pytest.raises(UpstreamError) as raised:
                await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "hi"})
    assert raised.value.outcome == "input_required"
    assert [call.retry for call in fake.calls] == [False]


# --- policy changes (D.3) and limits (G19) -----------------------------------------------------


async def test_a_new_pin_is_applied_without_reconnecting(tmp_path: Path) -> None:
    fake = McpFake()
    pins = review(fake)
    with deployment(tmp_path, fake, include=TOOLS, review=pins, era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            version = connection.state.version
            repinned = deployed.changed(review={**pins, "echo": "sha256:" + "0" * 64})
            pool.apply(repinned.gateway)
            assert connection.state.evaluation is not None
            assert "echo" not in connection.state.evaluation.exposed
            assert connection.state.version == version + 1
            # The listing still showed the old pin, so the tool is now marked as drifted.
            assert ("echo", "sha256:" + "0" * 64) in pool.marks.for_server(SERVER)
            # Putting the reviewed pin back clears that mark.
            pool.apply(deployed.changed(review=pins).gateway)
            assert "echo" in connection.state.evaluation.exposed
            assert pool.marks.for_server(SERVER) == frozenset()
            assert pool.connections() == [connection]
    assert len(fake.requests("initialize")) == 1


async def test_a_changed_path_closes_the_connection(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            pool.apply(deployed.changed(path="/other").gateway)
            with anyio.fail_after(10):
                await connection.done.wait()
            assert pool.connections() == []
    assert [item.method for item in fake.received].count("DELETE") == 1
    assert [line["reason"] for line in deployed.events("upstream_closing")] == ["policy"]


async def test_an_unassigned_client_loses_its_connection(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake), era="legacy") as deployed:
        async with pool_for(deployed) as pool:
            one = pool.connection(SERVER, deployed.server, CLIENTS[0])
            two = pool.connection(SERVER, deployed.server, CLIENTS[1])
            await pool.wait_ready(one)
            await pool.wait_ready(two)
            pool.apply(deployed.changed(clients=(CLIENTS[1],)).gateway)
            with anyio.fail_after(10):
                await one.done.wait()
            assert pool.connections() == [two]


async def test_a_removed_server_closes_its_connections(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(connection)
            gateway = deployed.view.gateway.model_copy(update={"servers": {}})
            pool.apply(gateway)
            with anyio.fail_after(10):
                await connection.done.wait()


async def test_a_modern_upstream_is_shared_by_every_client(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        async with pool_for(deployed) as pool:
            first = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(first)
            # Once the era is known to be modern, clients share one connection.
            shared = pool.connection(SERVER, deployed.server, CLIENTS[1])
            await pool.wait_ready(shared)
            assert shared.key == (SERVER, "*")
            assert pool.connection(SERVER, deployed.server, CLIENTS[0]) is shared


@pytest.mark.parametrize(("shared", "sessions"), [(False, 2), (True, 1)])
async def test_legacy_sessions_per_client_unless_shared(
    tmp_path: Path, shared: bool, sessions: int
) -> None:
    fake = McpFake()
    options = {"include": TOOLS, "review": review(fake), "era": "legacy", "shared_session": shared}
    with deployment(tmp_path, fake, **options) as deployed:
        async with pool_for(deployed) as pool:
            for client in CLIENTS:
                await pool.call(SERVER, deployed.server, client, "echo", {"text": client})
            await pool.call(SERVER, deployed.server, CLIENTS[0], "echo", {"text": "again"})
    sessions_used = {item.session_id for item in fake.requests("tools/call")}
    assert len(sessions_used) == sessions


async def test_at_the_session_limit_the_least_recently_used_idle_connection_closes(
    tmp_path: Path,
) -> None:
    fake = McpFake()
    clients = ("agent1", "agent2", "agent3")
    options = {"include": TOOLS, "review": review(fake), "era": "legacy", "clients": clients}
    with deployment(tmp_path, fake, limits={"max_upstream_sessions": 2}, **options) as deployed:
        async with pool_for(deployed) as pool:
            for client in clients[:2]:
                await pool.call(SERVER, deployed.server, client, "echo", {"text": client})
            first = next(c for c in pool.connections() if c.key[1] == clients[0])
            await pool.call(SERVER, deployed.server, clients[2], "echo", {"text": "3"})
            with anyio.fail_after(10):
                await first.done.wait()
            assert sorted(c.key[1] for c in pool.connections()) == ["agent2", "agent3"]


async def test_at_the_session_limit_with_nothing_idle_the_gateway_is_busy(tmp_path: Path) -> None:
    fake = McpFake()
    options = {"include": TOOLS, "review": review(fake), "era": "legacy"}
    with deployment(tmp_path, fake, limits={"max_upstream_sessions": 1}, **options) as deployed:
        async with pool_for(deployed) as pool:
            busy = pool.connection(SERVER, deployed.server, CLIENTS[0])
            await pool.wait_ready(busy)
            busy.holds += 1
            with pytest.raises(UpstreamError, match="unavailable"):
                pool.connection(SERVER, deployed.server, CLIENTS[1])


# --- the policy client on the real vault (D.2) -------------------------------------------------


async def test_the_policy_client_fetches_and_long_polls_the_real_view(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:
        applied: list[Snapshot] = []

        async def apply(snapshot: Snapshot, previous: Snapshot | None) -> None:
            applied.append(snapshot)

        http = view_client(parse_link(deployed.vault_url), KeySource(KEYS.gateway_key(1)))
        async with http:
            client = PolicyClient(http, apply, wait=1)
            assert await client.fetch_once() is True
            assert applied[0].view == deployed.view
            started = anyio.current_time()
            assert await client.fetch_once() is True  # a 304 after the wait
            assert anyio.current_time() - started >= 0.9
            assert len(applied) == 1


async def test_the_policy_client_without_the_key_gets_nothing(tmp_path: Path) -> None:
    fake = McpFake()
    with deployment(tmp_path, fake, include=TOOLS, review=review(fake)) as deployed:

        async def apply(snapshot: Snapshot, previous: Snapshot | None) -> None:
            raise AssertionError("no view without the key")

        async with view_client(parse_link(deployed.vault_url), None) as http:
            assert await PolicyClient(http, apply).fetch_once() is False
    assert [line["status"] for line in deployed.events("policy_fetch_failed")] == [403]


# --- the soak (G19) ----------------------------------------------------------------------------


async def test_opening_and_closing_many_sessions_leaves_nothing_behind(tmp_path: Path) -> None:
    fake = McpFake()
    clients = tuple(f"agent{n}" for n in range(200))
    options = {"include": TOOLS, "review": review(fake), "era": "legacy", "clients": clients}
    with deployment(tmp_path, fake, **options) as deployed:
        async with pool_for(deployed) as pool:
            before = len(asyncio.all_tasks())
            for start in range(0, len(clients), 20):
                batch = clients[start : start + 20]
                async with anyio.create_task_group() as group:
                    for client in batch:
                        group.start_soon(
                            pool.call, SERVER, deployed.server, client, "echo", {"text": "x"}
                        )
                for connection in pool.connections():
                    connection.request_close()
                with anyio.fail_after(30):
                    for connection in pool.connections():
                        await connection.done.wait()
                pool.reap()
                assert pool.connections() == []
            await settle()
            assert len(asyncio.all_tasks()) <= before
    assert len(fake.requests("initialize")) == 200
    assert [item.method for item in fake.received].count("DELETE") == 200
