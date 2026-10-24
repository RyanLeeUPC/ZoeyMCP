"""Acceptance: J2's CLI half, a server that adds tools (M6 design J.5; Y20, Y29).

The fake lists three new tools; ``zoeymcp review <server>`` names them as tools nobody reviewed
and exits 1, and the summary, from the gateway's status, says the same; a review's
``--decline-rest`` snippet, committed, makes both quiet; and a declined tool whose definition
changes counts again. Over real sockets and real TLS, as S10's rows are (``test_mcp_shapes``).
Home and health come with the status report (step 7).
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.mcp_server import ADDED, AddTools, McpFake, base_tools
from tests.gateway.rig import Running, agent, pin_of_fake, until
from zoeymcp.common.policy.attention import loaded, quiet
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import server as gateway_server

from .conftest import serve_tls
from .gateway import CLIENTS, SERVER, GatewayDeployment
from .test_mcp_shapes import KEY, sweep
from .tls import ProviderCA

pytestmark = pytest.mark.anyio

# Every base tool but echo is included; echo was declined at a review before, and the fake
# changes echo's description when asked (change_tool), so it is the one that comes back.
TOOLS = {
    "add": "allow",
    "slow": "allow",
    "counter": "allow",
    "report": "allow",
    "lookup": "approve",
}
NOBODY = "3 listed that nobody reviewed: export_all, purge, share"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@contextlib.contextmanager
def deployed(tmp_path: Path, ca: ProviderCA, fake: McpFake) -> Iterator[GatewayDeployment]:
    assert sorted([*TOOLS, "echo"]) == sorted(tool["name"] for tool in base_tools())
    with serve_tls(fake.app(), ca, lifespan=True) as upstream:
        gateway = GatewayDeployment(
            tmp_path,
            upstream,
            ca,
            secrets={"notes-key": KEY},
            tools=TOOLS,
            pins={name: pin_of_fake(fake, name) for name in TOOLS},
            declined={"echo": pin_of_fake(fake, "echo")},
        )
        yield gateway
    sweep(gateway.seen, clients=gateway.clients, gateway_key=gateway.vault.keys.gateway_key(1),
          fake=fake)  # fmt: skip


def attention(running: Running) -> dict[str, Any] | None:
    """The server's attention decision in the gateway's status, as ``review`` reads it; None
    before a connection has listed the server."""
    found: dict[str, Any] | None = gateway_server.status(running.app)["servers"][SERVER][
        "attention"
    ]
    return found


def is_quiet(running: Running) -> bool:
    found = attention(running)
    return found is not None and quiet(loaded(found))


def summary_row(out: str) -> list[str]:
    """The summary's lines for the server: its row, and the line under it if there is one."""
    lines = out.splitlines()
    [at] = [index for index, line in enumerate(lines) if line.startswith(f"{SERVER}  ")]
    return [line for line in lines[at : at + 2] if line == lines[at] or line.startswith("  ")]


async def test_one_attention(tmp_path: Path, ca: ProviderCA) -> None:
    """Y29 for every state J2 walks: ``review <server>``'s exit code and line, and the summary's,
    from the gateway's status, agree, before the new tools, with them, and once declined."""
    # A legacy upstream keeps one connection per client, so each client's agent makes the
    # gateway list the server again.
    fake = McpFake(mode="legacy", key=KEY, key_header="x-api-key")
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        async with agent(running, CLIENTS[0]) as first:
            await first.list_tools()
            await until(lambda: is_quiet(running))
            reviewed = gateway.cli(running, "review", SERVER)
            summary = gateway.cli(running, "review")
            assert (reviewed[0], summary[0]) == (0, 0), reviewed[1] + summary[1]
            assert len(summary_row(summary[1])) == 1
            assert "nobody reviewed" not in reviewed[1]
            # From the next listing on, the server lists three more tools.
            fake.add_tools = AddTools(after=fake.lists)
            async with agent(running, CLIENTS[1]) as second:
                listed = sorted(tool.name for tool in (await second.list_tools()).tools)
                assert listed == sorted(TOOLS)  # not included, so not served
                await until(lambda: (attention(running) or {}).get("new") == list(ADDED))
                reviewed = gateway.cli(running, "review", SERVER)
                summary = gateway.cli(running, "review")
                assert (reviewed[0], summary[0]) == (1, 1)
                assert NOBODY in reviewed[1].splitlines()
                assert summary_row(summary[1])[1] == f"  {NOBODY}"
                # Declined, the next review and the status are quiet again.
                code, out, _ = gateway.cli(
                    running, "review", SERVER, "--decline-rest", "--format", "json"
                )
                assert code == 1  # the snippet isn't committed yet
                entry = load_mapping("\n".join(json.loads(out)["snippet"]))["gateway"]
                server = entry["servers"][SERVER]
                assert server["declined"] == {
                    name: pin_of_fake(fake, name, listing=fake.lists) for name in ("echo", *ADDED)
                }
                gateway.reload(TOOLS, server["review"], server["declined"])
                await until(lambda: is_quiet(running))
                reviewed = gateway.cli(running, "review", SERVER)
                summary = gateway.cli(running, "review")
                assert (reviewed[0], summary[0]) == (0, 0), reviewed[1] + summary[1]
                assert len(summary_row(summary[1])) == 1
                assert "nobody reviewed" not in reviewed[1]


async def test_a_declined_tool_that_changes_counts_again(tmp_path: Path, ca: ProviderCA) -> None:
    """Y20: echo's pin no longer matches the declined one, so it is a tool nobody reviewed; a
    review declining it at its new pin, committed, is quiet."""
    fake = McpFake(key=KEY, key_header="x-api-key")
    with deployed(tmp_path, ca, fake) as gateway, gateway.running() as running:
        code, out, _ = gateway.cli(running, "review", SERVER)
        assert code == 0, out
        assert any(line.split()[:2] == ["echo", "declined"] for line in out.splitlines())
        declined = pin_of_fake(fake, "echo")
        fake.change_tool("description")
        code, out, _ = gateway.cli(running, "review", SERVER, "--decline", "echo")
        assert code == 1
        assert "1 listed that nobody reviewed: echo" in out.splitlines()
        assert any(line.split()[:2] == ["echo", "unreviewed"] for line in out.splitlines())
        server = load_mapping(out[out.index("# YAML to commit") :])["gateway"]["servers"][SERVER]
        assert server["declined"] == {"echo": pin_of_fake(fake, "echo")}
        assert server["declined"]["echo"] != declined
        gateway.reload(TOOLS, server["review"], server["declined"])
        await until(
            lambda: (
                (snapshot := running.app.policy.snapshot) is not None
                and snapshot.view.gateway.servers[SERVER].declined == server["declined"]
            )
        )
        code, out, _ = gateway.cli(running, "review", SERVER)
        assert code == 0, out
