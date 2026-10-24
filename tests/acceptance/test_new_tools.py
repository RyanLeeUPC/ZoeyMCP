"""Acceptance: J2, a server that adds tools (M6 design J.5, K.1; Y20, Y29).

The fake lists three new tools; ``zoeymcp review <server>`` names them as tools nobody reviewed
and exits 1, and the summary, from the gateway's status, says the same; so do the vault's health
(``tools_unreviewed`` in its ``gateway`` section) and Home's attention list, from the status
report the gateway pushes (step 7). A review's ``--decline-rest`` snippet, committed, makes all
of them quiet; and a declined tool whose definition changes counts again, in ``review``, health
and Home alike. J1's drift on an included tool agrees the same way (``drift_marked``, Home's
``drifted`` item). Over real sockets and real TLS, as S10's rows are (``test_mcp_shapes``).
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
from zoeymcp.portal.app import attention_items
from zoeymcp.vault.admin import HealthReader

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
def deployed(
    tmp_path: Path, ca: ProviderCA, fake: McpFake, *, status_push: bool = False
) -> Iterator[GatewayDeployment]:
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
            status_push=status_push,
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


def vault_says(gateway: GatewayDeployment) -> tuple[list[str], list[str], list[str]]:
    """What the vault reads in the gateway's latest status report for the server: health's
    gateway findings, Home's items (what ``GET /api/attention`` answers), and the new tools in
    the decision as it holds it."""
    vault = gateway.vault
    reader = HealthReader(
        vault.store, lambda: vault.app.policy, gateway_status=vault.app.gateway_status
    )
    report = vault.call(reader.report)
    section = report["gateway"]
    review = {"kind": "review", "server": SERVER}
    findings = [f["code"] for f in section["findings"] if f["action"] == review]
    items = [item["kind"] for item in attention_items(report)["items"]]
    rows = [row for row in section["servers"] if row["name"] == SERVER]
    new = rows[0]["attention"]["new"] if rows else []
    return findings, items, new


def vault_decision(gateway: GatewayDeployment) -> dict[str, list[str]]:
    """The server's attention decision as health's row holds it, from the latest report; empty
    before one names the server."""
    vault = gateway.vault
    reader = HealthReader(
        vault.store, lambda: vault.app.policy, gateway_status=vault.app.gateway_status
    )
    section = vault.call(reader.report)["gateway"]
    rows = [row for row in section["servers"] if row["name"] == SERVER]
    found: dict[str, list[str]] = rows[0]["attention"] if rows else {}
    return found


def summary_row(out: str) -> list[str]:
    """The summary's lines for the server: its row, and the line under it if there is one."""
    lines = out.splitlines()
    [at] = [index for index, line in enumerate(lines) if line.startswith(f"{SERVER}  ")]
    return [line for line in lines[at : at + 2] if line == lines[at] or line.startswith("  ")]


async def test_one_attention(tmp_path: Path, ca: ProviderCA) -> None:
    """Y29 for every state J2 walks: ``review <server>``'s exit code and line, the summary's,
    from the gateway's status, and the vault's health findings and Home items, from the status
    report the gateway pushes, agree, before the new tools, with them, and once declined."""
    # A legacy upstream keeps one connection per client, so each client's agent makes the
    # gateway list the server again.
    fake = McpFake(mode="legacy", key=KEY, key_header="x-api-key")
    with (
        deployed(tmp_path, ca, fake, status_push=True) as gateway,
        gateway.running() as running,
    ):
        async with agent(running, CLIENTS[0]) as first:
            await first.list_tools()
            await until(lambda: is_quiet(running))
            reviewed = gateway.cli(running, "review", SERVER)
            summary = gateway.cli(running, "review")
            assert (reviewed[0], summary[0]) == (0, 0), reviewed[1] + summary[1]
            assert len(summary_row(summary[1])) == 1
            assert "nobody reviewed" not in reviewed[1]
            await until(lambda: gateway.vault.app.gateway_status().report is not None, 20)
            assert vault_says(gateway) == ([], [], [])
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
                # The status report carries the same decision to health and Home (J2, Y20).
                await until(lambda: vault_says(gateway)[2] == list(ADDED), 20)
                assert vault_says(gateway)[:2] == (["tools_unreviewed"], ["unreviewed"])
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
                await until(lambda: vault_says(gateway) == ([], [], []), 20)


async def test_a_declined_tool_that_changes_counts_again(tmp_path: Path, ca: ProviderCA) -> None:
    """Y20, Y29: echo's pin no longer matches the declined one, so it is a tool nobody reviewed,
    in ``review``, health's findings and Home's items alike (the decision's
    ``changed_declined``); a review declining it at its new pin, committed, is quiet in all
    three."""
    fake = McpFake(mode="legacy", key=KEY, key_header="x-api-key")
    with (
        deployed(tmp_path, ca, fake, status_push=True) as gateway,
        gateway.running() as running,
    ):
        code, out, _ = gateway.cli(running, "review", SERVER)
        assert code == 0, out
        assert any(line.split()[:2] == ["echo", "declined"] for line in out.splitlines())
        declined = pin_of_fake(fake, "echo")
        fake.change_tool("description")
        async with agent(running, CLIENTS[0]) as client:
            await client.list_tools()
            await until(lambda: (attention(running) or {}).get("changed_declined") == ["echo"])
            code, out, _ = gateway.cli(running, "review", SERVER, "--decline", "echo")
            assert code == 1
            assert "1 listed that nobody reviewed: echo" in out.splitlines()
            assert any(line.split()[:2] == ["echo", "unreviewed"] for line in out.splitlines())
            await until(lambda: vault_decision(gateway).get("changed_declined") == ["echo"], 20)
            assert vault_says(gateway) == (["tools_unreviewed"], ["unreviewed"], [])
            snippet = out[out.index("# YAML to commit") :]
            server = load_mapping(snippet)["gateway"]["servers"][SERVER]
            assert server["declined"] == {"echo": pin_of_fake(fake, "echo")}
            assert server["declined"]["echo"] != declined
            gateway.reload(TOOLS, server["review"], server["declined"])
            await until(
                lambda: (
                    (snapshot := running.app.policy.snapshot) is not None
                    and snapshot.view.gateway.servers[SERVER].declined == server["declined"]
                )
            )
            await until(lambda: is_quiet(running))
            code, out, _ = gateway.cli(running, "review", SERVER)
            assert code == 0, out
            await until(lambda: vault_says(gateway) == ([], [], []), 20)


async def test_one_attention_for_drift(tmp_path: Path, ca: ProviderCA) -> None:
    """Y29 for J1: an included tool whose definition changed makes ``review <server>`` exit 1,
    health raise ``drift_marked`` and Home show a ``drifted`` item, from the status report the
    gateway pushes."""
    fake = McpFake(mode="legacy", key=KEY, key_header="x-api-key")
    with (
        deployed(tmp_path, ca, fake, status_push=True) as gateway,
        gateway.running() as running,
    ):
        fake.change_tool("enum")  # add's rounding enum: add is included and pinned
        async with agent(running, CLIENTS[0]) as client:
            listed = sorted(tool.name for tool in (await client.list_tools()).tools)
            assert listed == sorted(name for name in TOOLS if name != "add")  # hidden
            await until(lambda: (attention(running) or {}).get("drifted") == ["add"])
            reviewed = gateway.cli(running, "review", SERVER)
            summary = gateway.cli(running, "review")
            assert (reviewed[0], summary[0]) == (1, 1), reviewed[1] + summary[1]
            await until(lambda: vault_decision(gateway).get("drifted") == ["add"], 20)
            assert vault_says(gateway) == (["drift_marked"], ["drifted"], [])
