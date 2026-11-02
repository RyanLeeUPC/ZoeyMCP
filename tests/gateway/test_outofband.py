"""Out-of-band approvals from the gateway's side (M8 design C.1 rows 2-7, E; Z11).

Built from step 10 on: an ``attended`` client's call to a ``vault_approval`` tool goes to the
vault, which asks the operator's approvers, while its other ``approve`` tools keep elicitation
(G-18); a client nobody answers for is refused. Steps 12a and 12b add the endings, withdrawals
and relays. The rig is :mod:`tests.gateway.test_elsewhere`'s.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import anyio
import pytest

from tests.fakes.agent import ACCEPT, Script, agent
from tests.gateway.rig import CLIENTS
from tests.gateway.test_elsewhere import BOUND, call_in, headers, holding, ref_of, text
from zoeymcp.gateway.pipeline import NO_OUT_OF_BAND

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def test_attended_reaches_held_tool(tmp_path: Path) -> None:
    """Z11, G-18: agent1 is attended and not out of band. Its call to the held ``echo`` is
    asked on the vault's surface, never on its own session, and runs once approved there; its
    call to ``add``, an approve tool the vault doesn't hold, is elicited as before. agent2,
    whom nobody answers for, is refused before anything is held or sent."""
    script = Script([ACCEPT])
    options: dict[str, Any] = {"approve": ["echo", "add"], "vault_approval": ["echo"]}
    with anyio.fail_after(BOUND), holding(tmp_path, **options) as rig:
        async with agent(rig.running.mcp(), script=script, headers=headers()) as client:
            async with anyio.create_task_group() as group:
                held = await call_in(group, lambda: client.call_tool("echo", {"text": "held"}))
                [hold] = await rig.surface.holds(1)
                assert script.prompts == []
                await rig.decide(hold)
            asked = await client.call_tool("add", {"a": 1, "b": 2})
        async with agent(rig.running.mcp(), headers=headers(CLIENTS[1])) as other:
            refused = await other.call_tool("echo", {"text": "nobody"})
        await rig.settled()
    [result] = held
    assert not result.is_error
    assert "held" in text(result)
    assert hold.client == CLIENTS[0]
    assert not asked.is_error
    assert text(asked) == "3"
    assert len(script.prompts) == 1  # add's, on the agent's own session
    assert [shown.tool for shown in rig.surface.shown] == ["echo"]
    assert text(refused) == f"{NO_OUT_OF_BAND} (ref {ref_of(refused)})"
    assert rig.calls() == [{"text": "held"}]
    assert rig.calls("add") == [{"a": 1, "b": 2}]
    assert rig.ledger(hold.ref)[0] == ("asked", "vault")
    assert rig.ledger(ref_of(refused)) == []  # refused before anything was recorded
