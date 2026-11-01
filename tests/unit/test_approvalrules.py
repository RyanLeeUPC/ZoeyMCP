"""The rules for a waiting prompt after a policy change (M8 design C.1, O.3
``test_approvalrules.py``): :func:`still_asked`, moved from ``approve.py``'s ``_still_allowed``,
and :func:`withdraw_picks`, lifted from the closure in ``Approvals.withdraw``.
``tests/gateway/test_approval_recheck.py`` pins both through the gateway (M6 Q32 (b)).
"""

from __future__ import annotations

from typing import Any

import pytest

from zoeymcp.common.policy.schema import Approvals, GatewayLimits
from zoeymcp.common.policy.view import ViewGateway
from zoeymcp.gateway.approvalrules import still_asked, withdraw_picks
from zoeymcp.gateway.approvals import Key, Pending, Settings, Table

PIN = "sha256:" + "1" * 64
KEY = Key("agent1", "mail", "send")


def remote(approve: list[str], allow: list[str] | None = None) -> dict[str, Any]:
    allow = allow or []
    return {
        "kind": "remote",
        "vault_path": "/mail/mcp",
        "tools": {"include": approve + allow, "allow": allow, "approve": approve},
        "review": dict.fromkeys(approve + allow, PIN),
        "on_drift": "hide",
        "shared_session": False,
        "wrap_results": False,
        "enable": [],
        "era": "modern",
        "drift_check_interval": 300,
        "call_timeout": None,
    }


def toolkit(approve: list[str]) -> dict[str, Any]:
    return {
        "kind": "toolkit",
        "module": "zoeymcp.toolkits.mail",
        "tools": {"include": approve, "allow": [], "approve": approve},
        "pinning": "required",
        "review": {},
        "on_drift": "hide",
        "slots": {},
        "wrap_results": False,
        "call_timeout": None,
    }


def gateway(
    *,
    servers: dict[str, Any] | None = None,
    assigned: list[str] | None = None,
    approvals: dict[str, Any] | None = None,
    clients: bool = True,
) -> ViewGateway:
    client = {
        "token_sha256": "sha256:" + "0" * 64,
        "servers": ["mail"] if assigned is None else assigned,
        "sources": [],
        "approvals": {"attended": True} if approvals is None else approvals,
    }
    return ViewGateway.model_validate(
        {
            "hosts": ["gateway.example"],
            "origins": [],
            "limits": GatewayLimits().model_dump(),
            "approvals": Approvals().model_dump(),
            "clients": {"agent1": client} if clients else {},
            "servers": {"mail": remote(["send"])} if servers is None else servers,
        }
    )


def record(*, handle: str | None) -> Pending:
    return Pending(
        ref="r1",
        key=KEY,
        era="modern",
        args={},
        args_digest="sha256:" + "a" * 64,
        pin=PIN,
        plan=None,
        text_sha256="b" * 64,
        code=None,
        session_sha256=None,
        handle_sha256=handle,
        asks=1,
        asked_at=0.0,
        expires_at=300.0,
        hard_deadline=390.0,
    )


# --- still_asked --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "servers",
    [
        pytest.param({"mail": remote(["send"])}, id="remote"),
        pytest.param({"mail": toolkit(["send"])}, id="toolkit"),
    ],
)
def test_an_assigned_attended_approve_tool_is_still_asked(servers: dict[str, Any]) -> None:
    assert still_asked(gateway(servers=servers), KEY)


@pytest.mark.parametrize(
    "view",
    [
        pytest.param(gateway(clients=False), id="client-removed"),
        pytest.param(gateway(servers={}), id="server-removed"),
        pytest.param(gateway(servers={"other": remote(["send"])}, assigned=[]), id="both-gone"),
        pytest.param(gateway(assigned=[]), id="unassigned"),
        pytest.param(gateway(approvals={"attended": False}), id="unattended"),
        pytest.param(gateway(servers={"mail": remote([], allow=["send"])}), id="moved-to-allow"),
        pytest.param(gateway(servers={"mail": remote(["other"])}), id="tool-removed"),
        pytest.param(gateway(servers={"mail": toolkit([])}), id="toolkit-tool-removed"),
    ],
)
def test_a_view_that_no_longer_allows_the_prompt_withdraws_it(view: ViewGateway) -> None:
    assert not still_asked(view, KEY)


def test_a_client_without_approvals_is_never_asked() -> None:
    view = gateway()
    assert still_asked(view, KEY)
    unasked = view.model_copy(
        update={
            "clients": {"agent1": view.clients["agent1"].model_copy(update={"approvals": None})}
        }
    )
    assert not still_asked(unasked, KEY)


# --- withdraw_picks -----------------------------------------------------------------------------


def test_a_record_the_withdrawal_doesnt_match_is_left_alone() -> None:
    assert withdraw_picks(record(handle="c" * 64), lambda _: False) == (False, False)
    assert withdraw_picks(record(handle=None), lambda _: False) == (False, False)


def test_a_matched_record_is_picked_and_says_whether_it_is_mid_retry() -> None:
    seen: list[Pending] = []

    def matches(found: Pending) -> bool:
        seen.append(found)
        return True

    waiting = record(handle="c" * 64)
    assert withdraw_picks(waiting, matches) == (True, False)
    # A consumed handle: a retry's handler holds the record and sees the decision itself.
    consumed = record(handle=None)
    assert withdraw_picks(consumed, matches) == (True, True)
    assert seen == [waiting, consumed]


def test_every_record_is_elicited_until_relays_exist() -> None:
    """``Pending.how``, which step 12b's ``still_asked`` reads: set at ``begin``, and today always
    ``elicitation``."""
    assert record(handle=None).how == "elicitation"
    table = Table()
    begun = table.begin(
        KEY,
        settings=Settings(
            timeout=300,
            call_timeout=60,
            cooldown=15,
            max_pending_per_client=1,
            max_prompts_per_hour=30,
        ),
        now=0.0,
        ref="r1",
        era="legacy",
        args={},
        args_digest="sha256:" + "a" * 64,
        pin=PIN,
        text_sha256="b" * 64,
    )
    assert isinstance(begun, Pending)
    assert begun.how == "elicitation"
