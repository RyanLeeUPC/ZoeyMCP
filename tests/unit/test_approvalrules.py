"""The rules for a waiting prompt after a policy change (M8 design C.1, O.3
``test_approvalrules.py``): :func:`still_asked`, moved from ``approve.py``'s ``_still_allowed``
and (step 12b) rewritten for relays (G-24, E-6): an elicited record keeps the old rule's meaning,
a relayed one needs its client ``out_of_band`` and an approver, and neither survives its tool
going to ``vault_approval``; :func:`withdraw_picks`, lifted from the closure in
``Approvals.withdraw``; and (step 12a) :func:`ending_records`, the records the decisions poller
writes for the vault's ending of a held call (E.2, D.2).
``tests/gateway/test_approval_recheck.py`` pins both through the gateway (M6 Q32 (b)).
"""

from __future__ import annotations

from typing import Any, Literal

import pytest

from zoeymcp.common import ledgerformat
from zoeymcp.common.policy.schema import Approvals, GatewayLimits
from zoeymcp.common.policy.view import ViewGateway, ViewOutOfBand
from zoeymcp.gateway.approvalrules import ENDINGS, ending_records, still_asked, withdraw_picks
from zoeymcp.gateway.approvals import Key, Pending, Settings, Table

PIN = "sha256:" + "1" * 64
KEY = Key("agent1", "mail", "send")
OUT_OF_BAND = ViewOutOfBand(timeout=3600, block_seconds=120, result_ttl=3600)
RELAYED = {"attended": False, "out_of_band": True}


def remote(
    approve: list[str], allow: list[str] | None = None, *, held: list[str] | None = None
) -> dict[str, Any]:
    allow = allow or []
    tools = {"include": approve + allow, "allow": allow, "approve": approve}
    return {
        "kind": "remote",
        "vault_path": "/mail/mcp",
        "tools": {**tools, **({"vault_approval": held} if held is not None else {})},
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
    out_of_band: bool = True,
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
            "approvals": {
                **Approvals().model_dump(),
                **({"out_of_band": OUT_OF_BAND.model_dump()} if out_of_band else {}),
            },
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
    assert still_asked(gateway(servers=servers), KEY, "elicitation")


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
    assert not still_asked(view, KEY, "elicitation")


def test_a_client_without_approvals_is_never_asked() -> None:
    view = gateway(approvals={"attended": True, "out_of_band": True})
    assert still_asked(view, KEY, "elicitation")
    assert still_asked(view, KEY, "relay")
    unasked = view.model_copy(
        update={
            "clients": {"agent1": view.clients["agent1"].model_copy(update={"approvals": None})}
        }
    )
    assert not still_asked(unasked, KEY, "elicitation")
    assert not still_asked(unasked, KEY, "relay")


# --- still_asked for a relay (step 12b; G-24, E-6) ------------------------------------------------


@pytest.mark.parametrize(
    "servers",
    [
        pytest.param({"mail": remote(["send"])}, id="remote"),
        pytest.param({"mail": toolkit(["send"])}, id="toolkit"),
    ],
)
def test_an_out_of_band_clients_relay_is_still_asked(servers: dict[str, Any]) -> None:
    """E-6: the old rule withdrew every relay of a client that isn't attended at each view
    change; a relay needs the client ``out_of_band`` instead, and survives such a change."""
    view = gateway(servers=servers, approvals=RELAYED)
    assert still_asked(view, KEY, "relay")
    assert not still_asked(view, KEY, "elicitation")  # nobody watches this client's session


@pytest.mark.parametrize(
    "view",
    [
        pytest.param(gateway(approvals={"attended": True}), id="lost-out-of-band"),
        pytest.param(gateway(approvals=RELAYED, out_of_band=False), id="approvers-removed"),
        pytest.param(gateway(approvals=RELAYED, clients=False), id="client-removed"),
        pytest.param(gateway(approvals=RELAYED, servers={}), id="server-removed"),
        pytest.param(gateway(approvals=RELAYED, assigned=[]), id="unassigned"),
        pytest.param(
            gateway(approvals=RELAYED, servers={"mail": remote([], allow=["send"])}),
            id="moved-to-allow",
        ),
        pytest.param(
            gateway(approvals=RELAYED, servers={"mail": remote(["other"])}), id="tool-removed"
        ),
        pytest.param(
            gateway(approvals=RELAYED, servers={"mail": remote(["send"], held=["send"])}),
            id="now-vault-held",
        ),
    ],
)
def test_a_view_that_no_longer_relays_the_call_withdraws_it(view: ViewGateway) -> None:
    """G-24: removing a client's ``out_of_band`` (or the approvers it is relayed to) withdraws
    its relays, as does anything that withdraws an elicited prompt."""
    assert not still_asked(view, KEY, "relay")


def test_a_tool_the_vault_now_holds_is_asked_here_no_more() -> None:
    """M6 Q32 (b), restated for M8: a tool moved to ``vault_approval`` is the vault's to ask
    (Z1), so a prompt the gateway asks for it, either way, is withdrawn."""
    held = {"mail": remote(["send"], held=["send"])}
    assert not still_asked(gateway(servers=held), KEY, "elicitation")
    assert not still_asked(gateway(servers=held, approvals=RELAYED), KEY, "relay")
    assert still_asked(gateway(servers={"mail": remote(["send"], held=[])}), KEY, "elicitation")


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


@pytest.mark.parametrize("how", ["elicitation", "relay"])
def test_how_a_record_is_asked_is_set_at_begin(how: Literal["elicitation", "relay"]) -> None:
    """``Pending.how``, which ``still_asked``'s callers pass: ``elicitation`` unless ``begin``
    says otherwise (a relay, step 12b)."""
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
        how=how,
    )
    assert isinstance(begun, Pending)
    assert begun.how == how


# --- ending_records -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "decision", "cooldown"),
    [
        ("denied", "decline", True),
        ("expired", "timeout", True),
        ("withdrawn", "withdrawn", False),
    ],
)
def test_an_ending_that_sent_nothing_is_not_sent(
    status: str, decision: str, cooldown: bool
) -> None:
    """A decline and an expiry start the cooldown, as for a call the gateway asked about itself
    (E.1); a withdrawal doesn't. Whatever outcome the vault named, nothing was sent."""
    assert ending_records(status, "not_sent") == (decision, "not_sent", cooldown)
    assert ending_records(status, "ok") == (decision, "not_sent", cooldown)


@pytest.mark.parametrize("outcome", sorted(ledgerformat.OUTCOMES))
def test_a_forwarded_call_keeps_the_vaults_outcome(outcome: str) -> None:
    assert ending_records("done", outcome) == ("approved_elsewhere", outcome, False)


@pytest.mark.parametrize(
    "status",
    ["pending", "approved", "forwarding", "held", "unknown", "Done", "", None, 1, ["done"]],
    ids=[
        "pending",
        "approved",
        "forwarding",
        "held",
        "unknown",
        "case",
        "empty",
        "null",
        "number",
        "list",
    ],
)
def test_a_status_that_isnt_an_ending_writes_nothing(status: object) -> None:
    assert ending_records(status, "ok") is None


def test_every_ending_the_vault_reports_has_its_row() -> None:
    """The vault's four endings (``vault/internal.py``'s ``EndedStatus``), each one decision the
    gateway's ledger knows."""
    assert set(ENDINGS) == {"done", "denied", "expired", "withdrawn"}
    for decision, _ in ENDINGS.values():
        assert decision in ledgerformat.DECISIONS
