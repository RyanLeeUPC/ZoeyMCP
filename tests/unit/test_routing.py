"""The routing decision (M8 design C.1, O.3 ``test_routing.py``).

Each row both ways: when it holds, its route; when it just doesn't, the next row's. Row 1b in both
orders: a stray ``requestState`` is refused before the ``allow`` and unclassified rows it precedes,
and after the legacy row that precedes it; on an ``approve`` tool it is a retry, which the
gateway's handle check answers (``approve.py``), so it is asked even for an unattended client, as
before step 3; on a ``vault_approval`` tool, which is never given a handle, it is refused before
rows 2-5, and so are modern ``inputResponses``. Rows 2-7 read M8's dark fields, so the last test
reaches them through a policy ``check`` passes only lit (``tests/dark.py``).
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml

from tests.dark import lit
from tests.unit.test_policy import errors, m8
from zoeymcp.common.policy import check_policy, parse_policy
from zoeymcp.common.policy.schema import Tools
from zoeymcp.common.policy.view import ViewClient, build_view
from zoeymcp.gateway.routing import (
    Allow,
    AskElicitation,
    AskOutOfBand,
    Elsewhere,
    Refuse,
    Route,
    attended,
    decide,
    out_of_band,
)

TOOLS = Tools(
    include=["send", "read", "draft", "order"],
    allow=["read"],
    approve=["send", "order"],
    vault_approval=["order"],
)
# "draft" is included but neither allowed nor approved: unclassified. "order" is held.


def client(approvals: dict[str, Any] | None) -> ViewClient:
    return ViewClient.model_validate(
        {
            "token_sha256": "sha256:" + "0" * 64,
            "servers": ["mail"],
            "sources": [],
            "approvals": approvals,
        }
    )


ATTENDED = client({"attended": True})
UNATTENDED = client({"attended": False})
NO_APPROVALS = client(None)
OUT_OF_BAND = client({"attended": False, "out_of_band": True})
BOTH = client({"attended": True, "out_of_band": True})


def route(
    tool: str,
    *,
    who: ViewClient | None = ATTENDED,
    era: Any = "modern",
    state: bool = False,
    inputs: bool = False,
    tools: Tools = TOOLS,
    approver: bool = True,
    headers: bool = False,
    toolkit: bool = False,
) -> Route:
    return decide(
        tool=tool,
        tools=tools,
        client=who,
        era=era,
        request_state=state,
        inputs=inputs,
        out_of_band_configured=approver,
        header_params=headers,
        toolkit=toolkit,
    )


# --- row 1: a legacy request carries no MRTR input ------------------------------------------------


@pytest.mark.parametrize("tool", ["send", "read", "draft", "order"])
@pytest.mark.parametrize(
    ("state", "inputs"),
    [
        pytest.param(True, False, id="state"),
        pytest.param(False, True, id="inputs"),
        pytest.param(True, True, id="both"),
    ],
)
def test_row_1_a_legacy_request_with_input_is_refused(tool: str, state: bool, inputs: bool) -> None:
    assert route(tool, era="legacy", state=state, inputs=inputs) == Refuse("unexpected_input")


def test_row_1_needs_the_legacy_era_and_some_input() -> None:
    assert route("read", era="legacy") == Allow()
    assert route("send", era="legacy") == AskElicitation()
    # Modern answers on an approve tool are the approval's to read (asked anew, or a retry).
    assert route("send", inputs=True) == AskElicitation()
    # Modern answers alone on an allow tool were never refused, and still aren't.
    assert route("read", inputs=True) == Allow()


# --- row 1b: a requestState on a tool the gateway issued no handle for ---------------------------


@pytest.mark.parametrize("tool", ["read", "draft"])
def test_row_1b_refuses_a_stray_state_before_the_allow_and_unclassified_rows(tool: str) -> None:
    assert route(tool, state=True) == Refuse("unexpected_state")
    assert route(tool, state=True, inputs=True) == Refuse("unexpected_state")
    # The other order: without the state, the later row decides.
    assert route(tool) == (Allow() if tool == "read" else Refuse("unclassified"))


def test_row_1b_comes_after_the_legacy_row() -> None:
    assert route("read", era="legacy", state=True) == Refuse("unexpected_input")


@pytest.mark.parametrize(
    "who",
    [
        pytest.param(ATTENDED, id="attended"),
        pytest.param(UNATTENDED, id="unattended"),
        pytest.param(NO_APPROVALS, id="no-approvals"),
    ],
)
def test_a_state_on_an_approve_tool_is_a_retry_for_the_handle_check(
    who: ViewClient,
) -> None:
    assert route("send", who=who, state=True) == AskElicitation()


@pytest.mark.parametrize(
    ("state", "inputs"),
    [
        pytest.param(True, False, id="state"),
        pytest.param(False, True, id="inputs"),
        pytest.param(True, True, id="both"),
    ],
)
def test_row_1b_refuses_any_input_on_a_held_tool_before_rows_2_to_5(
    state: bool, inputs: bool
) -> None:
    # Before row 2 (a client nobody answers for) as before row 5: no handle is ever issued for it.
    assert route("order", state=state, inputs=inputs) == Refuse("unexpected_state")
    assert route("order", who=UNATTENDED, state=state, inputs=inputs) == Refuse("unexpected_state")
    assert route("order", state=state, inputs=inputs, approver=False) == Refuse("unexpected_state")
    # The legacy row still comes first; and without the input, row 5 decides.
    assert route("order", era="legacy", state=state, inputs=inputs) == Refuse("unexpected_input")
    assert route("order") == Elsewhere("pending")


# --- rows 2-5: a vault_approval tool -------------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [
        pytest.param(UNATTENDED, id="unattended"),
        pytest.param(NO_APPROVALS, id="no-approvals"),
        pytest.param(None, id="no-context"),
    ],
)
def test_row_2_a_client_nobody_answers_for_is_refused(who: ViewClient | None) -> None:
    assert route("order", who=who) == Refuse("no_out_of_band")
    # Before rows 3 and 4: the client's setting is the one missing.
    assert route("order", who=who, approver=False, headers=True) == Refuse("no_out_of_band")


@pytest.mark.parametrize(
    "who",
    [
        pytest.param(ATTENDED, id="attended"),
        pytest.param(OUT_OF_BAND, id="out-of-band"),
        pytest.param(BOTH, id="both"),
    ],
)
def test_rows_3_to_5_for_a_client_someone_answers_for(who: ViewClient) -> None:
    # Row 3 before row 4; row 4 before row 5; row 5 when neither holds (G-18, Z11).
    assert route("order", who=who, approver=False, headers=True) == Refuse("no_approver")
    assert route("order", who=who, approver=False) == Refuse("no_approver")
    assert route("order", who=who, headers=True) == Refuse("header_params")
    assert route("order", who=who) == Elsewhere("pending")
    assert route("order", who=who, era="legacy") == Elsewhere("pending")


def test_row_5_blocks_for_a_toolkit() -> None:
    assert route("order", toolkit=True) == Elsewhere("block")
    assert route("order", who=OUT_OF_BAND, toolkit=True) == Elsewhere("block")
    assert route("send", toolkit=True) == AskElicitation()  # only a held tool is Elsewhere


def test_a_held_tool_is_held_whatever_else_lists_it() -> None:
    allowed = Tools(include=["order"], allow=["order"], vault_approval=["order"])
    assert route("order", tools=allowed) == Elsewhere("pending")
    assert route("order", tools=allowed, who=UNATTENDED) == Refuse("no_out_of_band")


# --- rows 6 and 7: an approve tool for an out-of-band client --------------------------------------


@pytest.mark.parametrize(
    "who",
    [pytest.param(OUT_OF_BAND, id="out-of-band"), pytest.param(BOTH, id="both")],
)
def test_rows_6_and_7_an_out_of_band_client_is_relayed(who: ViewClient) -> None:
    assert route("send", who=who) == AskOutOfBand()
    assert route("send", who=who, approver=False) == Refuse("no_approver")
    assert route("send", who=who, era="legacy") == AskOutOfBand()
    # An allow tool isn't asked; modern answers on an approve tool are asked anew (row 6).
    assert route("read", who=who) == Allow()
    assert route("send", who=who, inputs=True) == AskOutOfBand()


@pytest.mark.parametrize(
    "who",
    [pytest.param(OUT_OF_BAND, id="out-of-band"), pytest.param(BOTH, id="both")],
)
def test_a_retry_is_the_elicitations_before_rows_6_and_7(who: ViewClient) -> None:
    assert route("send", who=who, state=True) == AskElicitation()
    assert route("send", who=who, state=True, approver=False) == AskElicitation()


@pytest.mark.parametrize(
    "who",
    [
        pytest.param(ATTENDED, id="attended"),
        pytest.param(UNATTENDED, id="unattended"),
        pytest.param(NO_APPROVALS, id="no-approvals"),
    ],
)
def test_rows_6_and_7_need_an_out_of_band_client(who: ViewClient) -> None:
    expected: Route = AskElicitation() if who is ATTENDED else Refuse("no_approvals")
    assert route("send", who=who) == expected
    assert route("send", who=who, approver=False) == expected


# --- rows 8 and 9: an approve tool ---------------------------------------------------------------


def test_row_8_an_attended_client_is_asked() -> None:
    assert route("send") == AskElicitation()


@pytest.mark.parametrize(
    "who",
    [
        pytest.param(UNATTENDED, id="unattended"),
        pytest.param(NO_APPROVALS, id="no-approvals"),
        pytest.param(None, id="no-context"),
    ],
)
def test_row_9_anyone_else_is_refused(who: ViewClient | None) -> None:
    assert route("send", who=who) == Refuse("no_approvals")
    assert route("send", who=who, inputs=True) == Refuse("no_approvals")


def test_approve_is_read_before_allow() -> None:
    both = Tools(include=["send"], allow=["send"], approve=["send"])
    assert route("send", tools=both) == AskElicitation()
    assert route("send", tools=both, who=UNATTENDED) == Refuse("no_approvals")
    assert route("send", tools=both, state=True, who=UNATTENDED) == AskElicitation()


# --- rows 11 and 12 ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "who",
    [
        pytest.param(ATTENDED, id="attended"),
        pytest.param(UNATTENDED, id="unattended"),
        pytest.param(None, id="no-context"),
    ],
)
def test_rows_11_and_12_ignore_the_client(who: ViewClient | None) -> None:
    assert route("read", who=who) == Allow()
    assert route("draft", who=who) == Refuse("unclassified")
    assert route("absent", who=who) == Refuse("unclassified")


def test_the_routes_compare_by_value() -> None:
    assert Refuse("unclassified") != Refuse("no_approvals")
    routes: list[Route] = [Allow(), AskElicitation(), AskOutOfBand()]
    assert routes[0] != routes[1] != routes[2]
    assert Elsewhere("block") != Elsewhere("pending")


# --- attended and out_of_band ---------------------------------------------------------------------


def test_attended_needs_an_approvals_block_that_says_so() -> None:
    assert attended(ATTENDED)
    assert not attended(UNATTENDED)
    assert not attended(NO_APPROVALS)
    assert not attended(None)


def test_out_of_band_needs_an_approvals_block_that_says_so() -> None:
    assert out_of_band(OUT_OF_BAND)
    assert out_of_band(BOTH)
    assert not out_of_band(ATTENDED)
    assert not out_of_band(NO_APPROVALS)
    assert not out_of_band(None)


# --- rows 2-7 on a checked policy, lit -----------------------------------------------------------


def test_a_checked_policy_reaches_rows_2_to_7_only_lit(example_raw: dict[str, Any]) -> None:
    """The example with M8's fields (``test_policy.m8``): dark, ``check`` refuses it; lit, it
    passes, and its view routes the held tools Elsewhere for the attended client (a toolkit's to
    block), and that client's other approve tools, once it is out of band, to a relay."""
    raw = m8(example_raw)
    raw["gateway"]["clients"]["agent1"]["approvals"]["out_of_band"] = True
    raw["gateway"]["servers"]["broker-trade"]["tools"]["vault_approval"] = ["place_order"]
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    assert errors(check_policy(policy))  # dark: row 0
    with lit():
        assert errors(check_policy(policy)) == []
    gateway = build_view(policy).gateway
    agent = gateway.clients["agent1"]
    configured = gateway.approvals.out_of_band is not None

    def at(server: str, tool: str, *, toolkit: bool = False) -> Route:
        return decide(
            tool=tool,
            tools=gateway.servers[server].tools,
            client=agent,
            era="modern",
            request_state=False,
            inputs=False,
            out_of_band_configured=configured,
            header_params=False,
            toolkit=toolkit,
        )

    assert at("broker-trade", "place_order") == Elsewhere("pending")
    assert at("mail", "send_note", toolkit=True) == Elsewhere("block")
    unheld = [
        (name, tool)
        for name, server in gateway.servers.items()
        for tool in server.tools.approve
        if tool not in server.tools.vault_approval
    ]
    assert unheld == [("broker-trade", "cancel_order")]
    assert at("broker-trade", "cancel_order") == AskOutOfBand()
