"""The routing decision, today's rows (M8 design C.1, O.3 ``test_routing.py``).

Each row both ways: when it holds, its route; when it just doesn't, the next row's. Row 1b in both
orders: a stray ``requestState`` is refused before the ``allow`` and unclassified rows it precedes,
and after the legacy row that precedes it; on an ``approve`` tool it is a retry, which the
gateway's handle check answers (``approve.py``), so it is asked even for an unattended client, as
before step 3.
"""

from __future__ import annotations

from typing import Any

import pytest

from zoeymcp.common.policy.schema import Tools
from zoeymcp.common.policy.view import ViewClient
from zoeymcp.gateway.routing import Allow, AskElicitation, Refuse, Route, attended, decide

TOOLS = Tools(include=["send", "read", "draft"], allow=["read"], approve=["send"])
# "draft" is included but neither allowed nor approved: unclassified.


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


def route(
    tool: str,
    *,
    who: ViewClient | None = ATTENDED,
    era: Any = "modern",
    state: bool = False,
    inputs: bool = False,
    tools: Tools = TOOLS,
) -> Route:
    return decide(tool=tool, tools=tools, client=who, era=era, request_state=state, inputs=inputs)


# --- row 1: a legacy request carries no MRTR input ------------------------------------------------


@pytest.mark.parametrize("tool", ["send", "read", "draft"])
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
    routes: list[Route] = [Allow(), AskElicitation()]
    assert routes[0] != routes[1]


# --- attended ------------------------------------------------------------------------------------


def test_attended_needs_an_approvals_block_that_says_so() -> None:
    assert attended(ATTENDED)
    assert not attended(UNATTENDED)
    assert not attended(NO_APPROVALS)
    assert not attended(None)
