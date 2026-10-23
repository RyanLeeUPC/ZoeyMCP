"""The listen acknowledgment filter (M6 design K.4): for every kind asked, and every set of kinds
a path may serve, only what the path sends is kept, never resource subscriptions."""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from mcp.types import SubscriptionsListenRequestParams

from zoeymcp.gateway.capabilities import TOOLS_ONLY, Kind, ServedKinds, honored

URI = "file:///notes/1"
ASKED = ("toolsListChanged", "promptsListChanged", "resourcesListChanged")
OTHERS: tuple[Kind, ...] = ("prompts", "resources", "completions")
# What a path may serve: tools always, and any of the others.
PATHS: list[ServedKinds] = [
    frozenset({"tools", *others})
    for count in range(4)
    for others in itertools.combinations(OTHERS, count)
]
# The kind each acknowledged member names.
KIND: dict[str, Kind] = {
    "toolsListChanged": "tools",
    "promptsListChanged": "prompts",
    "resourcesListChanged": "resources",
}


def params(notifications: dict[str, Any], **extra: Any) -> SubscriptionsListenRequestParams:
    raw = {"notifications": notifications, **extra}
    return SubscriptionsListenRequestParams.model_validate(raw)


def kept(found: SubscriptionsListenRequestParams) -> dict[str, Any]:
    return found.notifications.model_dump(by_alias=True, exclude_none=True)


def test_every_path_serves_tools_only_for_now() -> None:
    assert frozenset({"tools"}) == TOOLS_ONLY


@pytest.mark.parametrize("served", PATHS, ids=lambda served: "+".join(sorted(served)))
@pytest.mark.parametrize(
    "asked",
    [set(chosen) for count in range(4) for chosen in itertools.combinations(ASKED, count)],
    ids=lambda asked: "+".join(sorted(asked)) or "nothing",
)
def test_only_what_the_path_serves_is_kept(served: ServedKinds, asked: set[str]) -> None:
    notifications: dict[str, Any] = dict.fromkeys(asked, True)
    notifications["resourceSubscriptions"] = [URI]
    expected = {member: True for member in sorted(asked) if KIND[member] in served}
    assert kept(honored(params(notifications), served)) == expected


@pytest.mark.parametrize("served", PATHS, ids=lambda served: "+".join(sorted(served)))
def test_resource_subscriptions_are_never_kept(served: ServedKinds) -> None:
    found = honored(params({"resourceSubscriptions": [URI]}), served)
    assert found.notifications.resource_subscriptions is None
    assert kept(found) == {}


def test_tools_are_kept_on_a_path_with_no_other_kind() -> None:
    found = honored(params({"toolsListChanged": True, "promptsListChanged": True}), TOOLS_ONLY)
    assert found.notifications.tools_list_changed is True
    assert found.notifications.prompts_list_changed is None
    assert found.notifications.resources_list_changed is None


def test_a_false_flag_stays_false_and_is_never_turned_on() -> None:
    asked = {"toolsListChanged": False, "promptsListChanged": False, "resourcesListChanged": False}
    found = honored(params(asked), frozenset({"tools", "prompts", "resources"}))
    assert kept(found) == dict.fromkeys(ASKED, False)


def test_unknown_members_are_dropped_and_meta_is_kept() -> None:
    meta = {"progressToken": 7}
    asked = params({"toolsListChanged": True, "taskIds": ["t-1"]}, _meta=meta)
    found = honored(asked, TOOLS_ONLY)
    assert kept(found) == {"toolsListChanged": True}
    assert found.notifications.model_extra == {}
    assert found.model_dump(by_alias=True, exclude_none=True)["_meta"] == meta


def test_the_request_is_not_changed() -> None:
    asked = params({"toolsListChanged": True, "promptsListChanged": True})
    honored(asked, TOOLS_ONLY)
    assert kept(asked) == {"toolsListChanged": True, "promptsListChanged": True}
