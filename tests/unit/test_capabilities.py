"""What a path serves and states (M6 design L.5), and the listen acknowledgment filter (K.4).

``served``: tools always, each other kind only enabled and with an entry included, completions
only beside a served prompt or template (SPEC-6), a toolkit tools only. ``advertised``: each
served list with ``listChanged`` and never ``subscribe``, from the kinds alone. ``notified``: the
lists a view change may change. The filter: for every kind asked, and every set of kinds a path
may serve, only what the path sends is kept, never resource subscriptions.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from mcp.types import SubscriptionsListenRequestParams

from zoeymcp.common.policy.view import ViewRemoteServer, ViewToolkitServer
from zoeymcp.gateway.capabilities import (
    LISTED_IN,
    TOOLS_ONLY,
    Kind,
    ServedKinds,
    advertised,
    honored,
    notified,
    served,
)

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


def test_tools_only_is_tools() -> None:
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


# --- what a path serves (L.5) ----------------------------------------------------------------

TEMPLATE = "notes://notes/{id}"
FIXED = "notes://index"


def remote(
    enable: list[str],
    *,
    prompts: list[str] | None = None,
    templates: list[str] | None = None,
    fixed: list[str] | None = None,
) -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": [], "allow": [], "approve": []},
            "review": {},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": enable,
            "prompts": {"include": prompts or []},
            "resources": {
                "templates": {"include": templates or []},
                "fixed": {"include": fixed or []},
            },
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


TOOLKIT = ViewToolkitServer.model_validate(
    {
        "kind": "toolkit",
        "module": "zoeymcp.toolkits.mail",
        "tools": {"include": [], "allow": [], "approve": []},
        "pinning": "required",
        "review": {},
        "on_drift": "hide",
        "slots": {},
        "wrap_results": False,
        "call_timeout": None,
    }
)
EVERYTHING = ["prompts", "resources", "completions"]


@pytest.mark.parametrize(
    ("server", "expected"),
    [
        # Enabled with nothing included serves nothing more.
        (remote(EVERYTHING), {"tools"}),
        (remote([], prompts=["p"], templates=[TEMPLATE], fixed=[FIXED]), {"tools"}),
        (remote(["prompts"], prompts=["p"]), {"tools", "prompts"}),
        (remote(["prompts"], templates=[TEMPLATE], fixed=[FIXED]), {"tools"}),
        (remote(["resources"], templates=[TEMPLATE]), {"tools", "resources"}),
        (remote(["resources"], fixed=[FIXED]), {"tools", "resources"}),
        (remote(["resources"], prompts=["p"]), {"tools"}),
        (
            remote(["prompts", "resources"], prompts=["p"], fixed=[FIXED]),
            {"tools", "prompts", "resources"},
        ),
        # Completions only beside a served prompt or template: a fixed resource has nothing
        # to complete (SPEC-6).
        (remote(EVERYTHING, prompts=["p"]), {"tools", "prompts", "completions"}),
        (remote(EVERYTHING, templates=[TEMPLATE]), {"tools", "resources", "completions"}),
        (remote(EVERYTHING, fixed=[FIXED]), {"tools", "resources"}),
        (remote(["completions", "resources"], prompts=["p"]), {"tools"}),
        (remote(["completions", "prompts"], templates=[TEMPLATE]), {"tools"}),
        (remote(["completions"], prompts=["p"], templates=[TEMPLATE]), {"tools"}),
        (
            remote(EVERYTHING, prompts=["p"], templates=[TEMPLATE], fixed=[FIXED]),
            {"tools", "prompts", "resources", "completions"},
        ),
        (TOOLKIT, {"tools"}),
    ],
    ids=lambda value: "+".join(sorted(value)) if isinstance(value, set) else None,
)
def test_what_a_path_serves(
    server: ViewRemoteServer | ViewToolkitServer, expected: set[str]
) -> None:
    assert served(server) == frozenset(expected)


def test_a_toolkit_serves_tools_only() -> None:
    assert served(TOOLKIT) is TOOLS_ONLY


@pytest.mark.parametrize("kinds", PATHS, ids=lambda served: "+".join(sorted(served)))
def test_what_a_path_states(kinds: ServedKinds) -> None:
    """Every list served with listChanged, which the gateway sends; never subscribe; nothing
    else (SPEC-1)."""
    expected: dict[str, Any] = {"tools": {"listChanged": True}}
    if "prompts" in kinds:
        expected["prompts"] = {"listChanged": True}
    if "resources" in kinds:
        expected["resources"] = {"listChanged": True}
    if "completions" in kinds:
        expected["completions"] = {}
    stated = advertised(kinds)
    assert stated.model_dump(by_alias=True, exclude_none=True) == expected
    if stated.resources is not None:
        assert stated.resources.subscribe is None


def test_a_tools_only_path_states_what_m3_did() -> None:
    """Byte for byte as before: tools with listChanged, and nothing else."""
    dumped = advertised(TOOLS_ONLY).model_dump(by_alias=True, exclude_none=True, mode="json")
    assert dumped == {"tools": {"listChanged": True}}


def test_each_definition_kind_is_listed_in_its_list() -> None:
    assert dict(LISTED_IN) == {
        "tool": "tools",
        "prompt": "prompts",
        "resource_template": "resources",
        "resource": "resources",
    }


PROMPTS = remote(EVERYTHING, prompts=["p"])
RESOURCES = remote(EVERYTHING, fixed=[FIXED])


@pytest.mark.parametrize(
    ("before", "after", "expected"),
    [
        (None, None, {"tools"}),
        (remote([]), remote(["prompts"]), {"tools"}),
        (None, PROMPTS, {"tools", "prompts"}),
        (PROMPTS, None, {"tools", "prompts"}),
        (PROMPTS, RESOURCES, {"tools", "prompts", "resources"}),
        (RESOURCES, RESOURCES, {"tools", "resources"}),
        (TOOLKIT, PROMPTS, {"tools", "prompts"}),
    ],
)
def test_the_lists_a_view_change_announces(
    before: ViewRemoteServer | ViewToolkitServer | None,
    after: ViewRemoteServer | ViewToolkitServer | None,
    expected: set[str],
) -> None:
    """Tools as always, each other list either side serves, and never completions."""
    assert notified(before, after) == frozenset(expected)
