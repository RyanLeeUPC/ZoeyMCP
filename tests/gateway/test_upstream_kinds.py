"""Prompts and resources in the upstream runtime (M6 design L.4), against the fake MCP server
through a real vault: every enabled kind listed after the tools, each walk failing on its own
(SPEC-7, FM-31), the serving walk of ``resources/list`` stopping once every included fixed URI is
listed, the review's walk listing the upstream's whole list under the caps (OPS-11), drift marks
by kind, and ``on_drift: fail`` blocking the whole server for any kind (Q20 (a)).

Built dark (L.11): ``check`` still refuses ``enable`` of these kinds, so each test builds the
server's view directly.
"""

from __future__ import annotations

import copy
import io
import json
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import pytest
from mcp.types import Prompt, Resource, ResourceTemplate, TextContent
from pydantic import BaseModel

from tests.fakes.mcp_server import (
    ASSISTANT_PROMPT,
    FIXED,
    HIDDEN_PROMPT,
    TEMPLATE,
    Announced,
    McpFake,
    base_prompts,
    base_resources,
    base_templates,
)
from tests.gateway.rig import CLIENTS, SERVER, deployment, pin_of_fake, pool_for, until
from zoeymcp.common import reviewreport
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.policy.view import ViewGateway, ViewRemoteServer
from zoeymcp.gateway import logs, pins, review, upstream
from zoeymcp.gateway.connstate import Phase
from zoeymcp.gateway.defstore import DefinitionStore
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.policyclient import Snapshot
from zoeymcp.gateway.vaultlink import parse_link

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Listings may follow each other at once."""
    monkeypatch.setattr(upstream, "COALESCE", 0.0)


def kind_pin(kind: pins.DefinitionKind, wire: dict[str, Any]) -> str:
    models: dict[str, type[BaseModel]] = {
        "prompt": Prompt,
        "resource_template": ResourceTemplate,
        "resource": Resource,
    }
    model = models[kind]
    return pins.project_kind(kind, model.model_validate(copy.deepcopy(wire))).pin


PROMPT_PIN = kind_pin("prompt", base_prompts()[0])
TEMPLATE_PIN = kind_pin("resource_template", base_templates()[0])
FIXED_PIN = kind_pin("resource", base_resources()[0])


def with_kinds(
    server: ViewRemoteServer,
    *,
    enable: list[str] | None = None,
    prompts: dict[str, Any] | None = None,
    templates: dict[str, Any] | None = None,
    fixed: dict[str, Any] | None = None,
    on_drift: str | None = None,
) -> ViewRemoteServer:
    """``server`` enabling prompts and resources, with these blocks (built dark: no ``check``)."""
    data = server.model_dump()
    data.update(
        enable=["prompts", "resources"] if enable is None else enable,
        prompts=prompts or {},
        resources={"templates": templates or {}, "fixed": fixed or {}},
    )
    if on_drift is not None:
        data["on_drift"] = on_drift
    return ViewRemoteServer.model_validate(data)


def reviewed_kinds(server: ViewRemoteServer, **options: Any) -> ViewRemoteServer:
    """Every kind of the fake included at its pin: the first prompt, the template, the fixed
    resource."""
    return with_kinds(
        server,
        prompts={"include": [ASSISTANT_PROMPT], "review": {ASSISTANT_PROMPT: PROMPT_PIN}},
        templates={"include": [TEMPLATE], "review": {TEMPLATE: TEMPLATE_PIN}},
        fixed={"include": [FIXED], "review": {FIXED: FIXED_PIN}},
        **options,
    )


def pin_server() -> ViewRemoteServer:
    """A remote server including no tools, for a test that needs no deployment."""
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": [], "allow": [], "approve": []},
            "review": {},
            "declined": {},
            "on_drift": "hide",
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def review_of(fake: McpFake) -> dict[str, str]:
    return {name: pin_of_fake(fake, name) for name in TOOLS}


def methods(fake: McpFake) -> list[str]:
    """The JSON-RPC requests the fake received, in order, beyond the handshake."""
    skipped = {"initialize", "notifications/initialized", "server/discover", "ping"}
    return [
        item.rpc_method
        for item in fake.received
        if item.rpc_method is not None
        and item.rpc_method not in skipped
        and not item.rpc_method.startswith("notifications/")
        and item.rpc_method != "subscriptions/listen"
    ]


def text(result: object) -> str:
    content = result.content  # type: ignore[attr-defined]
    assert isinstance(content[0], TextContent)
    return content[0].text


@pytest.mark.parametrize("era", ["auto", "legacy"])
async def test_every_enabled_kind_is_listed_after_the_tools(tmp_path: Path, era: str) -> None:
    fake = McpFake(prompts=True, resources=True)
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake), era=era) as deployed:
        policy = reviewed_kinds(deployed.server)
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            with anyio.fail_after(20):
                evaluation = await pool.wait_ready(connection)
            assert sorted(evaluation.exposed) == sorted(TOOLS)
            prompts = evaluation.kinds["prompt"]
            assert set(prompts.exposed) == {ASSISTANT_PROMPT}
            assert [(r.kind, r.tool) for r in prompts.reports] == [("unreviewed", HIDDEN_PROMPT)]
            templates = evaluation.kinds["resource_template"]
            assert set(templates.exposed) == {TEMPLATE}
            # The fake writes a whole priority; the projection holds the float (S18-1).
            assert templates.exposed[TEMPLATE].definition["annotations"] == {
                "audience": ["user"],
                "priority": 1.0,
            }
            assert set(evaluation.kinds["resource"].exposed) == {FIXED}
            # The definition store keeps each kind by its pin, for a drift's reviewed side.
            assert pool.defs.get(PROMPT_PIN, "prompt") == pins.project_prompt(
                Prompt.model_validate(base_prompts()[0])
            )
            assert pool.defs.get(PROMPT_PIN) is None
    sent = methods(fake)
    assert sent[: sent.index("prompts/list")].count("tools/list") >= 1
    assert sent.count("prompts/list") == sent.count("resources/templates/list") >= 1
    [listing, *_] = deployed.events("listing")
    assert (listing["prompts"], listing["resource_templates"], listing["resources"]) == (2, 1, 1)
    assert deployed.events("kind_list_failed") == []
    [unreviewed] = deployed.events("prompt_unreviewed")
    assert (unreviewed["server"], unreviewed["name"]) == (SERVER, HIDDEN_PROMPT)
    assert "tool" not in unreviewed


async def test_a_server_that_enables_nothing_more_lists_its_tools_alone(tmp_path: Path) -> None:
    fake = McpFake(prompts=True, resources=True)
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake)) as deployed:
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, deployed.server, CLIENTS[0])
            evaluation = await pool.wait_ready(connection)
            assert evaluation.kinds == {}
            assert connection.listings == {}
    assert set(methods(fake)) == {"tools/list"}
    [listing, *_] = deployed.events("listing")
    assert "prompts" not in listing
    # And the egress filter keeps refusing the lists on such a server's connection.
    assert not any(item.rpc_method in ("prompts/list", "resources/list") for item in fake.received)


async def test_resource_list_over_cap_keeps_tools(tmp_path: Path) -> None:
    """FM-31, SPEC-7: a server listing more resources than the cap cuts that kind alone: the
    unseen fixed resource is missing, one seen before the cap is served at its pin, and the
    server's tools are listed and served."""
    fake = McpFake(prompts=True, resources=True, extra_resources=10)
    extra = {"uri": "notes://extra/9", "name": "extra_9"}
    cap = len(fake.tools_for(None, 1))
    with deployment(
        tmp_path, fake, include=TOOLS, review=review_of(fake), limits={"max_tools_per_server": cap}
    ) as deployed:
        policy = with_kinds(
            deployed.server,
            prompts={"include": [ASSISTANT_PROMPT], "review": {ASSISTANT_PROMPT: PROMPT_PIN}},
            fixed={
                "include": [FIXED, extra["uri"]],
                "review": {FIXED: FIXED_PIN, extra["uri"]: kind_pin("resource", extra)},
            },
        )
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            evaluation = await pool.wait_ready(connection)
            assert connection.state.phase is Phase.READY
            assert sorted(evaluation.exposed) == sorted(TOOLS)
            resources = evaluation.kinds["resource"]
            assert set(resources.exposed) == {FIXED}
            assert [r.tool for r in resources.reports if r.kind == "missing"] == [extra["uri"]]
            cut = connection.listings["resource"]
            assert (len(cut.items), cut.cut, cut.failure) == (cap, True, None)
            assert set(evaluation.kinds["prompt"].exposed) == {ASSISTANT_PROMPT}
            result = await pool.call(SERVER, policy, CLIENTS[0], "echo", {"text": "hi"})
            assert text(result) == "hi"
    cuts = deployed.events("kind_list_cut")  # each listing's, the stream open's too
    assert cuts
    assert {(line["definition_kind"], line["reason"], line["listed"]) for line in cuts} == {
        ("resource", "entries", cap)
    }
    assert deployed.events("kind_list_failed") == []
    assert deployed.events("server_list_failed") == []


@pytest.mark.parametrize("failing", ["prompts", "resources"])
async def test_each_kinds_walk_fails_on_its_own(tmp_path: Path, failing: str) -> None:
    """The upstream doesn't serve one kind it is listed for: that kind lists nothing, so its
    included entries are missing, and the tools and the other kind stand."""
    fake = McpFake(prompts=failing != "prompts", resources=failing != "resources")
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake)) as deployed:
        policy = reviewed_kinds(deployed.server)
        async with pool_for(deployed) as pool:
            evaluation = await pool.wait_ready(pool.connection(SERVER, policy, CLIENTS[0]))
    assert sorted(evaluation.exposed) == sorted(TOOLS)
    failed_kinds = ["prompt"] if failing == "prompts" else ["resource_template", "resource"]
    for kind, found in evaluation.kinds.items():
        if kind in failed_kinds:
            assert found.exposed == {}
            assert [r.kind for r in found.reports] == ["missing"]
        else:
            assert len(found.exposed) == 1
    assert {line["definition_kind"] for line in deployed.events("kind_list_failed")} == set(
        failed_kinds
    )
    assert {line["reason"] for line in deployed.events("kind_list_failed")} == {"MCPError"}


async def test_serving_stops_once_every_included_fixed_uri_is_listed(tmp_path: Path) -> None:
    fake = McpFake(resources=True, extra_resources=5, kind_page_size=1)
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake)) as deployed:
        policy = with_kinds(
            deployed.server, enable=["resources"], fixed={"include": [FIXED], "review": {}}
        )
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            await pool.wait_ready(connection)
            assert [pins.key_of("resource", r) for r in connection.listings["resource"].items] == [
                FIXED
            ]
            # Nothing included: nothing needs listing to serve.
            bare = with_kinds(deployed.server, enable=["resources"])
            other = pool.connection(SERVER, bare, CLIENTS[1])
            await pool.wait_ready(other)
            assert list(other.listings["resource"].items) == []
            assert other.listings["resource"].failure is None
    # Six pages are on offer; one was asked for, by the first connection only.
    assert methods(fake).count("resources/list") == 1
    # The templates are listed whole, page by page, both times.
    assert methods(fake).count("resources/templates/list") == 2


class _Policy:
    def __init__(self, view: Any) -> None:
        self._snapshot = Snapshot(view, 0.0)

    def fresh(self) -> Snapshot:
        return self._snapshot


async def test_the_review_lists_the_whole_resource_list_under_the_caps(tmp_path: Path) -> None:
    """OPS-11: a review lists every fixed resource the upstream lists, up to the cap, as
    unreviewed candidates, with a finding that the cap cut it short, so one can be included at a
    pin the review learned; serving would have failed the kind."""
    fake = McpFake(resources=True, extra_resources=10)
    cap = len(fake.tools_for(None, 1))
    with deployment(
        tmp_path, fake, include=TOOLS, review=review_of(fake), limits={"max_tools_per_server": cap}
    ) as deployed:
        policy = with_kinds(deployed.server, enable=["resources"])
        gateway = deployed.view.gateway.model_dump()
        gateway["servers"][SERVER] = policy.model_dump()
        view = deployed.view.model_copy(update={"gateway": ViewGateway.model_validate(gateway)})
        async with pool_for(deployed) as pool:
            app = SimpleNamespace(policy=_Policy(view), pool=pool)
            with anyio.fail_after(30):
                answer = await review.review(app, SERVER)
    entries = [entry for entry in answer["tools"] if entry.get("kind") == "resource"]
    assert len(entries) == cap
    assert FIXED in {entry["name"] for entry in entries}
    assert all(entry["state"] == "unreviewed" and entry["pin"] for entry in entries)
    assert answer["listings"]["resource"]["findings"][0]["message"] == (
        f"the server lists more than the review could take under gateway.limits: the first "
        f"{cap} are shown"
    )
    assert answer["policy"]["resources"]["fixed"]["include"] == []
    assert "prompts" not in answer["policy"]
    limits = GatewayLimits(max_tools_per_server=cap)
    report = reviewreport.read(reviewreport.fit(answer, limits), limits)
    assert isinstance(report, reviewreport.RemoteReport)
    assert report.listings is not None
    assert report.listings["resource"].failure is None


@pytest.mark.parametrize("on_drift", ["hide", "fail"])
async def test_a_drifted_prompt_is_marked_and_fail_blocks_the_whole_server(
    tmp_path: Path, on_drift: str, quick: None
) -> None:
    """Q20 (a): under ``on_drift: fail`` a prompt changed after review blocks every kind, tools
    included; under ``hide`` only the prompt is hidden. The mark holds by kind."""
    fake = McpFake(prompts=True, resources=True)
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake)) as deployed:
        policy = reviewed_kinds(deployed.server, on_drift=on_drift)
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            first = await pool.wait_ready(connection)
            assert set(first.kinds["prompt"].exposed) == {ASSISTANT_PROMPT}
            fake.change_kind("prompt")
            connection.change("list_changed")
            await until(lambda: pool.marks.for_server(SERVER, "prompt"))
            await until(lambda: connection.state.phase is Phase.READY)
            evaluation = await pool.wait_ready(connection)
            assert pool.marks.for_server(SERVER, "prompt") == {(ASSISTANT_PROMPT, PROMPT_PIN)}
            assert pool.marks.for_server(SERVER) == frozenset()
            assert evaluation.kinds["prompt"].exposed == {}
            if on_drift == "fail":
                assert evaluation.blocked
                assert evaluation.exposed == {}
                assert all(found.exposed == {} for found in evaluation.kinds.values())
            else:
                assert not evaluation.blocked
                assert sorted(evaluation.exposed) == sorted(TOOLS)
                assert set(evaluation.kinds["resource"].exposed) == {FIXED}
    [marked] = deployed.events("drift_marked")
    assert (marked["definition_kind"], marked["name"]) == ("prompt", ASSISTANT_PROMPT)
    [drift] = deployed.events("prompt_drift")
    assert (drift["name"], drift["pinned"], drift["changed"]) == (
        ASSISTANT_PROMPT,
        PROMPT_PIN,
        ["description"],
    )
    assert len(deployed.events("server_blocked")) == (1 if on_drift == "fail" else 0)


async def test_a_repin_reevaluates_every_kind_and_an_enable_change_reopens(
    tmp_path: Path, quick: None
) -> None:
    fake = McpFake(prompts=True, resources=True)
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake)) as deployed:
        policy = with_kinds(deployed.server, prompts={"include": [ASSISTANT_PROMPT]})
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            first = await pool.wait_ready(connection)
            assert first.kinds["prompt"].exposed == {}
            listed = methods(fake).count("prompts/list")
            # A pin for the included prompt: evaluated again from the last listing, no request.
            repinned = with_kinds(
                deployed.server,
                prompts={"include": [ASSISTANT_PROMPT], "review": {ASSISTANT_PROMPT: PROMPT_PIN}},
            )
            gateway = deployed.view.gateway.model_dump()
            gateway["servers"][SERVER] = repinned.model_dump()
            pool.apply(ViewGateway.model_validate(gateway))
            assert connection.state.evaluation is not None
            assert set(connection.state.evaluation.kinds["prompt"].exposed) == {ASSISTANT_PROMPT}
            assert methods(fake).count("prompts/list") == listed
            # Enabling resources too changes what the connection is listed for: it closes.
            gateway["servers"][SERVER] = with_kinds(repinned, enable=["prompts"]).model_dump()
            pool.apply(ViewGateway.model_validate(gateway))
            await until(lambda: connection.state.phase is Phase.CLOSED)
    [closing] = deployed.events("upstream_closing")
    assert closing["reason"] == "policy"


async def test_a_newly_included_fixed_uri_is_listed_at_once(tmp_path: Path, quick: None) -> None:
    """J12: a review learns a fixed resource's pin, and the operator includes it. The serving walk
    listed nothing for the old, empty include, so the new view lists resources again at once
    instead of reporting the URI missing until the timer's re-list."""
    fake = McpFake(resources=True)
    # Legacy: no listen stream, whose open would list again on its own.
    with deployment(
        tmp_path, fake, include=TOOLS, review=review_of(fake), era="legacy"
    ) as deployed:
        policy = with_kinds(deployed.server, enable=["resources"])
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            first = await pool.wait_ready(connection)
            assert first.kinds["resource"].exposed == {}
            assert methods(fake).count("resources/list") == 0
            included = with_kinds(
                deployed.server,
                enable=["resources"],
                fixed={"include": [FIXED], "review": {FIXED: FIXED_PIN}},
            )
            gateway = deployed.view.gateway.model_dump()
            gateway["servers"][SERVER] = included.model_dump()
            pool.apply(ViewGateway.model_validate(gateway))

            def exposed() -> bool:
                evaluation = connection.state.evaluation
                return evaluation is not None and FIXED in evaluation.kinds["resource"].exposed

            await until(exposed)
            assert connection.state.phase is Phase.READY
    assert methods(fake).count("resources/list") == 1
    assert [line["trigger"] for line in deployed.events("listing")] == ["connect", "policy"]


async def test_a_drift_line_compares_against_its_own_servers_listing(tmp_path: Path) -> None:
    """A drift line's ``changed`` members are the drifted server's: another server's live
    connection listing a prompt of the same name, differently, is not looked at."""
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        pool = upstream.UpstreamPool(
            parse_link("http://vault.invalid"),
            None,
            DriftMarks.load(tmp_path),
            DefinitionStore(tmp_path),
        )
        reviewed = Prompt.model_validate(base_prompts()[0])
        pool.defs.put(PROMPT_PIN, pins.project_prompt(reviewed), "prompt")
        drifted = reviewed.model_copy(update={"description": "Changed."})
        other = reviewed.model_copy(update={"title": "Another server's"})
        # The other server's connection comes first, as the lookup walks the connections.
        for name, listed in (("other", other), (SERVER, drifted)):
            connection = SimpleNamespace(
                server=name, tools=[], listings={"prompt": pins.KindListing([listed])}
            )
            pool._connections[(name, "*")] = connection  # type: ignore[assignment]
        policy = reviewed_kinds(pin_server())
        pool.evaluate(SERVER, policy, [], {"prompt": pins.KindListing([drifted])})
    finally:
        logs.set_stream(None)
    lines = [json.loads(line) for line in stream.getvalue().splitlines()]
    [drift] = [line for line in lines if line["event"] == "prompt_drift"]
    assert (drift["server"], drift["name"], drift["changed"]) == (
        SERVER,
        ASSISTANT_PROMPT,
        ["description"],
    )


async def announced_until(fake: McpFake, kind: Announced, condition: Callable[[], object]) -> None:
    """Announce ``kind``'s list_changed every 2 s until ``condition`` holds (a stream a slow runner
    opens late misses the first)."""
    with anyio.fail_after(15):
        while not condition():
            await anyio.to_thread.run_sync(lambda: fake.announce(1, kind))
            with anyio.move_on_after(2):
                await until(condition, timeout=3)


@pytest.mark.parametrize("era", ["auto", "legacy"])
@pytest.mark.parametrize("kind", ["prompts", "resources"])
async def test_a_kinds_list_changed_is_a_change_signal(
    tmp_path: Path, era: str, kind: Announced, quick: None
) -> None:
    """Legacy ``notifications/<kind>/list_changed`` and the modern listen stream, which the
    gateway asks for the kinds it lists, each start a listing of every kind."""
    fake = McpFake(prompts=True, resources=True)
    with deployment(tmp_path, fake, include=TOOLS, review=review_of(fake), era=era) as deployed:
        policy = reviewed_kinds(deployed.server)
        async with pool_for(deployed) as pool:
            connection = pool.connection(SERVER, policy, CLIENTS[0])
            await pool.wait_ready(connection)
            if era == "auto":
                await until(lambda: fake.listens >= 1)

            def relisted() -> bool:
                listings = deployed.events("listing")
                return any(line["trigger"] == "list_changed" for line in listings)

            await announced_until(fake, kind, relisted)
    if era == "auto":
        [listen, *_] = fake.requests("subscriptions/listen")
        assert listen.params["notifications"] == {
            "toolsListChanged": True,
            "promptsListChanged": True,
            "resourcesListChanged": True,
        }
    relisting = next(
        line for line in deployed.events("listing") if line["trigger"] == "list_changed"
    )
    assert (relisting["prompts"], relisting["resource_templates"], relisting["resources"]) == (
        2,
        1,
        1,
    )
