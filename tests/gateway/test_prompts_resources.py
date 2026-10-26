"""Prompts, resources and completions served through the whole gateway (M6 design L.5, L.6;
SPEC-1 to SPEC-6), from an agent's SDK client through a real vault to the fake upstream's
prompts and resources modes.

The vault serves a view built directly, so a case needs no review first: :func:`changes` wraps
the vault's ``build_view`` and replaces the server's entry with one that enables and includes
them. The policy the vault routes by is the rig's own. S18
(``tests/acceptance/test_prompts_resources_shape.py``) serves them from a checked policy.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import anyio
import httpx
import mcp_types
import pytest
from mcp.client.subscriptions import PromptsListChanged
from mcp.server.context import HandlerResult
from mcp.shared.exceptions import MCPError
from mcp.types import (
    PromptReference,
    ReadResourceResult,
    ResourceTemplateReference,
    TextContent,
    TextResourceContents,
)

from tests.fakes.mcp_server import (
    ASSISTANT_PROMPT,
    FIXED,
    HIDDEN_PROMPT,
    HOSTILE,
    OTHER_URI,
    TEMPLATE,
    McpFake,
    Switch,
    base_prompts,
)
from tests.gateway.rig import (
    CLIENTS,
    SERVER,
    Running,
    agent,
    deployment,
    gateway,
    pin_of_fake,
    token_for,
    until,
)
from tests.gateway.test_upstream_kinds import (
    FIXED_PIN,
    PROMPT_PIN,
    TEMPLATE_PIN,
    kind_pin,
    with_kinds,
)
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy import view as policy_view
from zoeymcp.common.policy.view import GatewayView, ViewRemoteServer, view_digest
from zoeymcp.gateway import app as gateway_app
from zoeymcp.gateway import upstream
from zoeymcp.vault import app as vault_app

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]
PLAIN = "plain"  # a tools-only path on the same gateway
HIDDEN_PIN = kind_pin("prompt", base_prompts()[1])
WRONG_PIN = "sha256:" + "0" * 64
LEGACY = "2025-11-25"
MODERN = "2026-07-28"
BOUND = 60  # seconds for one case's agent, start to end
Reference = PromptReference | ResourceTemplateReference
# A change to the server's view entry, by server name.
Changes = dict[str, Callable[[ViewRemoteServer], ViewRemoteServer]]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def changes(monkeypatch: pytest.MonkeyPatch) -> Changes:
    """The vault's view, with each named server's entry changed as the test says: the change
    is read at every install, so a reload after a new change serves it."""
    found: Changes = {}
    built = policy_view.build_view

    def build(policy: Policy) -> GatewayView:
        view = built(policy)
        servers = dict(view.gateway.servers)
        for name, change in found.items():
            server = servers[name]
            assert isinstance(server, ViewRemoteServer)
            servers[name] = change(server)
        gateway = view.gateway.model_copy(update={"servers": servers})
        return GatewayView(v=view.v, digest=view_digest(gateway), gateway=gateway)

    monkeypatch.setattr(vault_app, "build_view", build)
    return found


def served(
    *,
    assistant: tuple[str, ...] = (),
    template_pin: str = TEMPLATE_PIN,
    prompts: tuple[str, ...] = (ASSISTANT_PROMPT, HIDDEN_PROMPT),
) -> Callable[[ViewRemoteServer], ViewRemoteServer]:
    """The server enabling every kind: both prompts, the template and the fixed resource
    included at their pins."""
    pins = {ASSISTANT_PROMPT: PROMPT_PIN, HIDDEN_PROMPT: HIDDEN_PIN}

    def change(server: ViewRemoteServer) -> ViewRemoteServer:
        return with_kinds(
            server,
            enable=["prompts", "resources", "completions"],
            prompts={
                "include": list(prompts),
                "review": {name: pins[name] for name in prompts},
                "assistant": list(assistant),
            },
            templates={"include": [TEMPLATE], "review": {TEMPLATE: template_pin}},
            fixed={"include": [FIXED], "review": {FIXED: FIXED_PIN}},
        )

    return change


def options(fake: McpFake, **extra: Any) -> dict[str, Any]:
    """The rig's policy: the notes server, and a tools-only server on the same route."""
    review = {name: pin_of_fake(fake, name) for name in TOOLS}
    plain = {
        "kind": "remote",
        "route": "notes",
        "path": "/mcp",
        "tools": {"include": TOOLS, "allow": TOOLS, "approve": []},
        "review": review,
    }
    return {
        "include": TOOLS,
        "review": review,
        "servers": {PLAIN: plain},
        "assigned": {name: [SERVER, PLAIN] for name in CLIENTS},
        **extra,
    }


def wire(model: Any) -> dict[str, Any]:
    dumped: dict[str, Any] = model.model_dump(by_alias=True, exclude_none=True, mode="json")
    return dumped


def messages(response: httpx.Response) -> list[dict[str, Any]]:
    """The JSON-RPC messages of one answer, JSON or an event stream."""
    if response.headers.get("content-type", "").startswith("application/json"):
        return [response.json()]
    found = []
    for line in response.text.splitlines():
        if line.startswith("data:") and line[5:].strip():
            found.append(json.loads(line[5:]))
    return found


def post(running: Running, server: str, method: str, version: str | None) -> httpx.Response:
    """One raw request on a path, with no session: the method check comes before one."""
    params: dict[str, Any] = {}
    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "authorization": f"Bearer {token_for(CLIENTS[0])}",
    }
    if version is not None:
        headers["mcp-protocol-version"] = version
    if method == "initialize":
        params = {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": {"name": "a", "version": "1"},
        }
    elif version == MODERN:
        params = {
            "_meta": {
                mcp_types.PROTOCOL_VERSION_META_KEY: MODERN,
                mcp_types.CLIENT_CAPABILITIES_META_KEY: {},
                mcp_types.CLIENT_INFO_META_KEY: {"name": "a", "version": "1"},
            }
        }
        headers["mcp-method"] = method
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    return httpx.post(running.mcp(server), json=body, headers=headers, timeout=30)


def result_of(response: httpx.Response) -> dict[str, Any]:
    [message] = messages(response)
    assert "result" in message, message
    result: dict[str, Any] = message["result"]
    return result


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Listings may follow each other at once."""
    monkeypatch.setattr(upstream, "COALESCE", 0.0)


@pytest.fixture
def deployed_fake(tmp_path: Path, changes: Changes) -> Iterator[tuple[McpFake, Running]]:
    fake = McpFake(prompts=True, resources=True)
    changes[SERVER] = served()
    with deployment(tmp_path, fake, **options(fake)) as deployed, gateway(deployed) as running:
        yield fake, running


# --- capabilities per path (L.5, Y22) ------------------------------------------------------------

EVERY_KIND = {
    "tools": {"listChanged": True},
    "prompts": {"listChanged": True},
    "resources": {"listChanged": True},
    "completions": {},
}


async def test_each_path_states_what_it_serves_in_both_eras(
    deployed_fake: tuple[McpFake, Running],
) -> None:
    """The legacy initialize and the modern discover state the path's own kinds, never
    subscribe; the tools-only path on the same gateway states tools alone, as before."""
    fake, running = deployed_fake
    assert result_of(post(running, SERVER, "initialize", None))["capabilities"] == EVERY_KIND
    assert result_of(post(running, SERVER, "server/discover", MODERN))["capabilities"] == EVERY_KIND
    plain = {"tools": {"listChanged": True}}
    assert result_of(post(running, PLAIN, "initialize", None))["capabilities"] == plain
    assert result_of(post(running, PLAIN, "server/discover", MODERN))["capabilities"] == plain
    with anyio.fail_after(BOUND):
        for mode in ("auto", "legacy"):
            async with agent(running, mode=mode) as client:
                assert wire(client.server_capabilities) == EVERY_KIND
            async with agent(running, mode=mode, server=PLAIN) as client:
                assert wire(client.server_capabilities) == plain
    # The upstream is never told of a client capability (D-60).
    for item in fake.requests("initialize"):
        assert item.params["capabilities"] == {}


async def test_the_initialize_capabilities_fail_closed() -> None:
    """With no request scope, or no result to rewrite, the SDK's own capabilities (every path's
    kinds at once) never pass through: ``initialize`` is refused. Other methods pass untouched."""
    sdks = {"capabilities": EVERY_KIND}
    initialize = cast(Any, SimpleNamespace(method="initialize"))
    listing = cast(Any, SimpleNamespace(method="tools/list"))

    async def answer(ctx: Any) -> HandlerResult:
        return dict(sdks)

    async def nothing(ctx: Any) -> HandlerResult:
        return None

    with anyio.fail_after(BOUND):
        assert await gateway_app.capabilities_from_path(listing, answer) == sdks
        with pytest.raises(MCPError) as unscoped:
            await gateway_app.capabilities_from_path(initialize, answer)
        token = gateway_app.CURRENT.set(cast(Any, SimpleNamespace(policy=None)))
        try:
            with pytest.raises(MCPError) as undicted:
                await gateway_app.capabilities_from_path(initialize, nothing)
        finally:
            gateway_app.CURRENT.reset(token)
    assert unscoped.value.error.code == mcp_types.INTERNAL_ERROR
    assert undicted.value.error.code == mcp_types.INTERNAL_ERROR


@pytest.mark.parametrize(
    "method",
    [
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "completion/complete",
    ],
)
@pytest.mark.parametrize(("version", "status"), [(MODERN, 404), (LEGACY, 200)])
async def test_a_path_that_doesnt_serve_a_kind_answers_method_not_found(
    deployed_fake: tuple[McpFake, Running], method: str, version: str, status: int
) -> None:
    """Y22: -32601 before any handler runs, with the era's status, on the tools-only path,
    while the other path on the same gateway serves the kind."""
    fake, running = deployed_fake
    response = post(running, PLAIN, method, version)  # bounded by its own timeout: no await
    assert response.status_code == status
    [message] = messages(response)
    assert message["error"]["code"] == -32601
    assert fake.requests(method) == [] or method.endswith("/list")


# --- lists (L.6, SPEC-3) --------------------------------------------------------------------------


async def test_the_lists_are_the_pinned_projections_with_the_modern_cache_fields(
    deployed_fake: tuple[McpFake, Running],
) -> None:
    _fake, running = deployed_fake
    with anyio.fail_after(BOUND):
        async with agent(running) as client:
            prompts = await client.list_prompts()
            templates = await client.list_resource_templates()
            resources = await client.list_resources()
            read = await client.read_resource(FIXED)
    assert [prompt.name for prompt in prompts.prompts] == [ASSISTANT_PROMPT, HIDDEN_PROMPT]
    assert [template.uri_template for template in templates.resource_templates] == [TEMPLATE]
    assert [resource.uri for resource in resources.resources] == [FIXED]
    # The pinned projection: the fixed resource's size is never served (L.2).
    assert resources.resources[0].size is None
    for listed in (prompts, templates, resources):
        assert (listed.ttl_ms, listed.cache_scope) == (gateway_app.LISTING_TTL_MS, "private")
    assert gateway_app.LISTING_TTL_MS == 60_000
    # A read's contents are live: never cached (SPEC-3).
    assert (read.ttl_ms, read.cache_scope) == (0, "private")


async def test_a_legacy_agent_lists_every_kind(deployed_fake: tuple[McpFake, Running]) -> None:
    _fake, running = deployed_fake
    with anyio.fail_after(BOUND):
        async with agent(running, mode="legacy") as client:
            assert client.protocol_version == LEGACY
            assert len((await client.list_prompts()).prompts) == 2
            assert len((await client.list_resource_templates()).resource_templates) == 1
            assert len((await client.list_resources()).resources) == 1


async def test_a_list_has_one_page(deployed_fake: tuple[McpFake, Running]) -> None:
    _fake, running = deployed_fake
    with anyio.fail_after(BOUND):
        async with agent(running) as client:
            with pytest.raises(MCPError) as caught:
                await client.list_prompts(cursor="next")
    assert caught.value.error.code == mcp_types.INVALID_PARAMS


# --- prompts/get (L.6, Q19) --------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_an_assistant_message_is_refused_unless_the_prompt_is_listed(
    tmp_path: Path, changes: Changes, mode: str
) -> None:
    fake = McpFake(prompts=True, resources=True)
    changes[SERVER] = served()
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running, mode=mode) as client:
            with pytest.raises(MCPError) as caught:
                await client.get_prompt(ASSISTANT_PROMPT, {"topic": "notes"})
        changes[SERVER] = served(assistant=(ASSISTANT_PROMPT,))
        deployed.reload(**options(fake))
        await until(
            lambda: (
                running.app.policy.snapshot is not None
                and ASSISTANT_PROMPT
                in (
                    running.app.policy.snapshot.view.gateway.servers[SERVER].prompts.assistant  # type: ignore[union-attr]
                )
            )
        )
        async with agent(running, mode=mode) as client:
            allowed = await client.get_prompt(ASSISTANT_PROMPT, {"topic": "notes"})
    assert caught.value.error.code == mcp_types.INTERNAL_ERROR
    assert caught.value.error.message == (
        "the server's prompt speaks as the assistant, which this gateway refuses for brainstorm"
    )
    assert [message.role for message in allowed.messages] == ["user", "assistant"]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_a_prompts_text_is_revealed_and_another_uris_block_dropped_and_counted(
    deployed_fake: tuple[McpFake, Running], mode: str
) -> None:
    """The hidden prompt's zero-width character is shown, and its resource block naming a URI
    the path doesn't serve is dropped, its count under _meta, never as a message."""
    _fake, running = deployed_fake
    with anyio.fail_after(BOUND):
        async with agent(running, mode=mode) as client:
            result = await client.get_prompt(HIDDEN_PROMPT, {"id": "7"})
    assert len(result.messages) == 1
    content = result.messages[0].content
    assert isinstance(content, TextContent)
    assert content.text == "Summarize.[U+200B]"
    assert result.meta is not None
    assert result.meta["zoeymcp/dropped"] == 1
    assert HOSTILE not in json.dumps(wire(result))
    assert OTHER_URI not in json.dumps(wire(result))


async def test_only_declared_arguments_go_upstream(deployed_fake: tuple[McpFake, Running]) -> None:
    fake, running = deployed_fake
    with anyio.fail_after(BOUND):
        async with agent(running) as client:
            await client.get_prompt(HIDDEN_PROMPT, {"id": "7", "style": "short"})
            with pytest.raises(MCPError) as undeclared:
                await client.get_prompt(HIDDEN_PROMPT, {"id": "7", "evil": "x"})
            with pytest.raises(MCPError) as unknown:
                await client.get_prompt("nope", {})
            # Over max_argument_bytes (256 KiB), under the request's 1 MiB.
            with pytest.raises(MCPError) as big:
                await client.get_prompt(HIDDEN_PROMPT, {"id": "x" * (300 * 1024)})
    assert (undeclared.value.error.code, undeclared.value.error.message) == (
        mcp_types.INVALID_PARAMS,
        "arguments refused: not a declared argument",
    )
    assert (unknown.value.error.code, unknown.value.error.message) == (
        mcp_types.INVALID_PARAMS,
        "Unknown prompt",
    )
    assert big.value.error.message == "arguments refused: too large"
    [asked] = fake.requests("prompts/get")
    assert asked.params["arguments"] == {"id": "7", "style": "short"}
    assert asked.params["_meta"][mcp_types.CLIENT_CAPABILITIES_META_KEY] == {}


async def test_an_unincluded_prompt_is_unknown(tmp_path: Path, changes: Changes) -> None:
    fake = McpFake(prompts=True, resources=True)
    changes[SERVER] = served(prompts=(HIDDEN_PROMPT,))
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running) as client:
            assert [p.name for p in (await client.list_prompts()).prompts] == [HIDDEN_PROMPT]
            with pytest.raises(MCPError) as caught:
                await client.get_prompt(ASSISTANT_PROMPT, {"topic": "x"})
    assert caught.value.error.message == "Unknown prompt"
    assert fake.requests("prompts/get") == []


# --- resources/read (L.6, SPEC-2, SPEC-4, SPEC-5) -----------------------------------------------

REFUSED_URIS = [
    "notes://notes/.",
    "notes://notes/..",
    "notes://notes/%2E%2E",
    "notes://notes/%2e",
    "notes://other/1",
    "notes://notes/1/2",
    OTHER_URI,
    FIXED + "/",
]


@pytest.mark.parametrize(("mode", "code"), [("auto", -32602), ("legacy", -32002)])
async def test_a_read_is_not_found_unless_the_path_allows_the_uri(
    deployed_fake: tuple[McpFake, Running], mode: str, code: int
) -> None:
    """SPEC-2's refusals, with the era's not-found code (SPEC-4) and nothing sent upstream."""
    fake, running = deployed_fake
    with anyio.fail_after(BOUND):
        async with agent(running, mode=mode) as client:
            note = await client.read_resource("notes://notes/7")
            index = await client.read_resource(FIXED)
            refused = []
            for uri in REFUSED_URIS:
                with pytest.raises(MCPError) as caught:
                    await client.read_resource(uri)
                refused.append((caught.value.error.code, caught.value.error.message))
    assert [wire(item) for item in note.contents] == [
        {"uri": "notes://notes/7", "mimeType": "text/markdown", "text": "Note 7."}
    ]
    assert [item.uri for item in index.contents] == [FIXED]
    assert refused == [(code, "not found")] * len(REFUSED_URIS)
    assert sorted(item.params["uri"] for item in fake.requests("resources/read")) == [
        FIXED,
        "notes://notes/7",
    ]


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_another_uris_contents_are_dropped_and_counted(
    tmp_path: Path, changes: Changes, mode: str
) -> None:
    """MISS-7, SPEC-5: contents naming a second URI never reach the agent."""
    fake = McpFake(prompts=True, resources=True, switches={Switch.READ_OTHER_URI})
    changes[SERVER] = served()
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running, mode=mode) as client:
            read = await client.read_resource("notes://notes/7")
    assert [item.uri for item in read.contents] == ["notes://notes/7"]
    assert read.meta is not None
    assert read.meta["zoeymcp/dropped"] == 1
    assert HOSTILE not in json.dumps(wire(read))


@pytest.mark.parametrize(("mode", "code"), [("auto", -32602), ("legacy", -32002)])
async def test_nothing_left_is_not_found_never_an_empty_answer(
    tmp_path: Path, changes: Changes, monkeypatch: pytest.MonkeyPatch, mode: str, code: int
) -> None:
    fake = McpFake(prompts=True, resources=True)

    async def only_another(ctx: Any, params: Any) -> ReadResourceResult:
        contents = [TextResourceContents(uri=OTHER_URI, text=HOSTILE)]
        return ReadResourceResult(contents=contents)

    monkeypatch.setattr(fake, "_read_resource", only_another)
    changes[SERVER] = served()
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running, mode=mode) as client:
            with pytest.raises(MCPError) as caught:
                await client.read_resource("notes://notes/7")
    assert (caught.value.error.code, caught.value.error.message) == (code, "not found")


# --- completion/complete (L.6, MISS-8, SPEC-6) --------------------------------------------------


async def test_a_completion_names_a_served_prompt_or_template_and_their_arguments(
    deployed_fake: tuple[McpFake, Running],
) -> None:
    fake, running = deployed_fake
    prompt = PromptReference(type="ref/prompt", name=ASSISTANT_PROMPT)
    template = ResourceTemplateReference(type="ref/resource", uri=TEMPLATE)
    refused: list[tuple[int, str]] = []
    cases: list[tuple[Reference, dict[str, str], dict[str, str] | None]] = [
        (
            PromptReference(type="ref/prompt", name="nope"),
            {"name": "topic", "value": "a"},
            None,
        ),
        (
            ResourceTemplateReference(type="ref/resource", uri="notes://x/{id}"),
            {"name": "id", "value": "a"},
            None,
        ),
        (prompt, {"name": "style", "value": "a"}, None),
        (template, {"name": "topic", "value": "a"}, None),
        (prompt, {"name": "topic", "value": "a"}, {"evil": "x"}),
        (template, {"name": "id", "value": "a"}, {"topic": "x"}),
    ]
    with anyio.fail_after(BOUND):
        async with agent(running) as client:
            by_prompt = await client.complete(
                prompt, {"name": "topic", "value": "no"}, {"topic": "a"}
            )
            by_template = await client.complete(template, {"name": "id", "value": "7"})
            for ref, argument, context in cases:
                with pytest.raises(MCPError) as caught:
                    await client.complete(ref, argument, context)
                refused.append((caught.value.error.code, caught.value.error.message))
    assert by_prompt.completion.values == ["no-0", "no-1"]
    assert (by_prompt.completion.total, by_prompt.completion.has_more) == (2, False)
    assert by_template.completion.values == ["7-0", "7-1"]
    unknown = (mcp_types.INVALID_PARAMS, "Unknown reference")
    undeclared = (mcp_types.INVALID_PARAMS, "arguments refused: not a declared argument")
    assert refused == [unknown, unknown, undeclared, undeclared, undeclared, undeclared]
    sent = fake.requests("completion/complete")
    assert len(sent) == 2
    # context.arguments goes upstream only with the prompt's own keys (SPEC-6).
    assert sent[0].params["context"] == {"arguments": {"topic": "a"}}
    assert sent[0].params["ref"] == {"type": "ref/prompt", "name": ASSISTANT_PROMPT}


# --- upstream errors (L.6, H13) ------------------------------------------------------------------


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_a_missing_client_capability_gets_the_gateways_text(
    tmp_path: Path, changes: Changes, mode: str
) -> None:
    fake = McpFake(prompts=True, resources=True, switches={Switch.MISSING_CAPABILITY})
    changes[SERVER] = served()
    answers = []
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running, mode=mode) as client:
            for call in (
                client.get_prompt(HIDDEN_PROMPT, {"id": "1"}),
                client.read_resource(FIXED),
                client.complete(
                    PromptReference(type="ref/prompt", name=ASSISTANT_PROMPT),
                    {"name": "topic", "value": "a"},
                ),
            ):
                with pytest.raises(MCPError) as caught:
                    await call
                answers.append((caught.value.error.code, caught.value.error.message))
    capability = (-32021, "the server needs a capability this gateway doesn't offer")
    assert answers == [capability] * 3


async def test_an_upstream_that_asks_for_input_is_refused(tmp_path: Path, changes: Changes) -> None:
    """H13: an InputRequiredResult on prompts/get or resources/read is refused, as for tools."""
    fake = McpFake(prompts=True, resources=True, switches={Switch.INPUT_REQUIRED})
    changes[SERVER] = served()
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running) as client:
            with pytest.raises(MCPError) as prompt:
                await client.get_prompt(HIDDEN_PROMPT, {"id": "1"})
            with pytest.raises(MCPError) as read:
                await client.read_resource(FIXED)
    for caught in (prompt, read):
        assert caught.value.error.code == mcp_types.INTERNAL_ERROR
        assert caught.value.error.message.startswith(
            "refused: the server asked for input this gateway doesn't relay (ref "
        )
    assert len(fake.requests("prompts/get")) == len(fake.requests("resources/read")) == 1


# --- list changes, both eras (SPEC-1) ------------------------------------------------------------


async def test_a_drifted_prompt_is_hidden_and_a_legacy_session_told(
    tmp_path: Path, changes: Changes, quick: None
) -> None:
    fake = McpFake(prompts=True, resources=True)
    changes[SERVER] = served()
    seen: list[object] = []
    opened = anyio.Event()

    async def handler(message: object) -> None:
        seen.append(getattr(message, "method", None))

    with (
        deployment(tmp_path, fake, **options(fake, era="legacy")) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running, mode="legacy", message_handler=handler, opened=opened) as client:
            assert client.protocol_version == LEGACY
            assert len((await client.list_prompts()).prompts) == 2
            await opened.wait()  # the agent's GET stream, where the notification goes
            fake.change_kind("prompt")
            fake.announce(kind="prompts")
            await until(lambda: "notifications/prompts/list_changed" in seen)
            names = [prompt.name for prompt in (await client.list_prompts()).prompts]
            with pytest.raises(MCPError) as caught:
                await client.get_prompt(ASSISTANT_PROMPT, {"topic": "a"})
    assert names == [HIDDEN_PROMPT]
    assert caught.value.error.message == "Unknown prompt"
    assert "notifications/resources/list_changed" not in seen
    assert deployed.events("prompts_changed_sent")
    assert [line["name"] for line in deployed.events("prompt_drift")] == [ASSISTANT_PROMPT]


async def test_a_repinned_template_tells_a_legacy_session(
    tmp_path: Path, changes: Changes, quick: None
) -> None:
    fake = McpFake(prompts=True, resources=True)
    changes[SERVER] = served(template_pin=WRONG_PIN)
    seen: list[object] = []
    opened = anyio.Event()

    async def handler(message: object) -> None:
        seen.append(getattr(message, "method", None))

    with (
        deployment(tmp_path, fake, **options(fake, era="legacy")) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running, mode="legacy", message_handler=handler, opened=opened) as client:
            # The template drifted from the pin the policy holds: hidden.
            assert (await client.list_resource_templates()).resource_templates == []
            await opened.wait()
            changes[SERVER] = served()
            deployed.reload(**options(fake, era="legacy"))
            await until(lambda: "notifications/resources/list_changed" in seen)
            # The notification follows the re-evaluation: the next listing has the template.
            templates = (await client.list_resource_templates()).resource_templates
    assert [template.uri_template for template in templates] == [TEMPLATE]
    assert deployed.events("resources_changed_sent")


async def test_a_modern_listen_is_told_only_of_the_lists_the_path_serves(
    tmp_path: Path, changes: Changes, quick: None
) -> None:
    """K.4 per path: the acknowledgment names prompts and resources here, never a resource
    subscription, and the stream carries the prompts' change."""
    fake = McpFake(prompts=True, resources=True)
    changes[SERVER] = served()
    with (
        deployment(tmp_path, fake, **options(fake)) as deployed,
        gateway(deployed) as running,
        anyio.fail_after(BOUND),
    ):
        async with agent(running) as client:
            await client.list_prompts()
            async with client.listen(
                tools_list_changed=True,
                prompts_list_changed=True,
                resources_list_changed=True,
                resource_subscriptions=[FIXED],
            ) as events:
                honored = events.honored.model_dump(by_alias=True, exclude_none=True)
                fake.change_kind("prompt")
                fake.announce(kind="prompts")
                event = await events.__anext__()
    assert honored == {
        "toolsListChanged": True,
        "promptsListChanged": True,
        "resourcesListChanged": True,
    }
    assert isinstance(event, PromptsListChanged)
