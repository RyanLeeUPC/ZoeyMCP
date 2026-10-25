"""Contracts 57 to 61 (M6 design O.2): what M6's code relies on in the MCP SDK, and in
``cryptography`` for 61. Each lands in the step before the code that leans on it.

Contract 58 (step 18): ``mcp_types`` parse a prompt, a resource template and a resource with
every member design L.2 pins, each under the member the projection reads, and drop a member
they don't know, so a projection that reads L.2's members by name reads all of them and
nothing else. A priority is a float even when the wire writes a whole number, as the pins read
it. The pin golden vectors in ``tests/unit/test_format_stability.py`` start from those members.

Contract 59 (step 3a): the SDK's ``ListenHandler`` acknowledges every kind a listen asks for,
whether or not the server will ever send it, and then delivers only the kinds it acknowledged.
The gateway hands an agent's listen to that handler as it came (``gateway/app.py``'s
``_listen``), so its acknowledgment can name prompts, resources and resource subscriptions the
gateway never sends; design K.4's filter narrows the params first (step 3b). The server here is
shaped as the gateway's client-facing side is (``test_server_contract.Shaped``), and the stream
is read raw, since the SDK client also drops on its own side whatever wasn't acknowledged.

Contract 60 (step 19): the SDK client, as the gateway opens it (``input_required_max_rounds=0``,
``gateway/upstream.py``), raises ``InputRequiredRoundsExceededError`` when ``get_prompt`` or
``read_resource`` meets an ``InputRequiredResult``, so an upstream that asks for input is refused
as a tool call that asks is (H13); ``complete()`` sends a modern request with the per-request
``_meta`` every modern request has, which the egress filter checks; and an upstream's -32021
(a client capability it needs) surfaces as ``MCPError`` with that code, for both eras, so the
gateway can answer it with its own text (L.6). The upstream is ``tests/fakes/mcp_server.py``'s
prompts and resources modes.

Contract 61 (step 11a): ``cryptography``'s ``AESGCM``, which encrypts the managed policy's
revision bodies (``vault/policyseal.py``, design D.2), refuses a ciphertext whose associated data or
nonce changed, so a body moved under another header doesn't decrypt. It takes any nonce from 8 to
128 bytes, not only the 12 D.2 names, so ``keys.PolicyKey`` checks the length itself.

They join D-95's re-run list: run again on every SDK bump, and 61 on every ``cryptography`` bump.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import anyio
import httpx
import httpx2
import mcp_types
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mcp import Client, InputRequiredRoundsExceededError
from mcp.client.streamable_http import streamable_http_client
from mcp.server.subscriptions import (
    SUBSCRIPTION_ID_META_KEY,
    PromptsListChanged,
    ResourcesListChanged,
    ResourceUpdated,
    ServerEvent,
    ToolsListChanged,
)
from mcp.shared.exceptions import MCPError
from mcp.types import Prompt, PromptReference, Resource, ResourceTemplate
from pydantic import BaseModel

from tests.fakes.harness import serve
from tests.fakes.mcp_server import ASSISTANT_PROMPT, FIXED, PATH, McpFake, Switch

from .test_server_contract import Shaped, modern_body, modern_headers, modern_post, running

pytestmark = pytest.mark.anyio

ACKNOWLEDGED = "notifications/subscriptions/acknowledged"
NOTES = "file:///notes.txt"
# Every SDK interaction gets a deadline, so a behaviour change after a bump fails, not hangs.
DEADLINE = 5


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Frames:
    """The JSON-RPC messages of one listen stream, in the order sent."""

    def __init__(self, lines: AsyncIterator[str]) -> None:
        self._lines = lines

    async def next(self) -> dict[str, Any]:
        with anyio.fail_after(DEADLINE):
            async for line in self._lines:
                if line.startswith("data:") and line[5:].strip():
                    message: dict[str, Any] = json.loads(line[5:])
                    return message
        raise AssertionError("the stream ended")


@asynccontextmanager
async def listening(url: str, notifications: dict[str, Any]) -> AsyncIterator[Frames]:
    """A raw modern ``subscriptions/listen`` from client ``a``, open until the block ends."""
    method = "subscriptions/listen"
    body = modern_body(method, {"notifications": notifications})
    timeout = httpx.Timeout(10.0, read=30.0)
    async with (
        httpx.AsyncClient(timeout=timeout) as http,
        http.stream("POST", url, json=body, headers=modern_headers(method)) as response,
    ):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        yield Frames(response.aiter_lines())


# --- 58. a prompt, a resource template and a resource, as L.2 pins them --------------------------

ICONS = '"icons":[{"src":"https://icons.example/p.png"}],"_meta":{"k":"v"},"x-unknown":1'
PROMPT_WIRE = (
    '{"name":"summarize","title":"Summarize","description":"Summarizes a note.","arguments":'
    '[{"name":"style","title":"Style","description":"How.","required":false,"x-unknown":1},'
    '{"name":"id","required":true}],' + ICONS + "}"
)
ANNOTATIONS = (
    '"annotations":{"audience":["user","assistant"],"priority":0.5,'
    '"lastModified":"2026-10-01T00:00:00Z","x-unknown":1}'
)
TEMPLATE_WIRE = (
    '{"uriTemplate":"notes://notes/{id}","name":"note","title":"A note","description":"One note.",'
    '"mimeType":"text/markdown",' + ANNOTATIONS + "," + ICONS + "}"
)
RESOURCE_WIRE = (
    '{"uri":"notes://index","name":"index","title":"Index","description":"Every note.",'
    '"mimeType":"application/json","size":12,' + ANNOTATIONS + "," + ICONS + "}"
)


def plain(model: BaseModel) -> dict[str, Any]:
    """A parsed model under its wire names, members left unset left out."""
    found: dict[str, Any] = model.model_dump(mode="json", by_alias=True, exclude_none=True)
    return found


def test_58_a_prompt_keeps_every_member_l2_pins_and_no_unknown_one() -> None:
    """L.2's prompt projection reads ``name``, ``title``, ``description`` and each argument's
    ``name``, ``title``, ``description`` and ``required``, in listed order; ``icons`` and
    ``_meta`` are parsed into members of their own, never pinned; an unknown member is dropped."""
    prompt = Prompt.model_validate_json(PROMPT_WIRE)
    assert (prompt.name, prompt.title, prompt.description) == (
        "summarize",
        "Summarize",
        "Summarizes a note.",
    )
    assert prompt.arguments is not None
    assert [(a.name, a.title, a.description, a.required) for a in prompt.arguments] == [
        ("style", "Style", "How.", False),
        ("id", None, None, True),
    ]
    assert set(plain(prompt)) == {"name", "title", "description", "arguments", "icons", "_meta"}
    assert set(plain(prompt.arguments[0])) == {"name", "title", "description", "required"}
    assert "x-unknown" not in json.dumps(plain(prompt))


def test_58_a_resource_template_keeps_every_member_l2_pins_and_no_unknown_one() -> None:
    """``uriTemplate``, ``name``, ``title``, ``description``, ``mimeType`` and the annotations'
    ``audience`` and ``priority``; ``lastModified`` is a member of its own, never pinned."""
    template = ResourceTemplate.model_validate_json(TEMPLATE_WIRE)
    assert (template.uri_template, template.name, template.title, template.description) == (
        "notes://notes/{id}",
        "note",
        "A note",
        "One note.",
    )
    assert template.mime_type == "text/markdown"
    assert template.annotations is not None
    assert (template.annotations.audience, template.annotations.priority) == (
        ["user", "assistant"],
        0.5,
    )
    assert template.annotations.last_modified == "2026-10-01T00:00:00Z"
    pinned = {"uriTemplate", "name", "title", "description", "mimeType", "annotations"}
    assert set(plain(template)) == {*pinned, "icons", "_meta"}
    assert set(plain(template.annotations)) == {"audience", "priority", "lastModified"}
    assert "x-unknown" not in json.dumps(plain(template))


def test_58_a_resource_keeps_every_member_l2_pins_and_no_unknown_one() -> None:
    """``uri`` and the same metadata as a template; ``size`` is a member of its own, never
    pinned."""
    resource = Resource.model_validate_json(RESOURCE_WIRE)
    assert (resource.uri, resource.name, resource.title, resource.description) == (
        "notes://index",
        "index",
        "Index",
        "Every note.",
    )
    assert (resource.mime_type, resource.size) == ("application/json", 12)
    assert resource.annotations is not None
    assert (resource.annotations.audience, resource.annotations.priority) == (
        ["user", "assistant"],
        0.5,
    )
    pinned = {"uri", "name", "title", "description", "mimeType", "annotations"}
    assert set(plain(resource)) == {*pinned, "size", "icons", "_meta"}
    assert "x-unknown" not in json.dumps(plain(resource))


@pytest.mark.parametrize(
    ("model", "wire"),
    [
        (ResourceTemplate, '{"uriTemplate":"notes://notes/{id}","name":"note",'),
        (Resource, '{"uri":"notes://index","name":"index",'),
    ],
    ids=["template", "resource"],
)
def test_58_a_whole_priority_is_read_as_a_float(model: type[BaseModel], wire: str) -> None:
    """A wire ``1`` is the float ``1.0``, which canonical JSON writes apart from ``1``: the pin
    golden vectors hold the float, so a parse that kept the integer would move every such pin."""
    parsed = model.model_validate_json(wire + '"annotations":{"priority":1}}')
    priority = plain(parsed)["annotations"]["priority"]
    assert (type(priority), priority) == (float, 1.0)


# --- 59. the listen acknowledgment -------------------------------------------------------------


@pytest.mark.parametrize(
    ("asked", "acknowledged"),
    [
        (
            {
                "toolsListChanged": True,
                "promptsListChanged": True,
                "resourcesListChanged": True,
                "resourceSubscriptions": [NOTES],
            },
            {
                "toolsListChanged": True,
                "promptsListChanged": True,
                "resourcesListChanged": True,
                "resourceSubscriptions": [NOTES],
            },
        ),
        # A false flag or an empty list is left out, not echoed.
        (
            {"toolsListChanged": True, "promptsListChanged": False, "resourceSubscriptions": []},
            {"toolsListChanged": True},
        ),
    ],
)
async def test_59_listen_handler_acknowledges_every_kind_asked_for(
    asked: dict[str, Any], acknowledged: dict[str, Any]
) -> None:
    """Even kinds the server doesn't serve: it registers only the tools handlers."""
    shaped = Shaped()
    with running(shaped) as url:
        discovered = modern_post(url, "server/discover").json()["result"]["capabilities"]
        async with listening(url, asked) as frames:
            ack = await frames.next()
    assert not {"prompts", "resources"} & set(discovered)
    assert ack["method"] == ACKNOWLEDGED
    assert ack["params"]["notifications"] == acknowledged
    assert ack["params"]["_meta"] == {SUBSCRIPTION_ID_META_KEY: 7}


async def test_59_listen_handler_delivers_only_the_kinds_it_acknowledged() -> None:
    shaped = Shaped()
    asked = {"toolsListChanged": True, "promptsListChanged": True, "resourceSubscriptions": [NOTES]}
    events: list[ServerEvent] = [
        ResourcesListChanged(),
        ResourceUpdated(uri="file:///other.txt"),
        ResourceUpdated(uri=NOTES),
        PromptsListChanged(),
        ToolsListChanged(),
    ]
    with running(shaped) as url:
        async with listening(url, asked) as frames:
            ack = await frames.next()
            for event in events:
                await shaped.run(shaped.buses["a"].publish(event))
            delivered = [await frames.next() for _ in range(3)]
            with anyio.move_on_after(0.5) as quiet:
                await frames.next()
    assert ack["method"] == ACKNOWLEDGED
    assert [frame["method"] for frame in delivered] == [
        "notifications/resources/updated",
        "notifications/prompts/list_changed",
        "notifications/tools/list_changed",
    ]
    assert delivered[0]["params"]["uri"] == NOTES
    assert all(frame["params"]["_meta"] == {SUBSCRIPTION_ID_META_KEY: 7} for frame in delivered)
    assert quiet.cancelled_caught


# --- 60. prompts and resources, as the gateway's client asks for them ----------------------------


@asynccontextmanager
async def upstream(fake: McpFake, mode: str = "auto") -> AsyncIterator[Client]:
    """An SDK client opened as the gateway opens one, on the fake with prompts and resources."""
    fake.prompts = fake.resources = True
    with serve(fake.app(), lifespan=True) as url:
        async with httpx2.AsyncClient(timeout=httpx2.Timeout(10.0)) as http:
            transport = streamable_http_client(url + PATH, http_client=http)
            client = Client(transport, mode=mode, cache=None, input_required_max_rounds=0)
            async with client as connected:
                yield connected


async def ask(client: Client, call: str) -> object:
    """One get, read or completion of the fake's first prompt or its fixed resource."""
    if call == "get_prompt":
        return await client.get_prompt(ASSISTANT_PROMPT, {"topic": "notes"})
    if call == "read_resource":
        return await client.read_resource(FIXED)
    return await client.complete(
        PromptReference(type="ref/prompt", name=ASSISTANT_PROMPT), {"name": "topic", "value": "no"}
    )


@pytest.mark.parametrize("call", ["get_prompt", "read_resource"])
async def test_60_an_input_required_result_raises_with_no_rounds(call: str) -> None:
    fake = McpFake(switches={Switch.INPUT_REQUIRED})
    async with upstream(fake) as client:
        assert client.protocol_version == "2026-07-28"
        with anyio.fail_after(DEADLINE), pytest.raises(InputRequiredRoundsExceededError):
            await ask(client, call)
    method = "prompts/get" if call == "get_prompt" else "resources/read"
    # Asked once: no round answered, nothing retried with inputResponses or requestState.
    [asked] = fake.requests(method)
    assert not {"inputResponses", "requestState"} & set(asked.params)


async def test_60_complete_carries_the_modern_per_request_meta() -> None:
    fake = McpFake()
    async with upstream(fake) as client:
        with anyio.fail_after(DEADLINE):
            result = await client.complete(
                PromptReference(type="ref/prompt", name=ASSISTANT_PROMPT),
                {"name": "topic", "value": "no"},
                context_arguments={"style": "short"},
            )
    assert result.completion.values == ["no-0", "no-1"]
    [asked] = fake.requests("completion/complete")
    assert asked.meta_keys == sorted(
        [
            mcp_types.PROTOCOL_VERSION_META_KEY,
            mcp_types.CLIENT_CAPABILITIES_META_KEY,
            mcp_types.CLIENT_INFO_META_KEY,
        ]
    )
    assert asked.params["_meta"][mcp_types.CLIENT_CAPABILITIES_META_KEY] == {}
    assert asked.params["context"] == {"arguments": {"style": "short"}}


@pytest.mark.parametrize("mode", ["auto", "legacy"])
@pytest.mark.parametrize("call", ["get_prompt", "read_resource", "complete"])
async def test_60_a_missing_client_capability_is_an_mcp_error_with_its_code(
    mode: str, call: str
) -> None:
    fake = McpFake(switches={Switch.MISSING_CAPABILITY})
    async with upstream(fake, mode) as client:
        with anyio.fail_after(DEADLINE), pytest.raises(MCPError) as caught:
            await ask(client, call)
    assert caught.value.error.code == mcp_types.MISSING_REQUIRED_CLIENT_CAPABILITY == -32021


# --- 61. AES-GCM, as the policy store's revision bodies use it ------------------------------------

KEY = bytes(range(32))
NONCE = bytes(range(12))
ASSOCIATED = b"zoeymcp/policy-body/v1\nsha256:" + b"0" * 64


def test_61_aesgcm_refuses_a_changed_associated_data_or_nonce() -> None:
    """The associated data binds a revision's body to its header (D.2): a body moved under another
    header, or decrypted with another nonce, fails as a whole, with no plaintext."""
    sealed = AESGCM(KEY).encrypt(NONCE, b"body", ASSOCIATED)
    assert len(sealed) == len(b"body") + 16
    assert AESGCM(KEY).decrypt(NONCE, sealed, ASSOCIATED) == b"body"
    for nonce, associated in (
        (NONCE, ASSOCIATED[:-1] + b"1"),
        (NONCE, b""),
        (NONCE, None),
        (bytes(range(1, 13)), ASSOCIATED),
    ):
        with pytest.raises(InvalidTag):
            AESGCM(KEY).decrypt(nonce, sealed, associated)
    with pytest.raises(InvalidTag):
        AESGCM(bytes(range(1, 33))).decrypt(NONCE, sealed, ASSOCIATED)
    with pytest.raises(InvalidTag):
        AESGCM(KEY).decrypt(NONCE, sealed[:-1] + bytes([sealed[-1] ^ 1]), ASSOCIATED)


def test_61_aesgcm_takes_nonces_of_8_to_128_bytes_so_the_policy_key_checks_for_12() -> None:
    """D.2 names a 12-byte nonce, but ``AESGCM`` doesn't require one: any length from 8 to 128
    bytes is accepted. ``keys.PolicyKey`` refuses every length but 12 itself."""
    for size in (8, 12, 13, 16, 128):
        assert AESGCM(KEY).encrypt(bytes(size), b"body", None)
    for size in (0, 7, 129):
        with pytest.raises(ValueError, match=r"^Nonce must be between 8 and 128 bytes$"):
            AESGCM(KEY).encrypt(bytes(size), b"body", None)
    with pytest.raises(ValueError, match=r"^AESGCM key must be 128, 192, or 256 bits.$"):
        AESGCM(KEY[:31])
