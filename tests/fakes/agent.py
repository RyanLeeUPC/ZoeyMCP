"""The agent side of approvals: a scripted SDK client and a raw wire client (M4 design N.1).

:func:`agent` is the SDK ``Client`` as an agent runs it, in any of the three protocol versions
approvals use: modern (2026-07-28), and legacy at 2025-11-25 or 2025-06-18. Its elicitation
callback follows a :class:`Script`: accept, decline, cancel, wait, raise, return an error, send
content or type the confirmation code it reads from the prompt. Every prompt is recorded.

The SDK always declares form and URL elicitation when a callback is set, and always offers
2025-11-25 at ``initialize``. :class:`Rewriter` changes those on the wire, so a test can be a
client that declares URL only, a bare ``{}``, nothing, or speaks 2025-06-18.

:class:`RawAgent` builds requests by hand, for what the SDK won't send: pre-answered calls,
replayed, foreign, guessed or malformed handles, changed arguments, nested answer content,
forged response POSTs and dropped streams.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, Literal

import anyio
import httpx
import httpx2
import mcp_types as types
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp_types.version import MODERN_PROTOCOL_VERSIONS

Version = Literal["modern", "2025-11-25", "2025-06-18"]
Declares = Literal["form", "url", "both", "bare", "none"]
MODERN: str = MODERN_PROTOCOL_VERSIONS[-1]
LEGACY_VERSIONS: tuple[Version, ...] = ("2025-11-25", "2025-06-18")
VERSIONS: tuple[Version, ...] = ("modern", *LEGACY_VERSIONS)
INPUT_KEY = "zoeymcp-approval"
CODE = re.compile(r"To approve, accept and type this code: ([A-Z0-9]{4})")
_DECLARED: Mapping[Declares, dict[str, Any] | None] = {
    "form": {"form": {}},
    "url": {"url": {}},
    "both": {"form": {}, "url": {}},
    "bare": {},
    "none": None,
}


# --- the scripted callback -----------------------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    """One answer the agent's human gives."""

    action: Literal["accept", "decline", "cancel"] = "accept"
    content: dict[str, Any] | None = None
    delay: float = 0.0  # seconds before answering
    fails: Literal["raise", "error"] | None = None  # the callback raises, or returns ErrorData
    type_code: bool = False  # put the code the prompt shows into ``content["code"]``


ACCEPT = Answer()
DECLINE = Answer("decline")
CANCEL = Answer("cancel")


@dataclass(frozen=True)
class Prompt:
    """One elicitation the agent was shown."""

    message: str
    schema: dict[str, Any]
    mode: str | None

    @property
    def code(self) -> str | None:
        match = CODE.search(self.message)
        return match.group(1) if match else None


@dataclass
class Script:
    """The answers to give, in order; the last one repeats."""

    answers: list[Answer] = field(default_factory=lambda: [ACCEPT])
    prompts: list[Prompt] = field(default_factory=list)

    async def __call__(
        self, context: Any, params: types.ElicitRequestParams
    ) -> types.ElicitResult | types.ErrorData:
        message = getattr(params, "message", "")
        schema = getattr(params, "requested_schema", {})
        self.prompts.append(Prompt(message, dict(schema), getattr(params, "mode", None)))
        answer = self.answers[min(len(self.prompts), len(self.answers)) - 1]
        if answer.delay:
            await anyio.sleep(answer.delay)
        if answer.fails == "raise":
            raise RuntimeError("the agent's elicitation callback failed")
        if answer.fails == "error":
            return types.ErrorData(code=types.INTERNAL_ERROR, message="callback refused")
        content = dict(answer.content) if answer.content is not None else None
        if answer.type_code:
            content = {**(content or {}), "code": self.prompts[-1].code or ""}
        return types.ElicitResult(action=answer.action, content=content)


# --- rewriting what the SDK declares ------------------------------------------------------------


class Rewriter(httpx2.AsyncBaseTransport):
    """Changes the elicitation capability (and, for 2025-06-18, the offered version) on the wire."""

    def __init__(
        self, declares: Declares, version: Version, inner: httpx2.AsyncBaseTransport | None = None
    ) -> None:
        self._declares = declares
        self._version = version
        self._inner = inner if inner is not None else httpx2.AsyncHTTPTransport()
        self.sent: list[dict[str, Any]] = []  # every JSON-RPC body sent, after rewriting

    async def handle_async_request(self, request: httpx2.Request) -> httpx2.Response:
        if request.method == "POST":
            body = await request.aread()
            try:
                value = json.loads(body)
            except ValueError:
                value = None
            if isinstance(value, dict):
                self._rewrite(value)
                self.sent.append(value)
                content = json.dumps(value).encode()
                headers = [(k, v) for k, v in request.headers.raw if k.lower() != b"content-length"]
                request = httpx2.Request(
                    request.method, request.url, headers=headers, content=content
                )
        return await self._inner.handle_async_request(request)

    def _rewrite(self, message: dict[str, Any]) -> None:
        params = message.get("params")
        if not isinstance(params, dict):
            return
        if message.get("method") == "initialize":
            if self._version == "2025-06-18":
                params["protocolVersion"] = "2025-06-18"
            self._set(params.setdefault("capabilities", {}))
        meta = params.get("_meta")
        if isinstance(meta, dict) and isinstance(
            meta.get(types.CLIENT_CAPABILITIES_META_KEY), dict
        ):
            self._set(meta[types.CLIENT_CAPABILITIES_META_KEY])

    def _set(self, capabilities: dict[str, Any]) -> None:
        declared = _DECLARED[self._declares]
        if declared is None:
            capabilities.pop("elicitation", None)
        else:
            capabilities["elicitation"] = dict(declared)

    async def aclose(self) -> None:
        await self._inner.aclose()


@asynccontextmanager
async def agent(
    url: str,
    *,
    version: Version = "modern",
    script: Script | None = None,
    declares: Declares = "both",
    headers: Mapping[str, str] | None = None,
    **options: Any,
) -> AsyncIterator[Client]:
    """An SDK client for ``url`` speaking ``version``, answering prompts by ``script``."""
    rewriter = Rewriter(declares, version)
    async with httpx2.AsyncClient(
        headers=dict(headers or {}), timeout=httpx2.Timeout(30.0), transport=rewriter
    ) as http:
        transport = streamable_http_client(url, http_client=http)
        mode = MODERN if version == "modern" else "legacy"
        callback = script if script is not None else Script()
        async with Client(
            transport, mode=mode, cache=None, elicitation_callback=callback, **options
        ) as client:
            client.rewriter = rewriter  # type: ignore[attr-defined]
            yield client


# --- the raw wire ------------------------------------------------------------------------------


def sse_messages(text: str) -> list[dict[str, Any]]:
    """The JSON-RPC messages in an SSE body (or one JSON body)."""
    lines = [line[5:].strip() for line in text.splitlines() if line.startswith("data:")]
    values = [json.loads(line) for line in lines if line] if lines else [json.loads(text)]
    return [v for v in values if isinstance(v, dict)]


@dataclass
class RawAgent:
    """Requests built by hand against one MCP URL, with fixed extra headers (the token)."""

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=lambda: {"elicitation": {}})
    next_id: int = 100

    def _id(self) -> int:
        self.next_id += 1
        return self.next_id

    def _base(self) -> dict[str, str]:
        return {"accept": "application/json, text/event-stream", **self.headers}

    # --- modern ---

    def modern_body(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        request_state: object = None,
        input_responses: object = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "name": name,
            "arguments": arguments,
            "_meta": {
                types.PROTOCOL_VERSION_META_KEY: MODERN,
                types.CLIENT_CAPABILITIES_META_KEY: self.capabilities,
            },
        }
        if request_state is not None:
            params["requestState"] = request_state
        if input_responses is not None:
            params["inputResponses"] = input_responses
        return {"jsonrpc": "2.0", "id": self._id(), "method": "tools/call", "params": params}

    async def modern_call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        url: str | None = None,
        request_state: object = None,
        input_responses: object = None,
    ) -> dict[str, Any]:
        """One modern ``tools/call``; returns the JSON-RPC answer."""
        body = self.modern_body(
            name, arguments, request_state=request_state, input_responses=input_responses
        )
        headers = {
            **self._base(),
            "mcp-protocol-version": MODERN,
            "mcp-method": "tools/call",
            "mcp-name": name,
        }
        async with httpx.AsyncClient(timeout=30) as http:
            response = await http.post(url or self.url, json=body, headers=headers)
        return sse_messages(response.text)[-1]

    # --- legacy ---

    async def legacy_session(self, version: str = "2025-11-25") -> str:
        body = {
            "jsonrpc": "2.0",
            "id": self._id(),
            "method": "initialize",
            "params": {
                "protocolVersion": version,
                "capabilities": self.capabilities,
                "clientInfo": {"name": "raw-agent", "version": "1"},
            },
        }
        async with httpx.AsyncClient(timeout=30) as http:
            response = await http.post(self.url, json=body, headers=self._base())
            response.raise_for_status()
            session = response.headers["mcp-session-id"]
            initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            await http.post(
                self.url, json=initialized, headers=self.legacy_headers(session, version)
            )
        return session

    def legacy_headers(self, session: str, version: str = "2025-11-25") -> dict[str, str]:
        return {**self._base(), "mcp-session-id": session, "mcp-protocol-version": version}

    async def respond(
        self, session: str, request_id: object, result: dict[str, Any], version: str = "2025-11-25"
    ) -> httpx.Response:
        """A JSON-RPC response POST, as an agent answers a server's request."""
        body = {"jsonrpc": "2.0", "id": request_id, "result": result}
        async with httpx.AsyncClient(timeout=30) as http:
            return await http.post(
                self.url, json=body, headers=self.legacy_headers(session, version)
            )
