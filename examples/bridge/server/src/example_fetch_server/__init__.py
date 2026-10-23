"""A small stdio MCP server, the program behind ZoeyMCP's bridge example (M7 design C.7).

It uses the standard library alone, so its wheel builds offline and is the whole lock. It speaks
the legacy era over stdio, one JSON-RPC message per line: ``initialize`` (answered with the
client's version when it is one of :data:`VERSIONS`, else the newest), ``ping``, ``tools/list``
and ``tools/call``; a notification is read and ignored, and any other method is ``-32601``.

- ``echo`` answers its ``text``;
- ``fetch`` fetches an ``https://`` URL with :mod:`urllib`, which goes through the proxy
  variables the bridge sets (``HTTPS_PROXY``), and answers the status and the size of what came
  back, never the body; a failure is a tool error naming its kind;
- ``wait`` writes ``waiting <seconds> s`` to stderr, then answers after ``seconds`` (at most
  :data:`WAIT_MAX`): a call in flight that a stop must let finish, which a bridge run with
  ``--stderr text`` shows has begun.

stdout carries nothing but the protocol; it has no update check and sends no telemetry.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from typing import IO, Any, Final

NAME: Final = "example-fetch-server"
VERSION: Final = "0.1.0"
# The legacy protocol versions it serves, newest first.
VERSIONS: Final = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
WAIT_MAX: Final = 60.0
FETCH_TIMEOUT: Final = 15.0
# What fetch reads of a body, at most, to count it.
FETCH_MAX: Final = 1024 * 1024
ERROR_TEXT_MAX: Final = 200
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602

TOOLS: Final = (
    {
        "name": "echo",
        "description": "Answers the text it is given.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "fetch",
        "description": "Fetches an https URL and answers its status and size, not its body.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "wait",
        "description": "Answers after the given number of seconds, at most 60.",
        "inputSchema": {
            "type": "object",
            "properties": {"seconds": {"type": "number", "minimum": 0, "maximum": WAIT_MAX}},
            "required": ["seconds"],
        },
    },
)


class ToolError(Exception):
    """A tool's failure, answered as its result with ``isError``."""


def _text(value: str, *, error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": value}], "isError": error}


def _cut(value: str) -> str:
    return value if len(value) <= ERROR_TEXT_MAX else value[:ERROR_TEXT_MAX] + "..."


def fetch(url: str, opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """``status <code>, <n> bytes`` for ``url``, which must be ``https://``."""
    if not url.startswith("https://"):
        raise ToolError("only https:// URLs are fetched")
    agent = {"User-Agent": f"{NAME}/{VERSION}"}
    request = urllib.request.Request(url, headers=agent)  # noqa: S310 - https only, checked above
    try:
        with opener(request, timeout=FETCH_TIMEOUT) as answer:
            size = len(answer.read(FETCH_MAX))
            return f"status {answer.status}, {size} bytes"
    except urllib.error.HTTPError as exc:
        return f"status {exc.code}, 0 bytes"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        reason = getattr(exc, "reason", exc)
        raise ToolError(_cut(f"{type(exc).__name__}: {reason}")) from exc


def _number(arguments: dict[str, Any], key: str) -> float:
    value = arguments.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ToolError(f"{key} must be a number")
    return float(value)


def _note(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def call(
    name: str,
    arguments: dict[str, Any],
    sleep: Callable[[float], None] = time.sleep,
    note: Callable[[str], None] = _note,
) -> str:
    """What tool ``name`` answers for ``arguments``; ``note`` takes its stderr lines."""
    if name == "echo":
        text = arguments.get("text")
        if not isinstance(text, str):
            raise ToolError("text must be a string")
        return text
    if name == "fetch":
        url = arguments.get("url")
        if not isinstance(url, str):
            raise ToolError("url must be a string")
        return fetch(url)
    if name == "wait":
        seconds = _number(arguments, "seconds")
        if not 0 <= seconds <= WAIT_MAX:
            raise ToolError(f"seconds must be between 0 and {WAIT_MAX:g}")
        note(f"waiting {seconds:g} s")
        sleep(seconds)
        return f"waited {seconds:g} s"
    raise KeyError(name)


def _error(rpc_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "error": {"code": code, "message": message}}


def _result(rpc_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}


def _initialize(params: dict[str, Any]) -> dict[str, Any]:
    asked = params.get("protocolVersion")
    return {
        "protocolVersion": asked if asked in VERSIONS else VERSIONS[0],
        "capabilities": {"tools": {}},
        "serverInfo": {"name": NAME, "version": VERSION},
    }


def _tools_call(rpc_id: Any, params: dict[str, Any]) -> dict[str, Any]:
    name, arguments = params.get("name"), params.get("arguments", {})
    if not isinstance(name, str) or not isinstance(arguments, dict):
        return _error(rpc_id, INVALID_PARAMS, "tools/call needs a name and an arguments object")
    try:
        return _result(rpc_id, _text(call(name, arguments)))
    except KeyError:
        return _error(rpc_id, INVALID_PARAMS, f"Unknown tool: {_cut(name)}")
    except ToolError as exc:
        return _result(rpc_id, _text(str(exc), error=True))


def handle(message: object) -> dict[str, Any] | None:
    """The answer to one message, or None for a notification or a response."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 message")
    method = message.get("method")
    if "id" not in message or not isinstance(method, str):
        return None  # a notification (initialized, cancelled) or an answer: nothing to say
    rpc_id = message["id"]
    params = message.get("params")
    params = {} if params is None else params
    if not isinstance(params, dict):
        return _error(rpc_id, INVALID_PARAMS, "params must be an object")
    if method == "initialize":
        return _result(rpc_id, _initialize(params))
    if method == "ping":
        return _result(rpc_id, {})
    if method == "tools/list":
        return _result(rpc_id, {"tools": list(TOOLS)})
    if method == "tools/call":
        return _tools_call(rpc_id, params)
    return _error(rpc_id, METHOD_NOT_FOUND, "Method not found")


def serve(lines: Iterable[bytes], out: IO[str]) -> None:
    """Answer each line of ``lines`` on ``out``, until they end."""
    for line in lines:
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            answer: dict[str, Any] | None = _error(None, PARSE_ERROR, "not JSON")
        else:
            answer = handle(message)
        if answer is not None:
            out.write(json.dumps(answer, separators=(",", ":")) + "\n")
            out.flush()


def main() -> None:
    serve(sys.stdin.buffer, sys.stdout)


if __name__ == "__main__":
    main()
