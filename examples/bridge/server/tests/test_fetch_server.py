"""The bridge example's stdio server (M7 design C.7): what it answers, line by line."""

from __future__ import annotations

import io
import json
import subprocess
import sys
import urllib.error
from pathlib import Path
from typing import Any

import example_fetch_server as server
import pytest

SOURCE = Path(server.__file__).resolve().parents[1]


def ask(method: str, params: dict[str, Any] | None = None, rpc_id: Any = 1) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": rpc_id, "method": method}
    if params is not None:
        message["params"] = params
    answer = server.handle(message)
    assert answer is not None
    return answer


def tool(name: str, **arguments: Any) -> dict[str, Any]:
    result: dict[str, Any] = ask("tools/call", {"name": name, "arguments": arguments})["result"]
    return result


@pytest.mark.parametrize("version", server.VERSIONS)
def test_initialize_answers_a_version_it_serves(version: str) -> None:
    answer = ask("initialize", {"protocolVersion": version, "capabilities": {}})
    result = answer["result"]
    assert result["protocolVersion"] == version
    assert result["serverInfo"] == {"name": server.NAME, "version": server.VERSION}
    assert result["capabilities"] == {"tools": {}}


@pytest.mark.parametrize("version", ["2026-07-28", "1999-01-01", None])
def test_initialize_answers_its_newest_for_another(version: str | None) -> None:
    result = ask("initialize", {"protocolVersion": version})["result"]
    assert result["protocolVersion"] == server.VERSIONS[0]


def test_tools_ping_and_unknown_methods() -> None:
    names = [entry["name"] for entry in ask("tools/list")["result"]["tools"]]
    assert names == ["echo", "fetch", "wait"]
    assert ask("ping", rpc_id="p") == {"jsonrpc": "2.0", "id": "p", "result": {}}
    assert ask("resources/list")["error"]["code"] == server.METHOD_NOT_FOUND
    assert ask("tools/list", rpc_id=None)["id"] is None


def test_notifications_and_answers_get_nothing() -> None:
    assert server.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle({"jsonrpc": "2.0", "id": 4, "result": {}}) is None
    assert server.handle(["batch"])["error"]["code"] == server.INVALID_REQUEST  # type: ignore[index]
    assert ask("tools/list", [])["error"]["code"] == server.INVALID_PARAMS  # type: ignore[arg-type]


def test_echo_and_wait() -> None:
    assert tool("echo", text="hello") == {
        "content": [{"type": "text", "text": "hello"}],
        "isError": False,
    }
    slept: list[float] = []
    noted: list[str] = []
    assert server.call("wait", {"seconds": 1.5}, slept.append, noted.append) == "waited 1.5 s"
    assert server.call("wait", {"seconds": 0}, slept.append, noted.append) == "waited 0 s"
    assert slept == [1.5, 0.0]
    # Each wait says it began before it sleeps, on stderr: a stop's row waits for that line.
    assert noted == ["waiting 1.5 s", "waiting 0 s"]


@pytest.mark.parametrize(
    ("name", "arguments", "message"),
    [
        ("echo", {}, "text must be a string"),
        ("fetch", {"url": 5}, "url must be a string"),
        ("fetch", {"url": "http://example.org/"}, "only https:// URLs are fetched"),
        ("wait", {"seconds": "1"}, "seconds must be a number"),
        ("wait", {"seconds": True}, "seconds must be a number"),
        ("wait", {"seconds": 60.5}, "seconds must be between 0 and 60"),
        ("wait", {"seconds": -1}, "seconds must be between 0 and 60"),
    ],
)
def test_bad_arguments_are_tool_errors(name: str, arguments: dict[str, Any], message: str) -> None:
    assert tool(name, **arguments) == {
        "content": [{"type": "text", "text": message}],
        "isError": True,
    }


def test_an_unknown_tool_or_bad_params_are_protocol_errors() -> None:
    unknown = ask("tools/call", {"name": "nope", "arguments": {}})
    assert unknown["error"] == {"code": server.INVALID_PARAMS, "message": "Unknown tool: nope"}
    assert ask("tools/call", {"name": "echo", "arguments": []})["error"]["code"] == (
        server.INVALID_PARAMS
    )


class Answer(io.BytesIO):
    status = 200


def test_fetch_answers_the_status_and_size_never_the_body() -> None:
    seen: list[Any] = []

    def opener(request: Any, timeout: float) -> Answer:
        seen.append((request.full_url, request.get_header("User-agent"), timeout))
        return Answer(b"<secret body>")

    assert server.fetch("https://docs.example.org/", opener) == "status 200, 13 bytes"
    assert seen == [("https://docs.example.org/", "example-fetch-server/0.1.0", 15.0)]


def test_fetch_failures_name_their_kind() -> None:
    def refused(request: Any, timeout: float) -> Answer:
        raise urllib.error.URLError("Tunnel connection failed: 403 Forbidden")

    def missing(request: Any, timeout: float) -> Answer:
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    with pytest.raises(server.ToolError, match=r"^URLError: Tunnel connection failed: 403"):
        server.fetch("https://unlisted.example/", refused)
    assert server.fetch("https://docs.example.org/x", missing) == "status 404, 0 bytes"


def test_serve_answers_line_by_line() -> None:
    lines = [
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
        b"\n",
        b"not json\n",
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo",'
        b'"arguments":{"text":"x"}}}\n',
    ]
    out = io.StringIO()
    server.serve(lines, out)
    answers = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [answer.get("id") for answer in answers] == [1, None, 2]
    assert answers[1]["error"]["code"] == server.PARSE_ERROR
    assert answers[2]["result"]["content"][0]["text"] == "x"


def test_it_runs_as_a_program_until_stdin_ends() -> None:
    lines = [
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "x"}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    ]
    found = subprocess.run(  # noqa: S603 - our own interpreter and module
        [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
         "import example_fetch_server; example_fetch_server.main()", str(SOURCE)],
        input=b"".join(json.dumps(line).encode() + b"\n" for line in lines),
        capture_output=True,
        timeout=30,
        check=True,
    )  # fmt: skip
    answers = [json.loads(line) for line in found.stdout.splitlines()]
    assert [answer["id"] for answer in answers] == [0, 1]
    assert found.stderr == b""
