"""``zoeymcp review`` and ``gateway-status`` against the running gateway (M3 design I, G.4, G.5).

The CLI runs as it does in the container, except that its admin socket is the gateway's admin
app served next to it (the rig's ``admin_url``).
"""

from __future__ import annotations

import io
import json
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.fakes.mcp_server import C1_CSI, ZERO_WIDTH, Drift, McpFake, Switch
from tests.gateway.rig import SERVER, Running, agent, deployment, gateway, pin_of_fake, raw_policy
from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy, check_policy
from zoeymcp.common.yamlload import load_mapping

pytestmark = pytest.mark.anyio

TOOLS = ["echo", "add", "slow"]
TOOLKIT = {"mail": {"kind": "toolkit", "module": "example_toolkits.mail"}}
UNASSIGNED = {"spare": {"kind": "remote", "route": "notes"}}

Cli = Callable[..., tuple[int, str, str]]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def review_pins(fake: McpFake, names: list[str] = TOOLS) -> dict[str, str]:
    return {name: pin_of_fake(fake, name) for name in names}


@pytest.fixture
def cli(monkeypatch: pytest.MonkeyPatch) -> Callable[[Running], Cli]:
    """``cli(running)(*argv)``: the CLI, its admin socket forwarded to the running gateway."""
    real = httpx.HTTPTransport

    def bound(running: Running) -> Cli:
        def handle(request: httpx.Request) -> httpx.Response:
            with httpx.Client(transport=real(), timeout=120) as client:
                answer = client.request(
                    request.method,
                    running.admin_url + request.url.raw_path.decode(),
                    content=request.content,
                )
            return httpx.Response(answer.status_code, content=answer.content)

        def run(*argv: str) -> tuple[int, str, str]:
            monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handle))
            out, err = io.StringIO(), io.StringIO()
            code = main(list(argv), stdin=io.StringIO(), out=out, err=err)
            return code, out.getvalue(), err.getvalue()

        return run

    return bound


def snippet_of(output: str) -> dict[str, Any]:
    text = output[output.index("# YAML to commit") :]
    document = load_mapping(text)
    assert isinstance(document, dict)
    return document


def merged(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    """``patch`` pasted over ``base``: mappings merge, everything else is replaced."""
    out = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merged(out[key], value)
        else:
            out[key] = value
    return out


def check_errors(raw: dict[str, Any]) -> set[tuple[str, str]]:
    findings = check_policy(Policy.model_validate(raw))
    return {(f.path, f.message) for f in findings if f.level == "error"}


def no_hidden(text: str) -> None:
    for char in text:
        if char in "\n":
            continue
        assert unicodedata.category(char) not in ("Cc", "Cf", "Co", "Cn", "Cs", "Zl", "Zp"), (
            f"U+{ord(char):04X} reached the terminal"
        )


# --- review <server> -----------------------------------------------------------------------------


async def test_a_clean_server_exits_0_and_its_snippet_changes_nothing(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake()
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake)}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        code, out, err = cli(running)("review", SERVER)
        before = raw_policy(deployed.fake_url, **options)
    assert (code, err) == (0, ""), err
    lines = out.splitlines()
    assert lines[0].startswith(f"server {SERVER}  (remote, vault path /notes/mcp, modern ")
    for name in TOOLS:
        assert any(line.split()[:2] == [name, "ok"] for line in lines)
    assert any(
        line.split()[:2] == ["counter", "unreviewed"] and line.endswith("not included")
        for line in lines
    )
    patch = snippet_of(out)
    server = patch["gateway"]["servers"][SERVER]
    assert server["era"] == "modern"
    assert server["review"] == options["review"]
    assert check_errors(merged(before, patch)) == check_errors(before)
    # Unincluded tools are comments, with their pins.
    assert f"# not included: counter  {pin_of_fake(fake, 'counter')}" in out


async def test_drift_is_shown_with_a_diff_and_marks_the_tool(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake(drift=Drift("description", after=1))
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake)}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        async with agent(running) as client:
            assert "echo" in [tool.name for tool in (await client.list_tools()).tools]
        run = cli(running)
        code, out, _ = run("review", SERVER)
        json_code, json_out, _ = run("review", SERVER, "--format", "json", "--repin", "echo")
        before = raw_policy(deployed.fake_url, **options)
        status_code, status_out, _ = run("gateway-status", "--format", "json")
    assert code == 1
    echo = next(line for line in out.splitlines() if line.split()[:1] == ["echo"])
    assert "DRIFT" in echo
    assert "changed: description" in echo
    assert "marked" in echo
    assert "diff echo:" in out
    assert '-  "description": "Returns the text it is given.",' in out
    # The default snippet keeps the reviewed pin, so the tool stays hidden.
    pinned = review_pins(McpFake())["echo"]
    assert snippet_of(out)["gateway"]["servers"][SERVER]["review"]["echo"] == pinned
    assert "--repin echo takes it" in out
    # --repin takes the new pin; JSON output carries the snippet and nothing outside ASCII.
    assert json_code == 1
    assert json_out.isascii()
    data = json.loads(json_out)
    [entry] = [tool for tool in data["tools"] if tool["name"] == "echo"]
    assert (entry["state"], entry["changed"]) == ("drift", ["description"])
    assert data["marked"] == ["echo"]
    repinned = load_mapping("\n".join(data["snippet"]))
    assert repinned["gateway"]["servers"][SERVER]["review"]["echo"] == entry["pin"]
    assert check_errors(merged(before, repinned)) == check_errors(before)
    # The mark holds for every client: the status says so.
    assert status_code == 0
    assert json.loads(status_out)["servers"][SERVER]["marked"] == ["echo"]


async def test_clear_is_refused_while_drifted_and_restores_once_matching(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    # Listing 1 (the agent's) is clean, 2 (a review) drifted, 3 (the next review) clean again.
    fake = McpFake(drift=Drift("description", after=1, flip_back_after=1))
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake)}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        run = cli(running)
        async with agent(running) as client:
            assert "echo" in [tool.name for tool in (await client.list_tools()).tools]
            refused, refused_out, refused_err = run("review", SERVER, "--clear")
            # The upstream flipped back, but the mark holds until a clear.
            assert "echo" not in [tool.name for tool in (await client.list_tools()).tools]
            cleared, cleared_out, _ = run("review", SERVER, "--clear")
            assert "echo" in [tool.name for tool in (await client.list_tools()).tools]
    assert refused == 1
    assert "--clear refused: not every included tool matches its pin: echo" in refused_err
    assert "DRIFT" in refused_out
    assert cleared == 0
    assert "cleared drift marks: echo" in cleared_out
    assert deployed.events("drift_cleared")[-1]["by"] == "review"


async def test_hostile_definitions_reach_the_terminal_visible_and_unpinned(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake(switches={Switch.INJECT_DEFINITIONS, Switch.INJECT_SERVER_INFO})
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake)}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        run = cli(running)
        code, out, err = run("review", SERVER, "--all")
        json_code, json_out, _ = run("review", SERVER, "--format", "json")
    assert code == 0, err  # the included tools match; the hostile ones aren't included
    no_hidden(out)
    assert ZERO_WIDTH not in out
    assert C1_CSI not in out
    assert "[U+200B]" in out
    assert "[U+009B]" in out
    assert "instructions (never forwarded)" in out
    data = json.loads(json_out)
    assert json_out.isascii()
    assert json_code == 0
    hostile = [
        tool for tool in data["tools"] if any(f["level"] == "error" for f in tool["findings"])
    ]
    assert hostile
    tail = out.split("# YAML to commit")[1]
    for entry in hostile:
        assert entry["pin"] is None or entry["pin"] not in tail.replace("(error findings", "")
    assert "(error findings: not pinnable)" in tail


async def test_add_includes_a_tool_and_leaves_its_classification_to_the_operator(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake()
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake)}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        run = cli(running)
        code, out, _ = run("review", SERVER, "--add", "counter")
        bad = run("review", SERVER, "--add", "echo")
        unknown = run("review", SERVER, "--repin", "add")
        before = raw_policy(deployed.fake_url, **options)
    assert code == 0
    server = snippet_of(out)["gateway"]["servers"][SERVER]
    assert server["tools"]["include"] == [*TOOLS, "counter"]
    assert server["review"]["counter"] == pin_of_fake(fake, "counter")
    added = check_errors(merged(before, snippet_of(out))) - check_errors(before)
    assert [path for path, _ in added] == [f"gateway.servers.{SERVER}.tools"]
    assert (bad[0], bad[2]) == (2, "zoeymcp review: --add echo: it is already included\n")
    assert (unknown[0], unknown[2]) == (2, "zoeymcp review: --repin add: it hasn't drifted\n")


async def test_a_review_that_cant_run_exits_2(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake(switches={Switch.UNSUPPORTED_VERSION})
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(McpFake()), "servers": TOOLKIT}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        run = cli(running)
        failed = run("review", SERVER)
        unknown = run("review", "nothing")
        toolkit = run("review", "mail")
    assert failed[0] == 2
    assert "the review couldn't list the server's tools (" in failed[2]
    assert (unknown[0], unknown[2]) == (2, "zoeymcp review: no gateway server named 'nothing'\n")
    assert toolkit[0] == 2
    assert "toolkit server" in toolkit[2]


async def test_an_unassigned_server_can_be_reviewed_first(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake()
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake), "servers": UNASSIGNED}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        code, out, _ = cli(running)("review", "spare", "--add", "echo")
    # Nothing is included yet, so nothing needs the operator; --add starts the entry.
    assert code == 0
    spare = snippet_of(out)["gateway"]["servers"]["spare"]
    assert spare["tools"] == {"include": ["echo"], "allow": [], "approve": []}
    assert spare["review"] == {"echo": pin_of_fake(fake, "echo")}


# --- the summary and gateway-status --------------------------------------------------------------


async def test_the_summary_and_status_make_no_upstream_call(
    tmp_path: Path, cli: Callable[[Running], Cli]
) -> None:
    fake = McpFake()
    options: dict[str, Any] = {"include": TOOLS, "review": review_pins(fake), "servers": TOOLKIT}
    with deployment(tmp_path, fake, **options) as deployed, gateway(deployed) as running:
        async with agent(running) as client:
            await client.list_tools()
        run = cli(running)
        listed = fake.lists
        summary = run("review")
        status = run("gateway-status")
        one = run("gateway-status", SERVER, "--format", "json")
        missing = run("gateway-status", "nothing")
        bad = run("review", "--clear")
        assert fake.lists == listed
    assert summary[0] == 0
    [notes] = [line for line in summary[1].splitlines() if line.startswith(SERVER)]
    assert "exposed 3/3" in notes
    assert "marked 0" in notes
    assert "unreviewed 3" in notes
    assert "mail  toolkit: not served by this version" in summary[1]
    assert status[0] == 0
    assert status[1].startswith("view sha256:")
    assert f"{SERVER}  remote  ready" in status[1]
    assert list(json.loads(one[1])["servers"]) == [SERVER]
    assert missing[0] == 2
    assert bad == (2, "", "zoeymcp review: these options need a server\n")
