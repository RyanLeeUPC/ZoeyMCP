"""S18 and J12: prompts, resources and completions turned on from a checked policy, end to end
over real sockets and real TLS (M6 design L.9, L.11, J12; step 21b).

Agent (the SDK client, both eras) -> gateway -> vault -> the fake MCP server's prompts and
resources modes, with ``inject_kinds`` so each kind lists one more entry carrying S12's hostile
text. Declarative (J12's first half, in process like S10): the shipped
``remote-mcp-static-key.yaml`` with ``enable`` added and reloaded, which ``check`` now accepts;
``zoeymcp review notes --choose`` lists the prompts, the template and the fixed resource with
their pins, the hostile ones revealed and not includable; ``--choices`` gives the fragment with
the ``prompts:`` and ``resources:`` blocks, reloaded; an agent sees the kinds in that path's
capabilities, lists and gets them, reads an allowed URI (never the contents the upstream adds
for a second one) and is refused the others with the era's not-found code, completes an included
prompt's argument and is refused the rest; a prompt changed after review is hidden and marked,
and a legacy session is told. Managed (J12's second half, as processes like S17): an export
with only ``enable`` added, imported with the vault stopped, serves no prompt; the portal's
review shows the kinds' rows revealed, and its Save (``policy.save``, one passkey) includes them
at their verified pins, which the gateway serves. The server's row (D-216): before ``enable``
names a kind, the MCP servers row says what the upstream offers and isn't served, with J12's
way to serve it in the mode, and ``review notes`` says so too; once a prompt and a template
drift, the status report the gateway pushes carries them, health's ``drift_marked`` names each
and Home's list has one item for each, with **Review**.
Every declarative test ends with S12's sweeps (``test_mcp_shapes.sweep``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import anyio
import httpx2
import mcp_types
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.exceptions import MCPError
from mcp.types import PromptReference, ResourceTemplateReference, TextContent

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser, Page
from tests.fakes.mcp_server import (
    ASSISTANT_PROMPT,
    FIXED,
    HIDDEN_PROMPT,
    HOSTILE_FIXED,
    HOSTILE_PROMPT,
    HOSTILE_TEMPLATE,
    OTHER_URI,
    TEMPLATE,
    ZERO_WIDTH,
    McpFake,
    Switch,
    base_prompts,
    base_tools,
)
from tests.gateway.rig import CLIENTS, Running, agent, pin_of_fake, until
from tests.gateway.test_upstream_kinds import FIXED_PIN, PROMPT_PIN, TEMPLATE_PIN, kind_pin
from tests.portal.flows import enrol, login, redeem
from zoeymcp.common.policy.schema import RemoteServer
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import upstream as upstream_module
from zoeymcp.portal import app as portal_app
from zoeymcp.vault.admin import HealthReader
from zoeymcp.vault.managed import head_policy
from zoeymcp.vault.onboarding import listed_server

from .conftest import serve_tls
from .gateway import NO_PINS, SERVER, GatewayDeployment, server_text
from .procs import free_port
from .test_managed_shape import (
    AGENT_TOKEN,
    deployment_of,
    edited_export,
    gateway_on,
    notes_policy,
    opened,
    seen_by,
    vault,
    wait_for,
)
from .test_mcp_shapes import KEY, TOOLS, declined_rest, deployed, dumped, pins
from .test_portal_shapes import setup_code
from .tls import ProviderCA

pytestmark = pytest.mark.anyio

HIDDEN_PIN = kind_pin("prompt", base_prompts()[1])
KINDS = ["prompts", "resources", "completions"]
# What a review includes of each kind: both prompts (one speaks as the assistant, refused when
# got), the template and the fixed resource.
INCLUDED = {ASSISTANT_PROMPT, HIDDEN_PROMPT, TEMPLATE, FIXED}
# Each hostile entry, and what the review calls its kind.
HOSTILE = {
    HOSTILE_PROMPT: "prompt",
    HOSTILE_TEMPLATE: "resource template",
    HOSTILE_FIXED: "resource",
}
REFUSED_URIS = [
    "notes://notes/.",
    "notes://notes/..",
    "notes://notes/%2E%2E",
    "notes://other/1",
    OTHER_URI,
]
NOT_FOUND = {"auto": -32602, "legacy": -32002}
BOUND = 60  # seconds for one agent's walk, start to end
WHOLE = 180  # seconds for a whole declarative case: two reloads, the reviews and the walk


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def kinds_fake(*switches: Switch, **options: Any) -> McpFake:
    """The fake serving every kind, one hostile entry of each among them, behind S10's key,
    with ``switches`` besides."""
    return McpFake(
        key=KEY,
        key_header="x-api-key",
        prompts=True,
        resources=True,
        switches={Switch.INJECT_KINDS, *switches},
        **options,
    )


def with_kinds(fake: McpFake, blocks: dict[str, Any] | None = None) -> dict[str, str]:
    """The profile's replacements: S10's tools, pins and declines, the server enabling every
    kind, and ``blocks`` (its ``prompts`` and ``resources``) as given."""
    text = server_text(TOOLS, pins(fake), declined_rest(fake, TOOLS))
    extra = f"\n      enable: {json.dumps(KINDS)}"
    for key, value in (blocks or {}).items():
        extra += f"\n      {key}: {json.dumps(value)}"
    return {**text, NO_PINS: text[NO_PINS] + extra}


def reload(gateway: GatewayDeployment, replace: dict[str, str]) -> None:
    """A new policy, checked with no error (``Deployment.load``), swapped into the running
    vault (SIGHUP)."""
    policy = gateway.vault.load(replace)
    gateway.vault.call(lambda: gateway.vault.app.reload(policy))


def in_view(running: Running) -> ViewRemoteServer | None:
    """notes as the gateway's view holds it; None before a view."""
    snapshot = running.app.policy.snapshot
    if snapshot is None:
        return None
    server = snapshot.view.gateway.servers[SERVER]
    assert isinstance(server, ViewRemoteServer)
    return server


def stated(client: Client) -> list[str]:
    """The kinds a path's capabilities state, as the agent read them."""
    assert client.server_capabilities is not None
    return sorted(client.server_capabilities.model_dump(exclude_none=True))


def chosen(out: str) -> str:
    """The choices file with every base prompt, template and fixed resource included."""
    lines = []
    for line in out.splitlines():
        words = line.split()
        if words[:1] in (["prompt:"], ["resource:"]) and words[2] in INCLUDED:
            assert words[1] == "skip", line
            line = line.replace(" skip ", " include ", 1)
        lines.append(line)
    return "\n".join(lines) + "\n"


def reviewed(gateway: GatewayDeployment, running: Running, tmp_path: Path) -> dict[str, Any]:
    """J12 declarative: ``review notes --choose``, every base entry included, read back with
    ``--choices``; the fragment's notes server."""
    code, out, _ = gateway.cli(running, "review", SERVER, "--choose")
    assert code == 0, out
    kinds = [line for line in out.splitlines() if line.split()[:1] in (["prompt:"], ["resource:"])]
    assert sorted(line.split()[2] for line in kinds) == sorted(INCLUDED)
    # Each hostile entry has an error finding, so a comment and no line; its definition shows
    # every hidden character revealed.
    for name, noun in HOSTILE.items():
        said = f"# {noun} {name} can't be included: error finding (control character U+001B"
        assert any(line.startswith(said) for line in out.splitlines()), name
        code, shown, _ = gateway.cli(running, "review", SERVER, "--show", name)
        assert "[U+200B]" in shown, shown
        assert "[U+202E]" in shown, shown
    file = tmp_path / "choices.txt"
    file.write_bytes(chosen(out).encode())
    code, out, err = gateway.cli(running, "review", SERVER, "--choices", str(file))
    assert code == 0, err
    assert out.startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review:, declined:, prompts: "
        "and resources: blocks of gateway.servers.notes, then assign notes to its clients.\n"
    )
    for name, noun in HOSTILE.items():
        said = f"# can't be included, error finding: {name} ({noun}; review notes shows why)"
        assert said in out.splitlines()
    fragment = load_mapping(out)
    server: dict[str, Any] = fragment["gateway"]["servers"][SERVER]
    return server


def text_of(result: Any) -> str:
    return "".join(
        block.text
        for message in result.messages
        if isinstance(block := message.content, TextContent)
    )


async def walk(running: Running, mode: str) -> dict[str, Any]:
    """What an agent of ``mode`` sees of the kinds on notes: each list, each get, read and
    completion, and each refusal, as (code, message)."""
    seen: dict[str, Any] = {}
    prompt = PromptReference(type="ref/prompt", name=HIDDEN_PROMPT)
    with anyio.fail_after(BOUND):
        async with agent(running, mode=mode) as client:
            seen["capabilities"] = stated(client)
            prompts = await client.list_prompts()
            templates = await client.list_resource_templates()
            resources = await client.list_resources()
            seen["lists"] = (
                [item.name for item in prompts.prompts],
                [item.uri_template for item in templates.resource_templates],
                [item.uri for item in resources.resources],
            )
            seen["ttl"] = [(r.ttl_ms, r.cache_scope) for r in (prompts, templates, resources)]
            got = await client.get_prompt(HIDDEN_PROMPT, {"id": "7"})
            seen["got"] = (text_of(got), (got.meta or {}).get("zoeymcp/dropped"))
            note = await client.read_resource("notes://notes/7")
            index = await client.read_resource(FIXED)
            seen["read"] = [item.uri for item in (*note.contents, *index.contents)]
            seen["read_dropped"] = [(r.meta or {}).get("zoeymcp/dropped") for r in (note, index)]
            seen["read_ttl"] = (note.ttl_ms, note.cache_scope)
            seen["note"] = dumped(note)
            completed = await client.complete(prompt, {"name": "id", "value": "4"})
            seen["completed"] = completed.completion.values
            refusals = []
            for call in (
                client.get_prompt(ASSISTANT_PROMPT, {"topic": "notes"}),
                client.get_prompt(HOSTILE_PROMPT, {"topic": "notes"}),
                *(client.read_resource(uri) for uri in REFUSED_URIS),
                client.complete(prompt, {"name": "id", "value": "4"}, {"evil": "x"}),
                client.complete(
                    PromptReference(type="ref/prompt", name=HOSTILE_PROMPT),
                    {"name": "topic", "value": "a"},
                ),
                client.complete(
                    ResourceTemplateReference(type="ref/resource", uri=HOSTILE_TEMPLATE),
                    {"name": "id", "value": "a"},
                ),
            ):
                with pytest.raises(MCPError) as caught:
                    await call
                refusals.append((caught.value.error.code, caught.value.error.message))
            seen["refused"] = refusals
            seen["outputs"] = [dumped(x) for x in (prompts, templates, resources, got, completed)]
    return seen


@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_s18_turned_on_reviewed_and_served(tmp_path: Path, ca: ProviderCA, mode: str) -> None:
    """J12 declarative, S18: before ``enable`` the path serves tools only; enabled, the review
    lists every kind with its pin, the fragment includes the base entries, and the agent is
    served exactly what L.6 allows, in its era; each read's upstream answer also carries
    contents naming a second URI (``read_other_uri``), which never reach the agent (SPEC-5,
    MISS-7)."""
    fake = kinds_fake(Switch.READ_OTHER_URI)
    with (
        deployed(tmp_path, ca, fake) as gateway,
        gateway.running() as running,
        anyio.fail_after(WHOLE),
    ):
        async with agent(running, mode=mode) as client:
            assert stated(client) == ["tools"]
        reload(gateway, with_kinds(fake))
        await until(lambda: (server := in_view(running)) is not None and server.enable == KINDS)
        # Enabled but nothing included: still tools only on the path (L.5).
        async with agent(running, mode=mode) as client:
            assert stated(client) == ["tools"]
        server = reviewed(gateway, running, tmp_path)
        assert server["prompts"]["review"] == {
            ASSISTANT_PROMPT: PROMPT_PIN,
            HIDDEN_PROMPT: HIDDEN_PIN,
        }
        assert server["resources"]["templates"]["review"] == {TEMPLATE: TEMPLATE_PIN}
        assert server["resources"]["fixed"]["review"] == {FIXED: FIXED_PIN}
        reload(gateway, with_kinds(fake, {k: server[k] for k in ("prompts", "resources")}))
        both = [ASSISTANT_PROMPT, HIDDEN_PROMPT]
        await until(
            lambda: (server := in_view(running)) is not None and server.prompts.include == both
        )
        seen = await walk(running, mode)
        gateway.seen.outputs += seen["outputs"]
        code, out, _ = gateway.cli(running, "review", SERVER)
    assert code == 0, out
    assert seen["capabilities"] == ["completions", "prompts", "resources", "tools"]
    assert seen["lists"] == ([ASSISTANT_PROMPT, HIDDEN_PROMPT], [TEMPLATE], [FIXED])
    if mode == "auto":  # the modern wire's cache fields (SPEC-3)
        assert seen["ttl"] == [(60_000, "private")] * 3
        assert seen["read_ttl"] == (0, "private")
    text, dropped = seen["got"]
    assert text.startswith("Summarize.[U+200B] ")
    assert ZERO_WIDTH not in text
    assert "[U+202E]" in text
    assert dropped == 1  # the block naming another URI
    assert seen["read"] == ["notes://notes/7", FIXED]
    assert seen["read_dropped"] == [1, 1]  # the contents naming OTHER_URI
    assert OTHER_URI not in seen["note"]
    assert "[U+200B]" in seen["note"]
    assert ZERO_WIDTH not in seen["note"]
    assert seen["completed"] == ["4-0[U+200B]", "4-1[U+200B]"]
    assistant = (
        mcp_types.INTERNAL_ERROR,
        f"the server's prompt speaks as the assistant, which this gateway refuses for "
        f"{ASSISTANT_PROMPT}",
    )
    unknown_prompt = (mcp_types.INVALID_PARAMS, "Unknown prompt")
    not_found = (NOT_FOUND[mode], "not found")
    undeclared = (mcp_types.INVALID_PARAMS, "arguments refused: not a declared argument")
    unknown = (mcp_types.INVALID_PARAMS, "Unknown reference")
    assert seen["refused"] == [
        assistant,
        unknown_prompt,
        *[not_found] * len(REFUSED_URIS),
        undeclared,
        unknown,
        unknown,
    ]
    # Nothing refused went upstream, and nothing hostile was asked for.
    assert sorted(item.params["uri"] for item in fake.requests("resources/read")) == [
        FIXED,
        "notes://notes/7",
    ]
    assert [item.params["name"] for item in fake.requests("prompts/get")] == [
        HIDDEN_PROMPT,
        ASSISTANT_PROMPT,
    ]
    assert len(fake.requests("completion/complete")) == 1


async def test_s18_a_changed_prompt_is_hidden_marked_and_told(
    tmp_path: Path, ca: ProviderCA, monkeypatch: pytest.MonkeyPatch
) -> None:
    """S18, SPEC-1: a prompt changed after review is hidden and marked, a legacy session gets
    ``notifications/prompts/list_changed``, and ``review notes`` exits 1 naming it."""
    monkeypatch.setattr(upstream_module, "COALESCE", 0.0)
    fake = kinds_fake(mode="legacy")
    blocks = {
        "prompts": {
            "include": [ASSISTANT_PROMPT, HIDDEN_PROMPT],
            "review": {ASSISTANT_PROMPT: PROMPT_PIN, HIDDEN_PROMPT: HIDDEN_PIN},
        },
        "resources": {"templates": {"include": [TEMPLATE], "review": {TEMPLATE: TEMPLATE_PIN}}},
    }
    seen: list[object] = []
    stream = anyio.Event()

    async def handler(message: object) -> None:
        seen.append(getattr(message, "method", None))

    with (
        deployed(tmp_path, ca, fake, replace=with_kinds(fake, blocks)) as gateway,
        gateway.running() as running,
    ):
        with anyio.fail_after(BOUND):
            async with agent(
                running, mode="legacy", message_handler=handler, opened=stream
            ) as client:
                assert len((await client.list_prompts()).prompts) == 2
                await stream.wait()  # the agent's GET stream, where the notification goes
                fake.change_kind("prompt")
                fake.announce(kind="prompts")
                await until(lambda: "notifications/prompts/list_changed" in seen)
                names = [prompt.name for prompt in (await client.list_prompts()).prompts]
                with pytest.raises(MCPError) as caught:
                    await client.get_prompt(ASSISTANT_PROMPT, {"topic": "a"})
        code, out, _ = gateway.cli(running, "review", SERVER)
    assert names == [HIDDEN_PROMPT]
    assert caught.value.error.message == "Unknown prompt"
    assert "notifications/resources/list_changed" not in seen
    assert [line["name"] for line in gateway.seen.events("prompt_drift")] == [ASSISTANT_PROMPT]
    marked = gateway.seen.events("drift_marked")
    assert [(line["definition_kind"], line["name"]) for line in marked] == [
        ("prompt", ASSISTANT_PROMPT)
    ]
    assert code == 1, out
    [line] = [line for line in out.splitlines() if line.split()[:2] == [ASSISTANT_PROMPT, "DRIFT"]]
    assert line.endswith("changed: description    hidden, marked"), out


# --- the server's row, health and Home per kind (D-216) ----------------------------------------

OFFERED_TEXT = (
    "notes offers prompts, resources and completions, not served: add enable: [prompts, "
    "resources, completions] to notes in your policy and reload"
)


def vault_reads(gateway: GatewayDeployment) -> tuple[dict[str, Any], dict[str, Any]]:
    """What the vault makes of the gateway's latest status report: the health report, and
    notes's row on the MCP servers page as the portal builds it from that report."""
    vault = gateway.vault
    reader = HealthReader(
        vault.store, lambda: vault.app.policy, gateway_status=vault.app.gateway_status
    )
    report: dict[str, Any] = vault.call(reader.report)
    listed = listed_server(vault.app.policy, SERVER)
    assert listed is not None
    row = portal_app._server_row(listed, None, portal_app._offered(report).get(SERVER))
    return report, row


def reported_kinds(gateway: GatewayDeployment) -> dict[str, Any]:
    """The kinds of notes in the vault's latest status report, as their plain lists."""
    report = gateway.vault.app.gateway_status().report
    entry = None if report is None else report.servers.get(SERVER)
    return {} if entry is None else {k: v.as_dict() for k, v in entry.kinds.items()}


async def test_s18_the_row_health_and_home_name_each_kind(tmp_path: Path, ca: ProviderCA) -> None:
    """J12's row and D-216, declarative: before ``enable``, notes's row and ``review notes`` say
    the upstream offers prompts, resources and completions that aren't served, with the
    declarative way to serve them; enabled and included, nothing is left out; then a prompt and
    the template change (a legacy upstream lists again for the second client's connection),
    and the gateway's status, health's ``drift_marked`` and Home's list name each, Home's items
    with **Review**."""
    fake = McpFake(key=KEY, key_header="x-api-key", mode="legacy", prompts=True, resources=True)
    blocks = {
        "prompts": {"include": [ASSISTANT_PROMPT], "review": {ASSISTANT_PROMPT: PROMPT_PIN}},
        "resources": {"templates": {"include": [TEMPLATE], "review": {TEMPLATE: TEMPLATE_PIN}}},
    }
    with (
        deployed(tmp_path, ca, fake, status_push=True) as gateway,
        gateway.running() as running,
        anyio.fail_after(WHOLE),
    ):
        async with agent(running, CLIENTS[0]) as client:
            await client.list_tools()
        await until(lambda: "offered" in str(vault_reads(gateway)[0]["gateway"]["servers"]), 20)
        _, row = vault_reads(gateway)
        assert row["offered_not_served"] == ["prompts", "resources", "completions"]
        assert row["next"][-1] == {
            "do": "enable_kinds",
            "label": "Add enable: [prompts, resources, completions] to notes in your policy "
            "and reload",
        }
        code, out, _ = gateway.cli(running, "review", SERVER)
        assert OFFERED_TEXT in out.splitlines(), out
        reload(gateway, with_kinds(fake, blocks))
        await until(lambda: (server := in_view(running)) is not None and server.enable == KINDS)
        assert vault_reads(gateway)[1]["offered_not_served"] == []
        async with agent(running, CLIENTS[0]) as client:
            assert [p.name for p in (await client.list_prompts()).prompts] == [ASSISTANT_PROMPT]
        fake.change_kind("prompt")
        fake.change_kind("resource_template")
        async with agent(running, CLIENTS[1]) as client:
            assert (await client.list_prompts()).prompts == []  # hidden, marked
        drifted = {
            "prompt": [ASSISTANT_PROMPT],
            "resource_template": [TEMPLATE],
        }
        await until(
            lambda: (
                {k: v["drifted"] for k, v in reported_kinds(gateway).items()}
                == {**drifted, "resource": []}
            ),
            20,
        )
        report, row = vault_reads(gateway)
        code, out, _ = gateway.cli(running, "review", SERVER)
    assert row["offered_not_served"] == []
    assert code == 1, out  # the drift needs the operator
    assert not any("not served" in line for line in out.splitlines()), out
    # The first client's connection still lists the old definitions, which the new marks
    # hide: the decision combines both connections (Y29), as for tools.
    findings = [f["text"] for f in report["gateway"]["findings"] if f["code"] == "drift_marked"]
    assert [text.split(";")[0] for text in findings] == [
        f"notes: included prompts 1 changed since the review ({ASSISTANT_PROMPT})",
        f"notes: included resource templates 1 changed since the review ({TEMPLATE})",
    ]
    items = portal_app.attention_items(report)["items"]
    review = {"kind": "review", "server": SERVER}
    seen = [(item["subject"], item["text_shown"], item["action"]) for item in items]
    assert ("prompt", "notes changed 1 included prompt since the review", review) in seen
    assert (
        "resource_template",
        "notes changed 1 included resource template since the review",
        review,
    ) in seen
    assert {item["subject"] for item in items} == {"prompt", "resource_template"}


# --- J12 in managed mode (processes, as S17) ----------------------------------------------------


def kinds_seen(port: int) -> tuple[list[str], list[str]] | None:
    """The kinds the gateway on ``port`` states for agent1 on notes and the prompts it lists
    there; None while it can't answer."""

    async def walked() -> tuple[list[str], list[str]]:
        headers = {"authorization": f"Bearer {AGENT_TOKEN}"}
        async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0)) as http:
            url = f"http://127.0.0.1:{port}/s/{SERVER}/mcp"
            async with Client(streamable_http_client(url, http_client=http), cache=None) as agent:
                kinds = stated(agent)
                if "prompts" not in kinds:
                    return kinds, []
                return kinds, [prompt.name for prompt in (await agent.list_prompts()).prompts]

    try:
        return anyio.run(walked)
    except Exception:  # the SDK's errors arrive in exception groups
        return None


def tools_listed(port: int) -> None:
    """agent1 lists notes's tools through the gateway on ``port``, so the gateway connects to the
    upstream and sees what it offers (its status's ``offered``)."""

    async def listed() -> None:
        headers = {"authorization": f"Bearer {AGENT_TOKEN}"}
        async with httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30.0)) as http:
            url = f"http://127.0.0.1:{port}/s/{SERVER}/mcp"
            async with Client(streamable_http_client(url, http_client=http), cache=None) as agent:
                await agent.list_tools()

    anyio.run(listed)


def saved_with_kinds(
    page: Page, passkey: SoftAuthenticator, tools: list[str], *processes: Any
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    """**Review again** on notes in the portal, the tools kept approve and the summarize prompt,
    the template and the fixed resource included, saved with the passkey: the kind the draft
    named, the review's rows and the confirm's answer."""
    queued = page.fetch("POST", f"/api/review/{SERVER}", json={"fresh": True})
    assert queued.status_code == 200, queued.text
    path = f"/api/review/jobs/{queued.json()['job']}"
    read: dict[str, Any] = {}

    def done() -> bool:
        answer = page.fetch("GET", path)
        assert answer.status_code == 200, answer.text
        read.update(answer.json())
        return bool(read["state"] == "done")

    wait_for(done, "the review", *processes)
    kinds = {
        "prompt": {"include": [HIDDEN_PROMPT]},
        "resource_template": {"include": [TEMPLATE]},
        "resource": {"include": [FIXED]},
    }
    choices = {"include": tools, "allow": [], "approve": tools, "kinds": kinds}
    drafted = page.fetch("POST", f"{path}/diff", json={**choices, "decline_rest": False})
    assert drafted.status_code == 200, drafted.text
    draft = drafted.json()
    data = {"draft": draft["draft"], "base": draft["base"]}
    held = page.fetch("POST", "/api/actions", json={"kind": draft["kind"], "data": data})
    assert held.status_code == 200, held.text
    assertion = passkey.get(held.json()["options"], page.origin).body()
    confirm = f"/api/actions/{held.json()['action']}/confirm"
    saved = page.fetch("POST", confirm, json={"credential": assertion})
    assert saved.status_code == 200, saved.text
    answer: dict[str, Any] = saved.json()
    return str(draft["kind"]), read, answer


def row_of(page: Page) -> dict[str, Any]:
    """notes's row on the MCP servers page."""
    answer = page.fetch("GET", "/api/servers")
    assert answer.status_code == 200, answer.text
    [row] = [row for row in answer.json()["servers"] if row.get("server") == SERVER]
    found: dict[str, Any] = row
    return found


def offered_row(page: Page) -> list[str]:
    found: list[str] = row_of(page)["offered_not_served"]
    return found


def test_j12_managed(tmp_path: Path, ca: ProviderCA) -> None:
    """J12 managed: ``enable`` is the host's, so an export with only ``enable: [prompts,
    resources]`` added is imported with the vault stopped (revision 2) and serves no prompt, none
    being included; the portal's review then lists the server's prompts, resource templates and
    fixed resources under their headings, the hostile ones revealed and not includable, and its
    Save, a ``policy.save`` with one passkey, includes the chosen ones at the pins the review
    verified (revision 3), which the gateway serves."""
    fake = McpFake(mode="modern", prompts=True, resources=True, switches={Switch.INJECT_KINDS})
    tool_pins = {wire["name"]: pin_of_fake(fake, wire["name"]) for wire in base_tools()}
    tools = sorted(tool_pins)
    made = vault(tmp_path)
    made.ca = ca.ca_file
    port = free_port()
    passkey = SoftAuthenticator()
    with serve_tls(fake.app(), ca, lifespan=True) as upstream, Browser(timeout=60.0) as browser:
        made.policy = notes_policy(made.portal, upstream, tool_pins)
        page = browser.page(f"http://localhost:{made.portal}")
        running = made.start()
        state_of_gateway = tmp_path / "gateway-state"
        gateway = gateway_on(made, state_of_gateway, port)
        try:
            assert redeem(page, setup_code(made.state, made.env)).status_code == 200
            assert enrol(page, passkey).status_code == 200
            wait_for(lambda: kinds_seen(port) is not None, "notes served", gateway, running)
            assert kinds_seen(port) == (["tools"], [])
            # J12's row (D-216): what the upstream offers and isn't served, the managed way.
            assert login(page, passkey).status_code == 200
            tools_listed(port)
            every = ["prompts", "resources", "completions"]
            wait_for(lambda: offered_row(page) == every, "the row's offer", gateway, running)
            assert row_of(page)["next"][-1] == {
                "do": "enable_kinds",
                "label": "Export, add enable: [prompts, resources, completions] to notes, import",
            }
            made.stop()

            def enable(data: dict[str, Any]) -> None:
                data["gateway"]["servers"][SERVER]["enable"] = ["prompts", "resources"]

            state = ["--state", str(made.state)]
            text = edited_export(made, enable, state)
            argv = ["policy", "import", "-", *state, "--yes", "--accept-widening"]
            code, _, err = made.cli(argv, text)
            assert code == 0, err
            assert "  gateway.servers.notes.enable: prompts added (wider)\n" in err
            assert opened(made).revision == 2
            running = made.start()
            assert login(page, passkey).status_code == 200
            # Enabled, but nothing included: the path still states tools only.
            deployment = deployment_of(made)
            wait_for(lambda: seen_by(state_of_gateway) == {deployment: 2}, "revision 2", gateway)
            assert kinds_seen(port) == (["tools"], [])
            tools_listed(port)
            wait_for(lambda: offered_row(page) == ["completions"], "completions", gateway, running)
            assert row_of(page)["next"][-1]["label"] == (
                "Export, add enable: [completions] to notes, import"
            )
            kind, read, answer = saved_with_kinds(page, passkey, tools, gateway, running)
            assert (kind, answer["revision"]) == ("policy.save", 3)
            rows = {row["name_shown"]: row for row in read["tools"] if row["kind"] != "tool"}
            headings = [row["heading"] for row in read["tools"] if row["heading"]]
            assert headings == ["Prompts", "Resource templates", "Resources"]
            for name in HOSTILE:
                assert rows[name]["pinnable"] is False
                assert "[U+200B]" in rows[name]["description_shown"]
            assert ZERO_WIDTH not in json.dumps(read, ensure_ascii=False)
            served = (["prompts", "resources", "tools"], [HIDDEN_PROMPT])
            wait_for(lambda: kinds_seen(port) == served, "the prompt served", gateway, running)
        finally:
            gateway.stop()
            made.stop()
    saved = head_policy(opened(made)).gateway
    assert saved is not None
    notes = saved.servers[SERVER]
    assert isinstance(notes, RemoteServer)
    assert notes.prompts.review == {HIDDEN_PROMPT: HIDDEN_PIN}
    assert notes.resources.templates.review == {TEMPLATE: TEMPLATE_PIN}
    assert notes.resources.fixed.review == {FIXED: FIXED_PIN}
    assert opened(made).top.header["kind"] == "policy.save"
