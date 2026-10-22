"""``zoeymcp review``: the gateway's report, the CLI's rendering and snippet, and the uid switch
(M3 design I, B.2)."""

from __future__ import annotations

import io
import json
import unicodedata
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from mcp.types import Implementation, Tool

from zoeymcp.cli import admin_client
from zoeymcp.cli import review as view
from zoeymcp.cli.main import main
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.policy.view import ViewRemoteServer
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins
from zoeymcp.gateway.review import ReviewError, report

LIMITS = GatewayLimits()
C1 = "\x9b"
BIDI = "\u202e"


def wire(name: str, description: str = "Does a thing.") -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "inputSchema": {"type": "object", "properties": {"q": {"type": "string"}}},
    }


def tool(name: str, description: str = "Does a thing.") -> Tool:
    return Tool.model_validate(wire(name, description))


def pin(name: str, description: str = "Does a thing.") -> str:
    return pins.project_and_pin(tool(name, description)).pin


def policy(include: list[str], review: dict[str, str], on_drift: str = "hide") -> ViewRemoteServer:
    return ViewRemoteServer.model_validate(
        {
            "kind": "remote",
            "vault_path": "/notes/mcp",
            "tools": {"include": include, "allow": include, "approve": []},
            "review": review,
            "on_drift": on_drift,
            "shared_session": False,
            "wrap_results": False,
            "enable": [],
            "era": "auto",
            "drift_check_interval": 300,
            "call_timeout": None,
        }
    )


def reviewed(
    tools: list[Tool],
    server: ViewRemoteServer,
    marks: frozenset[pins.Mark] = frozenset(),
    defs: dict[str, Any] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    evaluation = pins.evaluate(tools, server, marks, LIMITS)
    options: dict[str, Any] = {
        "era": "modern",
        "protocol_version": "2026-07-28",
        "server_info": None,
        "instructions": None,
        **extra,
    }
    return report(
        "notes",
        server,
        tools,
        evaluation,
        marks=evaluation.marks,
        defs=(defs or {}).get,
        limits=LIMITS,
        **options,
    )


def states(answer: dict[str, Any]) -> dict[str, str]:
    return {entry["name"]: entry["state"] for entry in answer["tools"]}


# --- the gateway's report ------------------------------------------------------------------------


def test_every_state() -> None:
    old = pins.project_and_pin(tool("drifts")).definition
    server = policy(
        ["fine", "drifts", "gone", "bad", "twice"],
        {
            "fine": pin("fine"),
            "drifts": pin("drifts"),
            "gone": pin("gone"),
            "bad": pin("bad"),
            "twice": pin("twice"),
        },
    )
    tools = [
        tool("fine"),
        tool("drifts", "Does another thing."),
        tool("bad", "Hidden\u200b text."),
        tool("twice"),
        tool("twice", "Again."),
        tool("extra"),
    ]
    answer = reviewed(tools, server, defs={pin("drifts"): old})
    assert states(answer) == {
        "fine": "ok",
        "drifts": "drift",
        "bad": "invalid",
        "twice": "duplicate",
        "extra": "unreviewed",
        "gone": "missing",
    }
    by_name = {entry["name"]: entry for entry in answer["tools"]}
    assert by_name["drifts"]["changed"] == ["description"]
    assert by_name["drifts"]["diff"][:2] == ["--- reviewed", "+++ listed"]
    assert by_name["drifts"]["pinned"] == pin("drifts")
    assert by_name["drifts"]["pin"] == pin("drifts", "Does another thing.")
    assert any(f["level"] == "error" for f in by_name["bad"]["findings"])
    assert by_name["twice"]["definition"] is None
    assert by_name["gone"]["pin"] is None
    assert by_name["extra"]["included"] is False
    assert by_name["fine"]["classification"] == "allow"
    assert answer["marked"] == ["drifts"]
    assert answer["clean"] is False
    assert answer["policy"]["include"] == ["fine", "drifts", "gone", "bad", "twice"]


def test_a_held_mark_and_a_blocked_server() -> None:
    server = policy(["a", "b"], {"a": pin("a"), "b": pin("b")})
    marked = reviewed([tool("a"), tool("b")], server, marks=frozenset({("a", pin("a"))}))
    assert states(marked) == {"a": "marked", "b": "ok"}
    assert marked["clean"] is False
    strict = policy(["a", "b"], {"a": pin("a"), "b": pin("b")}, on_drift="fail")
    blocked = reviewed([tool("a"), tool("b", "Changed.")], strict)
    assert states(blocked) == {"a": "blocked", "b": "drift"}
    assert blocked["blocked"] is True


def test_a_clean_server_and_what_is_never_forwarded() -> None:
    server = policy(["a"], {"a": pin("a")})
    answer = reviewed(
        [tool("a")],
        server,
        server_info=Implementation(name="up", version="2", title="Up"),
        instructions="x" * 20_000,
    )
    assert answer["clean"] is True
    assert answer["server_info"] == {"name": "up", "version": "2", "title": "Up"}
    assert len(answer["instructions"]) == 16_384 + 3
    assert answer["vault_path"] == "/notes/mcp"


def test_an_invalid_projection_has_no_pin() -> None:
    server = policy([], {})
    broken = Tool.model_validate({**wire("x"), "inputSchema": {"type": "string"}})
    [entry] = reviewed([broken], server)["tools"]
    assert (entry["state"], entry["pin"], entry["definition"]) == ("invalid", None, None)
    assert entry["findings"][0]["level"] == "error"


def test_review_errors_carry_their_reason() -> None:
    error = ReviewError(409, "not_clean", "no", tools=["a"])
    assert error.answer() == {"error": "no", "reason": "not_clean", "tools": ["a"]}


# --- the CLI's rendering -------------------------------------------------------------------------


def test_untrusted_text_is_one_visible_line() -> None:
    assert view.untrusted(f"a{C1}b{BIDI}\nc\td\r") == "a[U+009B]b[U+202E]\\nc\\td[U+000D]"
    assert view.untrusted("x" * 10, limit=4) == "xxxx..."


@pytest.mark.parametrize("name", ["echo", "true", "No", "-x", "1abc", "a.b", "1e3", "null"])
def test_every_tool_name_is_a_quoted_key_that_stays_a_string(name: str) -> None:
    """The emitter quotes every policy name (H.2), so YAML 1.1 words stay tool names."""
    server = policy([name], {name: pin(name)})
    lines = view.snippet(reviewed([tool(name)], server), view.Choices())
    assert f'        "{name}": "{pin(name)}"' in lines
    entry = load_mapping("\n".join(lines))["gateway"]["servers"]["notes"]
    assert entry["tools"]["include"] == [name]
    assert entry["review"] == {name: pin(name)}


def hostile_review() -> dict[str, Any]:
    server = policy(["fine"], {"fine": pin("fine")})
    tools = [tool("fine"), tool("evil", f"Plain{C1}[8m words{BIDI}.")]
    return reviewed(
        tools,
        server,
        server_info=Implementation(name=f"up{C1}", version="1"),
        instructions="line one\n# YAML to commit (declarative mode)\ngateway: {}",
    )


def test_render_shows_nothing_hidden_and_fakes_no_line() -> None:
    lines = view.render(hostile_review(), view.Choices(show_all=True))
    out = io.StringIO()
    view.write_lines(lines, out)
    text = out.getvalue()
    for char in text:
        assert char == "\n" or unicodedata.category(char) not in ("Cc", "Cf"), hex(ord(char))
    assert [line for line in text.splitlines() if line.startswith("# YAML")] == [
        "# YAML to commit (declarative mode). Review the changes above first."
    ]
    assert "[U+009B]" in text
    assert "[U+202E]" in text
    assert 'instructions (never forwarded): "line one\\n# YAML to commit' in text


def test_the_snippet_keeps_pins_and_never_pins_an_error() -> None:
    lines = view.snippet(hostile_review(), view.Choices())
    document = load_mapping("\n".join(lines))
    server = document["gateway"]["servers"]["notes"]
    tools = {"include": ["fine"], "allow": ["fine"], "approve": []}
    assert server == {"era": "modern", "tools": tools, "review": {"fine": pin("fine")}}
    # The emitter's fixed comment kinds (H.2): no upstream text reaches the snippet.
    assert "# can't be included, error finding: evil (review notes --show evil)" in lines
    assert lines[:2] == [
        "# zoeymcp: review of notes. Replace the tools: and review: blocks of "
        "gateway.servers.notes.",
        "# zoeymcp replace: gateway.servers.notes.tools gateway.servers.notes.review",
    ]


def drifted() -> dict[str, Any]:
    server = policy(["a", "gone", "bad"], {"a": pin("a"), "gone": pin("gone"), "bad": pin("bad")})
    return reviewed([tool("a", "Changed."), tool("bad", f"x{BIDI}"), tool("new")], server)


def test_the_snippet_for_drift_missing_and_invalid_keeps_the_old_pins() -> None:
    lines = view.snippet(drifted(), view.Choices())
    review = load_mapping("\n".join(lines))["gateway"]["servers"]["notes"]["review"]
    assert review == {"a": pin("a"), "gone": pin("gone"), "bad": pin("bad")}
    text = "\n".join(lines)
    drift = f"# kept: a (drift: the server lists {pin('a', 'Changed.')}; review notes --repin a "
    assert drift + "takes it)" in text
    assert "# kept: gone (missing: the server doesn't list it)" in text
    assert "# kept: bad (invalid: not pinnable, kept hidden)" in text
    assert (
        f"# not included: new ({pin('new')}; not annotated: approve suggested if you include it)"
        in text
    )


def test_repin_and_add() -> None:
    choices = view.Choices(repin=frozenset({"a"}), add=("new",))
    lines = view.snippet(drifted(), choices)
    server = load_mapping("\n".join(lines))["gateway"]["servers"]["notes"]
    assert server["review"]["a"] == pin("a", "Changed.")
    assert server["review"]["new"] == pin("new")
    assert server["tools"] == {
        "include": ["a", "gone", "bad", "new"],
        "allow": ["a", "gone", "bad"],
        "approve": [],
    }
    assert "# added: new (put it in allow or approve; nothing is implied)" in lines
    assert "# suggested: new (not annotated: approve suggested if you include it)" in lines
    assert f"# changed: a (was {pin('a')})" in lines
    assert f'        "a": "{pin("a", "Changed.")}"' in lines


@pytest.mark.parametrize(
    ("choices", "message"),
    [
        (view.Choices(add=("nothing",)), "--add nothing: the server doesn't list it"),
        (view.Choices(add=("gone",)), "--add gone: the server doesn't list it"),
        (view.Choices(add=("a",)), "--add a: it is already included"),
        (view.Choices(repin=frozenset({"new"})), "--repin new: it hasn't drifted"),
        (view.Choices(tools=frozenset({"zz"})), "the server lists no tool named zz"),
        (view.Choices(show=frozenset({"zz"})), "the server lists no tool named zz"),
    ],
)
def test_choices_that_dont_fit_are_refused(choices: view.Choices, message: str) -> None:
    with pytest.raises(view.UsageError, match=message):
        view.check_choices(drifted(), choices)


def test_an_error_tool_cant_be_added_or_repinned() -> None:
    server = policy(["a"], {"a": pin("a")})
    answer = reviewed([tool("a", f"x{BIDI}y"), tool("b", f"x{BIDI}")], server)
    with pytest.raises(view.UsageError, match="error findings"):
        view.check_choices(answer, view.Choices(add=("b",)))
    entry = {**answer["tools"][0], "state": "drift"}
    with pytest.raises(view.UsageError, match="error findings"):
        view.check_choices({**answer, "tools": [entry]}, view.Choices(repin=frozenset({"a"})))


def hinted(name: str, **hints: bool) -> Tool:
    return Tool.model_validate({**wire(name), "annotations": hints})


def pins_of_hinted(name: str) -> str:
    return pins.project_and_pin(hinted(name, readOnlyHint=True)).pin


def classifying() -> dict[str, Any]:
    """A server with nothing included yet: tools the server marks read-only, destructive, both
    (a contradiction), not at all, and one with an error finding that claims read-only."""
    return reviewed(
        [
            hinted("ro", readOnlyHint=True),
            hinted("rw", readOnlyHint=False, destructiveHint=True),
            hinted("both", readOnlyHint=True, destructiveHint=True),
            tool("plain"),
            Tool.model_validate({**wire("bad", f"x{BIDI}"), "annotations": {"readOnlyHint": True}}),
        ],
        policy([], {}),
    )


def listed_pins(answer: dict[str, Any]) -> dict[str, str]:
    return {entry["name"]: entry["pin"] for entry in answer["tools"]}


def snippet_entry(lines: list[str]) -> dict[str, Any]:
    entry: dict[str, Any] = load_mapping("\n".join(lines))["gateway"]["servers"]["notes"]
    return entry


def test_allow_and_approve_include_and_classify() -> None:
    answer = classifying()
    choices = view.Choices(allow=("plain",), approve=("rw",), add=("both",))
    view.check_choices(answer, choices)
    lines = view.snippet(answer, choices)
    entry = snippet_entry(lines)
    assert entry["tools"] == {
        "include": ["both", "plain", "rw"],
        "allow": ["plain"],
        "approve": ["rw"],
    }
    found = listed_pins(answer)
    assert entry["review"] == {name: found[name] for name in ("both", "plain", "rw")}
    assert "# added: plain (allow)" in lines
    assert "# added: rw (approve)" in lines
    # --add leaves the classification to the operator, with the server's suggestion beside it.
    assert "# added: both (put it in allow or approve; nothing is implied)" in lines
    assert (
        "# suggested: both (not read-only (the server's hints): approve suggested if you "
        "include it)"
    ) in lines
    assert f"# not included: ro ({found['ro']}; read-only (the server's suggestion))" in lines
    assert "# can't be included, error finding: bad (review notes --show bad)" in lines


def test_allow_read_only_allows_only_what_the_server_marks_read_only() -> None:
    """Nothing bulk-allows a destructive tool, an unannotated one or one with an error finding
    (PC-2, F-52): only ro, which says why it was allowed."""
    answer = classifying()
    assert view.read_only(answer) == ["ro"]
    lines = view.snippet(answer, view.Choices(allow_read_only=True))
    entry = snippet_entry(lines)
    assert entry["tools"] == {"include": ["ro"], "allow": ["ro"], "approve": []}
    assert entry["review"] == {"ro": listed_pins(answer)["ro"]}
    assert "# added: ro (allowed because the server marks it read-only)" in lines
    # An option naming the tool wins over the bulk one.
    both = view.Choices(allow_read_only=True, approve=("ro",))
    assert snippet_entry(view.snippet(answer, both))["tools"]["approve"] == ["ro"]


def test_bulk_allow_leaves_included_tools_alone() -> None:
    server = policy(["ro"], {"ro": pins_of_hinted("ro")})
    answer = reviewed([hinted("ro", readOnlyHint=True), hinted("ro2", readOnlyHint=True)], server)
    entry = snippet_entry(view.snippet(answer, view.Choices(allow_read_only=True)))
    assert entry["tools"] == {"include": ["ro", "ro2"], "allow": ["ro", "ro2"], "approve": []}


@pytest.mark.parametrize(
    ("choices", "message"),
    [
        (view.Choices(allow=("nothing",)), "--allow nothing: the server doesn't list it"),
        (view.Choices(approve=("bad",)), "--approve bad: it has error findings"),
        (view.Choices(allow=("bad",)), "--allow bad: it has error findings"),
        (view.Choices(add=("ro",), allow=("ro",)), "ro: name it in one of --add, --allow and"),
        (view.Choices(allow=("ro",), approve=("ro",)), "ro: name it in one of"),
    ],
)
def test_classifying_options_that_dont_fit(choices: view.Choices, message: str) -> None:
    with pytest.raises(view.UsageError, match=message):
        view.check_choices(classifying(), choices)
    server = policy(["ro"], {"ro": pins_of_hinted("ro")})
    included = reviewed([hinted("ro", readOnlyHint=True)], server)
    with pytest.raises(view.UsageError, match="--approve ro: it is already included"):
        view.check_choices(included, view.Choices(approve=("ro",)))


def test_tool_lines() -> None:
    lines = view.render(drifted(), view.Choices(tools=frozenset({"a", "gone"})))
    assert lines[1].split()[:3] == ["a", "DRIFT", "changed"]
    assert "changed (no reviewed copy kept)" in lines[1]
    assert lines[2].split()[:4] == ["gone", "MISSING", "pinned", pin("gone")[:19] + "..."]
    assert not any(line.split()[:1] == ["new"] for line in lines[1:4])


def test_exit_codes() -> None:
    assert view.exit_code({"clean": True}) == 0
    assert view.exit_code({"clean": False}) == 1


# --- the summary and gateway-status --------------------------------------------------------------


def status(**servers: Any) -> dict[str, Any]:
    return {"version": "1", "view": "sha256:" + "0" * 64, "fresh": True, "servers": servers}


REMOTE = {
    "kind": "remote",
    "state": ["ready"],
    "era": "modern",
    "connections": 1,
    "included": 2,
    "exposed": 2,
    "marked": [],
    "reports": {"unreviewed": ["x"]},
    "listed_s_ago": 12.4,
}


def test_the_summary() -> None:
    lines, code = view.summary(status(notes=REMOTE))
    assert code == 0
    assert lines == [
        "notes  modern  exposed 2/2  drift 0  marked 0  missing 0  unreviewed 1  invalid 0  "
        "listed 12 s ago",
    ]
    marked = {**REMOTE, "marked": ["a"], "listed_s_ago": None, "era": None}
    lines, code = view.summary(status(notes=marked))
    assert code == 1
    assert "era unknown" in lines[0]
    assert lines[0].endswith("never listed")
    drift = {**REMOTE, "reports": {"drift": ["a"]}}
    assert view.summary(status(notes=drift))[1] == 1
    stale = {**status(), "fresh": False}
    assert view.summary(stale) == (
        ["no gateway servers", "the gateway has no fresh view of the policy"],
        1,
    )


def test_status_lines() -> None:
    marked = {**REMOTE, "marked": ["a"], "reports": {"drift": ["a"], "missing": []}}
    lines = view.status_lines(status(notes=marked), None)
    assert lines == [
        f"view sha256:{'0' * 64}  fresh",
        "notes  remote  ready  era modern  connections 1  exposed 2/2",
        "  marked: a",
        "  drift: a",
        "  last listing 12 s ago",
    ]
    assert view.status_lines(status(notes=REMOTE, other=REMOTE), "other")[1].startswith("other")
    none = {**status(), "view": None, "fresh": False}
    assert view.status_lines(none, None) == ["view none yet  NOT FRESH"]


# --- the CLI against a canned gateway ------------------------------------------------------------


class FakeGateway:
    def __init__(self, answers: dict[tuple[str, str], tuple[int, Any]]) -> None:
        self.answers = answers
        self.paths: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.raw_path.decode()
        self.paths.append(path)
        code, data = self.answers[(request.method, path)]
        return httpx.Response(code, json=data)


def run_cli(monkeypatch: pytest.MonkeyPatch, fake: FakeGateway, *argv: str) -> tuple[int, str, str]:
    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(fake.handle))
    out, err = io.StringIO(), io.StringIO()
    return main(list(argv), stdin=io.StringIO(), out=out, err=err), out.getvalue(), err.getvalue()


def test_review_and_status_use_the_gateway_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[str] = []
    fake = FakeGateway({("GET", "/status"): (200, status(notes=REMOTE))})

    def transport(**options: Any) -> httpx.BaseTransport:
        seen.append(options["uds"])
        return httpx.MockTransport(fake.handle)

    monkeypatch.setattr(httpx, "HTTPTransport", transport)
    monkeypatch.setenv(admin_client.GATEWAY_SOCKET_ENV, "/elsewhere/admin.sock")
    out, err = io.StringIO(), io.StringIO()
    assert main(["gateway-status"], stdin=io.StringIO(), out=out, err=err) == 0
    assert main(["review", "--socket", "/x.sock"], stdin=io.StringIO(), out=out, err=err) == 0
    assert seen == ["/elsewhere/admin.sock", "/x.sock"]


def test_review_json_has_the_snippet_and_is_ascii(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = hostile_review()
    fake = FakeGateway({("POST", "/review/notes"): (200, answer)})
    code, out, _ = run_cli(monkeypatch, fake, "review", "notes", "--format", "json")
    assert code == 0
    assert out.isascii()
    data = json.loads(out)
    assert data["snippet"] == view.snippet(answer, view.Choices())


def test_review_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    refused = {"error": "not every included tool matches its pin: a", "reason": "not_clean"}
    fake = FakeGateway(
        {
            ("POST", "/review/gone"): (404, {"error": "no gateway server named 'gone'"}),
            ("POST", "/review/notes/clear"): (409, {**refused, "review": drifted()}),
            ("POST", "/review/odd/clear"): (409, refused),
            ("POST", "/review/notes"): (200, drifted()),
            ("GET", "/status"): (200, status(notes=REMOTE)),
        }
    )
    assert run_cli(monkeypatch, fake, "review", "gone") == (
        2,
        "",
        "zoeymcp review: no gateway server named 'gone'\n",
    )
    code, out, err = run_cli(monkeypatch, fake, "review", "notes", "--clear")
    assert code == 1
    assert err == "zoeymcp review: --clear refused: not every included tool matches its pin: a\n"
    assert "DRIFT" in out
    assert run_cli(monkeypatch, fake, "review", "odd", "--clear")[0] == 2
    code, _, err = run_cli(monkeypatch, fake, "review", "notes", "--add", "zz")
    assert (code, err) == (2, "zoeymcp review: --add zz: the server doesn't list it\n")
    assert run_cli(monkeypatch, fake, "review", "--all")[0] == 2
    code, _, err = run_cli(monkeypatch, fake, "gateway-status", "zz")
    assert (code, err) == (2, "zoeymcp gateway-status: no gateway server named 'zz'\n")
    code, out, _ = run_cli(monkeypatch, fake, "gateway-status", "notes", "--format", "json")
    assert list(json.loads(out)["servers"]) == ["notes"]
    code, out, _ = run_cli(monkeypatch, fake, "review", "--format", "json")
    assert json.loads(out)["servers"]["notes"]["kind"] == "remote"


def test_review_classifies_through_the_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGateway({("POST", "/review/notes"): (200, classifying())})
    code, out, err = run_cli(
        monkeypatch, fake, "review", "notes", "--allow-read-only", "--approve", "plain"
    )
    assert (code, err) == (0, "")
    snippet = out[out.index("# YAML to commit") :].splitlines()[1:]
    assert snippet_entry(snippet)["tools"] == {
        "include": ["plain", "ro"],
        "allow": ["ro"],
        "approve": ["plain"],
    }
    code, _, err = run_cli(monkeypatch, fake, "review", "notes", "--allow", "rw", "--add", "rw")
    assert (code, err) == (
        2,
        "zoeymcp review: rw: name it in one of --add, --allow and --approve\n",
    )


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--suggest"], "--suggest goes with --choose"),
        (["--choose", "--choices", "-"], "--choose writes a choices file and --choices reads one"),
        (["--choose", "--add", "x"], "--choose and --choices print text and take no other"),
        (["--choices", "-", "--allow-read-only"], "take no other choices"),
        (["--choose", "--format", "json"], "take no other choices"),
        (["--choose", "--show", "x"], "take no other choices"),
    ],
)
def test_choices_usage_errors(
    monkeypatch: pytest.MonkeyPatch, argv: list[str], message: str
) -> None:
    fake = FakeGateway({})
    code, out, err = run_cli(monkeypatch, fake, "review", "notes", *argv)
    assert (code, out) == (2, "")
    assert message in err
    assert fake.paths == []
    for option in (["--choose"], ["--allow-read-only"], ["--approve", "x"]):
        assert run_cli(monkeypatch, fake, "review", *option)[2] == (
            "zoeymcp review: these options need a server\n"
        )


def test_choose_and_choices_over_the_gateways_socket(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    """The gateway's socket keeps no job, so the header names none; a file read by path comes
    back as fragment 2, and a listing changed since refuses it, printing nothing."""
    answer = classifying()
    fake = FakeGateway({("POST", "/review/notes"): (200, answer)})
    code, out, err = run_cli(monkeypatch, fake, "review", "notes", "--choose", "--suggest")
    assert (code, err) == (0, "")
    assert out.splitlines()[1].startswith("# report - sha256:")
    lines = [
        "approve" + line[4:] if line.split()[:2] == ["skip", "plain"] else line
        for line in out.splitlines()
    ]
    path = tmp_path / "notes.choices"
    path.write_bytes(("\n".join(lines) + "\n").encode())
    code, out, err = run_cli(monkeypatch, fake, "review", "notes", "--choices", str(path))
    assert code == 0
    assert err.startswith("zoeymcp review: the file includes 2 tools (1 allow, 1 approve). ")
    assert load_mapping(out)["gateway"]["servers"]["notes"]["tools"] == {
        "include": ["plain", "ro"],
        "allow": ["ro"],
        "approve": ["plain"],
    }
    assert fake.paths == ["/review/notes", "/review/notes"]
    changed = "sha256:" + "1" * 64
    later = [{**e, "pin": changed} if e["name"] == "ro" else e for e in answer["tools"]]
    fake.answers[("POST", "/review/notes")] = (200, {**answer, "tools": later})
    code, out, err = run_cli(monkeypatch, fake, "review", "notes", "--choices", str(path))
    assert (code, out) == (2, "")
    assert err == (
        "zoeymcp review: choices_stale: changed since review --choose wrote the file: ro; read "
        "each again (review notes --show TOOL), then write the file again\n"
    )


def test_a_choices_file_is_read_before_the_review_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    fake = FakeGateway({})
    bad = tmp_path / "bad.choices"
    bad.write_bytes(b"# zoeymcp review notes: \xff\n")
    headless = tmp_path / "headless.choices"
    headless.write_bytes(f"allow ro {'sha256:' + '0' * 64}\n".encode())
    for path in (tmp_path / "gone.choices", bad):
        code, out, err = run_cli(monkeypatch, fake, "review", "notes", "--choices", str(path))
        assert (code, out) == (2, "")
        assert err.startswith(f"zoeymcp review: can't read {path}: ")
    code, out, err = run_cli(monkeypatch, fake, "review", "notes", "--choices", str(headless))
    assert (code, out) == (2, "")
    assert err.startswith("zoeymcp review: choices_invalid: the file has no zoeymcp review header")
    assert fake.paths == []


def test_an_unreachable_gateway_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no such socket")

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(refuse))
    for argv in (["review"], ["review", "notes"], ["gateway-status"]):
        err = io.StringIO()
        assert main(argv, stdin=io.StringIO(), out=io.StringIO(), err=err) == 2
        assert "can't reach the gateway's admin socket at /run/zoeymcp-gateway/admin.sock" in (
            err.getvalue()
        )


# --- the uid switch ------------------------------------------------------------------------------


class FakeOs:
    """The parts of :mod:`os` the uid switch uses, recording calls."""

    def __init__(self, euid: int, owner: int, group: int, *, fail: bool = False) -> None:
        self.euid, self.owner, self.group, self.fail = euid, owner, group, fail
        self.calls: list[tuple[str, Any]] = []

    def geteuid(self) -> int:
        return self.euid

    def stat(self, path: str) -> Any:
        self.calls.append(("stat", path))
        if self.owner < 0:
            raise FileNotFoundError(path)
        return SimpleNamespace(st_uid=self.owner, st_gid=self.group)

    def setgroups(self, groups: list[int]) -> None:
        self.calls.append(("setgroups", groups))

    def setgid(self, gid: int) -> None:
        self.calls.append(("setgid", gid))

    def setuid(self, uid: int) -> None:
        self.calls.append(("setuid", uid))
        if self.fail:
            raise PermissionError(1, "Operation not permitted")


def test_root_becomes_the_owner_of_the_socket_directory() -> None:
    system = FakeOs(0, 10002, 10002)
    admin_client.become_socket_owner("/run/zoeymcp-gateway/admin.sock", system)
    assert system.calls == [
        ("stat", "/run/zoeymcp-gateway"),
        ("setgroups", []),
        ("setgid", 10002),
        ("setuid", 10002),
    ]


@pytest.mark.parametrize(("euid", "owner"), [(10001, 10001), (0, 0), (0, -1)])
def test_no_switch_unless_root_and_another_owner(euid: int, owner: int) -> None:
    system = FakeOs(euid, owner, owner)
    admin_client.become_socket_owner("/run/zoeymcp/admin.sock", system)
    assert all(name == "stat" for name, _ in system.calls)


def test_no_switch_without_geteuid() -> None:
    admin_client.become_socket_owner("/run/zoeymcp/admin.sock", SimpleNamespace())


def test_a_failed_switch_says_how_to_run_it() -> None:
    system = FakeOs(0, 10001, 10001, fail=True)
    with pytest.raises(admin_client.AdminUnavailable, match=r"run with -u 10001"):
        admin_client.become_socket_owner("/run/zoeymcp/admin.sock", system)


def test_the_switch_happens_before_connecting(monkeypatch: pytest.MonkeyPatch) -> None:
    order: list[str] = []
    monkeypatch.setattr(admin_client, "become_socket_owner", lambda socket: order.append(socket))
    fake = FakeGateway({("GET", "/status"): (200, status())})

    def transport(**_: Any) -> httpx.BaseTransport:
        order.append("connect")
        return httpx.MockTransport(fake.handle)

    monkeypatch.setattr(httpx, "HTTPTransport", transport)
    admin_client.gateway_status("/run/zoeymcp-gateway/admin.sock")
    assert order == ["/run/zoeymcp-gateway/admin.sock", "connect"]


TOOLKIT = {
    "kind": "toolkit",
    "state": "loaded",
    "module": "example_toolkits.mail",
    "distribution": "example-toolkits",
    "version": "0.1.0",
    "pinning": "required",
    "included": 1,
    "exposed": 1,
    "marked": [],
    "reports": {},
}


def test_toolkit_servers_in_the_summary_and_status() -> None:
    lines, code = view.summary(status(mail=TOOLKIT))
    assert (lines, code) == (
        [
            "mail  toolkit example_toolkits.mail  exposed 1/1  drift 0  marked 0  missing 0  "
            "invalid 0  pinning required"
        ],
        0,
    )
    unavailable = {"kind": "toolkit", "state": "unavailable", "reason": "not_registered"}
    assert view.summary(status(mail=unavailable)) == (
        ["mail  toolkit unavailable (not_registered)"],
        1,
    )
    marked = {**TOOLKIT, "marked": ["send_note"], "reports": {"drift": ["send_note"]}}
    assert view.summary(status(mail=marked))[1] == 1
    assert view.status_lines(status(mail=marked, odd=unavailable), None)[1:] == [
        "mail  toolkit  example_toolkits.mail 0.1.0  pinning required  exposed 1/1",
        "  marked: send_note",
        "  drift: send_note",
        "odd  toolkit  unavailable (not_registered)",
    ]
