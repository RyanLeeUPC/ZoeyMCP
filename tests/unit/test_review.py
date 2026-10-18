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


@pytest.mark.parametrize(
    ("name", "key"),
    [
        ("echo", "echo"),
        ("get_note", "get_note"),
        ("true", '"true"'),
        ("No", '"No"'),
        ("-x", '"-x"'),
        ("1abc", '"1abc"'),
        ("a.b", '"a.b"'),
    ],
)
def test_yaml_keys_are_quoted_when_needed(name: str, key: str) -> None:
    assert view.yaml_key(name) == key
    assert load_mapping(f"{key}: 1\n") == {name: 1}


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
    assert server == {"era": "modern", "review": {"fine": pin("fine")}}
    assert "      # not included: evil  (error findings: not pinnable)" in lines


def drifted() -> dict[str, Any]:
    server = policy(["a", "gone", "bad"], {"a": pin("a"), "gone": pin("gone"), "bad": pin("bad")})
    return reviewed([tool("a", "Changed."), tool("bad", f"x{BIDI}"), tool("new")], server)


def test_the_snippet_for_drift_missing_and_invalid_keeps_the_old_pins() -> None:
    lines = view.snippet(drifted(), view.Choices())
    review = load_mapping("\n".join(lines))["gateway"]["servers"]["notes"]["review"]
    assert review == {"a": pin("a"), "gone": pin("gone"), "bad": pin("bad")}
    text = "\n".join(lines)
    assert f"# DRIFT: the server lists {pin('a', 'Changed.')}; --repin a takes it" in text
    assert "# MISSING: the server doesn't list it" in text
    assert "# INVALID: not pinnable, kept hidden" in text
    assert f"# not included: new  {pin('new')}" in text


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
    assert "        # new: put it in allow or approve; nothing is implied" in lines
    assert f"        a: {pin('a', 'Changed.')}  # CHANGED, was {pin('a')}" in lines


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
    lines, code = view.summary(status(notes=REMOTE, mail={"kind": "toolkit", "state": "x"}))
    assert code == 0
    assert lines == [
        "mail  toolkit: not served by this version",
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
    lines = view.status_lines(status(notes=marked, mail={"kind": "toolkit"}), None)
    assert lines == [
        f"view sha256:{'0' * 64}  fresh",
        "mail  toolkit  unsupported",
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
