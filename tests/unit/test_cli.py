from __future__ import annotations

import getpass
import io
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from zoeymcp.cli import admin_client
from zoeymcp.cli.main import (
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_UNREADABLE,
    NOT_PERSISTED,
    duration,
    format_status,
    main,
)

from .conftest import EXAMPLE_POLICY


def run(argv: list[str], stdin: str = "") -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), out=out)
    return code, out.getvalue()


def test_check_example_file() -> None:
    code, out = run(["check", "--config", str(EXAMPLE_POLICY)])
    assert code == EXIT_OK
    assert out.strip().endswith("ok (0 error(s), 1 warning(s))")


def test_check_from_stdin(example_text: str) -> None:
    code, out = run(["check", "--config", "-"], stdin=example_text)
    assert code == EXIT_OK
    assert out.splitlines()[-1] == "<stdin>: ok (0 error(s), 1 warning(s))"


def test_check_from_env(example_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZOEYMCP_CONFIG", example_text)
    code, out = run(["check"])
    assert code == EXIT_OK
    assert out.splitlines()[-1] == "$ZOEYMCP_CONFIG: ok (0 error(s), 1 warning(s))"


def test_check_reports_errors_as_json(example_text: str) -> None:
    bad = example_text.replace(
        "callers: [gateway] # the gateway only", "callers: [{placeholder: ph-sandbox-0123456789}]"
    )
    code, out = run(["check", "--config", "-", "--format", "json"], stdin=bad)
    assert code == EXIT_FINDINGS
    report = json.loads(out)
    assert report["ok"] is False
    assert report["readable"] is True
    assert report["errors"] == 1
    found = [f["path"] for f in report["findings"] if f["level"] == "error"]
    assert found == ["routes[1].callers"]


def test_schema_errors_exit_with_findings() -> None:
    code, out = run(["check", "--config", "-"], stdin="version: 1\n")
    assert code == EXIT_FINDINGS
    assert "mode: Field required" in out


def test_resolve_env_flag(example_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    text = example_text.replace("secret: store:music-stats", "secret: env:ZMCP_TEST_STATS")
    monkeypatch.delenv("ZMCP_TEST_STATS", raising=False)
    assert run(["check", "--config", "-"], stdin=text)[0] == EXIT_OK
    code, out = run(["check", "--config", "-", "--resolve-env"], stdin=text)
    assert code == EXIT_FINDINGS
    assert "env var ZMCP_TEST_STATS is not set" in out


def test_missing_file_is_unreadable(tmp_path: Path) -> None:
    code, out = run(["check", "--config", str(tmp_path / "absent.yaml")])
    assert code == EXIT_UNREADABLE
    assert "can't read" in out


def test_no_policy_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZOEYMCP_CONFIG", raising=False)
    code, out = run(["check"])
    assert code == EXIT_UNREADABLE
    assert "no policy given" in out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert capsys.readouterr().out.startswith("zoeymcp ")


def test_keygen_prints_a_matching_pair() -> None:
    from zoeymcp.vault.keys import KeySet

    code, out = run(["keygen"])
    assert code == EXIT_OK
    lines = dict(line.split("=", 1) for line in out.splitlines())
    assert set(lines) == {"ZOEYMCP_MASTER_KEY", "ZOEYMCP_GATEWAY_KEY"}
    assert (
        KeySet.from_text(lines["ZOEYMCP_MASTER_KEY"]).gateway_key(1) == lines["ZOEYMCP_GATEWAY_KEY"]
    )
    assert run(["keygen"])[1] != out


@pytest.mark.parametrize(
    ("binding", "text"),
    [
        (
            {"origins": ["https://a.example:443", "https://b.example:443"]},
            "origins https://a.example:443, https://b.example:443",
        ),
        (
            {
                "oauth": {
                    "token": "https://accounts.example:443",
                    "resources": ["https://api.example:443", "https://files.example:443"],
                }
            },
            "token endpoint https://accounts.example:443, "
            "access tokens to https://api.example:443, https://files.example:443",
        ),
        (
            {
                "smtp": {
                    "host": "smtp.mail.example",
                    "port": 465,
                    "from": "a@mail.example",
                    "to": ["b@mail.example", "c@mail.example"],
                }
            },
            "SMTP smtp.mail.example:465 from a@mail.example to b@mail.example, c@mail.example",
        ),
        ({"other": 1}, '{"other": 1}'),
    ],
    ids=["origins", "oauth", "smtp", "unknown"],
)
def test_describe_binding(binding: dict[str, Any], text: str) -> None:
    assert admin_client.describe_binding(binding) == text


# --- login and oauth, against a canned admin socket --------------------------------------------

BINDING = {
    "oauth": {"token": "https://accounts.example:443", "resources": ["https://api.example:443"]}
}
AUTHORIZE = "https://accounts.example/authorize?response_type=code&client_id=example-client"
PASTED = "http://127.0.0.1/callback?code=fake-code-1&state=fake-state-1"
STARTED: dict[str, Any] = {
    "flow": "flow-0001",
    "authorize_url": AUTHORIZE,
    "redirect_uri": "http://127.0.0.1/callback",
    "expires": 1_800_000_600,
    "requested_scopes": ["read"],
    "expected_scopes": ["read"],
    "client_auth": "none",
    "rotates": True,
    "binding": BINDING,
    "binding_change": None,
}
COMPLETED: dict[str, Any] = {
    "slot": "oauth.music.live",
    "binding": BINDING,
    "granted_scopes": ["read", "admin"],
    "unexpected_scopes": ["admin"],
    "missing_scopes": [],
    "access_expires_in": 3600,
    "refresh_expires_at": None,
    "consented_at": "2026-10-17T09:00:00Z",
    "grant_expires_at": "2027-04-15T09:00:00Z",
    "persisted": True,
    "seed_note": "The env seed MUSIC_REFRESH is now ignored (reseed: never). You may remove it.",
}
HEADER = (
    "Credential   music (public client, PKCE S256, rotating refresh tokens)\n"
    "Binding      token endpoint https://accounts.example:443\n"
    "             access tokens to https://api.example:443\n"
    "Scopes       read\n"
    "\n"
    "Open this URL in a browser and approve:\n"
    f"  {AUTHORIZE}\n"
)
STORED = (
    "Stored the refresh token for music as oauth.music.live.\n"
    "Granted: read admin\n"
    "The grant ends at 2027-04-15T09:00:00Z; run login again before then.\n"
    "The env seed MUSIC_REFRESH is now ignored (reseed: never). You may remove it.\n"
)


def paste_text(how: str) -> str:
    return (
        "\nYour browser will then try to open http://127.0.0.1/callback?... and fail to load. "
        "That is\nexpected. Copy the full address from the address bar and paste it here "
        f"({how}, 10 minutes):\n"
    )


class FakeAdmin:
    """The admin socket, answering each method and path with a canned answer."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {
            ("POST", "/oauth/music/login"): (200, STARTED),
            ("POST", "/oauth/music/complete"): (200, COMPLETED),
            ("DELETE", "/oauth/flows/flow-0001"): (200, {"cancelled": True}),
        }
        self.requests: list[tuple[str, str, Any]] = []
        self.timeouts: list[float] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.raw_path.decode(), body))
        self.timeouts.append(request.extensions["timeout"]["read"])
        status, data = self.answers[(request.method, request.url.raw_path.decode())]
        return httpx.Response(status, json=data)


@pytest.fixture
def admin(monkeypatch: pytest.MonkeyPatch) -> FakeAdmin:
    fake = FakeAdmin()
    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(fake.handle))
    return fake


class TTY(io.StringIO):
    """A terminal: the paste must come from getpass. Its stdin is empty, so reading it fails."""

    def isatty(self) -> bool:
        return True


def cli(argv: list[str], stdin: io.StringIO | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=stdin or io.StringIO(), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_login_reads_one_stdin_line_off_a_terminal(admin: FakeAdmin) -> None:
    code, out, err = cli(["login", "music", "--socket", "x"], io.StringIO(PASTED + "\r\nmore\n"))
    assert code == EXIT_OK
    assert out == HEADER + paste_text("one line on stdin") + STORED
    assert err == "UNEXPECTED: admin\n"
    assert admin.requests == [
        ("POST", "/oauth/music/login", {"rebind": False}),
        ("POST", "/oauth/music/complete", {"flow": "flow-0001", "redirect_url": PASTED}),
    ]
    # A login may wait for the token endpoint, and then for a refresh in flight.
    assert admin.timeouts == [76.0, 76.0]
    assert admin_client.LOGIN_TIMEOUT == 20.0 + 41.0 + 15
    assert "fake-code-1" not in out + err
    assert "fake-state-1" not in out + err


def test_login_reads_the_paste_hidden_on_a_terminal(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []

    def hidden(prompt: str) -> str:
        prompts.append(prompt)
        return f"  {PASTED}  "

    monkeypatch.setattr(getpass, "getpass", hidden)
    code, out, err = cli(["login", "music", "--socket", "x"], TTY())
    assert code == EXIT_OK
    assert prompts == ["> "]
    assert out == HEADER + paste_text("input hidden") + STORED
    assert admin.requests[-1] == (
        "POST",
        "/oauth/music/complete",
        {"flow": "flow-0001", "redirect_url": PASTED},
    )
    assert PASTED not in out + err


def test_login_start_prints_the_url_and_the_flow(admin: FakeAdmin) -> None:
    code, out, err = cli(["login", "music", "--start", "--rebind", "--socket", "x"])
    assert code == EXIT_OK
    assert out == HEADER + (
        "\nThen, within 10 minutes, run: zoeymcp login music --flow flow-0001\n"
        "and give it the address your browser was sent to.\n"
    )
    assert err == ""
    assert admin.requests == [("POST", "/oauth/music/login", {"rebind": True})]


def test_login_flow_completes_from_stdin(admin: FakeAdmin) -> None:
    argv = ["login", "music", "--flow", "flow-0001", "--socket", "x"]
    code, out, err = cli(argv, io.StringIO(PASTED))
    assert code == EXIT_OK
    assert out == STORED
    assert err == "UNEXPECTED: admin\n"
    assert admin.requests == [
        ("POST", "/oauth/music/complete", {"flow": "flow-0001", "redirect_url": PASTED})
    ]
    assert admin.timeouts == [76.0]


def test_login_start_and_flow_exclude_each_other() -> None:
    with pytest.raises(SystemExit) as info:
        main(["login", "music", "--start", "--flow", "f"], out=io.StringIO(), err=io.StringIO())
    assert info.value.code == 2


def test_login_shows_a_rebinding(admin: FakeAdmin) -> None:
    old = {"origins": ["https://old.example:443"]}
    started = {**STARTED, "binding_change": {"old": old, "new": BINDING}}
    admin.answers[("POST", "/oauth/music/login")] = (200, started)
    code, out, _ = cli(["login", "music", "--start", "--rebind", "--socket", "x"])
    assert code == EXIT_OK
    assert "Rebinding    was origins https://old.example:443\nScopes       read\n" in out


def test_login_describes_a_confidential_client_without_scopes(admin: FakeAdmin) -> None:
    started = {**STARTED, "client_auth": "post", "rotates": False, "requested_scopes": []}
    admin.answers[("POST", "/oauth/music/login")] = (200, started)
    _, out, _ = cli(["login", "music", "--start", "--socket", "x"])
    assert out.startswith(
        "Credential   music (confidential client, PKCE S256, non-rotating refresh tokens)\n"
    )
    assert "Scopes       (none requested)\n" in out


@pytest.mark.parametrize("stdin", ["", "\n", "   \n"])
def test_login_without_a_paste_cancels_the_flow(admin: FakeAdmin, stdin: str) -> None:
    code, _, err = cli(["login", "music", "--socket", "x"], io.StringIO(stdin))
    assert code == EXIT_FINDINGS
    assert err == "zoeymcp login: no address given\n"
    assert admin.requests[-1] == ("DELETE", "/oauth/flows/flow-0001", None)


@pytest.mark.parametrize("raised", [KeyboardInterrupt, EOFError])
def test_ctrl_c_cancels_the_flow(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch, raised: type[BaseException]
) -> None:
    def interrupted(prompt: str) -> str:
        raise raised

    monkeypatch.setattr(getpass, "getpass", interrupted)
    code, _, err = cli(["login", "music", "--socket", "x"], TTY())
    assert code == EXIT_FINDINGS
    assert err == "zoeymcp login: cancelled\n"
    assert admin.requests[-1] == ("DELETE", "/oauth/flows/flow-0001", None)
    assert len(admin.requests) == 2


@pytest.mark.parametrize("raised", [KeyboardInterrupt, EOFError])
def test_ctrl_c_cancels_a_flow_given_by_id(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch, raised: type[BaseException]
) -> None:
    def interrupted(prompt: str) -> str:
        raise raised

    monkeypatch.setattr(getpass, "getpass", interrupted)
    code, out, err = cli(["login", "music", "--flow", "flow-0001", "--socket", "x"], TTY())
    assert (code, out, err) == (EXIT_FINDINGS, "", "zoeymcp login: cancelled\n")
    assert admin.requests == [("DELETE", "/oauth/flows/flow-0001", None)]


def test_no_paste_cancels_a_flow_given_by_id(admin: FakeAdmin) -> None:
    code, _, err = cli(["login", "music", "--flow", "flow-0001", "--socket", "x"])
    assert (code, err) == (EXIT_FINDINGS, "zoeymcp login: no address given\n")
    assert admin.requests == [("DELETE", "/oauth/flows/flow-0001", None)]


def test_a_failed_cancel_still_reports_the_interruption(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(getpass, "getpass", interrupted)
    admin.answers[("DELETE", "/oauth/flows/flow-0001")] = (500, {"error": "boom"})
    code, _, err = cli(["login", "music", "--socket", "x"], TTY())
    assert (code, err) == (EXIT_FINDINGS, "zoeymcp login: cancelled\n")


def test_a_login_kept_only_in_memory_exits_1(admin: FakeAdmin) -> None:
    completed = {**COMPLETED, "persisted": False, "seed_note": None, "grant_expires_at": None}
    completed |= {"unexpected_scopes": [], "missing_scopes": ["write", "delete"]}
    completed |= {"refresh_expires_at": "2026-10-18T09:00:00Z"}
    admin.answers[("POST", "/oauth/music/complete")] = (200, completed)
    argv = ["login", "music", "--flow", "flow-0001", "--socket", "x"]
    code, out, err = cli(argv, io.StringIO(PASTED))
    assert code == EXIT_FINDINGS
    assert out == (
        "Stored the refresh token for music as oauth.music.live.\n"
        "Granted: read admin\n"
        "The refresh token expires at 2026-10-18T09:00:00Z; run login again before then.\n"
    )
    assert err == f"missing: write delete\nzoeymcp login: {NOT_PERSISTED}\n"
    assert NOT_PERSISTED == (
        "kept in memory, not on disk; fix the state volume; "
        "zoeymcp oauth status shows when it is saved"
    )


def test_a_login_with_no_scopes_says_so(admin: FakeAdmin) -> None:
    completed = {**COMPLETED, "granted_scopes": [], "unexpected_scopes": []}
    admin.answers[("POST", "/oauth/music/complete")] = (200, completed)
    argv = ["login", "music", "--flow", "flow-0001", "--socket", "x"]
    _, out, err = cli(argv, io.StringIO(PASTED))
    assert "Granted: (no scopes)\n" in out
    assert err == ""


def test_login_errors(admin: FakeAdmin) -> None:
    old = {"origins": ["https://old.example:443"]}
    refusal = {
        "error": "the policy binds this grant differently; pass --rebind to accept",
        "reason": "binding_changed",
        "old": old,
        "new": BINDING,
    }
    admin.answers[("POST", "/oauth/music/login")] = (409, refusal)
    code, out, err = cli(["login", "music", "--socket", "x"])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err == (
        "zoeymcp login: the policy binds this grant differently; pass --rebind to accept\n"
        "  old: origins https://old.example:443\n"
        "  new: token endpoint https://accounts.example:443, "
        "access tokens to https://api.example:443\n"
    )
    provider = {
        "error": "the provider refused the authorization: access_denied",
        "reason": "provider_error",
        "provider_error": "access_denied",
        "description": "The user said no",
    }
    admin.answers[("POST", "/oauth/music/complete")] = (400, provider)
    code, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert code == EXIT_FINDINGS
    assert err == (
        "zoeymcp login: the provider refused the authorization: access_denied\n"
        "  the provider says: The user said no\n"
    )
    admin.answers[("POST", "/oauth/music/complete")] = (400, {**provider, "description": None})
    _, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert err == "zoeymcp login: the provider refused the authorization: access_denied\n"
    plain = {"error": "no such login is pending", "reason": "flow_unknown"}
    admin.answers[("POST", "/oauth/music/complete")] = (404, plain)
    _, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert err == "zoeymcp login: no such login is pending\n"


def test_admin_errors_keep_their_answer(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/oauth/music/login")] = (404, {"error": "nope", "reason": "not_oauth"})
    with pytest.raises(admin_client.AdminUnavailable) as caught:
        admin_client.oauth_login("x", "music", rebind=False)
    assert str(caught.value) == "nope"
    assert caught.value.reason == "not_oauth"
    assert caught.value.data == {"error": "nope", "reason": "not_oauth"}
    admin.answers[("POST", "/oauth/music/login")] = (500, {"reason": 7})
    with pytest.raises(admin_client.AdminUnavailable) as caught:
        admin_client.oauth_login("x", "music", rebind=False)
    assert str(caught.value) == "HTTP 500"
    assert caught.value.reason is None
    assert admin_client.AdminUnavailable("x").data == {}


def test_client_credentials_login_is_a_test_fetch(admin: FakeAdmin) -> None:
    fetched = {**COMPLETED, "slot": "cc:music", "granted_scopes": ["read"]}
    fetched |= {"unexpected_scopes": [], "missing_scopes": ["write"], "access_expires_in": 600}
    admin.answers[("POST", "/oauth/music/login")] = (200, fetched)
    code, out, err = cli(["login", "music", "--socket", "x"])
    assert code == EXIT_OK
    assert out == (
        "The client credentials of music work: the token endpoint issued an access token "
        "for 600 s. Nothing was stored.\nGranted: read\n"
    )
    assert err == "missing: write\n"
    assert len(admin.requests) == 1


def test_read_redirect_url() -> None:
    assert admin_client.read_redirect_url(io.StringIO(" x \r\nsecond\n"), "> ") == "x"
    with pytest.raises(admin_client.AdminUnavailable, match="no address given"):
        admin_client.read_redirect_url(io.StringIO(""), "> ")


def test_the_admin_timeout_defaults_to_10_s(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/oauth")] = (200, {"credentials": []})
    admin.answers[("POST", "/oauth/music/reset")] = (200, {"credential": "music", "reset": True})
    admin_client.oauth_status("x")
    admin_client.oauth_reset("x", "music")
    admin_client.oauth_cancel("x", "flow-0001")
    assert admin.timeouts == [10.0, 10.0, 10.0]
    assert [r[:2] for r in admin.requests] == [
        ("GET", "/oauth"),
        ("POST", "/oauth/music/reset"),
        ("DELETE", "/oauth/flows/flow-0001"),
    ]


def test_path_segments_are_quoted(admin: FakeAdmin) -> None:
    admin.answers[("DELETE", "/oauth/flows/a%2Fb")] = (200, {"cancelled": False})
    admin_client.oauth_cancel("x", "a/b")
    assert admin.requests == [("DELETE", "/oauth/flows/a%2Fb", None)]


STATUS: dict[str, Any] = {
    "credential": "music",
    "grant": "refresh_token",
    "slot": "oauth.music.live",
    "state": "terminal",
    "refreshing": True,
    "code": "oauth_reconsent_needed",
    "error": "invalid_grant",
    "failures": 1,
    "retry_in": 90.5,
    "access_expires_in": 1500.0,
    "persisted": False,
    "meta": None,
    "upstream": {"code": "upstream_insufficient_scope", "at": "2026-10-17T09:01:00Z"},
    "hint": "run: zoeymcp login music",
    "last_ok_ago": 7200,
    "reconsent_due": "2026-10-20T09:00:00Z",
    "scopes": {"unexpected": ["admin", "root"], "missing": ["read"]},
}
QUIET: dict[str, Any] = {
    **STATUS,
    "state": "ok",
    "refreshing": False,
    "code": None,
    "retry_in": None,
    "access_expires_in": None,
    "persisted": True,
    "upstream": None,
    "hint": None,
    "last_ok_ago": None,
    "reconsent_due": None,
    "scopes": None,
}


def test_format_status() -> None:
    assert format_status(STATUS) == [
        "music: terminal oauth_reconsent_needed (refreshing)",
        "  hint: run: zoeymcp login music",
        "  retry in 90 s",
        "  access token expires in 25 min",
        "  last success 2 h ago",
        "  WARNING re-consent due by 2026-10-20T09:00:00Z",
        "  UNEXPECTED scopes: admin root",
        "  missing scopes: read",
        "  WARNING an upstream said upstream_insufficient_scope at 2026-10-17T09:01:00Z",
        "  degraded (not persisted): the store can't be written; check the state volume",
    ]
    assert format_status(QUIET) == ["music: ok"]
    assert format_status({**QUIET, "scopes": {"unexpected": [], "missing": []}}) == ["music: ok"]
    assert format_status({**QUIET, "last_ok_ago": 0}) == ["music: ok", "  last success 0 s ago"]
    assert format_status({**QUIET, "retry_in": 0.0, "access_expires_in": 0.0}) == [
        "music: ok",
        "  retry in 0 s",
        "  access token expires in 0 s",
    ]


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0, "0 s"),
        (119.9, "119 s"),
        (120, "2 min"),
        (7199, "119 min"),
        (7200, "2 h"),
        (172799, "47 h"),
        (172800, "2 days"),
    ],
)
def test_duration(seconds: float, text: str) -> None:
    assert duration(seconds) == text


def test_oauth_status_lists_or_filters(admin: FakeAdmin) -> None:
    other = {**QUIET, "credential": "files"}
    admin.answers[("GET", "/oauth")] = (200, {"credentials": [STATUS, other]})
    code, out, err = cli(["oauth", "status", "--socket", "x"])
    assert (code, err) == (EXIT_OK, "")
    assert out == "\n".join([*format_status(STATUS), "files: ok"]) + "\n"
    code, out, _ = cli(["oauth", "status", "files", "--socket", "x"])
    assert (code, out) == (EXIT_OK, "files: ok\n")
    code, out, err = cli(["oauth", "status", "nope", "--socket", "x"])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err == "zoeymcp oauth status: no oauth2 credential named 'nope'\n"
    admin.answers[("GET", "/oauth")] = (200, {"credentials": []})
    assert cli(["oauth", "status", "--socket", "x"]) == (EXIT_OK, "no oauth2 credentials\n", "")


def test_oauth_reset(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/oauth/music/reset")] = (200, {"credential": "music", "reset": True})
    assert cli(["oauth", "reset", "music", "--socket", "x"]) == (
        EXIT_OK,
        "reset music: the next request that needs a token tries once\n",
        "",
    )
    refusal = {"error": "no oauth2 credential named 'nope'", "reason": "not_oauth"}
    admin.answers[("POST", "/oauth/nope/reset")] = (404, refusal)
    assert cli(["oauth", "reset", "nope", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp oauth reset: no oauth2 credential named 'nope'\n",
    )
    admin.answers[("GET", "/oauth")] = (503, {"error": "OAuth needs the vault's token manager"})
    assert cli(["oauth", "status", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp oauth status: OAuth needs the vault's token manager\n",
    )
