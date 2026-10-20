from __future__ import annotations

import getpass
import inspect
import io
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

import httpx
import pytest

from zoeymcp.cli import admin_client
from zoeymcp.cli import main as main_module
from zoeymcp.cli.main import (
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_UNREADABLE,
    GATEWAY_ENVIRONMENT,
    NOT_PERSISTED,
    duration,
    exec_gateway_environment,
    format_status,
    gateway_command,
    health_action,
    main,
    new_client_token,
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


def test_client_token_prints_a_token_and_its_hash() -> None:
    import hashlib

    out, err = io.StringIO(), io.StringIO()
    assert main(["client-token"], out=out, err=err) == EXIT_OK
    lines = dict(line.split(": ", 1) for line in out.getvalue().splitlines())
    assert list(lines) == ["client_token", "token_sha256"]
    token = lines["client_token"]
    assert re.fullmatch(r"zgc1-[A-Za-z0-9_-]{43}", token)
    assert len(token) == 48
    assert lines["token_sha256"] == "sha256:" + hashlib.sha256(token.encode()).hexdigest()
    assert token not in err.getvalue()
    assert "token_sha256" in err.getvalue()
    assert run(["client-token"])[1] != out.getvalue()


def test_a_client_token_passes_the_policy_schema(example_text: str) -> None:
    out = io.StringIO()
    main(["client-token"], out=out, err=io.StringIO())
    lines = dict(line.split(": ", 1) for line in out.getvalue().splitlines())
    pattern = r"token_sha256: \S+"
    hashed, count = re.subn(pattern, f"token_sha256: {lines['token_sha256']}", example_text)
    assert count == 1
    assert f"token_sha256: {lines['token_sha256']}" in hashed
    assert run(["check", "--config", "-"], stdin=hashed)[0] == EXIT_OK
    literal, count = re.subn(pattern, f"token: {lines['client_token']}", example_text)
    assert count == 1
    code, report = run(["check", "--config", "-"], stdin=literal)
    assert code == EXIT_OK
    assert "gateway.clients.agent1.token: anyone who reads the policy" in report
    assert "easy to guess" not in report


def test_new_client_tokens_are_random(monkeypatch: pytest.MonkeyPatch) -> None:
    import secrets

    monkeypatch.setattr(secrets, "token_bytes", lambda n: bytes(range(n)))
    assert new_client_token() == "zgc1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


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


def test_login_says_where_a_callback_address_lands(admin: FakeAdmin) -> None:
    """M5 H.6, review finding R16: a credential registered with the portal's callback address
    sends the browser there, and the callback takes no command-line login, so the CLI says to
    paste the address from that tab. ``callback`` is null on every CLI start."""
    callback = "http://localhost:8081/oauth/callback/music"
    started = {**STARTED, "redirect_uri": callback, "callback": None, "callback_address": True}
    admin.answers[("POST", "/oauth/music/login")] = (200, started)
    code, out, _ = cli(["login", "music", "--socket", "x"], io.StringIO(PASTED + "\n"))
    assert code == EXIT_OK
    assert (
        out
        == HEADER
        + (
            "\nYour browser will land on the portal's callback, which doesn't take a command-line "
            "login:\ncopy the full address from that tab's address bar and paste it here (one line "
            "on stdin, 10 minutes):\n"
        )
        + STORED
    )
    # Without the key (an older vault) or with it false, the loopback text as before.
    for value in (False, None):
        started = {**STARTED, "callback": None, "callback_address": value}
        admin.answers[("POST", "/oauth/music/login")] = (200, started)
        _, out, _ = cli(["login", "music", "--socket", "x"], io.StringIO(PASTED + "\n"))
        assert out == HEADER + paste_text("one line on stdin") + STORED


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
        "\nThen, within 10 minutes, run: zoeymcp login music --flow=flow-0001\n"
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


def test_a_flow_id_may_start_with_a_dash(admin: FakeAdmin) -> None:
    """Flow IDs are URL-safe base64, so one in 64 starts with a dash. The command --start
    prints still parses."""
    admin.answers[("POST", "/oauth/music/login")] = (200, {**STARTED, "flow": "-flow-0001"})
    code, out, _ = cli(["login", "music", "--start", "--socket", "x"])
    assert code == EXIT_OK
    [printed] = re.findall(r"run: zoeymcp (login .*)$", out, re.MULTILINE)
    code, out, _ = cli([*shlex.split(printed), "--socket", "x"], io.StringIO(PASTED))
    assert (code, out) == (EXIT_OK, STORED)
    assert admin.requests[-1] == (
        "POST",
        "/oauth/music/complete",
        {"flow": "-flow-0001", "redirect_url": PASTED},
    )


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


@pytest.mark.parametrize(
    ("replaced", "first"),
    [("portal", "Replaced a login pending in the portal.\n"), ("cli", ""), (None, "")],
)
def test_login_says_it_replaced_a_portal_login(
    admin: FakeAdmin, replaced: str | None, first: str
) -> None:
    admin.answers[("POST", "/oauth/music/login")] = (200, {**STARTED, "replaced": replaced})
    code, out, err = cli(["login", "music", "--start", "--socket", "x"])
    assert code == EXIT_OK
    assert err == ""
    assert out.startswith(first + HEADER)


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


def test_secret_set_and_delete_wait_for_a_refresh_in_flight(admin: FakeAdmin) -> None:
    admin.answers[("PUT", "/secrets/music-secret")] = (200, {"name": "music-secret"})
    admin.answers[("DELETE", "/secrets/music-secret")] = (200, {"deleted": True})
    admin_client.secret_set("x", "music-secret", "value", None)
    admin_client.secret_delete("x", "music-secret")
    # The vault may wait for a refresh of a credential that uses the secret.
    assert admin.timeouts == [56.0, 56.0]
    assert admin_client.SECRET_TIMEOUT == 41.0 + 15


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
    "last_failure": {"code": None, "at": "2026-10-16T09:00:00Z"},
    "idle": {"days": 171, "limit": 180},
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
    "last_failure": None,
    "idle": None,
}


# --- gateway-key -------------------------------------------------------------------------------

GATEWAY_KEY = "zgw1-fake-gateway-key-0002"


def gateway_answer(previous: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    return {"generation": 2, "key": GATEWAY_KEY, "previous": previous, **extra}


def test_gateway_key_prints_the_key(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/gateway-key")] = (200, gateway_answer(None))
    code, out, err = cli(["gateway-key", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_GATEWAY_KEY={GATEWAY_KEY}\n"
    assert err == "Generation 2.\n"
    assert admin.requests == [("GET", "/gateway-key", None)]
    assert admin.timeouts == [10.0]


@pytest.mark.parametrize(
    ("generation", "master_key", "line"),
    [
        (1, "current", "rotation pending: generation 1 accepted until 2026-10-05T21:14:27Z\n"),
        (
            2,
            "previous",
            "rotation pending: generation 2 (previous master key) accepted until "
            "2026-10-05T21:14:27Z\n",
        ),
        (
            1,
            "previous",
            "rotation pending: generations 1 and 2 (previous master key) accepted until "
            "2026-10-05T21:14:27Z\n",
        ),
    ],
)
def test_gateway_key_shows_a_pending_rotation(
    admin: FakeAdmin, generation: int, master_key: str, line: str
) -> None:
    previous = {"generation": generation, "until": 1_791_234_867, "master_key": master_key}
    admin.answers[("GET", "/gateway-key")] = (200, gateway_answer(previous))
    code, out, err = cli(["gateway-key", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_GATEWAY_KEY={GATEWAY_KEY}\n"
    assert err == "Generation 2.\n" + line


@pytest.mark.parametrize(
    ("retired", "line"),
    [
        (1, "Retired generation 1: only this key is accepted now.\n"),
        (None, "No previous key was accepted.\n"),
    ],
)
def test_gateway_key_retire_previous(admin: FakeAdmin, retired: int | None, line: str) -> None:
    path = "/gateway-key/retire-previous"
    admin.answers[("POST", path)] = (200, gateway_answer(None, retired=retired))
    code, out, err = cli(["gateway-key", "--retire-previous", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_GATEWAY_KEY={GATEWAY_KEY}\n"
    assert err == "Generation 2.\n" + line
    assert admin.requests == [("POST", path, None)]
    assert admin.timeouts == [10.0]


def test_gateway_key_retire_previous_not_written(admin: FakeAdmin) -> None:
    error = {"error": "kept in memory, not written to disk; check the state volume"}
    admin.answers[("POST", "/gateway-key/retire-previous")] = (500, error)
    code, out, err = cli(["gateway-key", "--retire-previous", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out == ""
    assert err == (
        "zoeymcp gateway-key: kept in memory, not written to disk; check the state volume\n"
    )


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
        "  WARNING last attempt failed: no code at 2026-10-16T09:00:00Z (from stored metadata)",
        "  WARNING unused for 171 days; the provider drops unused grants after 180 "
        "(from stored metadata)",
        "  degraded (not persisted): the store can't be written; check the state volume",
    ]
    assert format_status(QUIET) == ["music: ok"]
    failed = {**QUIET, "last_failure": {"code": "oauth_unavailable", "at": "2026-10-16T09:00:00Z"}}
    assert format_status(failed) == [
        "music: ok",
        "  WARNING last attempt failed: oauth_unavailable at 2026-10-16T09:00:00Z "
        "(from stored metadata)",
    ]
    # An older vault's answer has neither.
    older = {k: v for k, v in QUIET.items() if k not in ("last_failure", "idle")}
    assert format_status(older) == ["music: ok"]
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


# --- health ------------------------------------------------------------------------------------


def health_report(**changes: Any) -> dict[str, Any]:
    """What the vault's GET /health answers for a small deployment, from :mod:`health` itself."""
    from zoeymcp.vault.health import Inputs, Sends, assess
    from zoeymcp.vault.store import origin_binding

    from .test_health import (
        API,
        MAIL,
        MAIL_BINDING,
        OTHER,
        SPOTIFY_ENTRIES,
        entry,
        header,
        make_policy,
        spotify,
        status,
    )

    policy = make_policy({"notes": header(), "music": spotify()}, connectors={"mail": MAIL})
    entries = [
        entry("notes-key", origin_binding([API, OTHER])),
        *SPOTIFY_ENTRIES[:2],
        entry("mail-pass", MAIL_BINDING),
        entry("old-key", origin_binding([API])),
    ]
    failure = {"code": "oauth_unavailable", "at": "2026-10-16T09:00:00Z"}
    last = {"state": "sent", "at": "2026-10-17T08:00:00Z", "smtp_code": 250}
    inputs = Inputs(
        policy,
        entries,
        frozenset({"MAIL_USER"}),
        [status(last_failure=failure)],
        {"mail": Sends(17, 0, last)},
    )
    return {**assess(inputs), **changes}


HEALTH_LINES = [
    "notes (header): info",
    "  info    binding_wider: store:notes-key is bound to more than the policy uses; it works",
    "          run: zoeymcp secret set notes-key",
    "music (oauth2): error",
    "  error   missing: store:music-refresh has no entry",
    "          run: zoeymcp login music",
    "  warning last_failure: last attempt failed: oauth_unavailable at 2026-10-16T09:00:00Z "
    "(from stored metadata)",
    "          run: zoeymcp oauth reset music",
    "connector mail: warning (17 of 20 sends in 24 h)",
    "  warning near_limit: 17 of 20 sends in the last 24 hours",
    "          wait: it clears with time",
    "store: info (5 entries)",
    "  info    unreferenced: nothing in the policy uses store:old-key",
    "          run: zoeymcp secret delete old-key",
    "health: FAILED (1 error(s), 2 warning(s), 2 info)",
]


def test_health_text(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/health")] = (200, health_report())
    text = "".join(f"{line}\n" for line in HEALTH_LINES)
    assert cli(["health", "--socket", "x"]) == (EXIT_FINDINGS, text, "")
    assert admin.requests == [("GET", "/health", None)]
    assert admin.timeouts == [10.0]


def test_health_json(admin: FakeAdmin) -> None:
    report = health_report()
    admin.answers[("GET", "/health")] = (200, report)
    code, out, err = cli(["health", "--json", "--socket", "x"])
    assert (code, err) == (EXIT_FINDINGS, "")
    assert out == json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


@pytest.mark.parametrize(
    ("counts", "plain", "strict"),
    [
        ({"error": 0, "warning": 0, "info": 3}, EXIT_OK, EXIT_OK),
        ({"error": 0, "warning": 1, "info": 0}, EXIT_OK, EXIT_FINDINGS),
        ({"error": 1, "warning": 0, "info": 0}, EXIT_FINDINGS, EXIT_FINDINGS),
    ],
)
def test_health_exit_codes(
    admin: FakeAdmin, counts: dict[str, int], plain: int, strict: int
) -> None:
    empty = {"entries": 0, "level": "ok", "findings": []}
    report = {"summary": counts, "credentials": [], "connectors": [], "store": empty}
    admin.answers[("GET", "/health")] = (200, report)
    verdict = "ok" if plain == EXIT_OK else "FAILED"
    tail = f"({counts['error']} error(s), {counts['warning']} warning(s), {counts['info']} info)"
    assert cli(["health", "--socket", "x"]) == (
        plain,
        f"store: ok (0 entries)\nhealth: {verdict} {tail}\n",
        "",
    )
    assert cli(["health", "--strict", "--socket", "x"])[0] == strict
    assert cli(["health", "--strict", "--json", "--socket", "x"])[0] == strict


def test_health_when_the_vault_cant_be_asked(admin: FakeAdmin, tmp_path: Path) -> None:
    admin.answers[("GET", "/health")] = (503, {"error": "starting"})
    assert cli(["health", "--socket", "x"]) == (EXIT_UNREADABLE, "", "zoeymcp health: starting\n")


def test_health_with_no_vault_at_all(tmp_path: Path) -> None:
    code, out, err = cli(["health", "--socket", str(tmp_path / "admin.sock")])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err.startswith("zoeymcp health: can't reach the vault's admin socket at ")


@pytest.mark.parametrize(
    ("action", "text"),
    [
        (None, None),
        ({"kind": "connect", "credential": "music"}, "run: zoeymcp login music"),
        ({"kind": "reset", "credential": "music"}, "run: zoeymcp oauth reset music"),
        (
            {"kind": "set_secret", "credential": "music", "ref": "store:music-id"},
            "run: zoeymcp secret set music-id",
        ),
        (
            {"kind": "restart", "connector": "mail", "ref": "env:MAIL_USER"},
            "set env MAIL_USER and restart the vault",
        ),
        ({"kind": "delete_secret", "secret": "old"}, "run: zoeymcp secret delete old"),
        ({"kind": "fix_policy", "credential": "music"}, "fix the policy"),
        ({"kind": "wait", "connector": "mail"}, "wait: it clears with time"),
        ({"kind": "check_volume"}, "check the state volume"),
        (
            {"kind": "check_mailbox", "connector": "mail"},
            "check the mailbox for the sends with an unknown outcome",
        ),
        (
            {"kind": "add_passkey"},
            "run: zoeymcp setup-code, and enrol a second passkey with it",
        ),
        (
            {"kind": "review_passkeys"},
            "run: zoeymcp passkeys, and remove any you don't recognize",
        ),
        ({"kind": "reset_passkeys"}, "run: zoeymcp setup-code --reset"),
        # A newer vault's action: its kind.
        ({"kind": "enrol_elsewhere"}, "enrol_elsewhere"),
    ],
)
def test_health_actions_in_the_clis_words(action: dict[str, str] | None, text: str | None) -> None:
    assert health_action(action) == text


def test_health_shows_hidden_characters(admin: FakeAdmin) -> None:
    """Store entry names and meta are shown as text, never as terminal controls."""
    finding = {
        "code": "unreferenced",
        "level": "info",
        "advisory": False,
        "text": "nothing in the policy uses store:x" + chr(27) + "[2J",
        "action": None,
    }
    store = {"entries": 1, "level": "info", "findings": [finding]}
    report = {
        "summary": {"error": 0, "warning": 0, "info": 1},
        "credentials": [],
        "connectors": [],
        "store": store,
    }
    admin.answers[("GET", "/health")] = (200, report)
    code, out, _ = cli(["health", "--socket", "x"])
    assert code == EXIT_OK
    assert chr(27) not in out
    assert (
        out.splitlines()[1]
        == "  info    unreferenced: nothing in the policy uses store:x[U+001B][2J"
    )


# --- the gateway's environment -----------------------------------------------------------------


def _environment(tmp_path: Path) -> Path:
    environment = tmp_path / "zoeymcp-gateway"
    (environment / "bin").mkdir(parents=True)
    (environment / "bin" / "python").write_bytes(b"")
    return environment


def test_gateway_command_moves_into_the_gateway_environment(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    command = gateway_command(
        ["gateway", "--listen", "0.0.0.0:8090"],
        environment=environment,
        prefix=str(tmp_path / "zoeymcp"),
    )
    python = str(environment / "bin" / "python")
    assert command == [python, "-I", "-m", "zoeymcp", "gateway", "--listen", "0.0.0.0:8090"]


def test_gateway_command_runs_here_inside_the_gateway_environment(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    assert gateway_command(["gateway"], environment=environment, prefix=str(environment)) is None
    # The same directory, spelled another way.
    other_spelling = str(environment / "bin" / "..")
    assert gateway_command(["gateway"], environment=environment, prefix=other_spelling) is None
    (tmp_path / "x").mkdir()
    other_environment = tmp_path / "x" / ".." / "zoeymcp-gateway"
    assert (
        gateway_command(["gateway"], environment=other_environment, prefix=str(environment)) is None
    )


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_gateway_command_runs_here_through_a_symlink(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(environment)
    assert gateway_command(["gateway"], environment=link, prefix=str(environment)) is None
    assert gateway_command(["gateway"], environment=environment, prefix=str(link)) is None


def test_gateway_command_runs_here_without_the_environment(tmp_path: Path) -> None:
    # A development checkout has no second environment.
    absent = tmp_path / "absent"
    assert gateway_command(["gateway"], environment=absent, prefix=str(tmp_path)) is None
    # A directory where the interpreter should be isn't one.
    broken = tmp_path / "broken"
    (broken / "bin" / "python").mkdir(parents=True)
    assert gateway_command(["gateway"], environment=broken, prefix=str(tmp_path)) is None


def test_gateway_command_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert Path("/opt/zoeymcp-gateway") == GATEWAY_ENVIRONMENT
    parameters = inspect.signature(gateway_command).parameters
    assert parameters["environment"].default == Path("/opt/zoeymcp-gateway")
    assert parameters["prefix"].default is None
    # Without a prefix, this interpreter's is used.
    environment = _environment(tmp_path)
    monkeypatch.setattr(sys, "prefix", str(environment))
    assert gateway_command(["gateway"], environment=environment) is None
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert gateway_command(["gateway"], environment=environment) is not None


def test_exec_gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(os, "execv", lambda path, args: calls.append((path, args)))
    monkeypatch.setattr(
        main_module, "gateway_command", lambda argv: ["/env/bin/python", "-m", "zoeymcp", *argv]
    )
    exec_gateway_environment(["gateway", "--state", "/state-gateway"])
    assert calls == [
        (
            "/env/bin/python",
            ["/env/bin/python", "-m", "zoeymcp", "gateway", "--state", "/state-gateway"],
        )
    ]
    calls.clear()
    monkeypatch.setattr(main_module, "gateway_command", lambda argv: None)
    exec_gateway_environment(["gateway"])
    assert calls == []


class _Moved(Exception):
    pass


def test_main_moves_only_the_gateway_command(monkeypatch: pytest.MonkeyPatch) -> None:
    moved: list[list[str]] = []

    def move(argv: list[str]) -> None:
        moved.append(list(argv))
        raise _Moved

    monkeypatch.setattr(main_module, "exec_gateway_environment", move)
    with pytest.raises(_Moved):
        main(["gateway", "--listen", "0.0.0.0:8090"])
    assert moved == [["gateway", "--listen", "0.0.0.0:8090"]]
    monkeypatch.setattr(sys, "argv", ["zoeymcp", "gateway"])
    with pytest.raises(_Moved):
        main()
    assert moved[-1] == ["gateway"]
    moved.clear()
    # Other commands run here, even with "gateway" as an argument.
    assert run(["keygen"])[0] == EXIT_OK
    assert run(["check", "--config", "gateway"])[0] == EXIT_UNREADABLE
    with pytest.raises(SystemExit):
        main([])
    assert moved == []


# --- ledger --vault (M5 design J.4, J.5) ---------------------------------------------------------

HEAD = "sha256:" + "a" * 64
ARCHIVED = {
    "name": "archive-1767276000000",
    "first_seq": 0,
    "head_seq": 9,
    "head_hash": HEAD,
    "received_ms": 1_767_276_000_000,
    "size": 5450,
}
CALL_ROW = {
    "kind": "call",
    "seq": 12,
    "ref": "3f9c0000000000aa",
    "at": "2026-10-19T09:12:03Z",
    "client": "agent1",
    "server": "mail",
    "tool": "send" + chr(27) + "[2J",
    "era": "modern",
    "decision": "accept",
    "waited_ms": 8123,
    "outcome": "ok",
    "detail": "sent",
    "writes": 1,
    "writes_sent": 1,
    "writes_unknown": 0,
    "writers": {"asked": "gateway"},
    "not_in_policy": ["client"],
    "journal": [
        {
            "key": "3f9c0000000000aa.1",
            "state": "sent",
            "smtp_code": 250,
            "at": "2026-10-19T09:12:05Z",
        }
    ],
}
LEDGER_ROW = {
    "kind": "recovered",
    "seq": 11,
    "at": "2026-10-19T09:00:00Z",
    "writer": "gateway",
    "fields": {"abandoned": 1, "not_sent": 0, "unknown": 0},
}
PAGE = {
    "state": {
        "state": "ok",
        "head_seq": 12,
        "head_hash": HEAD,
        "start_seq": 0,
        "reported_ago": 12,
        "broken_at": None,
    },
    "rows": [CALL_ROW, LEDGER_ROW],
    "orphans": [
        {
            "connector": "mail",
            "key": "a1b2000000000000.1",
            "state": "sent",
            "at": "2026-10-19T08:01:00Z",
            "flag": "no_ledger_record",
        }
    ],
    "next": 11,
    "refused": None,
    "archives": [{**ARCHIVED, "dropped": False}],
}
PAGE_LINES = [
    f"copy: ok, head seq 12 ({HEAD}), chain from seq 0, head moved 12 s ago",
    "2026-10-19T09:00:00Z ledger recovered abandoned=1 not_sent=0 unknown=0",
    "2026-10-19T09:12:03Z 3f9c0000000000aa agent1 mail/send[U+001B][2J modern accept ok (sent)",
    "  not in the current policy: client",
    "  send 3f9c0000000000aa.1 sent 250 2026-10-19T09:12:05Z",
    "orphan send a1b2000000000000.1 on mail: sent at 2026-10-19T08:01:00Z (no_ledger_record)",
    f"archived archive-1767276000000: seq 0-9 (head {HEAD}), last received "
    "2026-01-01 14:00:00Z, 5450 bytes",
    "older rows: zoeymcp ledger --vault --before 11",
    "each row is as reported by the gateway",
]


def test_ledger_vault_reads_the_copy(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/ledger/reported")] = (200, PAGE)
    code, out, err = cli(["ledger", "--vault", "--socket", "x"])
    assert (code, err) == (EXIT_OK, "")
    assert out.splitlines() == PAGE_LINES
    admin.answers[("GET", "/ledger/reported?before=11")] = (200, PAGE)
    assert cli(["ledger", "--vault", "--before", "11", "--socket", "x"])[0] == EXIT_OK
    assert [path for _, path, _ in admin.requests] == [
        "/ledger/reported",
        "/ledger/reported?before=11",
    ]


def test_ledger_vault_as_json(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/ledger/reported")] = (200, PAGE)
    code, out, _ = cli(["ledger", "--vault", "--format", "json", "--socket", "x"])
    assert code == EXIT_OK
    assert json.loads(out) == PAGE


def test_ledger_vault_says_what_is_wrong(admin: FakeAdmin) -> None:
    refused = {"reason": "fork", "held_seq": 9, "offered_seq": 3, "at": 1_767_276_000_000}
    state = {**PAGE["state"], "state": "fork", "head_seq": None, "broken_at": 4}  # type: ignore[dict-item]
    page = {**PAGE, "state": state, "rows": [], "orphans": [], "next": None}
    page |= {"refused": refused, "archives": [{**ARCHIVED, "dropped": True}]}
    admin.answers[("GET", "/ledger/reported")] = (200, page)
    code, out, _ = cli(["ledger", "--vault", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out.splitlines() == [
        "copy: fork, nothing reported yet",
        "broken: the copy's files stop chaining at seq 4",
        "refused: fork at seq 3 (held seq 9, 2026-01-01 14:00:00Z); after deciding why, run: "
        "zoeymcp ledger --vault --restart-chain",
        f"archived archive-1767276000000: seq 0-9 (head {HEAD}), last received "
        "2026-01-01 14:00:00Z, 5450 bytes, files dropped",
    ]


def test_ledger_vault_when_the_vault_cant_be_asked(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/ledger/reported")] = (503, {"error": "no copy", "reason": "x"})
    assert cli(["ledger", "--vault", "--socket", "x"]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp ledger: no copy\n",
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["--vault", "--verify"],
        ["--vault", "--since", "1d"],
        ["--vault", "--client", "agent1"],
        ["--vault", "check", "ref", "file"],
        ["--restart-chain"],
        ["--before", "3"],
    ],
)
def test_ledger_vault_flags_go_together(admin: FakeAdmin, argv: list[str]) -> None:
    code, out, err = cli(["ledger", *argv, "--socket", "x"])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err.startswith("zoeymcp ledger: ")
    assert admin.requests == []


PLAN = {
    "state": "fork",
    "refused": {"reason": "fork", "held_seq": 9, "offered_seq": 3, "at": 1_767_276_000_000},
    "archive": {**ARCHIVED, "name": None},
    "drop": [{**ARCHIVED, "name": "archive-1767000000000"}],
}
PLAN_LINES = [
    "the copy is fork: fork at seq 3 (held seq 9, 2026-01-01 14:00:00Z)",
    f"archive: seq 0-9 (head {HEAD}), last received 2026-01-01 14:00:00Z, 5450 bytes",
    f"delete archive-1767000000000: seq 0-9 (head {HEAD}), last received 2026-01-01 14:00:00Z, "
    "5450 bytes; its head stays as an anchor",
    "the next report from the gateway then starts a new chain, on trust",
]
RESTART = "/ledger/reported/restart"


def test_restart_chain_shows_the_plan_and_asks(admin: FakeAdmin) -> None:
    admin.answers[("POST", RESTART)] = (200, {"plan": PLAN})
    code, out, err = cli(
        ["ledger", "--vault", "--restart-chain", "--socket", "x"], io.StringIO("n\n")
    )
    assert (code, err) == (EXIT_FINDINGS, "zoeymcp ledger: not restarted\n")
    assert out == "".join(f"{line}\n" for line in PLAN_LINES) + "Restart the chain? [y/N] "
    assert admin.requests == [("POST", RESTART, {"dry_run": True})]


def test_restart_chain_runs_exactly_the_plan_shown(admin: FakeAdmin) -> None:
    done = {"restarted": {**PLAN, "archive": ARCHIVED}, "head": {}}
    answers = iter([(200, {"plan": PLAN}), (200, done)])
    admin.answers = InTurn(answers)
    code, out, err = cli(
        ["ledger", "--vault", "--restart-chain", "--socket", "x"], io.StringIO("yes\n")
    )
    assert (code, err) == (EXIT_OK, "")
    assert out.endswith(
        "restarted: archived as archive-1767276000000; the next report starts a new chain\n"
    )
    assert admin.requests[1] == ("POST", RESTART, {"plan": PLAN})


def test_restart_chain_refuses_a_plan_that_changed(admin: FakeAdmin) -> None:
    changed = {"error": "changed", "reason": "changed", "plan": PLAN}
    admin.answers = InTurn(iter([(200, {"plan": PLAN}), (409, changed)]))
    code, _, err = cli(
        ["ledger", "--vault", "--restart-chain", "--socket", "x"], io.StringIO("y\n")
    )
    assert code == EXIT_FINDINGS
    assert err == "zoeymcp ledger: the copy changed since this plan; nothing was done; run again\n"


def test_restart_chain_when_nothing_is_refused(admin: FakeAdmin) -> None:
    refused = {"error": "the copy takes reports", "reason": "not_restartable"}
    admin.answers[("POST", RESTART)] = (409, refused)
    code, out, err = cli(["ledger", "--vault", "--restart-chain", "--socket", "x"])
    assert (code, out, err) == (EXIT_UNREADABLE, "", "zoeymcp ledger: the copy takes reports\n")


class InTurn(dict[tuple[str, str], tuple[int, dict[str, Any]]]):
    """Answers taken in turn, whatever the method and path."""

    def __init__(self, answers: Any) -> None:
        super().__init__()
        self.answers = answers

    def __getitem__(self, key: tuple[str, str]) -> tuple[int, dict[str, Any]]:
        answer: tuple[int, dict[str, Any]] = next(self.answers)
        return answer


def test_health_shows_the_ledger_copy(admin: FakeAdmin) -> None:
    finding = {
        "code": "ledger_copy_refused",
        "level": "error",
        "advisory": False,
        "text": "a fork",
        "action": {"kind": "read_ledger"},
    }
    empty = {"entries": 0, "level": "ok", "findings": []}
    copy = {"state": "fork", "head_seq": 9, "reported_ago": 3, "broken_at": None}
    report = {
        "summary": {"error": 1, "warning": 0, "info": 0},
        "credentials": [],
        "connectors": [],
        "store": empty,
        "ledger_copy": {**copy, "level": "error", "findings": [finding]},
    }
    admin.answers[("GET", "/health")] = (200, report)
    code, out, _ = cli(["health", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out.splitlines()[1:4] == [
        "ledger copy: error (fork, head seq 9)",
        "  error   ledger_copy_refused: a fork",
        "          run: zoeymcp ledger --vault",
    ]
    assert health_action({"kind": "check_gateway"}) == (
        "check that the gateway runs and reaches the vault"
    )


@pytest.mark.parametrize(
    ("state", "lines"),
    [
        (
            {"count": 1},
            [
                "passkeys: info (1 enrolled)",
                "  info    passkey_single: only one passkey is enrolled: add a second, so losing "
                "one doesn't lock you out",
                "          run: zoeymcp setup-code, and enrol a second passkey with it",
            ],
        ),
        (
            {"count": 2, "regressed_ago": 0.0},
            [
                "passkeys: warning (2 enrolled)",
                "  warning passkey_counter: a passkey's signature counter went back in the last "
                "30 days: the authenticator may have been copied",
                "          run: zoeymcp passkeys, and remove any you don't recognize",
            ],
        ),
        (
            {"count": 0, "unavailable": True},
            [
                "passkeys: error (can't be verified)",
                "  error   passkeys_unavailable: the passkey file can't be verified (edited, or "
                "written under another master key); portal login is off",
                "          run: zoeymcp setup-code --reset",
            ],
        ),
        ({"count": 3}, ["passkeys: ok (3 enrolled)"]),
    ],
)
def test_health_shows_the_passkeys(
    admin: FakeAdmin, state: dict[str, Any], lines: list[str]
) -> None:
    from zoeymcp.vault.health import PasskeyState, _passkeys

    empty = {"entries": 0, "level": "ok", "findings": []}
    report = {
        "summary": {"error": 0, "warning": 0, "info": 0},
        "credentials": [],
        "connectors": [],
        "store": empty,
        "passkeys": _passkeys(PasskeyState(**state)),
    }
    admin.answers[("GET", "/health")] = (200, report)
    _, out, _ = cli(["health", "--socket", "x"])
    assert out.splitlines()[1:-1] == lines


# --- setup-code, passkeys and sessions (M5 design E) -------------------------------------------

ORIGINS = ["http://localhost:8081", "https://zoeymcp.tailnet.example"]
SETUP_CODE = "AAAQEA-YEAUDA-OCAJBI-FQYDIO"
ISSUED: dict[str, Any] = {
    "code": SETUP_CODE,
    "expires": 1_760_000_900,
    "reset": False,
    "passkeys": 0,
    "origins": ORIGINS,
}
FIRST_LINE = (
    "One-time code, valid for 15 minutes. Open http://localhost:8081 or "
    "https://zoeymcp.tailnet.example and choose Set up.\n"
)
REFUSED_LINE = (
    "If the portal refuses this code before you have used it, someone else has: run zoeymcp "
    "setup-code --reset.\n"
)
TEST_MASTER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"  # bytes(range(32))


def test_setup_code_prints_the_code_and_where_to_use_it(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/setup-code")] = (200, ISSUED)
    assert cli(["setup-code", "--socket", "x"]) == (
        EXIT_OK,
        f"{SETUP_CODE}\n",
        FIRST_LINE + REFUSED_LINE,
    )
    assert admin.requests == [("POST", "/setup-code", {"reset": False})]
    assert admin.timeouts == [10.0]
    cli(["setup-code", "--reset", "--socket", "x"])
    assert admin.requests[-1] == ("POST", "/setup-code", {"reset": True})


@pytest.mark.parametrize(
    ("changes", "line"),
    [
        ({"passkeys": 1}, "1 passkey is enrolled; enrolling with this code adds one.\n"),
        ({"passkeys": 3}, "3 passkeys are enrolled; enrolling with this code adds one.\n"),
        (
            {"passkeys": 1, "reset": True},
            "1 passkey is enrolled; enrolling with this code removes all of them and ends every "
            "session.\n",
        ),
        (
            {"passkeys": 2, "reset": True},
            "2 passkeys are enrolled; enrolling with this code removes all of them and ends every "
            "session.\n",
        ),
        ({"passkeys": 0, "reset": True}, ""),
        (
            {"passkeys": None},
            "The passkey file can't be verified: only a code issued with --reset can enrol; run "
            "zoeymcp setup-code --reset.\n",
        ),
        (
            {"passkeys": None, "reset": True},
            "The passkey file can't be verified: enrolling with this code moves it aside, removes "
            "every passkey and ends every session.\n",
        ),
    ],
)
def test_setup_code_says_what_enrolling_does(
    admin: FakeAdmin, changes: dict[str, Any], line: str
) -> None:
    admin.answers[("POST", "/setup-code")] = (200, {**ISSUED, **changes})
    _, _, err = cli(["setup-code", "--socket", "x"])
    assert err == FIRST_LINE + line + REFUSED_LINE


@pytest.mark.parametrize(
    ("origins", "line"),
    [
        (["http://localhost:8081"], "Open http://localhost:8081 and choose Set up."),
        ([], "The policy has no admin block, so no portal takes it yet."),
    ],
)
def test_setup_code_names_the_origins(admin: FakeAdmin, origins: list[str], line: str) -> None:
    admin.answers[("POST", "/setup-code")] = (200, {**ISSUED, "origins": origins})
    _, _, err = cli(["setup-code", "--socket", "x"])
    assert err.splitlines()[0] == f"One-time code, valid for 15 minutes. {line}"


def test_setup_code_errors(admin: FakeAdmin) -> None:
    refusal = {"error": "the setup code couldn't be written", "reason": "not_written"}
    admin.answers[("POST", "/setup-code")] = (500, refusal)
    assert cli(["setup-code", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp setup-code: the setup code couldn't be written\n",
    )


STATUS_PATH = "/setup-code/status?wait=30"
WAITING = "Waiting until a passkey is enrolled with this code (Ctrl-C stops waiting).\n"
ENROLLED = {
    "fingerprint": "3f9a1c0e52d4b7a8",
    "origin": "http://localhost:8081",
    "name": "laptop",
    "created": 1_760_000_043,
}


def status_answer(state: str, **changes: Any) -> tuple[int, dict[str, Any]]:
    answer = {"state": state, "expires": 1_760_000_900, "reset": False, "origin": None}
    return 200, {**answer, "passkey": None, **changes}


def test_setup_code_wait_shows_the_enrolled_passkey(admin: FakeAdmin) -> None:
    origin = "http://localhost:8081"
    admin.answers = InTurn(
        iter(
            [
                (200, ISSUED),
                status_answer("pending"),
                status_answer("redeemed", origin=origin),
                status_answer("redeemed", origin=origin),
                status_answer("enrolled", origin=origin, passkey=ENROLLED),
            ]
        )
    )
    code, out, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert code == EXIT_OK
    assert out == (
        f"{SETUP_CODE}\n"
        "enrolled: 3f9a1c0e52d4b7a8 on http://localhost:8081 as laptop at 08:54:03 UTC\n"
    )
    assert err == (
        FIRST_LINE
        + REFUSED_LINE
        + WAITING
        + "Redeemed on http://localhost:8081; waiting for the enrolment.\n"
    )
    assert [request[:2] for request in admin.requests[1:]] == [("GET", STATUS_PATH)] * 4
    assert admin.timeouts[1:] == [40.0] * 4


@pytest.mark.parametrize(
    ("answer", "line"),
    [
        (status_answer("expired"), "the code expired, or was withdrawn, unused; issue a new code"),
        (
            status_answer("expired", origin="http://localhost:8081"),
            "redeemed on http://localhost:8081, but no passkey was enrolled in time; issue a new "
            "code",
        ),
        (
            status_answer("none", expires=None),
            "the vault has a newer code, or restarted: nothing to wait for",
        ),
        (
            status_answer("pending", expires=1_760_000_901),
            "the vault has a newer code, or restarted: nothing to wait for",
        ),
        (
            status_answer("enrolled", expires=1_760_000_901, passkey=ENROLLED),
            "the vault has a newer code, or restarted: nothing to wait for",
        ),
    ],
)
def test_setup_code_wait_ends_without_an_enrolment(
    admin: FakeAdmin, answer: tuple[int, dict[str, Any]], line: str
) -> None:
    admin.answers = InTurn(iter([(200, ISSUED), status_answer("pending"), answer]))
    code, out, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert (code, out) == (EXIT_FINDINGS, f"{SETUP_CODE}\n")
    assert err == FIRST_LINE + REFUSED_LINE + WAITING + f"zoeymcp setup-code: {line}\n"


def test_setup_code_wait_stops_on_ctrl_c(admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch) -> None:
    admin.answers[("POST", "/setup-code")] = (200, ISSUED)

    def interrupted(socket: str, *, wait: int) -> dict[str, Any]:
        raise KeyboardInterrupt

    monkeypatch.setattr(admin_client, "setup_code_status", interrupted)
    code, _, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert err.endswith(
        WAITING + "zoeymcp setup-code: stopped waiting; the code still works until it expires\n"
    )


def test_setup_code_wait_when_the_vault_goes_away(admin: FakeAdmin) -> None:
    admin.answers = InTurn(iter([(200, ISSUED), (503, {"error": "stopping"})]))
    code, _, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert err.endswith(WAITING + "zoeymcp setup-code: stopping\n")


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """``setup-code --state`` as the vault's user, with the test master key."""
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", TEST_MASTER)
    monkeypatch.delenv("ZOEYMCP_MASTER_KEY_PREVIOUS", raising=False)
    monkeypatch.setattr(main_module, "running_as_root", lambda: False)


def test_setup_code_offline_writes_a_record_the_vault_redeems(
    tmp_path: Path, offline: None
) -> None:
    import asyncio

    from zoeymcp.portal import setupcode
    from zoeymcp.vault.admin import SetupCodes
    from zoeymcp.vault.keys import KeySet

    code, out, err = cli(["setup-code", "--state", str(tmp_path), "--reset"])
    assert code == EXIT_OK
    assert err == "One-time code, valid for 15 minutes. Open the portal and choose Set up.\n" + (
        REFUSED_LINE
    )
    typed = out.strip()
    key = KeySet.from_text(TEST_MASTER).portal_key
    record = setupcode.unseal((tmp_path / "setup.json").read_bytes(), key)
    assert record is not None
    assert (record.sha256, record.reset) == (setupcode.digest(typed), True)
    redeemed = asyncio.run(SetupCodes(tmp_path, key).redeem(typed, origin="http://localhost:8081"))
    assert redeemed == setupcode.Redeemed(record.expires, True)


def test_setup_code_offline_counts_the_passkeys(
    tmp_path: Path, offline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zoeymcp.portal.passkeys import seal

    from .test_passkeys import KEY, OLD, made

    portal = tmp_path / "portal"
    portal.mkdir(mode=0o700)
    (portal / "passkeys.json").write_bytes(seal(made(1, 2), KEY))
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1] == "2 passkeys are enrolled; enrolling with this code adds one."
    # Under the previous master key during a rotation.
    (portal / "passkeys.json").write_bytes(seal(made(1), OLD))
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1].startswith("The passkey file can't be verified")
    old_master = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"  # bytes(range(1, 33))
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY_PREVIOUS", old_master)
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1] == "1 passkey is enrolled; enrolling with this code adds one."
    (portal / "passkeys.json").write_bytes(b"edited")
    _, _, err = cli(["setup-code", "--state", str(tmp_path), "--reset"])
    assert err.splitlines()[1].startswith("The passkey file can't be verified: enrolling")
    (portal / "passkeys.json").unlink()
    (portal / "passkeys.json").mkdir(mode=0o700)
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1].startswith("The passkey file can't be verified")


def test_setup_code_offline_refusals(
    tmp_path: Path, offline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = str(tmp_path / "state")
    assert cli(["setup-code", "--state", state, "--wait"]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp setup-code: --wait asks the vault, so it can't go with --state\n",
    )
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", "")
    assert cli(["setup-code", "--state", state]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp setup-code: --state needs the vault's master key in ZOEYMCP_MASTER_KEY\n",
    )
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", "too-short")
    code, out, err = cli(["setup-code", "--state", state])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err == "zoeymcp setup-code: the master key isn't valid base64url\n"
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", TEST_MASTER)
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY_PREVIOUS", "too-short")
    assert cli(["setup-code", "--state", state])[0] == EXIT_UNREADABLE
    monkeypatch.delenv("ZOEYMCP_MASTER_KEY_PREVIOUS")
    monkeypatch.setattr(main_module, "running_as_root", lambda: True)
    assert cli(["setup-code", "--state", state]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp setup-code: --state won't run as root: the vault's uid couldn't read the file. "
        "Run it as the vault's user.\n",
    )
    assert not (tmp_path / "state").exists()
    monkeypatch.setattr(main_module, "running_as_root", lambda: False)
    (tmp_path / "file").write_bytes(b"")
    code, out, err = cli(["setup-code", "--state", str(tmp_path / "file")])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err.startswith(f"zoeymcp setup-code: can't write {tmp_path / 'file' / 'setup.json'}: ")


@pytest.mark.parametrize(("uid", "root"), [(0, True), (10001, False), (None, False)])
def test_running_as_root(monkeypatch: pytest.MonkeyPatch, uid: int | None, root: bool) -> None:
    if uid is None:
        monkeypatch.delattr(os, "geteuid", raising=False)
    else:
        monkeypatch.setattr(os, "geteuid", lambda: uid, raising=False)
    assert main_module.running_as_root() is root


LISTED: list[dict[str, Any]] = [
    {
        "fingerprint": "3f9a1c0e52d4b7a8",
        "name": "laptop",
        "rp_id": "localhost",
        "alg": "ES256",
        "synced": True,
        "transports": ["hybrid", "internal"],
        "via": "setup_code",
        "origin": "http://localhost:8081",
        "created": 1_760_000_043,
        "last_used": 1_760_054_400,
    },
    {
        "fingerprint": "0123456789abcdef",
        "name": "security key",
        "rp_id": "zoeymcp.tailnet.example",
        "alg": "EdDSA",
        "synced": False,
        "transports": ["usb"],
        "via": "portal",
        "origin": "https://zoeymcp.tailnet.example",
        "created": 1_759_000_000,
        "last_used": None,
    },
]
LISTED_LINES = [
    "3f9a1c0e52d4b7a8  laptop",
    "  ES256, synced, for localhost; enrolled 2025-10-09T08:54:03Z via setup_code on "
    "http://localhost:8081; last used 2025-10-10",
    "0123456789abcdef  security key",
    "  EdDSA, device-bound, for zoeymcp.tailnet.example; enrolled 2025-09-27T19:06:40Z via "
    "portal on https://zoeymcp.tailnet.example; never used",
]


def test_passkeys_are_listed(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/passkeys")] = (200, {"passkeys": LISTED})
    text = "".join(f"{line}\n" for line in LISTED_LINES)
    assert cli(["passkeys", "--socket", "x"]) == (EXIT_OK, text, "")
    admin.answers[("GET", "/passkeys")] = (200, {"passkeys": []})
    assert cli(["passkeys", "--socket", "x"]) == (EXIT_OK, "no passkeys\n", "")
    unavailable = {"error": "the passkey file can't be verified", "reason": "unavailable"}
    admin.answers[("GET", "/passkeys")] = (503, unavailable)
    assert cli(["passkeys", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp passkeys: the passkey file can't be verified\n",
    )


def test_a_passkey_is_removed(admin: FakeAdmin) -> None:
    path = "/passkeys/3f9a1c0e52d4b7a8"
    removed = {"removed": LISTED[0], "sessions_ended": 2, "remaining": 1}
    admin.answers[("DELETE", path)] = (200, removed)
    assert cli(["passkeys", "--remove", "3f9a1c0e52d4b7a8", "--socket", "x"]) == (
        EXIT_OK,
        f"removed {LISTED_LINES[0]}\n{LISTED_LINES[1]}\n2 session(s) ended; 1 passkey(s) left\n",
        "",
    )
    admin.answers[("DELETE", path)] = (200, {**removed, "remaining": 0})
    code, out, err = cli(["passkeys", "--remove", "3f9a1c0e52d4b7a8", "--socket", "x"])
    assert (code, out.splitlines()[-1]) == (EXIT_OK, "2 session(s) ended; 0 passkey(s) left")
    assert err == "No passkey is left: the portal waits for a setup code (zoeymcp setup-code).\n"
    admin.answers[("DELETE", "/passkeys/0000000000000000")] = (
        404,
        {"error": "no passkey has that fingerprint", "reason": "not_found"},
    )
    assert cli(["passkeys", "--remove", "0000000000000000", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp passkeys: no passkey has that fingerprint\n",
    )
    admin.answers[("DELETE", "/passkeys/a%2Fb")] = (400, {"error": "bad", "reason": "x"})
    assert cli(["passkeys", "--remove", "a/b", "--socket", "x"])[0] == EXIT_FINDINGS


def test_sessions_are_listed_and_ended(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/sessions")] = (200, {"sessions": []})
    assert cli(["sessions", "--socket", "x"]) == (EXIT_OK, "no portal sessions\n", "")
    session = {"session": "ab12", "scope": "full"}
    admin.answers[("GET", "/sessions")] = (200, {"sessions": [session]})
    assert cli(["sessions", "--socket", "x"]) == (
        EXIT_OK,
        '{"scope": "full", "session": "ab12"}\n',
        "",
    )
    admin.answers[("DELETE", "/sessions")] = (200, {"ended": 3})
    assert cli(["sessions", "--end-all", "--socket", "x"]) == (
        EXIT_OK,
        "ended 3 portal session(s)\n",
        "",
    )
    admin.answers[("DELETE", "/sessions")] = (503, {"error": "stopping"})
    assert cli(["sessions", "--end-all", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp sessions: stopping\n",
    )
