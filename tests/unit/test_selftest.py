from __future__ import annotations

import asyncio
import base64
import io
import json
import socket
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml

from zoeymcp.cli.main import EXIT_FINDINGS, EXIT_OK, main
from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.selftest import runner
from zoeymcp.selftest.cases import CaseFile, UpstreamExpectation, parse_cases
from zoeymcp.selftest.echo import TokenClient, TokenEcho, endpoint_key
from zoeymcp.selftest.runner import Rig, generate_mutants, mutate
from zoeymcp.vault import app as app_module
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.connectors.smtp import SendResult

from .conftest import EXAMPLE_POLICY

EXAMPLE_CASES = EXAMPLE_POLICY.parent / "selftest-cases.yaml"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def example_cases() -> CaseFile:
    return parse_cases(EXAMPLE_CASES.read_text(encoding="utf-8"))


def without(cases: CaseFile, name: str) -> CaseFile:
    kept = [c for c in cases.cases if c.name != name]
    assert len(kept) == len(cases.cases) - 1
    return CaseFile(cases=kept)


def test_example_cases_pass(tmp_path: Path) -> None:
    policy = example_policy()
    results = asyncio.run(Rig(policy, tmp_path).run(policy, example_cases()))
    assert [(r.name, r.problems) for r in results if not r.ok] == []


def test_example_cases_kill_every_mutant(tmp_path: Path) -> None:
    policy = example_policy()
    report = asyncio.run(mutate(policy, example_cases(), Rig(policy, tmp_path)))
    assert report.survived == []
    assert len(report.killed) == len(generate_mutants(policy)) >= 10


def test_a_missing_refusal_case_lets_a_mutant_survive(tmp_path: Path) -> None:
    policy = example_policy()
    weaker = without(example_cases(), "stats refuses writes")
    report = asyncio.run(mutate(policy, weaker, Rig(policy, tmp_path)))
    assert report.survived == ["routes[0] (stats).rules[0]: allow every method"]


def test_a_missing_upstream_check_lets_force_go_unnoticed(tmp_path: Path) -> None:
    policy = example_policy()
    cases = example_cases()
    first = cases.cases[0]
    relaxed = first.model_copy(
        update={"expect": first.expect.model_copy(update={"upstream": None})}
    )
    weaker = CaseFile(cases=[relaxed, *cases.cases[1:]])
    report = asyncio.run(mutate(policy, weaker, Rig(policy, tmp_path)))
    assert "routes[0] (stats).query.force.user: no longer forced" in report.survived


def test_equivalent_mutants_are_not_generated() -> None:
    descriptions = [m.description for m in generate_mutants(example_policy())]
    # api_key is the credential's own parameter: the vault always removes it.
    assert not any("api_key no longer stripped" in d for d in descriptions)


def test_failures_are_reported(tmp_path: Path) -> None:
    policy = example_policy()
    text = EXAMPLE_CASES.read_text(encoding="utf-8").replace("user: alice", "user: bob")
    results = asyncio.run(Rig(policy, tmp_path).run(policy, parse_cases(text)))
    [failed] = [r for r in results if not r.ok]
    assert failed.problems == ["query 'user' is 'alice', expected 'bob'"]


def test_credential_false_catches_a_leak(tmp_path: Path) -> None:
    policy = example_policy()
    cases = parse_cases(
        yaml.safe_dump(
            {
                "cases": [
                    {
                        "name": "claims no credential",
                        "request": {
                            "method": "GET",
                            "path": "/stats/2.0/",
                            "caller": {"placeholder": "ph-agent1-stats-4c1f9b27"},
                        },
                        "expect": {"status": 200, "upstream": {"credential": False}},
                    }
                ]
            }
        )
    )
    [result] = asyncio.run(Rig(policy, tmp_path).run(policy, cases))
    assert result.problems == ["a secret reached the upstream"]


def test_case_file_validation() -> None:
    with pytest.raises(ValueError, match="forwarded request"):
        parse_cases(
            "cases:\n  - name: x\n    request: {method: GET, path: /a}\n"
            "    expect: {status: 403, upstream: {path: /a}}\n"
        )


def run_cli(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    return main(argv, out=out, err=io.StringIO()), out.getvalue()


def test_cli_selftest_with_mutation() -> None:
    code, out = run_cli(
        ["selftest", "--config", str(EXAMPLE_POLICY), "--cases", str(EXAMPLE_CASES), "--mutate"]
    )
    assert code == EXIT_OK, out
    assert "19/19 cases passed" in out
    assert "SURVIVED" not in out


def test_cli_selftest_reports_survivors(tmp_path: Path) -> None:
    weaker = without(example_cases(), "stats refuses other API versions")
    cases_file = tmp_path / "weaker.yaml"
    cases_file.write_text(
        yaml.safe_dump({"cases": [c.model_dump() for c in weaker.cases]}), encoding="utf-8"
    )
    code, out = run_cli(
        ["selftest", "--config", str(EXAMPLE_POLICY), "--cases", str(cases_file), "--mutate"]
    )
    assert code == EXIT_FINDINGS
    assert "SURVIVED  routes[0] (stats).rules[0].paths[0]: /2.0/** widened to /**" in out


# --- OAuth (design F) ----------------------------------------------------------------------------

BROKER_CASE = "the gateway may post to the broker's MCP endpoint with an access token"


def only(cases: CaseFile, name: str) -> CaseFile:
    return CaseFile(cases=[c for c in cases.cases if c.name == name])


def test_the_oauth_case_passes_with_no_network_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_network(*args: object, **kwargs: object) -> None:
        raise AssertionError("a self-test built a network transport")

    echoes: list[TokenEcho] = []

    class Recording(TokenEcho):
        def __post_init__(self) -> None:
            super().__post_init__()
            echoes.append(self)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "__init__", no_network)
    monkeypatch.setattr(runner, "TokenEcho", Recording)
    policy = example_policy()
    results = asyncio.run(Rig(policy, tmp_path).run(policy, example_cases()))
    assert [(r.name, r.problems) for r in results if not r.ok] == []
    [echo] = echoes
    assert echo.calls == 1
    assert list(echo.last_issued) == ["broker-mcp"]
    assert echo.issued[0].startswith("selftest-at-")


SEND_CASE = "the gateway may send, with an idempotency key"


def test_the_mail_cases_open_no_socket_and_record_one_send(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("a self-test opened a socket")

    recorders: list[runner.SendRecorder] = []

    class Recording(runner.SendRecorder):
        def __init__(self) -> None:
            super().__init__()
            recorders.append(self)

    monkeypatch.setattr(socket, "create_connection", no_socket)
    monkeypatch.setattr(runner, "SendRecorder", Recording)
    policy = example_policy()
    rig = Rig(policy, tmp_path)
    for _ in range(2):  # a fresh journal each run: the same key sends again
        results = asyncio.run(rig.run(policy, example_cases()))
        assert [(r.name, r.problems) for r in results if not r.ok] == []
    assert [len(r.sends) for r in recorders] == [1, 1]
    [(sender, recipients, data)] = recorders[0].sends
    assert (sender, recipients) == ("agent@mail.example", ["partner@mail.example"])
    assert b"Message-ID: <selftest-1@selftest.invalid>" in data
    assert b"Subject: Self-test" in data


def test_a_send_case_notices_a_send_that_didnt_happen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def sent_nothing(self: runner.SendRecorder, *args: object, **kwargs: object) -> object:
        return SendResult("final_reply", final_dot_written=True, reply_code=250)

    monkeypatch.setattr(runner.SendRecorder, "__call__", sent_nothing)
    policy = example_policy()
    [result] = asyncio.run(Rig(policy, tmp_path).run(policy, only(example_cases(), SEND_CASE)))
    assert result.problems == ["0 message(s) sent, expected 1"]


def test_a_connector_case_cant_expect_an_upstream(tmp_path: Path) -> None:
    [case] = only(example_cases(), "the gateway may read the mail config").cases
    case = case.model_copy(
        update={
            "expect": case.expect.model_copy(
                update={"upstream": UpstreamExpectation(path="/config")}
            )
        }
    )
    policy = example_policy()
    [result] = asyncio.run(Rig(policy, tmp_path).run(policy, CaseFile(cases=[case])))
    assert result.problems == ["a connector route has no upstream to expect"]


def test_a_broken_injection_fails_the_oauth_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(app_module, "_bearer", lambda grant: ("authorization", "Bearer wrong"))
    policy = example_policy()
    [result] = asyncio.run(Rig(policy, tmp_path).run(policy, only(example_cases(), BROKER_CASE)))
    assert result.problems == ["the route's credential wasn't injected"]


def test_a_refused_token_call_fails_the_oauth_case(tmp_path: Path) -> None:
    policy = example_policy()
    rig = Rig(policy, tmp_path)
    rig.store.put("broker-refresh", "not-the-dummy-value", derive_binding(policy, "broker-refresh"))
    [result] = asyncio.run(rig.run(policy, only(example_cases(), BROKER_CASE)))
    assert result.problems == ["status 502, expected 200", "0 upstream request(s), expected 1"]


def test_an_access_token_leak_is_caught(tmp_path: Path) -> None:
    policy = example_policy()
    case = only(example_cases(), BROKER_CASE).cases[0]
    claims_none = case.model_copy(
        update={
            "expect": case.expect.model_copy(
                update={"upstream": UpstreamExpectation(credential=False)}
            )
        }
    )
    [result] = asyncio.run(Rig(policy, tmp_path).run(policy, CaseFile(cases=[claims_none])))
    assert result.problems == ["a secret reached the upstream"]


def test_broker_mutants_are_killed(tmp_path: Path) -> None:
    policy = example_policy()
    report = asyncio.run(mutate(policy, example_cases(), Rig(policy, tmp_path)))
    broker = [d for d in report.killed if "(broker-mcp)" in d]
    assert broker == [
        "routes[1] (broker-mcp).rules[0]: allow every method",
        "routes[1] (broker-mcp).rules[0].paths[0]: /mcp widened to /**",
    ]


OAUTH_POLICY = """
version: 1
mode: declarative
credentials:
  basic-form:
    kind: oauth2
    token_url: https://auth.example/token
    client_id: basic-client:1
    client_secret: store:basic-secret
    refresh_token: store:basic-refresh
  post-json:
    kind: oauth2
    token_url: https://auth.example/token
    client_id: post-client
    client_auth: post
    client_secret: env:POST_SECRET
    refresh_token: env:POST_SEED
    token_body: json
  public:
    kind: oauth2
    token_url: https://other-auth.example/oauth/token
    client_id: store:public-client
    client_auth: none
    rotates: true
    refresh_token: store:public-refresh
  machine:
    kind: oauth2
    grant: client_credentials
    token_url: https://auth.example/token
    client_id: machine-client
    client_secret: store:machine-secret
    scope: read
routes:
"""


def oauth_route(name: str) -> str:
    return (
        f"  - {{name: {name}, prefix: /{name}, upstream: https://{name}.example, "
        f"credential: {name}, callers: [gateway], "
        "rules: [{methods: [GET, POST], paths: ['/**']}]}\n"
    )


OAUTH_NAMES = ("basic-form", "post-json", "public", "machine")


def oauth_policy() -> Policy:
    return parse_policy(OAUTH_POLICY + "".join(oauth_route(n) for n in OAUTH_NAMES), "oauth")


def oauth_cases(*names: str, status: int = 200) -> CaseFile:
    cases = []
    for name in names:
        expect: dict[str, Any] = {"status": status}
        if status == 200:
            expect["upstream"] = {"path": "/token", "credential": True}
        cases.append(
            {
                "name": name,
                "request": {"method": "GET", "path": f"/{name}/token", "caller": "gateway"},
                "expect": expect,
            }
        )
    return parse_cases(yaml.safe_dump({"cases": cases}))


def test_every_client_authentication_and_body(tmp_path: Path) -> None:
    policy = oauth_policy()
    rig = Rig(policy, tmp_path)
    results = asyncio.run(rig.run(policy, oauth_cases(*OAUTH_NAMES)))
    assert [(r.name, r.problems) for r in results] == [(n, []) for n in OAUTH_NAMES]


def test_token_clients(tmp_path: Path) -> None:
    policy = oauth_policy()
    rig = Rig(policy, tmp_path)
    clients = {c.credential: c for c in rig.token_clients(policy)}
    assert sorted(clients) == sorted(OAUTH_NAMES)
    basic = clients["basic-form"]
    assert (basic.grant, basic.auth, basic.body) == ("refresh_token", "basic", "form")
    assert basic.client_id == "basic-client:1"
    assert basic.client_secret == rig.values["store:basic-secret"]
    assert basic.refresh_token == rig.values["store:basic-refresh"]
    post = clients["post-json"]
    assert (post.auth, post.body) == ("post", "json")
    assert post.client_secret == rig.environ["POST_SECRET"]
    assert post.refresh_token == rig.environ["POST_SEED"]
    public = clients["public"]
    assert public.client_id == rig.values["store:public-client"]
    assert (public.auth, public.client_secret) == ("none", None)
    machine = clients["machine"]
    assert (machine.grant, machine.refresh_token) == ("client_credentials", None)


@pytest.mark.parametrize(
    ("credential", "field"),
    [
        ("basic-form", "client_secret"),
        ("basic-form", "refresh_token"),
        ("post-json", "client_secret"),
        ("post-json", "refresh_token"),
        ("public", "client_id"),
        ("public", "refresh_token"),
        ("machine", "client_secret"),
    ],
)
def test_a_wrong_dummy_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, credential: str, field: str
) -> None:
    policy = oauth_policy()
    rig = Rig(policy, tmp_path)
    real = rig.token_clients

    def wrong(policy: Policy) -> list[TokenClient]:
        return [
            replace(c, **{field: "wrong-value"}) if c.credential == credential else c
            for c in real(policy)
        ]

    monkeypatch.setattr(rig, "token_clients", wrong)
    [result] = asyncio.run(rig.run(policy, oauth_cases(credential)))
    assert result.problems == ["status 502, expected 200", "0 upstream request(s), expected 1"]


async def post(echo: TokenEcho, url: str, **kwargs: Any) -> httpx.Response:
    async def app(scope: Any, receive: Any, send: Any) -> None:
        assert echo.handles(scope)
        await echo(scope, receive, send)

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
        return await client.post(url, **kwargs)


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


BASIC = TokenClient(
    credential="b",
    token_url="https://auth.example/token",
    grant="refresh_token",
    auth="basic",
    body="form",
    client_id="id:1",
    client_secret="se cret+",
    refresh_token="rt-1",
)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("headers", "data", "status"),
    [
        ({"authorization": basic("id%3A1", "se+cret%2B")}, {"grant_type": "refresh_token"}, 400),
        (
            {"authorization": basic("id%3A1", "se+cret%2B")},
            {"grant_type": "refresh_token", "refresh_token": "rt-1"},
            200,
        ),
        (
            {"authorization": basic("id%3A1", "se+cret%2B")},
            {"grant_type": "client_credentials"},
            400,
        ),
        (
            {"authorization": basic("id%3A1", "se+cret%2B")},
            {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_secret": "x"},
            401,
        ),
        ({"authorization": basic("id%3A1", "wrong")}, {"grant_type": "refresh_token"}, 401),
        ({"authorization": basic("id:1", "se cret+")}, {"grant_type": "refresh_token"}, 401),
        ({"authorization": "Basic not-base64!"}, {"grant_type": "refresh_token"}, 401),
        ({"authorization": "Basic " + base64.b64encode(b"nocolon").decode()}, {}, 401),
        ({"authorization": "Bearer abc"}, {"grant_type": "refresh_token"}, 401),
        (
            {},
            {"grant_type": "refresh_token", "client_id": "id:1", "client_secret": "se cret+"},
            401,
        ),
    ],
)
async def test_token_echo_basic(headers: dict[str, str], data: dict[str, str], status: int) -> None:
    echo = TokenEcho([BASIC])
    response = await post(echo, "https://auth.example/token", headers=headers, data=data)
    assert response.status_code == status
    if status == 200:
        assert response.json() == {
            "access_token": echo.last_issued["b"],
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        assert echo.issued == [echo.last_issued["b"]]
    else:
        assert echo.last_issued == {}
        error = "invalid_grant" if status == 400 else "invalid_client"
        assert response.json() == {"error": error}


POST = replace(BASIC, credential="p", auth="post", body="json", client_id="id")
POST_JSON = {
    "grant_type": "refresh_token",
    "refresh_token": "rt-1",
    "client_id": "id",
    "client_secret": "se cret+",
}
NONE = replace(BASIC, credential="n", auth="none", client_id="id", client_secret=None)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("client", "kwargs", "status"),
    [
        (
            POST,
            {
                "json": {
                    "grant_type": "refresh_token",
                    "refresh_token": "rt-1",
                    "client_id": "id",
                    "client_secret": "se cret+",
                }
            },
            200,
        ),
        (
            POST,
            {"json": {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "id"}},
            401,
        ),
        (
            POST,
            {
                "data": {
                    "grant_type": "refresh_token",
                    "refresh_token": "rt-1",
                    "client_id": "id",
                    "client_secret": "se cret+",
                }
            },
            401,
        ),
        (POST, {"content": b"[1]", "headers": {"content-type": "application/json"}}, 401),
        (
            POST,
            {
                "content": json.dumps(POST_JSON).encode(),
                "headers": {"content-type": "text/plain"},
            },
            401,
        ),
        (
            POST,
            {
                "content": json.dumps(POST_JSON).encode(),
                "headers": {"content-type": "Application/JSON; charset=utf-8"},
            },
            200,
        ),
        (POST, {"content": b"{", "headers": {"content-type": "application/json"}}, 401),
        (
            NONE,
            {"data": {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "id"}},
            200,
        ),
        (
            NONE,
            {"data": {"grant_type": "refresh_token", "refresh_token": "rt-2", "client_id": "id"}},
            400,
        ),
        (
            NONE,
            {
                "data": {
                    "grant_type": "refresh_token",
                    "refresh_token": "rt-1",
                    "client_id": "id",
                    "client_secret": "s",
                }
            },
            401,
        ),
        (
            NONE,
            {"data": {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "x"}},
            401,
        ),
        (
            NONE,
            {
                "content": b"grant_type=refresh_token&refresh_token=rt-1&refresh_token=rt-1"
                b"&client_id=id",
                "headers": {"content-type": "application/x-www-form-urlencoded"},
            },
            401,
        ),
        (
            NONE,
            {
                "content": b"grant_type=refresh_token&refresh_token=rt-1&client_id=id"
                b"&resource=a&resource=b",
                "headers": {"content-type": "application/x-www-form-urlencoded"},
            },
            200,
        ),
        (
            NONE,
            {
                "data": {"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "id"},
                "headers": {"authorization": "Bearer x"},
            },
            401,
        ),
    ],
)
async def test_token_echo_post_and_none(
    client: TokenClient, kwargs: dict[str, Any], status: int
) -> None:
    echo = TokenEcho([client])
    response = await post(echo, "https://auth.example/token", **kwargs)
    assert response.status_code == status


@pytest.mark.anyio
async def test_a_basic_client_without_a_secret_is_refused() -> None:
    echo = TokenEcho([replace(BASIC, client_secret=None)])
    response = await post(
        echo,
        "https://auth.example/token",
        headers={"authorization": basic("id%3A1", "")},
        data={"grant_type": "refresh_token", "refresh_token": "rt-1"},
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_a_post_client_without_a_secret_is_refused() -> None:
    echo = TokenEcho([replace(POST, body="form", client_secret=None)])
    response = await post(
        echo,
        "https://auth.example/token",
        data={"grant_type": "refresh_token", "refresh_token": "rt-1", "client_id": "id"},
    )
    assert response.status_code == 401


def scope(method: str, url: str) -> dict[str, Any]:
    parsed = httpx.URL(url)
    return {
        "type": "http",
        "method": method,
        "scheme": parsed.scheme,
        "server": (parsed.host, parsed.port),
        "path": parsed.path,
        "raw_path": parsed.raw_path.split(b"?")[0],
    }


@pytest.mark.parametrize(
    ("method", "url", "handled"),
    [
        ("POST", "https://auth.example/token", True),
        ("POST", "https://AUTH.example:443/token", True),
        ("POST", "https://auth.example/token?x=1", True),
        ("GET", "https://auth.example/token", False),
        ("POST", "https://auth.example/token/", False),
        ("POST", "https://auth.example/other", False),
        ("POST", "http://auth.example/token", False),
        ("POST", "https://auth.example:8443/token", False),
        ("POST", "https://api.example/token", False),
        ("POST", "https://[::1]:8443/token", False),
    ],
)
def test_token_echo_dispatch(method: str, url: str, handled: bool) -> None:
    assert TokenEcho([BASIC]).handles(scope(method, url)) is handled


def test_token_echo_dispatch_on_ipv6() -> None:
    echo = TokenEcho([replace(BASIC, token_url="https://[::1]:8443/token")])
    assert echo.handles(scope("POST", "https://[::1]:8443/token")) is True
    assert echo.handles(scope("POST", "https://[::1]:8444/token")) is False


def test_token_echo_dispatch_without_a_raw_path() -> None:
    found = scope("POST", "https://auth.example/token")
    del found["raw_path"]
    assert TokenEcho([BASIC]).handles(found) is True


def test_token_echo_dispatch_needs_a_server() -> None:
    echo = TokenEcho([BASIC])
    assert echo.handles({**scope("POST", "https://auth.example/token"), "server": None}) is False


def test_endpoint_key() -> None:
    assert endpoint_key("https://Auth.example/oauth/token?tenant=1") == (
        "https://auth.example:443",
        "/oauth/token",
    )
    assert endpoint_key("http://[::1]:8080/t") == ("http://[::1]:8080", "/t")
