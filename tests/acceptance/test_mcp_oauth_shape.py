"""Acceptance: an OAuth credential behind a gateway-served remote MCP route, without discovery
(S6 x S10, register D-116; M5 design P.2 step 4d).

Agent (the SDK client) -> gateway -> vault -> the fake MCP server, which takes the fake
authorization server's live access tokens only. The shipped ``remote-mcp-oauth.yaml`` is used
with only its endpoints, upstream, client token, source and example tools swapped. The operator
logs in with the real CLI (``zoeymcp login``, the test playing the browser and pasting the
address). The vault, the authorization server and the MCP server read one clock, so a test can
let an access token expire.
"""

from __future__ import annotations

import io
import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
import pytest

from tests.fakes.agent import ACCEPT, Script, agent
from tests.fakes.mcp_server import McpFake
from tests.fakes.oauth_server import FakeAuthServer
from tests.gateway.rig import pin_of_fake, token_for
from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import OAuth2Credential, RemoteServer, hash_token
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.oauth.protocol import MIN_401_AGE
from zoeymcp.vault.store import STORE_FILE

from .conftest import BASE, PROFILES, Clock, serve_tls
from .gateway import GatewayDeployment, Seen
from .test_mcp_shapes import LINKS, own_uid, text
from .test_oauth_shapes import PRINTED_URL, REDIRECT, Browser
from .tls import ProviderCA

pytestmark = pytest.mark.anyio

PROFILE = "remote-mcp-oauth.yaml"
CREDENTIAL = "notes-oauth"
SLOT = "notes-refresh"
CLIENT = "agent1"
CLIENT_ID = "example-notes-client"
SCOPES = ("notes.read", "notes.write")
RESOURCE = "https://mcp.notes.example/mcp"
ENDPOINTS = {
    "https://auth.notes.example/token": "/token",
    "https://auth.notes.example/authorize": "/authorize",
}
# The profile's example tools, played by the fake's: one allowed, one approved.
TOOLS = {"search_notes": "echo", "create_note": "add"}
EXAMPLE_PINS = {"search_notes": "sha256:" + "1" * 64, "create_note": "sha256:" + "2" * 64}
HOUR = 3600.0
# Every token and code the fake authorization server issues.
ISSUED = re.compile(r"fake-notes-(?:rt|at|code)-\d+")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def fragment() -> dict[str, Any]:
    return load_mapping((PROFILES / PROFILE).read_text(encoding="utf-8"))


# --- the profile -------------------------------------------------------------------------------


def test_the_profile_passes_check() -> None:
    out = io.StringIO()
    document = io.StringIO(json.dumps({**BASE, **fragment()}))
    assert main(["check", "--config", "-"], stdin=document, out=out) == 0
    assert out.getvalue() == "<stdin>: ok (0 error(s), 0 warning(s))\n"


def test_the_profile_says_what_the_shape_needs() -> None:
    raw = fragment()
    policy = Policy.model_validate({**BASE, **raw})
    [cred] = policy.credentials.values()
    assert isinstance(cred, OAuth2Credential)
    # A public client registered by hand, PKCE at login, refresh tokens that rotate.
    assert (cred.effective_client_auth, cred.client_secret, cred.rotates) == ("none", None, True)
    assert (cred.grant, cred.redirect_uri) == ("refresh_token", REDIRECT)
    assert cred.authorize_url is not None
    # The token's audience, on token requests and at login (RFC 8707).
    assert cred.extra_params == cred.authorize_params == {"resource": RESOURCE}
    [route] = policy.routes
    assert (route.callers, route.stream, route.credential) == (["gateway"], True, CREDENTIAL)
    assert RESOURCE.startswith(f"{route.upstream}/")
    gateway = policy.gateway
    assert gateway is not None
    [server] = gateway.servers.values()
    assert isinstance(server, RemoteServer)
    assert (server.tools.allow, server.tools.approve) == (["search_notes"], ["create_note"])
    assert sorted(server.review) == sorted(server.tools.include)
    # The approve tool needs an attended client: one whose human answers its prompts.
    approvals = gateway.clients[CLIENT].approvals
    assert approvals is not None
    assert approvals.attended
    # No portal: the operator logs in with the CLI.
    assert "admin" not in raw
    assert policy.admin is None


# --- the rig -------------------------------------------------------------------------------------


def as_fake(fake: McpFake) -> dict[str, str]:
    """The profile's example tools and pins, swapped for the fake's."""
    swap = {
        f"{name}: {EXAMPLE_PINS[name]}": f"{tool}: {pin_of_fake(fake, tool)}"
        for name, tool in TOOLS.items()
    }
    swap.update(TOOLS)
    return swap


@contextmanager
def deployed(
    tmp_path: Path, ca: ProviderCA, auth: FakeAuthServer, fake: McpFake, clock: Clock, link: str
) -> Iterator[GatewayDeployment]:
    with (
        serve_tls(auth.app(), ca) as auth_url,
        serve_tls(fake.app(), ca, lifespan=True) as upstream,
    ):
        replace = {old: auth_url + path for old, path in ENDPOINTS.items()}
        replace["sources: [192.0.2.0/24]"] = "sources: [127.0.0.1/32]"
        replace.update(as_fake(fake))
        gateway = GatewayDeployment(
            tmp_path,
            upstream,
            ca,
            profile=PROFILE,
            clients=(CLIENT,),
            link=link,  # type: ignore[arg-type]
            link_uid=own_uid() if link == "unix" else None,
            replace=replace,
            clock=clock,
        )
        yield gateway
    store_file = gateway.vault.state / STORE_FILE
    sweep(gateway.seen, store_file.read_text(encoding="utf-8"), gateway.vault.keys.gateway_key(1))


def sweep(seen: Seen, store: str, gateway_key: str) -> None:
    """No token or code the authorization server issued, and no client token or gateway key,
    reached a log line, an answer, the CLI or the store file."""
    for where, found in (("a log, an answer or the CLI", seen.everything()), ("the store", store)):
        leaked = ISSUED.search(found)
        assert leaked is None, f"{leaked.group(0)} reached {where}"
    everything = seen.everything()
    for value in (token_for(CLIENT), hash_token(token_for(CLIENT)), gateway_key):
        assert value not in everything


def login(gateway: GatewayDeployment, ca: ProviderCA) -> tuple[int, str, str]:
    """``zoeymcp login`` against the running vault's admin app: approve, then paste."""
    original = httpx.HTTPTransport
    httpx.HTTPTransport = lambda **_: gateway.vault.admin_transport()  # type: ignore[assignment,misc]
    try:
        out, err = io.StringIO(), io.StringIO()
        code = main(["login", CREDENTIAL], stdin=Browser(out, ca), out=out, err=err)
    finally:
        httpx.HTTPTransport = original  # type: ignore[misc]
    gateway.seen.outputs += [out.getvalue(), err.getvalue()]
    return code, out.getvalue(), err.getvalue()


def mcp_headers() -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(CLIENT)}"}


def refresh_triggers(seen: Seen) -> list[str]:
    return [e["trigger"] for e in seen.events("oauth_refresh") if e["trigger"] != "login"]


# --- S6 x S10 ------------------------------------------------------------------------------------


@pytest.mark.parametrize("link", LINKS)
async def test_login_calls_refreshes_a_refused_token_and_an_approval(
    tmp_path: Path, ca: ProviderCA, link: str
) -> None:
    clock = Clock()
    auth = FakeAuthServer(
        clock.wall,
        client_id=CLIENT_ID,
        auth="none",
        rotate=True,
        scopes=SCOPES,
        prefix="fake-notes",
    )
    fake = McpFake(authorize=auth.access_ok)
    script = Script([ACCEPT])
    with deployed(tmp_path, ca, auth, fake, clock, link) as gateway, gateway.running() as running:
        # The CLI paste: a PKCE login that asks for the server as the token's audience.
        code, out, err = login(gateway, ca)
        assert (code, err) == (0, "")
        assert f"Stored the refresh token for {CREDENTIAL} as {SLOT}.\n" in out
        [url] = PRINTED_URL.findall(out)
        query = dict(parse_qsl(urlsplit(url).query))
        assert (query["code_challenge_method"], query["resource"]) == ("S256", RESOURCE)
        [exchange] = auth.calls
        assert (exchange.grant_type, exchange.auth, exchange.status) == (
            "authorization_code",
            "body",
            200,
        )
        assert exchange.params["resource"] == RESOURCE
        assert "client_secret" not in exchange.params
        first = auth.active_refresh_token()

        async with agent(running.mcp(), script=script, headers=mcp_headers()) as client:
            listed = await client.list_tools()
            assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS.values())
            assert text(await client.call_tool("echo", {"text": "before"})) == "before"
            assert len(auth.calls) == 1  # the login's access token is used

            # The access token expires between calls, twice: each refresh rotates, and the
            # next one presents the new refresh token.
            clock.advance(HOUR)
            assert text(await client.call_tool("echo", {"text": "refreshed"})) == "refreshed"
            rotated = auth.active_refresh_token()
            assert rotated not in (None, first)
            clock.advance(HOUR)
            assert text(await client.call_tool("echo", {"text": "rotated"})) == "rotated"
            presented = [(c.refresh_token, c.params["resource"]) for c in auth.refresh_calls]
            assert presented == [(first, RESOURCE), (rotated, RESOURCE)]

            # The server refuses a token that hasn't expired: the call fails as an upstream
            # error, and the vault doesn't send the POST again.
            clock.advance(MIN_401_AGE)
            auth.drop_access_tokens()
            refused = await client.call_tool("echo", {"text": "refused"})
            assert refused.is_error
            assert text(refused).startswith("upstream error (ref ")
            assert len(auth.refresh_calls) == 2
            # The vault dropped the token, so the next call gets a new one.
            assert text(await client.call_tool("echo", {"text": "after"})) == "after"
            assert len(auth.refresh_calls) == 3

            # The approve tool: the agent's human is asked, accepts, and the call runs.
            added = await client.call_tool("add", {"a": 2, "b": 3})
            assert (added.is_error, text(added)) == (False, "5")
        gateway.seen.outputs += [text(refused), text(added)]

    [prompt] = script.prompts
    assert "Tool: notes \N{RIGHTWARDS ARROW} add" in prompt.message
    assert [(call.name, call.arguments) for call in fake.calls] == [
        *(("echo", {"text": word}) for word in ("before", "refreshed", "rotated", "after")),
        ("add", {"a": 2, "b": 3}),
    ]
    # The refused call reached the server once. Every call carried an access token from the
    # authorization server, a new one after each refresh.
    calls = fake.requests("tools/call")
    assert [item.params["arguments"] for item in calls if item.status == 401] == [
        {"text": "refused"}
    ]
    tokens = [str(item.header("authorization")).removeprefix("Bearer ") for item in calls]
    assert all(ISSUED.fullmatch(token) for token in tokens)
    assert len(set(tokens)) == 4
    # The gateway's own GET (its event stream) may meet the dropped token too, depending on timing;
    # the refused POST is the one the vault answers for, once.
    rejections = gateway.seen.events("oauth_upstream_401")
    posts = [event for event in rejections if event["method"] == "POST"]
    assert [event["action"] for event in posts] == ["invalidated"], rejections
    assert {event["method"] for event in rejections} <= {"POST", "GET"}, rejections
    triggers = refresh_triggers(gateway.seen)
    assert triggers == ["expiry", "expiry", "upstream_401"], (triggers, rejections)


@pytest.mark.parametrize(
    ("leak", "where"),
    [
        ("fake-notes-at-7", "seen"),
        ("fake-notes-rt-12", "store"),
        (token_for(CLIENT), "seen"),
        (hash_token(token_for(CLIENT)), "seen"),
        ("zgw1-gateway", "seen"),
    ],
)
def test_the_sweep_sees_a_leak(leak: str, where: str) -> None:
    seen = Seen()
    store = ""
    if where == "seen":
        seen.outputs.append(f"output {leak}")
    else:
        store = f'{{"value": "{leak}"}}'
    with pytest.raises(AssertionError):
        sweep(seen, store, "zgw1-gateway")
