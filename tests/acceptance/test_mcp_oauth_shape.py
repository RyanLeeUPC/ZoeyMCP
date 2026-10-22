"""Acceptance: an OAuth credential behind a gateway-served remote MCP route, without discovery
(S6 x S10, register D-116; M5 design P.2 step 4d).

Agent (the SDK client) -> gateway -> vault -> the fake MCP server, which takes the fake
authorization server's live access tokens only. The shipped ``remote-mcp-oauth.yaml`` is used
with only its endpoints, upstream, client token, source and example tools swapped. The operator
logs in with the real CLI (``zoeymcp login``, the test playing the browser and pasting the
address), or through the portal (M5 design H.1, step 14a): a setup code, a passkey, Connect, the
approval in the browser, the paste, and its confirm with the passkey. Then the same calls. The
vault, the authorization server and the MCP server read one clock, so a test can let an access
token expire.
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
from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Browser as PortalBrowser
from tests.fakes.mcp_server import McpFake
from tests.fakes.oauth_server import FakeAuthServer
from tests.gateway.rig import Running, pin_of_fake, token_for
from tests.portal.flows import enrol, redeem
from tests.portal.flows import login as sign_in
from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.schema import OAuth2Credential, RemoteServer, hash_token
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault.oauth.protocol import MIN_401_AGE
from zoeymcp.vault.store import STORE_FILE

from .conftest import BASE, PROFILES, Clock, serve_tls
from .gateway import GatewayDeployment
from .helpers import Seen, listening
from .test_mcp_shapes import LINKS, own_uid, text
from .test_oauth_shapes import PRINTED_URL, REDIRECT, Browser, browse
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
    tmp_path: Path,
    ca: ProviderCA,
    auth: FakeAuthServer,
    fake: McpFake,
    clock: Clock,
    link: str,
    *,
    portal: bool = False,
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
            portal=portal,
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


def portal_login(gateway: GatewayDeployment, ca: ProviderCA) -> str:
    """Connect through the portal by paste (H.1): a setup code issued as the socket issues one, a
    passkey enrolled with it and signed in with, then Connect, the approval in the browser's new
    tab, the paste, and its confirm with the passkey. Every portal answer is kept for the sweep.
    Returns the authorization URL."""
    vault = gateway.vault
    code, _ = vault.call(lambda: vault.setup.issue())
    passkey = SoftAuthenticator()
    with PortalBrowser() as browser:
        page = browser.page(vault.portal_origin)
        assert redeem(page, code.reveal()).status_code == 200
        assert enrol(page, passkey).status_code == 200
        assert sign_in(page, passkey).status_code == 200
        started = page.fetch("POST", f"/api/oauth/{CREDENTIAL}/start", json={})
        assert started.status_code == 200, started.text
        url: str = started.json()["authorize_url"]
        pasted = browse(url, ca)
        data = {"credential": CREDENTIAL, "flow": started.json()["flow"], "redirect_url": pasted}
        held = page.fetch("POST", "/api/actions", json={"kind": "oauth.complete", "data": data})
        assert held.status_code == 200, held.text
        assert auth_calls(gateway) == 0  # nothing exchanged before the passkey
        assertion = passkey.get(held.json()["options"], page.origin).body()
        path = f"/api/actions/{held.json()['action']}/confirm"
        done = page.fetch("POST", path, json={"credential": assertion})
        assert done.status_code == 200, done.text
        assert (done.json()["slot"], done.json()["persisted"]) == (SLOT, True)
        listed = page.fetch("GET", "/api/oauth")
        assert [entry["state"] for entry in listed.json()["credentials"]] == ["ok"]
        gateway.seen.outputs += [r.text for r in (started, held, done, listed)]
    return url


def auth_calls(gateway: GatewayDeployment) -> int:
    """How many token calls the vault has logged."""
    return len(gateway.seen.events("oauth_refresh"))


def check_the_login(auth: FakeAuthServer, url: str) -> None:
    """A PKCE login that asked for the server as the token's audience, and one exchange."""
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


def mcp_headers() -> dict[str, str]:
    return {"authorization": f"Bearer {token_for(CLIENT)}"}


def refresh_triggers(seen: Seen) -> list[str]:
    return [e["trigger"] for e in seen.events("oauth_refresh") if e["trigger"] != "login"]


# --- S6 x S10 ------------------------------------------------------------------------------------


def notes_server(clock: Clock) -> FakeAuthServer:
    return FakeAuthServer(
        clock.wall,
        client_id=CLIENT_ID,
        auth="none",
        rotate=True,
        scopes=SCOPES,
        prefix="fake-notes",
    )


@pytest.mark.parametrize("link", LINKS)
async def test_login_calls_refreshes_a_refused_token_and_an_approval(
    tmp_path: Path, ca: ProviderCA, link: str
) -> None:
    clock = Clock()
    auth = notes_server(clock)
    fake = McpFake(authorize=auth.access_ok)
    script = Script([ACCEPT])
    with deployed(tmp_path, ca, auth, fake, clock, link) as gateway, gateway.running() as running:
        # The CLI paste: a PKCE login that asks for the server as the token's audience.
        code, out, err = login(gateway, ca)
        assert (code, err) == (0, "")
        assert f"Stored the refresh token for {CREDENTIAL} as {SLOT}.\n" in out
        [url] = PRINTED_URL.findall(out)
        check_the_login(auth, url)
        await the_calls(gateway, running, auth, fake, clock, script)
    check_the_calls(gateway, fake, script)


@pytest.mark.parametrize("link", LINKS)
async def test_a_portal_connect_by_paste_then_the_same_calls(
    tmp_path: Path, ca: ProviderCA, link: str
) -> None:
    """D-116's portal variant (M5 design step 14a): the operator connects in the portal."""
    clock = Clock()
    auth = notes_server(clock)
    fake = McpFake(authorize=auth.access_ok)
    script = Script([ACCEPT])
    with (
        deployed(tmp_path, ca, auth, fake, clock, link, portal=True) as gateway,
        gateway.running() as running,
    ):
        url = portal_login(gateway, ca)
        check_the_login(auth, url)
        await the_calls(gateway, running, auth, fake, clock, script)
    check_the_calls(gateway, fake, script)
    confirmed = gateway.seen.events("step_up_confirmed")
    assert [line["action"] for line in confirmed] == ["oauth.complete"]


async def the_calls(
    gateway: GatewayDeployment,
    running: Running,
    auth: FakeAuthServer,
    fake: McpFake,
    clock: Clock,
    script: Script,
) -> None:
    """With the grant stored: calls, two refreshes that rotate, a refused token, an approval."""
    first = auth.active_refresh_token()
    async with agent(running.mcp(), script=script, headers=mcp_headers()) as client:
        listed = await client.list_tools()
        assert sorted(tool.name for tool in listed.tools) == sorted(TOOLS.values())
        assert text(await client.call_tool("echo", {"text": "before"})) == "before"
        assert len(auth.calls) == 1  # the login's access token is used
        await listening(gateway.seen, fake)

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


def check_the_calls(gateway: GatewayDeployment, fake: McpFake, script: Script) -> None:
    [prompt] = script.prompts
    assert "Tool: notes \N{RIGHTWARDS ARROW} add" in prompt.message
    assert [(call.name, call.arguments) for call in fake.calls] == [
        *(("echo", {"text": word}) for word in ("before", "refreshed", "rotated", "after")),
        ("add", {"a": 2, "b": 3}),
    ]
    # The refused call reached the server once, and was never sent again. Every call carried an
    # access token from the authorization server, a new one after each refresh.
    calls = fake.requests("tools/call")
    arguments = [item.params["arguments"] for item in calls]
    assert arguments.count({"text": "refused"}) == 1
    assert [item.params["arguments"] for item in calls if item.status == 401] == [
        {"text": "refused"}
    ]
    tokens = [str(item.header("authorization")).removeprefix("Bearer ") for item in calls]
    assert all(ISSUED.fullmatch(token) for token in tokens)
    assert len(set(tokens)) == 4
    # Nothing else met a dropped or expired token (see listening()): the server refused the one
    # POST, which the vault answered for once, dropping the token, and only the next request
    # refreshed because of it.
    rejections = gateway.seen.events("oauth_upstream_401")
    refused = [
        {"method": item.method, "rpc": item.rpc_method, "id": rpc_id(item.message)}
        for item in fake.received
        if item.status == 401
    ]
    triggers = refresh_triggers(gateway.seen)
    detail = json.dumps({"vault": rejections, "server": refused, "triggers": triggers}, indent=1)
    answered = [(line["method"], line["action"]) for line in rejections]
    assert answered == [("POST", "invalidated")], detail
    assert [(item["method"], item["rpc"]) for item in refused] == [("POST", "tools/call")], detail
    assert triggers == ["expiry", "expiry", "upstream_401"], detail


def rpc_id(message: Any) -> Any:
    return message.get("id") if isinstance(message, dict) else None


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
