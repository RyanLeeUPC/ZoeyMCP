"""A small in-process world for onboarding by URL (M7 design D.2, D.3), for the tests of the
surfaces around the service: the admin socket, the no-secret walk and the leak sweep.

One ``httpx.MockTransport`` answers as an MCP server that asks for a token and publishes its
protected-resource metadata, and as its authorization server's metadata; the endpoint check's
names answer an address the guard calls global. No network, no sleep. The service's own effect
tests, through the real fakes over TLS and the guard, are ``test_onboard_service.py``'s.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx

from zoeymcp.common.policy import Policy
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.onboard import OnboardService
from zoeymcp.vault.store import SecretStore

SERVER_URL = "https://mcp.notes.example/mcp"
ISSUER = "https://auth.notes.example"
PRM_URL = "https://mcp.notes.example/.well-known/oauth-protected-resource/mcp"
AS_URL = "https://auth.notes.example/.well-known/oauth-authorization-server"
CLIENT_ID = "notes-given-client"
# A given client secret, planted for the sweeps to look for.
GIVEN_SECRET = "onboard-given-secret-value-0001"
SECRET_NAME = "notes-client-secret"
# An address netguard calls global (tests/fakes/resolver.py's range).
GLOBAL = "11.0.0.1"


class Body(httpx.AsyncByteStream):
    """An answer's body as a server streams it, so the vault reads it raw."""

    def __init__(self, content: bytes) -> None:
        self.content = content

    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield self.content


def metadata() -> dict[str, Any]:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
        "authorization_response_iss_parameter_supported": True,
        "scopes_supported": ["notes.read", "offline_access"],
    }


def handler(request: httpx.Request) -> httpx.Response:
    """The MCP server and its authorization server, by URL."""
    url = str(request.url)
    if request.method == "POST" and url == SERVER_URL:
        challenge = f'Bearer resource_metadata="{PRM_URL}", scope="notes.read"'
        return httpx.Response(401, headers={"www-authenticate": challenge})
    documents = {
        PRM_URL: {
            "resource": SERVER_URL,
            "authorization_servers": [ISSUER],
            "scopes_supported": ["notes.read"],
        },
        AS_URL: metadata(),
    }
    if request.method == "GET" and url in documents:
        body = Body(json.dumps(documents[url]).encode())
        return httpx.Response(200, headers={"content-type": "application/json"}, stream=body)
    return httpx.Response(404)


async def resolve(host: str, port: int) -> list[str]:
    return [GLOBAL]


def onboard_service(
    store: SecretStore, tokens: TokenManager | None, policy: Callable[[], Policy]
) -> OnboardService:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    return OnboardService(
        store, tokens, policy, client, source="examples/policy.yaml", resolver=resolve
    )


def confidential() -> dict[str, Any]:
    """The discovery of a given confidential client: its client ID, issuer and a secret."""
    return {"url": SERVER_URL, "client_id": CLIENT_ID, "issuer": ISSUER, "secret_given": True}
