"""The built-in echo upstream and token endpoint for self-tests.

:class:`EchoUpstream` records every request and answers ``200 {"ok": true}``. :class:`TokenEcho`
plays every token endpoint of the policy: it mints a dummy access token for the rig's dummy client
and refresh token, sent the way the credential says, and refuses anything else.
"""

from __future__ import annotations

import base64
import binascii
import json
import secrets
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, unquote_plus

import httpx
from starlette.types import Receive, Scope, Send

from ..vault.store import canonical_origin


@dataclass(frozen=True)
class Received:
    method: str
    path: str
    query: list[tuple[str, str]]
    headers: list[tuple[str, str]]
    body: bytes

    def header(self, name: str) -> str | None:
        values = [v for k, v in self.headers if k == name.lower()]
        return values[0] if values else None


@dataclass
class EchoUpstream:
    received: list[Received] = field(default_factory=list)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        raw_path = scope.get("raw_path") or scope["path"].encode()
        self.received.append(
            Received(
                method=scope["method"],
                path=unquote(raw_path.decode("ascii", "replace")),
                query=parse_qsl(
                    scope["query_string"].decode("ascii", "replace"), keep_blank_values=True
                ),
                headers=[
                    (k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope["headers"]
                ],
                body=body,
            )
        )
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b'{"ok":true}'})


_CHECKED = ("grant_type", "refresh_token", "client_id", "client_secret")


def endpoint_key(url: str) -> tuple[str, str]:
    """A token endpoint as dispatch compares it: the canonical origin and the raw path."""
    parsed = httpx.URL(url)
    return canonical_origin(url), parsed.raw_path.split(b"?")[0].decode("ascii")


def _scope_key(scope: Scope) -> tuple[str, str] | None:
    host, port = scope.get("server") or (None, None)
    if not host:
        return None
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    try:
        origin = canonical_origin(f"{scope['scheme']}://{netloc}")
    except ValueError:
        return None
    raw_path: bytes = scope.get("raw_path") or scope["path"].encode()
    return origin, raw_path.decode("ascii", "replace")


@dataclass(frozen=True)
class TokenClient:
    """What one oauth2 credential must send to its token endpoint, with the rig's dummies."""

    credential: str
    token_url: str
    grant: str
    auth: str
    body: str
    client_id: str
    client_secret: str | None = field(default=None, repr=False)
    refresh_token: str | None = field(default=None, repr=False)


@dataclass
class TokenEcho:
    """Every token endpoint of the policy. It never rotates a refresh token.

    A POST is accepted only when the client authenticates the way ``auth`` says (Basic with the
    RFC 6749 encoding, in the body, or the client ID alone) in the body format the credential
    uses, and presents the dummy refresh token. Otherwise it answers 401 ``invalid_client`` or
    400 ``invalid_grant``.
    """

    clients: list[TokenClient]
    # The last access token issued per credential, and every one issued.
    last_issued: dict[str, str] = field(default_factory=dict)
    issued: list[str] = field(default_factory=list)
    calls: int = 0

    def __post_init__(self) -> None:
        self._endpoints = {endpoint_key(c.token_url) for c in self.clients}

    def handles(self, scope: Scope) -> bool:
        """A POST to one of the policy's token URLs (origin and path)."""
        return scope.get("method") == "POST" and _scope_key(scope) in self._endpoints

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        self.calls += 1
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        key = _scope_key(scope)
        candidates = [c for c in self.clients if endpoint_key(c.token_url) == key]
        status, answer = self._answer(candidates, headers, body)
        payload = json.dumps(answer).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": payload})

    def _answer(
        self, candidates: Iterable[TokenClient], headers: dict[str, str], body: bytes
    ) -> tuple[int, dict[str, Any]]:
        known_client = False
        for client in candidates:
            params = _params(client.body, headers.get("content-type", ""), body)
            if params is None or not _client_ok(client, headers, params):
                continue
            known_client = True
            if params.get("grant_type") != client.grant:
                continue
            if client.grant == "refresh_token" and params.get("refresh_token") != (
                client.refresh_token
            ):
                continue
            token = f"selftest-at-{secrets.token_hex(8)}"
            self.last_issued[client.credential] = token
            self.issued.append(token)
            return 200, {"access_token": token, "token_type": "Bearer", "expires_in": 3600}
        if known_client:
            return 400, {"error": "invalid_grant"}
        return 401, {"error": "invalid_client"}


def _params(kind: str, content_type: str, body: bytes) -> dict[str, Any] | None:
    """The request's parameters, if it's in the body format the credential uses."""
    media = content_type.split(";", 1)[0].strip().lower()
    if kind == "json":
        if media != "application/json":
            return None
        try:
            data = json.loads(body)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None
    if media != "application/x-www-form-urlencoded":
        return None
    pairs = parse_qsl(body.decode("ascii", "replace"), keep_blank_values=True)
    names = [name for name, _ in pairs]
    # extra_params may repeat (a list of resources); the checked parameters may not.
    if any(names.count(name) > 1 for name in _CHECKED):
        return None
    return dict(pairs)


def _client_ok(client: TokenClient, headers: dict[str, str], params: dict[str, Any]) -> bool:
    authorization = headers.get("authorization")
    if client.auth == "basic":
        if authorization is None or "client_secret" in params:
            return False
        scheme, _, encoded = authorization.partition(" ")
        if scheme.lower() != "basic":
            return False
        try:
            decoded = base64.b64decode(encoded, validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError):
            return False
        user, sep, password = decoded.partition(":")
        return (
            bool(sep)
            and client.client_secret is not None
            and (unquote_plus(user), unquote_plus(password))
            == (client.client_id, client.client_secret)
        )
    if authorization is not None or params.get("client_id") != client.client_id:
        return False
    if client.auth == "post":
        secret = params.get("client_secret")
        return client.client_secret is not None and secret == client.client_secret
    return "client_secret" not in params
