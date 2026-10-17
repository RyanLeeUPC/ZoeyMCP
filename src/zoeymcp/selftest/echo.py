"""The built-in echo upstream: records every request, answers ``200 {"ok": true}``."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote

from starlette.types import Receive, Scope, Send


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
