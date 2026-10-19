"""A fake records API for the S16 batch-tool shape (M4 design M.5, N.1), as an ASGI app.

``GET /v1/records/{id}``, ``POST /v1/records/batch`` and ``POST /v1/records/archive``, behind a
header credential. There is deliberately no DELETE. Switches fail one item, store one item
differently (so a read-back differs), or slow every answer down.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

from starlette.types import Receive, Scope, Send

SECRET = "records-key-0001"  # test-only
_RECORD = re.compile(r"^/v1/records/([A-Za-z0-9_-]{1,64})$")


@dataclass
class RecordsApi:
    fail_item: int | None = None  # this index of a batch is refused
    differ_item: int | None = None  # this index is stored with another title
    slow: float = 0.0
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    archived: list[str] = field(default_factory=list)
    requests: list[tuple[str, str]] = field(default_factory=list)
    in_flight: int = 0
    max_in_flight: int = 0

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return
        method, path = scope["method"], scope["path"]
        self.requests.append((method, path))
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            if self.slow:
                await asyncio.sleep(self.slow)
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            if headers.get("authorization") != f"Bearer {SECRET}":
                await _answer(send, 401, {"error": "unauthorized"})
                return
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"")
                if not message.get("more_body"):
                    break
            await self._route(method, path, body, send)
        finally:
            self.in_flight -= 1

    async def _route(self, method: str, path: str, body: bytes, send: Send) -> None:
        found = _RECORD.fullmatch(path)
        if method == "GET" and found is not None:
            record = self.records.get(found.group(1))
            if record is None:
                await _answer(send, 404, {"error": "no such record"})
            else:
                await _answer(send, 200, record)
            return
        if method == "POST" and path == "/v1/records/batch":
            created = []
            for index, item in enumerate(json.loads(body)["records"]):
                if index == self.fail_item:
                    created.append({"index": index, "error": "refused"})
                    continue
                record_id = f"r{len(self.records) + 1:04d}"
                stored = dict(item)
                if index == self.differ_item:
                    stored["title"] = stored["title"] + " (changed)"
                self.records[record_id] = {"id": record_id, **stored}
                created.append({"index": index, "id": record_id})
            await _answer(send, 200, {"created": created})
            return
        if method == "POST" and path == "/v1/records/archive":
            ids = json.loads(body)["ids"]
            self.archived.extend(ids)
            await _answer(send, 200, {"archived": len(ids)})
            return
        await _answer(send, 405 if method == "DELETE" else 404, {"error": "not here"})


async def _answer(send: Send, status: int, data: Any) -> None:
    body = json.dumps(data).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})
