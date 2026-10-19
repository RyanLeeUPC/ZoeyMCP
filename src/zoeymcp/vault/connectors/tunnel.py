"""The CONNECT tunnel through the egress proxy, as pure decisions (M4 design J.4 step 1).

The request asks for exactly the connector's host and port. The reply head is read byte by byte
up to the blank line, so a mail server's greeting sent right behind the ``200`` is never swallowed,
and it must be ``200`` within :data:`MAX_HEAD_BYTES`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

MAX_HEAD_BYTES = 8 * 1024
END = b"\r\n\r\n"
_STATUS = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?$")


@dataclass(frozen=True)
class Reply:
    """What the proxy's reply head says: open (200), refused (any other status), or broken."""

    kind: Literal["open", "refused", "broken"]
    status: int | None = None


def connect_request(host: str, port: int) -> bytes:
    target = f"{host}:{port}".encode("ascii")
    return b"CONNECT " + target + b" HTTP/1.1\r\nHost: " + target + b"\r\n\r\n"


def head_complete(head: bytes) -> bool:
    """Whether the bytes read so far end the reply head."""
    return head.endswith(END)


def parse_connect_reply(head: bytes) -> Reply:
    """The proxy's answer, from its whole reply head (status line, headers, blank line)."""
    if len(head) > MAX_HEAD_BYTES or not head_complete(head):
        return Reply("broken")
    status_line = head.split(b"\r\n", 1)[0]
    match = _STATUS.fullmatch(status_line)
    if match is None:
        return Reply("broken")
    status = int(match.group(1))
    return Reply("open", status) if status == 200 else Reply("refused", status)
