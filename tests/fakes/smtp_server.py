"""A fake SMTP server for the connector's tests (M4 design N.1). asyncio only, no new dependency.

It speaks implicit TLS (port 465 style) or STARTTLS (587 style) with certificates from the test
CA, accepts AUTH PLAIN and LOGIN, and records everything a test checks: each command, whether TLS
was up when AUTH came, the EHLO name, the envelope and the message. :class:`Switch` turns on each
misbehaviour the connector must survive without sending, or without sending twice.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import enum
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from tests.acceptance.tls import ProviderCA, issue_cert

USERNAME = "agent@mail.example"
PASSWORD = "app-password-0001"  # test-only


class Switch(enum.Enum):
    NO_STARTTLS = "no_starttls"  # EHLO leaves STARTTLS out
    STARTTLS_454 = "starttls_454"  # STARTTLS answered 454
    WRONG_NAME = "wrong_name"  # the certificate names another host
    AUTH_ONLY_BEFORE_TLS = "auth_only_before_tls"  # AUTH advertised only before TLS
    AUTH_535 = "auth_535"  # every AUTH refused
    REJECT_ONE_RCPT = "reject_one_rcpt"  # the second recipient gets 550
    DROP_AFTER_DOT = "drop_after_dot"  # hang up after the final dot, before replying
    HANG_AFTER_DOT = "hang_after_dot"  # never reply to the final dot
    SLOW = "slow"  # every reply waits a little
    ECHO_USERNAME = "echo_username"  # the AUTH reply text echoes the username


@dataclass
class Session:
    """One connection, as the server saw it."""

    commands: list[str] = field(default_factory=list)
    ehlo: list[str] = field(default_factory=list)
    tls_at_auth: list[bool] = field(default_factory=list)
    mail_from: str | None = None
    rcpt_to: list[str] = field(default_factory=list)
    data: bytes | None = None
    tls: bool = False


@dataclass
class SmtpFake:
    ca: ProviderCA
    mode: Literal["implicit", "starttls"] = "implicit"
    switches: set[Switch] = field(default_factory=set)
    name: str = "localhost"
    sessions: list[Session] = field(default_factory=list)
    _loop: asyncio.AbstractEventLoop | None = None
    _context: ssl.SSLContext | None = None

    @property
    def messages(self) -> list[bytes]:
        return [s.data for s in self.sessions if s.data is not None]

    def context(self, directory: Path) -> ssl.SSLContext:
        if Switch.WRONG_NAME in self.switches:
            cert, key = issue_cert(self.ca, "other.example", directory)
        else:
            cert, key = issue_cert(self.ca, self.name, directory)
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(str(cert), str(key))
        return context

    async def _reply(self, writer: asyncio.StreamWriter, line: str) -> None:
        if Switch.SLOW in self.switches:
            await asyncio.sleep(0.2)
        writer.write(line.encode() + b"\r\n")
        await writer.drain()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        session = Session(tls=self.mode == "implicit")
        self.sessions.append(session)
        try:
            await self._reply(writer, "220 fake.mail.example ESMTP ready")
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                line = raw.decode(errors="replace").rstrip("\r\n")
                session.commands.append(line)
                verb = line.split(" ", 1)[0].upper()
                if verb in ("EHLO", "HELO"):
                    session.ehlo.append(line.partition(" ")[2])
                    await self._ehlo(writer, session)
                elif verb == "STARTTLS":
                    if Switch.STARTTLS_454 in self.switches or self.mode != "starttls":
                        await self._reply(writer, "454 TLS not available")
                        continue
                    await self._reply(writer, "220 go ahead")
                    assert self._context is not None
                    await writer.start_tls(self._context)
                    session.tls = True
                elif verb == "AUTH":
                    await self._auth(reader, writer, session, line)
                elif verb == "MAIL":
                    session.mail_from = line.partition(":")[2].strip().strip("<>")
                    await self._reply(writer, "250 OK")
                elif verb == "RCPT":
                    address = line.partition(":")[2].strip().strip("<>")
                    if Switch.REJECT_ONE_RCPT in self.switches and len(session.rcpt_to) == 1:
                        await self._reply(writer, "550 no such user")
                        continue
                    session.rcpt_to.append(address)
                    await self._reply(writer, "250 OK")
                elif verb == "RSET":
                    session.mail_from, session.rcpt_to = None, []
                    await self._reply(writer, "250 OK")
                elif verb == "DATA":
                    await self._reply(writer, "354 end with <CRLF>.<CRLF>")
                    data = b""
                    while True:
                        chunk = await reader.readline()
                        if not chunk:
                            return
                        if chunk == b".\r\n":
                            break
                        data += chunk
                    session.data = data
                    if Switch.DROP_AFTER_DOT in self.switches:
                        return
                    if Switch.HANG_AFTER_DOT in self.switches:
                        await asyncio.sleep(3600)
                    await self._reply(writer, "250 2.0.0 queued as FAKE1")
                elif verb == "QUIT":
                    await self._reply(writer, "221 bye")
                    return
                elif verb == "NOOP":
                    await self._reply(writer, "250 OK")
                else:
                    await self._reply(writer, "502 not implemented")
        except (ConnectionError, ssl.SSLError, asyncio.IncompleteReadError):
            return
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _ehlo(self, writer: asyncio.StreamWriter, session: Session) -> None:
        lines = ["fake.mail.example"]
        if self.mode == "starttls" and not session.tls and Switch.NO_STARTTLS not in self.switches:
            lines.append("STARTTLS")
        advertise_auth = session.tls != (Switch.AUTH_ONLY_BEFORE_TLS in self.switches)
        if advertise_auth:
            lines.append("AUTH PLAIN LOGIN")
        lines.append("8BITMIME")
        for index, item in enumerate(lines):
            await self._reply(writer, f"250{'-' if index < len(lines) - 1 else ' '}{item}")

    async def _auth(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session: Session,
        line: str,
    ) -> None:
        session.tls_at_auth.append(session.tls)
        parts = line.split(" ")
        mechanism = parts[1].upper() if len(parts) > 1 else ""
        username = password = ""
        if mechanism == "PLAIN":
            encoded = parts[2] if len(parts) > 2 else ""
            if not encoded:
                await self._reply(writer, "334 ")
                encoded = (await reader.readline()).decode().strip()
            pieces = base64.b64decode(encoded).split(b"\0")
            if len(pieces) == 3:
                username, password = pieces[1].decode(), pieces[2].decode()
        elif mechanism == "LOGIN":
            if len(parts) > 2:
                username = base64.b64decode(parts[2]).decode()
            else:
                await self._reply(writer, "334 VXNlcm5hbWU6")
                username = base64.b64decode((await reader.readline()).strip()).decode()
            await self._reply(writer, "334 UGFzc3dvcmQ6")
            password = base64.b64decode((await reader.readline()).strip()).decode()
        echoed = f" for {username}" if Switch.ECHO_USERNAME in self.switches else ""
        if Switch.AUTH_535 in self.switches or (username, password) != (USERNAME, PASSWORD):
            await self._reply(writer, f"535 authentication failed{echoed}")
            return
        await self._reply(writer, f"235 authenticated{echoed}")


@contextmanager
def serve_smtp(fake: SmtpFake, directory: Path) -> Iterator[tuple[str, int]]:
    """Run ``fake`` on 127.0.0.1 in its own thread; yields (host, port)."""
    fake._context = fake.context(directory)
    started = threading.Event()
    port: list[int] = []
    stop: list[asyncio.Event] = []

    async def main() -> None:
        fake._loop = asyncio.get_running_loop()
        stop.append(asyncio.Event())
        ssl_context = fake._context if fake.mode == "implicit" else None
        server = await asyncio.start_server(fake._handle, "127.0.0.1", 0, ssl=ssl_context)
        port.append(server.sockets[0].getsockname()[1])
        started.set()
        async with server:
            await stop[0].wait()

    thread = threading.Thread(target=lambda: asyncio.run(main()), daemon=True)
    thread.start()
    if not started.wait(10):
        raise RuntimeError("the fake SMTP server didn't start")
    try:
        yield "127.0.0.1", port[0]
    finally:
        loop = fake._loop
        if loop is not None:
            loop.call_soon_threadsafe(stop[0].set)
        thread.join(5)
