"""The egress role's allowlists, long-polled from the vault (M7 design I.4, G.2, G.3, X15).

The role asks ``GET /_zoeymcp/egress/v1/allowlists`` with the egress key in
``x-zoeymcp-egress``; once it holds a list it sends ``If-None-Match`` with the list's digest and
``?wait=25``, so the vault answers 200 with new lists as soon as they change, or 304. Each 200
or 304 is contact. The lists serve until no contact has come for 300 s: then every new tunnel is
refused (``list_stale``) until contact resumes (fail closed, Q25), and ``egress_allowlist_stale``
is logged once. A document that doesn't parse is refused and the last good one stays, still
going stale on time; a destination in it whose host no CONNECT could name (one the vault keeps
as written because IDNA refuses it, D-190) is skipped and counted, since the role would refuse
it anyway. Failures back off 1, 2, 4 ... 30 s, jittered, and the first request after a failure
doesn't wait, so the role is back within 30 s of the vault's return (FM-26). The connect has its
own 10 s, and the held poll's socket sends TCP keepalives, so a vault that vanishes without
closing it (a killed container) fails the poll within :data:`KEEPALIVE_LIMIT` rather than at
the request's end. SIGHUP re-reads the key file and fetches at once.

The key comes from ``ZOEYMCP_EGRESS_KEY`` or a file named by ``ZOEYMCP_EGRESS_KEY_FILE``,
re-read on SIGHUP and after a 403 (at most once per 10 s). It grants the lists and nothing else;
its wrapper refuses to be logged. The HTTP client is the standard library's streams: the role
may import nothing else (``EGRESS_SIDE``).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import re
import socket
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

from ..common import netguard
from ..common.logs import refuse_type
from . import event
from .connect import CONNECT_TIMEOUT, Lists
from .listen import SOURCE

PATH: Final = "/_zoeymcp/egress/v1/allowlists"
HEADER: Final = "x-zoeymcp-egress"
KEY_ENV: Final = "ZOEYMCP_EGRESS_KEY"
KEY_FILE_ENV: Final = "ZOEYMCP_EGRESS_KEY_FILE"
KEY_PATTERN = re.compile(r"zeg1-[A-Za-z0-9_-]{43}")
KEY_RELOAD_INTERVAL: Final = 10.0  # at most one re-read of the key file per this, after a 403
# M7 design M.6.
ALLOWLIST_WAIT: Final = 25
ALLOWLIST_MAX_STALE: Final = 300.0
BACKOFF_START: Final = 1.0
BACKOFF_MAX: Final = 30.0
# How long one request may take beyond the vault's wait, and how large its answer may be.
REQUEST_SLACK: Final = 15.0
ANSWER_HEAD_MAX: Final = 16 * 1024
DOCUMENT_MAX: Final = 4 * 1024 * 1024
# The held poll's TCP keepalive: probes after this many idle seconds, this far apart, this many.
KEEPALIVE_IDLE: Final = 5
KEEPALIVE_INTERVAL: Final = 5
KEEPALIVE_COUNT: Final = 2
KEEPALIVE_LIMIT: Final = KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_COUNT
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
# A destination's host a CONNECT could name: a name (253 characters and a trailing dot at most),
# an IPv4 address, or an IPv6 one without brackets (netguard.entry_key adds them).
_HOST = re.compile(r"[A-Za-z0-9._:-]{1,253}\.?")
_LENGTH = re.compile(r"[0-9]{1,10}")


class AllowlistError(ValueError):
    """A ``--vault`` value or an egress key the role can't use; safe to print."""


class DocumentError(ValueError):
    """An answer from the vault that isn't a usable allowlist document."""


# --- the key ------------------------------------------------------------------------------------


class EgressKey:
    """The egress key. Its ``repr`` hides it, and logging it raises (M7 design M.5)."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if KEY_PATTERN.fullmatch(value) is None:
            raise AllowlistError("the egress key isn't in the zeg1- format")
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "EgressKey(***)"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, EgressKey) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


refuse_type(EgressKey)


class KeySource:
    """Where the key comes from: a value read once, or a file re-read on SIGHUP and after the
    vault refuses the key (at most once per :data:`KEY_RELOAD_INTERVAL`)."""

    def __init__(
        self,
        value: str | None = None,
        file: Path | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._file = file
        self._clock = clock
        self._last_reload: float | None = None
        if file is not None:
            self._key = self._read()
        elif value is not None:
            self._key = EgressKey(value)
        else:
            raise AllowlistError(
                f"no egress key: set {KEY_ENV} (or {KEY_FILE_ENV}) to what zoeymcp egress-key "
                "prints in the vault's container"
            )

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> KeySource:
        file = environ.get(KEY_FILE_ENV)
        return cls(environ.get(KEY_ENV) or None, Path(file) if file else None)

    def current(self) -> EgressKey:
        return self._key

    def _read(self) -> EgressKey:
        if self._file is None:
            raise AllowlistError("no egress key file is configured")
        try:
            text = self._file.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise AllowlistError("the egress key file can't be read") from exc
        return EgressKey(text.strip())

    def reload(self) -> bool:
        """Re-read the key file now. Returns whether the key changed; a bad file keeps the old."""
        if self._file is None:
            return False
        self._last_reload = self._clock()
        try:
            key = self._read()
        except AllowlistError as exc:
            event("egress_key_unreadable", reason=str(exc))
            return False
        changed = key != self._key
        self._key = key
        return changed

    def after_refusal(self) -> bool:
        """The vault refused the key: re-read the file, unless that was done just now."""
        now = self._clock()
        if self._last_reload is not None and now - self._last_reload < KEY_RELOAD_INTERVAL:
            return False
        return self.reload()


# --- the vault and its document -----------------------------------------------------------------


def parse_vault(spec: str) -> tuple[str, int]:
    """``--vault http://host[:port]``: the vault's TCP listener, port 80 unless given."""
    parts = urlsplit(spec)
    if parts.scheme != "http" or not parts.hostname:
        raise AllowlistError("--vault is http://host[:port], the vault's listener")
    # urlsplit reports a trailing "?" or "#" as no query and no fragment.
    if (
        parts.username
        or parts.password
        or parts.path not in ("", "/")
        or "?" in spec
        or "#" in spec
    ):
        raise AllowlistError("--vault is http://host[:port], with no path, query or user")
    try:
        port = parts.port
    except ValueError as exc:
        raise AllowlistError("--vault's port is invalid") from exc
    return parts.hostname, 80 if port is None else port


def parse_document(body: bytes) -> tuple[str, dict[str, dict[str, bool]], int]:
    """The digest, every source's list (``entry_key`` to its private mark) and how many
    destinations were skipped, from the vault's answer (G.2: ``{"v": 1, "digest": ...,
    "sources": {source: [{host, port, private}]}}``). A destination whose host no CONNECT could
    name is skipped, not refused: :func:`.connect.admit` would refuse every tunnel to it anyway,
    and one such route mustn't cost every source its list."""
    try:
        document = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        raise DocumentError("not JSON") from exc
    version = document.get("v") if isinstance(document, dict) else None
    if type(version) is not int or version != 1:
        raise DocumentError("not a version 1 allowlist document")
    digest, sources = document.get("digest"), document.get("sources")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise DocumentError("the digest isn't sha256:<hex>")
    if not isinstance(sources, dict):
        raise DocumentError("sources isn't an object")
    lists: dict[str, dict[str, bool]] = {}
    skipped = 0
    for source, entries in sources.items():
        if not SOURCE.fullmatch(source) or not isinstance(entries, list):
            raise DocumentError("a source isn't a name with a list")
        found: dict[str, bool] = {}
        for entry in entries:
            parsed = _entry(entry)
            if parsed is None:
                skipped += 1
                continue
            key, private = parsed
            if key in found:
                raise DocumentError(f"{source} lists {key} twice")
            found[key] = private
        lists[source] = found
    return digest, lists, skipped


def _entry(entry: Any) -> tuple[str, bool] | None:
    """A destination's key and private mark; None for a host no CONNECT could name."""
    if not isinstance(entry, dict):
        raise DocumentError("a destination isn't an object")
    host, port, private = entry.get("host"), entry.get("port"), entry.get("private")
    if not isinstance(host, str):
        raise DocumentError("a destination's host isn't text")
    if type(port) is not int or not 0 < port < 65536:
        raise DocumentError("a destination's port isn't 1 to 65535")
    if type(private) is not bool:
        raise DocumentError("a destination's private mark isn't true or false")
    if not _HOST.fullmatch(host):
        return None
    return netguard.entry_key(host, port), private


def _answer_head(head: bytes) -> tuple[int, int | None]:
    """The status and Content-Length of an answer head; None for no length."""
    lines = head.decode("latin-1").removesuffix("\r\n\r\n").split("\r\n")
    version, _, rest = lines[0].partition(" ")
    status = rest[:3]
    if not version.startswith("HTTP/1.") or not status.isdigit():
        raise DocumentError("not an HTTP/1 answer")
    length: int | None = None
    for line in lines[1:]:
        name, _, value = line.partition(":")
        name, value = name.strip().lower(), value.strip()
        if name == "transfer-encoding":
            raise DocumentError("a chunked answer")
        if name == "content-length":
            if not _LENGTH.fullmatch(value) or int(value) > DOCUMENT_MAX:
                raise DocumentError("the answer's length isn't usable")
            length = int(value)
    return int(status), length


def backoff(failures: int, jitter: float) -> float:
    """1, 2, 4 ... seconds after the ``failures``-th failure in a row, times ``jitter`` (0.5 to
    1.5), and never more than 30 s."""
    return min(BACKOFF_MAX, BACKOFF_START * float(2 ** min(failures - 1, 5)) * jitter)


def _jitter() -> float:
    return random.uniform(0.5, 1.5)  # noqa: S311 - spreads retries, not a secret


def _keepalive(sock: Any) -> None:
    """Turn on TCP keepalive with :data:`KEEPALIVE_IDLE`, :data:`KEEPALIVE_INTERVAL` and
    :data:`KEEPALIVE_COUNT`, where the platform has those options."""
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    for name, value in (
        ("TCP_KEEPIDLE", KEEPALIVE_IDLE),
        ("TCP_KEEPINTVL", KEEPALIVE_INTERVAL),
        ("TCP_KEEPCNT", KEEPALIVE_COUNT),
    ):
        option = getattr(socket, name, None)
        if option is not None:
            with contextlib.suppress(OSError):
                sock.setsockopt(socket.IPPROTO_TCP, option, value)


# --- the poll -------------------------------------------------------------------------------------


class Allowlist:
    """The lists the role holds, and the long poll that keeps them."""

    def __init__(
        self,
        vault: str,
        key: KeySource,
        *,
        clock: Callable[[], float] = time.monotonic,
        wait: int = ALLOWLIST_WAIT,
        on_apply: Callable[[Lists], None] = lambda lists: None,
        on_contact: Callable[[], None] = lambda: None,
        jitter: Callable[[], float] | None = None,
    ) -> None:
        self._host, self._port = parse_vault(vault)
        self._authority = netguard.entry_key(self._host, self._port)
        self._key = key
        self._clock = clock
        self._wait = wait
        self._on_apply = on_apply
        self._on_contact = on_contact
        self._jitter = jitter or _jitter
        self.lists: Lists | None = None
        self.digest: str | None = None
        self.last_contact: float | None = None
        self._since = clock()
        self._failures = 0
        self._stale_reported = False
        self._wake: asyncio.Event | None = None

    @property
    def vault(self) -> str:
        return self._authority

    def fresh(self) -> Lists | None:
        """The lists, while the last contact is at most 300 s old; else None, logging
        ``egress_allowlist_stale`` the first time."""
        age = self._clock() - (self._since if self.last_contact is None else self.last_contact)
        if age > ALLOWLIST_MAX_STALE:
            if not self._stale_reported:
                self._stale_reported = True
                event("egress_allowlist_stale", age_s=round(age, 1), digest=self.digest)
            return None
        return self.lists

    def refresh(self) -> None:
        """Fetch now, instead of waiting out a backoff (SIGHUP)."""
        if self._wake is not None:
            self._wake.set()

    def _request(self) -> bytes:
        target, lines = PATH, []
        if self.digest is not None:
            lines.append(f'If-None-Match: "{self.digest}"')
            # After a failure the vault is asked not to wait, so its return is contact at once
            # (FM-26), not up to 25 s later.
            if self._wait and not self._failures:
                target += f"?wait={self._wait}"
        head = [
            f"GET {target} HTTP/1.1",
            f"Host: {self._authority}",
            f"{HEADER}: {self._key.current().reveal()}",
            "Accept: application/json",
            "Connection: close",
            *lines,
        ]
        return ("\r\n".join(head) + "\r\n\r\n").encode("ascii")

    async def _get(self) -> tuple[int, bytes]:
        async with asyncio.timeout(CONNECT_TIMEOUT):
            reader, writer = await asyncio.open_connection(
                self._host, self._port, limit=ANSWER_HEAD_MAX
            )
        try:
            _keepalive(writer.get_extra_info("socket"))
            writer.write(self._request())
            await writer.drain()
            status, length = _answer_head(await reader.readuntil(b"\r\n\r\n"))
            if length is None and status == 200:
                raise DocumentError("an answer with no length")
            return status, await reader.readexactly(length or 0)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def fetch_once(self) -> bool:
        """One request. Returns whether it was contact (a 200 with usable lists, or a 304)."""
        try:
            async with asyncio.timeout(self._wait + REQUEST_SLACK):
                status, body = await self._get()
        except Exception as exc:  # every failure is the same to the caller
            event("egress_allowlist_failed", error_type=type(exc).__name__)
            return False
        if status == 304 and self.lists is not None:
            self._contact()
            return True
        if status != 200:
            if status == 403:
                self._key.after_refusal()
            event("egress_allowlist_failed", status=status)
            return False
        try:
            digest, lists, skipped = parse_document(body)
        except DocumentError as exc:
            event("egress_allowlist_failed", status=status, reason=str(exc))
            return False
        changed = digest != self.digest
        self.lists, self.digest = lists, digest
        if changed:
            counts = {source: len(entries) for source, entries in sorted(lists.items())}
            event("egress_allowlist_applied", digest=digest, sources=counts, skipped=skipped)
            self._on_apply(lists)
        self._contact()
        return True

    def _contact(self) -> None:
        self.last_contact = self._clock()
        self._failures = 0
        self._stale_reported = False
        self._on_contact()

    async def run(self) -> None:
        """Fetch for ever: long polls while things work, backoff while they don't. A pass that
        raises is a failure like any other, so the poll never ends while the role runs."""
        self._wake = asyncio.Event()
        while True:
            try:
                contact = await self.fetch_once()
            except Exception as exc:  # parsing or applying failed in a way no rule foresaw
                event("egress_allowlist_failed", error_type=type(exc).__name__)
                contact = False
            if contact:
                self._wake.clear()
                continue
            self.fresh()  # logs the staleness even when no tunnel is asked for
            self._failures += 1
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), backoff(self._failures, self._jitter()))
            self._wake.clear()
