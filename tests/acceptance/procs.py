"""Real ``zoeymcp`` processes, for the crash tests (M4 design N.1, H10).

A process runs ``zoeymcp.cli.main`` in a fresh interpreter, so a kill is a real kill: nothing in
the test's process can finish the work. The changes from production: certifi's bundle is the
test CA, so the vault's TLS clients (the SMTP connector included) trust the fakes; with a
hooks file the guarded clients answer names from the fake resolver's map (M7 design B.2, BP-1),
so a name reaches a loopback fake through the address guard; with a sockets directory a
bridge's socket client finds its socket there, while the policy keeps the fixed
``unix:/run/zoeymcp-bridge-<name>/mcp.sock`` (B.2's ``socket_path`` hook); with a holds file
the managed policy store holds after a write until it is killed (``tests/fakes/policyholds.py``,
M6 design O.1). ``lit`` lit M8's dark policy fields until step 18 turned them on; its slot
stays and does nothing, as ``tests/dark.py``'s ``lit()`` does (M8 design A.2 row 0, G-2). A
hooks file made by :func:`telegram_hooks` also sends ``api.telegram.org`` to the fake Bot API
(``run_telegram.py``, M8 design BP-9) and gives the Telegram surface short timings (BP-10). A
hooks file with ``review_start_grace`` sets the vault's review start grace (``vault/reviewjobs.py``,
45 s) for a vault no gateway polls, whose queued review is then refused at once (D-210). All
happen in the launcher below, never in ZoeyMCP's code.

:class:`ManagedVault` is a managed vault on one state directory, started, killed and started
again, with the host's ``zoeymcp`` commands run beside it (M6 design O.1, O.5), and, on Linux,
the gateway's link socket of the standard tier.
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
# argv: the CA file or "", the hooks file (tests/fakes/resolver.py's FakeResolver.save, with the
# Telegram surface's timings under "telegram" when telegram_hooks made it, and the review start
# grace under "review_start_grace" when a test sets it) or "",
# the bridges' sockets directory (tests/fakes/resolver.py's install_sockets) or "", the policy
# store's holds file (tests/fakes/policyholds.py's save) or "", "lit" or "" (read by nothing since
# M8 step 18 turned the dark fields on), then zoeymcp's own arguments.
LAUNCHER = f"""
import sys
import certifi
if sys.argv[1]:
    certifi.where = lambda: sys.argv[1]
if sys.argv[2] or sys.argv[3] or sys.argv[4]:
    sys.path.insert(0, {str(ROOT)!r})
if sys.argv[2]:
    import json
    from tests.fakes.resolver import install
    install(sys.argv[2])
    hooked = json.loads(open(sys.argv[2], "rb").read())
    timings = hooked.get("telegram")
    if timings:
        from zoeymcp.vault import telegram
        telegram.TIMINGS = telegram.Timings(**timings)
    if "review_start_grace" in hooked:
        from zoeymcp.vault import reviewjobs
        reviewjobs.REVIEW_START_GRACE = hooked["review_start_grace"]
if sys.argv[3]:
    from tests.fakes.resolver import install_sockets
    install_sockets(sys.argv[3])
if sys.argv[4]:
    from tests.fakes.policyholds import install as install_holds
    install_holds(sys.argv[4])
from zoeymcp.cli.main import main
sys.exit(main(sys.argv[6:]))
"""
# What a child needs from the test's environment to start at all, and nothing secret.
PASSED = ("PATH", "SYSTEMROOT", "PYTHONPATH", "TEMP", "TMP", "HOME", "USERPROFILE")


# The Bot API's name, which a hooks file sends to the fake (M8 design G.2, BP-9).
TELEGRAM_HOST = "api.telegram.org"


def telegram_hooks(
    path: Path, port: int, *, names: Mapping[str, int] | None = None, **timings: float
) -> Path:
    """A hooks file for a vault process whose Telegram approver reaches the fake Bot API on
    ``127.0.0.1:<port>`` (``run_telegram.py``, BP-9): ``api.telegram.org`` answers an address
    reserved for the run, which the dial map sends there, through the address guard unchanged.
    ``names`` sends other names to other loopback ports the same way (a route's upstream).
    ``timings`` are ``vault/telegram.py``'s ``Timings`` fields, short for a test (BP-10)."""
    from tests.fakes.resolver import FakeResolver

    resolver = FakeResolver()
    resolver.serve(TELEGRAM_HOST, port)
    for name, other in (names or {}).items():
        resolver.serve(name, other)
    resolver.save(path)
    if timings:
        document = json.loads(path.read_bytes())
        document["telegram"] = timings
        path.write_bytes(json.dumps(document, indent=2).encode() + b"\n")
    return path


# free_port's ports (D-256): above the well-known ports, outside the range the kernel hands out
# itself, and never one this run has handed out already.
PORTS_FROM = 20000
_handed: set[int] = set()
_pick = random.Random()  # noqa: S311 - spreading ports, not a secret


def ephemeral_ports() -> range:
    """The ports the kernel gives a socket bound to port 0 or connecting out: Linux's
    ``ip_local_port_range``, else the IANA dynamic range (Windows' and macOS's default)."""
    try:
        text = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text(encoding="ascii")
        low, high = (int(part) for part in text.split())
    except (OSError, ValueError):
        low, high = 49152, 65535
    return range(low, high + 1)


def free_port() -> int:
    """A port nothing listens on now, for a process to bind later (D-256). Probing port 0 handed
    out a port from the kernel's ephemeral range, which the kernel could then give to any other
    socket before the process bound it (a fake's port-0 listener, or a connection's own end),
    and the process failed ``Address already in use``. This picks outside that range instead, so
    only another explicit bind can take it, and never the same port twice in a run."""
    ephemeral = ephemeral_ports()
    spare = [
        port for port in range(PORTS_FROM, 65536) if port not in ephemeral and port not in _handed
    ]
    for port in _pick.sample(spare, min(len(spare), 64)):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:  # in use, or reserved (Windows' excluded port ranges)
                continue
        _handed.add(port)
        return port
    raise RuntimeError("no free port outside the ephemeral range")


def own_uid() -> int:
    """This process's uid, which the link socket lets in (Linux only; 0 elsewhere)."""
    if sys.platform == "win32":
        return 0
    return os.getuid()


@dataclass
class Process:
    popen: subprocess.Popen[bytes]
    log: Path

    def kill(self) -> None:
        """SIGKILL (TerminateProcess on Windows): no handler runs."""
        self.popen.kill()
        self.popen.wait(15)

    def stop(self) -> None:
        if self.popen.poll() is None:
            self.popen.terminate()
            try:
                self.popen.wait(30)
            except subprocess.TimeoutExpired:
                self.kill()

    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace")


def start(
    argv: Sequence[str],
    *,
    env: Mapping[str, str],
    log: Path,
    ca: Path | None = None,
    hooks: Path | None = None,
    sockets: Path | None = None,
    holds: Path | None = None,
    lit: bool = False,
) -> Process:
    """``zoeymcp <argv>`` in its own process, with only ``env`` and the basics. ``hooks`` is a
    fake resolver's saved map, for the guarded clients; ``sockets`` the directory that holds
    each bridge's socket, as ``zoeymcp-bridge-<name>/mcp.sock``; ``holds`` the policy store's
    holds file; ``lit`` lit M8's dark policy fields before step 18 and does nothing now."""
    environment = {name: os.environ[name] for name in PASSED if name in os.environ}
    environment.update(env)
    handle = log.open("ab")
    popen = subprocess.Popen(  # noqa: S603 - our own interpreter and arguments
        [
            sys.executable,
            "-c",
            LAUNCHER,
            str(ca or ""),
            str(hooks or ""),
            str(sockets or ""),
            str(holds or ""),
            "lit" if lit else "",
            *argv,
        ],
        env=environment,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    handle.close()
    return Process(popen, log)


def wait_port(port: int, process: Process, timeout: float = 30.0) -> None:
    """Until something listens on ``port``; fails with the process's output if it exits."""
    deadline = time.monotonic() + timeout
    while True:
        if process.popen.poll() is not None:
            raise RuntimeError(f"the process exited:\n{process.output()}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            if time.monotonic() > deadline:
                raise RuntimeError(f"nothing listened on {port}:\n{process.output()}") from None
            time.sleep(0.1)


def wait_file(path: Path, process: Process, timeout: float = 30.0) -> None:
    """Until ``path`` exists (a hold's marker); fails with the process's output if it exits."""
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.popen.poll() is not None:
            raise RuntimeError(f"the process exited:\n{process.output()}")
        if time.monotonic() > deadline:
            raise RuntimeError(f"{path.name} never appeared:\n{process.output()}")
        time.sleep(0.05)


def managed_policy(portal: int, **changes: Any) -> dict[str, Any]:
    """The smallest managed policy a vault starts with: its portal on ``portal`` (managed mode
    needs ``admin``, A.2) and one client written with a literal token, which a revision holds as
    its hash."""
    document: dict[str, Any] = {
        "version": 1,
        "mode": "managed",
        "admin": {"listen": f"127.0.0.1:{portal}", "origins": [f"http://localhost:{portal}"]},
        "gateway": {"clients": {"agent1": {"token": "managed-client-token-0001"}}},
    }
    document.update(changes)
    return document


@dataclass
class ManagedVault:
    """A vault process on ``state``, its policy in ``ZOEYMCP_CONFIG`` (``policy``, or none), its
    master key in ``env``. :meth:`start` returns once the portal listens (and, with
    ``admin_socket``, the admin socket is there); :meth:`refused` once a start refused, with its
    output. :meth:`cli` runs ``zoeymcp`` beside it, in its own process with the same environment,
    as ``docker compose run`` does with the vault's service, or ``exec`` over the admin socket."""

    tmp: Path
    env: dict[str, str]
    policy: dict[str, Any] | None = None
    port: int = field(default_factory=free_port)
    portal: int = field(default_factory=free_port)
    process: Process | None = None
    # With an admin socket (a Unix socket, so not on Windows), which :meth:`cli` reaches.
    admin_socket: bool = False
    # The CA file its TLS clients trust instead of certifi's (a route to a fake upstream).
    ca: Path | None = None
    # ZOEYMCP_CONFIG's text as given, in place of ``policy`` (a source that doesn't load).
    config: str | None = None
    # With the gateway's link socket (Linux), the standard tier's link, for this uid only.
    link_socket: bool = False
    # A fake resolver's saved map, for the guarded clients (``start``'s ``hooks``).
    hooks: Path | None = None
    # ``start``'s ``lit``, for it and for :meth:`cli`: nothing since M8 step 18 (G-2).
    lit: bool = False

    @property
    def state(self) -> Path:
        return self.tmp / "state"

    @property
    def socket(self) -> Path:
        return self.tmp / "admin" / "admin.sock"

    @property
    def link(self) -> Path:
        return self.tmp / "link" / "vault.sock"

    @property
    def log(self) -> Path:
        return self.tmp / "vault.log"

    def environ(self) -> dict[str, str]:
        found = dict(self.env)
        if self.config is not None:
            found["ZOEYMCP_CONFIG"] = self.config
        elif self.policy is not None:
            found["ZOEYMCP_CONFIG"] = json.dumps(self.policy)
        if self.admin_socket:
            found["ZOEYMCP_ADMIN_SOCKET"] = str(self.socket)
        return found

    def launch(self, *, holds: Mapping[str, Path] | None = None) -> Process:
        """The vault, without waiting; with ``holds``, each hold to its marker file."""
        self.state.mkdir(mode=0o700, exist_ok=True)
        held = None
        if holds:
            from tests.fakes.policyholds import save

            held = self.tmp / "holds.json"
            save(held, **holds)
        argv = ["vault", "--listen", f"127.0.0.1:{self.port}", "--state", str(self.state)]
        argv += ["--admin-socket", str(self.socket) if self.admin_socket else "none"]
        if self.link_socket:
            self.link.parent.mkdir(mode=0o700, exist_ok=True)
            argv += ["--gateway-socket", str(self.link), "--gateway-uid", str(own_uid())]
        self.process = start(
            argv,
            env=self.environ(),
            log=self.log,
            ca=self.ca,
            hooks=self.hooks,
            holds=held,
            lit=self.lit,
        )
        return self.process

    def start(self) -> Process:
        process = self.launch()
        wait_port(self.portal, process)
        if self.admin_socket:
            wait_file(self.socket, process)
        if self.link_socket:
            wait_file(self.link, process)
        return process

    def refused(self, timeout: float = 30.0) -> str:
        """A start that refused: its output from this start on."""
        before = len(self.output())
        process = self.launch()
        try:
            code = process.popen.wait(timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            raise RuntimeError(f"the vault started:\n{process.output()}") from None
        assert code == 2, process.output()
        return process.output()[before:]

    def kill(self) -> None:
        if self.process is not None:
            self.process.kill()

    def stop(self) -> None:
        if self.process is not None:
            self.process.stop()

    def output(self) -> str:
        return self.log.read_text(encoding="utf-8", errors="replace") if self.log.exists() else ""

    def cli(self, argv: Sequence[str], stdin: str | None = None) -> tuple[int, str, str]:
        """``zoeymcp <argv>`` beside the vault: its exit code, stdout and stderr."""
        environment = {name: os.environ[name] for name in PASSED if name in os.environ}
        environment.update(self.environ())
        done = subprocess.run(  # noqa: S603 - our own interpreter and arguments
            [sys.executable, "-c", LAUNCHER, "", "", "", "", "lit" if self.lit else "", *argv],
            env=environment,
            input=(stdin or "").encode(),
            capture_output=True,
            timeout=120,
            check=False,
        )
        # Windows writes a text stream's line breaks as CRLF.
        out, err = (stream.decode().replace("\r\n", "\n") for stream in (done.stdout, done.stderr))
        return done.returncode, out, err
