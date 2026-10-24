"""Real ``zoeymcp`` processes, for the crash tests (M4 design N.1, H10).

A process runs ``zoeymcp.cli.main`` in a fresh interpreter, so a kill is a real kill: nothing in
the test's process can finish the work. The changes from production: certifi's bundle is the
test CA, so the vault's TLS clients (the SMTP connector included) trust the fakes; with a
hooks file the guarded clients answer names from the fake resolver's map (M7 design B.2, BP-1),
so a name reaches a loopback fake through the address guard; with a sockets directory a
bridge's socket client finds its socket there, while the policy keeps the fixed
``unix:/run/zoeymcp-bridge-<name>/mcp.sock`` (B.2's ``socket_path`` hook); and with a holds file
the managed policy store holds after a write until it is killed (``tests/fakes/policyholds.py``,
M6 design O.1). All happen in the launcher below, never in ZoeyMCP's code.

:class:`ManagedVault` is a managed vault on one state directory, started, killed and started
again, with the host's ``zoeymcp`` commands run beside it (M6 design O.1, O.5).
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
# argv: the CA file or "", the hooks file (tests/fakes/resolver.py's FakeResolver.save) or "",
# the bridges' sockets directory (tests/fakes/resolver.py's install_sockets) or "", the policy
# store's holds file (tests/fakes/policyholds.py's save) or "", then zoeymcp's own arguments.
LAUNCHER = f"""
import sys
import certifi
if sys.argv[1]:
    certifi.where = lambda: sys.argv[1]
if sys.argv[2] or sys.argv[3] or sys.argv[4]:
    sys.path.insert(0, {str(ROOT)!r})
if sys.argv[2]:
    from tests.fakes.resolver import install
    install(sys.argv[2])
if sys.argv[3]:
    from tests.fakes.resolver import install_sockets
    install_sockets(sys.argv[3])
if sys.argv[4]:
    from tests.fakes.policyholds import install as install_holds
    install_holds(sys.argv[4])
from zoeymcp.cli.main import main
sys.exit(main(sys.argv[5:]))
"""
# What a child needs from the test's environment to start at all, and nothing secret.
PASSED = ("PATH", "SYSTEMROOT", "PYTHONPATH", "TEMP", "TMP", "HOME", "USERPROFILE")


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


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
) -> Process:
    """``zoeymcp <argv>`` in its own process, with only ``env`` and the basics. ``hooks`` is a
    fake resolver's saved map, for the guarded clients; ``sockets`` the directory that holds
    each bridge's socket, as ``zoeymcp-bridge-<name>/mcp.sock``; ``holds`` the policy store's
    holds file."""
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

    @property
    def state(self) -> Path:
        return self.tmp / "state"

    @property
    def socket(self) -> Path:
        return self.tmp / "admin" / "admin.sock"

    @property
    def log(self) -> Path:
        return self.tmp / "vault.log"

    def environ(self) -> dict[str, str]:
        found = dict(self.env)
        if self.policy is not None:
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
        self.process = start(argv, env=self.environ(), log=self.log, holds=held)
        return self.process

    def start(self) -> Process:
        process = self.launch()
        wait_port(self.portal, process)
        if self.admin_socket:
            wait_file(self.socket, process)
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
            [sys.executable, "-c", LAUNCHER, "", "", "", "", *argv],
            env=environment,
            input=(stdin or "").encode(),
            capture_output=True,
            timeout=120,
            check=False,
        )
        # Windows writes a text stream's line breaks as CRLF.
        out, err = (stream.decode().replace("\r\n", "\n") for stream in (done.stdout, done.stderr))
        return done.returncode, out, err
