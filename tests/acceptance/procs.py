"""Real ``zoeymcp`` processes, for the crash tests (M4 design N.1, H10).

A process runs ``zoeymcp.cli.main`` in a fresh interpreter, so a kill is a real kill: nothing in
the test's process can finish the work. The changes from production: certifi's bundle is the
test CA, so the vault's TLS clients (the SMTP connector included) trust the fakes; with a
hooks file the guarded clients answer names from the fake resolver's map (M7 design B.2, BP-1),
so a name reaches a loopback fake through the address guard; and with a sockets directory a
bridge's socket client finds its socket there, while the policy keeps the fixed
``unix:/run/zoeymcp-bridge-<name>/mcp.sock`` (B.2's ``socket_path`` hook). All happen in the
launcher below, never in ZoeyMCP's code.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# argv: the CA file or "", the hooks file (tests/fakes/resolver.py's FakeResolver.save) or "",
# the bridges' sockets directory (tests/fakes/resolver.py's install_sockets) or "", then
# zoeymcp's own arguments.
LAUNCHER = f"""
import sys
import certifi
if sys.argv[1]:
    certifi.where = lambda: sys.argv[1]
if sys.argv[2] or sys.argv[3]:
    sys.path.insert(0, {str(ROOT)!r})
if sys.argv[2]:
    from tests.fakes.resolver import install
    install(sys.argv[2])
if sys.argv[3]:
    from tests.fakes.resolver import install_sockets
    install_sockets(sys.argv[3])
from zoeymcp.cli.main import main
sys.exit(main(sys.argv[4:]))
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
) -> Process:
    """``zoeymcp <argv>`` in its own process, with only ``env`` and the basics. ``hooks`` is a
    fake resolver's saved map, for the guarded clients; ``sockets`` the directory that holds
    each bridge's socket, as ``zoeymcp-bridge-<name>/mcp.sock``."""
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
