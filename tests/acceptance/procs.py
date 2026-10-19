"""Real ``zoeymcp`` processes, for the crash tests (M4 design N.1, H10).

A process runs ``zoeymcp.cli.main`` in a fresh interpreter, so a kill is a real kill: nothing in
the test's process can finish the work. The one change from production: certifi's bundle is the
test CA, so the vault's TLS clients (the SMTP connector included) trust the fakes. That happens in
the launcher below, never in ZoeyMCP's code.
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

LAUNCHER = """
import sys
import certifi
if sys.argv[1]:
    certifi.where = lambda: sys.argv[1]
from zoeymcp.cli.main import main
sys.exit(main(sys.argv[2:]))
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
    argv: Sequence[str], *, env: Mapping[str, str], log: Path, ca: Path | None = None
) -> Process:
    """``zoeymcp <argv>`` in its own process, with only ``env`` and the basics."""
    environment = {name: os.environ[name] for name in PASSED if name in os.environ}
    environment.update(env)
    handle = log.open("ab")
    popen = subprocess.Popen(  # noqa: S603 - our own interpreter and arguments
        [sys.executable, "-c", LAUNCHER, str(ca or ""), *argv],
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
