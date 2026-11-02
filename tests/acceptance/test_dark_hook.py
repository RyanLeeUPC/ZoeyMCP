"""The launcher's ``lit`` hook (M8 design A.2 row 0, O.1; G-2, BP-2): a process test lights M8's
dark policy fields in the fresh interpreter, as ``tests/dark.py``'s ``lit()`` does in a test's
own, so a vault started on a policy that uses them admits it. Without the hook ``check`` refuses
them, as a shipped build does until step 18.
"""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest

from .procs import start

pytestmark = pytest.mark.anyio

POLICY = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]},
    "approvers": {"portal": {}},
}
DARK = "approvers: arrives in a later M8 step"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _checked(tmp_path: Path, *, lit: bool) -> tuple[int, str]:
    """``zoeymcp check`` on :data:`POLICY` through the launcher: its exit status and output."""
    config = tmp_path / "policy.json"
    config.write_bytes(json.dumps(POLICY).encode())
    log = tmp_path / f"check-{lit}.log"
    process = start(["check", "--config", str(config)], env={}, log=log, lit=lit)
    try:
        with anyio.fail_after(60):
            # Abandoned on a timeout: the stop below ends the wait in its thread.
            status = await anyio.to_thread.run_sync(process.popen.wait, abandon_on_cancel=True)
    finally:
        process.stop()
    return status, process.output()


async def test_the_launcher_lights_the_dark_fields_only_when_asked(tmp_path: Path) -> None:
    status, output = await _checked(tmp_path, lit=False)
    assert status != 0, output
    assert DARK in output
    status, output = await _checked(tmp_path, lit=True)
    assert status == 0, output
    assert DARK not in output
