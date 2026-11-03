"""The launcher's ``lit`` hook after M8 step 18 (M8 design A.2 row 0, O.1; G-2, BP-2): the
dark table is gone, so ``check`` admits M8's policy fields in a fresh interpreter with the hook or
without it, as a shipped build does. The hook's slot stays and does nothing, as
``tests/dark.py``'s ``lit()`` does in a test's own process.
"""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest

from zoeymcp.common.policy import check

from .procs import start

pytestmark = pytest.mark.anyio

POLICY = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "127.0.0.1:8081", "origins": ["http://localhost:8081"]},
    "approvers": {"portal": {}},
}
DARK = "arrives in a later M8 step"


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


async def test_the_m8_fields_are_admitted_with_the_hook_or_without(tmp_path: Path) -> None:
    assert not hasattr(check, "_DARK")
    for lit in (False, True):
        status, output = await _checked(tmp_path, lit=lit)
        assert status == 0, output
        assert DARK not in output
