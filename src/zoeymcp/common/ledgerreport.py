"""The ledger report's wire format, shared by the gateway and the vault (M5 design J.2).

The gateway ``POST``s ``{"v": 1, "lines": [...]}`` to :data:`PATH` on the link, each line one
canonical ledger record without its newline. The vault answers it, and a ``GET`` of the same path,
with the head of its copy: ``{"head_seq", "head_hash", "state"}``. Deciding on a report is the
vault's (:mod:`zoeymcp.vault.reports`) and choosing what to send is the gateway's
(:mod:`zoeymcp.gateway.reporting`); this module holds only what both sides must agree on.

This module is pure and standard library only: the vault and the gateway both import it.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from . import canonical

PATH: Final = "/_zoeymcp/gateway/v1/report/ledger"
VERSION: Final = 1
MAX_LINES: Final = 256
MAX_BODY_BYTES: Final = 2**20

# ``ok`` takes reports; the others are sticky refusals, lifted only by a stepped-up restart.
State = Literal["ok", "fork", "gap", "full"]
STATES: Final = frozenset({"ok", "fork", "gap", "full"})


@dataclass(frozen=True)
class Head:
    """The copy's head: the last record it holds (both None before its first report)."""

    seq: int | None
    hash: str | None
    state: State = "ok"

    def to_json(self) -> dict[str, Any]:
        return {"head_seq": self.seq, "head_hash": self.hash, "state": self.state}


def encode(lines: Sequence[bytes]) -> bytes:
    """A report's body, canonical JSON: the bytes the vault's cap counts."""
    body = {"v": VERSION, "lines": [line.decode("utf-8") for line in lines]}
    return canonical.dumps_canonical(body)
