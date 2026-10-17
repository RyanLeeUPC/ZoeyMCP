"""Findings reported by policy loading and ``zoeymcp check``."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

Level = Literal["error", "warning"]


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    level: Level
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"level": self.level, "path": self.path, "message": self.message}


def format_location(location: Sequence[int | str]) -> str:
    """Turn a location like ``("routes", 1, "callers")`` into ``routes[1].callers``."""
    out = ""
    for part in location:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else part
    return out or "(document)"
