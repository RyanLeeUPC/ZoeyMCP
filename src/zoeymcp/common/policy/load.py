"""Reading a policy document from a file, stdin or ``ZOEYMCP_CONFIG`` (design R51)."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TextIO

from pydantic import ValidationError

from ..yamlload import YAMLRejected, load_mapping
from .findings import Finding, format_location
from .schema import Policy

CONFIG_ENV = "ZOEYMCP_CONFIG"


class PolicyError(Exception):
    """A policy document that couldn't be read or doesn't match the schema."""

    def __init__(self, source: str, findings: list[Finding], *, readable: bool = True) -> None:
        self.source = source
        self.findings = findings
        self.readable = readable
        super().__init__(f"{source}: {len(findings)} problem(s)")


def read_source(
    config: str | None, environ: Mapping[str, str], stdin: TextIO = sys.stdin
) -> tuple[str, str]:
    """Return ``(text, source label)`` for ``--config <file>``, ``--config -`` or the env var."""
    if config == "-":
        return stdin.read(), "<stdin>"
    if config is not None:
        try:
            return Path(config).read_text(encoding="utf-8"), config
        except OSError as exc:
            raise PolicyError(
                config, [Finding("(document)", "error", f"can't read: {exc}")], readable=False
            ) from exc
        except UnicodeDecodeError as exc:
            raise PolicyError(
                config, [Finding("(document)", "error", "not valid UTF-8")], readable=False
            ) from exc
    text = environ.get(CONFIG_ENV)
    if text is None:
        raise PolicyError(
            "(none)",
            [Finding("(document)", "error", f"no policy given: use --config or set {CONFIG_ENV}")],
            readable=False,
        )
    return text, f"${CONFIG_ENV}"


def parse_policy(text: str, source: str) -> Policy:
    """Parse and schema-validate a policy document."""
    try:
        raw = load_mapping(text)
    except YAMLRejected as exc:
        raise PolicyError(source, [Finding("(document)", "error", str(exc))]) from exc
    try:
        return Policy.model_validate(raw)
    except ValidationError as exc:
        findings = [
            Finding(format_location(error["loc"]), "error", error["msg"])
            for error in exc.errors(include_url=False)
        ]
        raise PolicyError(source, sorted(set(findings))) from exc
