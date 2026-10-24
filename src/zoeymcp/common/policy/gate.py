"""One parse-and-check gate (M6 design C; R53, R64, R66; Y2). Pure, mutation-tested.

Every policy that can run passes here, whatever brought it: :func:`admit_text` takes a document's
text through the strict loader (``common/yamlload.py``), the schema and ``check`` with the
vault's environment, and :func:`admit` runs ``check`` on a policy built in memory (a candidate, a
revision). A policy with an error is a :class:`GateRefused`, whose reason says how far it got:

- ``unreadable``: the text isn't a document the loader reads (and only that: a source the caller
  couldn't read, or no source at all, is the caller's, F.1's ``none``);
- ``invalid``: the schema refused it;
- ``fails_check``: ``check`` found an error.

A refusal's text is the one the vault's start and reload have always given, naming the first
:data:`SHOWN` errors: ``policy <source> refused: <path>: <message>; ...``, and for ``check``
``policy <source> fails check (N error(s)): ...`` with every error counted. An admitted policy
carries ``check``'s warnings. :func:`refused_text` gives the same text for a source the caller
couldn't read, without a refusal of the gate's. ``check_policy`` itself is unchanged; ``zoeymcp
check`` still calls it directly (C.2).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from ..yamlload import YAMLRejected, load_mapping
from .check import check_policy
from .findings import Finding
from .load import PolicyError, validate_policy
from .schema import Policy

Reason = Literal["unreadable", "invalid", "fails_check"]
# The errors a refusal's text names, as the vault's start has always named them.
SHOWN: Final = 5


@dataclass(frozen=True)
class Admitted:
    policy: Policy
    findings: tuple[Finding, ...]  # warnings; never an error


def refused_text(source: str, errors: Sequence[Finding]) -> str:
    """``policy <source> refused: <path>: <message>; ...``, naming the first :data:`SHOWN`."""
    details = "; ".join(f"{f.path}: {f.message}" for f in errors[:SHOWN])
    return f"policy {source} refused: {details}"


class GateRefused(Exception):
    """A policy the gate refused. ``findings`` are the first :data:`SHOWN` errors, ``count``
    all of them; ``str()`` is the refusal's text."""

    def __init__(self, reason: Reason, source: str, errors: Sequence[Finding]) -> None:
        self.reason = reason
        self.source = source
        self.findings = tuple(errors[:SHOWN])
        self.count = len(errors)
        if reason == "fails_check":
            details = "; ".join(f"{f.path}: {f.message}" for f in self.findings)
            text = f"policy {source} fails check ({self.count} error(s)): {details}"
        else:
            text = refused_text(source, errors)
        super().__init__(text)


def admit_text(text: str, source: str, *, environ: Mapping[str, str]) -> Admitted:
    """The strict loader, the schema, then ``check_policy(policy, environ=environ)``."""
    try:
        raw = load_mapping(text)
    except YAMLRejected as exc:
        raise GateRefused("unreadable", source, [Finding("(document)", "error", str(exc))]) from exc
    try:
        policy = validate_policy(raw, source)
    except PolicyError as exc:
        raise GateRefused("invalid", source, exc.findings) from exc
    return admit(policy, source, environ=environ)


def admit(policy: Policy, source: str, *, environ: Mapping[str, str]) -> Admitted:
    """``check_policy(policy, environ=environ)`` on a policy built in memory (a candidate, a
    revision)."""
    found = check_policy(policy, environ=environ)
    errors = [f for f in found if f.level == "error"]
    if errors:
        raise GateRefused("fails_check", source, errors)
    return Admitted(policy, tuple(found))
