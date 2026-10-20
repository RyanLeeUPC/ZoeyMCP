"""Print the mutant name patterns one mutation shard runs.

Usage: python scripts/mutation-shard.py --shard N --of COUNT

Every mutant of the modules in ``[tool.mutmut] only_mutate`` is run by exactly one shard. A
module heavier than half an even share is cut into parts by the last digit of its mutant numbers
(``zoeymcp.common.policy.check.*__mutmut_*[01234]``), so no shard waits on one big module. The
parts are assigned largest first to the lightest shard. The weights come from WEIGHTS, which
scripts/mutation-weights.py regenerates; a module not in the table gets a middling weight. The
merge step fails if any mutant ran in no shard or in two, so a stale table only costs balance.
"""

from __future__ import annotations

import argparse
import itertools
import math
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
DIGITS = "0123456789"
DEFAULT_WEIGHT = 100
# Seconds of test time across each module's mutants, measured in CI on 3357235 (13,255 mutants).
# A shard's mutmut step took about 116 s plus a quarter of its total.
WEIGHTS = {
    "zoeymcp.common.policy.check": 2949,
    "zoeymcp.vault.oauth.tokens": 2014,
    "zoeymcp.common.canonical": 1898,
    "zoeymcp.vault.store": 1457,
    "zoeymcp.vault.request": 673,
    "zoeymcp.vault.oauth.login": 487,
    "zoeymcp.vault.health": 353,
    "zoeymcp.vault.oauth.protocol": 348,
    "zoeymcp.common.policy.match": 336,
    "zoeymcp.vault.gatewaykeys": 332,
    "zoeymcp.portal.webauthn": 320,
    "zoeymcp.gateway.schemas": 250,
    "zoeymcp.portal.passkeys": 250,
    "zoeymcp.common.approvaltext": 209,
    "zoeymcp.common.ledgerformat": 202,
    "zoeymcp.common.policy.view": 172,
    "zoeymcp.vault.connectors.mailmsg": 154,
    "zoeymcp.vault.oauth.pkce": 151,
    "zoeymcp.vault.reports": 107,
    "zoeymcp.vault.bindings": 100,
    "zoeymcp.gateway.access": 99,
    "zoeymcp.portal.admission": 99,
    "zoeymcp.gateway.pins": 95,
    "zoeymcp.gateway.approvals": 90,
    "zoeymcp.common.textrules": 87,
    "zoeymcp.toolkit.params": 86,
    "zoeymcp.vault.ledgerview": 84,
    "zoeymcp.gateway.egressrules": 76,
    "zoeymcp.vault.secretplan": 73,
    "zoeymcp.vault.connectors.sendjournal": 64,
    "zoeymcp.gateway.findings": 62,
    "zoeymcp.portal.sessions": 43,
    "zoeymcp.portal.setupcode": 43,
    "zoeymcp.gateway.sanitize": 42,
    "zoeymcp.common.files": 31,
    "zoeymcp.toolkit.rules": 31,
    "zoeymcp.gateway.reporting": 30,
    "zoeymcp.portal.refusals": 25,
    "zoeymcp.portal.actions": 19,
    "zoeymcp.portal.policyview": 19,
    "zoeymcp.entrypoint.env": 18,
    "zoeymcp.gateway.connstate": 18,
    "zoeymcp.portal.listen": 15,
    "zoeymcp.portal.limits": 13,
    "zoeymcp.portal.routes": 12,
    "zoeymcp.vault.connectors.tunnel": 12,
    "zoeymcp.vault.peer": 8,
    "zoeymcp.common.ledgerjoin": 6,
    "zoeymcp.vault.connectors.smtpflow": 5,
    "zoeymcp.common.policy.callback": 3,
    "zoeymcp.portal.display": 3,
    "zoeymcp.toolkit.plan": 2,
}


class Part(NamedTuple):
    """The mutants of ``module`` whose number ends in one of ``digits``."""

    module: str
    digits: str
    weight: float

    def pattern(self) -> str:
        if self.digits == DIGITS:
            return f"{self.module}.*"
        return f"{self.module}.*__mutmut_*[{self.digits}]"


def modules(pyproject: Path = ROOT / "pyproject.toml") -> list[str]:
    """The dotted module names ``only_mutate`` lists, like ``zoeymcp.vault.request``."""
    with pyproject.open("rb") as handle:
        patterns = tomllib.load(handle)["tool"]["mutmut"]["only_mutate"]
    found = []
    for pattern in patterns:
        path = pattern.lstrip("*").removesuffix(".py").strip("/")
        found.append(path.replace("/", "."))
    return found


def parts(names: list[str], count: int) -> list[Part]:
    """Each module whole, or cut by last digit into parts no heavier than half an even share."""
    weight = {name: WEIGHTS.get(name, DEFAULT_WEIGHT) for name in names}
    half_share = sum(weight.values()) / count / 2
    found = []
    for name in names:
        cuts = min(len(DIGITS), max(1, math.ceil(weight[name] / half_share)))
        bounds = [round(i * len(DIGITS) / cuts) for i in range(cuts + 1)]
        for low, high in itertools.pairwise(bounds):
            digits = DIGITS[low:high]
            found.append(Part(name, digits, weight[name] * len(digits) / len(DIGITS)))
    return found


def shards(names: list[str], count: int) -> list[list[Part]]:
    """The parts of ``names`` in ``count`` groups of about equal weight, deterministically."""
    groups: list[list[Part]] = [[] for _ in range(count)]
    loads = [0.0] * count
    for part in sorted(parts(names, count), key=lambda p: (-p.weight, p.module, p.digits)):
        lightest = loads.index(min(loads))
        groups[lightest].append(part)
        loads[lightest] += part.weight
    return groups


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--of", type=int, required=True)
    args = parser.parse_args()
    if not 0 <= args.shard < args.of:
        print("--shard must be from 0 to --of minus 1", file=sys.stderr)
        return 2
    print(" ".join(part.pattern() for part in shards(modules(), args.of)[args.shard]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
