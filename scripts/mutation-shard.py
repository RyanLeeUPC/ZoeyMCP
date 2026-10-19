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
    "zoeymcp.common.policy.check": 2489,
    "zoeymcp.vault.store": 1517,
    "zoeymcp.common.canonical": 1327,
    "zoeymcp.vault.oauth.tokens": 1092,
    "zoeymcp.vault.request": 616,
    "zoeymcp.vault.oauth.protocol": 368,
    "zoeymcp.common.policy.match": 271,
    "zoeymcp.gateway.schemas": 240,
    "zoeymcp.vault.gatewaykeys": 239,
    "zoeymcp.vault.oauth.login": 218,
    "zoeymcp.common.approvaltext": 177,
    "zoeymcp.vault.connectors.mailmsg": 145,
    "zoeymcp.common.policy.view": 126,
    "zoeymcp.toolkit.params": 105,
    "zoeymcp.gateway.approvals": 84,
    "zoeymcp.gateway.access": 78,
    "zoeymcp.common.ledgerformat": 76,
    "zoeymcp.gateway.pins": 63,
    "zoeymcp.gateway.egressrules": 61,
    "zoeymcp.vault.connectors.sendjournal": 57,
    "zoeymcp.gateway.findings": 51,
    "zoeymcp.vault.bindings": 49,
    "zoeymcp.vault.oauth.pkce": 45,
    "zoeymcp.gateway.sanitize": 40,
    "zoeymcp.toolkit.rules": 27,
    "zoeymcp.common.textrules": 25,
    "zoeymcp.entrypoint.env": 15,
    "zoeymcp.gateway.connstate": 13,
    "zoeymcp.common.files": 11,
    "zoeymcp.vault.connectors.tunnel": 11,
    "zoeymcp.vault.peer": 6,
    "zoeymcp.vault.connectors.smtpflow": 4,
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
