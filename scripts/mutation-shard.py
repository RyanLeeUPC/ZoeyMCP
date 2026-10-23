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
# Seconds of test time across each module's mutants, measured in CI on 2c9aabc (29,443 mutants).
# A shard's mutmut step took about 300 s plus 27% of its total.
WEIGHTS = {
    "zoeymcp.common.policy.check": 7711,
    "zoeymcp.vault.oauth.tokens": 2574,
    "zoeymcp.vault.oauth.discovery": 2145,
    "zoeymcp.common.canonical": 1941,
    "zoeymcp.gateway.schemas": 1560,
    "zoeymcp.vault.store": 1177,
    "zoeymcp.vault.health": 803,
    "zoeymcp.common.policy.match": 754,
    "zoeymcp.vault.oauth.login": 684,
    "zoeymcp.cli.choices": 665,
    "zoeymcp.vault.request": 652,
    "zoeymcp.vault.oauth.protocol": 624,
    "zoeymcp.portal.reviewview": 551,
    "zoeymcp.vault.onboarding": 489,
    "zoeymcp.common.policy.change": 447,
    "zoeymcp.common.policy.emit": 327,
    "zoeymcp.common.policy.view": 291,
    "zoeymcp.vault.gatewaykeys": 260,
    "zoeymcp.portal.webauthn": 241,
    "zoeymcp.common.approvaltext": 236,
    "zoeymcp.gateway.pins": 218,
    "zoeymcp.common.ledgerformat": 213,
    "zoeymcp.portal.passkeys": 209,
    "zoeymcp.vault.reviewjobs": 207,
    "zoeymcp.vault.connectors.mailmsg": 193,
    "zoeymcp.common.netguard": 151,
    "zoeymcp.common.reviewreport": 150,
    "zoeymcp.vault.secretplan": 132,
    "zoeymcp.common.egresslist": 124,
    "zoeymcp.vault.bindings": 124,
    "zoeymcp.common.policy.fields": 120,
    "zoeymcp.vault.oauth.pkce": 114,
    "zoeymcp.vault.oauth.dcr": 111,
    "zoeymcp.gateway.approvals": 107,
    "zoeymcp.vault.ledgerview": 102,
    "zoeymcp.bridge.framing": 97,
    "zoeymcp.bridge.relay": 96,
    "zoeymcp.bridge.admit": 93,
    "zoeymcp.toolkit.params": 88,
    "zoeymcp.vault.connectors.sendjournal": 84,
    "zoeymcp.common.textrules": 79,
    "zoeymcp.vault.reports": 79,
    "zoeymcp.gateway.access": 76,
    "zoeymcp.gateway.findings": 75,
    "zoeymcp.portal.sessions": 71,
    "zoeymcp.portal.admission": 65,
    "zoeymcp.bridge.sessions": 56,
    "zoeymcp.entrypoint.env": 55,
    "zoeymcp.common.policy.merge": 45,
    "zoeymcp.gateway.egressrules": 45,
    "zoeymcp.gateway.sanitize": 42,
    "zoeymcp.common.files": 41,
    "zoeymcp.portal.setupcode": 33,
    "zoeymcp.vault.internal": 30,
    "zoeymcp.egress.connect": 29,
    "zoeymcp.gateway.reporting": 29,
    "zoeymcp.toolkit.rules": 29,
    "zoeymcp.portal.refusals": 27,
    "zoeymcp.gateway.connstate": 25,
    "zoeymcp.portal.actions": 25,
    "zoeymcp.portal.limits": 23,
    "zoeymcp.bridge.childenv": 18,
    "zoeymcp.portal.listen": 16,
    "zoeymcp.vault.connectors.tunnel": 14,
    "zoeymcp.portal.policyview": 13,
    "zoeymcp.common.suggest": 10,
    "zoeymcp.portal.display": 9,
    "zoeymcp.common.ledgerjoin": 8,
    "zoeymcp.portal.routes": 7,
    "zoeymcp.vault.peer": 7,
    "zoeymcp.common.pinhash": 4,
    "zoeymcp.vault.connectors.smtpflow": 4,
    "zoeymcp.toolkit.plan": 3,
    "zoeymcp.common.policy.callback": 2,
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
