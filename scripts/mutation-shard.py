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
# Seconds of test time across each module's mutants, measured in CI on 4fd8c97 (39,077 mutants).
# A shard's mutmut step took about 60 s plus 38% of its total. A cut module's digits aren't
# equal shares (check's digit 4 took 644 s, its digit 2 1,494 s), so a shard can run up to a
# fifth over its share: SHARDS keeps room for that.
WEIGHTS = {
    "zoeymcp.common.policy.check": 11175,
    "zoeymcp.common.canonical": 3313,
    "zoeymcp.vault.oauth.tokens": 2443,
    "zoeymcp.gateway.schemas": 2251,
    "zoeymcp.vault.oauth.discovery": 2119,
    "zoeymcp.cli.choices": 1971,
    "zoeymcp.common.policy.change": 1381,
    "zoeymcp.vault.health": 1291,
    "zoeymcp.vault.store": 1200,
    "zoeymcp.portal.reviewview": 1062,
    "zoeymcp.common.policy.plan": 788,
    "zoeymcp.common.policy.reviewchange": 739,
    "zoeymcp.common.policy.match": 724,
    "zoeymcp.vault.policyseal": 724,
    "zoeymcp.vault.request": 673,
    "zoeymcp.vault.onboarding": 581,
    "zoeymcp.vault.gatewaykeys": 564,
    "zoeymcp.gateway.pins": 557,
    "zoeymcp.vault.oauth.login": 541,
    "zoeymcp.common.policy.view": 527,
    "zoeymcp.vault.policystart": 525,
    "zoeymcp.common.reviewreport": 431,
    "zoeymcp.common.yamlload": 413,
    "zoeymcp.common.policy.emit": 410,
    "zoeymcp.vault.oauth.protocol": 376,
    "zoeymcp.portal.webauthn": 357,
    "zoeymcp.common.egresslist": 239,
    "zoeymcp.common.policy.fields": 238,
    "zoeymcp.common.policy.ratchet": 233,
    "zoeymcp.common.policy.diff": 209,
    "zoeymcp.common.ledgerformat": 199,
    "zoeymcp.vault.reviewjobs": 192,
    "zoeymcp.portal.passkeys": 185,
    "zoeymcp.vault.bindings": 184,
    "zoeymcp.common.netguard": 179,
    "zoeymcp.common.approvaltext": 170,
    "zoeymcp.vault.connectors.mailmsg": 159,
    "zoeymcp.common.textrules": 152,
    "zoeymcp.vault.secretplan": 142,
    "zoeymcp.gateway.findings": 139,
    "zoeymcp.vault.oauth.pkce": 139,
    "zoeymcp.toolkit.params": 132,
    "zoeymcp.gateway.access": 128,
    "zoeymcp.gateway.sanitize": 128,
    "zoeymcp.vault.reports": 121,
    "zoeymcp.gateway.approvals": 120,
    "zoeymcp.bridge.framing": 108,
    "zoeymcp.bridge.admit": 107,
    "zoeymcp.bridge.relay": 105,
    "zoeymcp.common.policy.merge": 103,
    "zoeymcp.gateway.egressrules": 100,
    "zoeymcp.vault.oauth.dcr": 96,
    "zoeymcp.portal.admission": 93,
    "zoeymcp.vault.connectors.sendjournal": 90,
    "zoeymcp.common.policy.export": 87,
    "zoeymcp.vault.internal": 77,
    "zoeymcp.vault.statusreport": 76,
    "zoeymcp.common.files": 73,
    "zoeymcp.portal.setupcode": 68,
    "zoeymcp.bridge.sessions": 62,
    "zoeymcp.entrypoint.env": 61,
    "zoeymcp.vault.ledgerview": 61,
    "zoeymcp.common.policy.gate": 58,
    "zoeymcp.portal.sessions": 54,
    "zoeymcp.common.policy.restart": 53,
    "zoeymcp.portal.refusals": 46,
    "zoeymcp.portal.policyview": 43,
    "zoeymcp.common.policy.attention": 41,
    "zoeymcp.egress.connect": 40,
    "zoeymcp.toolkit.rules": 36,
    "zoeymcp.gateway.witness": 30,
    "zoeymcp.gateway.reporting": 28,
    "zoeymcp.portal.actions": 26,
    "zoeymcp.gateway.connstate": 25,
    "zoeymcp.bridge.childenv": 22,
    "zoeymcp.portal.listen": 22,
    "zoeymcp.gateway.capabilities": 21,
    "zoeymcp.portal.drafts": 20,
    "zoeymcp.common.pinhash": 18,
    "zoeymcp.portal.limits": 16,
    "zoeymcp.vault.connectors.tunnel": 15,
    "zoeymcp.common.suggest": 14,
    "zoeymcp.gateway.resourcematch": 13,
    "zoeymcp.portal.policydiffview": 13,
    "zoeymcp.common.ledgerjoin": 11,
    "zoeymcp.portal.routes": 10,
    "zoeymcp.vault.peer": 8,
    "zoeymcp.common.policy.callback": 7,
    "zoeymcp.portal.display": 6,
    "zoeymcp.vault.connectors.smtpflow": 6,
    "zoeymcp.toolkit.plan": 3,
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
