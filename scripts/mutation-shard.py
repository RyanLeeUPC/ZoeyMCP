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
# Seconds of test time across each module's mutants, measured in CI on fdd4100 (39,071 mutants).
# A shard's mutmut step took about 420 s plus 28% of its total.
WEIGHTS = {
    "zoeymcp.common.policy.check": 11277,
    "zoeymcp.common.canonical": 2823,
    "zoeymcp.vault.oauth.tokens": 2243,
    "zoeymcp.vault.oauth.discovery": 2176,
    "zoeymcp.cli.choices": 1922,
    "zoeymcp.gateway.schemas": 1822,
    "zoeymcp.vault.health": 1285,
    "zoeymcp.common.policy.change": 1282,
    "zoeymcp.vault.store": 990,
    "zoeymcp.portal.reviewview": 941,
    "zoeymcp.vault.request": 762,
    "zoeymcp.vault.onboarding": 759,
    "zoeymcp.common.policy.plan": 754,
    "zoeymcp.common.policy.match": 735,
    "zoeymcp.common.policy.reviewchange": 725,
    "zoeymcp.vault.policyseal": 694,
    "zoeymcp.vault.oauth.login": 572,
    "zoeymcp.gateway.pins": 562,
    "zoeymcp.vault.oauth.protocol": 478,
    "zoeymcp.vault.policystart": 457,
    "zoeymcp.common.yamlload": 378,
    "zoeymcp.common.policy.view": 374,
    "zoeymcp.common.policy.emit": 338,
    "zoeymcp.vault.gatewaykeys": 328,
    "zoeymcp.common.reviewreport": 305,
    "zoeymcp.portal.passkeys": 294,
    "zoeymcp.vault.reviewjobs": 289,
    "zoeymcp.portal.webauthn": 274,
    "zoeymcp.common.egresslist": 233,
    "zoeymcp.common.approvaltext": 232,
    "zoeymcp.common.policy.diff": 199,
    "zoeymcp.common.ledgerformat": 197,
    "zoeymcp.vault.bindings": 191,
    "zoeymcp.vault.connectors.mailmsg": 189,
    "zoeymcp.common.policy.fields": 182,
    "zoeymcp.vault.oauth.pkce": 174,
    "zoeymcp.vault.secretplan": 150,
    "zoeymcp.gateway.findings": 123,
    "zoeymcp.common.policy.ratchet": 120,
    "zoeymcp.gateway.approvals": 120,
    "zoeymcp.vault.oauth.dcr": 117,
    "zoeymcp.vault.statusreport": 117,
    "zoeymcp.common.netguard": 110,
    "zoeymcp.common.policy.merge": 107,
    "zoeymcp.gateway.sanitize": 107,
    "zoeymcp.toolkit.params": 103,
    "zoeymcp.bridge.relay": 102,
    "zoeymcp.vault.reports": 101,
    "zoeymcp.gateway.egressrules": 99,
    "zoeymcp.vault.ledgerview": 98,
    "zoeymcp.gateway.access": 97,
    "zoeymcp.bridge.framing": 90,
    "zoeymcp.portal.admission": 87,
    "zoeymcp.entrypoint.env": 85,
    "zoeymcp.common.files": 83,
    "zoeymcp.common.textrules": 83,
    "zoeymcp.common.policy.export": 79,
    "zoeymcp.bridge.admit": 73,
    "zoeymcp.portal.sessions": 72,
    "zoeymcp.vault.connectors.sendjournal": 71,
    "zoeymcp.portal.setupcode": 67,
    "zoeymcp.common.policy.restart": 64,
    "zoeymcp.common.policy.gate": 56,
    "zoeymcp.bridge.sessions": 53,
    "zoeymcp.portal.policyview": 46,
    "zoeymcp.gateway.witness": 44,
    "zoeymcp.vault.internal": 44,
    "zoeymcp.egress.connect": 41,
    "zoeymcp.gateway.reporting": 36,
    "zoeymcp.portal.refusals": 36,
    "zoeymcp.toolkit.rules": 36,
    "zoeymcp.common.policy.attention": 33,
    "zoeymcp.portal.limits": 24,
    "zoeymcp.portal.listen": 24,
    "zoeymcp.gateway.connstate": 23,
    "zoeymcp.gateway.capabilities": 22,
    "zoeymcp.portal.drafts": 20,
    "zoeymcp.portal.actions": 19,
    "zoeymcp.portal.policydiffview": 18,
    "zoeymcp.bridge.childenv": 15,
    "zoeymcp.vault.connectors.tunnel": 15,
    "zoeymcp.common.pinhash": 14,
    "zoeymcp.gateway.resourcematch": 13,
    "zoeymcp.portal.routes": 11,
    "zoeymcp.vault.peer": 11,
    "zoeymcp.common.suggest": 10,
    "zoeymcp.common.ledgerjoin": 9,
    "zoeymcp.portal.display": 8,
    "zoeymcp.common.policy.callback": 5,
    "zoeymcp.vault.connectors.smtpflow": 5,
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
