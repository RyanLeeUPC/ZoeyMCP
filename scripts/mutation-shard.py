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
# Seconds of test time across each module's mutants, measured in CI on ec81280 (35,936 mutants).
# A shard's mutmut step took about 250 s plus 29% of its total.
WEIGHTS = {
    "zoeymcp.common.policy.check": 9906,
    "zoeymcp.common.canonical": 2595,
    "zoeymcp.vault.oauth.tokens": 2037,
    "zoeymcp.vault.oauth.discovery": 1991,
    "zoeymcp.gateway.schemas": 1899,
    "zoeymcp.cli.choices": 1348,
    "zoeymcp.vault.store": 975,
    "zoeymcp.vault.health": 922,
    "zoeymcp.common.policy.change": 889,
    "zoeymcp.portal.reviewview": 803,
    "zoeymcp.vault.onboarding": 668,
    "zoeymcp.vault.request": 660,
    "zoeymcp.vault.oauth.login": 647,
    "zoeymcp.common.policy.match": 608,
    "zoeymcp.vault.oauth.protocol": 426,
    "zoeymcp.common.policy.plan": 393,
    "zoeymcp.common.policy.emit": 353,
    "zoeymcp.vault.policyseal": 346,
    "zoeymcp.portal.webauthn": 339,
    "zoeymcp.vault.gatewaykeys": 332,
    "zoeymcp.common.policy.reviewchange": 305,
    "zoeymcp.common.policy.view": 294,
    "zoeymcp.gateway.pins": 282,
    "zoeymcp.common.yamlload": 280,
    "zoeymcp.common.approvaltext": 225,
    "zoeymcp.common.egresslist": 223,
    "zoeymcp.common.reviewreport": 212,
    "zoeymcp.portal.passkeys": 208,
    "zoeymcp.vault.connectors.mailmsg": 201,
    "zoeymcp.vault.reviewjobs": 188,
    "zoeymcp.vault.policystart": 174,
    "zoeymcp.vault.bindings": 173,
    "zoeymcp.vault.oauth.pkce": 168,
    "zoeymcp.common.netguard": 157,
    "zoeymcp.common.textrules": 137,
    "zoeymcp.gateway.approvals": 118,
    "zoeymcp.portal.admission": 116,
    "zoeymcp.vault.oauth.dcr": 115,
    "zoeymcp.common.policy.fields": 112,
    "zoeymcp.vault.secretplan": 111,
    "zoeymcp.common.ledgerformat": 106,
    "zoeymcp.common.policy.ratchet": 98,
    "zoeymcp.bridge.relay": 97,
    "zoeymcp.bridge.framing": 95,
    "zoeymcp.common.policy.diff": 95,
    "zoeymcp.bridge.admit": 93,
    "zoeymcp.vault.ledgerview": 91,
    "zoeymcp.gateway.access": 88,
    "zoeymcp.vault.reports": 87,
    "zoeymcp.gateway.findings": 86,
    "zoeymcp.entrypoint.env": 83,
    "zoeymcp.gateway.egressrules": 82,
    "zoeymcp.common.policy.restart": 80,
    "zoeymcp.toolkit.params": 78,
    "zoeymcp.vault.connectors.sendjournal": 67,
    "zoeymcp.vault.statusreport": 67,
    "zoeymcp.gateway.sanitize": 60,
    "zoeymcp.portal.sessions": 54,
    "zoeymcp.vault.internal": 53,
    "zoeymcp.portal.setupcode": 46,
    "zoeymcp.common.policy.merge": 45,
    "zoeymcp.portal.refusals": 43,
    "zoeymcp.egress.connect": 39,
    "zoeymcp.common.policy.gate": 37,
    "zoeymcp.common.policy.export": 36,
    "zoeymcp.toolkit.rules": 35,
    "zoeymcp.portal.policyview": 28,
    "zoeymcp.gateway.reporting": 26,
    "zoeymcp.common.files": 25,
    "zoeymcp.portal.actions": 25,
    "zoeymcp.common.policy.attention": 23,
    "zoeymcp.portal.limits": 22,
    "zoeymcp.gateway.connstate": 21,
    "zoeymcp.bridge.sessions": 19,
    "zoeymcp.portal.listen": 17,
    "zoeymcp.portal.routes": 14,
    "zoeymcp.bridge.childenv": 11,
    "zoeymcp.vault.connectors.tunnel": 11,
    "zoeymcp.common.suggest": 9,
    "zoeymcp.portal.policydiffview": 9,
    "zoeymcp.vault.peer": 8,
    "zoeymcp.common.ledgerjoin": 6,
    "zoeymcp.common.policy.callback": 6,
    "zoeymcp.vault.connectors.smtpflow": 6,
    "zoeymcp.common.pinhash": 5,
    "zoeymcp.gateway.capabilities": 4,
    "zoeymcp.portal.display": 4,
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
