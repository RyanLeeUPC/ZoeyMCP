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
# Seconds of test time across each module's mutants, measured in CI on 8aacec6 (36,888 mutants).
# A shard's mutmut step took about 160 s plus 32% of its total.
WEIGHTS = {
    "zoeymcp.common.policy.check": 11296,
    "zoeymcp.common.canonical": 3125,
    "zoeymcp.vault.oauth.tokens": 2717,
    "zoeymcp.vault.oauth.discovery": 2180,
    "zoeymcp.vault.store": 1491,
    "zoeymcp.gateway.schemas": 1406,
    "zoeymcp.common.policy.change": 1176,
    "zoeymcp.vault.health": 1167,
    "zoeymcp.cli.choices": 1004,
    "zoeymcp.common.policy.plan": 888,
    "zoeymcp.portal.reviewview": 880,
    "zoeymcp.common.policy.match": 747,
    "zoeymcp.vault.onboarding": 741,
    "zoeymcp.vault.request": 737,
    "zoeymcp.vault.oauth.login": 580,
    "zoeymcp.vault.policyseal": 571,
    "zoeymcp.vault.oauth.protocol": 563,
    "zoeymcp.vault.gatewaykeys": 497,
    "zoeymcp.common.policy.view": 485,
    "zoeymcp.vault.policystart": 443,
    "zoeymcp.common.policy.emit": 437,
    "zoeymcp.common.yamlload": 362,
    "zoeymcp.common.policy.reviewchange": 355,
    "zoeymcp.gateway.pins": 334,
    "zoeymcp.portal.webauthn": 323,
    "zoeymcp.portal.passkeys": 290,
    "zoeymcp.common.policy.ratchet": 267,
    "zoeymcp.vault.reviewjobs": 267,
    "zoeymcp.common.egresslist": 263,
    "zoeymcp.common.approvaltext": 230,
    "zoeymcp.vault.oauth.pkce": 222,
    "zoeymcp.common.policy.fields": 202,
    "zoeymcp.vault.connectors.mailmsg": 185,
    "zoeymcp.common.ledgerformat": 165,
    "zoeymcp.common.reviewreport": 163,
    "zoeymcp.common.netguard": 160,
    "zoeymcp.toolkit.params": 159,
    "zoeymcp.vault.secretplan": 155,
    "zoeymcp.common.policy.diff": 152,
    "zoeymcp.vault.bindings": 145,
    "zoeymcp.bridge.relay": 126,
    "zoeymcp.common.policy.merge": 117,
    "zoeymcp.vault.reports": 116,
    "zoeymcp.gateway.approvals": 114,
    "zoeymcp.portal.admission": 113,
    "zoeymcp.gateway.access": 111,
    "zoeymcp.bridge.framing": 104,
    "zoeymcp.vault.statusreport": 101,
    "zoeymcp.vault.oauth.dcr": 99,
    "zoeymcp.vault.ledgerview": 97,
    "zoeymcp.gateway.findings": 93,
    "zoeymcp.common.policy.restart": 86,
    "zoeymcp.common.textrules": 86,
    "zoeymcp.entrypoint.env": 81,
    "zoeymcp.bridge.admit": 73,
    "zoeymcp.common.policy.export": 73,
    "zoeymcp.common.files": 71,
    "zoeymcp.portal.sessions": 71,
    "zoeymcp.gateway.egressrules": 69,
    "zoeymcp.vault.connectors.sendjournal": 69,
    "zoeymcp.portal.setupcode": 66,
    "zoeymcp.common.policy.gate": 63,
    "zoeymcp.gateway.sanitize": 61,
    "zoeymcp.portal.policyview": 55,
    "zoeymcp.vault.internal": 54,
    "zoeymcp.portal.refusals": 47,
    "zoeymcp.gateway.reporting": 38,
    "zoeymcp.gateway.witness": 37,
    "zoeymcp.toolkit.rules": 36,
    "zoeymcp.egress.connect": 33,
    "zoeymcp.portal.listen": 27,
    "zoeymcp.common.policy.attention": 26,
    "zoeymcp.gateway.connstate": 24,
    "zoeymcp.portal.actions": 23,
    "zoeymcp.portal.drafts": 23,
    "zoeymcp.bridge.sessions": 19,
    "zoeymcp.portal.limits": 18,
    "zoeymcp.portal.routes": 18,
    "zoeymcp.bridge.childenv": 16,
    "zoeymcp.vault.connectors.tunnel": 14,
    "zoeymcp.portal.policydiffview": 13,
    "zoeymcp.vault.peer": 11,
    "zoeymcp.portal.display": 10,
    "zoeymcp.common.ledgerjoin": 9,
    "zoeymcp.common.suggest": 9,
    "zoeymcp.vault.connectors.smtpflow": 6,
    "zoeymcp.common.policy.callback": 5,
    "zoeymcp.gateway.capabilities": 5,
    "zoeymcp.common.pinhash": 4,
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
