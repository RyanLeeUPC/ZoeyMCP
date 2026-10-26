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
# Seconds of test time across each module's mutants, measured in CI on 45371ee (37,912 mutants).
# A shard's mutmut step took about 130 s plus 34% of its total.
WEIGHTS = {
    "zoeymcp.common.policy.check": 10167,
    "zoeymcp.common.canonical": 3259,
    "zoeymcp.vault.oauth.tokens": 2747,
    "zoeymcp.vault.oauth.discovery": 2361,
    "zoeymcp.gateway.schemas": 2211,
    "zoeymcp.vault.health": 1387,
    "zoeymcp.common.policy.change": 1039,
    "zoeymcp.vault.store": 1025,
    "zoeymcp.portal.reviewview": 963,
    "zoeymcp.common.policy.plan": 913,
    "zoeymcp.vault.onboarding": 797,
    "zoeymcp.cli.choices": 752,
    "zoeymcp.vault.oauth.login": 719,
    "zoeymcp.vault.request": 614,
    "zoeymcp.vault.oauth.protocol": 611,
    "zoeymcp.vault.gatewaykeys": 578,
    "zoeymcp.common.policy.match": 551,
    "zoeymcp.common.policy.reviewchange": 530,
    "zoeymcp.vault.policystart": 525,
    "zoeymcp.common.policy.emit": 413,
    "zoeymcp.common.reviewreport": 404,
    "zoeymcp.vault.policyseal": 396,
    "zoeymcp.common.yamlload": 367,
    "zoeymcp.portal.webauthn": 353,
    "zoeymcp.gateway.pins": 272,
    "zoeymcp.vault.reviewjobs": 260,
    "zoeymcp.common.policy.view": 252,
    "zoeymcp.common.approvaltext": 250,
    "zoeymcp.common.policy.ratchet": 235,
    "zoeymcp.vault.oauth.pkce": 224,
    "zoeymcp.common.ledgerformat": 215,
    "zoeymcp.vault.connectors.mailmsg": 206,
    "zoeymcp.vault.bindings": 184,
    "zoeymcp.common.policy.diff": 182,
    "zoeymcp.portal.passkeys": 163,
    "zoeymcp.common.policy.fields": 149,
    "zoeymcp.vault.secretplan": 142,
    "zoeymcp.common.egresslist": 141,
    "zoeymcp.common.textrules": 141,
    "zoeymcp.toolkit.params": 138,
    "zoeymcp.gateway.access": 128,
    "zoeymcp.gateway.sanitize": 128,
    "zoeymcp.vault.reports": 127,
    "zoeymcp.vault.oauth.dcr": 125,
    "zoeymcp.portal.admission": 124,
    "zoeymcp.bridge.framing": 110,
    "zoeymcp.common.policy.merge": 108,
    "zoeymcp.vault.ledgerview": 106,
    "zoeymcp.bridge.admit": 97,
    "zoeymcp.gateway.egressrules": 96,
    "zoeymcp.common.netguard": 88,
    "zoeymcp.common.policy.export": 85,
    "zoeymcp.entrypoint.env": 84,
    "zoeymcp.bridge.relay": 81,
    "zoeymcp.gateway.findings": 75,
    "zoeymcp.vault.internal": 75,
    "zoeymcp.portal.sessions": 73,
    "zoeymcp.portal.setupcode": 66,
    "zoeymcp.gateway.approvals": 65,
    "zoeymcp.bridge.sessions": 62,
    "zoeymcp.vault.statusreport": 55,
    "zoeymcp.portal.refusals": 53,
    "zoeymcp.vault.connectors.sendjournal": 50,
    "zoeymcp.gateway.witness": 43,
    "zoeymcp.common.policy.gate": 42,
    "zoeymcp.gateway.reporting": 42,
    "zoeymcp.common.policy.restart": 41,
    "zoeymcp.common.policy.attention": 40,
    "zoeymcp.toolkit.rules": 39,
    "zoeymcp.common.files": 36,
    "zoeymcp.portal.drafts": 32,
    "zoeymcp.portal.policyview": 32,
    "zoeymcp.egress.connect": 25,
    "zoeymcp.portal.actions": 25,
    "zoeymcp.gateway.capabilities": 24,
    "zoeymcp.portal.listen": 23,
    "zoeymcp.gateway.connstate": 19,
    "zoeymcp.bridge.childenv": 18,
    "zoeymcp.common.pinhash": 16,
    "zoeymcp.portal.routes": 16,
    "zoeymcp.gateway.resourcematch": 15,
    "zoeymcp.common.suggest": 13,
    "zoeymcp.portal.limits": 12,
    "zoeymcp.vault.peer": 12,
    "zoeymcp.common.ledgerjoin": 10,
    "zoeymcp.portal.display": 10,
    "zoeymcp.portal.policydiffview": 10,
    "zoeymcp.vault.connectors.tunnel": 8,
    "zoeymcp.vault.connectors.smtpflow": 7,
    "zoeymcp.common.policy.callback": 3,
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
