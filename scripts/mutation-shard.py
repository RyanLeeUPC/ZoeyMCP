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
# Seconds of test time across each module's mutants, measured in CI on a523e92 (44,051 mutants).
# On 4fd8c97 a shard's mutmut step took about 60 s plus 38% of its total. A cut module's digits
# aren't equal shares (there, check's digit 4 took 644 s, its digit 2 1,494 s), so a shard can run
# up to a fifth over its share: SHARDS keeps room for that.
WEIGHTS = {
    "zoeymcp.common.policy.check": 13951,
    "zoeymcp.common.canonical": 2383,
    "zoeymcp.vault.oauth.discovery": 2380,
    "zoeymcp.vault.oauth.tokens": 2229,
    "zoeymcp.cli.choices": 1517,
    "zoeymcp.vault.health": 1512,
    "zoeymcp.gateway.schemas": 1432,
    "zoeymcp.vault.store": 1237,
    "zoeymcp.common.policy.plan": 1109,
    "zoeymcp.portal.reviewview": 1089,
    "zoeymcp.common.policy.change": 900,
    "zoeymcp.vault.onboarding": 887,
    "zoeymcp.vault.request": 804,
    "zoeymcp.common.policy.match": 752,
    "zoeymcp.common.policy.view": 743,
    "zoeymcp.vault.policyseal": 683,
    "zoeymcp.vault.oauth.protocol": 674,
    "zoeymcp.vault.gatewaykeys": 550,
    "zoeymcp.vault.policystart": 548,
    "zoeymcp.common.yamlload": 431,
    "zoeymcp.common.policy.reviewchange": 430,
    "zoeymcp.portal.webauthn": 409,
    "zoeymcp.vault.oauth.login": 409,
    "zoeymcp.gateway.pins": 309,
    "zoeymcp.common.ledgerformat": 265,
    "zoeymcp.common.policy.emit": 245,
    "zoeymcp.vault.oauth.pkce": 240,
    "zoeymcp.common.policy.held": 232,
    "zoeymcp.common.reviewreport": 232,
    "zoeymcp.common.egresslist": 230,
    "zoeymcp.vault.holds": 204,
    "zoeymcp.common.netguard": 203,
    "zoeymcp.common.envelope": 196,
    "zoeymcp.common.approvaltext": 191,
    "zoeymcp.common.policy.fields": 189,
    "zoeymcp.vault.reviewjobs": 179,
    "zoeymcp.portal.passkeys": 176,
    "zoeymcp.vault.statusreport": 175,
    "zoeymcp.common.textrules": 164,
    "zoeymcp.vault.ledgerview": 162,
    "zoeymcp.common.policy.ratchet": 149,
    "zoeymcp.toolkit.params": 147,
    "zoeymcp.vault.bindings": 145,
    "zoeymcp.gateway.approvals": 142,
    "zoeymcp.bridge.relay": 140,
    "zoeymcp.vault.connectors.mailmsg": 135,
    "zoeymcp.vault.internal": 135,
    "zoeymcp.vault.reports": 135,
    "zoeymcp.common.policy.diff": 129,
    "zoeymcp.vault.secretplan": 128,
    "zoeymcp.gateway.findings": 125,
    "zoeymcp.vault.connectors.sendjournal": 104,
    "zoeymcp.common.policy.restart": 99,
    "zoeymcp.common.policy.merge": 97,
    "zoeymcp.bridge.framing": 96,
    "zoeymcp.entrypoint.env": 91,
    "zoeymcp.gateway.sanitize": 90,
    "zoeymcp.portal.sessions": 84,
    "zoeymcp.vault.oauth.dcr": 84,
    "zoeymcp.gateway.access": 81,
    "zoeymcp.vault.telegramwire": 79,
    "zoeymcp.common.heldresult": 78,
    "zoeymcp.portal.admission": 75,
    "zoeymcp.portal.approvalsview": 75,
    "zoeymcp.gateway.egressrules": 73,
    "zoeymcp.bridge.admit": 71,
    "zoeymcp.portal.policyview": 65,
    "zoeymcp.common.policy.export": 60,
    "zoeymcp.portal.refusals": 58,
    "zoeymcp.bridge.sessions": 55,
    "zoeymcp.portal.setupcode": 55,
    "zoeymcp.common.resultstore": 52,
    "zoeymcp.common.files": 51,
    "zoeymcp.gateway.witness": 46,
    "zoeymcp.egress.connect": 45,
    "zoeymcp.common.policy.gate": 40,
    "zoeymcp.toolkit.rules": 40,
    "zoeymcp.gateway.connstate": 38,
    "zoeymcp.portal.drafts": 33,
    "zoeymcp.portal.actions": 32,
    "zoeymcp.common.policy.attention": 29,
    "zoeymcp.gateway.reporting": 28,
    "zoeymcp.portal.listen": 25,
    "zoeymcp.gateway.capabilities": 21,
    "zoeymcp.portal.policydiffview": 20,
    "zoeymcp.common.pinhash": 19,
    "zoeymcp.portal.limits": 18,
    "zoeymcp.common.policy.serverpaths": 17,
    "zoeymcp.vault.connectors.tunnel": 16,
    "zoeymcp.bridge.childenv": 12,
    "zoeymcp.common.ledgerjoin": 12,
    "zoeymcp.portal.display": 12,
    "zoeymcp.gateway.approvalrules": 11,
    "zoeymcp.gateway.resourcematch": 11,
    "zoeymcp.gateway.routing": 11,
    "zoeymcp.portal.routes": 10,
    "zoeymcp.common.mcpwire": 9,
    "zoeymcp.common.policy.callback": 8,
    "zoeymcp.common.suggest": 8,
    "zoeymcp.vault.peer": 7,
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
