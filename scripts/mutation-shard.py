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
# Seconds of test time across each module's mutants, measured in CI on cc88902 (42,374 mutants).
# On 4fd8c97 a shard's mutmut step took about 60 s plus 38% of its total. A cut module's digits
# aren't equal shares (there, check's digit 4 took 644 s, its digit 2 1,494 s), so a shard can run
# up to a fifth over its share: SHARDS keeps room for that.
WEIGHTS = {
    "zoeymcp.common.policy.check": 15432,
    "zoeymcp.common.canonical": 2898,
    "zoeymcp.vault.oauth.tokens": 2811,
    "zoeymcp.vault.oauth.discovery": 2375,
    "zoeymcp.gateway.schemas": 2131,
    "zoeymcp.vault.health": 1482,
    "zoeymcp.vault.store": 1337,
    "zoeymcp.cli.choices": 1289,
    "zoeymcp.common.policy.change": 1269,
    "zoeymcp.portal.reviewview": 789,
    "zoeymcp.common.policy.plan": 779,
    "zoeymcp.vault.request": 776,
    "zoeymcp.common.policy.match": 719,
    "zoeymcp.common.policy.reviewchange": 693,
    "zoeymcp.vault.policyseal": 648,
    "zoeymcp.vault.gatewaykeys": 556,
    "zoeymcp.vault.oauth.login": 550,
    "zoeymcp.vault.onboarding": 535,
    "zoeymcp.vault.policystart": 515,
    "zoeymcp.gateway.pins": 503,
    "zoeymcp.common.policy.view": 459,
    "zoeymcp.common.reviewreport": 445,
    "zoeymcp.common.policy.emit": 440,
    "zoeymcp.vault.oauth.protocol": 392,
    "zoeymcp.common.yamlload": 389,
    "zoeymcp.portal.passkeys": 294,
    "zoeymcp.vault.reviewjobs": 293,
    "zoeymcp.portal.webauthn": 273,
    "zoeymcp.common.policy.fields": 271,
    "zoeymcp.vault.bindings": 268,
    "zoeymcp.common.policy.ratchet": 243,
    "zoeymcp.common.approvaltext": 237,
    "zoeymcp.common.policy.held": 234,
    "zoeymcp.vault.oauth.pkce": 232,
    "zoeymcp.vault.ledgerview": 226,
    "zoeymcp.vault.connectors.mailmsg": 219,
    "zoeymcp.common.egresslist": 202,
    "zoeymcp.common.policy.diff": 199,
    "zoeymcp.common.envelope": 194,
    "zoeymcp.common.ledgerformat": 193,
    "zoeymcp.vault.holds": 186,
    "zoeymcp.common.netguard": 178,
    "zoeymcp.gateway.findings": 160,
    "zoeymcp.gateway.access": 141,
    "zoeymcp.vault.secretplan": 139,
    "zoeymcp.toolkit.params": 131,
    "zoeymcp.vault.statusreport": 125,
    "zoeymcp.bridge.relay": 114,
    "zoeymcp.common.textrules": 112,
    "zoeymcp.gateway.egressrules": 111,
    "zoeymcp.vault.reports": 104,
    "zoeymcp.portal.admission": 101,
    "zoeymcp.bridge.framing": 99,
    "zoeymcp.common.policy.merge": 99,
    "zoeymcp.gateway.approvals": 97,
    "zoeymcp.common.resultstore": 94,
    "zoeymcp.vault.oauth.dcr": 87,
    "zoeymcp.common.files": 85,
    "zoeymcp.gateway.sanitize": 85,
    "zoeymcp.common.policy.gate": 81,
    "zoeymcp.vault.internal": 81,
    "zoeymcp.common.policy.restart": 79,
    "zoeymcp.common.heldresult": 78,
    "zoeymcp.portal.sessions": 78,
    "zoeymcp.portal.setupcode": 75,
    "zoeymcp.vault.connectors.sendjournal": 72,
    "zoeymcp.entrypoint.env": 67,
    "zoeymcp.common.policy.export": 64,
    "zoeymcp.bridge.sessions": 63,
    "zoeymcp.portal.refusals": 55,
    "zoeymcp.bridge.admit": 54,
    "zoeymcp.common.policy.attention": 44,
    "zoeymcp.gateway.reporting": 41,
    "zoeymcp.gateway.connstate": 38,
    "zoeymcp.portal.policyview": 38,
    "zoeymcp.common.policy.serverpaths": 37,
    "zoeymcp.portal.drafts": 36,
    "zoeymcp.egress.connect": 34,
    "zoeymcp.toolkit.rules": 30,
    "zoeymcp.portal.listen": 25,
    "zoeymcp.gateway.witness": 23,
    "zoeymcp.portal.actions": 22,
    "zoeymcp.common.pinhash": 19,
    "zoeymcp.gateway.capabilities": 19,
    "zoeymcp.common.ledgerjoin": 17,
    "zoeymcp.gateway.routing": 17,
    "zoeymcp.portal.limits": 17,
    "zoeymcp.bridge.childenv": 16,
    "zoeymcp.common.mcpwire": 16,
    "zoeymcp.vault.connectors.tunnel": 16,
    "zoeymcp.portal.routes": 15,
    "zoeymcp.gateway.resourcematch": 13,
    "zoeymcp.vault.peer": 13,
    "zoeymcp.portal.display": 11,
    "zoeymcp.portal.policydiffview": 11,
    "zoeymcp.common.suggest": 8,
    "zoeymcp.common.policy.callback": 7,
    "zoeymcp.vault.connectors.smtpflow": 7,
    "zoeymcp.gateway.approvalrules": 5,
    "zoeymcp.toolkit.plan": 4,
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
