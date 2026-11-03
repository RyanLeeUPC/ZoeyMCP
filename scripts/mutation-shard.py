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
# Seconds of test time across each module's mutants, measured in CI on 3396f21 (43,322 mutants).
# On 4fd8c97 a shard's mutmut step took about 60 s plus 38% of its total. A cut module's digits
# aren't equal shares (there, check's digit 4 took 644 s, its digit 2 1,494 s), so a shard can run
# up to a fifth over its share: SHARDS keeps room for that.
WEIGHTS = {
    "zoeymcp.common.policy.check": 16194,
    "zoeymcp.common.canonical": 2910,
    "zoeymcp.vault.oauth.discovery": 2105,
    "zoeymcp.gateway.schemas": 2045,
    "zoeymcp.cli.choices": 1969,
    "zoeymcp.vault.oauth.tokens": 1797,
    "zoeymcp.vault.store": 1519,
    "zoeymcp.vault.health": 1513,
    "zoeymcp.portal.reviewview": 1118,
    "zoeymcp.common.policy.plan": 1112,
    "zoeymcp.common.policy.change": 927,
    "zoeymcp.common.policy.reviewchange": 790,
    "zoeymcp.vault.request": 761,
    "zoeymcp.vault.onboarding": 758,
    "zoeymcp.vault.oauth.login": 753,
    "zoeymcp.common.policy.view": 685,
    "zoeymcp.common.policy.match": 670,
    "zoeymcp.gateway.pins": 560,
    "zoeymcp.vault.policystart": 546,
    "zoeymcp.vault.gatewaykeys": 511,
    "zoeymcp.common.reviewreport": 439,
    "zoeymcp.common.yamlload": 425,
    "zoeymcp.vault.policyseal": 420,
    "zoeymcp.common.policy.emit": 398,
    "zoeymcp.portal.webauthn": 392,
    "zoeymcp.vault.oauth.protocol": 382,
    "zoeymcp.common.approvaltext": 316,
    "zoeymcp.vault.reviewjobs": 295,
    "zoeymcp.common.policy.held": 279,
    "zoeymcp.common.ledgerformat": 271,
    "zoeymcp.common.policy.fields": 257,
    "zoeymcp.vault.oauth.pkce": 245,
    "zoeymcp.portal.passkeys": 236,
    "zoeymcp.common.policy.ratchet": 222,
    "zoeymcp.vault.connectors.mailmsg": 212,
    "zoeymcp.common.envelope": 198,
    "zoeymcp.vault.holds": 196,
    "zoeymcp.common.textrules": 176,
    "zoeymcp.common.netguard": 175,
    "zoeymcp.vault.bindings": 170,
    "zoeymcp.vault.internal": 165,
    "zoeymcp.vault.ledgerview": 163,
    "zoeymcp.common.egresslist": 158,
    "zoeymcp.vault.statusreport": 157,
    "zoeymcp.gateway.findings": 155,
    "zoeymcp.gateway.sanitize": 144,
    "zoeymcp.bridge.relay": 140,
    "zoeymcp.gateway.approvals": 140,
    "zoeymcp.gateway.access": 137,
    "zoeymcp.common.policy.diff": 134,
    "zoeymcp.vault.oauth.dcr": 130,
    "zoeymcp.vault.reports": 129,
    "zoeymcp.toolkit.params": 128,
    "zoeymcp.gateway.egressrules": 111,
    "zoeymcp.common.policy.merge": 109,
    "zoeymcp.common.policy.restart": 98,
    "zoeymcp.portal.admission": 98,
    "zoeymcp.vault.secretplan": 98,
    "zoeymcp.vault.connectors.sendjournal": 96,
    "zoeymcp.bridge.framing": 95,
    "zoeymcp.entrypoint.env": 92,
    "zoeymcp.bridge.admit": 88,
    "zoeymcp.common.files": 83,
    "zoeymcp.common.heldresult": 75,
    "zoeymcp.vault.telegramwire": 69,
    "zoeymcp.common.policy.export": 65,
    "zoeymcp.bridge.sessions": 63,
    "zoeymcp.portal.policyview": 63,
    "zoeymcp.common.resultstore": 61,
    "zoeymcp.portal.sessions": 58,
    "zoeymcp.portal.refusals": 54,
    "zoeymcp.common.policy.attention": 47,
    "zoeymcp.common.policy.gate": 46,
    "zoeymcp.portal.setupcode": 43,
    "zoeymcp.toolkit.rules": 41,
    "zoeymcp.gateway.reporting": 40,
    "zoeymcp.common.policy.serverpaths": 39,
    "zoeymcp.portal.drafts": 37,
    "zoeymcp.gateway.witness": 36,
    "zoeymcp.egress.connect": 32,
    "zoeymcp.portal.actions": 28,
    "zoeymcp.portal.limits": 28,
    "zoeymcp.gateway.connstate": 27,
    "zoeymcp.portal.listen": 24,
    "zoeymcp.gateway.capabilities": 22,
    "zoeymcp.common.mcpwire": 19,
    "zoeymcp.portal.policydiffview": 18,
    "zoeymcp.portal.routes": 18,
    "zoeymcp.common.pinhash": 17,
    "zoeymcp.gateway.resourcematch": 17,
    "zoeymcp.gateway.routing": 16,
    "zoeymcp.common.suggest": 15,
    "zoeymcp.bridge.childenv": 14,
    "zoeymcp.common.ledgerjoin": 14,
    "zoeymcp.vault.connectors.tunnel": 11,
    "zoeymcp.portal.display": 10,
    "zoeymcp.common.policy.callback": 8,
    "zoeymcp.vault.peer": 8,
    "zoeymcp.gateway.approvalrules": 7,
    "zoeymcp.toolkit.plan": 4,
    "zoeymcp.vault.connectors.smtpflow": 4,
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
