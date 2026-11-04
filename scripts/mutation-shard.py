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
# Seconds of test time across each module's mutants, measured in CI on 723abb2 (44,574 mutants).
# On 4fd8c97 a shard's mutmut step took about 60 s plus 38% of its total. A cut module's digits
# aren't equal shares (there, check's digit 4 took 644 s, its digit 2 1,494 s), so a shard can run
# up to a fifth over its share: SHARDS keeps room for that.
WEIGHTS = {
    "zoeymcp.common.policy.check": 13547,
    "zoeymcp.common.canonical": 3619,
    "zoeymcp.vault.oauth.tokens": 2568,
    "zoeymcp.vault.oauth.discovery": 2546,
    "zoeymcp.vault.store": 1646,
    "zoeymcp.gateway.schemas": 1608,
    "zoeymcp.common.policy.plan": 1484,
    "zoeymcp.cli.choices": 1439,
    "zoeymcp.vault.health": 1413,
    "zoeymcp.common.policy.change": 1391,
    "zoeymcp.portal.reviewview": 1323,
    "zoeymcp.common.policy.reviewchange": 912,
    "zoeymcp.vault.onboarding": 866,
    "zoeymcp.common.policy.view": 794,
    "zoeymcp.vault.request": 794,
    "zoeymcp.vault.oauth.login": 765,
    "zoeymcp.common.policy.match": 623,
    "zoeymcp.vault.gatewaykeys": 571,
    "zoeymcp.vault.oauth.protocol": 515,
    "zoeymcp.vault.policystart": 440,
    "zoeymcp.vault.policyseal": 420,
    "zoeymcp.portal.webauthn": 410,
    "zoeymcp.portal.passkeys": 340,
    "zoeymcp.gateway.pins": 302,
    "zoeymcp.common.egresslist": 300,
    "zoeymcp.common.policy.emit": 290,
    "zoeymcp.vault.bindings": 288,
    "zoeymcp.common.ledgerformat": 285,
    "zoeymcp.common.policy.held": 261,
    "zoeymcp.common.yamlload": 259,
    "zoeymcp.common.approvaltext": 254,
    "zoeymcp.vault.oauth.pkce": 253,
    "zoeymcp.common.policy.fields": 249,
    "zoeymcp.vault.internal": 248,
    "zoeymcp.common.policy.diff": 227,
    "zoeymcp.common.envelope": 221,
    "zoeymcp.common.reviewreport": 221,
    "zoeymcp.common.policy.ratchet": 211,
    "zoeymcp.common.netguard": 192,
    "zoeymcp.vault.holds": 191,
    "zoeymcp.common.textrules": 165,
    "zoeymcp.toolkit.params": 157,
    "zoeymcp.vault.reviewjobs": 154,
    "zoeymcp.gateway.access": 151,
    "zoeymcp.gateway.findings": 151,
    "zoeymcp.gateway.approvals": 145,
    "zoeymcp.bridge.relay": 144,
    "zoeymcp.portal.admission": 143,
    "zoeymcp.vault.oauth.dcr": 141,
    "zoeymcp.vault.connectors.mailmsg": 135,
    "zoeymcp.vault.ledgerview": 131,
    "zoeymcp.gateway.egressrules": 121,
    "zoeymcp.gateway.sanitize": 115,
    "zoeymcp.common.policy.export": 105,
    "zoeymcp.vault.connectors.sendjournal": 97,
    "zoeymcp.entrypoint.env": 96,
    "zoeymcp.bridge.framing": 95,
    "zoeymcp.portal.approvalsview": 95,
    "zoeymcp.vault.secretplan": 93,
    "zoeymcp.vault.statusreport": 93,
    "zoeymcp.portal.sessions": 88,
    "zoeymcp.common.heldresult": 81,
    "zoeymcp.common.policy.merge": 81,
    "zoeymcp.portal.setupcode": 79,
    "zoeymcp.common.policy.restart": 73,
    "zoeymcp.vault.reports": 69,
    "zoeymcp.vault.telegramwire": 69,
    "zoeymcp.common.files": 68,
    "zoeymcp.common.policy.gate": 67,
    "zoeymcp.bridge.admit": 61,
    "zoeymcp.portal.policyview": 58,
    "zoeymcp.common.resultstore": 54,
    "zoeymcp.portal.refusals": 53,
    "zoeymcp.bridge.sessions": 50,
    "zoeymcp.common.policy.attention": 49,
    "zoeymcp.gateway.witness": 49,
    "zoeymcp.toolkit.rules": 45,
    "zoeymcp.gateway.connstate": 40,
    "zoeymcp.portal.drafts": 37,
    "zoeymcp.portal.actions": 32,
    "zoeymcp.gateway.reporting": 30,
    "zoeymcp.egress.connect": 28,
    "zoeymcp.portal.limits": 28,
    "zoeymcp.bridge.childenv": 27,
    "zoeymcp.gateway.capabilities": 25,
    "zoeymcp.common.ledgerjoin": 20,
    "zoeymcp.common.pinhash": 20,
    "zoeymcp.common.mcpwire": 17,
    "zoeymcp.common.policy.serverpaths": 17,
    "zoeymcp.gateway.resourcematch": 15,
    "zoeymcp.portal.listen": 14,
    "zoeymcp.vault.connectors.tunnel": 13,
    "zoeymcp.vault.peer": 12,
    "zoeymcp.gateway.approvalrules": 11,
    "zoeymcp.gateway.routing": 11,
    "zoeymcp.portal.policydiffview": 10,
    "zoeymcp.common.policy.callback": 8,
    "zoeymcp.common.suggest": 8,
    "zoeymcp.portal.display": 8,
    "zoeymcp.portal.routes": 8,
    "zoeymcp.vault.connectors.smtpflow": 8,
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
