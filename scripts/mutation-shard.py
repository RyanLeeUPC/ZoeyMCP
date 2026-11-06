"""Print the mutant name patterns one mutation shard runs.

Usage: python scripts/mutation-shard.py --shard N --of COUNT

Every mutant of the modules in ``[tool.mutmut] only_mutate`` is run by exactly one shard. A
module heavier than half an even share is cut into its ten last digits of the mutant numbers,
each weighted by its measured time (DIGIT_WEIGHTS), so no shard waits on one big module. The
parts are assigned largest first to the lightest shard, and a shard's digits of one module make
one pattern (``zoeymcp.common.policy.check.*__mutmut_*[038]``). The weights come from WEIGHTS and
DIGIT_WEIGHTS, which scripts/mutation-weights.py regenerates; a module not in WEIGHTS gets a
middling weight, and a cut module not in DIGIT_WEIGHTS ten equal digits. The merge step fails if
any mutant ran in no shard or in two, so a stale table only costs balance.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[1]
DIGITS = "0123456789"
DEFAULT_WEIGHT = 100
# Seconds of test time across each module's mutants, and per last digit of the mutant number for
# the modules with at least 1% of the total, measured in CI on 7dff31d (44,584 mutants). There a
# shard's job took about 7 minutes plus 0.358 of its weight (r = 0.93 over the 16 shards);
# predicted_seconds uses that fit, and mutation.yml's 25-minute rule applies to it.
JOB_OVERHEAD_SECONDS = 421
JOB_SECONDS_PER_WEIGHT = 0.358
WEIGHTS: dict[str, int] = {
    "zoeymcp.common.policy.check": 13514,
    "zoeymcp.vault.oauth.tokens": 2612,
    "zoeymcp.vault.oauth.discovery": 2505,
    "zoeymcp.common.canonical": 2182,
    "zoeymcp.vault.health": 1649,
    "zoeymcp.vault.store": 1618,
    "zoeymcp.cli.choices": 1342,
    "zoeymcp.common.policy.change": 1306,
    "zoeymcp.portal.reviewview": 1215,
    "zoeymcp.common.policy.plan": 1128,
    "zoeymcp.common.policy.view": 808,
    "zoeymcp.vault.onboarding": 783,
    "zoeymcp.common.policy.match": 780,
    "zoeymcp.vault.policyseal": 757,
    "zoeymcp.vault.oauth.protocol": 678,
    "zoeymcp.vault.request": 669,
    "zoeymcp.gateway.schemas": 633,
    "zoeymcp.vault.policystart": 546,
    "zoeymcp.vault.gatewaykeys": 487,
    "zoeymcp.common.policy.reviewchange": 461,
    "zoeymcp.common.reviewreport": 461,
    "zoeymcp.vault.oauth.login": 456,
    "zoeymcp.portal.webauthn": 394,
    "zoeymcp.common.policy.emit": 337,
    "zoeymcp.portal.passkeys": 336,
    "zoeymcp.common.policy.held": 297,
    "zoeymcp.gateway.pins": 297,
    "zoeymcp.common.egresslist": 287,
    "zoeymcp.common.approvaltext": 285,
    "zoeymcp.common.policy.ratchet": 270,
    "zoeymcp.common.yamlload": 269,
    "zoeymcp.common.policy.fields": 261,
    "zoeymcp.vault.holds": 230,
    "zoeymcp.vault.reviewjobs": 228,
    "zoeymcp.vault.connectors.mailmsg": 225,
    "zoeymcp.common.envelope": 210,
    "zoeymcp.common.ledgerformat": 201,
    "zoeymcp.vault.oauth.pkce": 192,
    "zoeymcp.common.netguard": 177,
    "zoeymcp.common.textrules": 176,
    "zoeymcp.vault.internal": 175,
    "zoeymcp.common.policy.diff": 170,
    "zoeymcp.vault.bindings": 170,
    "zoeymcp.gateway.findings": 168,
    "zoeymcp.vault.ledgerview": 156,
    "zoeymcp.gateway.sanitize": 146,
    "zoeymcp.vault.secretplan": 137,
    "zoeymcp.portal.approvalsview": 126,
    "zoeymcp.bridge.relay": 125,
    "zoeymcp.gateway.egressrules": 122,
    "zoeymcp.vault.oauth.dcr": 119,
    "zoeymcp.vault.telegramwire": 116,
    "zoeymcp.toolkit.params": 110,
    "zoeymcp.portal.admission": 108,
    "zoeymcp.common.policy.export": 107,
    "zoeymcp.entrypoint.env": 105,
    "zoeymcp.bridge.framing": 103,
    "zoeymcp.vault.statusreport": 103,
    "zoeymcp.common.policy.merge": 100,
    "zoeymcp.vault.reports": 99,
    "zoeymcp.bridge.admit": 97,
    "zoeymcp.gateway.access": 93,
    "zoeymcp.common.policy.restart": 90,
    "zoeymcp.portal.sessions": 85,
    "zoeymcp.common.heldresult": 80,
    "zoeymcp.gateway.approvals": 80,
    "zoeymcp.common.policy.gate": 75,
    "zoeymcp.common.resultstore": 68,
    "zoeymcp.portal.policyview": 66,
    "zoeymcp.common.files": 64,
    "zoeymcp.bridge.sessions": 59,
    "zoeymcp.vault.connectors.sendjournal": 59,
    "zoeymcp.portal.refusals": 56,
    "zoeymcp.egress.connect": 47,
    "zoeymcp.portal.setupcode": 47,
    "zoeymcp.common.policy.attention": 44,
    "zoeymcp.toolkit.rules": 42,
    "zoeymcp.portal.drafts": 38,
    "zoeymcp.gateway.connstate": 33,
    "zoeymcp.gateway.reporting": 32,
    "zoeymcp.gateway.witness": 30,
    "zoeymcp.portal.limits": 28,
    "zoeymcp.common.ledgerjoin": 24,
    "zoeymcp.common.policy.serverpaths": 24,
    "zoeymcp.gateway.capabilities": 23,
    "zoeymcp.portal.actions": 23,
    "zoeymcp.common.pinhash": 21,
    "zoeymcp.bridge.childenv": 20,
    "zoeymcp.gateway.routing": 19,
    "zoeymcp.portal.listen": 18,
    "zoeymcp.gateway.resourcematch": 17,
    "zoeymcp.portal.routes": 17,
    "zoeymcp.portal.policydiffview": 15,
    "zoeymcp.common.mcpwire": 13,
    "zoeymcp.vault.peer": 13,
    "zoeymcp.portal.display": 11,
    "zoeymcp.vault.connectors.tunnel": 11,
    "zoeymcp.common.suggest": 10,
    "zoeymcp.gateway.approvalrules": 10,
    "zoeymcp.vault.connectors.smtpflow": 7,
    "zoeymcp.common.policy.callback": 5,
    "zoeymcp.toolkit.plan": 3,
}
DIGIT_WEIGHTS: dict[str, tuple[int, ...]] = {
    "zoeymcp.common.policy.check": (1684, 1658, 1317, 924, 932, 1038, 1392, 1432, 1501, 1637),
    "zoeymcp.vault.oauth.tokens": (245, 215, 215, 354, 295, 271, 266, 273, 289, 189),
    "zoeymcp.vault.oauth.discovery": (263, 72, 284, 452, 299, 89, 244, 424, 293, 83),
    "zoeymcp.common.canonical": (71, 539, 308, 194, 44, 191, 309, 249, 230, 48),
    "zoeymcp.vault.health": (130, 154, 179, 150, 229, 144, 170, 193, 139, 160),
    "zoeymcp.vault.store": (158, 149, 139, 135, 141, 133, 235, 150, 242, 135),
    "zoeymcp.cli.choices": (161, 130, 119, 118, 133, 133, 124, 131, 141, 150),
    "zoeymcp.common.policy.change": (122, 67, 142, 97, 108, 191, 121, 71, 148, 241),
    "zoeymcp.portal.reviewview": (129, 105, 125, 116, 125, 111, 121, 125, 132, 126),
    "zoeymcp.common.policy.plan": (128, 69, 201, 87, 71, 155, 65, 73, 96, 183),
    "zoeymcp.common.policy.view": (43, 124, 74, 65, 81, 74, 113, 47, 91, 95),
    "zoeymcp.vault.onboarding": (81, 96, 69, 75, 65, 87, 57, 117, 55, 82),
    "zoeymcp.common.policy.match": (127, 12, 33, 175, 88, 10, 20, 10, 202, 103),
    "zoeymcp.vault.policyseal": (45, 55, 52, 52, 125, 86, 153, 83, 62, 45),
    "zoeymcp.vault.oauth.protocol": (59, 76, 62, 75, 63, 69, 68, 72, 62, 73),
    "zoeymcp.vault.request": (80, 85, 27, 105, 42, 111, 20, 40, 111, 49),
    "zoeymcp.gateway.schemas": (67, 49, 48, 143, 105, 42, 42, 39, 63, 34),
    "zoeymcp.vault.policystart": (29, 38, 77, 77, 76, 84, 75, 30, 30, 29),
    "zoeymcp.vault.gatewaykeys": (32, 34, 42, 34, 29, 29, 92, 105, 58, 31),
    "zoeymcp.common.policy.reviewchange": (41, 50, 55, 50, 45, 48, 45, 46, 41, 41),
    "zoeymcp.common.reviewreport": (75, 32, 91, 58, 55, 33, 36, 27, 27, 25),
    "zoeymcp.vault.oauth.login": (39, 48, 48, 52, 45, 51, 43, 46, 43, 41),
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
    """Each module whole, or, if heavier than half an even share, cut into its ten last digits."""
    weight = {name: WEIGHTS.get(name, DEFAULT_WEIGHT) for name in names}
    half_share = sum(weight.values()) / count / 2
    found = []
    for name in names:
        if weight[name] <= half_share:
            found.append(Part(name, DIGITS, weight[name]))
            continue
        measured = DIGIT_WEIGHTS.get(name, (1,) * len(DIGITS))
        for digit, share in zip(DIGITS, measured, strict=True):
            found.append(Part(name, digit, weight[name] * share / sum(measured)))
    return found


def shards(names: list[str], count: int) -> list[list[Part]]:
    """The parts of ``names`` in ``count`` groups of about equal weight, deterministically; a
    group's digits of one module are one part."""
    groups: list[list[Part]] = [[] for _ in range(count)]
    loads = [0.0] * count
    for part in sorted(parts(names, count), key=lambda p: (-p.weight, p.module, p.digits)):
        lightest = loads.index(min(loads))
        groups[lightest].append(part)
        loads[lightest] += part.weight
    merged: list[list[Part]] = []
    for group in groups:
        by_module: dict[str, list[Part]] = {}
        for part in group:
            by_module.setdefault(part.module, []).append(part)
        merged.append(
            [
                Part(module, "".join(sorted(p.digits for p in each)), sum(p.weight for p in each))
                for module, each in by_module.items()
            ]
        )
    return merged


def predicted_seconds(group: list[Part]) -> float:
    """A shard's job time on an average runner, from its parts' weights."""
    return JOB_OVERHEAD_SECONDS + JOB_SECONDS_PER_WEIGHT * sum(part.weight for part in group)


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
