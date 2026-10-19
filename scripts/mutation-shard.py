"""Print the mutant name patterns one mutation shard runs.

Usage: python scripts/mutation-shard.py --shard N --of COUNT

Every module in ``[tool.mutmut] only_mutate`` goes to exactly one shard. Modules are assigned
largest first to the lightest shard, by a weight measured from a full run (the estimated test time
of its mutants plus half a second per mutant); a module not in the table gets a middling weight.
The merge step fails if any mutant ran in no shard or in two, so a stale table only costs balance.
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WEIGHT = 500
# Measured on b65e3eb (13,255 mutants): estimated test seconds + 0.5 s per mutant.
WEIGHTS = {
    "zoeymcp.common.policy.check": 4917,
    "zoeymcp.vault.oauth.tokens": 4606,
    "zoeymcp.vault.store": 3976,
    "zoeymcp.common.canonical": 3972,
    "zoeymcp.vault.gatewaykeys": 1897,
    "zoeymcp.vault.oauth.protocol": 1604,
    "zoeymcp.common.policy.match": 1558,
    "zoeymcp.vault.request": 1400,
    "zoeymcp.vault.connectors.mailmsg": 1263,
    "zoeymcp.common.policy.view": 1022,
    "zoeymcp.common.approvaltext": 730,
    "zoeymcp.gateway.schemas": 670,
    "zoeymcp.vault.oauth.login": 616,
    "zoeymcp.vault.connectors.sendjournal": 551,
    "zoeymcp.common.textrules": 537,
    "zoeymcp.common.ledgerformat": 491,
    "zoeymcp.gateway.approvals": 456,
    "zoeymcp.toolkit.params": 403,
    "zoeymcp.vault.bindings": 337,
    "zoeymcp.gateway.access": 278,
    "zoeymcp.gateway.pins": 255,
    "zoeymcp.vault.oauth.pkce": 203,
    "zoeymcp.gateway.egressrules": 176,
    "zoeymcp.gateway.findings": 158,
    "zoeymcp.gateway.sanitize": 132,
    "zoeymcp.toolkit.rules": 101,
    "zoeymcp.vault.connectors.smtpflow": 90,
    "zoeymcp.gateway.connstate": 80,
    "zoeymcp.common.files": 66,
    "zoeymcp.vault.peer": 66,
    "zoeymcp.entrypoint.env": 59,
    "zoeymcp.vault.connectors.tunnel": 36,
    "zoeymcp.toolkit.plan": 12,
}


def modules(pyproject: Path = ROOT / "pyproject.toml") -> list[str]:
    """The dotted module names ``only_mutate`` lists, like ``zoeymcp.vault.request``."""
    with pyproject.open("rb") as handle:
        patterns = tomllib.load(handle)["tool"]["mutmut"]["only_mutate"]
    found = []
    for pattern in patterns:
        path = pattern.lstrip("*").removesuffix(".py").strip("/")
        found.append(path.replace("/", "."))
    return found


def shards(names: list[str], count: int) -> list[list[str]]:
    """``names`` in ``count`` groups of about equal weight, deterministically."""
    groups: list[list[str]] = [[] for _ in range(count)]
    loads = [0] * count
    for name in sorted(names, key=lambda n: (-WEIGHTS.get(n, DEFAULT_WEIGHT), n)):
        lightest = loads.index(min(loads))
        groups[lightest].append(name)
        loads[lightest] += WEIGHTS.get(name, DEFAULT_WEIGHT)
    return groups


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--shard", type=int, required=True)
    parser.add_argument("--of", type=int, required=True)
    args = parser.parse_args()
    if not 0 <= args.shard < args.of:
        print("--shard must be from 0 to --of minus 1", file=sys.stderr)
        return 2
    print(" ".join(f"{name}.*" for name in shards(modules(), args.of)[args.shard]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
