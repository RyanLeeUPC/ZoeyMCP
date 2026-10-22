"""The policies in operations.md's egress how-tos load and pass ``check`` (M7 design P.2, steps 3a
and 17c).

A fenced block whose info string is ``yaml policy`` is a whole policy: every one in "Your own egress
proxy", "Fitting ZoeyMCP into an existing stack" and "The egress role" must parse with no
``check`` error, so a recipe can't drift from the schema. The first section's sample output (a
block starting with the emitter's header) must be what ``check --emit-egress-allowlist`` prints
for its policy, byte for byte, so the how-to shows the snippet as it really is.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from zoeymcp.common import egresslist
from zoeymcp.common.policy import Policy, check_policy, parse_policy

OPERATIONS = Path(__file__).resolve().parents[2] / "docs" / "operations.md"
SECTIONS = ("Your own egress proxy", "Fitting ZoeyMCP into an existing stack", "The egress role")
FENCE = re.compile(r"^( *)```([\w-]*)((?: [\w-]+)*)\n(.*?)^\1```\n", re.MULTILINE | re.DOTALL)
HEADER = "# zoeymcp egress allowlist, lists "


def section(title: str) -> str:
    """The text under the ``## <n>. <title>`` heading, up to the next ``## `` heading."""
    text = OPERATIONS.read_bytes().decode("utf-8")
    [start] = [m.end() for m in re.finditer(rf"^## \d+\. {re.escape(title)}\n", text, re.M)]
    following = re.search(r"^## ", text[start:], re.MULTILINE)
    return text[start : start + following.start()] if following else text[start:]


def blocks(text: str) -> list[tuple[str, str]]:
    """Each fenced block's info string and its body, the fence's indentation removed."""
    found = []
    for match in FENCE.finditer(text):
        indent = len(match.group(1))
        body = "".join(line[indent:] for line in match.group(4).splitlines(keepends=True))
        found.append(((match.group(2) + match.group(3)).strip(), body))
    return found


def policies(title: str) -> list[Policy]:
    return [
        parse_policy(body, title) for info, body in blocks(section(title)) if info == "yaml policy"
    ]


@pytest.mark.parametrize("title", SECTIONS)
def test_every_policy_in_the_recipe_passes_check(title: str) -> None:
    found = policies(title)
    assert found, f"no yaml policy block in {title!r}"
    for policy in found:
        errors = [f"{f.path}: {f.message}" for f in check_policy(policy) if f.level == "error"]
        assert errors == []


def test_the_own_proxy_recipe_shows_the_emitters_real_output() -> None:
    [policy] = policies(SECTIONS[0])
    lists = egresslist.derive(policy)
    shown = [body for info, body in blocks(section(SECTIONS[0])) if body.startswith(HEADER)]
    assert shown == [
        egresslist.render(lists, "text"),
        egresslist.render(lists, "squid", acl_names=policy.egress_proxy_acls),
    ]


def test_the_role_recipe_names_the_roles_vault_listener() -> None:
    """The role's section sends the vault through the profile's listener, as the role, and its
    connector's destination is in the vault's list the role allows (H15)."""
    [policy] = policies(SECTIONS[2])
    assert (policy.egress_proxy, policy.egress_proxy_kind) == ("http://egress-vault:3128", "role")
    destinations = {(d.host, d.port) for d in egresslist.derive(policy)["vault"]}
    assert ("smtp.mail.example", 465) in destinations


def test_blocks_finds_indented_and_tagged_fences() -> None:
    text = "a\n\n```yaml policy\nversion: 1\n```\n\n- item\n\n  ```text\n  one\n    two\n  ```\n"
    assert blocks(text) == [("yaml policy", "version: 1\n"), ("text", "one\n  two\n")]
