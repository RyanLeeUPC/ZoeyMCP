"""The policies in operations.md's egress, bridge and managed policy how-tos load and pass
``check`` (M7 design P.2, steps 3a, 17c and 18e; M6 design P.1, BP-8, step 13b), and the public
docs say what M8's approvals close no wider than it is built (M8 design P.1, Z26, step 21).

A fenced block whose info string is ``yaml policy`` is a whole policy: every one in "Your own egress
proxy", "Fitting ZoeyMCP into an existing stack", "The egress role", "A stdio server behind a
bridge" and "Managed policy" must parse with no ``check`` error, so a recipe can't drift from the
schema. The first
section's sample output (a block starting with the emitter's header) must be what ``check
--emit-egress-allowlist`` prints for its policy, byte for byte, so the how-to shows the snippet
as it really is.

M8's rule for turning ``vault_approval`` off (A.4's one paragraph, the kind's name and the host
clause included) is written word for word in four places: design.md 6.4 and 7.1, operations.md's
Approvals section (§19, its managed-mode bullet) and threat-model.md's managed-mode limits. Z26's
scoped-claim sentence is in threat-model.md, the README and operations.md's §36, and no public
doc calls the gateway's approvals vault-enforced (T-14). Line breaks and indentation don't count:
each text is compared with its whitespace collapsed.

Every operations.md section with a recipe that edits the policy and reloads or recreates the vault
names its managed form too (an export, an edit and ``policy import``, or the portal's own change,
"in managed mode"), or is one of the sections whose recipes §34's general rule covers, which
opens "Managed policy" (M6 design P.1, D-218). The check is per section: a new section with such a
recipe and no managed form fails, and so does a section that loses its managed form; a second
recipe in a section that already names one isn't told apart.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from zoeymcp.common import egresslist
from zoeymcp.common.policy import Policy, check, check_policy, parse_policy
from zoeymcp.common.policy.schema import RemoteServer
from zoeymcp.common.yamlload import load_mapping

ROOT = Path(__file__).resolve().parents[2]
OPERATIONS = ROOT / "docs" / "operations.md"
DESIGN = ROOT / "docs" / "design.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
README = ROOT / "README.md"
BRIDGE_PROFILE = ROOT / "profiles" / "stdio-bridge.yaml"
# Every public doc: the README and docs/ (Z26).
PUBLIC = (README, *sorted((ROOT / "docs").glob("*.md")))
# M8 design A.4's one paragraph, final since the owner's answers (2026-11-01).
VAULT_OFF_RULE = (
    "`vault_approval` goes off only through the portal's own step-up kind "
    "`tool.vault_approval_off` (one tool, or every writer of one connector, per passkey, each "
    "with its own sentence) or a host import with `--accept-widening`; a portal save, review "
    "save, `include` drop or rollback that would drop a held tool is refused, and so is a host "
    "rollback."
)
# Z26's scoped claim: what M8 closes, by mechanism and only within scope.
SCOPED_CLAIM = (
    "M8 closes the approval gaps by mechanism and only within scope: a holder of an agent's token "
    "can't answer its own prompt for a `vault_approval` tool, or for any `approve` tool of an "
    "`out_of_band` client, and a compromised gateway or toolkit can't skip the approval of a "
    "`vault_approval` tool where only the vault can make the call (its route holds a credential, "
    "is a connector or a bridge, or the deployment is hardened); every other approval is the "
    "gateway's, which a compromised gateway or toolkit can still skip."
)
# T-14: a sentence calling the gateway's own approvals, a relayed or an elicited one,
# vault-enforced.
OVERCLAIM = re.compile(
    r"\b(?:gateway(?:-held|'s)?|relayed|elicited|elicitation|out-of-band) approvals? "
    r"(?:is|are) (?:also |now |then )?vault-enforced",
    re.IGNORECASE,
)
SECTIONS = (
    "Your own egress proxy",
    "Fitting ZoeyMCP into an existing stack",
    "The egress role",
    "A stdio server behind a bridge",
    "Managed policy",
)
FENCE = re.compile(r"^( *)```([\w-]*)((?: [\w-]+)*)\n(.*?)^\1```\n", re.MULTILINE | re.DOTALL)
HEADER = "# zoeymcp egress allowlist, lists "


def section(title: str) -> str:
    """The text under the ``## <n>. <title>`` heading, up to the next ``## `` heading."""
    text = OPERATIONS.read_bytes().decode("utf-8")
    [start] = [m.end() for m in re.finditer(rf"^## \d+\. {re.escape(title)}\n", text, re.M)]
    following = re.search(r"^## ", text[start:], re.MULTILINE)
    return text[start : start + following.start()] if following else text[start:]


def subsection(path: Path, number: str) -> str:
    return subsection_of(path.read_bytes().decode("utf-8"), number)


def subsection_of(text: str, number: str) -> str:
    """The text under a ``### <number> ...`` heading, up to the next heading of its level or
    above (a deeper one is part of it)."""
    [start] = [m.end() for m in re.finditer(rf"^### {re.escape(number)} .*\n", text, re.M)]
    following = re.search(r"^##?#? ", text[start:], re.MULTILINE)
    return text[start : start + following.start()] if following else text[start:]


def flat(text: str) -> str:
    """``text`` with every run of whitespace (a line break and its indentation included) one
    space, so a paragraph reads the same however it is wrapped."""
    return " ".join(text.split())


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


def test_the_bridge_how_to_is_the_profile_in_each_tier() -> None:
    """The bridge's how-to (M7 design C.9, C.10): its hardened policy is the S11 profile's route
    and server, and its standard one the same with the launcher's socket as the upstream, no
    opt-in and no egress list; both are local MCP routes."""
    hardened, standard = policies(SECTIONS[3])
    profile = load_mapping(BRIDGE_PROFILE.read_text(encoding="utf-8"))
    [shipped] = profile["routes"]
    for policy in (hardened, standard):
        [route] = policy.routes
        assert (route.name, route.prefix, route.credential) == (
            shipped["name"],
            shipped["prefix"],
            shipped["credential"],
        )
        assert check.local_mcp_routes(policy) == {route.name}
        assert policy.gateway is not None
        server = policy.gateway.servers["fetch"]
        assert isinstance(server, RemoteServer)
        assert (server.route, server.era) == (route.name, "legacy")
    [route] = hardened.routes
    assert route.upstream == shipped["upstream"]
    assert route.program is not None
    assert list(route.program.egress) == shipped["program"]["egress"]
    [route] = standard.routes
    assert route.upstream == "unix:/run/zoeymcp-bridge-fetch/mcp.sock"
    assert (route.allow_insecure_upstream, route.program) == (False, None)


# A recipe that edits the policy and reloads or recreates the vault, in the guide's wordings
# ("check and reload", "**Reload** the policy", "recreate the vault", `kill -s HUP vault`, ...).
RECIPE = re.compile(
    r"(?:\band|\bthen|,|\bor|\bfirst)\s+(?:reload|recreate (?:the vault|it|the container))\b"
    r"|\*\*Reload\*\*|\breload the policy\b|\brecreat(?:e|ing) the vault\b"
    r"|\bkill -s HUP vault\b|\bup -d vault\b",
    re.IGNORECASE,
)
# Its managed form beside it: the host's import, or what managed mode does instead.
MANAGED_FORM = re.compile(r"\bpolicy import\b|\bin managed mode\b", re.IGNORECASE)
# §34's general rule, the first words of "Managed policy".
GENERAL_RULE = (
    'In managed mode, every "edit the policy and reload" in this guide is an export, an edit and '
    "`zoeymcp policy import`, or the portal's own change where there is one."
)
# The sections the general rule covers: troubleshooting tables whose fix for a code is "fix the
# policy and reload", where a managed form on every row would repeat the rule.
COVERED_BY_THE_RULE = (
    "Logging in",
    "Credential health: `health`, `oauth status` and `oauth reset`",
    "Codes",
)


def numbered_sections() -> list[str]:
    """Every ``## <n>. <title>`` heading's title in operations.md, in order."""
    text = OPERATIONS.read_bytes().decode("utf-8")
    return re.findall(r"^## \d+\. (.+)\n", text, re.MULTILINE)


def test_the_general_rule_opens_managed_policy() -> None:
    assert flat(section("Managed policy")).startswith(f"**{GENERAL_RULE}**")


def test_every_reload_recipe_has_its_managed_form_beside_it() -> None:
    """A section that tells you to edit the policy and reload or recreate the vault also says
    what to do in managed mode, unless it is one the general rule covers (D-218)."""
    missing = [
        title
        for title in numbered_sections()
        if title != "Managed policy"
        and title not in COVERED_BY_THE_RULE
        and RECIPE.search(flat(section(title)))
        and not MANAGED_FORM.search(flat(section(title)))
    ]
    assert missing == [], "a reload recipe with no managed form beside it (§34's general rule)"


@pytest.mark.parametrize("title", COVERED_BY_THE_RULE)
def test_a_section_the_rule_covers_still_needs_it(title: str) -> None:
    """Each listed section still has a recipe and no managed form of its own: one that gains a
    managed form, or loses its recipe, comes off the list."""
    text = flat(section(title))
    assert RECIPE.search(text)
    assert MANAGED_FORM.search(text) is None


def test_the_recipe_guard_finds_what_it_is_for() -> None:
    for said in (
        "fix the policy (scope), reload, or `oauth reset`",
        "list its `host:port` in `egress_private` and reload (§7)",
        "4. **Reload** the policy (§7).",
        "remove the client and reload the policy.",
        "uncomment them and recreate the vault",
        "commit it and recreate the container",
        "For a policy file, `$c kill -s HUP vault` (§7).",
        "applied by recreating the vault: `$c up -d vault`.",
    ):
        assert RECIPE.search(said), said
    for said in (
        "A reload that fails in some other way logs `reload_failed`",
        "the gateway reloads its view",
        "after a restart, sign in again",
        "No reload: the policy names the secret",
    ):
        assert RECIPE.search(said) is None, said
    assert MANAGED_FORM.search("an export, an edit and `zoeymcp policy import`")
    assert MANAGED_FORM.search("In managed mode, **Pause** on the Policy page")
    assert MANAGED_FORM.search("managed policy, §34") is None


PLACES = {
    "design-6.4": lambda: subsection(DESIGN, "6.4"),
    "design-7.1": lambda: subsection(DESIGN, "7.1"),
    "operations-19": lambda: section("Approvals"),
    "threat-model": lambda: THREAT_MODEL.read_bytes().decode("utf-8"),
}


@pytest.mark.parametrize("place", sorted(PLACES))
def test_the_vault_off_rule_is_in_its_four_places(place: str) -> None:
    """A.4's paragraph, whole: the kind's name, its connector form and the host clause."""
    assert flat(VAULT_OFF_RULE) in flat(PLACES[place]())


CLAIMS = {
    "threat-model": lambda: THREAT_MODEL.read_bytes().decode("utf-8"),
    "readme": lambda: README.read_bytes().decode("utf-8"),
    "operations-36": lambda: section("Vault-enforced and out-of-band approvals"),
}


@pytest.mark.parametrize("place", sorted(CLAIMS))
def test_the_scoped_claim_is_said_where_m8_is_summed_up(place: str) -> None:
    assert flat(SCOPED_CLAIM) in flat(CLAIMS[place]())


@pytest.mark.parametrize("path", PUBLIC, ids=lambda path: path.name)
def test_no_public_doc_calls_the_gateways_approvals_vault_enforced(path: Path) -> None:
    text = flat(path.read_bytes().decode("utf-8"))
    assert OVERCLAIM.search(text) is None


def test_the_overclaim_guard_finds_what_it_is_for() -> None:
    for said in (
        "The gateway's approvals are vault-enforced.",
        "relayed approvals are also vault-enforced",
        "an elicited approval is vault-enforced",
        "Gateway-held approvals are now vault-enforced",
    ):
        assert OVERCLAIM.search(said), said
    for said in (
        "Vault-enforced approvals close the gap for vault_approval tools.",
        "a relay is recorded where: gateway and never called vault-enforced",
        "the gateway's approvals stay open",
    ):
        assert OVERCLAIM.search(said) is None, said


def test_the_flattened_text_ignores_wrapping() -> None:
    assert flat("one\n    two  three\n") == "one two three"


def test_a_subsection_ends_at_its_level() -> None:
    text = "### 6.4 Held\n\nbody\n#### deeper\nmore\n### 6.5 Next\nnot this\n## 7. On\n"
    assert subsection_of(text, "6.4") == "\nbody\n#### deeper\nmore\n"
    assert subsection_of(text, "6.5") == "not this\n"
    assert subsection_of("### 6.6 Last\ntail\n", "6.6") == "tail\n"


def test_blocks_finds_indented_and_tagged_fences() -> None:
    text = "a\n\n```yaml policy\nversion: 1\n```\n\n- item\n\n  ```text\n  one\n    two\n  ```\n"
    assert blocks(text) == [("yaml policy", "version: 1\n"), ("text", "one\n  two\n")]
