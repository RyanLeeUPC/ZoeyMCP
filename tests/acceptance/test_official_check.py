"""The host's official-image check, scripts/check-official-image.sh (M8 design L.5, L.6, Z25;
BP-5), run by ``sh`` against fixture compose files and a fixture digest list, with ``docker
compose config`` and ``gh`` stubbed by scripts on ``PATH``. The docker stub resolves the images
as Compose does for these files (``${...}`` with nested defaults and ``:?``, anchors and merge
keys, profiles, several files as one project), so the fixtures' shapes reach the script as
Compose would give them: an interpolated image, a nested default, an anchored third-party image
and a derived gateway image. The gh stub records each call and passes or fails it as told.

It spawns ``sh``, so it stays out of ``tests/unit`` and out of mutmut's copy, and runs on Linux,
the hosts the check is for.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Protocol

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="it spawns sh; the host check runs on Linux hosts (BP-5)"
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check-official-image.sh"
SHIPPED_LIST = ROOT / "release" / "digests.txt"
HARDENED = ROOT / "deploy" / "compose.hardened.yaml"
STANDARD = ROOT / "deploy" / "compose.yaml"
BRIDGE_STANDARD = ROOT / "examples" / "bridge" / "compose.standard.yaml"
BOUND = 30

INDEX = "sha256:" + "a" * 64
PLATFORM = "sha256:" + "b" * 64
TREE = "c" * 40
UNLISTED = "sha256:" + "e" * 64
OFFICIAL = "ghcr.io/ryanleeupc/zoeymcp"
PINNED = f"{OFFICIAL}@{INDEX}"
DERIVED = "zoeymcp-derived@sha256:" + "d" * 64
CADDY = "caddy:2.11.7-alpine@sha256:" + "f" * 64
LIST = f"# a fixture list\n\n0.1.0 {INDEX} {PLATFORM} {TREE}\n"
VERIFY = [
    "attestation",
    "verify",
    f"oci://{PINNED}",
    "--repo",
    "RyanLeeUPC/ZoeyMCP",
    "--signer-workflow",
    "RyanLeeUPC/ZoeyMCP/.github/workflows/release.yml",
    "--source-ref",
    "refs/tags/v0.1.0",
    "--deny-self-hosted-runners",
]
SBOM = ["--predicate-type", "https://spdx.dev/Document/v2.3"]

# The hardened tier's shape: the vault's image interpolated, the gateway's a nested default, and
# Caddy's an anchor (deploy/compose.hardened.yaml).
COMPOSE = f"""\
x-hardened: &hardened
  read_only: true
x-caddy: &caddy-image {CADDY}
services:
  vault:
    <<: *hardened
    image: ${{ZOEYMCP_IMAGE:-zoeymcp:local}}
  gateway:
    <<: *hardened
    image: ${{ZOEYMCP_GATEWAY_IMAGE:-${{ZOEYMCP_IMAGE:-zoeymcp:local}}}}
  lan:
    image: *caddy-image
"""

# ``docker compose -f FILE... config --images``, resolved as Compose resolves these files. Every
# call is logged as one JSON line.
DOCKER_STUB = r"""
import json, os, re, sys

import yaml

with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(["docker", *sys.argv[1:]]) + "\n")
args = sys.argv[1:]
files = [args[i + 1] for i, arg in enumerate(args) if arg == "-f"]
rest = [arg for i, arg in enumerate(args) if arg != "-f" and (i == 0 or args[i - 1] != "-f")]
if rest != ["compose", "config", "--images"] or not files:
    sys.exit(f"docker stub: not a call it knows: {args}")
INNERMOST = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|:\?)([^${}]*))?\}")


def value(match):
    name, kind, given = match.groups()
    if os.environ.get(name):
        return os.environ[name]
    if kind == ":?":
        sys.exit(f"required variable {name} is missing a value: {given}")
    return given if kind == ":-" else ""


services = {}
for path in files:
    with open(path, encoding="utf-8") as handle:
        text = handle.read().replace("$$", "\0")
    while True:
        replaced = INNERMOST.sub(value, text)
        if replaced == text:
            break
        text = replaced
    for name, service in (yaml.safe_load(text.replace("\0", "$")) or {})["services"].items():
        services.setdefault(name, {}).update(service)
active = set(filter(None, os.environ.get("COMPOSE_PROFILES", "").split(",")))
for service in services.values():
    if "image" in service and (not service.get("profiles") or active & set(service["profiles"])):
        print(service["image"])
"""

# ``gh --version`` and ``gh attestation verify``: GH_STUB_VERSION is its version, and
# GH_STUB_FAIL names the attestation that doesn't verify (provenance, or sbom).
GH_STUB = r"""
import json, os, sys

with open(os.environ["STUB_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(["gh", *sys.argv[1:]]) + "\n")
if sys.argv[1:] == ["--version"]:
    print(f"gh version {os.environ.get('GH_STUB_VERSION', '2.74.0')} (2025-06-11)")
    sys.exit(0)
kind = "sbom" if "--predicate-type" in sys.argv else "provenance"
if os.environ.get("GH_STUB_FAIL") == kind:
    sys.exit(f"gh stub: the {kind} attestation doesn't verify")
print(f"gh stub: the {kind} attestation verified")
"""


class Run:
    """One run of the script: its exit status, its output and the stubs' calls."""

    def __init__(self, done: subprocess.CompletedProcess[str], log: Path) -> None:
        self.status = done.returncode
        self.out = done.stdout
        self.err = done.stderr
        lines = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        self.calls: list[list[str]] = [json.loads(line) for line in lines]

    def gh(self) -> list[list[str]]:
        """The gh attestation calls, each without the leading ``gh``."""
        return [call[1:] for call in self.calls if call[:2] == ["gh", "attestation"]]


class Check(Protocol):
    def __call__(
        self,
        *args: str | Path,
        files: tuple[Path, ...] = ...,
        listed: Path | None = ...,
        **environ: str,
    ) -> Run: ...


@pytest.fixture
def check(tmp_path: Path) -> Check:
    stubs = tmp_path / "bin"
    stubs.mkdir(mode=0o700)
    for name, source in (("docker", DOCKER_STUB), ("gh", GH_STUB)):
        program = tmp_path / f"{name}_stub.py"
        program.write_bytes(source.encode("utf-8"))
        wrapper = stubs / name
        wrapper.write_bytes(f'#!/bin/sh\nexec "{sys.executable}" -I "{program}" "$@"\n'.encode())
        wrapper.chmod(0o700)
    compose = tmp_path / "compose.yaml"
    compose.write_bytes(COMPOSE.encode("utf-8"))
    digests = tmp_path / "digests.txt"
    digests.write_bytes(LIST.encode("utf-8"))
    log = tmp_path / "calls.jsonl"

    def run(
        *args: str | Path,
        files: tuple[Path, ...] = (compose,),
        listed: Path | None = digests,
        **environ: str,
    ) -> Run:
        given = [*files, *args, *(["--digests", listed] if listed else [])]
        env = {"PATH": f"{stubs}:/usr/bin:/bin", "STUB_LOG": str(log), **environ}
        if log.exists():
            log.unlink()
        done = subprocess.run(  # noqa: S603 - our own script and arguments
            ["/bin/sh", str(SCRIPT), *map(str, given)],
            env=env,
            capture_output=True,
            text=True,
            timeout=BOUND,
            check=False,
        )
        return Run(done, log)

    return run


def test_a_pinned_release_passes_and_a_third_party_image_is_not_checked(
    check: Check, tmp_path: Path
) -> None:
    """The vault's interpolated image and the gateway's nested default resolve to one release's
    index digest, checked once: provenance, then the SBOM, each against the release workflow at
    the release's tag. Caddy, an anchor, is reported and doesn't fail the check."""
    run = check(ZOEYMCP_IMAGE=PINNED)
    assert run.status == 0, run.out + run.err
    assert run.calls[0] == [
        "docker",
        "compose",
        "-f",
        str(tmp_path / "compose.yaml"),
        "config",
        "--images",
    ]
    assert run.gh() == [VERIFY, VERIFY + SBOM]
    lines = run.out.splitlines()
    assert f"not checked (third party): {CADDY}" in lines
    assert (
        f"official: {PINNED} (release 0.1.0; its provenance and SBOM attestations verified)"
        in lines
    )
    assert lines[-1] == "every ZoeyMCP image passed (1)"


def test_a_derived_gateway_is_not_checked_beside_the_official_vault(check: Check) -> None:
    """A derived image isn't official by construction; the check applies to the official vault
    beside it (and to the base it was built from, operations.md §37)."""
    run = check(ZOEYMCP_IMAGE=PINNED, ZOEYMCP_GATEWAY_IMAGE=DERIVED)
    assert run.status == 0, run.out + run.err
    assert f"not checked (third party): {DERIVED}" in run.out.splitlines()
    assert run.gh() == [VERIFY, VERIFY + SBOM]


def test_a_local_build_fails_unless_allowed(check: Check) -> None:
    """Nothing set: both defaults are zoeymcp:local, which isn't official; the line says how to
    check it against the source. gh is never asked. --allow-local passes it."""
    run = check()
    assert run.status == 1
    [line] = [line for line in run.out.splitlines() if line.startswith("FAIL ")]
    assert line.startswith("FAIL zoeymcp:local: not an official image (a local build);")
    assert "io.zoeymcp.source-tree" in line
    assert "git rev-parse 'HEAD^{tree}'" in line
    assert run.out.splitlines()[-1] == "not official: 1 of 1 ZoeyMCP images failed the check"
    assert run.gh() == []
    allowed = check("--allow-local")
    assert allowed.status == 0, allowed.out + allowed.err
    assert "allowed by --allow-local: zoeymcp:local is not an official image (a local build)" in (
        allowed.out.splitlines()
    )


def test_the_shipped_hardened_file_is_a_local_build_until_a_release(check: Check) -> None:
    """As shipped, the hardened tier's images default to zoeymcp:local (M8 design L.5: the pre-main
    release pass switches the defaults), which the check refuses as a local build."""
    run = check(files=(HARDENED,), ZOEYMCP_MASTER_KEY="set", ZOEYMCP_GATEWAY_KEY="set")
    assert run.status == 1, run.out + run.err
    assert any(line.startswith("FAIL zoeymcp:local: ") for line in run.out.splitlines())
    official = check(
        files=(HARDENED,),
        ZOEYMCP_MASTER_KEY="set",
        ZOEYMCP_GATEWAY_KEY="set",
        ZOEYMCP_IMAGE=PINNED,
    )
    assert official.status == 0, official.out + official.err
    assert official.gh() == [VERIFY, VERIFY + SBOM]


def test_the_bundle_and_the_trusted_root_are_passed_to_gh(check: Check, tmp_path: Path) -> None:
    """The offline path (OPS-16): the release's attestation bundle, one JSON-lines file holding
    both attestations, and a trusted root for a host with no network to GitHub, reach both
    verifications; gh takes the attestation of each call's predicate type from the one file."""
    bundle = tmp_path / "bundle.jsonl"
    bundle.write_bytes(b"{}\n")
    root = tmp_path / "trusted_root.jsonl"
    root.write_bytes(b"{}\n")
    run = check("--bundle", bundle, ZOEYMCP_IMAGE=PINNED)
    assert run.status == 0, run.out + run.err
    assert run.gh() == [
        [*VERIFY, "--bundle", str(bundle)],
        [*VERIFY, *SBOM, "--bundle", str(bundle)],
    ]
    both = check("--trusted-root", root, "--bundle", bundle, ZOEYMCP_IMAGE=PINNED)
    offline = ["--bundle", str(bundle), "--custom-trusted-root", str(root)]
    assert both.gh() == [VERIFY + offline, VERIFY + SBOM + offline]
    missing = check("--bundle", tmp_path / "absent.jsonl", ZOEYMCP_IMAGE=PINNED)
    assert missing.status == 2
    assert "no bundle at" in missing.err


@pytest.mark.parametrize(
    ("image", "expected"),
    [
        (f"{OFFICIAL}:0.1.0", "not pinned by digest (@sha256:...); a tag can be moved"),
        (
            f"{OFFICIAL}@sha256:" + "a" * 63,
            "not pinned by digest (@sha256:...); a tag can be moved",
        ),
        (f"{OFFICIAL}@{UNLISTED}", "not an official release's digest (not in "),
        (f"{OFFICIAL}@{PLATFORM}", "that is release 0.1.0's platform manifest digest; pin its"),
    ],
    ids=["tag", "short-digest", "unlisted", "platform-digest"],
)
def test_an_image_that_isnt_a_listed_index_digest_fails(
    check: Check, image: str, expected: str
) -> None:
    run = check(ZOEYMCP_IMAGE=image)
    assert run.status == 1
    assert f"FAIL {image}: {expected}" in run.out
    assert run.gh() == []


@pytest.mark.parametrize(
    ("failing", "expected"),
    [
        ("provenance", "release 0.1.0's provenance attestation didn't verify:"),
        ("sbom", "release 0.1.0's SBOM attestation didn't verify:"),
    ],
    ids=["provenance", "sbom"],
)
def test_an_attestation_that_doesnt_verify_fails(check: Check, failing: str, expected: str) -> None:
    run = check(ZOEYMCP_IMAGE=PINNED, GH_STUB_FAIL=failing)
    assert run.status == 1
    assert f"FAIL {PINNED}: {expected}" in run.out
    # gh's own words follow, indented.
    assert f"    gh stub: the {failing} attestation doesn't verify" in run.out.splitlines()


def test_an_empty_list_says_no_release_yet(check: Check, tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"# nothing released\n")
    run = check(listed=empty, ZOEYMCP_IMAGE=PINNED)
    assert run.status == 1
    assert run.out.splitlines()[0] == (
        f"{empty} lists no release yet: no image has been published, so no digest is official."
    )
    assert f"FAIL {PINNED}: not an official release's digest: {empty} lists no release yet" in (
        run.out.splitlines()
    )
    assert run.gh() == []


def test_the_shipped_list_is_read_by_default(check: Check) -> None:
    """Without --digests the script reads release/digests.txt beside it. Until the first release
    it lists none, and says so (M8 design L.5)."""
    run = check(listed=None, ZOEYMCP_IMAGE=PINNED)
    released = [
        line
        for line in SHIPPED_LIST.read_bytes().decode("utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    if released:
        assert run.status in (0, 1), run.out + run.err
    else:
        assert run.status == 1
        assert run.out.splitlines()[0].endswith(
            "/release/digests.txt lists no release yet: no image has been published, so no "
            "digest is official."
        )


@pytest.mark.parametrize(
    "line",
    [
        f"0.1.0 {INDEX} {PLATFORM}",
        f"v0.1.0 {INDEX} {PLATFORM} {TREE}",
        f"0.1.0  {INDEX} {PLATFORM} {TREE}",
        f"0.1.0 {INDEX} {PLATFORM} {TREE} extra",
        f"0.1.0 sha256:<digest> {PLATFORM} {TREE}",
    ],
    ids=["three-fields", "v-prefix", "two-spaces", "five-fields", "placeholder"],
)
def test_a_list_line_that_isnt_a_release_is_refused(
    check: Check, tmp_path: Path, line: str
) -> None:
    listed = tmp_path / "bad.txt"
    listed.write_bytes(f"# a comment\n{line}\n".encode())
    run = check(listed=listed, ZOEYMCP_IMAGE=PINNED)
    assert run.status == 2
    assert f"{listed} line 2 isn't <version> <index digest>" in run.err
    assert run.calls == []


def test_a_digest_listed_twice_is_refused(check: Check, tmp_path: Path) -> None:
    listed = tmp_path / "twice.txt"
    listed.write_bytes(f"{LIST}0.1.1 {INDEX} {PLATFORM} {TREE}\n".encode())
    run = check(listed=listed, ZOEYMCP_IMAGE=PINNED)
    assert run.status == 2
    assert f"lists {INDEX} for more than one release" in run.err


@pytest.mark.parametrize(
    "other",
    ["registry.example:5000/zoeymcp", "ghcr.io/someone-else/zoeymcp"],
    ids=["mirror", "look-alike"],
)
def test_another_name_for_zoeymcp_fails_unless_named(check: Check, other: str) -> None:
    """T36's mirror and look-alike name: an image named zoeymcp anywhere but the official name
    fails, and gh is never asked; named with --image, it is checked as the official one is."""
    unnamed = check(ZOEYMCP_IMAGE=f"{other}@{INDEX}")
    assert unnamed.status == 1
    assert (
        f"FAIL {other}@{INDEX}: not the official name {OFFICIAL}; to check a mirror of it, pass "
        "--image with the mirror's name"
    ) in unnamed.out.splitlines()
    assert unnamed.gh() == []
    named = check("--image", other, ZOEYMCP_IMAGE=f"{other}@{INDEX}")
    assert named.status == 0, named.out + named.err
    subject = f"oci://{other}@{INDEX}"
    assert [call[2] for call in named.gh()] == [subject, subject]


def test_files_with_no_zoeymcp_image_fail(check: Check) -> None:
    """The standard tier with a bridge (operations.md §33): the one container runs the derived
    image, so the files name no ZoeyMCP image, and the check fails rather than pass vacuously."""
    run = check(files=(STANDARD, BRIDGE_STANDARD), ZOEYMCP_MASTER_KEY="set")
    assert run.status == 1, run.out + run.err
    lines = run.out.splitlines()
    assert "not checked (third party): zoeymcp-bridge-fetch:local" in lines
    assert lines[-1].startswith(
        "FAIL: no ZoeyMCP image in these files, so nothing was checked; the vault must run the "
        "official image"
    )
    assert run.gh() == []


def test_several_files_are_one_project(check: Check, tmp_path: Path) -> None:
    """An override's image replaces the base file's, as ``docker compose -f a -f b`` reads them."""
    override = tmp_path / "override.yaml"
    override.write_bytes(f"services:\n  gateway:\n    image: {PINNED}\n".encode())
    run = check(files=(tmp_path / "compose.yaml", override), ZOEYMCP_IMAGE=PINNED)
    assert run.status == 0, run.out + run.err
    assert run.calls[0][:5] == ["docker", "compose", "-f", str(tmp_path / "compose.yaml"), "-f"]
    assert run.calls[0][5] == str(override)


def test_an_old_gh_is_refused(check: Check) -> None:
    run = check(ZOEYMCP_IMAGE=PINNED, GH_STUB_VERSION="2.73.9")
    assert run.status == 2
    assert "gh 2.73.9 is older than 2.74.0" in run.err
    assert run.gh() == []


def test_images_compose_cant_resolve_are_exit_2(check: Check, tmp_path: Path) -> None:
    required = tmp_path / "required.yaml"
    required.write_bytes(b"services:\n  vault:\n    image: ${ZOEYMCP_IMAGE:?pin it}\n")
    run = check(files=(required,))
    assert run.status == 2
    assert "required variable ZOEYMCP_IMAGE is missing a value" in run.err
    assert "couldn't resolve the images" in run.err


@pytest.mark.parametrize(
    "args",
    [(), ("--image",), ("--allow", "compose.yaml")],
    ids=["no-file", "no-value", "unknown-option"],
)
def test_a_usage_error_is_exit_2(check: Check, tmp_path: Path, args: tuple[str, ...]) -> None:
    run = check(*args, files=(), listed=None)
    assert run.status == 2
    assert "usage: check-official-image.sh" in run.err
    assert run.calls == []
