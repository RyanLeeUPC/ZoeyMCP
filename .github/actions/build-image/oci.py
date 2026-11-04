"""The OCI layout reader the build action and the release's publish job share (M8 design L.1, L.3).

Standard library only, run with the runner's own ``python3 -I``. Every blob read is checked against
its digest, so a digest printed here is recomputed, never copied from a file's name. A layout is
what ``docker buildx build --output type=oci,tar=false`` writes with attestations on: index.json
names one image index, which holds the platform manifest and its attestation manifest (platform
unknown/unknown), whose layers are in-toto statements, the SPDX SBOM and the SLSA provenance.

    oci.py digests LAYOUT           index-digest=, platform-digest= and source-tree= lines
    oci.py index FILE               the same digests of a raw image index (a pushed one, read back)
    oci.py compare FIRST SECOND     whether two builds' platform manifest digests match, and what
                                    differs if not; exits 1 on a difference
    oci.py candidate LAYOUT INSPECT that the image docker loaded (docker image inspect's JSON) is
                                    the layout's: the same layers and config
    oci.py sbom LAYOUT OUT          the SPDX document, as the file actions/attest's sbom-path needs
    oci.py identity LAYOUT ...      the identity allowlist over labels, the SBOM and the provenance
    oci.py scan REPORT MODE         grype's JSON report; with MODE enforce, a fixed High or Critical
                                    advisory in an OS package fails
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
SPDX = "https://spdx.dev/Document"
SLSA = "https://slsa.dev/provenance/"

# The identity allowlist (M8 design L.1, G-14): each value below is one the repository itself
# states; anything else fails, and a failure names the field, never its value, since a public log
# would publish what the check guards. The labels are the Dockerfile's (test_release_workflow.py
# holds the two to each other), the commit's revision and tree added.
REPOSITORY = "https://github.com/RyanLeeUPC/ZoeyMCP"
OWNER = "RyanLeeUPC"  # the repository owner's account
LABELS = {
    "org.opencontainers.image.title": "ZoeyMCP",
    "org.opencontainers.image.description": "Credential vault and MCP gateway for AI agents",
    "org.opencontainers.image.source": REPOSITORY,
    "org.opencontainers.image.licenses": "Apache-2.0",
}
REVISION_LABEL = "org.opencontainers.image.revision"
TREE_LABEL = "io.zoeymcp.source-tree"
# The SBOM's creators are the scanner's own lines: syft's organisation and the tool names of syft
# and BuildKit, each with its version.
CREATORS = frozenset({"Organization: Anchore, Inc"})
TOOL = re.compile(r"Tool: (?:syft|buildkit)-v?[0-9][0-9A-Za-z.+-]*")
NO_ONE = "NOASSERTION"

# The scan gates OS packages only: the Python packages are uv.lock's, which the advisories job
# checks on every dev push.
GATED_TYPES = frozenset({"deb"})
GATED_SEVERITIES = frozenset({"High", "Critical"})


class LayoutError(Exception):
    """A layout or index that isn't what a build makes."""


def blob(layout: Path, digest: str) -> bytes:
    """The blob named by ``digest``, checked against it."""
    algorithm, _, hexdigest = digest.partition(":")
    if algorithm != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", hexdigest):
        raise LayoutError(f"not a sha256 digest: {digest}")
    data = (layout / "blobs" / "sha256" / hexdigest).read_bytes()
    if hashlib.sha256(data).hexdigest() != hexdigest:
        raise LayoutError(f"the blob {digest} doesn't match its digest")
    return data


def document(layout: Path, digest: str) -> Any:
    return json.loads(blob(layout, digest))


def top(layout: Path) -> dict[str, Any]:
    """index.json's one entry: the image index."""
    entries = json.loads((layout / "index.json").read_bytes())["manifests"]
    if len(entries) != 1:
        raise LayoutError(f"index.json names {len(entries)} images, not one")
    entry: dict[str, Any] = entries[0]
    if entry.get("mediaType") not in INDEX_TYPES:
        raise LayoutError("index.json names no image index (a build without attestations?)")
    return entry


def platform_entry(manifests: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """The one entry that isn't an attestation manifest (those are platform unknown/unknown)."""
    found = [m for m in manifests if m.get("platform", {}).get("os") != "unknown"]
    if len(found) != 1:
        raise LayoutError(f"{len(found)} platform manifests, not one")
    return found[0]


def platform_digest(layout: Path) -> str:
    """The platform manifest's digest: the one two builds of a commit must share."""
    entry = platform_entry([top(layout)])
    while entry.get("mediaType") in INDEX_TYPES:
        entry = platform_entry(document(layout, entry["digest"])["manifests"])
    return str(entry["digest"])


def config(layout: Path) -> dict[str, Any]:
    manifest = document(layout, platform_digest(layout))
    found: dict[str, Any] = document(layout, manifest["config"]["digest"])
    return found


def digests(layout: Path) -> dict[str, str]:
    """The index digest (what the compose files pin and the attestations name), the platform
    manifest digest and the source tree the image's label states."""
    index = str(top(layout)["digest"])
    blob(layout, index)
    labels = config(layout).get("config", {}).get("Labels") or {}
    return {
        "index-digest": index,
        "platform-digest": platform_digest(layout),
        "source-tree": str(labels.get(TREE_LABEL, "")),
    }


def raw_index(data: bytes) -> dict[str, str]:
    """The digest of a raw image index, and the platform manifest it names."""
    index = json.loads(data)
    if index.get("mediaType") not in INDEX_TYPES:
        raise LayoutError("not an image index")
    return {
        "index-digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "platform-digest": str(platform_entry(index["manifests"])["digest"]),
    }


def statements(layout: Path) -> list[dict[str, Any]]:
    """The in-toto statements attached to the layout's platform manifest."""
    index = document(layout, str(top(layout)["digest"]))
    platform = platform_digest(layout)
    found = []
    for entry in index["manifests"]:
        annotations = entry.get("annotations", {})
        if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
            continue
        if annotations.get("vnd.docker.reference.digest") != platform:
            continue
        for layer in document(layout, entry["digest"])["layers"]:
            found.append(json.loads(blob(layout, layer["digest"])))
    return found


def predicate(layout: Path, prefix: str) -> dict[str, Any]:
    """The one attached statement's predicate whose type starts with ``prefix``."""
    found = [s for s in statements(layout) if str(s.get("predicateType", "")).startswith(prefix)]
    if len(found) != 1:
        raise LayoutError(f"{len(found)} attestations of type {prefix}, not one")
    body: dict[str, Any] = found[0]["predicate"]
    return body


def builder_id(provenance: dict[str, Any]) -> str:
    """SLSA v1's runDetails.builder.id, or v0.2's builder.id."""
    if "runDetails" in provenance:
        return str(provenance["runDetails"].get("builder", {}).get("id", ""))
    return str(provenance.get("builder", {}).get("id", ""))


def described(sbom: dict[str, Any]) -> set[str]:
    """The SPDX ids the document describes: its root packages."""
    roots = set(sbom.get("documentDescribes", []))
    for relation in sbom.get("relationships", []):
        if (
            relation.get("spdxElementId") == "SPDXRef-DOCUMENT"
            and relation.get("relationshipType") == "DESCRIBES"
        ):
            roots.add(relation.get("relatedSpdxElement"))
    return roots


def identity(
    labels: dict[str, str],
    sbom: dict[str, Any],
    provenance: dict[str, Any],
    *,
    revision: str,
    tree: str,
    builder: str,
    projects: Iterable[str],
    authors: Iterable[str],
) -> list[str]:
    """Each field outside the allowlist, by name: the labels exactly; the SBOM's creators; the
    supplier and originator of its root packages and of the project's own packages (a third
    party's packages name their own maintainers); the provenance's builder id, this run's."""
    problems = []
    expected = {**LABELS, REVISION_LABEL: revision, TREE_LABEL: tree}
    for key in sorted(set(labels) | set(expected)):
        if labels.get(key) != expected.get(key):
            problems.append(f"the label {key} isn't an allowed value")
    creators = sbom.get("creationInfo", {}).get("creators", [])
    if not creators:
        problems.append("the SBOM names no creator")
    for number, creator in enumerate(creators, 1):
        if creator not in CREATORS and not TOOL.fullmatch(str(creator)):
            problems.append(f"the SBOM's creator {number} isn't an allowed value")
    people = {NO_ONE, f"Organization: {OWNER}"} | {f"Person: {author}" for author in authors}
    roots = described(sbom)
    names = set(projects)
    for package in sbom.get("packages", []):
        if package.get("SPDXID") in roots:
            what = "root package"
        elif package.get("name") in names:
            what = f"package {package['name']}"
        else:
            continue
        for field in ("supplier", "originator"):
            if field in package and package[field] not in people:
                problems.append(f"the SBOM's {field} of its {what} isn't an allowed value")
    if builder_id(provenance) != builder:
        problems.append("the provenance's builder id isn't this run's")
    return problems


def project(pyproject: Path) -> tuple[list[str], list[str]]:
    """The project's names and its authors' names, as pyproject.toml states them."""
    data = tomllib.loads(pyproject.read_bytes().decode("utf-8"))["project"]
    authors = [str(a["name"]) for a in data.get("authors", []) if "name" in a]
    return [str(data["name"])], authors


def scan(report: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Every match grype reported, one line each, and those that gate: a High or Critical
    advisory with a fix, in an OS package."""
    lines = []
    gating = []
    for match in report.get("matches", []):
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        severity = str(vulnerability.get("severity", "Unknown"))
        fixed = ", ".join(vulnerability.get("fix", {}).get("versions", [])) or "a later version"
        line = (
            f"{severity} {vulnerability.get('id')} in {artifact.get('name')} "
            f"{artifact.get('version')} ({artifact.get('type')}), fixed in {fixed}"
        )
        lines.append(line)
        if artifact.get("type") in GATED_TYPES and severity in GATED_SEVERITIES:
            gating.append(line)
    return lines, gating


def layer_files(layout: Path, digest: str) -> dict[str, tuple[Any, ...]]:
    found = {}
    _, _, hexdigest = digest.partition(":")
    with tarfile.open(layout / "blobs" / "sha256" / hexdigest) as layer:
        for member in layer:
            body = layer.extractfile(member) if member.isfile() else None
            content = hashlib.sha256(body.read()).hexdigest()[:12] if body else ""
            found[member.name] = (
                oct(member.mode),
                member.uid,
                member.gid,
                member.mtime,
                member.linkname,
                content,
            )
    return found


def differences(first: Path, second: Path) -> list[str]:
    """What differs between two builds' platform manifests: the config's keys, the layer count,
    and each differing layer's entries (the first 20)."""
    manifests = [document(layout, platform_digest(layout)) for layout in (first, second)]
    configs = [config(layout) for layout in (first, second)]
    found = []
    for key in sorted(set(configs[0]) | set(configs[1])):
        if configs[0].get(key) != configs[1].get(key):
            found.append(f"- config: {key} differs")
    layers = [m["layers"] for m in manifests]
    if len(layers[0]) != len(layers[1]):
        found.append(f"- layers: {len(layers[0])} and {len(layers[1])}")
    for number, (one, two) in enumerate(zip(*layers, strict=False), 1):
        if one["digest"] == two["digest"]:
            continue
        files = [layer_files(first, one["digest"]), layer_files(second, two["digest"])]
        changed = sorted(
            n for n in set(files[0]) | set(files[1]) if files[0].get(n) != files[1].get(n)
        )
        found.append(f"- layer {number}: {len(changed)} entries differ")
        found.extend(
            f"  - {name}: {files[0].get(name)} / {files[1].get(name)}" for name in changed[:20]
        )
    return found


# What docker image inspect shows of the image config, by the config's own key.
INSPECTED = ("Env", "User", "Entrypoint", "Cmd", "WorkingDir", "Labels")


def candidate(layout: Path, inspected: list[dict[str, Any]]) -> list[str]:
    """Where the image docker loaded isn't the layout's: its layers (by diff id) and config."""
    [image] = inspected
    built = config(layout)
    problems = []
    if image.get("RootFS", {}).get("Layers") != built.get("rootfs", {}).get("diff_ids"):
        problems.append("its layers aren't the layout's")
    for key in INSPECTED:
        if (image.get("Config", {}).get(key) or None) != (built.get("config", {}).get(key) or None):
            problems.append(f"its {key} isn't the layout's")
    return problems


def _lines(values: dict[str, str]) -> None:
    for key, value in values.items():
        print(f"{key}={value}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="oci.py")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("digests").add_argument("layout", type=Path)
    commands.add_parser("index").add_argument("file", type=Path)
    compare = commands.add_parser("compare")
    compare.add_argument("first", type=Path)
    compare.add_argument("second", type=Path)
    loaded = commands.add_parser("candidate")
    loaded.add_argument("layout", type=Path)
    loaded.add_argument("inspect", type=Path)
    extract = commands.add_parser("sbom")
    extract.add_argument("layout", type=Path)
    extract.add_argument("out", type=Path)
    allowed = commands.add_parser("identity")
    allowed.add_argument("layout", type=Path)
    for option in ("--sbom", "--pyproject"):
        allowed.add_argument(option, type=Path, required=True)
    for option in ("--revision", "--tree", "--builder-id"):
        allowed.add_argument(option, required=True)
    scanned = commands.add_parser("scan")
    scanned.add_argument("report", type=Path)
    scanned.add_argument("mode", choices=["enforce", "report"])
    args = parser.parse_args(argv)

    if args.command == "digests":
        _lines(digests(args.layout))
    elif args.command == "index":
        _lines(raw_index(args.file.read_bytes()))
    elif args.command == "compare":
        names = [platform_digest(args.first), platform_digest(args.second)]
        print(f"Reproducible build: first {names[0]}, second {names[1]}")
        if names[0] == names[1]:
            print("The platform manifest digests match.")
            return 0
        print("The platform manifest digests differ.")
        print("\n".join(differences(args.first, args.second)))
        return 1
    elif args.command == "candidate":
        problems = candidate(args.layout, json.loads(args.inspect.read_bytes()))
        for problem in problems:
            print(f"the loaded image isn't the layout's: {problem}", file=sys.stderr)
        return 1 if problems else 0
    elif args.command == "sbom":
        args.out.write_bytes(json.dumps(predicate(args.layout, SPDX), indent=1).encode("utf-8"))
    elif args.command == "identity":
        projects, authors = project(args.pyproject)
        labels = config(args.layout).get("config", {}).get("Labels") or {}
        problems = identity(
            labels,
            json.loads(args.sbom.read_bytes()),
            predicate(args.layout, SLSA),
            revision=args.revision,
            tree=args.tree,
            builder=args.builder_id,
            projects=projects,
            authors=authors,
        )
        for problem in problems:
            print(f"identity allowlist: {problem}", file=sys.stderr)
        if not problems:
            print("identity allowlist: the labels, the SBOM and the provenance hold allowed values")
        return 1 if problems else 0
    else:
        lines, gating = scan(json.loads(args.report.read_bytes()))
        print(f"Scan of the SBOM: {len(lines)} fixed advisories, {len(gating)} gating")
        print("\n".join(f"- {line}" for line in lines))
        if gating and args.mode == "enforce":
            print(
                "a fixed High or Critical advisory in an OS package fails the build",
                file=sys.stderr,
            )
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
