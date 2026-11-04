"""The release pipeline (M8 design L.1-L.3, L.6; Z24, T-6, SC-4, SC-12, SC-13, E-4, E-5, F15).

``release.yml`` runs on a ``v*`` tag push alone, with each job's exact permissions: ``guard`` and
``build`` read only and with no environment, ``guard`` checking the ancestry on a full checkout
before anything else, ``publish`` and ``release-notes`` under ``environment: release``, and
``publish`` running no build, scan or diff tool. Every checkout in every workflow and in the build
action sets ``persist-credentials: false``; every remote ``uses:`` is a 40-hex SHA and the only
local one is ``./.github/actions/build-image``, which ci.yml's dry run and release.yml's build use;
the action pushes nothing, builds twice on the BuildKit ci.yml pins, and compares the builds;
Dependabot and CI's lint and types cover it. The attestations name the index digest and the image,
push to the registry and create no storage record. The action's ``oci.py`` is run on fixture
layouts here: it recomputes digests, skips the attestation manifest, refuses a layout that names
more or fewer than one of each, reports what differs between two builds, extracts the SBOM,
prints the lines publish greps, refuses every identity value outside its allowlist without
printing it, and gates only a fixed High or Critical OS-package advisory. The repository's own
``.github``, ``Dockerfile`` and ``pyproject.toml`` are read, all copied by mutmut (the first two
in ``also_copy``).
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import tarfile
import tomllib
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
GITHUB = ROOT / ".github"
WORKFLOWS = sorted((GITHUB / "workflows").glob("*.yml"))
ACTION = GITHUB / "actions" / "build-image" / "action.yml"
LOCAL_ACTION = "./.github/actions/build-image"
PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")
IMAGE_PIN = re.compile(r"[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}")
IMAGE = "ghcr.io/ryanleeupc/zoeymcp"
# What publish must never run: the tools that build, scan or diff an image.
TOOLS = ("buildx", "docker build", "grype", "syft", "diffoci", "trivy")


def load_oci() -> ModuleType:
    path = GITHUB / "actions" / "build-image" / "oci.py"
    spec = importlib.util.spec_from_file_location("build_image_oci", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


oci = load_oci()


def read(path: Path) -> dict[Any, Any]:
    document: dict[Any, Any] = yaml.safe_load(path.read_bytes())
    return document


def release() -> dict[Any, Any]:
    return read(GITHUB / "workflows" / "release.yml")


def jobs() -> dict[str, Any]:
    found: dict[str, Any] = release()["jobs"]
    return found


def steps_of(path: Path) -> Iterator[dict[str, Any]]:
    """Every step of a workflow's jobs, or of the composite action."""
    document = read(path)
    if "runs" in document:
        yield from document["runs"]["steps"]
        return
    for job in document["jobs"].values():
        yield from job.get("steps", [])


def text(step: dict[str, Any]) -> str:
    return str(step.get("run", ""))


def action_steps() -> dict[str, dict[str, Any]]:
    return {str(step.get("name", step.get("uses"))): step for step in steps_of(ACTION)}


# --- release.yml (L.3, L.6) ----------------------------------------------------------------------


def test_the_only_trigger_is_a_v_tag_push() -> None:
    # PyYAML reads the key `on` as True.
    assert release()[True] == {"push": {"tags": ["v*"]}}
    assert release()["permissions"] == {"contents": "read"}


def test_each_job_has_exactly_its_permissions() -> None:
    assert {name: job.get("permissions") for name, job in jobs().items()} == {
        "guard": {"contents": "read"},
        "build": {"contents": "read"},
        "publish": {
            "contents": "read",
            "packages": "write",
            "id-token": "write",
            "attestations": "write",
        },
        "release-notes": {"contents": "write"},
    }
    assert {name: job.get("environment") for name, job in jobs().items()} == {
        "guard": None,
        "build": None,
        "publish": "release",
        "release-notes": "release",
    }
    assert {name: job.get("needs") for name, job in jobs().items()} == {
        "guard": None,
        "build": "guard",
        "publish": ["guard", "build"],
        "release-notes": "publish",
    }
    for job in jobs().values():
        assert 0 < job["timeout-minutes"] <= 45
        assert job["runs-on"] == "ubuntu-24.04"


def test_the_guard_checks_the_ancestry_first_on_a_full_checkout() -> None:
    [checkout, check] = jobs()["guard"]["steps"]
    assert checkout["uses"].startswith("actions/checkout@")
    assert checkout["with"] == {"fetch-depth": 0, "persist-credentials": False}
    run = text(check)
    fetch = "git fetch --no-tags origin +refs/heads/main:refs/remotes/origin/main\n"
    ancestry = 'if ! git merge-base --is-ancestor "$GITHUB_SHA" origin/main; then\n'
    refused = 'echo "refused: a release tag must name a commit on main" >&2\n'
    assert run.index(fetch) < run.index(ancestry) < run.index(refused)
    # A tag off main fails on the ancestry whatever else is wrong with it (E-1).
    assert run.index(refused) < run.index("v[0-9]+") < run.index('"${TAG#v}"')
    assert "grep -Eqx 'v[0-9]+\\.[0-9]+\\.[0-9]+'" in run
    assert check["env"] == {"TAG": "${{ github.ref_name }}"}


def test_the_build_job_runs_the_action_enforced_and_hands_on_its_layout() -> None:
    steps = jobs()["build"]["steps"]
    [built] = [step for step in steps if step.get("uses") == LOCAL_ACTION]
    assert built["with"] == {"ref": "${{ github.sha }}", "compare": "enforce", "scan": "enforce"}
    [upload] = [step for step in steps if str(step.get("uses", "")).startswith("actions/upload")]
    assert upload["with"]["name"] == "image"
    assert upload["with"]["path"].splitlines() == [
        "${{ steps.image.outputs.layout }}",
        "${{ steps.image.outputs.sbom }}",
    ]
    outputs = jobs()["build"]["outputs"]
    assert outputs["index-digest"] == "${{ steps.image.outputs.index-digest }}"
    assert outputs["platform-digest"] == "${{ steps.image.outputs.platform-digest }}"


def test_publish_runs_no_build_scan_or_diff_tool() -> None:
    for step in jobs()["publish"]["steps"]:
        assert step.get("uses") != LOCAL_ACTION
        said = (text(step) + str(step.get("uses", ""))).lower()
        assert not [tool for tool in TOOLS if tool in said], step
    names = [step.get("name") for step in jobs()["publish"]["steps"]]
    # The layout is checked before the push, and the pushed index after it.
    assert names.index("The downloaded layout is the one build compared") < names.index(
        "Push the compared layout by its digest"
    )
    assert names.index("Push the compared layout by its digest") < names.index(
        "The pushed index is the compared one"
    )
    assert names.index("The pushed index is the compared one") < names.index(
        "Provenance attestation"
    )


def test_publish_pushes_the_compared_layout_by_its_digest() -> None:
    steps = {step.get("name"): step for step in jobs()["publish"]["steps"]}
    push = text(steps["Push the compared layout by its digest"])
    assert '"$SKOPEO" copy --all --preserve-digests --authfile /auth.json \\\n' in push
    assert 'oci:/image "docker://$IMAGE@$INDEX"' in push
    assert '--volume "$RUNNER_TEMP/release/image:/image:ro"' in push
    pushed = text(steps["The pushed index is the compared one"])
    assert 'inspect --raw --authfile /auth.json "docker://$IMAGE@$INDEX"' in pushed
    assert 'grep -Fqx "platform-digest=$PLATFORM"' in pushed
    downloaded = text(steps["The downloaded layout is the one build compared"])
    assert 'grep -Fqx "index-digest=$INDEX"' in downloaded
    assert 'grep -Fqx "platform-digest=$PLATFORM"' in downloaded
    assert release()["env"]["IMAGE"] == IMAGE
    assert IMAGE_PIN.fullmatch(release()["env"]["SKOPEO"])


def test_the_attestations_name_the_pushed_index() -> None:
    attests = [
        step
        for step in jobs()["publish"]["steps"]
        if str(step.get("uses", "")).startswith("actions/attest@")
    ]
    assert len(attests) == 2
    for step in attests:
        given = step["with"]
        assert given["subject-name"] == IMAGE
        assert given["subject-digest"] == "${{ needs.build.outputs.index-digest }}"
        assert given["push-to-registry"] is True
        assert given["create-storage-record"] is False
    assert "sbom-path" not in attests[0]["with"]
    assert attests[1]["with"]["sbom-path"] == "${{ runner.temp }}/release/sbom.spdx.json"


def test_only_release_notes_writes_to_the_repository() -> None:
    [create] = [step for step in jobs()["release-notes"]["steps"] if "run" in step]
    run = text(create)
    assert 'gh release create "$TAG" --repo "$GITHUB_REPOSITORY" --verify-tag' in run
    for field in ("$INDEX", "$PLATFORM", "$TREE", "$BUILDKIT"):
        assert field in run
    assert '"$RUNNER_TEMP/attestations/zoeymcp-$TAG.jsonl"' in run
    assert create["env"]["GH_TOKEN"] == "${{ github.token }}"
    for name, job in jobs().items():
        if name != "release-notes":
            assert job["permissions"].get("contents") == "read", name


def test_the_header_says_no_tag_before_the_settings() -> None:
    header = (GITHUB / "workflows" / "release.yml").read_bytes().decode("utf-8").split("\non:")[0]
    said = " ".join(line.lstrip("# ") for line in header.splitlines())
    assert "NO v* TAG MAY BE PUSHED to this repository" in said
    for setting in ("a tag ruleset", "immutable releases", "a required reviewer"):
        assert setting in said


# --- every workflow and the action (SC-13, L.6) --------------------------------------------------


def test_there_are_the_workflows_and_the_action() -> None:
    names = [path.name for path in WORKFLOWS]
    assert names == ["advisories.yml", "ci.yml", "mutation.yml", "release.yml"]
    assert ACTION.is_file()


@pytest.mark.parametrize("path", [*WORKFLOWS, ACTION], ids=lambda path: path.name)
def test_every_checkout_keeps_no_credentials(path: Path) -> None:
    for step in steps_of(path):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step["with"]["persist-credentials"] is False, path.name


@pytest.mark.parametrize("path", [*WORKFLOWS, ACTION], ids=lambda path: path.name)
def test_every_remote_action_is_pinned_by_sha(path: Path) -> None:
    for step in steps_of(path):
        uses = step.get("uses")
        if uses is not None and uses != LOCAL_ACTION:
            assert PINNED.fullmatch(uses), uses
    # Each line that names one says which release its SHA is.
    for line in path.read_bytes().decode("utf-8").splitlines():
        if line.lstrip("- ").startswith("uses: ") and LOCAL_ACTION not in line:
            assert re.fullmatch(r" *(- )?uses: \S+@[0-9a-f]{40} # v[0-9]+\.[0-9]+\.[0-9]+", line)


def test_the_build_action_is_used_only_by_its_local_path_and_by_both_callers() -> None:
    callers = []
    for path in [*WORKFLOWS, ACTION]:
        document = read(path)
        for name, job in document.get("jobs", {}).items():
            for step in job.get("steps", []):
                uses = str(step.get("uses", ""))
                if "build-image" in uses:
                    assert uses == LOCAL_ACTION
                    callers.append(f"{path.name}:{name}")
                # A local action is read from the checkout, so the job checks out first.
                if uses == LOCAL_ACTION:
                    first = job["steps"][0]
                    assert str(first["uses"]).startswith("actions/checkout@")
    assert callers == ["ci.yml:release-dry-run", "release.yml:build"]


def test_the_updater_and_ci_cover_the_build_action() -> None:
    # Dependabot updates a composite action's pins only when its own folder is listed.
    [updates] = [
        entry
        for entry in read(GITHUB / "dependabot.yml")["updates"]
        if entry["package-ecosystem"] == "github-actions"
    ]
    assert sorted(GITHUB.glob("actions/*/action.yml")) == [ACTION]
    assert updates["directories"] == ["/", "/.github/actions/build-image"]
    # oci.py runs in the dry run and in publish, so CI lints, formats and type-checks it.
    lint = [text(step) for step in read(GITHUB / "workflows" / "ci.yml")["jobs"]["lint"]["steps"]]
    for command in ("ruff check ", "ruff format --check "):
        [run] = [line for line in lint if command in line]
        assert run.split()[-1] == ".github/actions/build-image", command
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_bytes().decode("utf-8"))
    assert ".github/actions/build-image" in pyproject["tool"]["mypy"]["files"]


# --- the dry run (L.2) ---------------------------------------------------------------------------


def test_the_dry_run_has_read_access_only_and_reports_its_scan() -> None:
    job = read(GITHUB / "workflows" / "ci.yml")["jobs"]["release-dry-run"]
    assert job["name"] == "image release dry run"
    assert job["permissions"] == {"contents": "read"}
    assert "environment" not in job
    assert job["timeout-minutes"] == 45
    [_, built] = job["steps"]
    assert built["uses"] == LOCAL_ACTION
    assert built["with"]["ref"] == "${{ github.sha }}"
    assert built["with"]["scan"] == "report"
    # BP-4: report until this job's own first compare matches, then this one line is enforce.
    assert built["with"]["compare"] in ("report", "enforce")
    assert "id-token" not in json.dumps(read(GITHUB / "workflows" / "ci.yml"))


# --- the build action (L.1) ----------------------------------------------------------------------


def test_the_action_builds_twice_on_the_pinned_buildkit_and_compares() -> None:
    steps = action_steps()
    pins = text(steps["Pins and inputs"])
    [buildkit] = re.findall(r'echo "buildkit=(\S+)"', pins)
    ci = read(GITHUB / "workflows" / "ci.yml")["jobs"]["image"]["steps"]
    [repro] = [step for step in ci if "Reproducible build" in str(step.get("name"))]
    assert f"buildkit={buildkit}\n" in text(repro)
    for tool in ("buildkit", "syft", "grype"):
        [pin] = re.findall(rf'echo "{tool}=(\S+)"', pins)
        assert IMAGE_PIN.fullmatch(pin), tool
    [buildx] = [step for step in steps.values() if "setup-buildx" in str(step.get("uses"))]
    # Not the selected builder: the recipes' plain docker build must stay on the docker driver,
    # the only one that sees the image the builds loaded into docker.
    assert buildx["with"] == {
        "driver": "docker-container",
        "driver-opts": "image=${{ steps.pins.outputs.buildkit }}",
        "use": False,
    }
    for step in steps_of(ACTION):
        assert not re.search(r"buildx use|--use\b", text(step)), step.get("name")
    build = text(steps["Build twice, each from scratch on a fresh builder"])
    assert "for build in image again; do\n" in build
    # Two calls a build: the attested OCI layout, then the same build from the cache with no
    # attestations, loaded into docker (the docker exporter can't load an index).
    assert build.count("docker buildx build ") == 2
    attested, loaded = build.split("docker buildx build ")[1:]
    assert '--output "type=oci,' in attested
    assert "type=docker" not in attested
    assert "--provenance=false --sbom=false \\\n" in loaded
    assert '--output "type=docker,name=zoeymcp-candidate:$build,rewrite-timestamp=true"' in loaded
    assert '--provenance "mode' not in loaded
    assert '--sbom "generator' not in loaded
    assert '--provenance "mode=max,builder-id=$BUILDER_ID"' in build
    assert '--sbom "generator=$SYFT"' in build
    assert 'SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"' in build
    assert '--output "type=oci,dest=$WORK/$build,tar=false,rewrite-timestamp=true"' in build
    assert '--driver-opt "image=$BUILDKIT"' in build
    compare = steps["The two builds' platform manifest digests match"]
    run = text(compare)
    assert 'oci.py" compare "$WORK/image" "$WORK/again"' in run
    assert "diffoci diff --semantic" in run.replace('"$WORK/diffoci" diff', "diffoci diff")
    assert 'if [ "$COMPARE" = enforce ]; then' in run
    # diffoci's fetch and hash check are one guarded condition: a failure warns, never fails a
    # report, and a binary that isn't its digest never runs.
    guarded = run.index('if curl -fsSL -o "$WORK/diffoci"')
    checked = run.index("| sha256sum -c - \\\n")
    ran = run.index('"$WORK/diffoci" diff')
    warned = run.index('echo "::warning::diffoci unavailable;')
    assert guarded < checked < run.index("; then\n", checked) < ran < warned
    assert warned < run.index('if [ "$COMPARE" = enforce ]; then')


def test_the_action_pushes_nothing_and_holds_no_token() -> None:
    for step in steps_of(ACTION):
        said = text(step) + json.dumps(step.get("with", {})) + json.dumps(step.get("env", {}))
        words = ("docker push", "--push", "type=registry", "skopeo", "docker login", "github.token")
        for word in (*words, "secrets."):
            assert word not in said.lower(), (step.get("name"), word)
    assert "push" not in json.dumps(read(ACTION)["inputs"])


def test_the_action_refuses_other_inputs_and_another_head() -> None:
    pins = text(action_steps()["Pins and inputs"])
    assert "enforce | report) ;;\n" in pins
    assert 'if [ "$head" != "$REF" ]; then\n' in pins
    assert set(read(ACTION)["inputs"]) == {"ref", "compare", "scan"}


def test_the_action_checks_what_l1_lists_in_order() -> None:
    names = list(action_steps())
    order = [
        "Build twice, each from scratch on a fresh builder",
        "The two builds' platform manifest digests match",
        "The loaded image is the layout's, and its digests",
        "Labels match the source",
        "The SBOM, as a file",
        "Identity allowlist",
        "Scan the SBOM's OS packages",
        "The bridge and derived recipes, built from this image and verified against it",
        "The official-image check, against a fixture digest list",
    ]
    assert [name for name in names if name in order] == order
    steps = action_steps()
    scan = text(steps["Scan the SBOM's OS packages"])
    assert '"$GRYPE" \\\n  sbom:/scan/sbom.spdx.json --only-fixed --output json' in scan
    official = text(steps["The official-image check, against a fixture digest list"])
    assert "env -u GH_TOKEN -u GITHUB_TOKEN sh scripts/check-official-image.sh" in official
    assert 'test "$status" -eq 1\n' in official
    recipes = text(
        steps["The bridge and derived recipes, built from this image and verified against it"]
    )
    assert "sh examples/bridge/verify.sh --bridge zoeymcp-candidate:image" in recipes
    assert "sh examples/derived-image/verify.sh zoeymcp-candidate:image" in recipes


def test_the_allowed_labels_are_the_dockerfiles() -> None:
    dockerfile = (ROOT / "Dockerfile").read_bytes().decode("utf-8")
    [block] = re.findall(r"^LABEL ((?:.*\\\n)*.*)$", dockerfile, flags=re.MULTILINE)
    labels = dict(re.findall(r'([a-z.-]+)="([^"]*)"', block))
    assert labels == {
        **oci.LABELS,
        oci.REVISION_LABEL: "${SOURCE_REVISION}",
        oci.TREE_LABEL: "${SOURCE_TREE}",
    }
    names, authors = oci.project(ROOT / "pyproject.toml")
    assert names == ["zoeymcp"]
    assert authors


# --- oci.py on fixture layouts -------------------------------------------------------------------

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
STATEMENT = "https://in-toto.io/Statement/v1"
REVISION = "a" * 40
TREE = "b" * 40
BUILDER = "https://github.com/RyanLeeUPC/ZoeyMCP/actions/runs/1/attempts/1"


def put(layout: Path, body: bytes) -> str:
    blobs = layout / "blobs" / "sha256"
    for folder in (layout, layout / "blobs", blobs):
        folder.mkdir(mode=0o700, exist_ok=True)
    digest = hashlib.sha256(body).hexdigest()
    (blobs / digest).write_bytes(body)
    return f"sha256:{digest}"


def descriptor(layout: Path, media_type: str, value: Any, **extra: Any) -> dict[str, Any]:
    body = value if isinstance(value, bytes) else json.dumps(value).encode("utf-8")
    return {"mediaType": media_type, "digest": put(layout, body), "size": len(body), **extra}


def layer(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            info.mtime = 1
            archive.addfile(info, io.BytesIO(body))
    return out.getvalue()


def allowed_sbom() -> dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {"creators": ["Organization: Anchore, Inc", "Tool: syft-v1.51.0"]},
        "documentDescribes": ["SPDXRef-root"],
        "packages": [
            {"SPDXID": "SPDXRef-root", "name": "sbom", "supplier": "NOASSERTION"},
            {"SPDXID": "SPDXRef-z", "name": "zoeymcp", "supplier": "Person: author-one"},
            {"SPDXID": "SPDXRef-d", "name": "libc6", "supplier": "Person: maintainer-one"},
        ],
    }


def allowed_labels() -> dict[str, str]:
    return {**oci.LABELS, oci.REVISION_LABEL: REVISION, oci.TREE_LABEL: TREE}


def make(
    layout: Path,
    *,
    files: dict[str, bytes] | None = None,
    labels: dict[str, str] | None = None,
    sbom: dict[str, Any] | None = None,
    extra: tuple[tuple[str, dict[str, Any]], ...] = (),
) -> Path:
    """A layout as buildx writes one: index.json, an image index, the platform manifest and its
    attestation manifest holding the SBOM and provenance statements (and ``extra`` ones)."""
    files = {"opt/zoeymcp/x": b"one"} if files is None else files
    body = layer(files)
    built = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"User": "vault", "Labels": allowed_labels() if labels is None else labels},
        "rootfs": {"type": "layers", "diff_ids": [f"sha256:{hashlib.sha256(body).hexdigest()}"]},
    }
    manifest = {
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": descriptor(layout, "application/vnd.oci.image.config.v1+json", built),
        "layers": [descriptor(layout, "application/vnd.oci.image.layer.v1.tar", body)],
    }
    platform = descriptor(
        layout, MANIFEST, manifest, platform={"architecture": "amd64", "os": "linux"}
    )
    statements = [
        ("https://spdx.dev/Document", allowed_sbom() if sbom is None else sbom),
        ("https://slsa.dev/provenance/v1", {"runDetails": {"builder": {"id": BUILDER}}}),
        *extra,
    ]
    attestation = {
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": descriptor(layout, "application/vnd.oci.image.config.v1+json", {}),
        "layers": [
            descriptor(
                layout,
                "application/vnd.in-toto+json",
                {"_type": STATEMENT, "predicateType": kind, "predicate": predicate},
                annotations={"in-toto.io/predicate-type": kind},
            )
            for kind, predicate in statements
        ],
    }
    attached = descriptor(
        layout,
        MANIFEST,
        attestation,
        platform={"architecture": "unknown", "os": "unknown"},
        annotations={
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": platform["digest"],
        },
    )
    index = descriptor(
        layout, INDEX, {"schemaVersion": 2, "mediaType": INDEX, "manifests": [platform, attached]}
    )
    (layout / "index.json").write_bytes(
        json.dumps({"schemaVersion": 2, "manifests": [index]}).encode()
    )
    return layout


def test_the_digests_are_recomputed_and_skip_the_attestation_manifest(tmp_path: Path) -> None:
    layout = make(tmp_path / "image")
    found = oci.digests(layout)
    index = json.loads((layout / "index.json").read_bytes())["manifests"][0]["digest"]
    platform = oci.document(layout, index)["manifests"][0]["digest"]
    assert found == {"index-digest": index, "platform-digest": platform, "source-tree": TREE}
    # A pushed index read back gives the same two.
    raw = oci.blob(layout, index)
    assert oci.raw_index(raw) == {"index-digest": index, "platform-digest": platform}
    # A blob that isn't its digest is refused, never trusted by its name.
    path = layout / "blobs" / "sha256" / platform.split(":")[1]
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(oci.LayoutError, match="doesn't match its digest"):
        oci.digests(layout)


def test_a_layout_without_an_index_is_refused(tmp_path: Path) -> None:
    layout = make(tmp_path / "image")
    entry = json.loads((layout / "index.json").read_bytes())["manifests"][0]
    entry["mediaType"] = MANIFEST
    (layout / "index.json").write_bytes(json.dumps({"manifests": [entry]}).encode())
    with pytest.raises(oci.LayoutError, match="names no image index"):
        oci.digests(layout)


def test_a_layout_names_one_of_each_and_sha256_digests_only(tmp_path: Path) -> None:
    layout = make(tmp_path / "image", extra=((oci.SPDX, {}),))
    entry = json.loads((layout / "index.json").read_bytes())["manifests"][0]
    # Two SBOM statements: neither is taken as the one.
    with pytest.raises(oci.LayoutError, match=r"^2 attestations of type https://spdx"):
        oci.predicate(layout, oci.SPDX)
    with pytest.raises(oci.LayoutError, match=r"^0 attestations of type "):
        oci.predicate(layout, "https://example.invalid/")
    linux = {"platform": {"os": "linux"}}
    attached = {"platform": {"os": "unknown"}}
    for manifests, count in (([], 0), ([linux, linux], 2), ([attached], 0)):
        with pytest.raises(oci.LayoutError, match=f"^{count} platform manifests, not one$"):
            oci.platform_entry(manifests)
    for digest in ("sha512:" + "0" * 64, "sha256:" + "0" * 63, "sha256:" + "A" * 64):
        with pytest.raises(oci.LayoutError, match=r"^not a sha256 digest: "):
            oci.blob(layout, digest)
    (layout / "index.json").write_bytes(json.dumps({"manifests": [entry, entry]}).encode())
    with pytest.raises(oci.LayoutError, match=r"^index\.json names 2 images, not one$"):
        oci.digests(layout)


def test_a_raw_index_must_be_an_index(tmp_path: Path) -> None:
    layout = make(tmp_path / "image")
    platform = oci.digests(layout)["platform-digest"]
    with pytest.raises(oci.LayoutError, match=r"^not an image index$"):
        oci.raw_index(oci.blob(layout, platform))


def test_the_digest_commands_print_the_lines_publish_greps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # release.yml's publish job matches whole lines: grep -Fqx "index-digest=$INDEX".
    layout = make(tmp_path / "image")
    found = oci.digests(layout)
    index = f"index-digest={found['index-digest']}"
    platform = f"platform-digest={found['platform-digest']}"
    assert oci.main(["digests", str(layout)]) == 0
    assert capsys.readouterr().out.splitlines() == [index, platform, f"source-tree={TREE}"]
    pushed = tmp_path / "pushed.json"
    pushed.write_bytes(oci.blob(layout, found["index-digest"]))
    assert oci.main(["index", str(pushed)]) == 0
    assert capsys.readouterr().out.splitlines() == [index, platform]


def test_two_builds_compare_by_their_platform_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    first = make(tmp_path / "first")
    same = make(tmp_path / "same")
    other = make(tmp_path / "other", files={"opt/zoeymcp/x": b"two"})
    assert oci.platform_digest(first) == oci.platform_digest(same)
    assert oci.main(["compare", str(first), str(same)]) == 0
    assert "The platform manifest digests match." in capsys.readouterr().out
    assert oci.main(["compare", str(first), str(other)]) == 1
    said = capsys.readouterr().out
    assert "The platform manifest digests differ." in said
    assert "- config: rootfs differs" in said
    assert "- layer 1: 1 entries differ" in said
    assert "  - opt/zoeymcp/x: " in said


def test_the_sbom_comes_out_as_its_own_file(tmp_path: Path) -> None:
    layout = make(tmp_path / "image")
    out = tmp_path / "sbom.spdx.json"
    assert oci.main(["sbom", str(layout), str(out)]) == 0
    assert json.loads(out.read_bytes()) == allowed_sbom()


def test_the_loaded_image_must_be_the_layouts(tmp_path: Path) -> None:
    layout = make(tmp_path / "image")
    built = oci.config(layout)
    inspected = {"RootFS": {"Layers": built["rootfs"]["diff_ids"]}, "Config": built["config"]}
    assert oci.candidate(layout, [inspected]) == []
    changed = {
        "RootFS": {"Layers": ["sha256:" + "0" * 64]},
        "Config": {**built["config"], "User": "root"},
    }
    assert oci.candidate(layout, [changed]) == [
        "its layers aren't the layout's",
        "its User isn't the layout's",
    ]


def identity_of(layout: Path, sbom: dict[str, Any]) -> list[str]:
    labels = oci.config(layout)["config"]["Labels"]
    found: list[str] = oci.identity(
        labels,
        sbom,
        oci.predicate(layout, oci.SLSA),
        revision=REVISION,
        tree=TREE,
        builder=BUILDER,
        projects=["zoeymcp"],
        authors=["author-one"],
    )
    return found


def test_the_allowed_values_pass(tmp_path: Path) -> None:
    # A third party's package names its own maintainer, which isn't checked.
    assert identity_of(make(tmp_path / "image"), allowed_sbom()) == []
    # BuildKit's own tool line is a creator too.
    sbom = allowed_sbom()
    sbom["creationInfo"]["creators"].append("Tool: buildkit-v0.34.1")
    assert identity_of(make(tmp_path / "again", sbom=sbom), sbom) == []


SECRET = "an-unlisted-value"
CASES: dict[str, tuple[dict[str, str] | None, dict[str, Any] | None]] = {
    "label": ({**allowed_labels(), "org.opencontainers.image.source": SECRET}, None),
    "extra-label": ({**allowed_labels(), "maintainer": SECRET}, None),
    "missing-label": ({k: v for k, v in allowed_labels().items() if k != oci.TREE_LABEL}, None),
    "creator": (None, {"creationInfo": {"creators": [f"Person: {SECRET}"]}}),
    "no-creator": (None, {"creationInfo": {"creators": []}}),
    "supplier": (None, {"packages": [{"name": "zoeymcp", "supplier": f"Person: {SECRET}"}]}),
    "originator": (None, {"packages": [{"name": "zoeymcp", "originator": f"Person: {SECRET}"}]}),
    "root": (
        None,
        {"packages": [{"SPDXID": "SPDXRef-root", "supplier": f"Organization: {SECRET}"}]},
    ),
    # SPDX 2.3's other way to name a root: a DESCRIBES relationship from the document. Neither
    # another relationship from the document nor a DESCRIBES from a package makes a root.
    "described-root": (
        None,
        {
            "documentDescribes": [],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-root",
                },
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "SPDXRef-d",
                },
                {
                    "spdxElementId": "SPDXRef-root",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-d",
                },
            ],
            "packages": [
                {"SPDXID": "SPDXRef-root", "supplier": f"Organization: {SECRET}"},
                {"SPDXID": "SPDXRef-d", "name": "libc6", "supplier": "Person: maintainer-one"},
            ],
        },
    ),
}
EXPECTED = {
    "label": "the label org.opencontainers.image.source isn't an allowed value",
    "extra-label": "the label maintainer isn't an allowed value",
    "missing-label": "the label io.zoeymcp.source-tree isn't an allowed value",
    "creator": "the SBOM's creator 1 isn't an allowed value",
    "no-creator": "the SBOM names no creator",
    "supplier": "the SBOM's supplier of its package zoeymcp isn't an allowed value",
    "originator": "the SBOM's originator of its package zoeymcp isn't an allowed value",
    "root": "the SBOM's supplier of its root package isn't an allowed value",
    "described-root": "the SBOM's supplier of its root package isn't an allowed value",
}


@pytest.mark.parametrize("case", sorted(CASES))
def test_a_value_outside_the_allowlist_fails_by_its_field_alone(tmp_path: Path, case: str) -> None:
    labels, changes = CASES[case]
    sbom = {**allowed_sbom(), **(changes or {})}
    layout = make(tmp_path / "image", labels=labels, sbom=sbom)
    found = identity_of(layout, sbom)
    assert found == [EXPECTED[case]]
    # Never the value itself: a public log would publish what the check guards.
    assert SECRET not in " ".join(found)


def test_another_runs_builder_id_fails(tmp_path: Path) -> None:
    layout = make(tmp_path / "image")
    found = oci.identity(
        allowed_labels(),
        allowed_sbom(),
        {"builder": {"id": BUILDER}},  # SLSA v0.2's place
        revision=REVISION,
        tree=TREE,
        builder=BUILDER.replace("runs/1", "runs/2"),
        projects=["zoeymcp"],
        authors=["author-one"],
    )
    assert found == ["the provenance's builder id isn't this run's"]
    assert identity_of(layout, allowed_sbom()) == []


def test_the_identity_command_reads_the_layout_the_sbom_and_the_pyproject(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    layout = make(tmp_path / "image")
    sbom = tmp_path / "sbom.spdx.json"
    assert oci.main(["sbom", str(layout), str(sbom)]) == 0
    pyproject = tmp_path / "pyproject.toml"

    def run(author: str, revision: str, tree: str, builder: str = BUILDER) -> int:
        pyproject.write_bytes(
            f'[project]\nname = "zoeymcp"\nauthors = [{{ name = "{author}" }}]\n'.encode()
        )
        given = ["--revision", revision, "--tree", tree, "--builder-id", builder]
        found: int = oci.main(
            ["identity", str(layout), "--sbom", str(sbom), "--pyproject", str(pyproject), *given]
        )
        return found

    assert run("author-one", REVISION, TREE) == 0
    said = capsys.readouterr()
    allowed = "the labels, the SBOM and the provenance hold allowed values"
    assert said.out == f"identity allowlist: {allowed}\n"
    assert said.err == ""
    # The revision and the tree are each their own label.
    assert run("author-one", TREE, REVISION) == 1
    assert capsys.readouterr().err.splitlines() == [
        "identity allowlist: the label io.zoeymcp.source-tree isn't an allowed value",
        "identity allowlist: the label org.opencontainers.image.revision isn't an allowed value",
    ]
    # The project's own package names an author pyproject.toml doesn't.
    assert run("author-two", REVISION, TREE) == 1
    assert capsys.readouterr().err.splitlines() == [
        "identity allowlist: the SBOM's supplier of its package zoeymcp isn't an allowed value"
    ]
    assert run("author-one", REVISION, TREE, BUILDER.replace("runs/1", "runs/2")) == 1
    assert capsys.readouterr().err.splitlines() == [
        "identity allowlist: the provenance's builder id isn't this run's"
    ]


def grype(*matches: tuple[str, str, str]) -> dict[str, Any]:
    return {
        "matches": [
            {
                "vulnerability": {
                    "id": f"CVE-{n}",
                    "severity": severity,
                    "fix": {"versions": ["2"]},
                },
                "artifact": {"name": name, "version": "1", "type": kind},
            }
            for n, (severity, name, kind) in enumerate(matches)
        ]
    }


def test_the_scan_gates_a_fixed_high_or_critical_os_package_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = grype(
        ("Critical", "openssl", "deb"),
        ("High", "httpx", "python"),
        ("Medium", "libc6", "deb"),
    )
    lines, gating = oci.scan(report)
    assert len(lines) == 3
    assert gating == ["Critical CVE-0 in openssl 1 (deb), fixed in 2"]
    path = tmp_path / "grype.json"
    path.write_bytes(json.dumps(report).encode())
    assert oci.main(["scan", str(path), "report"]) == 0
    assert oci.main(["scan", str(path), "enforce"]) == 1
    assert "3 fixed advisories, 1 gating" in capsys.readouterr().out
    path.write_bytes(json.dumps(grype(("High", "httpx", "python"))).encode())
    assert oci.main(["scan", str(path), "enforce"]) == 0
    # High gates as Critical does, in an OS package.
    path.write_bytes(json.dumps(grype(("High", "libc6", "deb"))).encode())
    assert oci.main(["scan", str(path), "enforce"]) == 1
    assert oci.main(["scan", str(path), "report"]) == 0
    assert oci.scan(grype(("High", "libc6", "deb")))[1] == [
        "High CVE-0 in libc6 1 (deb), fixed in 2"
    ]
