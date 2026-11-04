#!/bin/sh
# Checks on the host, before deploying, that the ZoeyMCP images a deployment's compose files name
# are official releases (M8 design L.5, Z25; docs/operations.md §37): each pinned by digest, the
# digest listed in release/digests.txt as a release's index digest, and its provenance and SBOM
# attestations verified by gh against this repository's release workflow at that release's tag.
# A container can't check its own image, so the host does.
# Compose resolves the images (docker compose config --images), so .env, nested ${...:-...}
# defaults and YAML anchors resolve as they do at up; several files are one project, as
# docker compose -f a -f b reads them, and a service in a profile counts when COMPOSE_PROFILES
# turns it on. ZoeyMCP images are those under ghcr.io/ryanleeupc/zoeymcp, local builds (the bare
# name zoeymcp, as in zoeymcp:local), any name given with --image (a mirror, say), and any other
# image whose last path part is zoeymcp (an unnamed mirror, a look-alike namespace), which fails
# as not the official name. Every other image is reported "not checked (third party)" and doesn't
# fail the check, but files with no ZoeyMCP image at all fail: the vault must run one. A local
# build fails unless --allow-local. --bundle passes the release's attestation bundle to gh, one
# JSON-lines file holding both attestations (as gh attestation download writes it), which gh then
# verifies against instead of the GitHub API, each call taking the attestation of its type; and
# --trusted-root a trusted root written by gh attestation trusted-root, for a host with no
# network to GitHub at all.
# Usage: scripts/check-official-image.sh COMPOSE_FILE... [--image NAME]... [--bundle FILE]
#            [--trusted-root FILE] [--digests FILE] [--allow-local]
# Exits 0 when every ZoeyMCP image passes, 1 when any fails or there is none, and 2 on a usage
# error, a digest list it can't read, gh missing or too old, or images Compose couldn't resolve.
set -eu

usage="usage: check-official-image.sh COMPOSE_FILE... [--image NAME]... [--bundle FILE] \
[--trusted-root FILE] [--digests FILE] [--allow-local]"
official_name=ghcr.io/ryanleeupc/zoeymcp
repo=RyanLeeUPC/ZoeyMCP
signer=RyanLeeUPC/ZoeyMCP/.github/workflows/release.yml
sbom_type=https://spdx.dev/Document/v2.3
# The oldest gh with every gh attestation verify flag used below.
gh_minimum=2.74.0
digests="$(cd "$(dirname "$0")/.." && pwd)/release/digests.txt"

refuse() {
    echo "check-official-image: $*" >&2
    exit 2
}

names=""
bundle=""
trusted_root=""
allow_local=""
files=0
count=$#
while [ "$count" -gt 0 ]; do
    arg="$1"
    shift
    count=$((count - 1))
    case "$arg" in
        --image | --bundle | --trusted-root | --digests)
            [ "$count" -gt 0 ] || refuse "$arg needs a value; $usage"
            value="$1"
            shift
            count=$((count - 1))
            case "$arg" in
                --image) names="$names $value" ;;
                --bundle) bundle="$value" ;;
                --trusted-root) trusted_root="$value" ;;
                --digests) digests="$value" ;;
            esac
            ;;
        --allow-local) allow_local=yes ;;
        -*) refuse "unknown option $arg; $usage" ;;
        *)
            # The compose files go to the end, each after its -f; the rest is still to read.
            set -- "$@" -f "$arg"
            files=$((files + 1))
            ;;
    esac
done
[ "$files" -gt 0 ] || refuse "$usage"
if [ -n "$bundle" ] && [ ! -f "$bundle" ]; then
    refuse "no bundle at $bundle"
fi
if [ -n "$trusted_root" ] && [ ! -f "$trusted_root" ]; then
    refuse "no trusted root at $trusted_root"
fi

# Every line of the list is a comment, blank or a release; any other line is refused, not skipped.
[ -f "$digests" ] || refuse "no digest list at $digests"
releases=""
line_number=0
while IFS= read -r line || [ -n "$line" ]; do
    line_number=$((line_number + 1))
    case "$line" in
        '' | '#'*) continue ;;
    esac
    if ! printf '%s\n' "$line" | grep -Eqx \
        '[0-9]+\.[0-9]+\.[0-9]+ sha256:[0-9a-f]{64} sha256:[0-9a-f]{64} [0-9a-f]{40}'; then
        refuse "$digests line $line_number isn't \
<version> <index digest> <platform manifest digest> <source tree>"
    fi
    releases="$releases
$line"
done <"$digests"
if [ -z "$releases" ]; then
    echo "$digests lists no release yet: no image has been published, so no digest is official."
fi

if ! images="$(docker compose "$@" config --images)"; then
    refuse "docker compose couldn't resolve the images; run this with the .env and variables \
you deploy with"
fi
[ -n "$images" ] || refuse "the compose files name no image"

# $1 >= $2, each major.minor.patch.
at_least() {
    old_ifs="$IFS"
    IFS=.
    # shellcheck disable=SC2086
    set -- $1 $2
    IFS="$old_ifs"
    [ "$#" -eq 6 ] || return 1
    if [ "$1" -ne "$4" ]; then
        [ "$1" -gt "$4" ]
        return
    fi
    if [ "$2" -ne "$5" ]; then
        [ "$2" -gt "$5" ]
        return
    fi
    [ "$3" -ge "$6" ]
}

gh_checked=""
gh_ready() {
    [ -z "$gh_checked" ] || return 0
    command -v gh >/dev/null 2>&1 \
        || refuse "gh isn't installed: gh $gh_minimum or later verifies the attestations"
    gh_version="$(gh --version | sed -n 's/^gh version \([0-9][0-9.]*\).*/\1/p' | head -n 1)"
    at_least "$gh_version" "$gh_minimum" 2>/dev/null \
        || refuse "gh ${gh_version:-of an unknown version} is older than $gh_minimum"
    gh_checked=yes
}

# gh attestation verify SUBJECT for release $version, with this run's bundle and trusted root and
# any further flags.
verify() {
    subject="$1"
    shift
    if [ -n "$bundle" ]; then
        set -- "$@" --bundle "$bundle"
    fi
    if [ -n "$trusted_root" ]; then
        set -- "$@" --custom-trusted-root "$trusted_root"
    fi
    gh attestation verify "$subject" --repo "$repo" --signer-workflow "$signer" \
        --source-ref "refs/tags/v$version" --deny-self-hosted-runners "$@"
}

failed=0
checked=0
while IFS= read -r image; do
    [ -n "$image" ] || continue
    # The name: the reference without its digest, and without its tag (after the last colon of
    # the last path part, so a registry's port stays).
    name="${image%%@*}"
    case "${name##*/}" in
        *:*) name="${name%:*}" ;;
    esac
    if [ "$name" = zoeymcp ]; then
        checked=$((checked + 1))
        if [ -n "$allow_local" ]; then
            echo "allowed by --allow-local: $image is not an official image (a local build)"
        else
            echo "FAIL $image: not an official image (a local build); to check it matches your \
source, compare docker inspect --format '{{ index .Config.Labels \"io.zoeymcp.source-tree\" }}' \
$image with git rev-parse 'HEAD^{tree}' (--allow-local passes a local build)"
            failed=$((failed + 1))
        fi
        continue
    fi
    zoeymcp_image=""
    if [ "$name" = "$official_name" ]; then
        zoeymcp_image=yes
    fi
    for given in $names; do
        if [ "$name" = "$given" ] || [ "$image" = "$given" ]; then
            zoeymcp_image=yes
        fi
    done
    if [ -z "$zoeymcp_image" ]; then
        if [ "${name##*/}" = zoeymcp ]; then
            checked=$((checked + 1))
            echo "FAIL $image: not the official name $official_name; to check a mirror of it, \
pass --image with the mirror's name"
            failed=$((failed + 1))
        else
            echo "not checked (third party): $image"
        fi
        continue
    fi
    checked=$((checked + 1))
    digest="${image#*@}"
    if [ "$digest" = "$image" ] || ! printf '%s\n' "$digest" | grep -Eqx 'sha256:[0-9a-f]{64}'; then
        echo "FAIL $image: not pinned by digest (@sha256:...); a tag can be moved"
        failed=$((failed + 1))
        continue
    fi
    if [ -z "$releases" ]; then
        echo "FAIL $image: not an official release's digest: $digests lists no release yet"
        failed=$((failed + 1))
        continue
    fi
    found="$(printf '%s\n' "$releases" | awk -v digest="$digest" '$2 == digest')"
    if [ -z "$found" ]; then
        platform_of="$(printf '%s\n' "$releases" | awk -v digest="$digest" '$3 == digest {print $1}')"
        if [ -n "$platform_of" ]; then
            echo "FAIL $image: that is release $platform_of's platform manifest digest; pin its \
index digest, which the attestations name"
        else
            echo "FAIL $image: not an official release's digest (not in $digests)"
        fi
        failed=$((failed + 1))
        continue
    fi
    if [ "$(printf '%s\n' "$found" | wc -l)" -ne 1 ]; then
        refuse "$digests lists $digest for more than one release"
    fi
    version="${found%% *}"
    gh_ready
    if ! output="$(verify "oci://$name@$digest" 2>&1)"; then
        echo "FAIL $image: release $version's provenance attestation didn't verify:"
        printf '%s\n' "$output" | sed 's/^/    /'
        failed=$((failed + 1))
        continue
    fi
    if ! output="$(verify "oci://$name@$digest" --predicate-type "$sbom_type" 2>&1)"; then
        echo "FAIL $image: release $version's SBOM attestation didn't verify:"
        printf '%s\n' "$output" | sed 's/^/    /'
        failed=$((failed + 1))
        continue
    fi
    echo "official: $image (release $version; its provenance and SBOM attestations verified)"
done <<EOF
$(printf '%s\n' "$images" | sort -u)
EOF

if [ "$checked" -eq 0 ]; then
    echo "FAIL: no ZoeyMCP image in these files, so nothing was checked; the vault must run the \
official image (--image names a mirror of it), and a derived image is checked by its base \
(docs/operations.md, \"Getting and verifying the image\")"
    exit 1
fi
if [ "$failed" -gt 0 ]; then
    echo "not official: $failed of $checked ZoeyMCP images failed the check"
    exit 1
fi
echo "every ZoeyMCP image passed ($checked)"
