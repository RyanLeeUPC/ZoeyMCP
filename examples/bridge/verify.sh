#!/bin/sh
# Proves a bridge image is the official one plus a stdio server in its own prefix, and nothing
# else (M7 design C.7: the derived-image verifier's bridge mode, with M4's checks 1-3). In the
# standard tier this image is the vault's own, so:
#   1. its layers are the official layers, in order, plus exactly one (two with --node);
#   2. User, Entrypoint, Cmd, Env and WorkingDir are unchanged, so no LD_PRELOAD or changed PATH
#      reaches the vault, which the standard launcher hands the whole environment;
#   3. the added layers touch only /opt/stdio-server (and /opt/node with --node): no
#      /etc/ld.so.preload, shared library, base interpreter or standard library;
#   4. both zoeymcp environments are byte for byte the official image's, so no new .pth;
#   5. nothing it added is setuid, setgid or world-writable;
#   6. emSign ECC Root CA - G3 isn't in the image's Debian store (the official Dockerfile drops it);
#   7. the labels: the official io.zoeymcp.source-tree, and io.zoeymcp.bridge.command naming an
#      executable file under /opt/stdio-server (or /opt/node).
# Checks 1, 2, 3 and 5 read layer metadata and tar listings without running the image; 4, 6 and 7
# run only the base interpreter, isolated and with no network. The example server has no update
# check or telemetry, so there is no switch to check; a recipe whose server has one checks it here.
# scripts/smoke-image.sh --bridge runs the image in both shapes.
# Usage: examples/bridge/verify.sh --bridge [--node] OFFICIAL IMAGE
set -eu

usage="usage: verify.sh --bridge [--node] OFFICIAL IMAGE"
[ "${1:-}" = "--bridge" ] || { echo "$usage" >&2; exit 2; }
shift
node=""
added=1
if [ "${1:-}" = "--node" ]; then
    node="opt/node"
    added=2
    shift
fi
official="${1:?$usage}"
image="${2:?$usage}"
python="${PYTHON:-python3}"  # the host's, for reading files; never inside an image
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
    echo "VERIFY FAIL: $*" >&2
    exit 1
}
step() { echo "--- $*"; }
# Runs the base interpreter in IMAGE, isolated, with no network: in_image IMAGE ARGS...
in_image() {
    in_image_name="$1"
    shift
    docker run --rm --network none --entrypoint /usr/local/bin/python3 "$in_image_name" -I "$@"
}

step "1, 2: the official layers plus $added, and the same configuration"
docker image inspect "$official" > "$work/official.json"
docker image inspect "$image" > "$work/image.json"
"$python" -I - "$work/official.json" "$work/image.json" "$added" <<'PY' \
    || fail "layers or configuration differ"
import json, sys
official, derived = (json.load(open(path))[0] for path in sys.argv[1:3])
added = int(sys.argv[3])
base, mine = official["RootFS"]["Layers"], derived["RootFS"]["Layers"]
if mine[: len(base)] != base or len(mine) != len(base) + added:
    sys.exit(f"layers: {len(base)} official, {len(mine)} here, prefix equal: {mine[:len(base)] == base}")
for key in ("User", "Entrypoint", "Cmd", "Env", "WorkingDir"):
    if official["Config"].get(key) != derived["Config"].get(key):
        sys.exit(f"Config.{key} differs")
PY

step "3, 5: the added layers touch only /opt/stdio-server${node:+ and /opt/node}, nothing setuid or world-writable"
docker save "$image" -o "$work/image.tar"
"$python" -I - "$work/image.tar" "$work/official.json" "$node" <<'PY' \
    || fail "an added layer touches more, or adds a setuid, setgid or world-writable file"
import json, stat, sys, tarfile
image = tarfile.open(sys.argv[1])
base = len(json.load(open(sys.argv[2]))[0]["RootFS"]["Layers"])
prefixes = ["opt/stdio-server"] + ([sys.argv[3]] if sys.argv[3] else [])
manifest = json.load(image.extractfile("manifest.json"))
outside, unsafe = [], []
for name in manifest[0]["Layers"][base:]:
    layer = tarfile.open(fileobj=image.extractfile(name))
    for member in layer.getmembers():
        path = member.name.lstrip("./")
        if path not in ("", "opt") and not any(
            path == prefix or path.startswith(prefix + "/") for prefix in prefixes
        ):
            outside.append(path)
        if not member.issym() and member.mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH):
            unsafe.append(f"{oct(member.mode)} {path}")
problems = []
if outside:
    problems.append("outside the server's prefix: " + ", ".join(sorted(outside)[:20]))
if unsafe:
    problems.append("setuid, setgid or world-writable: " + ", ".join(sorted(unsafe)[:20]))
if problems:
    sys.exit("\n".join(problems))
PY

step "4: both zoeymcp environments are the official image's, byte for byte"
listing='
import hashlib, os, stat
for root in ("/opt/zoeymcp", "/opt/zoeymcp-gateway"):
    for top, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(top, name)
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode):
                digest = "link:" + os.readlink(path)
            else:
                with open(path, "rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
            print(f"{oct(info.st_mode)} {info.st_uid}:{info.st_gid} {digest} {path}")
'
in_image "$official" -c "$listing" > "$work/official.txt"
in_image "$image" -c "$listing" > "$work/image.txt"
grep -q ' /opt/zoeymcp/' "$work/official.txt" || fail "the official image has no /opt/zoeymcp"
cmp -s "$work/official.txt" "$work/image.txt" || {
    diff "$work/official.txt" "$work/image.txt" | head -20 >&2
    fail "a zoeymcp environment differs from the official image's"
}

step "6: emSign ECC Root CA - G3 isn't in the Debian store"
roots='
import os, ssl, sys
name = "emSign_ECC_Root_CA_-_G3"
source = f"/usr/share/ca-certificates/mozilla/{name}.crt"
problems = []
if not os.path.isfile(source):
    sys.exit(f"{source} is gone: this check would prove nothing; name the root again")
body = "".join(l for l in open(source) if not l.startswith("-----")).replace("\n", "")
bundle = open("/etc/ssl/certs/ca-certificates.crt").read().replace("\n", "")
if body in bundle:
    problems.append("the root is in /etc/ssl/certs/ca-certificates.crt")
if os.path.lexists(f"/etc/ssl/certs/{name}.pem"):
    problems.append(f"/etc/ssl/certs/{name}.pem exists")
if f"!mozilla/{name}.crt" not in open("/etc/ca-certificates.conf").read().splitlines():
    problems.append("/etc/ca-certificates.conf does not disable it")
loaded = ssl.create_default_context().get_ca_certs()
if any("emSign ECC Root CA - G3" in str(cert.get("subject")) for cert in loaded):
    problems.append("the default SSL context loads it")
if problems:
    sys.exit("; ".join(problems))
'
in_image "$image" -c "$roots" || fail "emSign ECC Root CA - G3 is still trusted"

step "7: the labels"
label() {
    docker image inspect "$1" --format "{{ index .Config.Labels \"$2\" }}"
}
tree="$(label "$official" io.zoeymcp.source-tree)"
[ -n "$tree" ] && [ "$tree" = "$(label "$image" io.zoeymcp.source-tree)" ] \
    || fail "io.zoeymcp.source-tree isn't the official image's"
command="$(label "$image" io.zoeymcp.bridge.command)"
case "$command" in
    /opt/stdio-server/*) ;;
    /opt/node/*) [ -n "$node" ] || fail "io.zoeymcp.bridge.command is under /opt/node without --node" ;;
    *) fail "io.zoeymcp.bridge.command isn't under the server's prefix: $command" ;;
esac
in_image "$image" -c 'import os, sys; sys.exit(not os.access(sys.argv[1], os.X_OK))' "$command" \
    || fail "io.zoeymcp.bridge.command names no executable file: $command"
echo "bridge image verified: $image"
