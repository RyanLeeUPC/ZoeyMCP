#!/bin/sh
# Proves a derived image is the official one plus toolkits in the gateway's environment, and
# nothing else (M4 design I.2):
#   1. its layers are the official layers, in order, plus exactly one;
#   2. User, Entrypoint, Cmd, Env and WorkingDir are unchanged;
#   3. the added layer touches only /opt/zoeymcp-gateway;
#   4. every official file there is unchanged, new files sit only under site-packages and bin,
#      and none is a .pth, setuid, setgid or world-writable;
#   5. scripts/smoke-image.sh --derived OFFICIAL DERIVED passes, which also reviews the example's
#      mail toolkit in the derived gateway.
# Checks 3 and 4 read files without running them, so no .pth runs before it is checked.
# Usage: examples/derived-image/verify.sh OFFICIAL DERIVED
set -eu

official="${1:?usage: verify.sh OFFICIAL DERIVED}"
derived="${2:?usage: verify.sh OFFICIAL DERIVED}"
here="$(cd "$(dirname "$0")" && pwd)"
python="${PYTHON:-python3}"  # the host's, for reading files; never inside an image
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() {
    echo "VERIFY FAIL: $*" >&2
    exit 1
}
step() { echo "--- $*"; }

step "1, 2: the official layers plus one, and the same configuration"
docker image inspect "$official" > "$work/official.json"
docker image inspect "$derived" > "$work/derived.json"
"$python" -I - "$work/official.json" "$work/derived.json" <<'PY' || fail "layers or configuration differ"
import json, sys
official, derived = (json.load(open(path))[0] for path in sys.argv[1:3])
base, mine = official["RootFS"]["Layers"], derived["RootFS"]["Layers"]
if mine[: len(base)] != base or len(mine) != len(base) + 1:
    sys.exit(f"layers: {len(base)} official, {len(mine)} derived, prefix equal: {mine[:len(base)] == base}")
for key in ("User", "Entrypoint", "Cmd", "Env", "WorkingDir"):
    if official["Config"].get(key) != derived["Config"].get(key):
        sys.exit(f"Config.{key} differs")
PY

step "3: the added layer touches only /opt/zoeymcp-gateway"
docker save "$derived" -o "$work/derived.tar"
"$python" -I - "$work/derived.tar" "$work/derived.json" <<'PY' || fail "the added layer touches more"
import hashlib, json, sys, tarfile
image = tarfile.open(sys.argv[1])
diff_ids = json.load(open(sys.argv[2]))[0]["RootFS"]["Layers"]
manifest = json.load(image.extractfile("manifest.json"))
last = manifest[0]["Layers"][-1]
layer = tarfile.open(fileobj=image.extractfile(last))
bad = []
for member in layer.getmembers():
    name = member.name.lstrip("./")
    if name in ("opt", "opt/zoeymcp-gateway") or name.startswith("opt/zoeymcp-gateway/"):
        continue
    bad.append(name)
if bad:
    sys.exit("outside /opt/zoeymcp-gateway: " + ", ".join(sorted(bad)[:20]))
PY

step "4: official gateway files unchanged; new files only in site-packages and bin"
listing='
import hashlib, os, stat, sys
root = "/opt/zoeymcp-gateway"
for top, dirs, files in os.walk(root):
    for name in files:
        path = os.path.join(top, name)
        info = os.lstat(path)
        if stat.S_ISLNK(info.st_mode):
            digest = "link:" + os.readlink(path)
        else:
            with open(path, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()
        print(f"{oct(info.st_mode)} {digest} {path}")
'
docker run --rm --network none --entrypoint /usr/local/bin/python3 "$official" -I -c "$listing" \
    > "$work/official.txt"
docker run --rm --network none --entrypoint /usr/local/bin/python3 "$derived" -I -c "$listing" \
    > "$work/derived.txt"
"$python" -I - "$work/official.txt" "$work/derived.txt" <<'PY' || fail "the gateway environment changed"
import stat, sys
def read(path):
    found = {}
    for line in open(path):
        mode, digest, name = line.rstrip("\n").split(" ", 2)
        found[name] = (int(mode, 8), digest)
    return found
official, derived = read(sys.argv[1]), read(sys.argv[2])
problems = [f"changed or gone: {n}" for n, v in official.items() if derived.get(n) != v]
for name, (mode, _) in sorted(derived.items()):
    if name in official:
        continue
    rest = name.removeprefix("/opt/zoeymcp-gateway/")
    if "/site-packages/" not in name and not rest.startswith("bin/"):
        problems.append(f"new outside site-packages and bin: {name}")
    if name.endswith(".pth"):
        problems.append(f"new .pth: {name}")
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_IWOTH):
        problems.append(f"setuid, setgid or world-writable: {name}")
if problems:
    sys.exit("\n".join(problems[:30]))
PY

step "5: the image smoke test, against the official image"
sh "$here/../../scripts/smoke-image.sh" --derived "$official" "$derived"
echo "derived image verified: $derived"
