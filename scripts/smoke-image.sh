#!/bin/sh
# Smoke-test a built image: the vault the way the hardened tier runs it (read-only, no capabilities,
# no-new-privileges, non-root), then the standard tier from deploy/compose.yaml. Both tiers reach
# a fake upstream (tests/fakes/run_mcp_server.py) with one tools/list and one tools/call. Both
# serve the portal on the host's loopback, and the probes show who else can reach it. A Squid
# pinned by digest parses the emitted egress allowlist and is probed against it (contract 51).
# With --derived OFFICIAL, IMAGE is a derived image (examples/derived-image): its environments are
# compared with OFFICIAL's instead of with the fixed lists, and its toolkits must load.
# Usage: scripts/smoke-image.sh [--derived OFFICIAL] IMAGE
set -eu

official=""
if [ "${1:-}" = "--derived" ]; then
    official="${2:?usage: smoke-image.sh [--derived OFFICIAL] IMAGE}"
    shift 2
fi
image="${1:?usage: smoke-image.sh [--derived OFFICIAL] IMAGE}"
name="zoeymcp-smoke-$$"
volume="zoeymcp-smoke-state-$$"
project="zoeymcp-smoke-$$"
hardened_project="zoeymcp-smoke-hardened-$$"
probe_net="zoeymcp-smoke-probe-$$"
work="$(mktemp -d)"
port=18080
examples="$(cd "$(dirname "$0")/../examples" && pwd)"
deploy="$(cd "$(dirname "$0")/../deploy" && pwd)"
tests="$(cd "$(dirname "$0")/../tests" && pwd)"
hardened="--read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:size=16m"
# Contract 51's Squid, pinned by digest (ci.yml pulls this line's image first).
squid_image=ubuntu/squid:6.6-24.04_edge@sha256:8a3baed477e2c282ab8aa5edad442f69873246964f225c5c2ae8364b6610963c
squid_net="zoeymcp-smoke-squid-$$"
j5_project="zoeymcp-smoke-j5-$$"

# The standard tier, from deploy/compose.yaml; once written, standard.yaml swaps in a policy
# with a real client token and adds the fake upstream.
standard() {
    if [ -f "$work/standard.yaml" ]; then
        set -- -f "$work/standard.yaml" "$@"
    fi
    ZOEYMCP_IMAGE="$image" ZOEYMCP_MASTER_KEY="${key:-unset}"         docker compose -p "$project" -f "$deploy/compose.yaml" "$@"
}
# The hardened tier with the lan profile; override.yaml holds a policy with a real client
# token, and the fake upstream.
hardened_tier() {
    ZOEYMCP_IMAGE="$image" ZOEYMCP_MASTER_KEY="${hardened_master:-unset}" \
        ZOEYMCP_GATEWAY_KEY="${gateway_key:-unset}" \
        ZOEYMCP_GATEWAY_KEY_GENERATION="${generation:-1}" \
        ZOEYMCP_LAN_BIND=127.0.0.1 ZOEYMCP_LAN_HOST="${lan_host:-zoeymcp.lan.example}" \
        docker compose -p "$hardened_project" -f "$deploy/compose.hardened.yaml" \
        -f "$work/override.yaml" --profile lan "$@"
}

cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    standard down -v >/dev/null 2>&1 || true
    if [ -f "$work/override.yaml" ]; then
        hardened_tier down -v >/dev/null 2>&1 || true
    fi
    docker network rm "$probe_net" >/dev/null 2>&1 || true
    docker rm -f "$name-dns" "$name-squid" "$name-squid-mapped" "$name-squid-lookup" \
        >/dev/null 2>&1 || true
    docker network rm "$squid_net" >/dev/null 2>&1 || true
    ZOEYMCP_IMAGE="$image" ZOEYMCP_MASTER_KEY=unset ZOEYMCP_GATEWAY_KEY=unset \
        docker compose -p "$j5_project" -f "$deploy/compose.hardened.yaml" down -v >/dev/null 2>&1 \
        || true
    rm -rf "$work"
}
trap cleanup EXIT

fail() {
    echo "SMOKE FAIL: $*" >&2
    docker logs "$name" >&2 2>/dev/null || true
    docker logs "$name-squid" >&2 2>/dev/null || true
    standard logs >&2 2>/dev/null || true
    if [ -f "$work/override.yaml" ]; then
        hardened_tier logs >&2 2>/dev/null || true
    fi
    exit 1
}

step() { echo "--- $*"; }

step "version, and the image runs as the vault's uid"
docker run --rm "$image" --version
[ "$(docker run --rm --entrypoint id "$image" -u)" = "10001" ] || fail "image doesn't run as uid 10001"
[ "$(docker run --rm --entrypoint sh "$image" -c 'command -v zoeymcp')" = "/opt/zoeymcp/bin/zoeymcp" ] \
    || fail "zoeymcp on PATH isn't the vault's environment"

step "Docker Engine 28.0 or later (contract 44)"
# Before 28.0, hosts on the same L2 segment could reach ports published on a loopback address.
engine="$(docker version -f '{{.Server.Version}}')"
echo "Docker Engine $engine"
case "${engine%%.*}" in
    "" | *[!0-9]*) fail "can't read the Docker server's version: $engine" ;;
esac
[ "${engine%%.*}" -ge 28 ] || fail "Docker Engine $engine is older than 28.0"

# Runs one environment's interpreter in isolated mode: in_env DIR ARGS...
in_env() {
    env_dir="$1"
    shift
    docker run --rm --network none --entrypoint "$env_dir/bin/python" "$image" -I "$@"
}
# The same, in the official image: in_official DIR ARGS...
in_official() {
    env_dir="$1"
    shift
    docker run --rm --network none --entrypoint "$env_dir/bin/python" "$official" -I "$@"
}
# Prints which of the modules named in its arguments can be imported.
importable='
import importlib, sys
found = []
for name in sys.argv[1:]:
    try:
        importlib.import_module(name)
    except ModuleNotFoundError:
        continue
    found.append(name)
print(" ".join(found))
'
# Prints the .pth files in site-packages: Python runs each one at start. Fails unless it looked
# where zoeymcp is installed.
pth_files='
import glob, os, site, sys
dirs = site.getsitepackages()
if not any(os.path.isdir(os.path.join(d, "zoeymcp")) for d in dirs):
    sys.exit(f"no site-packages directory holds zoeymcp: {dirs}")
paths = [p for d in dirs for p in glob.glob(os.path.join(d, "*.pth"))]
print(" ".join(sorted(os.path.basename(p) for p in paths)))
'
# Prints the normalized names of the installed distributions.
distributions='
import importlib.metadata as metadata, re
names = {re.sub(r"[-_.]+", "-", d.metadata["Name"]).lower() for d in metadata.distributions()}
print(" ".join(sorted(names)))
'
# Prints what `zoeymcp gateway` execs into from this environment ("None": it runs here).
exec_target='
from zoeymcp.cli.main import gateway_command
print(gateway_command(["gateway"]))
'
# Prints installed OpenTelemetry distributions other than the API (a no-op without an SDK).
otel_beyond_api='
import importlib.metadata as metadata
names = {d.metadata["Name"].lower().replace("_", "-") for d in metadata.distributions()}
print(" ".join(sorted(n for n in names if n.startswith("opentelemetry") and n != "opentelemetry-api")))
'
# Every distribution only the gateway's environment has, on any platform; a unit test checks
# this list against uv.lock.
gateway_only_dists="attrs httpcore2 httpx2 httpx2-jsfetch jsonschema jsonschema-specifications"
gateway_only_dists="$gateway_only_dists mcp mcp-types opentelemetry-api pyjwt python-multipart"
gateway_only_dists="$gateway_only_dists pywin32 referencing regex rpds-py sse-starlette truststore"
# Their top-level modules.
gateway_only="mcp mcp_types httpx2 httpcore2 jsonschema jsonschema_specifications regex referencing"
gateway_only="$gateway_only rpds sse_starlette opentelemetry jwt multipart python_multipart"
gateway_only="$gateway_only truststore attr attrs"
allowed_pth="_virtualenv.pth"

# Prints name==version for every installed distribution.
versions='
import importlib.metadata as metadata, re
found = {(re.sub(r"[-_.]+", "-", d.metadata["Name"]).lower(), d.version) for d in metadata.distributions()}
print(" ".join(f"{n}=={v}" for n, v in sorted(found)))
'
# Prints the top-level modules of the named distributions that another distribution also has.
shadowing='
import importlib.metadata as metadata, re, sys
mine = set(sys.argv[1:])
owners = {}
for top, dists in metadata.packages_distributions().items():
    for dist in dists:
        owners.setdefault(top, set()).add(re.sub(r"[-_.]+", "-", dist).lower())
print(" ".join(sorted(t for t, o in owners.items() if o & mine and o - mine)))
'

if [ -n "$official" ]; then
    step "derived: the vault's environment is the official one; the gateway's adds only toolkits"
    [ "$(in_env /opt/zoeymcp -c "$versions")" = "$(in_official /opt/zoeymcp -c "$versions")" ] \
        || fail "the vault's environment differs from the official image's"
    official_gateway="$(in_official /opt/zoeymcp-gateway -c "$versions")"
    derived_gateway="$(in_env /opt/zoeymcp-gateway -c "$versions")"
    for pinned in $official_gateway; do
        case " $derived_gateway " in
            *" $pinned "*) ;;
            *) fail "the gateway's environment lost or changed $pinned" ;;
        esac
    done
    extras=""
    for pinned in $derived_gateway; do
        case " $official_gateway " in
            *" $pinned "*) ;;
            *) extras="$extras ${pinned%%==*}" ;;
        esac
    done
    [ -n "$extras" ] || fail "the derived image adds no distribution"
    vault_dists="$(in_env /opt/zoeymcp -c "$distributions")"
    for dist in $extras; do
        case " $vault_dists " in
            *" $dist "*) fail "the vault's environment has the toolkit distribution $dist" ;;
        esac
    done
    # shellcheck disable=SC2086
    found="$(in_env /opt/zoeymcp-gateway -c "$shadowing" $extras)"
    [ -z "$found" ] || fail "a toolkit distribution shadows an official module: $found"
    found="$(in_env /opt/zoeymcp -c "$importable" example_toolkits)"
    [ -z "$found" ] || fail "the vault's environment can import the example toolkits"
    entry_points='
import importlib.metadata as metadata
print(" ".join(sorted(e.value for e in metadata.entry_points(group="zoeymcp.toolkits"))))
'
    [ "$(in_env /opt/zoeymcp-gateway -c "$entry_points")" \
        = "example_toolkits.mail:toolkit example_toolkits.records:toolkit" ] \
        || fail "the zoeymcp.toolkits entry points aren't the example toolkits"
fi

step "two environments: the vault's has none of the gateway's packages"
vault_dists="$(in_env /opt/zoeymcp -c "$distributions")"
gateway_dists="$(in_env /opt/zoeymcp-gateway -c "$distributions")"
if [ -n "$official" ]; then
    # The derived image's extra distributions are checked above, against the official image.
    official_only="$(in_official /opt/zoeymcp-gateway -c "$distributions")"
    gateway_dists=""
    for dist in $official_only; do gateway_dists="$gateway_dists $dist"; done
fi
for dist in $gateway_only_dists; do
    case " $vault_dists " in
        *" $dist "*) fail "the vault's environment has $dist installed" ;;
    esac
done
for dist in $vault_dists; do
    case " $gateway_dists " in
        *" $dist "*) ;;
        *) fail "the gateway's environment lacks $dist" ;;
    esac
done
for dist in $gateway_dists; do
    case " $vault_dists $gateway_only_dists " in
        *" $dist "*) ;;
        *) fail "the gateway's environment has $dist, which neither list names" ;;
    esac
done
for dist in zoeymcp mcp mcp-types httpx2 jsonschema regex; do
    case " $gateway_dists " in
        *" $dist "*) ;;
        *) fail "the gateway's environment lacks $dist" ;;
    esac
done
# shellcheck disable=SC2086
found="$(in_env /opt/zoeymcp -c "$importable" $gateway_only)"
[ -z "$found" ] || fail "the vault's environment can import: $found"
found="$(in_env /opt/zoeymcp-gateway -c "$importable" zoeymcp mcp httpx2 jsonschema regex)"
[ "$found" = "zoeymcp mcp httpx2 jsonschema regex" ] \
    || fail "the gateway's environment imports only: $found"
[ "$(in_env /opt/zoeymcp-gateway -m zoeymcp --version)" = "$(docker run --rm "$image" --version)" ] \
    || fail "the two environments hold different versions of zoeymcp"
expected="['/opt/zoeymcp-gateway/bin/python', '-I', '-m', 'zoeymcp', 'gateway']"
[ "$(in_env /opt/zoeymcp -c "$exec_target")" = "$expected" ] \
    || fail "zoeymcp gateway doesn't exec into the gateway's environment"
[ "$(in_env /opt/zoeymcp-gateway -c "$exec_target")" = "None" ] \
    || fail "zoeymcp gateway would exec again from inside the gateway's environment"

step "only allowlisted .pth files, and no OpenTelemetry SDK or exporter"
for env in /opt/zoeymcp /opt/zoeymcp-gateway; do
    found="$(in_env "$env" -c "$pth_files")"
    [ -n "$found" ] || fail "$env lists no .pth files, not even $allowed_pth"
    for file in $found; do
        case " $allowed_pth " in
            *" $file "*) ;;
            *) fail "$env has $file in site-packages, which isn't on the .pth allowlist" ;;
        esac
    done
    found="$(in_env "$env" -c "$otel_beyond_api")"
    [ -z "$found" ] || fail "$env has OpenTelemetry beyond the API: $found"
done
found="$(in_env /opt/zoeymcp-gateway -c "$importable" opentelemetry.sdk)"
[ -z "$found" ] || fail "the OpenTelemetry SDK can be imported"

step "the portal's static files are installed in the vault's environment (contract 42)"
# Prints path, sha256 and content type of each file the portal serves (its static map), read
# from where the package is installed: site-packages, not an editable install's source tree.
static_files='
import hashlib, importlib.resources, sys
from zoeymcp.portal.routes import STATIC
folder = importlib.resources.files("zoeymcp.portal") / "static"
if not str(folder).startswith(sys.prefix + "/lib/") or "/site-packages/" not in str(folder):
    sys.exit(f"the portal is not installed in site-packages: {folder}")
for path, file in sorted(STATIC.items()):
    print(path, hashlib.sha256((folder / file.name).read_bytes()).hexdigest(), file.content_type)
'
in_env /opt/zoeymcp -c "$static_files" >"$work/static" \
    || fail "the vault's environment lacks the portal's static files"
cat "$work/static"
grep -q '^/ [0-9a-f]\{64\} text/html; charset=utf-8$' "$work/static" \
    || fail "the portal's static map has no HTML shell at /"

if [ -n "$official" ]; then
    step "derived: the example toolkit loads as the gateway's uid, origin checked, pinned as committed"
    load='
import json
from zoeymcp.common.policy import parse_policy
from zoeymcp.common.policy.view import build_view
from zoeymcp.gateway.marks import DriftMarks
from zoeymcp.gateway.toolkits import Loaded, Toolkits
from zoeymcp.gateway.vaultlink import parse_link
import tempfile
from pathlib import Path
policy = parse_policy(open("/examples/policy.yaml").read(), "example")
toolkits = Toolkits(parse_link("unix:/run/none.sock"), None, DriftMarks.load(Path(tempfile.mkdtemp())))
toolkits.apply(build_view(policy).gateway)
found = toolkits.get("mail")
assert isinstance(found, Loaded), found
print(json.dumps({n: e.pin for n, e in found.evaluation.exposed.items()}, sort_keys=True))
'
    found="$(docker run --rm --network none -u 10002:10002 -v "$examples:/examples:ro" \
        --entrypoint /opt/zoeymcp-gateway/bin/python "$image" -I -c "$load")" \
        || fail "the example mail toolkit didn't load in the derived gateway"
    expected="$(sed -n 's/^ *send_note: \(sha256:[0-9a-f]*\)$/{"send_note": "\1"}/p' "$examples/policy.yaml")"
    found="$(printf '%s
' "$found" | tail -n 1)"  # after the toolkit_loaded log line
    [ "$found" = "$expected" ] || fail "the loaded pins $found aren't the committed $expected"
fi

step "users, directories, and no setuid or setgid files"
expected="$(printf '%s\n' \
    "/state 10001:10001 700" \
    "/state-gateway 10002:10002 700" \
    "/run/zoeymcp 10001:10001 700" \
    "/run/zoeymcp-link 10001:10002 750" \
    "/run/zoeymcp-gateway 10002:10002 700")"
found="$(docker run --rm --entrypoint stat "$image" -c '%n %u:%g %a' \
    /state /state-gateway /run/zoeymcp /run/zoeymcp-link /run/zoeymcp-gateway)"
[ "$found" = "$expected" ] || fail "directory owners or modes differ: $found"
[ "$(docker run --rm --entrypoint id "$image" init)" = "uid=10003(init) gid=10003(init) groups=10003(init)" ] \
    || fail "no init user 10003"
found="$(docker run --rm --network none -u 0 --entrypoint find "$image" / -xdev \
    \( -user 10003 -o -group 10003 \) -print)"
[ -z "$found" ] || fail "the init user owns files: $found"
found="$(docker run --rm --network none -u 0 --entrypoint find "$image" / -xdev -perm /6000 -type f)"
[ -z "$found" ] || fail "setuid or setgid files: $found"

step "check and selftest --mutate on the example policy"
# The broker case expects 200: the self-test plays the OAuth token endpoint with dummy values.
# shellcheck disable=SC2086
docker run --rm $hardened -v "$examples:/examples:ro" "$image" check --config /examples/policy.yaml
# shellcheck disable=SC2086
docker run --rm $hardened -v "$examples:/examples:ro" "$image" \
    selftest --config /examples/policy.yaml --cases /examples/selftest-cases.yaml --mutate

step "J5: the egress allowlist emitted and compared from the hardened tier's inline policy"
# The two container commands of M7 design J5, as operations.md gives them: no --config, so the
# vault service's own ZOEYMCP_CONFIG is read; the findings go to stderr, the snippet to stdout.
j5_compose() {
    ZOEYMCP_IMAGE="$image" ZOEYMCP_MASTER_KEY=unset ZOEYMCP_GATEWAY_KEY=unset \
        docker compose -p "$j5_project" -f "$deploy/compose.hardened.yaml" "$@"
}
mkdir "$work/proxy"
j5_compose run --rm --no-deps -T vault \
    check --emit-egress-allowlist --allowlist-format squid >"$work/proxy/zoeymcp.conf" \
    || fail "check --emit-egress-allowlist failed on the hardened tier's inline policy"
grep -qx 'acl zoeymcp_vault_1 dstdomain -n mcp.notes.example' "$work/proxy/zoeymcp.conf" \
    || fail "the emitted snippet doesn't allow the inline policy's notes route"
chmod 0755 "$work/proxy"
chmod 0644 "$work/proxy/zoeymcp.conf"
j5_compose run --rm --no-deps -T -v "$work/proxy:/p:ro" vault \
    check --emit-egress-allowlist --allowlist-format squid --check /p/zoeymcp.conf \
    || fail "check --check refused the snippet it had just emitted"
sed 's/mcp\.notes\.example/mcp.other.example/' "$work/proxy/zoeymcp.conf" >"$work/proxy/stale.conf"
chmod 0644 "$work/proxy/stale.conf"
# Exit 1, with the differences listed: 2 (unreadable, a usage error) would show nothing.
status=0
j5_compose run --rm --no-deps -T -v "$work/proxy:/p:ro" vault \
    check --emit-egress-allowlist --allowlist-format squid --check /p/stale.conf \
    >"$work/proxy/stale.out" || status=$?
[ "$status" = 1 ] || fail "check --check on a stale snippet exited $status, not 1"
grep -qx 'missing: acl zoeymcp_vault_1 dstdomain -n mcp.notes.example' "$work/proxy/stale.out" \
    || fail "check --check didn't list the stale snippet's difference"
j5_compose down -v >/dev/null 2>&1

step "Squid parses the emitted snippet, and refuses private answers to listed names (contract 51)"
# The snippet for a test policy, inside the minimal squid.conf of M7 design I.6: it defines only
# what the snippet's header asks for, then the final deny. A fake DNS server on an internal
# network answers for the test names, so nothing leaves the host: a name the snippet lets
# through gets ERR_CONNECT_FAIL (no route), one it refuses ERR_ACCESS_DENIED. Every Squid here
# gets a working IPv6 loopback: without one Squid turns IPv6 off ("BCP 177"), drops the IPv6
# entries of zoeymcp_private_dst and ignores AAAA answers.
mkdir "$work/squid"
cat >"$work/squid/policy.yaml" <<'EOF'
version: 1
mode: declarative
routes:
  - {name: listed, prefix: /listed, upstream: "https://listed.squid.example",
     callers: [{placeholder: ph-squid-listed-0123456789}], rules: [{methods: [GET], paths: [/v1/**]}]}
  - {name: private, prefix: /private, upstream: "https://private.squid.example",
     callers: [{placeholder: ph-squid-private-0123456789}], rules: [{methods: [GET], paths: [/v1/**]}]}
  - {name: mapped, prefix: /mapped, upstream: "https://mapped.squid.example",
     callers: [{placeholder: ph-squid-mapped-0123456789}], rules: [{methods: [GET], paths: [/v1/**]}]}
  - {name: mixed, prefix: /mixed, upstream: "https://mixed.squid.example",
     callers: [{placeholder: ph-squid-mixed-0123456789}], rules: [{methods: [GET], paths: [/v1/**]}]}
EOF
squid_subnet=10.231.79.0/24
cat >"$work/squid/squid.conf" <<EOF
http_port 3128
acl CONNECT method CONNECT
acl zoeymcp_src_vault src $squid_subnet
include /etc/squid/zoeymcp.conf
http_access deny all
EOF
echo "nameserver 10.231.79.53" >"$work/squid/resolv.conf"
chmod 0755 "$work/squid"
chmod 0644 "$work/squid/policy.yaml" "$work/squid/squid.conf" "$work/squid/resolv.conf"
# shellcheck disable=SC2086
docker run --rm --network none $hardened -v "$work/squid:/w:ro" "$image" \
    check --config /w/policy.yaml --emit-egress-allowlist --allowlist-format squid \
    >"$work/squid/zoeymcp.conf" || fail "check --emit-egress-allowlist failed on the test policy"
chmod 0644 "$work/squid/zoeymcp.conf"
grep -q '^acl zoeymcp_private_dst dst .*127\.0\.0\.0/8' "$work/squid/zoeymcp.conf" \
    || fail "the snippet has no private-destination rule"
if grep -q '::ffff:0:0/96' "$work/squid/zoeymcp.conf"; then
    fail "the snippet refuses ::ffff:0:0/96, which Squid holds every IPv4 address in"
fi
# squid_conf SNIPPET: the docker run options that give Squid the minimal squid.conf with SNIPPET.
squid_conf() {
    echo "-v $work/squid/squid.conf:/etc/squid/squid.conf:ro -v $1:/etc/squid/zoeymcp.conf:ro" \
        "--sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0"
}
# squid_parse SNIPPET OUT: squid -k parse of the minimal squid.conf with SNIPPET, its log in OUT.
squid_parse() {
    # shellcheck disable=SC2046
    docker run --rm --network none --hostname squid.smoke.example $(squid_conf "$1") \
        --entrypoint squid "$squid_image" -k parse -f /etc/squid/squid.conf >"$2" 2>&1 \
        || { cat "$2"; fail "squid -k parse refused $1"; }
}
# What Squid logs when it keeps an ACL value only in part: an overlapping one ignored (6.6's
# wording first, then 7's) or every IPv6 one dropped because IPv6 is off. -k parse exits 0.
squid_dropped='is a subnetwork of|is ignored to keep splay|from the ACL named|Ignoring|Merging overlapping'
squid_dropped="$squid_dropped|IPv6 has not been enabled|BCP 177"
squid_parse "$work/squid/zoeymcp.conf" "$work/squid/parse"
if grep -E "$squid_dropped" "$work/squid/parse"; then
    fail "Squid didn't load every value of the emitted ACLs"
fi
# The control: ::ffff:0:0/96 holds every IPv4 row as Squid stores it, so Squid must say so.
sed 's|^acl zoeymcp_private_dst dst |&::ffff:0:0/96 |' "$work/squid/zoeymcp.conf" \
    >"$work/squid/mapped.conf"
chmod 0644 "$work/squid/mapped.conf"
squid_parse "$work/squid/mapped.conf" "$work/squid/parse-mapped"
grep -qE "$squid_dropped" "$work/squid/parse-mapped" \
    || { cat "$work/squid/parse-mapped"; fail "Squid printed no overlap warning for ::ffff:0:0/96"; }
# Fixed addresses below .128; the probes take theirs from the range above.
docker network create --internal --subnet "$squid_subnet" --ip-range 10.231.79.128/25 "$squid_net" \
    >/dev/null
# A DNS server for the test names: listed is public, private 10.x, mapped an AAAA answer
# ::ffff:127.0.0.1, mixed one public and one private address; unlisted isn't in the policy.
# 1.1.1.1's PTR name is the listed one, as that address's owner could make it.
fake_dns='
import socket, struct
v4 = lambda text: (1, socket.inet_pton(socket.AF_INET, text))
v6 = lambda text: (28, socket.inet_pton(socket.AF_INET6, text))
ptr = lambda text: (12, b"".join(bytes([len(x)]) + x.encode() for x in text.split(".")) + b"\0")
records = {
    "1.1.1.1.in-addr.arpa": [ptr("listed.squid.example")],
    "listed.squid.example": [v4("1.1.1.1")],
    "private.squid.example": [v4("10.0.0.9")],
    "mapped.squid.example": [v6("::ffff:127.0.0.1")],
    "mixed.squid.example": [v4("1.1.1.1"), v4("10.0.0.9")],
    "unlisted.squid.example": [v4("1.1.1.1")],
}
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.bind(("0.0.0.0", 53))
while True:
    query, peer = server.recvfrom(4096)
    end, labels = 12, []
    while query[end]:
        labels.append(query[end + 1 : end + 1 + query[end]].decode().lower())
        end += 1 + query[end]
    qtype = struct.unpack("!H", query[end + 1 : end + 3])[0]
    name = ".".join(labels)
    found = [data for kind, data in records.get(name, []) if kind == qtype]
    flags = 0x8180 | (0 if name in records else 3)
    answer = struct.pack("!6H", struct.unpack("!H", query[:2])[0], flags, 1, len(found), 0, 0)
    answer += query[12 : end + 5]
    for data in found:
        answer += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(data)) + data
    server.sendto(answer, peer)
'
# shellcheck disable=SC2086
docker run -d --name "$name-dns" $hardened --network "$squid_net" --ip 10.231.79.53 \
    --sysctl net.ipv4.ip_unprivileged_port_start=0 --entrypoint /opt/zoeymcp/bin/python \
    "$image" -I -c "$fake_dns" >/dev/null
# Prints the status and X-Squid-Error of a CONNECT to TARGET through the Squid at PROXY.
connect_through='
import socket, sys
proxy, target = sys.argv[1], sys.argv[2]
with socket.create_connection((proxy, 3128), timeout=30) as conn:
    conn.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = conn.recv(4096)
        if not chunk:
            break
        head += chunk
lines = head.decode("latin-1").split("\r\n")
errors = [l.split(":", 1)[1].split()[0] for l in lines[1:] if l.lower().startswith("x-squid-error:")]
print(lines[0].split(" ")[1], errors[0] if errors else "-")
'
# squid_client PROXY TARGET: connect_through, from a container on the Squid's network.
squid_client() {
    # shellcheck disable=SC2086
    docker run --rm $hardened --network "$squid_net" --entrypoint /opt/zoeymcp/bin/python \
        "$image" -I -c "$connect_through" "$@"
}
# squid_up NAME IP SNIPPET: a Squid with the minimal squid.conf and SNIPPET, answering on IP.
squid_up() {
    # shellcheck disable=SC2046
    docker run -d --name "$1" -u 0:0 --hostname squid.smoke.example --network "$squid_net" \
        --ip "$2" $(squid_conf "$3") \
        -v "$work/squid/resolv.conf:/etc/resolv.conf:ro" --entrypoint squid "$squid_image" \
        -N -d 1 -f /etc/squid/squid.conf >/dev/null
    i=0
    until squid_client "$2" unlisted.squid.example:443 >/dev/null 2>&1; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "Squid didn't start with the snippet"
        sleep 0.2
    done
}
# through IP TARGET: the answer of the Squid on IP to a CONNECT to TARGET.
through() {
    squid_client "$1" "$2" || fail "no answer from Squid for $2"
}
squid_up "$name-squid" 10.231.79.10 "$work/squid/zoeymcp.conf"
# 1.1.1.1 is public, unlisted, and its PTR name is listed: -n keeps dstdomain from using it.
for refused in private.squid.example mapped.squid.example mixed.squid.example \
    unlisted.squid.example 1.1.1.1; do
    found="$(through 10.231.79.10 "$refused:443")"
    echo "$refused: $found"
    [ "$found" = "403 ERR_ACCESS_DENIED" ] || fail "Squid didn't refuse $refused: $found"
done
found="$(through 10.231.79.10 listed.squid.example:443)"
echo "listed: $found"
case "$found" in
    403\ * | *\ ERR_ACCESS_DENIED | *\ ERR_DNS_FAIL) fail "Squid refused the listed public name: $found" ;;
esac
# The concern this settles: with ::ffff:0:0/96 in the rule, Squid refuses the public name too.
squid_up "$name-squid-mapped" 10.231.79.11 "$work/squid/mapped.conf"
[ "$(through 10.231.79.11 listed.squid.example:443)" = "403 ERR_ACCESS_DENIED" ] \
    || fail "Squid let a public IPv4 answer past ::ffff:0:0/96: the snippet's premise is wrong"
# The control for the PTR row: without -n, dstdomain matches 1.1.1.1 by its PTR name.
sed 's/ dstdomain -n / dstdomain /' "$work/squid/zoeymcp.conf" >"$work/squid/lookup.conf"
chmod 0644 "$work/squid/lookup.conf"
squid_up "$name-squid-lookup" 10.231.79.12 "$work/squid/lookup.conf"
found="$(through 10.231.79.12 1.1.1.1:443)"
echo "1.1.1.1 without -n: $found"
case "$found" in
    403\ * | *\ ERR_ACCESS_DENIED) fail "Squid without -n refused 1.1.1.1 too: the PTR row shows nothing" ;;
esac
docker rm -f "$name-dns" "$name-squid" "$name-squid-mapped" "$name-squid-lookup" >/dev/null
docker network rm "$squid_net" >/dev/null

step "start the vault, hardened"
key="$(docker run --rm "$image" keygen | sed -n 's/^ZOEYMCP_MASTER_KEY=//p')"
[ -n "$key" ] || fail "keygen printed no key"
docker volume create "$volume" >/dev/null
start_vault() {
    # shellcheck disable=SC2086
    docker run -d --name "$name" $hardened \
        --tmpfs /run/zoeymcp:size=1m,mode=0700,uid=10001,gid=10001 \
        -v "$volume:/state" \
        -e ZOEYMCP_MASTER_KEY="$key" \
        -e ZOEYMCP_CONFIG="$(cat "$examples/policy.yaml")" \
        -p "127.0.0.1:$port:8080" \
        "$image" vault >/dev/null
    i=0
    until curl -s -o /dev/null "http://127.0.0.1:$port/"; do
        i=$((i + 1))
        [ "$i" -lt 50 ] || fail "vault didn't start"
        sleep 0.2
    done
}
start_vault

step "refusals"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/stats/2.0/")" = "403" ] \
    || fail "no identity wasn't refused with 403"
[ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/nope")" = "404" ] \
    || fail "unknown prefix wasn't 404"

step "a secret set through the admin socket"
out="$(printf 'lfm-smoke-0123456789' | docker exec -i "$name" zoeymcp secret set music-stats)"
echo "$out"
echo "$out" | grep -q "bound to origins https://api.stats.example:443" || fail "unexpected binding"
docker exec "$name" zoeymcp secret list | grep -q '^music-stats ' || fail "secret not listed"
[ "$(docker exec "$name" stat -c '%a %u' /state/store.json)" = "600 10001" ] \
    || fail "store file isn't 0600 and owned by the vault"
if docker exec "$name" grep -q 'lfm-smoke-0123456789' /state/store.json; then
    fail "the store file contains the secret value"
fi

step "oauth status through the admin socket"
out="$(docker exec "$name" zoeymcp oauth status)"
echo "$out"
echo "$out" | grep -q '^broker-mcp: idle$' || fail "broker-mcp isn't listed as idle"

step "the container is read-only outside its tmpfs and volume"
if docker exec "$name" sh -c 'touch /opt/zoeymcp/x' 2>/dev/null; then
    fail "the image filesystem is writable"
fi

step "the secret survives a restart"
docker rm -f "$name" >/dev/null
start_vault
docker exec "$name" zoeymcp secret list | grep -q '^music-stats ' || fail "secret lost on restart"

step "a wrong master key refuses to start"
docker rm -f "$name" >/dev/null
other="$(docker run --rm "$image" keygen | sed -n 's/^ZOEYMCP_MASTER_KEY=//p')"
# shellcheck disable=SC2086
if docker run --rm $hardened -v "$volume:/state" -e ZOEYMCP_MASTER_KEY="$other" \
    -e ZOEYMCP_CONFIG="$(cat "$examples/policy.yaml")" "$image" vault 2>/tmp/zoeymcp-smoke-err; then
    fail "the vault started with the wrong master key"
fi
grep -q "ZOEYMCP_MASTER_KEY_PREVIOUS" /tmp/zoeymcp-smoke-err || fail "unexpected startup error"

step "standard tier: the launcher refuses a container that isn't its box"
std_box="--read-only --tmpfs /tmp:size=16m -u 0:0"
refused() {
    # refused REASON DOCKER-RUN-OPTIONS...: the launcher must refuse, naming REASON.
    reason="$1"
    shift
    # shellcheck disable=SC2068
    if docker run --rm $@ "$image" standard >/dev/null 2>/tmp/zoeymcp-smoke-err; then
        fail "the launcher started without: $reason"
    fi
    grep -q "$reason" /tmp/zoeymcp-smoke-err || fail "the refusal doesn't say: $reason"
}
refused "NoNewPrivs is not set" "$std_box --cap-drop ALL --cap-add SETUID --cap-add SETGID"
refused "capabilities beyond SETUID and SETGID" "$std_box --security-opt no-new-privileges:true"
refused "must start as root" "$hardened"

step "a client token, and the fake upstream's pins and certificate"
client="$(docker run --rm "$image" client-token 2>/dev/null)"
token="$(echo "$client" | sed -n 's/^client_token: //p')"
token_hash="$(echo "$client" | sed -n 's/^token_sha256: //p')"
[ -n "$token" ] && [ -n "$token_hash" ] || fail "client-token printed no token"
# The fake upstream is tests/fakes/run_mcp_server.py, run by the official image's gateway
# interpreter, the only one with the MCP SDK. .dockerignore keeps tests/ out of the image, so
# the repository's is mounted. Check refuses MCP over plain http, so the fake serves HTTPS from
# a throwaway CA, which the vault trusts through certifi's bundle with the CA added, mounted
# over the bundle its HTTP client reads.
fake_image="${official:-$image}"
fake_setup='
import sys
from pathlib import Path
import certifi
import mcp_types
from tests.acceptance.tls import issue_cert, make_ca
from tests.fakes.mcp_server import base_tools
from zoeymcp.gateway.pins import project_and_pin
out = Path(sys.argv[1])
ca = make_ca(out)
issue_cert(ca, "fake-upstream", out)
(out / "bundle.pem").write_text(Path(certifi.where()).read_text() + ca.ca_file.read_text())
for tool in base_tools():
    if tool["name"] in ("echo", "slow"):
        print(tool["name"], project_and_pin(mcp_types.Tool.model_validate(tool)).pin)
'
mkdir "$work/tls"
pins="$(docker run --rm --network none -u "$(id -u):$(id -g)" -e PYTHONPATH=/opt/src \
    -v "$tests:/opt/src/tests:ro" -v "$work/tls:/tls" \
    --entrypoint /opt/zoeymcp-gateway/bin/python "$fake_image" -c "$fake_setup" /tls)" \
    || fail "the fake upstream's pins and certificate couldn't be made"
chmod 0644 "$work/tls/"*
echo_pin="$(echo "$pins" | sed -n 's/^echo //p')"
slow_pin="$(echo "$pins" | sed -n 's/^slow //p')"
[ -n "$echo_pin" ] && [ -n "$slow_pin" ] || fail "no pins for echo and slow: $pins"
certifi_bundle="$(in_env /opt/zoeymcp -c 'import certifi; print(certifi.where())')"
[ -n "$certifi_bundle" ] || fail "the vault's environment has no certifi bundle"
# With --derived, the example mail toolkit as a server, with the connector and route its slot
# uses, so that review can be asked about a toolkit: mail_toolkit connectors|routes|servers.
mail_pin="$(sed -n 's/^ *send_note: \(sha256:[0-9a-f]*\)$/\1/p' "$examples/policy.yaml")"
mail_toolkit() {
    [ -n "$official" ] || return 0
    case "$1" in
        connectors)
            echo "        connectors:"
            echo "          mail-out:"
            echo "            {kind: smtp, host: smtp.mail.example, port: 465, from: agent@mail.example,"
            echo "             to: [partner@mail.example], username: store:mail-user,"
            echo "             password: store:mail-pass}"
            ;;
        routes)
            echo "          - name: mail-send"
            echo "            prefix: /mail"
            echo "            connector: mail-out"
            echo "            callers: [gateway]"
            echo "            rules: [{methods: [GET], paths: [/config]}, {methods: [POST], paths: [/send]}]"
            ;;
        servers)
            echo "            mail:"
            echo "              kind: toolkit"
            echo "              module: example_toolkits.mail"
            echo "              tools: {include: [send_note], approve: [send_note]}"
            echo "              review: {send_note: \"$mail_pin\"}"
            echo "              slots:"
            echo "                mail:"
            echo "                  route: mail-send"
            echo "                  rules:"
            echo "                    - {methods: [GET], paths: [/config]}"
            echo "                    - {methods: [POST], paths: [/send], approved: true}"
            ;;
    esac
}
# The smoke's policy after its first lines, indented for ZOEYMCP_CONFIG: the shipped notes
# server, and a fake server routed to the fake upstream, with echo and slow pinned and allowed.
smoke_policy() {
    cat <<EOF
        credentials:
          notes-key: {kind: header, header: X-API-Key, format: "{secret}", secret: "store:notes-key"}
$(mail_toolkit connectors)
        routes:
          - name: notes-mcp
            prefix: /notes
            upstream: https://mcp.notes.example
            credential: notes-key
            callers: [gateway]
            stream: true
            rules: [{methods: [POST, GET, DELETE], paths: [/mcp]}]
          - name: fake-mcp
            prefix: /fake
            upstream: https://fake-upstream:9000
            callers: [gateway]
            stream: true
            rules: [{methods: [POST, GET, DELETE], paths: [/mcp]}]
$(mail_toolkit routes)
        gateway:
          hosts: [gateway, localhost, 127.0.0.1, zoeymcp.lan.example]
          clients:
            agent1: {token_sha256: "$token_hash", servers: [notes, fake]}
          servers:
            notes: {kind: remote, route: notes-mcp, path: /mcp}
            fake:
              kind: remote
              route: fake-mcp
              path: /mcp
              tools: {include: [echo, slow], allow: [echo, slow]}
              review: {echo: "$echo_pin", slow: "$slow_pin"}
$(mail_toolkit servers)
EOF
}
# The vault's volume line that adds the fake upstream's CA to what it trusts.
vault_trust() {
    echo "    volumes: [\"$work/tls/bundle.pem:$certifi_bundle:ro\"]"
}
# The fake upstream's compose service, on the project's default network unless a networks
# line follows.
fake_service() {
    cat <<EOF
  fake-upstream:
    image: $fake_image
    entrypoint: [/opt/zoeymcp-gateway/bin/python]
    command: [-m, tests.fakes.run_mcp_server, /tls/fake-upstream.pem, /tls/fake-upstream.key]
    environment:
      PYTHONPATH: /opt/src
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    tmpfs: [/tmp:size=16m]
    volumes: ["$tests:/opt/src/tests:ro", "$work/tls:/tls:ro"]
EOF
}
# Modern-era requests to the fake server: one tools/list and one tools/call.
modern=2026-07-28
meta_keys='"io.modelcontextprotocol/protocolVersion":"'"$modern"'"'
meta_keys="$meta_keys"',"io.modelcontextprotocol/clientCapabilities":{}'
list_tools='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{'"$meta_keys"'}}}'
call_echo='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo",'
call_echo="$call_echo"'"arguments":{"text":"smoke-echo"},"_meta":{'"$meta_keys"'}}}'
# fake_mcp BASE BODY CURL-OPTIONS...: a POST of BODY to BASE/s/fake/mcp with the client token;
# prints the status, and the answer lands in $work/body.
fake_mcp() {
    fake_base="$1"
    fake_body="$2"
    shift 2
    curl -s -o "$work/body" -w '%{http_code}' -X POST -H 'content-type: application/json' \
        -H 'accept: application/json, text/event-stream' -H "authorization: Bearer $token" \
        -H "mcp-protocol-version: $modern" -d "$fake_body" "$@" "$fake_base/s/fake/mcp" || true
}
# fake_round BASE CURL-OPTIONS...: tools/list shows echo and slow but no tool the policy leaves
# out, and tools/call echo answers, through the vault and the fake upstream.
fake_round() {
    round_base="$1"
    shift
    i=0
    until [ "$(fake_mcp "$round_base" "$list_tools" -H 'mcp-method: tools/list' "$@")" = "200" ] \
        && grep -q '"name":"echo"' "$work/body"; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "tools/list never showed the fake upstream's echo tool"
        sleep 0.3
    done
    grep -q '"name":"slow"' "$work/body" || fail "tools/list doesn't show the fake upstream's slow tool"
    if grep -q '"name":"add"' "$work/body"; then
        fail "tools/list shows the fake upstream's add tool, which the policy leaves out"
    fi
    [ "$(fake_mcp "$round_base" "$call_echo" -H 'mcp-method: tools/call' -H 'mcp-name: echo' "$@")" \
        = "200" ] || fail "tools/call echo failed"
    grep -q '"text":"smoke-echo"' "$work/body" || fail "tools/call echo didn't answer with its text"
}

# C.3's headers, names lower-cased: every portal answer carries each exactly once.
csp="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self';"
csp="$csp object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';"
csp="$csp require-trusted-types-for 'script'; trusted-types 'none'"
printf '%s\n' "content-security-policy: $csp" "x-content-type-options: nosniff" \
    "referrer-policy: no-referrer" "cache-control: no-store" \
    "cross-origin-opener-policy: same-origin" "cross-origin-resource-policy: same-origin" \
    "x-frame-options: DENY" "x-zoeymcp-vault: portal" >"$work/c3"
# portal HOST PATH CURL-OPTIONS...: a request to the portal published on the host's loopback,
# with HOST as its Host header; prints the status, and the body and the headers (names
# lower-cased) land in $work.
portal() {
    portal_host="$1"
    portal_path="$2"
    shift 2
    : >"$work/raw-headers"
    curl -s -o "$work/body" -D "$work/raw-headers" -w '%{http_code}' -H "Host: $portal_host" \
        "$@" "http://127.0.0.1:8081$portal_path" || true
    tr -d '\r' <"$work/raw-headers" \
        | awk '{ i = index($0, ":"); print (i ? tolower(substr($0, 1, i - 1)) substr($0, i) : $0) }' \
        >"$work/headers"
}
# portal_post HOST PATH BODY: a JSON POST as the portal's own page sends it.
portal_post() {
    portal "$1" "$2" -X POST -H 'sec-fetch-site: same-origin' -H 'origin: http://localhost:8081' \
        -H 'content-type: application/json' -d "$3"
}
# c3 WHAT: the answer in $work carries each C.3 header exactly once, and no CORS header or ETag.
c3() {
    while IFS= read -r header; do
        [ "$(grep -cFx "$header" "$work/headers")" = "1" ] \
            || fail "$1 doesn't carry exactly one ${header%%:*} header as C.3 has it"
    done <"$work/c3"
    if grep -qE '^(access-control-|etag:)' "$work/headers"; then
        fail "$1 carries a CORS header or an ETag"
    fi
}
# portal_shell TIER: from the host's loopback, each static file with C.3's headers, its content
# type and the bytes the image installed (contract 42); a loopback IP literal as the Host gets
# the 308 to localhost for GET /, and 421 otherwise.
portal_shell() {
    i=0
    until [ "$(portal localhost:8081 /)" = "200" ]; do
        i=$((i + 1))
        [ "$i" -lt 50 ] || fail "$1: the portal didn't serve its shell on 127.0.0.1:8081"
        sleep 0.2
    done
    while read -r static_path static_hash static_type; do
        [ "$(portal localhost:8081 "$static_path")" = "200" ] || fail "$1: GET $static_path wasn't 200"
        c3 "$1: GET $static_path"
        grep -qFx "content-type: $static_type" "$work/headers" \
            || fail "$1: GET $static_path isn't served as $static_type"
        [ "$(sha256sum "$work/body" | cut -d ' ' -f 1)" = "$static_hash" ] \
            || fail "$1: GET $static_path isn't the file the image installed"
    done <"$work/static"
    [ "$(portal 127.0.0.1:8081 /)" = "308" ] || fail "$1: GET / with Host 127.0.0.1:8081 wasn't 308"
    c3 "$1: the 308"
    grep -qFx 'location: http://localhost:8081/' "$work/headers" \
        || fail "$1: the 308 doesn't send the browser to http://localhost:8081/"
    [ "$(portal 127.0.0.1:8081 /app.js)" = "421" ] \
        || fail "$1: GET /app.js with Host 127.0.0.1:8081 wasn't 421"
    c3 "$1: the 421"
    grep -qF 'http://localhost:8081/' "$work/body" || fail "$1: the 421 doesn't name http://localhost:8081/"
    [ "$(portal_post 127.0.0.1:8081 /api/setup/redeem '{"code":"x"}')" = "421" ] \
        || fail "$1: POST /api/setup/redeem with Host 127.0.0.1:8081 wasn't 421"
}
# portal_code TIER CODE LOGS-COMMAND...: CODE is a setup code just issued through the admin
# socket; a bad code gets 401 from the host's loopback, and CODE isn't in the tier's logs.
portal_code() {
    code_tier="$1"
    code="$2"
    shift 2
    case "$code" in
        ??????-??????-??????-??????) ;;
        *) fail "$code_tier: setup-code printed no code" ;;
    esac
    [ "$(portal_post localhost:8081 /api/setup/redeem '{"code":"AAAAAA-AAAAAA-AAAAAA-AAAAAA"}')" \
        = "401" ] || fail "$code_tier: a bad setup code wasn't refused with 401"
    c3 "$code_tier: the refused setup code"
    grep -q '"reason": *"setup_code_refused"' "$work/body" \
        || fail "$code_tier: a bad setup code wasn't refused as setup_code_refused"
    "$@" >"$work/logs" 2>&1
    grep -q '"event":"setup_code_issued"' "$work/logs" || fail "$code_tier: no setup_code_issued line"
    if grep -qiF -e "$code" -e "$(echo "$code" | tr -d -)" "$work/logs"; then
        fail "$code_tier: the setup code is in the container's logs"
    fi
}
# Exits non-zero naming each address that takes a connection on 8081 within 2 s.
unreachable='
import socket, sys
reached = []
for address in sys.argv[1:]:
    try:
        socket.create_connection((address, 8081), timeout=2).close()
    except OSError:
        continue
    reached.append(address)
if reached:
    sys.exit("reached port 8081 at " + ", ".join(reached))
print("8081 unreachable at", " ".join(sys.argv[1:]))
'
# probe NETWORK ARGS...: the vault's interpreter in a container on NETWORK, run as the hardened
# tier runs it.
probe() {
    probe_network="$1"
    shift
    # shellcheck disable=SC2086
    docker run --rm $hardened --network "$probe_network" --entrypoint /opt/zoeymcp/bin/python \
        "$image" -I "$@"
}
# unrelated TIER CONTAINER: a probe on a network of its own can't reach the loopback-published
# portal through the host's bridge addresses or any of CONTAINER's addresses (contract 44).
unrelated() {
    docker network inspect "$probe_net" >/dev/null 2>&1 || docker network create "$probe_net" >/dev/null
    bridges="$(docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}} {{end}}' "$probe_net" bridge)"
    addresses="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$2")"
    echo "$bridges" | grep -q '[0-9]' || fail "$1: no bridge address to probe"
    echo "$addresses" | grep -q '[0-9]' || fail "$1: no container address to probe"
    # shellcheck disable=SC2086
    probe "$probe_net" -c "$unreachable" $bridges $addresses \
        || fail "$1: a container on an unrelated network reached the portal"
}

step "standard tier: up, from deploy/compose.yaml, with the smoke's policy and the fake upstream"
# The portal as the compose file has it, on every address in the container.
cat >"$work/standard.yaml" <<EOF
services:
  zoeymcp:
$(vault_trust)
    environment:
      ZOEYMCP_CONFIG: |
        version: 1
        mode: declarative
        admin:
          listen: 0.0.0.0:8081
          origins: [http://localhost:8081]
$(smoke_policy)
$(fake_service)
EOF
standard up -d
i=0
until [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/healthz)" = "200" ]; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the standard tier's gateway didn't become ready"
    sleep 0.3
done
std="$(standard ps -q zoeymcp)"
[ -n "$std" ] || fail "no standard-tier container"

step "standard tier: three uids, and PID 1 holds nothing"
# pid uid CapEff role, for every process.
processes='
import os
for pid in sorted(int(p) for p in os.listdir("/proc") if p.isdigit()):
    try:
        with open(f"/proc/{pid}/status") as handle:
            status = dict(line.split(":", 1) for line in handle.read().splitlines() if ":" in line)
        with open(f"/proc/{pid}/cmdline", "rb") as handle:
            argv = handle.read().split(b"\0")
    except OSError:
        continue
    role = next((w.decode() for w in (b"standard", b"vault", b"gateway") if w in argv), "-")
    print(pid, status["Uid"].split()[0], status["CapEff"].strip(), role)
'
found="$(docker exec "$std" python -I -c "$processes")"
echo "$found"
echo "$found" | grep -qx "1 10003 0000000000000000 standard" \
    || fail "PID 1 isn't the launcher as 10003 with no capabilities"
vault_pid="$(echo "$found" | awk '$4 == "vault" && $2 == "10001" && $3 == "0000000000000000" {print $1}')"
gateway_pid="$(echo "$found" | awk '$4 == "gateway" && $2 == "10002" && $3 == "0000000000000000" {print $1}')"
[ -n "$vault_pid" ] || fail "no vault process as 10001 without capabilities"
[ -n "$gateway_pid" ] || fail "no gateway process as 10002 without capabilities"
[ "$(docker exec --privileged "$std" cat /proc/1/environ | wc -c)" -eq 0 ] \
    || fail "PID 1 still has an environment"
docker exec --privileged "$std" cat "/proc/$gateway_pid/environ" | tr '\0' '\n' \
    | grep -q '^ZOEYMCP_MASTER_KEY=' && fail "the gateway has the master key"
docker exec --privileged "$std" cat "/proc/$vault_pid/environ" | tr '\0' '\n' \
    | grep -q '^ZOEYMCP_MASTER_KEY=' || fail "the vault has no master key"

step "standard tier: the gateway's uid can't reach the vault's state, environment or admin socket"
if docker exec -u 10002 "$std" ls /state >/dev/null 2>&1; then
    fail "uid 10002 can list /state"
fi
if docker exec -u 10002 "$std" cat "/proc/$vault_pid/environ" >/dev/null 2>&1; then
    fail "uid 10002 can read the vault's environment"
fi
if docker exec -u 10002 "$std" zoeymcp secret list >/dev/null 2>&1; then
    fail "uid 10002 can use the vault's admin socket"
fi

step "standard tier: agents need a token; admin commands switch to the socket's owner"
[ "$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' \
    -d '{}' http://127.0.0.1:8090/s/notes/mcp)" = "401" ] || fail "no token wasn't 401"
out="$(printf 'notes-smoke-0123456789' | docker exec -i "$std" zoeymcp secret set notes-key)"
echo "$out"
echo "$out" | grep -q "^stored notes-key" || fail "secret set didn't reach the vault as root"
out="$(docker exec "$std" zoeymcp review)" || fail "review (no server) didn't reach the gateway"
echo "$out"
echo "$out" | grep -q "^notes  " || fail "review lists no notes server"
docker exec "$std" zoeymcp gateway-status | grep -q '^view sha256:' \
    || fail "gateway-status didn't reach the gateway"

step "standard tier: ledger --verify and ledger --vault exit 0 on an empty ledger, as root (D-74)"
docker exec "$std" zoeymcp ledger --verify || fail "ledger --verify failed on an empty ledger"
docker exec "$std" zoeymcp ledger --vault || fail "ledger --vault failed on an empty ledger"

if [ -n "$official" ]; then
    step "derived: review of the mail toolkit, as root (D-74)"
    out="$(docker exec "$std" zoeymcp review mail)" || fail "review mail didn't reach the gateway"
    echo "$out"
    echo "$out" | grep -qF "send_note: $mail_pin" || fail "review mail doesn't show the committed pin"
fi

step "standard tier: the portal's shell from the host's loopback, with C.3's headers (contract 42)"
portal_shell "standard tier"

step "standard tier: a bad setup code gets 401; one issued as root isn't in the logs"
code="$(docker exec "$std" zoeymcp setup-code)" || fail "setup-code as root didn't reach the vault"
portal_code "standard tier" "$code" standard logs zoeymcp

step "standard tier: a container on the compose network gets only the shell and 401/429 (Q29)"
# A sibling container on the compose network reaches the portal, as the gateway does in the
# standard tier: it gets the static shell, a login ceremony that names no passkey, and 401 or
# 429 from every route that holds anything, with the Host, Origin and Sec-Fetch-Site a browser
# on the operator's origin would send.
sibling='
import http.client, json, sys
from zoeymcp.portal.routes import ROUTES, STATIC
def ask(method, path, body=None):
    headers = {"Host": "localhost:8081", "Origin": "http://localhost:8081",
               "Sec-Fetch-Site": "same-origin"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    connection = http.client.HTTPConnection("zoeymcp", 8081, timeout=10)
    connection.request(method, path, body=data, headers=headers)
    answer = connection.getresponse()
    status, text = answer.status, answer.read()
    connection.close()
    print(method, path, status)
    return status, text
problems = []
for path in STATIC:
    if ask("GET", path)[0] != 200:
        problems.append(f"GET {path} is not the shell")
bodies = {"/api/setup/redeem": {"code": "AAAAAA-AAAAAA-AAAAAA-AAAAAA"}}
status, text = ask("POST", "/api/login/begin", {})
if status == 200:
    begun = json.loads(text)
    if set(begun) != {"ceremony", "options"} or begun["options"].get("allowCredentials"):
        problems.append(f"login/begin answered more than a ceremony: {sorted(begun)}")
    forged = {"id": "AAAA", "rawId": "AAAA", "type": "public-key", "response": {}}
    bodies["/api/login/finish"] = {"ceremony": begun["ceremony"], "credential": forged}
elif status != 429:
    problems.append(f"POST /api/login/begin: {status}")
for route in ROUTES:
    if route.path == "/api/login/begin":
        continue
    path = route.path.format(credential="x", flow="x", action="x")
    body = None
    if route.method == "POST":
        body = bodies.get(route.path, {key: "x" for key in route.body})
    status = ask(route.method, path, body)[0]
    if status not in (401, 429):
        problems.append(f"{route.method} {path}: {status}")
if problems:
    sys.exit("; ".join(problems))
'
probe "${project}_default" -c "$sibling" || fail "a container on the compose network got more"

step "standard tier: a container on an unrelated network can't reach the portal (contract 44)"
unrelated "standard tier" "$std"

step "standard tier: tools/list and tools/call through the vault to the fake upstream"
fake_round http://127.0.0.1:8090

step "standard tier: HUP reloads both, through the control pipes"
docker kill -s HUP "$std" >/dev/null
i=0
until [ "$(standard logs zoeymcp | grep -c '"event":"control_received","command":"HUP"')" -ge 2 ]; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "HUP didn't reach both children"
    sleep 0.2
done
standard logs zoeymcp | grep -q '"event":"reload_ok"' || fail "the vault didn't reload"

step "standard tier: a graceful stop"
standard stop -t 420 zoeymcp
[ "$(docker inspect -f '{{.State.ExitCode}}' "$std")" = "0" ] || fail "the launcher exited non-zero"
for child in vault gateway; do
    standard logs zoeymcp | grep -q "\"event\":\"child_exited\",\"child\":\"$child\",\"status\":0" \
        || fail "the $child didn't stop cleanly"
done

step "hardened tier: up, from deploy/compose.hardened.yaml with the lan profile"
keys="$(docker run --rm "$image" keygen)"
hardened_master="$(echo "$keys" | sed -n 's/^ZOEYMCP_MASTER_KEY=//p')"
gateway_key="$(echo "$keys" | sed -n 's/^ZOEYMCP_GATEWAY_KEY=//p')"
first_key="$gateway_key"
generation=1
# The smoke's policy, with this run's client token and the portal as the compose file has it
# (on the vault's egress alias), and the vault trusting the fake upstream's CA; compose
# interpolates the generation. The fake upstream joins egress, the vault's way out, for this run
# only (so it could reach the portal, as anything on egress could).
cat >"$work/override.yaml" <<EOF
services:
  vault:
$(vault_trust)
    environment:
      ZOEYMCP_CONFIG: |
        version: 1
        mode: declarative
        gateway_key_generation: \${ZOEYMCP_GATEWAY_KEY_GENERATION:-1}
        admin:
          listen: vault-portal:8081
          origins: [http://localhost:8081]
$(smoke_policy)
$(fake_service)
    networks: [egress]
EOF
hardened_tier up -d
gateway_fresh() {
    hardened_tier exec -T gateway zoeymcp gateway-status 2>/dev/null \
        | grep -q '^view sha256:[0-9a-f]*  fresh$'
}
i=0
until gateway_fresh; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the hardened gateway never got a fresh view"
    sleep 0.3
done

step "hardened tier: the gateway has no way out"
no_route='
import socket, sys
for target in (("1.1.1.1", 443), ("example.com", 443)):
    try:
        socket.create_connection(target, timeout=3).close()
    except OSError:
        continue
    sys.exit(f"reached {target}")
'
hardened_tier exec -T gateway python -I -c "$no_route" || fail "the gateway reached the internet"
out="$(hardened_tier exec -T gateway zoeymcp review)" || fail "review didn't reach the gateway"
echo "$out" | grep -q "^notes  " || fail "review lists no notes server"

step "hardened tier: the portal's shell from the host's loopback, with C.3's headers (contract 42)"
portal_shell "hardened tier"

step "hardened tier: a bad setup code gets 401; one issued through the socket isn't in the logs"
code="$(hardened_tier exec -T vault zoeymcp setup-code)" || fail "setup-code didn't reach the vault"
portal_code "hardened tier" "$code" hardened_tier logs vault

step "hardened tier: vault-portal is the vault's egress address, the only one on 8081 (contract 43)"
vault_id="$(hardened_tier ps -q vault)"
egress="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${hardened_project}_egress\").IPAddress}}" \
    "$vault_id")"
addresses="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "$vault_id")"
echo "the vault's addresses: $addresses; egress: $egress"
resolve='
import socket, sys
print(" ".join(sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[1], 8081)})))
'
found="$(hardened_tier exec -T vault python -I -c "$resolve" vault-portal)" \
    || fail "the vault can't resolve vault-portal"
[ -n "$egress" ] && [ "$found" = "$egress" ] \
    || fail "vault-portal resolves to $found in the vault, not its egress address $egress"
# shellcheck disable=SC2086
hardened_tier exec -T gateway python -I -c "$unreachable" vault vault-portal $addresses \
    || fail "the gateway reached the portal"
for network in internal direct agents; do
    # shellcheck disable=SC2086
    probe "${hardened_project}_$network" -c "$unreachable" vault vault-portal $addresses \
        || fail "a container on $network reached the portal"
done

step "hardened tier: a container on an unrelated network can't reach the portal (contract 44)"
unrelated "hardened tier" "$vault_id"

step "lan: TLS from Caddy's own CA, and the gateway's checks behind it"
i=0
until hardened_tier cp lan:/data/caddy/pki/authorities/local/root.crt "$work/root.crt" 2>/dev/null; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "Caddy made no root certificate"
    sleep 0.3
done
# lan_status HOST PATH CURL-OPTIONS...: the HTTP status; the body and headers land in $work.
lan_status() {
    lan_name="$1"
    lan_path="$2"
    shift 2
    curl -s -o "$work/body" -D "$work/headers" -w '%{http_code}' --cacert "$work/root.crt" \
        --resolve "$lan_name:8443:127.0.0.1" "$@" "https://$lan_name:8443$lan_path" || true
}
# lan_mcp HOST CURL-OPTIONS...: a JSON-RPC POST to the notes server.
lan_mcp() {
    lan_host_name="$1"
    shift
    lan_status "$lan_host_name" /s/notes/mcp -X POST -H 'content-type: application/json' \
        -H 'accept: application/json, text/event-stream' "$@"
}
i=0
until [ "$(lan_mcp zoeymcp.lan.example -d '{}')" = "401" ]; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "no 401 without a token through the lan proxy"
    sleep 0.3
done
[ "$(lan_mcp zoeymcp.lan.example -H 'origin: https://evil.example' -d '{}')" = "403" ] \
    || fail "an unlisted Origin wasn't 403 through the lan proxy"
[ "$(lan_status zoeymcp.lan.example /elsewhere)" = "404" ] || fail "a path outside /s/ wasn't 404"
initialize='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",'
initialize="$initialize"'"capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
[ "$(lan_mcp zoeymcp.lan.example -H "authorization: Bearer $token" -d "$initialize")" = "200" ] \
    || fail "initialize with the client token failed through the lan proxy"
grep -qi '^content-type: text/event-stream' "$work/headers" || fail "the answer isn't an SSE stream"
grep -q '^event: message' "$work/body" || fail "no SSE event came through"
grep -q '"name":"zoeymcp/notes"' "$work/body" || fail "the gateway's serverInfo didn't come through"

step "lan: tools/list and tools/call to the fake upstream, and slow's events one by one"
lan_base="https://zoeymcp.lan.example:8443"
fake_round "$lan_base" --cacert "$work/root.crt" --resolve zoeymcp.lan.example:8443:127.0.0.1
# Four progress events a second apart, then the result. Each must come through Caddy on its
# own, not held until the call ends.
call_slow='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"slow",'
call_slow="$call_slow"'"arguments":{"steps":4,"interval":1},"_meta":{"progressToken":"smoke",'
call_slow="$call_slow$meta_keys"'}}}'
curl -s -N -o "$work/slow" -w '%{http_code}' --cacert "$work/root.crt" \
    --resolve zoeymcp.lan.example:8443:127.0.0.1 -X POST -H 'content-type: application/json' \
    -H 'accept: application/json, text/event-stream' -H "authorization: Bearer $token" \
    -H "mcp-protocol-version: $modern" -H 'mcp-method: tools/call' -H 'mcp-name: slow' \
    -d "$call_slow" "$lan_base/s/fake/mcp" >"$work/slow-status" &
slow_pid=$!
# slow_events PATTERN: how many lines of the slow call's answer so far match PATTERN.
slow_events() {
    count="$(grep -c "$1" "$work/slow" 2>/dev/null)" || true
    echo "${count:-0}"
}
for seen in 1 2; do
    i=0
    until [ "$(slow_events '"method":"notifications/progress"')" -ge "$seen" ]; do
        i=$((i + 1))
        [ "$i" -lt 100 ] || fail "progress event $seen of the slow call never came through the lan proxy"
        sleep 0.1
    done
    [ "$(slow_events '"result":')" = "0" ] \
        || fail "progress event $seen came with the result: the lan proxy held the stream back"
done
wait "$slow_pid" || fail "the slow call through the lan proxy failed"
[ "$(cat "$work/slow-status")" = "200" ] || fail "the slow call through the lan proxy wasn't 200"
grep -q 'done after 4 steps' "$work/slow" || fail "the slow call's result didn't come through"

step "lan: a name missing from gateway.hosts gets 421"
lan_host=other.lan.example
hardened_tier up -d lan
i=0
until [ "$(lan_mcp other.lan.example -d '{}')" = "421" ]; do
    i=$((i + 1))
    [ "$i" -lt 50 ] || fail "a LAN name missing from gateway.hosts wasn't 421"
    sleep 0.3
done
lan_host=zoeymcp.lan.example

step "hardened tier: rotating the gateway key"
generation=2
hardened_tier up -d vault
i=0
until hardened_tier exec -T vault zoeymcp gateway-key 2>&1 \
    | grep -q '^rotation pending: generation 1 accepted until'; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the bump started no rotation window"
    sleep 0.3
done
gateway_key="$(hardened_tier exec -T vault zoeymcp gateway-key 2>/dev/null \
    | sed -n 's/^ZOEYMCP_GATEWAY_KEY=//p')"
[ -n "$gateway_key" ] && [ "$gateway_key" != "$first_key" ] || fail "no new gateway key"
hardened_tier up -d gateway
i=0
until hardened_tier logs vault \
    | grep -q '"event":"gateway_key_retired","generation":1,"reason":"new_key_used"'; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the new key's first use didn't retire the old one"
    sleep 0.3
done
i=0
until gateway_fresh; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || fail "the gateway has no fresh view after the rotation"
    sleep 0.3
done
if hardened_tier exec -T vault zoeymcp gateway-key 2>&1 | grep -q '^rotation pending'; then
    fail "a rotation is still pending"
fi
old_key_view='
import sys, urllib.error, urllib.request
request = urllib.request.Request(
    "http://vault:8080/_zoeymcp/gateway/v1/view", headers={"x-zoeymcp-gateway": sys.argv[1]}
)
try:
    urllib.request.urlopen(request, timeout=10)
except urllib.error.HTTPError as error:
    sys.exit(0 if error.code == 403 else f"status {error.code}")
sys.exit("the old key was accepted")
'
hardened_tier exec -T gateway python -I -c "$old_key_view" "$first_key" \
    || fail "the retired key wasn't refused"
hardened_tier down -v >/dev/null 2>&1

# --- contract 54: the existing-stack example ----------------------------------------------------
# examples/existing-stack/compose.yaml as shipped, with two internal networks standing in for the
# stack's own: its agent network and its proxy's (no proxy runs: nothing here goes out). The
# relay must pass Host, Origin and Sec-Fetch-* unchanged, so the vault's portal answers every
# probe through it exactly as it answers a container on the portal network; and neither the vault
# nor the gateway is on a network with a route out. This block removes all it starts, whatever
# happens, with its own trap.
step "existing stack: up, from examples/existing-stack/compose.yaml (contract 54)"
existing_project="zoeymcp-smoke-existing-$$"
stack_agents="zoeymcp-smoke-stack-agents-$$"
stack_proxy="zoeymcp-smoke-stack-proxy-$$"
existing_stack() {
    ZOEYMCP_IMAGE="$image" ZOEYMCP_MASTER_KEY="${existing_master:-unset}" \
        ZOEYMCP_GATEWAY_KEY="${existing_gateway_key:-unset}" \
        ZOEYMCP_STACK_AGENTS="$stack_agents" ZOEYMCP_STACK_PROXY="$stack_proxy" \
        docker compose -p "$existing_project" -f "$examples/existing-stack/compose.yaml" "$@"
}
existing_cleanup() {
    existing_stack down -v >/dev/null 2>&1 || true
    docker network rm "$stack_agents" "$stack_proxy" >/dev/null 2>&1 || true
}
trap 'existing_cleanup; cleanup' EXIT
existing_fail() {
    existing_stack logs >&2 2>/dev/null || true
    fail "existing stack: $*"
}
docker network create --internal "$stack_agents" >/dev/null
docker network create --internal "$stack_proxy" >/dev/null
existing_keys="$(docker run --rm "$image" keygen)"
existing_master="$(echo "$existing_keys" | sed -n 's/^ZOEYMCP_MASTER_KEY=//p')"
existing_gateway_key="$(echo "$existing_keys" | sed -n 's/^ZOEYMCP_GATEWAY_KEY=//p')"
existing_stack up -d
i=0
until [ "$(portal localhost:8081 /)" = "200" ]; do
    i=$((i + 1))
    [ "$i" -lt 100 ] || existing_fail "the portal's shell never came through the relay"
    sleep 0.3
done

step "existing stack: the portal answers through the relay as it does direct (contract 54)"
# One line per probe: its name, the status and the refusal's reason ("-" for none). The probes
# are the portal's posture checks (operations.md §26) and one for each header the relay must
# pass: Host (the shell, and a name the policy doesn't list), Sec-Fetch-Site and Origin (a
# cross-site request, a wrong Origin, and a setup code refused only after both passed), and
# Sec-Fetch-Mode and Sec-Fetch-Dest (a callback taken as a navigation, and one refused as not).
existing_probes='
import http.client, json, sys
host, port = sys.argv[1], int(sys.argv[2])
own = {"Host": "localhost:8081"}
page = {**own, "Sec-Fetch-Site": "same-origin", "Origin": "http://localhost:8081"}
code = {"code": "AAAAAA-AAAAAA-AAAAAA-AAAAAA"}
navigate = {**own, "Sec-Fetch-Site": "none", "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Dest": "document"}
probes = [
    ("shell", "GET", "/", own, None),
    ("wrong-host", "GET", "/", {"Host": "wrong.example"}, None),
    ("cross-site", "POST", "/api/logout",
     {**own, "Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, {}),
    ("wrong-origin", "POST", "/api/setup/redeem", {**page, "Origin": "http://evil.example"}, code),
    ("setup-code", "POST", "/api/setup/redeem", page, code),
    ("navigation", "GET", "/oauth/callback/smoke?state=x", navigate, None),
    ("not-navigation", "GET", "/oauth/callback/smoke?state=x",
     {**navigate, "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty"}, None),
]
for name, method, path, headers, body in probes:
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers = {**headers, "Content-Type": "application/json"}
    connection = http.client.HTTPConnection(host, port, timeout=10)
    connection.request(method, path, body=data, headers=headers)
    answer = connection.getresponse()
    text = answer.read()
    connection.close()
    try:
        reason = json.loads(text).get("reason") or "-"
    except (ValueError, AttributeError):
        reason = "-"
    print(name, answer.status, reason)
'
probe "${existing_project}_portal" -c "$existing_probes" vault-portal 8081 >"$work/direct" \
    || existing_fail "the probes failed from the portal network"
# shellcheck disable=SC2086
docker run --rm $hardened --network host --entrypoint /opt/zoeymcp/bin/python "$image" \
    -I -c "$existing_probes" 127.0.0.1 8081 >"$work/relayed" \
    || existing_fail "the probes failed through the relay"
cat "$work/relayed"
diff "$work/direct" "$work/relayed" || existing_fail "the portal answered differently through the relay"
for expected in "shell 200 -" "wrong-host 421 wrong_host" "cross-site 403 cross_site" \
    "wrong-origin 403 bad_origin" "setup-code 401 setup_code_refused" "not-navigation 403 -"; do
    grep -qx "$expected" "$work/relayed" || existing_fail "through the relay, not: $expected"
done
if grep -q '^navigation 403 ' "$work/relayed"; then
    existing_fail "a navigation to the callback was refused as not one: Sec-Fetch-* didn't pass"
fi
# No access log: nothing the relay wrote names a path it passed on.
if existing_stack logs portal-relay 2>&1 | grep -e '/api/' -e '/oauth/callback'; then
    existing_fail "the relay logged a request"
fi

step "existing stack: neither the vault nor the gateway has a network with a route out (contract 54)"
for existing_service in vault gateway; do
    existing_id="$(existing_stack ps -q "$existing_service")"
    [ -n "$existing_id" ] || existing_fail "no $existing_service container"
    existing_nets="$(docker inspect \
        -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$existing_id")"
    echo "$existing_service: $existing_nets"
    [ -n "$existing_nets" ] || existing_fail "$existing_service is on no network"
    for existing_net in $existing_nets; do
        [ "$(docker network inspect -f '{{.Internal}}' "$existing_net")" = true ] \
            || existing_fail "$existing_service is on $existing_net, which isn't internal"
    done
done

step "existing stack: the relay's 502 while the vault is down logs no URI or header (contract 54)"
# Caddy's error log records the request, URI and headers, for every 5xx it makes; the example's
# Caddyfile turns it off. Last, since a stopped vault leaves `ps -q` above without it; plain
# docker stop, since Compose's would stop the relay too, as a service depending on the vault.
existing_id="$(existing_stack ps -q vault)"
docker stop -t 5 "$existing_id" >/dev/null 2>&1 || existing_fail "the vault wouldn't stop"
existing_callback="/oauth/callback/smoke?code=zoeymcp-smoke-code&state=zoeymcp-smoke-state"
existing_status="$(portal localhost:8081 "$existing_callback" \
    -H "X-ZoeyMCP-Session: zoeymcp-smoke-session")"
[ "$existing_status" = "502" ] \
    || existing_fail "with the vault down, the relay answered $existing_status, not 502"
if existing_stack logs portal-relay 2>&1 | grep -e zoeymcp-smoke-code -e zoeymcp-smoke-state \
    -e zoeymcp-smoke-session -e /oauth/callback; then
    existing_fail "the relay logged the request it couldn't pass on"
fi
existing_cleanup
trap cleanup EXIT
# --- end of contract 54 -------------------------------------------------------------------------

echo "SMOKE OK"
