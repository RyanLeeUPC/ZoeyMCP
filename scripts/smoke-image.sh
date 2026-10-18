#!/bin/sh
# Smoke-test a built image: the vault the way the hardened tier runs it (read-only, no capabilities,
# no-new-privileges, non-root), then the standard tier from deploy/compose.yaml.
# Usage: scripts/smoke-image.sh IMAGE
set -eu

image="${1:?usage: smoke-image.sh IMAGE}"
name="zoeymcp-smoke-$$"
volume="zoeymcp-smoke-state-$$"
project="zoeymcp-smoke-$$"
port=18080
examples="$(cd "$(dirname "$0")/../examples" && pwd)"
deploy="$(cd "$(dirname "$0")/../deploy" && pwd)"
hardened="--read-only --cap-drop ALL --security-opt no-new-privileges:true --tmpfs /tmp:size=16m"

# The standard tier, from deploy/compose.yaml as shipped.
standard() {
    ZOEYMCP_IMAGE="$image" ZOEYMCP_MASTER_KEY="${key:-unset}"         docker compose -p "$project" -f "$deploy/compose.yaml" "$@"
}
cleanup() {
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker volume rm "$volume" >/dev/null 2>&1 || true
    standard down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "SMOKE FAIL: $*" >&2
    docker logs "$name" >&2 2>/dev/null || true
    standard logs >&2 2>/dev/null || true
    exit 1
}

step() { echo "--- $*"; }

step "version, and the image runs as the vault's uid"
docker run --rm "$image" --version
[ "$(docker run --rm --entrypoint id "$image" -u)" = "10001" ] || fail "image doesn't run as uid 10001"
[ "$(docker run --rm --entrypoint sh "$image" -c 'command -v zoeymcp')" = "/opt/zoeymcp/bin/zoeymcp" ] \
    || fail "zoeymcp on PATH isn't the vault's environment"

# Runs one environment's interpreter in isolated mode: in_env DIR ARGS...
in_env() {
    env_dir="$1"
    shift
    docker run --rm --network none --entrypoint "$env_dir/bin/python" "$image" -I "$@"
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

step "two environments: the vault's has none of the gateway's packages"
vault_dists="$(in_env /opt/zoeymcp -c "$distributions")"
gateway_dists="$(in_env /opt/zoeymcp-gateway -c "$distributions")"
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

step "standard tier: up, from deploy/compose.yaml"
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
standard stop -t 60 zoeymcp
[ "$(docker inspect -f '{{.State.ExitCode}}' "$std")" = "0" ] || fail "the launcher exited non-zero"
for child in vault gateway; do
    standard logs zoeymcp | grep -q "\"event\":\"child_exited\",\"child\":\"$child\",\"status\":0" \
        || fail "the $child didn't stop cleanly"
done

echo "SMOKE OK"
