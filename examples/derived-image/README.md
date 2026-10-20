# A derived image with toolkits

Toolkits run inside the gateway, so they must be installed in its environment. The official image
doesn't change: a derived image adds exactly one layer, which touches only
`/opt/zoeymcp-gateway`. The vault's environment (`/opt/zoeymcp`) and the interpreter
(`/usr/local`) stay the official layers byte for byte, and `verify.sh` proves it.

## Build

```sh
OFFICIAL=zoeymcp:local   # in production: <registry>/zoeymcp@sha256:<release digest>
examples/derived-image/lock.sh "$OFFICIAL"
docker build -f examples/derived-image/Dockerfile \
    --build-context toolkit=examples/toolkits/dist \
    --build-arg OFFICIAL="$OFFICIAL" -t zoeymcp-derived examples/derived-image
examples/derived-image/verify.sh "$OFFICIAL" zoeymcp-derived
```

`lock.sh` builds the toolkits' wheel outside any image, copies `zoeymcp-constraints.txt` (the
gateway environment's exact versions) out of the official image, compiles `requirements.in`
against it with hashes, and appends the wheel with the hash of the file it just built. So a
toolkit dependency can never move a gateway dependency, and `requirements.txt` (generated, never
committed) always matches the wheel. Put your toolkits' third-party dependencies in
`requirements.in`; the examples need only the standard library.

The build installs wheels only (no package build runs as root), refuses any new `.pth` file
(Python would run it at every gateway start, before ZoeyMCP's own checks), and leaves the
environments root-owned, so the gateway's uid can't change them. The gateway loads a toolkit only
from files it can't write, inside its environment, and only if an entry point in the
`zoeymcp.toolkits` group names its module.

## What `verify.sh` checks

1. The derived layers are the official layers, in order, plus exactly one.
2. `User`, `Entrypoint`, `Cmd`, `Env` and `WorkingDir` are unchanged.
3. The added layer touches nothing outside `/opt/zoeymcp-gateway`.
4. Every official file there is unchanged; new files sit only under `site-packages` and `bin`;
   none is a `.pth`, setuid, setgid or world-writable file.
5. The portal's static files are present in the vault's environment, byte for byte as the
   official image has them.
6. `scripts/smoke-image.sh --derived OFFICIAL DERIVED` passes on the derived image: the standard
   tier's isolation checks; the vault's environment equals the official one and can't import the
   toolkits; the gateway's holds every official distribution at its official version, and the
   added ones shadow no official module; the entry points are the expected ones; the example
   mail toolkit loads as the gateway's uid, with the origin check on, under the pin the example
   policy commits, and `zoeymcp review mail` shows that pin; and both tiers serve the portal's
   files.

Checks 3 and 4 only read files, so nothing the new layer holds runs before it is checked.

## Which tier

| Tier | Vault runs | Gateway runs |
| --- | --- | --- |
| Hardened (recommended with toolkits) | the official image, unchanged | the derived image: set `ZOEYMCP_GATEWAY_IMAGE` |
| Standard | the derived image's `/opt/zoeymcp`, which `verify.sh` proves official | the derived image's `/opt/zoeymcp-gateway` |

In the standard tier a compromised toolkit dependency runs as the gateway's uid in the vault's
container: it has the gateway's egress and routes, though not the vault's files, memory or
environment. Toolkits with third-party dependencies belong in the hardened tier.

The standard tier's launcher passes the gateway only an allowlisted environment, so a toolkit
can't read configuration from environment variables there. A toolkit's configuration is its policy
entry (slots and rules) and what the vault answers.
