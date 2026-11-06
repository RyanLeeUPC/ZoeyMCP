# ZoeyMCP image: one image for every role (vault, gateway, egress and bridge). A stdio MCP
# server's bridge runs from an image derived from this one (examples/bridge), which adds the
# server under /opt/stdio-server and nothing else.
#
# Base images are pinned by digest. Dependencies are installed from uv.lock, whose hashes uv
# verifies, and nothing is installed at runtime. Two virtual environments come from the one lock:
#   /opt/zoeymcp          the vault, the CLI and the launcher; on PATH
#   /opt/zoeymcp-gateway  the same plus the gateway extra (the MCP SDK and its dependencies)
# Python runs every .pth file in site-packages at start, so the vault's interpreter must not have
# the gateway's packages installed at all. `zoeymcp gateway` execs into the second environment.
#
#   docker build --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
#                --build-arg SOURCE_TREE="$(git rev-parse 'HEAD^{tree}')" -t zoeymcp .
#
# Reproducible (M8 design L.4): with SOURCE_DATE_EPOCH set to the commit's time and an OCI output
# with rewrite-timestamp=true, two builds of one commit give one platform manifest digest. The
# bytecode is unchecked-hash, the new accounts' last-change day is fixed, the files useradd leaves
# behind are removed, and rewrite-timestamp clamps every file's time to it, the certificate store's
# too.
#
#   docker buildx build --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
#       --build-arg SOURCE_REVISION=... --build-arg SOURCE_TREE=... \
#       --output type=oci,dest=zoeymcp-oci,tar=false,rewrite-timestamp=true .

FROM python:3.13.16-slim-trixie@sha256:cf50a4f6ac4f026458b08d5222023d700ac806410dff5e9ca8728fa44f2b850f AS base

FROM ghcr.io/astral-sh/uv:0.12.17@sha256:10787c682e4184e4f290de1171fd4703dc63de99221f10fe1c99002ce7fa9acc AS uv

FROM base AS build
ARG SOURCE_DATE_EPOCH
COPY --from=uv /uv /usr/local/bin/uv
# No UV_COMPILE_BYTECODE: with SOURCE_DATE_EPOCH set, py_compile would pick checked-hash, so the
# bytecode is compiled below, its mode named.
ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3 \
    PYTHONHASHSEED=0
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN UV_PROJECT_ENVIRONMENT=/opt/zoeymcp \
    uv sync --locked --no-dev --no-install-project \
 && UV_PROJECT_ENVIRONMENT=/opt/zoeymcp-gateway \
    uv sync --locked --no-dev --no-install-project --extra gateway
COPY src ./src
RUN UV_PROJECT_ENVIRONMENT=/opt/zoeymcp \
    uv sync --locked --no-dev --no-editable \
 && UV_PROJECT_ENVIRONMENT=/opt/zoeymcp-gateway \
    uv sync --locked --no-dev --no-editable --extra gateway
# uv leaves the project's own cache key in its dist-info (uv_cache.json, which holds a time) and
# lists it in RECORD; nothing reads either at run time, and both change from build to build.
RUN set -e; \
    for info in /opt/zoeymcp/lib/python3.13/site-packages/zoeymcp-*.dist-info \
        /opt/zoeymcp-gateway/lib/python3.13/site-packages/zoeymcp-*.dist-info; do \
        rm "$info/uv_cache.json"; \
        sed -i '/^zoeymcp-[^/]*\.dist-info\/uv_cache\.json,/d' "$info/RECORD"; \
    done
# Unchecked-hash .pyc holds no source time, and the fixed hash seed orders set constants the same
# way in every build; the image is never edited in place, so the source is never checked again.
RUN python3 -m compileall -q -f --invalidation-mode unchecked-hash \
        /opt/zoeymcp/lib /opt/zoeymcp-gateway/lib
# What a derived image compiles its toolkits against, so a toolkit's dependency can never move one
# of the gateway's (examples/derived-image).
RUN uv pip freeze --python /opt/zoeymcp-gateway/bin/python \
        > /opt/zoeymcp-gateway/zoeymcp-constraints.txt

FROM base
ARG SOURCE_DATE_EPOCH
ARG SOURCE_REVISION=unknown
ARG SOURCE_TREE=unknown
LABEL org.opencontainers.image.title="ZoeyMCP" \
      org.opencontainers.image.description="Credential vault and MCP gateway for AI agents" \
      org.opencontainers.image.source="https://github.com/RyanLeeUPC/ZoeyMCP" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.zoeymcp.source-tree="${SOURCE_TREE}"

# Debian's store still carries emSign ECC Root CA - G3, whose intermediates had compromised keys
# (GHSA-6q48-6c7w-9gw2; certifi dropped it in 2026.10.19). The vault trusts certifi alone, but a
# bridge's program reads this store, so the root goes here: the build fails if its line isn't
# there to disable, or if the root is still in the store afterwards.
RUN grep -qx 'mozilla/emSign_ECC_Root_CA_-_G3.crt' /etc/ca-certificates.conf \
 && sed -i 's|^mozilla/emSign_ECC_Root_CA_-_G3\.crt$|!&|' /etc/ca-certificates.conf \
 && update-ca-certificates --fresh >/dev/null \
 && test ! -e /etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem

# One uid per role, and 10003 for the standard tier's PID 1 once it drops root: it owns no files.
# 10005 is a hardened bridge's (examples/bridge/compose.bridge.yaml) and 10006 the egress role's
# (the hardened tier's egress-proxy profile); neither owns any file. A standard-tier bridge runs as
# 10100 plus its place in the launcher's --bridge list, which needs no user entry.
# A named volume mounted at /state or /state-gateway inherits the ownership set here. The
# directories under /run are tmpfs mounts in compose; they exist here with the same owners and
# modes for runtimes that ignore tmpfs options. The link socket's directory is group gateway and
# 0750, with no setgid bit: uvicorn makes the socket 0666, so the directory is the gate.
# For a reproducible build (M8 design L.4), each account's last password change is the base
# image's day for root rather than the build's, and what useradd leaves behind goes in the same
# RUN: the passwd-, group-, shadow- and gshadow- backups (shadow- holds the days useradd wrote)
# and the lastlog and faillog records.
RUN groupadd --gid 10001 vault \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vault \
 && groupadd --gid 10002 gateway \
 && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway \
 && groupadd --gid 10003 init \
 && useradd --uid 10003 --gid 10003 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin init \
 && groupadd --gid 10005 bridge \
 && useradd --uid 10005 --gid 10005 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin bridge \
 && groupadd --gid 10006 egress \
 && useradd --uid 10006 --gid 10006 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin egress \
 && day="$(getent shadow root | cut -d: -f3)" \
 && for user in vault gateway init bridge egress; do chage --lastday "$day" "$user"; done \
 && rm -f /etc/passwd- /etc/group- /etc/shadow- /etc/gshadow- /var/log/lastlog /var/log/faillog \
 && mkdir -p /state /state-gateway /run/zoeymcp /run/zoeymcp-link /run/zoeymcp-gateway \
 && chown 10001:10001 /state /run/zoeymcp \
 && chmod 0700 /state /run/zoeymcp \
 && chown 10002:10002 /state-gateway /run/zoeymcp-gateway \
 && chmod 0700 /state-gateway /run/zoeymcp-gateway \
 && chown 10001:10002 /run/zoeymcp-link \
 && chmod 0750 /run/zoeymcp-link

COPY --from=build /opt/zoeymcp /opt/zoeymcp
COPY --from=build /opt/zoeymcp-gateway /opt/zoeymcp-gateway

# No setuid or setgid file: without NoNewPrivs, one could hand the gateway uid privileges back.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} +

ENV PATH=/opt/zoeymcp/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
ENTRYPOINT ["zoeymcp"]
CMD ["--help"]
