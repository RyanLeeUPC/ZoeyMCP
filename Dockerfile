# ZoeyMCP image: one image for every role (vault, gateway and egress now; bridge later).
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

FROM python:3.13.15-slim-trixie@sha256:7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b AS base

FROM ghcr.io/astral-sh/uv:0.12.17@sha256:10787c682e4184e4f290de1171fd4703dc63de99221f10fe1c99002ce7fa9acc AS uv

FROM base AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3
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
# What a derived image compiles its toolkits against, so a toolkit's dependency can never move one
# of the gateway's (examples/derived-image).
RUN uv pip freeze --python /opt/zoeymcp-gateway/bin/python \
        > /opt/zoeymcp-gateway/zoeymcp-constraints.txt

FROM base
ARG SOURCE_REVISION=unknown
ARG SOURCE_TREE=unknown
LABEL org.opencontainers.image.title="ZoeyMCP" \
      org.opencontainers.image.description="Credential vault and MCP gateway for AI agents" \
      org.opencontainers.image.source="https://github.com/RyanLeeUPC/ZoeyMCP" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.zoeymcp.source-tree="${SOURCE_TREE}"

# One uid per role, and 10003 for the standard tier's PID 1 once it drops root: it owns no files.
# 10006 is the egress role's (the hardened tier's egress-proxy profile); it owns no files either.
# A named volume mounted at /state or /state-gateway inherits the ownership set here. The
# directories under /run are tmpfs mounts in compose; they exist here with the same owners and
# modes for runtimes that ignore tmpfs options. The link socket's directory is group gateway and
# 0750, with no setgid bit: uvicorn makes the socket 0666, so the directory is the gate.
RUN groupadd --gid 10001 vault \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vault \
 && groupadd --gid 10002 gateway \
 && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway \
 && groupadd --gid 10003 init \
 && useradd --uid 10003 --gid 10003 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin init \
 && groupadd --gid 10006 egress \
 && useradd --uid 10006 --gid 10006 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin egress \
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
