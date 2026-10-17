# ZoeyMCP image: one image for every role (vault now; gateway, bridge and egress later).
#
# Base images are pinned by digest. Dependencies are installed from uv.lock, whose hashes uv
# verifies, and nothing is installed at runtime.
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
    UV_PYTHON=/usr/local/bin/python3 \
    UV_PROJECT_ENVIRONMENT=/opt/zoeymcp
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM base
ARG SOURCE_REVISION=unknown
ARG SOURCE_TREE=unknown
LABEL org.opencontainers.image.title="ZoeyMCP" \
      org.opencontainers.image.description="Credential vault and MCP gateway for AI agents" \
      org.opencontainers.image.source="https://github.com/RyanLeeUPC/ZoeyMCP" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      io.zoeymcp.source-tree="${SOURCE_TREE}"

# One uid per role. /state and /run/zoeymcp belong to the vault; a named volume mounted at
# /state inherits this ownership. (The gateway gets its own state path in M3.)
RUN groupadd --gid 10001 vault \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin vault \
 && groupadd --gid 10002 gateway \
 && useradd --uid 10002 --gid 10002 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin gateway \
 && mkdir -p /state /run/zoeymcp \
 && chown 10001:10001 /state /run/zoeymcp \
 && chmod 0700 /state /run/zoeymcp

COPY --from=build /opt/zoeymcp /opt/zoeymcp
ENV PATH=/opt/zoeymcp/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER 10001:10001
ENTRYPOINT ["zoeymcp"]
CMD ["--help"]
