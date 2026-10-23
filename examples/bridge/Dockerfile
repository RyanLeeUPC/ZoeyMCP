# syntax=docker/dockerfile:1
# A derived ZoeyMCP image for one stdio MCP server behind a bridge (M7 design C.7): the official
# image plus one layer that adds only /opt/stdio-server, the server's own environment.
#
#   examples/bridge/lock.sh
#   docker build -f examples/bridge/Dockerfile \
#       --build-context server=examples/bridge/server/dist \
#       --build-arg OFFICIAL=OFFICIAL -t zoeymcp-bridge-fetch examples/bridge
#   examples/bridge/verify.sh --bridge OFFICIAL zoeymcp-bridge-fetch
#
# In production OFFICIAL is the release by digest: <registry>/zoeymcp@sha256:<digest>. The same
# image serves the hardened tier's bridge container (compose.bridge.yaml) and the whole standard
# container (compose.standard.yaml), where it must pass verify.sh --bridge: the vault runs from it.
#
# A Node server (not built here): in the install stage, `npm ci --ignore-scripts` from a committed
# package-lock.json with integrity hashes and NPM_CONFIG_UPDATE_NOTIFIER=false set in that stage
# only, so the final Env is unchanged; the final stage copies a pinned Node runtime, taken from a
# Node base by digest, into /opt/node, the one other prefix verify.sh --bridge --node allows.
ARG OFFICIAL=zoeymcp:local

FROM ghcr.io/astral-sh/uv:0.12.17@sha256:10787c682e4184e4f290de1171fd4703dc63de99221f10fe1c99002ce7fa9acc AS uv

FROM ${OFFICIAL} AS install
USER 0:0
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_PYTHON_DOWNLOADS=never
# requirements.lock comes from lock.sh: the server's wheel, and any dependency, each hashed.
COPY requirements.lock /build/requirements.lock
COPY --from=server . /build/dist/
# Wheels only, so no package build runs as root (a server published only as an sdist is built
# into a wheel elsewhere and locked by hash); its own environment, never /opt/zoeymcp or
# /opt/zoeymcp-gateway; no setuid or setgid file, and nothing others can write.
RUN uv venv --python /usr/local/bin/python3 --no-cache /opt/stdio-server/venv \
 && uv pip install --python /opt/stdio-server/venv/bin/python --no-deps --require-hashes \
        --only-binary :all: --no-cache -r /build/requirements.lock \
 && find /opt/stdio-server -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && chmod -R go-w /opt/stdio-server

FROM ${OFFICIAL}
ARG OFFICIAL
COPY --from=install /opt/stdio-server /opt/stdio-server
LABEL org.zoeymcp.derived-from="${OFFICIAL}" \
      io.zoeymcp.bridge.command="/opt/stdio-server/venv/bin/fetch-server"
