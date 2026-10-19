# syntax=docker/dockerfile:1
# A derived ZoeyMCP image: the official image plus one layer that changes only
# /opt/zoeymcp-gateway, the gateway's environment, by installing toolkits into it.
#
#   examples/derived-image/lock.sh OFFICIAL
#   docker build -f examples/derived-image/Dockerfile \
#       --build-context toolkit=examples/toolkits/dist \
#       --build-arg OFFICIAL=OFFICIAL -t zoeymcp-derived examples/derived-image
#   examples/derived-image/verify.sh OFFICIAL zoeymcp-derived
#
# In production OFFICIAL is the release by digest: <registry>/zoeymcp@sha256:<digest>.
ARG OFFICIAL=zoeymcp:local

FROM ghcr.io/astral-sh/uv:0.12.17@sha256:10787c682e4184e4f290de1171fd4703dc63de99221f10fe1c99002ce7fa9acc AS uv

FROM ${OFFICIAL} AS install
USER 0:0
COPY --from=uv /uv /usr/local/bin/uv
# requirements.txt comes from lock.sh: every dependency and the toolkit's own wheel, each hashed.
COPY requirements.txt /build/requirements.txt
COPY --from=toolkit . /build/dist/
# Wheels only, so no package build runs as root; no new .pth file, since Python would run it at
# every gateway start, before ZoeyMCP's own checks; no setuid or setgid file.
RUN uv pip install --python /opt/zoeymcp-gateway/bin/python --no-deps --require-hashes \
        --only-binary :all: --no-cache -r /build/requirements.txt \
 && test -z "$(find /opt/zoeymcp-gateway -name '*.pth' ! -name '_virtualenv.pth')" \
 && find /opt/zoeymcp-gateway -xdev -perm /6000 -type f -exec chmod a-s {} +

FROM ${OFFICIAL}
ARG OFFICIAL
COPY --from=install /opt/zoeymcp-gateway /opt/zoeymcp-gateway
LABEL org.zoeymcp.derived-from="${OFFICIAL}"
