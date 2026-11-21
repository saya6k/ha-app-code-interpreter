# Same layout as the app image, minus the analysis libraries (fast build).
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
ARG SANDBOX_FROM=ghcr.io/home-assistant/base-debian:trixie

FROM ${SANDBOX_FROM} AS sandbox
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv \
 && mkdir -p /sandbox /run/ci

FROM ${BUILD_FROM}
# hadolint ignore=DL3018
RUN apk add --no-cache python3 bubblewrap
COPY --from=sandbox / /opt/sandbox-root/
COPY ci /opt/sandbox-root/opt/ci
COPY mcp-server /opt/mcp-server
COPY check.py /check.py
ENTRYPOINT ["python3", "/check.py"]
