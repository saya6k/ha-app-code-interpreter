# BUILD_FROM is no longer injected by the Supervisor (>=2026.04.0) — default to
# the multi-arch HA base manifest, pinned to an Alpine version tag instead of
# the moving :latest. Overridable with --build-arg.
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# The base image is labeled io.hass.type=base and build-image only stamps
# io.hass.arch/version, so without this the add-on image inherits "base".
LABEL io.hass.type="app"

# ---- MCP server (Python venv) ---------------------------------------------
COPY rootfs/opt/mcp-server/requirements.txt /tmp/requirements.txt
RUN apk add --no-cache python3 py3-pip \
 && python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

WORKDIR /
