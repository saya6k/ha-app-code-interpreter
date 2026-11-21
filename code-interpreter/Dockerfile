# BUILD_FROM is no longer injected by the Supervisor (>=2026.04.0) — default to
# the multi-arch HA base manifest, pinned to an Alpine version tag instead of
# the moving :latest. Overridable with --build-arg.
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
# Sandbox rootfs (SPEC §3.9): glibc base so every analysis package installs
# from manylinux wheels on both arches.
ARG SANDBOX_FROM=ghcr.io/home-assistant/base-debian:trixie

# ---- Sandbox rootfs ---------------------------------------------------------
# Never run as a container: the app copies this filesystem to
# /opt/sandbox-root and bubblewrap mounts it read-only as each session's /.
FROM ${SANDBOX_FROM} AS sandbox

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv fonts-dejavu-core fonts-nanum \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY sandbox/requirements-sandbox.txt /tmp/requirements-sandbox.txt

# Heavy scientific stack first, light packages after, so a bump to a small
# package does not rebuild the big layer.
RUN /opt/venv/bin/pip install --only-binary=:all: -c /tmp/requirements-sandbox.txt \
      numpy pandas scipy statsmodels scikit-learn pyarrow matplotlib

RUN /opt/venv/bin/pip install --only-binary=:all: -r /tmp/requirements-sandbox.txt \
 && rm /tmp/requirements-sandbox.txt

# Mount points: the rootfs is read-only inside bubblewrap, so bind targets
# must already exist.
RUN mkdir -p /sandbox /run/ci

# ---- App --------------------------------------------------------------------
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# The base image is labeled io.hass.type=base and build-image only stamps
# io.hass.arch/version, so without this the add-on image inherits "base".
LABEL io.hass.type="app"

# ---- MCP server (Python venv) + bubblewrap ---------------------------------
COPY rootfs/opt/mcp-server/requirements.txt /tmp/requirements.txt
RUN apk add --no-cache python3 py3-pip bubblewrap \
 && python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# ---- Sandbox rootfs ---------------------------------------------------------
COPY --from=sandbox / /opt/sandbox-root/
# Sandbox-side code (REPL, launcher) as its own small layer, so code changes
# do not re-ship the ~1 GB rootfs layer above.
COPY rootfs/opt/ci /opt/sandbox-root/opt/ci

WORKDIR /
