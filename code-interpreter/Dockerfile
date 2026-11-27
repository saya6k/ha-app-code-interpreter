# BUILD_FROM is no longer injected by the Supervisor (>=2026.04.0) — default to
# the multi-arch HA base manifest, pinned to an Alpine version tag instead of
# the moving :latest. Overridable with --build-arg.
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
# Sandbox rootfs (SPEC §3.9): glibc base so every analysis package installs
# from manylinux wheels on both arches.
ARG SANDBOX_FROM=ghcr.io/home-assistant/base-debian:trixie

# ---- Node ---------------------------------------------------------------------
# Only bin/node from the official tarball, pinned by checksum. A stage of its
# own, so the download tools do not end up in the sandbox rootfs.
FROM ${SANDBOX_FROM} AS node

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl xz-utils \
 && rm -rf /var/lib/apt/lists/*

ARG NODE_VERSION=26.13.1
RUN case "$(uname -m)" in \
      aarch64) arch=arm64 sha=89e1853138db51e8b82d3e98ba9c0d3f2956a28e5e55ea1b7e12d25aae92d5dd ;; \
      x86_64) arch=x64 sha=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864 ;; \
      *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
 && echo "${sha}  /tmp/node.tar.xz" | sha256sum -c - \
 && mkdir -p /opt/node/bin \
 && tar -xJf /tmp/node.tar.xz -C /opt/node/bin --strip-components=2 "node-v${NODE_VERSION}-linux-${arch}/bin/node" \
 && tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 "node-v${NODE_VERSION}-linux-${arch}/LICENSE" \
 && rm /tmp/node.tar.xz

# ---- Sandbox rootfs ---------------------------------------------------------
# Never run as a container: the app copies this filesystem to
# /opt/sandbox-root and bubblewrap mounts it read-only as each session's /.
FROM ${SANDBOX_FROM} AS sandbox

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv fonts-dejavu-core fonts-nanum libatomic1 \
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

# The packages' own test suites (~185 MB, a fifth of the rootfs) are never
# run in a session. Removing them in a later layer still shrinks the image:
# the app stage copies this stage's filesystem, not its layers.
RUN find /opt/venv/lib -type d -name tests -prune -exec rm -rf {} +

# Node for the REPL (node stage above); no npm: nothing is installed into a session.
COPY --from=node /opt/node /opt/node

# Mount points: the rootfs is read-only inside bubblewrap, so bind targets
# must already exist.
RUN mkdir -p /sandbox /run/ci

# ---- App --------------------------------------------------------------------
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# The base image is labeled io.hass.type=base and build-image only stamps
# io.hass.arch/version, so without this the add-on image inherits "base".
LABEL io.hass.type="app"

# ---- hab (Home Assistant Builder) for ha.admin.hab() -------------------------
# A static Go binary run by the app, never inside the sandbox (it uses the
# Supervisor token). Pinned by checksum; its update check is off at run time.
ARG HAB_VERSION=1.10.0
RUN case "$(uname -m)" in \
      aarch64) arch=arm64 sha=719c61fb3b0c7a8295a61113b4730f251b3c3fa5c833c5bab64e8865e3af5b90 ;; \
      x86_64) arch=amd64 sha=2d2c0529f61f1e6bd8759f1cdf0ece153c04f51b7eee0e6def28ad6bbac8bca0 ;; \
      *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /usr/local/bin/hab \
      "https://github.com/balloob/home-assistant-build-cli/releases/download/${HAB_VERSION}/hab-linux-${arch}" \
 && echo "${sha}  /usr/local/bin/hab" | sha256sum -c - \
 && chmod 755 /usr/local/bin/hab

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

# ---- rootfs (MCP server, s6 services) ---------------------------------------
COPY rootfs /
RUN find /etc/s6-overlay/s6-rc.d -type f \( -name run -o -name finish \) -exec chmod a+x {} \; \
 && find /etc/s6-overlay/s6-rc.d -type f -name type -exec chmod 644 {} \;

WORKDIR /
