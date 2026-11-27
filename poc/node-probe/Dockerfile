# The app's layout minus the analysis libraries (fast build), plus Node.
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
ARG SANDBOX_FROM=ghcr.io/home-assistant/base-debian:trixie

FROM ${SANDBOX_FROM} AS sandbox
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates curl xz-utils libatomic1 \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv \
 && mkdir -p /sandbox /run/ci

# Only bin/node from the official tarball: no npm in the sandbox (SPEC-code-mode §3.8).
ARG NODE_VERSION=26.13.1
RUN case "$(uname -m)" in \
      aarch64) arch=arm64 sha=89e1853138db51e8b82d3e98ba9c0d3f2956a28e5e55ea1b7e12d25aae92d5dd ;; \
      x86_64) arch=x64 sha=5c063e46bab0fbc1c17cc445d7ff129cbdcd0471be6ed83b6ab864f8143bc864 ;; \
      *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${arch}.tar.xz" \
 && echo "${sha}  /tmp/node.tar.xz" | sha256sum -c - \
 && mkdir -p /opt/node/bin \
 && tar -xJf /tmp/node.tar.xz -C /tmp --strip-components=2 "node-v${NODE_VERSION}-linux-${arch}/bin/node" \
 && mv /tmp/node /opt/node/bin/node \
 && rm /tmp/node.tar.xz

FROM ${BUILD_FROM}
# hadolint ignore=DL3018
RUN apk add --no-cache python3 bubblewrap \
 && python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir mcp==1.26.0 websockets==15.0.1
COPY --from=sandbox / /opt/sandbox-root/
COPY ci /opt/sandbox-root/opt/ci
COPY js /opt/sandbox-root/opt/probe
COPY mcp-server /opt/mcp-server
COPY probe.py /probe.py
ENTRYPOINT ["/opt/venv/bin/python3", "/probe.py"]
