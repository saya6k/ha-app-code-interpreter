# Supervisor no longer injects BUILD_FROM — default to the multi-arch base.
ARG BUILD_FROM=ghcr.io/home-assistant/base:3.23
FROM ${BUILD_FROM}

# hadolint ignore=DL3018
RUN apk add --no-cache bubblewrap python3 util-linux-misc

COPY probe.py /probe.py

# One-shot script; the base image's s6 /init is not needed.
ENTRYPOINT ["python3", "/probe.py"]
