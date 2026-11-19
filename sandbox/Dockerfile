# Sandbox image for code-interpreter sessions (SPEC §3.9). glibc base so every
# analysis package installs from manylinux wheels on both arches. The base
# image's /init (s6) is unused — the app sets the entrypoint at create time.
ARG BUILD_FROM=ghcr.io/home-assistant/base-debian:trixie
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv fonts-dejavu-core fonts-nanum \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv

ENV PATH=/opt/venv/bin:$PATH \
    MPLBACKEND=Agg \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements-sandbox.txt /tmp/requirements-sandbox.txt

# Heavy scientific stack first, light packages after, so a bump to a small
# package does not re-download the big layer.
RUN pip install --only-binary=:all: -c /tmp/requirements-sandbox.txt \
      numpy pandas scipy statsmodels scikit-learn pyarrow matplotlib

RUN pip install --only-binary=:all: -r /tmp/requirements-sandbox.txt \
 && rm /tmp/requirements-sandbox.txt

WORKDIR /sandbox
