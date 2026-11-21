# Same stack as sandbox/Dockerfile (glibc, manylinux wheels) plus bubblewrap.
ARG BUILD_FROM=ghcr.io/home-assistant/base-debian:trixie
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv bubblewrap fonts-dejavu-core fonts-nanum \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/venv

COPY requirements-sandbox.txt /tmp/requirements-sandbox.txt
RUN /opt/venv/bin/pip install --no-cache-dir --only-binary=:all: \
      -r /tmp/requirements-sandbox.txt \
 && rm /tmp/requirements-sandbox.txt

COPY probe.py /probe.py

ENTRYPOINT ["/opt/venv/bin/python3", "/probe.py"]
