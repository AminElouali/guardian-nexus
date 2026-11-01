# Isolated build-tools image only; this is never used to run an evaluation.
FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=2

RUN sed -i \
        -e 's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20261027T000000Z|' \
        -e 's|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20261027T000000Z|' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/build-tools
COPY requirements-build.txt .
COPY build-wheels/ /opt/build-wheels/

# All Python build tools are locally staged and hash-locked. No PyPI lookup.
RUN python -m pip install \
    --no-index \
    --no-deps \
    --find-links=/opt/build-wheels \
    --require-hashes \
    -r requirements-build.txt

WORKDIR /tmp/build
