FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

ARG GARAK_VERSION=0.17.1
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/guardian-home \
    TMPDIR=/tmp

WORKDIR /opt/guardian-assessment

COPY requirements-runtime.txt /opt/guardian-assessment/requirements-runtime.txt
COPY requirements-build.txt /opt/guardian-assessment/requirements-build.txt

# These hash-locked dependencies are fetched only during image build from the
# official PyPI index. No package installation or network access occurs when the
# runtime worker executes. The sdist's build tools live in a temporary prefix.
RUN set -eu; \
    python -m pip install --no-cache-dir --disable-pip-version-check \
      --no-deps --require-hashes --only-binary=:all: \
      --index-url https://pypi.org/simple \
      --target=/tmp/guardian-build-tools -r requirements-build.txt; \
    PYTHONPATH=/tmp/guardian-build-tools python -m pip install \
      --no-cache-dir --disable-pip-version-check --no-deps \
      --require-hashes --no-build-isolation \
      --index-url https://pypi.org/simple -r requirements-runtime.txt; \
    rm -rf /tmp/guardian-build-tools; \
    python -c "import importlib.metadata as m; assert m.version('garak') == '${GARAK_VERSION}'; assert m.version('aiohttp') == '3.14.5'; assert m.version('nltk') == '3.10.4'; assert m.version('requests') == '2.34.2'; assert m.version('langdetect') == '1.0.9'; assert m.version('numpy') == '2.3.4'"

COPY . /opt/guardian-assessment
RUN chown -R 65532:65532 /opt/guardian-assessment

USER 65532:65532
ENTRYPOINT ["python", "-m", "guardian_ai_assessment"]
