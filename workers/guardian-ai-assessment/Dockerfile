FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb

ARG GARAK_VERSION=0.17.1
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/guardian-home \
    TMPDIR=/tmp

WORKDIR /opt/guardian-assessment

COPY requirements-runtime.txt /opt/guardian-assessment/requirements-runtime.txt

# This lock deliberately excludes Garak's broad optional model-provider stack.
# It pins the minimal local REST generator and fixed probe dependencies, all
# installed without resolving or downloading transitive dependencies at build
# time. Runtime execution never installs packages or downloads a model.
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      --no-deps -r requirements-runtime.txt \
    && python -c "import importlib.metadata as m; assert m.version('garak') == '${GARAK_VERSION}'; assert m.version('aiohttp') == '3.14.5'; assert m.version('nltk') == '3.10.4'; assert m.version('requests') == '2.34.2'"

COPY . /opt/guardian-assessment
RUN chown -R 65532:65532 /opt/guardian-assessment

USER 65532:65532
ENTRYPOINT ["python", "-m", "guardian_ai_assessment"]
