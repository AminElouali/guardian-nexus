FROM python:3.13-slim-bookworm@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f

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
    && python -c "import importlib.metadata; assert importlib.metadata.version('garak') == '${GARAK_VERSION}'"

COPY . /opt/guardian-assessment
RUN chown -R 65532:65532 /opt/guardian-assessment

USER 65532:65532
ENTRYPOINT ["python", "-m", "guardian_ai_assessment"]
