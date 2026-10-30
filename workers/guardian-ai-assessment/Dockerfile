FROM python:3.13-slim-bookworm

ARG GARAK_VERSION=0.17.1
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp/guardian-home \
    TMPDIR=/tmp

WORKDIR /opt/guardian-assessment

COPY requirements-runtime.txt /opt/guardian-assessment/requirements-runtime.txt

# This deliberately installs Garak without its broad optional model-provider
# stack. The local REST generator and the single pinned probe profile have a
# small, explicit dependency set and never download a model at runtime.
RUN python -m pip install --no-cache-dir --disable-pip-version-check \
      --no-deps "garak==${GARAK_VERSION}" \
    && python -m pip install --no-cache-dir --disable-pip-version-check \
      -r requirements-runtime.txt \
    && python -c "import importlib.metadata; assert importlib.metadata.version('garak') == '${GARAK_VERSION}'"

COPY . /opt/guardian-assessment
RUN chown -R 65532:65532 /opt/guardian-assessment

USER 65532:65532
ENTRYPOINT ["python", "-m", "guardian_ai_assessment"]
