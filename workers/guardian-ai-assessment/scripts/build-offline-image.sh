#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../../.." && pwd)"
WHEELHOUSE="$ROOT_DIR/generated-artifacts/guardian-ai-assessment-wheelhouse"
OUTPUT_DIR="$ROOT_DIR/generated-artifacts/guardian-ai-assessment-offline"
BASE_IMAGE="python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb"
IMAGE="guardian-ai-assessment:offline-rebuilt"

mkdir -p "$OUTPUT_DIR"
python3 "$SCRIPT_DIR/verify_wheelhouse.py" \
  --wheelhouse "$WHEELHOUSE" \
  --requirements "$WORKER_DIR/requirements-runtime.txt" \
  --requirements "$WORKER_DIR/requirements-build.txt" \
  > "$OUTPUT_DIR/wheelhouse-manifest.json"
sha256sum "$OUTPUT_DIR/wheelhouse-manifest.json" \
  > "$OUTPUT_DIR/wheelhouse-manifest.sha256"

# Refuse to pull the base image. A local image matching the pinned digest must
# already exist before the build context is assembled.
docker image inspect "$BASE_IMAGE" >/dev/null
context="$(mktemp -d "$OUTPUT_DIR/build-context.XXXXXX")"
cleanup() {
  rm -rf -- "$context"
}
trap cleanup EXIT
mkdir -p "$context/source" "$context/wheelhouse"
tar -C "$WORKER_DIR" \
  --exclude='./__pycache__' \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='./local-llm-build' \
  --exclude='./MVP_CHECKPOINT.md' \
  --exclude='./DEPENDENCY_AUDIT.md' \
  -cf - . | tar -C "$context/source" -xf -
cp -a "$WHEELHOUSE"/. "$context/wheelhouse"/
cp "$WORKER_DIR/Dockerfile.offline" "$context/Dockerfile"

DOCKER_BUILDKIT=1 docker build \
  --no-cache \
  --pull=false \
  --network=none \
  --file "$context/Dockerfile" \
  --tag "$IMAGE" \
  "$context"

image_id="$(docker image inspect "$IMAGE" --format '{{.Id}}')"
printf '%s\n' "$image_id" > "$OUTPUT_DIR/image-id.txt"
docker image inspect "$IMAGE" > "$OUTPUT_DIR/image-inspect.json"

docker run --rm \
  --pull=never \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user=65532:65532 \
  --entrypoint=python \
  "$IMAGE" \
  /opt/guardian-assessment/scripts/generate_container_sbom.py \
  --image-name "$IMAGE" \
  --image-id "$image_id" \
  --base-image "$BASE_IMAGE" \
  > "$OUTPUT_DIR/sbom.cdx.json"

sha256sum "$OUTPUT_DIR/sbom.cdx.json" > "$OUTPUT_DIR/sbom.cdx.sha256"
printf 'Built %s (%s) with --no-cache --pull=false --network=none\n' "$IMAGE" "$image_id"
printf 'Wheelhouse manifest: %s\nSBOM: %s\n' \
  "$OUTPUT_DIR/wheelhouse-manifest.json" "$OUTPUT_DIR/sbom.cdx.json"
