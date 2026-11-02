#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKER_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd -- "$WORKER_DIR/../.." && pwd)"
FULL_WHEELHOUSE="$ROOT_DIR/generated-artifacts/guardian-ai-assessment-wheelhouse"
OUTPUT_DIR="$ROOT_DIR/generated-artifacts/guardian-ai-assessment-offline/profile-segregation-20261102"
BASE_IMAGE="python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb"
GARAK_IMAGE="guardian-ai-assessment:garak-gve-profile-candidate"
QWEN_IMAGE="guardian-ai-assessment:qwen-gve-profile-candidate"

mkdir -p "$OUTPUT_DIR"
docker image inspect "$BASE_IMAGE" >/dev/null

python3 "$SCRIPT_DIR/verify_wheelhouse.py" \
  --wheelhouse "$FULL_WHEELHOUSE" \
  --requirements "$WORKER_DIR/requirements-runtime.txt" \
  --requirements "$WORKER_DIR/requirements-build.txt" \
  > "$OUTPUT_DIR/garak-wheelhouse-manifest.json"
sha256sum "$OUTPUT_DIR/garak-wheelhouse-manifest.json" \
  > "$OUTPUT_DIR/garak-wheelhouse-manifest.sha256"

context="$(mktemp -d "$OUTPUT_DIR/build-context.XXXXXX")"
cleanup() {
  rm -rf -- "$context"
}
trap cleanup EXIT
mkdir -p "$context/garak/source" "$context/garak/wheelhouse"
mkdir -p "$context/qwen/source/guardian_ai_assessment" \
  "$context/qwen/source/scripts" "$context/qwen/wheelhouse"

tar -C "$WORKER_DIR" \
  --exclude='./__pycache__' \
  --exclude='*/__pycache__' \
  --exclude='*.pyc' \
  --exclude='./local-llm-build' \
  --exclude='./MVP_CHECKPOINT.md' \
  --exclude='./DEPENDENCY_AUDIT.md' \
  -cf - . | tar -C "$context/garak/source" -xf -
cp -a "$FULL_WHEELHOUSE"/. "$context/garak/wheelhouse"/
cp "$WORKER_DIR/Dockerfile.offline" "$context/garak/Dockerfile"

for file in __init__.py llm_lab.py tool_adapter.py; do
  cp "$WORKER_DIR/guardian_ai_assessment/$file" \
    "$context/qwen/source/guardian_ai_assessment/$file"
done
cp "$WORKER_DIR/local-llm-manifest.json" "$context/qwen/source/"
cp "$WORKER_DIR/scripts/generate_container_sbom.py" \
  "$context/qwen/source/scripts/"
cp "$WORKER_DIR/requirements-qwen-runtime.txt" "$context/qwen/"
cp "$WORKER_DIR/Dockerfile.qwen.offline" "$context/qwen/Dockerfile"

python3 - "$FULL_WHEELHOUSE" "$WORKER_DIR/requirements-qwen-runtime.txt" \
  "$context/qwen/wheelhouse" "$SCRIPT_DIR/verify_wheelhouse.py" <<'PY'
import importlib.util
import shutil
import sys
from pathlib import Path

wheelhouse, lockfile, destination, verifier = map(Path, sys.argv[1:])
spec = importlib.util.spec_from_file_location("guardian_wheel_verifier", verifier)
if spec is None or spec.loader is None:
    raise SystemExit("wheel_verifier_unavailable")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for requirement in module.parse_lockfiles([lockfile]):
    matches = [
        path
        for path in wheelhouse.iterdir()
        if path.is_file() and module.sha256_file(path) == requirement["sha256"]
    ]
    if len(matches) != 1:
        raise SystemExit(f"locked_wheel_not_unique:{requirement['name']}")
    shutil.copy2(matches[0], destination / matches[0].name)
PY

python3 "$SCRIPT_DIR/verify_wheelhouse.py" \
  --wheelhouse "$context/qwen/wheelhouse" \
  --requirements "$WORKER_DIR/requirements-qwen-runtime.txt" \
  > "$OUTPUT_DIR/qwen-image-wheelhouse-manifest.json"
sha256sum "$OUTPUT_DIR/qwen-image-wheelhouse-manifest.json" \
  > "$OUTPUT_DIR/qwen-image-wheelhouse-manifest.sha256"

if ! DOCKER_BUILDKIT=1 docker build --no-cache --pull=false --network=none \
  --file "$context/garak/Dockerfile" --tag "$GARAK_IMAGE" "$context/garak" \
  > "$OUTPUT_DIR/garak-build.log" 2>&1; then
  echo "garak_build_failed" >&2
  tail -n 80 "$OUTPUT_DIR/garak-build.log" >&2
  exit 1
fi

if ! DOCKER_BUILDKIT=1 docker build --no-cache --pull=false --network=none \
  --file "$context/qwen/Dockerfile" --tag "$QWEN_IMAGE" "$context/qwen" \
  > "$OUTPUT_DIR/qwen-build.log" 2>&1; then
  echo "qwen_build_failed" >&2
  tail -n 80 "$OUTPUT_DIR/qwen-build.log" >&2
  exit 1
fi

for image in "$GARAK_IMAGE" "$QWEN_IMAGE"; do
  docker image inspect "$image" > "$OUTPUT_DIR/$(basename "$image").inspect.json"
done

garak_id="$(docker image inspect "$GARAK_IMAGE" --format '{{.Id}}')"
qwen_id="$(docker image inspect "$QWEN_IMAGE" --format '{{.Id}}')"
docker run --rm --pull=never --network=none --read-only --cpus=0.5 \
  --memory=512m --memory-swap=512m --pids-limit=64 --cap-drop=ALL \
  --security-opt=no-new-privileges --user=65532:65532 --log-driver=none \
  --entrypoint=python "$GARAK_IMAGE" -c \
  "import importlib.util as u, importlib.metadata as m; assert m.version('garak') == '0.17.1'; assert m.version('langdetect') == '1.0.9'; assert all(u.find_spec(x) is None for x in ('llama_cpp',))" \
  > "$OUTPUT_DIR/garak-profile-smoke.log" 2>&1
docker run --rm --pull=never --network=none --read-only --cpus=0.5 \
  --memory=512m --memory-swap=512m --pids-limit=64 --cap-drop=ALL \
  --security-opt=no-new-privileges --user=65532:65532 --log-driver=none \
  --entrypoint=python "$QWEN_IMAGE" -c \
  "import importlib.util as u, importlib.metadata as m; assert m.version('numpy') == '2.3.4'; assert m.version('typing_extensions') == '4.16.0'; assert all(u.find_spec(x) is None for x in ('garak','langdetect','nltk','llama_cpp'))" \
  > "$OUTPUT_DIR/qwen-profile-smoke.log" 2>&1

for image_info in \
  "$GARAK_IMAGE|$garak_id|garak-gve-v1" \
  "$QWEN_IMAGE|$qwen_id|qwen-gve-v1"; do
  image="${image_info%%|*}"
  remainder="${image_info#*|}"
  image_id="${remainder%%|*}"
  expected_label="${remainder#*|}"
  short="$(basename "$image")"
  label="$(docker image inspect --format '{{index .Config.Labels "org.guardian.profile"}}' "$image")"
  [[ "$label" == "$expected_label" ]] || {
    echo "profile_image_label_mismatch:$short:$label:$expected_label" >&2
    exit 1
  }
  docker run --rm --pull=never --network=none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --user=65532:65532 --log-driver=none \
    --entrypoint=python "$image" \
    /opt/guardian-assessment/scripts/generate_container_sbom.py \
    --image-name "$image" --image-id "$image_id" --base-image "$BASE_IMAGE" \
    > "$OUTPUT_DIR/$short.sbom.cdx.json"
  sha256sum "$OUTPUT_DIR/$short.sbom.cdx.json" \
    > "$OUTPUT_DIR/$short.sbom.cdx.sha256"
done

printf 'Garak/GVE candidate: %s %s\n' "$GARAK_IMAGE" "$garak_id"
printf 'Qwen/GVE candidate: %s %s\n' "$QWEN_IMAGE" "$qwen_id"
printf 'Offline wheelhouse manifests and CycloneDX SBOMs: %s\n' "$OUTPUT_DIR"
