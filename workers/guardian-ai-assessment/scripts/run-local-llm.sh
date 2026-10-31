#!/usr/bin/env sh
set -eu

if [ "$#" -ne 0 ]; then
  echo "This fixed local runner accepts no custom arguments." >&2
  exit 64
fi

WORKER_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$WORKER_ROOT/../.." && pwd)"
ARTIFACT_ROOT="$REPO_ROOT/generated-artifacts/guardian-llm-lab"
MODEL="$ARTIFACT_ROOT/Qwen3-0.6B-Q8_0.gguf"
WHEELHOUSE="$ARTIFACT_ROOT/wheelhouse"
MANIFEST="$WORKER_ROOT/local-llm-manifest.json"
IMAGE="guardian-ai-assessment:local"
OUTPUT="$ARTIFACT_ROOT/evidence.json"
TEMP_OUTPUT="$ARTIFACT_ROOT/evidence.json.tmp"

python3 - "$MANIFEST" "$MODEL" "$WHEELHOUSE" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
model_path = pathlib.Path(sys.argv[2])
wheelhouse = pathlib.Path(sys.argv[3])
model = manifest["model"]
if not model_path.is_file() or model_path.stat().st_size != model["sizeBytes"]:
    raise SystemExit("local_model_artifact_missing_or_wrong_size")

def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

if digest(model_path) != model["sha256"]:
    raise SystemExit("local_model_artifact_hash_mismatch")
runtime = manifest["runtime"]
expected = {
    runtime["wheel"]: runtime["wheelSha256"],
    **{dep["wheel"]: dep["sha256"] for dep in runtime["dependencies"] if "wheel" in dep},
}
for filename, expected_hash in expected.items():
    wheel = wheelhouse / filename
    if not wheel.is_file() or digest(wheel) != expected_hash:
        raise SystemExit(f"runtime_wheel_missing_or_hash_mismatch:{filename}")
PY

docker image inspect "$IMAGE" >/dev/null
mkdir -p "$ARTIFACT_ROOT"
rm -f "$TEMP_OUTPUT"

set +e
timeout --signal=TERM --kill-after=10s 180s docker run \
  --rm \
  --init \
  --pull=never \
  --network=none \
  --read-only \
  --cpus=1 \
  --memory=1536m \
  --memory-swap=1536m \
  --pids-limit=64 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user=65532:65532 \
  --log-driver=none \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777 \
  --tmpfs=/opt/llm-runtime:rw,exec,nosuid,nodev,size=128m,mode=1777 \
  --mount="type=bind,src=$MODEL,dst=/models/Qwen3-0.6B-Q8_0.gguf,readonly" \
  --mount="type=bind,src=$WHEELHOUSE,dst=/wheelhouse,readonly" \
  --mount="type=bind,src=$MANIFEST,dst=/opt/guardian-assessment/local-llm-manifest.json,readonly" \
  --mount="type=bind,src=$WORKER_ROOT/guardian_ai_assessment,dst=/opt/guardian-assessment/guardian_ai_assessment,readonly" \
  --workdir=/opt/guardian-assessment \
  --entrypoint=/bin/sh \
  "$IMAGE" \
  -ceu 'python -m pip install --no-index --no-deps --disable-pip-version-check --no-cache-dir --target=/opt/llm-runtime /wheelhouse/*.whl >&2
        export PYTHONPATH=/opt/llm-runtime:/opt/guardian-assessment
        exec python -m guardian_ai_assessment.llm_lab' \
  >"$TEMP_OUTPUT"
STATUS=$?
set -e

if [ "$STATUS" -ne 0 ]; then
  rm -f "$TEMP_OUTPUT"
  echo "local_llm_container_failed:$STATUS" >&2
  exit "$STATUS"
fi
python3 -m json.tool "$TEMP_OUTPUT" >/dev/null
mv "$TEMP_OUTPUT" "$OUTPUT"
printf 'Real local LLM evidence written to %s\n' "$OUTPUT"
