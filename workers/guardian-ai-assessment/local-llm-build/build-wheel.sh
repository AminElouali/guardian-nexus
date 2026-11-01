#!/usr/bin/env sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)"
SOURCE="$ROOT/generated-artifacts/guardian-ai-assessment-source-audit/llama_cpp_python-0.3.36.tar.gz"
PATCH="$ROOT/workers/guardian-ai-assessment/local-llm-build/optional-diskcache.patch"
OUT="$ROOT/generated-artifacts/guardian-llm-lab/patched-wheelhouse"
BUILDER_IMAGE="guardian-llama-source-builder:0.3.36"
SOURCE_SHA256="832db0699007f1be95a7e41ef12e88926b02ba836461e36a36372db2760c1a2e"

if [ ! -f "$SOURCE" ] || [ ! -f "$PATCH" ]; then
  echo "verified_sdist_or_patch_missing" >&2
  exit 2
fi
printf '%s  %s\n' "$SOURCE_SHA256" "$SOURCE" | sha256sum -c - >/dev/null
docker image inspect "$BUILDER_IMAGE" >/dev/null
mkdir -p "$OUT"

# The build image and all inputs are local; this process has no network.
docker run --rm --pull=never --network=none --read-only \
  --cpus=2 --memory=3072m --memory-swap=3072m --pids-limit=128 \
  --cap-drop=ALL --security-opt=no-new-privileges \
  --user="$(id -u):$(id -g)" \
  --tmpfs=/tmp:rw,exec,nosuid,nodev,size=2048m,mode=1777 \
  --mount="type=bind,src=$SOURCE,dst=/input/source.tar.gz,readonly" \
  --mount="type=bind,src=$PATCH,dst=/input/optional-diskcache.patch,readonly" \
  --mount="type=bind,src=$OUT,dst=/out" \
  --entrypoint=sh "$BUILDER_IMAGE" -ceu '
    mkdir -p /tmp/source /tmp/home
    tar -xzf /input/source.tar.gz -C /tmp/source
    cd /tmp/source/llama_cpp_python-0.3.36
    patch --batch --fuzz=0 -p1 < /input/optional-diskcache.patch
    ! grep -q "diskcache>=5.6.1" pyproject.toml
    ! grep -q "^import diskcache$" llama_cpp/llama_cache.py
    CMAKE_ARGS="-DGGML_NATIVE=OFF -DGGML_AVX=ON -DGGML_AVX2=ON -DGGML_FMA=ON -DGGML_AVX512=OFF -DGGML_OPENMP=OFF" \
    CMAKE_BUILD_PARALLEL_LEVEL=2 TMPDIR=/tmp HOME=/tmp/home \
      python3 -m pip wheel --no-deps --no-build-isolation --no-cache-dir --wheel-dir=/out .
  '

python3 - "$OUT" <<'PY'
import hashlib
import pathlib
import sys
import zipfile

wheelhouse = pathlib.Path(sys.argv[1])
wheels = list(wheelhouse.glob("llama_cpp_python-0.3.36-*.whl"))
if len(wheels) != 1:
    raise SystemExit("expected_exactly_one_patched_llama_cpp_python_wheel")
wheel = wheels[0]
with zipfile.ZipFile(wheel) as archive:
    metadata_name = next(
        name for name in archive.namelist()
        if name.endswith(".dist-info/METADATA")
    )
    metadata = archive.read(metadata_name).decode("utf-8")
    if any(line.lower().startswith("requires-dist: diskcache") for line in metadata.splitlines()):
        raise SystemExit("diskcache_dependency_still_declared")
    source = archive.read("llama_cpp/llama_cache.py").decode("utf-8")
    if "\nimport diskcache\n" in source:
        raise SystemExit("diskcache_still_imported_at_module_load")
print(f"{wheel.name} {wheel.stat().st_size} {hashlib.sha256(wheel.read_bytes()).hexdigest()}")
PY
