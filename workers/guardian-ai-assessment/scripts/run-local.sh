#!/usr/bin/env sh
set -eu

IMAGE="guardian-ai-assessment:local"
CONTAINER_ARGS="
  --rm
  --init
  --pull=never
  --network=none
  --read-only
  --cpus=0.5
  --memory=768m
  --memory-swap=768m
  --pids-limit=64
  --cap-drop=ALL
  --security-opt=no-new-privileges
  --user=65532:65532
  --log-driver=none
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m
"

# Keep the security options fixed. Never accept caller-supplied Docker flags,
# targets, credentials, or arbitrary probes through this script.
if [ "${1:-}" = "--self-test" ]; then
  # shellcheck disable=SC2086
  exec docker run $CONTAINER_ARGS "$IMAGE" --self-test
fi

if [ "$#" -ne 0 ]; then
  echo "This runner only supports the fixed local lab profile." >&2
  exit 64
fi

# shellcheck disable=SC2086
exec docker run $CONTAINER_ARGS "$IMAGE"
