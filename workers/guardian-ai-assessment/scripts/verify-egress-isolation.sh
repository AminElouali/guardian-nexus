#!/usr/bin/env sh
set -eu

IMAGE="${1:-guardian-ai-assessment:local}"
if [ "$#" -gt 1 ]; then
  echo "usage: verify-egress-isolation.sh [local-worker-image]" >&2
  exit 64
fi
docker image inspect "$IMAGE" >/dev/null

# This audit deliberately uses Docker's network=none and never mounts host
# sockets, credentials, model files, or writable workspace paths.
set +e
timeout --signal=TERM --kill-after=3s 20s docker run \
  --rm \
  --pull=never \
  --network=none \
  --read-only \
  --cpus=0.5 \
  --memory=256m \
  --memory-swap=256m \
  --pids-limit=32 \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user=65532:65532 \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 \
  --entrypoint=python \
  "$IMAGE" \
  -m guardian_ai_assessment.network_audit
status=$?
set -e

case "$status" in
  0) exit 0 ;;
  2)
    echo "IPv6 protocol unavailable; egress isolation is incomplete, not passed." >&2
    exit 2
    ;;
  *)
    echo "Egress isolation audit failed with status $status." >&2
    exit "$status"
    ;;
esac
