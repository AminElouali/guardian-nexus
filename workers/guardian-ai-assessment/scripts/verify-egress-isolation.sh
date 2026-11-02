#!/usr/bin/env sh
set -eu

IMAGE="${1:-guardian-ai-assessment:garak-gve-profile-candidate}"
if [ "$#" -gt 1 ]; then
  echo "usage: verify-egress-isolation.sh [local-worker-image]" >&2
  exit 64
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "profile_image_not_built" >&2
  exit 69
fi
PROFILE_LABEL="$(docker image inspect --format '{{index .Config.Labels "org.guardian.profile"}}' "$IMAGE")"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORKER_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"

# This audit deliberately uses Docker's network=none and never mounts host
# sockets, credentials, model files, or writable workspace paths.
set -- \
  --rm --pull=never --network=none --read-only --cpus=0.5 \
  --memory=256m --memory-swap=256m --pids-limit=32 --cap-drop=ALL \
  --security-opt=no-new-privileges --user=65532:65532 \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777
case "$PROFILE_LABEL" in
  garak-gve-v1) ;;
  qwen-gve-v1)
    set -- "$@" \
      --mount="type=bind,src=$WORKER_ROOT/guardian_ai_assessment,dst=/opt/guardian-assessment/guardian_ai_assessment,readonly"
    ;;
  *)
    echo "profile_image_label_mismatch" >&2
    exit 69
    ;;
esac
set -- "$@" --entrypoint=python "$IMAGE" -m guardian_ai_assessment.network_audit

set +e
timeout --signal=TERM --kill-after=3s 20s docker run "$@"
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
