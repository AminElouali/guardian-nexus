#!/usr/bin/env sh
set -eu

IMAGE="guardian-ai-assessment:garak-gve-profile-candidate"
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

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "garak_profile_image_not_built" >&2
  exit 69
fi
PROFILE_LABEL="$(docker image inspect --format '{{index .Config.Labels "org.guardian.profile"}}' "$IMAGE")"
if [ "$PROFILE_LABEL" != "garak-gve-v1" ]; then
  echo "garak_profile_image_label_mismatch" >&2
  exit 69
fi

# Keep the security options fixed. Never accept caller-supplied Docker flags,
# targets, credentials, or arbitrary probes through this script.
case "${1:-}" in
  --unit-tests)
    if [ "$#" -ne 1 ]; then
      echo "A fixed local mode accepts no extra arguments." >&2
      exit 64
    fi
    # shellcheck disable=SC2086
    exec docker run $CONTAINER_ARGS --entrypoint=python "$IMAGE" \
      -m unittest discover -s tests -v
    ;;
  --self-test|--validation-suite|--verification-suite)
    if [ "$#" -ne 1 ]; then
      echo "A fixed local mode accepts no extra arguments." >&2
      exit 64
    fi
    # shellcheck disable=SC2086
    exec docker run $CONTAINER_ARGS "$IMAGE" "$1"
    ;;
  "")
    ;;
  *)
    echo "This runner only supports fixed local lab modes." >&2
    exit 64
    ;;
esac

# shellcheck disable=SC2086
exec docker run $CONTAINER_ARGS "$IMAGE"
