#!/usr/bin/env bash
# Plan-only by default. This script is for a dedicated, authorized Ubuntu 24.04
# VM; it must never be run on the Replit workspace or a shared/production host.
set -Eeuo pipefail

MODE="${1:---plan}"
CONFIRMATION="${GUARDIAN_LAB_CONFIRM_DEDICATED_HOST:-}"
EXPECTED_CONFIRMATION="Ubuntu-24.04-dedicated-lab"
DROPIN_DIR="/etc/systemd/system/docker.socket.d"
DROPIN_PATH="${DROPIN_DIR}/99-guardian-nexus-lab.conf"
SOCKET_PATH="/run/docker.sock"

fail() {
  printf 'guardian_lab_provision_blocked:%s\n' "$1" >&2
  exit 1
}

check_target() {
  [[ -r /etc/os-release ]] || fail "os_release_unavailable"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] || fail "ubuntu_24_04_required"
  command -v systemd-detect-virt >/dev/null 2>&1 || fail "systemd_detect_virt_unavailable"
  if systemd-detect-virt --container >/dev/null 2>&1; then
    fail "container_host_not_supported"
  fi
  command -v systemctl >/dev/null 2>&1 || fail "systemd_required"
}

check_apply_authorization() {
  [[ "${EUID}" -eq 0 ]] || fail "root_required_for_apply"
  [[ "$CONFIRMATION" == "$EXPECTED_CONFIRMATION" ]] || fail "dedicated_host_confirmation_required"
  check_target
  command -v docker >/dev/null 2>&1 || fail "docker_cli_required"
  command -v runuser >/dev/null 2>&1 || fail "runuser_required"
  systemctl cat docker.socket >/dev/null 2>&1 || fail "docker_socket_unit_unavailable"
  local running
  running="$(docker ps -q 2>/dev/null)" || fail "docker_daemon_unavailable"
  [[ -z "$running" ]] || fail "running_containers_found"
}

ensure_group() {
  local group_name="$1"
  getent group "$group_name" >/dev/null 2>&1 || groupadd --system "$group_name"
}

ensure_user() {
  local user_name="$1"
  if ! getent passwd "$user_name" >/dev/null 2>&1; then
    useradd --system --user-group --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin "$user_name"
  fi
  local shell
  shell="$(getent passwd "$user_name" | cut -d: -f7)"
  [[ "$shell" == "/usr/sbin/nologin" ]] || fail "service_user_shell_unexpected"
}

check_role_memberships() {
  local api_groups worker_groups broker_groups
  api_groups="$(id -nG guardian-api)"
  worker_groups="$(id -nG guardian-worker)"
  broker_groups="$(id -nG guardian-broker)"
  [[ " $api_groups " != *" docker "* && " $api_groups " != *" guardian-docker-broker "* ]] \
    || fail "api_has_docker_authority"
  [[ " $worker_groups " != *" docker "* && " $worker_groups " != *" guardian-docker-broker "* ]] \
    || fail "worker_has_docker_authority"
  [[ " $broker_groups " == *" guardian-docker-broker "* ]] || fail "broker_socket_group_missing"
  [[ " $api_groups " == *" guardian-broker-clients "* ]] || fail "api_broker_client_group_missing"
  [[ " $broker_groups " == *" guardian-broker-clients "* ]] || fail "broker_client_group_missing"
  [[ " $worker_groups " != *" guardian-broker-clients "* ]] || fail "worker_broker_client_group_present"
  [[ "$(id -u guardian-api)" != "$(id -u guardian-worker)" ]] || fail "api_worker_uid_not_distinct"
  [[ "$(id -u guardian-api)" != "$(id -u guardian-broker)" ]] || fail "api_broker_uid_not_distinct"
  [[ "$(id -u guardian-worker)" != "$(id -u guardian-broker)" ]] || fail "worker_broker_uid_not_distinct"
  [[ "$(id -g guardian-api)" != "$(id -g guardian-worker)" ]] || fail "api_worker_gid_not_distinct"
  [[ "$(id -g guardian-api)" != "$(id -g guardian-broker)" ]] || fail "api_broker_gid_not_distinct"
  [[ "$(id -g guardian-worker)" != "$(id -g guardian-broker)" ]] || fail "worker_broker_gid_not_distinct"
  [[ "$(id -gn guardian-api)" == "guardian-api" ]] || fail "api_primary_group_mismatch"
  [[ "$(id -gn guardian-worker)" == "guardian-worker" ]] || fail "worker_primary_group_mismatch"
  [[ "$(id -gn guardian-broker)" == "guardian-broker" ]] || fail "broker_primary_group_mismatch"
}

verify_socket_access() {
  [[ -S "$SOCKET_PATH" ]] || fail "docker_socket_missing_after_apply"
  [[ "$(stat -c '%u:%g:%a' "$SOCKET_PATH")" == "0:$(getent group guardian-docker-broker | cut -d: -f3):660" ]] \
    || fail "docker_socket_owner_group_mode_mismatch"
  runuser -u guardian-api -- test ! -r "$SOCKET_PATH" || fail "api_can_read_docker_socket"
  runuser -u guardian-api -- test ! -w "$SOCKET_PATH" || fail "api_can_write_docker_socket"
  runuser -u guardian-worker -- test ! -r "$SOCKET_PATH" || fail "worker_can_read_docker_socket"
  runuser -u guardian-worker -- test ! -w "$SOCKET_PATH" || fail "worker_can_write_docker_socket"
  runuser -u guardian-broker -- test -r "$SOCKET_PATH" || fail "broker_cannot_read_docker_socket"
  runuser -u guardian-broker -- test -w "$SOCKET_PATH" || fail "broker_cannot_write_docker_socket"
}

case "$MODE" in
  --plan)
    cat <<'EOF'
Plan only; no files, users, groups, services, or Docker settings changed.
Target required: dedicated Ubuntu 24.04 VM with systemd and Docker socket activation.
Planned identities: guardian-api, guardian-worker, guardian-broker.
Planned Docker socket: root:guardian-docker-broker mode 0660; API and worker denied.
No service is started and no database or network connection is made.
EOF
    exit 0
    ;;
  --apply)
    check_apply_authorization
    ensure_group guardian-docker-broker
    ensure_group guardian-broker-clients
    ensure_user guardian-api
    ensure_user guardian-worker
    ensure_user guardian-broker
    usermod --append --groups guardian-docker-broker guardian-broker
    usermod --append --groups guardian-broker-clients guardian-api
    usermod --append --groups guardian-broker-clients guardian-broker
    check_role_memberships
    if [[ -e "$DROPIN_PATH" ]]; then
      grep -q '^# Managed by Guardian Nexus lab provisioning v1$' "$DROPIN_PATH" \
        || fail "docker_socket_dropin_exists_and_is_not_managed"
    else
      install -d -m 0755 "$DROPIN_DIR"
      temporary="${DROPIN_PATH}.tmp.$$"
      umask 022
      cat >"$temporary" <<'EOF'
# Managed by Guardian Nexus lab provisioning v1
[Socket]
SocketUser=root
SocketGroup=guardian-docker-broker
SocketMode=0660
EOF
      chmod 0644 "$temporary"
      mv "$temporary" "$DROPIN_PATH"
    fi
    if ! systemctl daemon-reload || ! systemctl restart docker.socket; then
      rm -f "$DROPIN_PATH"
      systemctl daemon-reload || true
      systemctl restart docker.socket || true
      fail "docker_socket_unit_restart_failed_rolled_back_dropin"
    fi
    verify_socket_access
    printf '%s\n' \
      "guardian_lab_provision_complete users_created_or_verified=3" \
      "docker_socket_access api=denied worker=denied broker=allowed" \
      "services_started=0 database_connections=0 external_connections=0"
    ;;
  --rollback)
    check_apply_authorization
    if [[ -e "$DROPIN_PATH" ]]; then
      grep -q '^# Managed by Guardian Nexus lab provisioning v1$' "$DROPIN_PATH" \
        || fail "refusing_to_remove_unmanaged_dropin"
      rm -f "$DROPIN_PATH"
      systemctl daemon-reload
      systemctl restart docker.socket
    fi
    printf '%s\n' \
      "guardian_lab_socket_rollback_complete managed_dropin_removed=1" \
      "service_accounts_retained=1 manual_review_required=1"
    ;;
  *)
    fail "usage_provision_sh_--plan_--apply_--rollback"
    ;;
esac
