#!/usr/bin/env bash
set -euo pipefail

# Read-only host checks. This script does not connect to Docker/PostgreSQL,
# change permissions, create users, or start services.
fail() {
  printf 'BLOCKED %s\n' "$1" >&2
  exit 1
}

[[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "run_as_host_admin_for_identity_checks"
command -v id >/dev/null || fail "id_missing"
command -v runuser >/dev/null || fail "runuser_missing"
command -v stat >/dev/null || fail "stat_missing"
command -v pgrep >/dev/null || fail "pgrep_missing"

api_user="${GUARDIAN_API_USER:-guardian-api}"
broker_user="${GUARDIAN_BROKER_USER:-guardian-assessment-broker}"
id -u "$api_user" >/dev/null 2>&1 || fail "api_identity_missing"
id -u "$broker_user" >/dev/null 2>&1 || fail "broker_identity_missing"
api_uid="$(id -u "$api_user")"
broker_uid="$(id -u "$broker_user")"
api_gid="$(id -g "$api_user")"
broker_gid="$(id -g "$broker_user")"
api_groups="$(id -G "$api_user")"
broker_groups="$(id -G "$broker_user")"
api_group_names="$(id -nG "$api_user")"
broker_group_names="$(id -nG "$broker_user")"
[[ "$api_uid" != "0" && "$broker_uid" != "0" ]] || fail "root_identity_forbidden"
[[ "$api_uid" != "$broker_uid" ]] || fail "shared_uid"
case " $api_group_names " in *" docker "*) fail "api_in_docker_group" ;; esac
case " $broker_group_names " in
  *" docker "*|*" sudo "*|*" wheel "*) fail "broker_in_privileged_group" ;;
esac

socket="${GUARDIAN_BROKER_DOCKER_SOCKET:-/run/user/${broker_uid}/docker.sock}"
[[ -S "$socket" ]] || fail "broker_rootless_socket_missing"
socket_owner="$(stat -c '%u' "$socket")"
[[ "$socket_owner" == "$broker_uid" ]] || fail "socket_not_owned_by_broker"
socket_gid="$(stat -c '%g' "$socket")"
socket_mode="$(stat -c '%a' "$socket")"
[[ "$socket_mode" == "600" || "$socket_mode" == "660" ]] ||
  fail "socket_permissions_too_broad"
if [[ "$socket_mode" == "660" ]] &&
  [[ " $api_groups " =~ (^|[[:space:]])${socket_gid}([[:space:]]|$) ]]; then
  fail "api_in_broker_socket_group"
fi
for candidate in "$socket" /var/run/docker.sock /run/docker.sock; do
  [[ -S "$candidate" ]] || continue
  if runuser -u "$api_user" -- test -r "$candidate" ||
    runuser -u "$api_user" -- test -w "$candidate"; then
    fail "api_can_access_docker_socket"
  fi
done
runuser -u "$broker_user" -- test -r "$socket" ||
  fail "broker_cannot_read_own_socket"
runuser -u "$broker_user" -- test -w "$socket" ||
  fail "broker_cannot_write_own_socket"
pgrep -u "$broker_uid" -f 'dockerd-rootless|rootlesskit' >/dev/null ||
  fail "broker_rootless_daemon_not_running"

printf 'host_identity_boundary=passed api_uid_gid=%s:%s api_groups=%s broker_uid_gid=%s:%s broker_groups=%s\n' \
  "$api_uid" "$api_gid" "$api_groups" "$broker_uid" "$broker_gid" "$broker_groups"
if [[ -s /proc/net/if_inet6 ]]; then
  printf 'ipv6_kernel=available egress=not_tested\n'
else
  printf 'ipv6_kernel=kernel_protocol_unavailable egress=not_tested\n'
fi
printf 'docker_daemon_requests=0 database_connections=0 host_mutations=0\n'
