#!/usr/bin/env bash
set -euo pipefail

# Deliberately gated: only a disposable local Guardian lab database is accepted.
[[ "${GUARDIAN_LAB_ACK:-}" == "provision-worker-login" ]] || {
  echo "BLOCKED explicit_lab_ack_required" >&2
  exit 64
}
db="${GUARDIAN_LAB_DB:-}"
admin="${GUARDIAN_LAB_DB_ADMIN:-}"
[[ "$db" =~ ^guardian_lab_[a-z0-9_]+$ ]] || {
  echo "BLOCKED database_name_must_start_guardian_lab_" >&2
  exit 64
}
[[ "$admin" =~ ^[a-z_][a-z0-9_]*$ ]] || {
  echo "BLOCKED invalid_local_admin_role" >&2
  exit 64
}
socket_dir="${GUARDIAN_PG_SOCKET_DIR:-/var/run/postgresql}"
[[ -S "$socket_dir/.s.PGSQL.${PGPORT:-5432}" ]] || {
  echo "BLOCKED local_postgresql_socket_missing" >&2
  exit 69
}
command -v psql >/dev/null || {
  echo "BLOCKED psql_missing" >&2
  exit 69
}

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec psql --no-password --no-psqlrc --single-transaction --set=ON_ERROR_STOP=1 \
  --host="$socket_dir" --username="$admin" --dbname="$db" \
  --file="$script_dir/../sql/provision-worker-login.sql"
