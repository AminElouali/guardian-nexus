#!/usr/bin/env bash
set -euo pipefail

[[ "${GUARDIAN_LAB_ACK:-}" == "verify-local-lab-db" ]] || {
  echo "BLOCKED explicit_lab_ack_required" >&2
  exit 64
}
db="${GUARDIAN_LAB_DB:-}"
[[ "$db" =~ ^guardian_lab_[a-z0-9_]+$ ]] || {
  echo "BLOCKED database_name_must_start_guardian_lab_" >&2
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

verify_session() {
  local login="$1"
  local parent_role="$2"
  local result
  result="$(psql --no-password --no-psqlrc --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --set=expected_login="$login" \
    --set=required_role="$parent_role" --host="$socket_dir" \
    --username="$login" --dbname="$db" --command="
WITH active_roles AS (
  SELECT oid, rolname, rolsuper, rolbypassrls
  FROM pg_roles
  WHERE rolname IN (session_user, current_user)
), tenant_tables AS (
  SELECT DISTINCT c.oid, c.relowner, c.relrowsecurity, c.relforcerowsecurity
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  JOIN pg_attribute a ON a.attrelid = c.oid
  WHERE n.nspname = 'public'
    AND c.relkind IN ('r', 'p')
    AND a.attnum > 0
    AND NOT a.attisdropped
    AND a.attname IN ('tenant_id', 'workspace_id')
)
SELECT CASE WHEN
  session_user = :'expected_login'
  AND NOT EXISTS (
    SELECT 1 FROM active_roles WHERE rolsuper OR rolbypassrls
  )
  AND pg_has_role(session_user, :'required_role', 'member')
  AND (SELECT count(*) > 0 AND bool_and(relrowsecurity AND relforcerowsecurity)
       FROM tenant_tables)
  AND NOT EXISTS (
    SELECT 1 FROM tenant_tables WHERE relowner IN (SELECT oid FROM active_roles)
  )
THEN 'passed' ELSE 'failed' END
")"
  [[ "$result" == "passed" ]] || {
    echo "BLOCKED database_role_or_forced_rls_check_failed role=$login" >&2
    return 1
  }
  printf 'database_session=passed login=%s inherited_role=%s\n' \
    "$login" "$parent_role"
}

verify_session "app_runtime_login" "app_runtime"
verify_session "app_ai_assessment_worker_login" "app_ai_assessment_worker"
printf 'database_passwords_read=0 database_mutations=0\n'
