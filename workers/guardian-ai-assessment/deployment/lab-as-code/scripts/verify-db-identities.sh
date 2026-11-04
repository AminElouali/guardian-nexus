#!/usr/bin/env bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[[ "${GUARDIAN_LAB_ACK:-}" == "verify-local-lab-db" ]] || {
  echo "BLOCKED explicit_lab_ack_required" >&2
  exit 64
}
db="${GUARDIAN_LAB_DB:-}"
[[ "$db" =~ ^guardian_lab_[a-z0-9_]+$ ]] || {
  echo "BLOCKED database_name_must_start_guardian_lab_" >&2
  exit 64
}
pg_port="${PGPORT:-5432}"
[[ "$pg_port" =~ ^[0-9]{1,5}$ ]] &&
  (( 10#$pg_port >= 1 && 10#$pg_port <= 65535 )) || {
  echo "BLOCKED invalid_local_postgresql_port" >&2
  exit 64
}
socket_dir="${GUARDIAN_PG_SOCKET_DIR:-/var/run/postgresql}"
[[ -S "$socket_dir/.s.PGSQL.$pg_port" ]] || {
  echo "BLOCKED local_postgresql_socket_missing" >&2
  exit 69
}
command -v psql >/dev/null || {
  echo "BLOCKED psql_missing" >&2
  exit 69
}
command -v env >/dev/null || {
  echo "BLOCKED env_missing" >&2
  exit 69
}
command -v runuser >/dev/null || {
  echo "BLOCKED runuser_missing" >&2
  exit 69
}
psql_bin="$(command -v psql)"
env_bin="$(command -v env)"
runuser_bin="$(command -v runuser)"
api_user="${GUARDIAN_API_USER:-guardian-api}"
broker_user="${GUARDIAN_BROKER_USER:-guardian-assessment-broker}"
[[ "$api_user" =~ ^[a-z_][a-z0-9_-]*$ &&
   "$broker_user" =~ ^[a-z_][a-z0-9_-]*$ ]] || {
  echo "BLOCKED invalid_service_identity" >&2
  exit 64
}
command -v id >/dev/null || {
  echo "BLOCKED id_missing" >&2
  exit 69
}
api_uid="$(id -u "$api_user" 2>/dev/null)" || {
  echo "BLOCKED api_identity_missing" >&2
  exit 1
}
broker_uid="$(id -u "$broker_user" 2>/dev/null)" || {
  echo "BLOCKED broker_identity_missing" >&2
  exit 1
}
[[ "$api_uid" != 0 && "$broker_uid" != 0 && "$api_uid" != "$broker_uid" ]] || {
  echo "BLOCKED database_service_identities_not_separate" >&2
  exit 1
}
[[ "${EUID:-$(id -u)}" -eq 0 ]] || {
  echo "BLOCKED run_as_host_admin_for_peer_identity_checks" >&2
  exit 1
}

verify_session() {
  local unix_user="$1"
  local login="$2"
  local parent_role="$3"
  local result
  case "$unix_user:$login:$parent_role" in
    "$api_user:app_runtime_login:app_runtime" | \
      "$broker_user:app_ai_assessment_worker_login:app_ai_assessment_worker") ;;
    *)
      echo "BLOCKED unexpected_database_identity_pair" >&2
      return 1
      ;;
  esac
  # Use only the two repository-defined login/role pairs. Scrub libpq's
  # inherited environment (especially PGPASSWORD, PGSERVICE, and PGOPTIONS),
  # require a real SET ROLE transition, and verify both identities' attributes.
  result="$("$runuser_bin" -u "$unix_user" -- "$env_bin" -i \
    PATH=/usr/sbin:/usr/bin:/sbin:/bin \
    "$psql_bin" --no-password --no-psqlrc --quiet --tuples-only --no-align \
    --set=ON_ERROR_STOP=1 --set=expected_login="$login" \
    --set=required_role="$parent_role" --host="$socket_dir" --port="$pg_port" \
    --username="$login" --dbname="$db" --command="
SET ROLE $parent_role;
WITH active_roles AS (
  SELECT oid, rolname, rolsuper, rolbypassrls, rolcanlogin, rolcreatedb,
         rolcreaterole, rolreplication, rolinherit
  FROM pg_roles
  WHERE rolname IN (
    session_user, current_user, :'expected_login'::name, :'required_role'::name
  )
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
  session_user = :'expected_login'::name
  AND current_user = :'required_role'::name
  AND session_user <> current_user
  AND EXISTS (
    SELECT 1 FROM active_roles
    WHERE rolname = :'expected_login'::name AND rolcanlogin
      AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolreplication AND NOT rolinherit
  )
  AND EXISTS (
    SELECT 1 FROM active_roles
    WHERE rolname = :'required_role'::name AND NOT rolcanlogin
      AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreatedb
      AND NOT rolcreaterole AND NOT rolreplication AND NOT rolinherit
  )
  AND NOT EXISTS (
    SELECT 1 FROM active_roles WHERE rolsuper OR rolbypassrls
  )
  AND pg_has_role(session_user, :'required_role'::name, 'member')
  AND (SELECT count(*) > 0 AND bool_and(relrowsecurity AND relforcerowsecurity)
       FROM tenant_tables)
  AND NOT EXISTS (
    SELECT 1 FROM tenant_tables WHERE relowner IN (SELECT oid FROM active_roles)
  )
  AND NOT EXISTS (
    SELECT 1
    FROM tenant_tables t
    JOIN pg_class c ON c.oid = t.oid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    JOIN pg_attribute a
      ON a.attrelid = t.oid AND a.attnum > 0 AND NOT a.attisdropped
    WHERE has_table_privilege(:'expected_login'::name, t.oid, 'SELECT')
       OR has_table_privilege(:'expected_login'::name, t.oid, 'INSERT')
       OR has_table_privilege(:'expected_login'::name, t.oid, 'UPDATE')
       OR has_table_privilege(:'expected_login'::name, t.oid, 'DELETE')
       OR has_column_privilege(
            :'expected_login'::name, format('%I.%I', n.nspname, c.relname),
            a.attname, 'SELECT')
       OR has_column_privilege(
            :'expected_login'::name, format('%I.%I', n.nspname, c.relname),
            a.attname, 'INSERT')
       OR has_column_privilege(
            :'expected_login'::name, format('%I.%I', n.nspname, c.relname),
            a.attname, 'UPDATE')
       OR has_column_privilege(
            :'expected_login'::name, format('%I.%I', n.nspname, c.relname),
            a.attname, 'REFERENCES')
  )
THEN 'passed' ELSE 'failed' END
")"
  [[ "$result" == "passed" ]] || {
    echo "BLOCKED database_role_or_forced_rls_check_failed role=$login" >&2
    return 1
  }
  printf 'database_session=passed login=%s effective_role=%s\n' \
    "$login" "$parent_role"
}

verify_session "$api_user" "app_runtime_login" "app_runtime"
verify_session "$broker_user" "app_ai_assessment_worker_login" "app_ai_assessment_worker"
printf 'database_passwords_read=0 inherited_pg_credentials=0 database_mutations=0 tenant_policy_predicates=not_checked\n'
