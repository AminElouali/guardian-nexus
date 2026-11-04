-- Run only through the explicit local-lab wrapper. No password is set here.
-- Local peer authentication must be configured by the authorized host admin.
DO $provision$
BEGIN
  IF current_database() !~ '^guardian_lab_[a-z0-9_]+$' THEN
    RAISE EXCEPTION 'refusing_non_lab_database';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_roles
    WHERE rolname = 'app_ai_assessment_worker'
      AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcanlogin
      AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication
      AND NOT rolinherit
  ) THEN
    RAISE EXCEPTION 'expected_worker_role_missing_or_privileged_or_login_enabled';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'app_ai_assessment_worker_login'
  ) THEN
    EXECUTE 'CREATE ROLE app_ai_assessment_worker_login LOGIN
      NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS';
  ELSE
    IF EXISTS (
      SELECT 1 FROM pg_roles
      WHERE rolname = 'app_ai_assessment_worker_login'
        AND (NOT rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
             OR rolreplication OR rolbypassrls OR rolinherit)
    ) THEN
      RAISE EXCEPTION 'existing_worker_login_is_privileged';
    END IF;
  END IF;
END
$provision$;

GRANT app_ai_assessment_worker TO app_ai_assessment_worker_login;
