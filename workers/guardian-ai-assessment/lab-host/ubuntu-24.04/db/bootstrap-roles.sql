-- Role skeleton only. No passwords, LOGIN attributes, grants, or data changes.
-- Run only after reviewing the target database and existing RLS migrations.
-- Login credentials must be created separately through the approved secret
-- manager/DBA procedure; never place them in this repository or shell history.

DO $$
BEGIN
  CREATE ROLE guardian_api_privileges NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE guardian_worker_privileges NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$
BEGIN
  CREATE ROLE guardian_broker_privileges NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Deliberately no GRANT statements: exact least-privilege table/function grants
-- depend on the reviewed schema and must preserve FORCE ROW LEVEL SECURITY.
