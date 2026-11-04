-- Read-only verification query; returns role flags only, never table contents.
SELECT
  rolname,
  rolsuper,
  rolcreatedb,
  rolcreaterole,
  rolbypassrls,
  rolcanlogin
FROM pg_roles
WHERE rolname IN (
  'guardian_api_login',
  'guardian_worker_login',
  'guardian_broker_login',
  'guardian_api_privileges',
  'guardian_worker_privileges',
  'guardian_broker_privileges'
)
ORDER BY rolname;

-- Required application sessions must be observed separately using a read-only
-- connection configured by the operator. A role skeleton alone is not proof
-- that a running API, worker, or broker uses a distinct DB session.
SELECT session_user, current_user, current_setting('transaction_read_only');
