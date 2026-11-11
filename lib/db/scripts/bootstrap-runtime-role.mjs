import pg from "pg";

if (
  process.env.NODE_ENV === "production" ||
  process.env.REPLIT_DEPLOYMENT === "1" ||
  process.env.ALLOW_DEV_DB_ROLE_BOOTSTRAP !== "true"
) {
  throw new Error(
    "Refusing database role bootstrap; run explicitly against development only.",
  );
}

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL must be set for the development database.");
}

const client = new pg.Client({ connectionString: process.env.DATABASE_URL });

try {
  await client.connect();
  const ensureRuntimeRole = async () => {
    const { rows } = await client.query(
      "SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime'",
    );
    if (rows.length === 0) {
      await client.query(`
        CREATE ROLE app_runtime
          NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOINHERIT NOREPLICATION NOBYPASSRLS;
      `);
    }
    await client.query(`
      ALTER ROLE app_runtime
        NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS;
    `);
  };
  const ensureAssessmentWorkerRole = async (grantQueueColumns = false) => {
    const { rows } = await client.query(
      "SELECT 1 FROM pg_roles WHERE rolname = 'app_ai_assessment_worker'",
    );
    if (rows.length === 0) {
      await client.query(`
        CREATE ROLE app_ai_assessment_worker
          NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOINHERIT NOREPLICATION NOBYPASSRLS;
      `);
    }
    await client.query(`
      ALTER ROLE app_ai_assessment_worker
        NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS;
      GRANT USAGE ON SCHEMA public TO app_ai_assessment_worker;
      GRANT app_ai_assessment_worker TO app_runtime
        WITH INHERIT FALSE, SET TRUE;
    `);
    if (grantQueueColumns) {
      await client.query(`
      REVOKE ALL PRIVILEGES ON TABLE public.ai_assessment_jobs
        FROM app_ai_assessment_worker;
      GRANT SELECT (
        id, workspace_id, requested_by_user_id, profile_id, status, attempts,
        worker_version, engine_version, error_code, lease_owner_id,
        lease_expires_at, heartbeat_at, worker_slot, created_at, updated_at,
        started_at, completed_at
      ) ON TABLE public.ai_assessment_jobs TO app_ai_assessment_worker;
      GRANT UPDATE (
        status, attempts, error_code, lease_owner_id, lease_expires_at,
        heartbeat_at, worker_slot, updated_at, started_at, completed_at
      ) ON TABLE public.ai_assessment_jobs TO app_ai_assessment_worker;
    `);
    }
  };
  const mode = process.argv[2] ?? "verify";
  if (mode === "harden") {
    await ensureRuntimeRole();
    await ensureAssessmentWorkerRole();
  } else if (mode === "grant") {
    await client.query(`
      GRANT USAGE ON SCHEMA public TO app_runtime;
      GRANT SELECT, INSERT, UPDATE, DELETE
        ON TABLE public.workspaces,
                 public.workspace_memberships,
                 public.assets,
                 public.workspace_monthly_usage,
                 public.workspace_audit_events,
                 public.workspace_integrations,
                 public.provider_connections,
                 public.connector_oauth_states,
                 public.connector_jobs,
                 public.ai_assessment_jobs
        TO app_runtime;
    `);
    await client.query(`
      GRANT SELECT, INSERT
        ON TABLE public.ai_assessment_approval_requests TO app_runtime;
      GRANT UPDATE (
        status, decided_by_user_id, decided_by_role, decided_at, simulated_at,
        simulation_result_code, simulation_result_sha256, replay_binding_sha256,
        updated_at
      )
        ON TABLE public.ai_assessment_approval_requests TO app_runtime;
    `);
    await ensureAssessmentWorkerRole(true);
  } else if (mode === "configure-login") {
    const password = process.env.APP_RUNTIME_DB_PASSWORD;
    if (!password) {
      throw new Error("APP_RUNTIME_DB_PASSWORD is not available to this development workflow.");
    }
    if (password.length < 32) {
      throw new Error("APP_RUNTIME_DB_PASSWORD must contain at least 32 characters.");
    }

    await client.query(`
      ALTER ROLE app_runtime
        NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS;
      GRANT USAGE ON SCHEMA public TO app_runtime;
      GRANT SELECT, INSERT, UPDATE, DELETE
        ON TABLE public.workspaces,
                 public.workspace_memberships,
                 public.assets,
                 public.workspace_monthly_usage,
                 public.workspace_audit_events,
                 public.workspace_integrations,
                 public.provider_connections,
                 public.connector_oauth_states,
                 public.connector_jobs,
                 public.ai_assessment_jobs
        TO app_runtime;
    `);
    await client.query(`
      GRANT SELECT, INSERT
        ON TABLE public.ai_assessment_approval_requests TO app_runtime;
      GRANT UPDATE (
        status, decided_by_user_id, decided_by_role, decided_at, simulated_at,
        simulation_result_code, simulation_result_sha256, replay_binding_sha256,
        updated_at
      )
        ON TABLE public.ai_assessment_approval_requests TO app_runtime;
    `);

    const { rows: existingLoginRows } = await client.query(`
      SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime_login'
    `);
    if (existingLoginRows.length === 0) {
      await client.query(`
        CREATE ROLE app_runtime_login
          LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
          NOINHERIT NOREPLICATION NOBYPASSRLS;
      `);
    }

    const { rows: quotedRows } = await client.query(
      "SELECT quote_literal($1) AS quoted_password",
      [password],
    );
    const quotedPassword = quotedRows[0]?.quoted_password;
    if (typeof quotedPassword !== "string") {
      throw new Error("Could not safely prepare the runtime database password.");
    }
    await client.query(`
      ALTER ROLE app_runtime_login
        WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
        NOINHERIT NOREPLICATION NOBYPASSRLS
        PASSWORD ${quotedPassword};
      GRANT app_runtime TO app_runtime_login WITH INHERIT FALSE, SET TRUE;
    `);

    const { rows: databaseRows } = await client.query(
      "SELECT quote_ident(current_database()) AS database_name",
    );
    const databaseName = databaseRows[0]?.database_name;
    if (typeof databaseName !== "string") {
      throw new Error("Could not determine the development database.");
    }
    await client.query(
      `GRANT CONNECT ON DATABASE ${databaseName} TO app_runtime_login`,
    );
    await ensureAssessmentWorkerRole(true);
  } else if (mode !== "verify") {
    if (mode !== "configure-login") {
      throw new Error(
        "Expected mode 'harden', 'verify', 'grant' or 'configure-login'.",
      );
    }
  }

  const { rows } = await client.query(`
    SELECT rolname, rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole
    FROM pg_roles
    WHERE rolname = 'app_runtime'
  `);
  const role = rows[0];
  if (
    !role ||
    role.rolsuper ||
    role.rolbypassrls ||
    role.rolcanlogin ||
    role.rolcreatedb ||
    role.rolcreaterole
  ) {
    throw new Error("app_runtime failed the restricted-role checks.");
  }

  if (mode === "verify" || mode === "grant" || mode === "configure-login") {
    const { rows: workerRows } = await client.query(`
      SELECT
        worker.rolsuper,
        worker.rolbypassrls,
        worker.rolcanlogin,
        worker.rolcreatedb,
        worker.rolcreaterole,
        worker.rolreplication,
        worker.rolinherit,
        pg_has_role(runtime.oid, worker.oid, 'MEMBER') AS runtime_can_set_worker_role,
        EXISTS (
          SELECT 1
          FROM pg_class AS protected
          JOIN pg_namespace AS protected_schema
            ON protected_schema.oid = protected.relnamespace
          WHERE protected_schema.nspname = 'public'
            AND protected.relname = 'ai_assessment_jobs'
            AND protected.relowner = worker.oid
        ) AS worker_owns_jobs,
        has_column_privilege(
          worker.oid, 'public.ai_assessment_jobs', 'result', 'SELECT'
        ) AS worker_can_read_result,
        has_column_privilege(
          worker.oid, 'public.ai_assessment_jobs', 'result', 'UPDATE'
        ) AS worker_can_write_result,
        has_column_privilege(
          worker.oid, 'public.ai_assessment_jobs', 'workspace_id', 'UPDATE'
        ) AS worker_can_change_tenant,
        has_column_privilege(
          worker.oid, 'public.ai_assessment_jobs', 'requested_by_user_id', 'UPDATE'
        ) AS worker_can_change_actor,
        has_column_privilege(
          worker.oid, 'public.ai_assessment_jobs', 'profile_id', 'UPDATE'
        ) AS worker_can_change_profile
      FROM pg_roles AS worker
      CROSS JOIN pg_roles AS runtime
      WHERE worker.rolname = 'app_ai_assessment_worker'
        AND runtime.rolname = 'app_runtime'
    `);
    const worker = workerRows[0];
    if (
      !worker ||
      worker.rolsuper ||
      worker.rolbypassrls ||
      worker.rolcanlogin ||
      worker.rolcreatedb ||
      worker.rolcreaterole ||
      worker.rolreplication ||
      worker.rolinherit ||
      !worker.runtime_can_set_worker_role ||
      worker.worker_owns_jobs ||
      worker.worker_can_read_result ||
      worker.worker_can_write_result ||
      worker.worker_can_change_tenant ||
      worker.worker_can_change_actor ||
      worker.worker_can_change_profile
    ) {
      throw new Error(
        "app_ai_assessment_worker failed its restricted queue-role checks.",
      );
    }
  }

  if (mode === "configure-login" || mode === "verify") {
    const { rows: loginRows } = await client.query(`
      SELECT
        login.rolsuper,
        login.rolbypassrls,
        login.rolcanlogin,
        login.rolcreatedb,
        login.rolcreaterole,
        login.rolreplication,
        login.rolinherit,
        pg_has_role(login.oid, runtime.oid, 'MEMBER') AS is_runtime_member,
        pg_has_role(login.oid, runtime.oid, 'USAGE') AS inherits_runtime_privileges,
        (SELECT COUNT(*)::int
         FROM pg_auth_members AS memberships
         WHERE memberships.member = login.oid) AS membership_count,
        (SELECT bool_and(
           memberships.roleid = runtime.oid
           AND NOT memberships.admin_option
           AND NOT memberships.inherit_option
           AND memberships.set_option
         )
         FROM pg_auth_members AS memberships
         WHERE memberships.member = login.oid) AS membership_is_restricted,
        EXISTS (
          SELECT 1
          FROM unnest(ARRAY[
            'workspaces',
            'workspace_memberships',
            'assets',
            'workspace_monthly_usage',
            'workspace_audit_events',
            'workspace_integrations',
            'provider_connections',
            'connector_oauth_states',
            'connector_jobs',
            'ai_assessment_jobs'
          ]) AS protected(table_name)
          WHERE NOT has_table_privilege(
            runtime.oid,
            format('public.%I', protected.table_name),
            'SELECT,INSERT,UPDATE,DELETE'
          )
        ) AS runtime_missing_table_grants,
        EXISTS (
          SELECT 1
          FROM pg_class AS protected
          JOIN pg_namespace AS protected_schema
            ON protected_schema.oid = protected.relnamespace
          WHERE protected_schema.nspname = 'public'
            AND protected.relname = ANY(ARRAY[
              'workspaces',
              'workspace_memberships',
              'assets',
              'workspace_monthly_usage',
              'workspace_audit_events',
              'workspace_integrations',
              'provider_connections',
              'connector_oauth_states',
              'connector_jobs',
              'ai_assessment_jobs'
            ])
            AND protected.relowner = runtime.oid
        ) AS runtime_owns_protected_table,
        EXISTS (
          SELECT 1
          FROM unnest(ARRAY[
            'workspaces',
            'workspace_memberships',
            'assets',
            'workspace_monthly_usage',
            'workspace_audit_events',
            'workspace_integrations',
            'provider_connections',
            'connector_oauth_states',
            'connector_jobs',
            'ai_assessment_jobs'
          ]) AS protected(table_name)
          WHERE has_table_privilege(
            login.oid, format('public.%I', protected.table_name), 'SELECT'
          )
          OR has_table_privilege(
            login.oid, format('public.%I', protected.table_name), 'INSERT'
          )
          OR has_table_privilege(
            login.oid, format('public.%I', protected.table_name), 'UPDATE'
          )
          OR has_table_privilege(
            login.oid, format('public.%I', protected.table_name), 'DELETE'
          )
        ) AS login_has_direct_table_access
      FROM pg_roles AS login
      CROSS JOIN pg_roles AS runtime
      WHERE login.rolname = 'app_runtime_login'
        AND runtime.rolname = 'app_runtime'
    `);
    const login = loginRows[0];
    if (
      !login ||
      login.rolsuper ||
      login.rolbypassrls ||
      !login.rolcanlogin ||
      login.rolcreatedb ||
      login.rolcreaterole ||
      login.rolreplication ||
      login.rolinherit ||
      !login.is_runtime_member ||
      login.inherits_runtime_privileges ||
      login.membership_count !== 1 ||
      !login.membership_is_restricted ||
      login.runtime_missing_table_grants ||
      login.runtime_owns_protected_table ||
      login.login_has_direct_table_access
    ) {
      throw new Error("app_runtime_login failed the least-privilege checks.");
    }
  }

  console.log(
    mode === "grant"
      ? "Development app_runtime role grants are ready."
      : mode === "configure-login"
        ? "Development runtime login is configured and least-privileged."
        : "Development app_runtime role passed restricted-role checks.",
  );
} finally {
  await client.end();
}
