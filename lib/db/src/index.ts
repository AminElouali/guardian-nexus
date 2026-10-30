import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import pg from "pg";
import * as schema from "./schema";
import { appRuntimeLoginRoleName } from "./schema/roles";

const { Pool } = pg;

function requiredEnvironmentValue(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} must be set for the non-privileged database runtime.`);
  }
  return value;
}

function runtimePoolConfig(): pg.PoolConfig {
  const connectionString = process.env.APP_RUNTIME_DATABASE_URL;
  if (connectionString) {
    let parsed: URL;
    try {
      parsed = new URL(connectionString);
    } catch {
      throw new Error("APP_RUNTIME_DATABASE_URL must be a valid PostgreSQL URL.");
    }
    if (
      !["postgres:", "postgresql:"].includes(parsed.protocol) ||
      decodeURIComponent(parsed.username) !== appRuntimeLoginRoleName ||
      !parsed.password
    ) {
      throw new Error(
        `APP_RUNTIME_DATABASE_URL must authenticate as ${appRuntimeLoginRoleName}.`,
      );
    }
    if (decodeURIComponent(parsed.password).length < 32) {
      throw new Error("The runtime database password must be at least 32 characters.");
    }
    delete process.env.APP_RUNTIME_DATABASE_URL;
    return { connectionString };
  }

  const password = requiredEnvironmentValue("APP_RUNTIME_DB_PASSWORD");
  if (password.length < 32) {
    throw new Error("The runtime database password must be at least 32 characters.");
  }
  const port = Number(process.env.PGPORT || 5432);
  if (!Number.isInteger(port) || port <= 0) {
    throw new Error("PGPORT must be a valid port number.");
  }
  const config: pg.PoolConfig = {
    host: requiredEnvironmentValue("PGHOST"),
    port,
    database: requiredEnvironmentValue("PGDATABASE"),
    user: appRuntimeLoginRoleName,
    password,
  };
  delete process.env.APP_RUNTIME_DB_PASSWORD;
  return config;
}

const poolConfig = runtimePoolConfig();
export const pool = new Pool(poolConfig);
export const db = drizzle(pool, { schema });

export async function assertRlsRuntimeReady(): Promise<void> {
  const { rows } = await db.execute(sql`
    SELECT
      c.relname,
      c.relrowsecurity,
      c.relforcerowsecurity,
      COUNT(p.policyname)::int AS policy_count,
      COUNT(*) FILTER (
        WHERE p.policyname IS NOT NULL
          AND (
            (p.cmd IN ('SELECT', 'UPDATE', 'DELETE', 'ALL') AND p.qual IS NULL)
            OR (p.cmd IN ('INSERT', 'UPDATE', 'ALL') AND p.with_check IS NULL)
            OR NOT (
              'app_runtime' = ANY(p.roles)
              OR (
                c.relname = 'ai_assessment_jobs'
                AND 'app_ai_assessment_worker' = ANY(p.roles)
              )
            )
          )
      )::int AS invalid_policies
    FROM pg_class AS c
    JOIN pg_namespace AS n ON n.oid = c.relnamespace
    LEFT JOIN pg_policies AS p
      ON p.schemaname = n.nspname
      AND p.tablename = c.relname
    WHERE n.nspname = 'public'
      AND c.relname IN (
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
      )
    GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
  `);
  const expectedPolicyCounts: Record<string, number> = {
    workspaces: 2,
    workspace_memberships: 3,
    assets: 1,
    workspace_monthly_usage: 1,
    workspace_audit_events: 2,
    workspace_integrations: 3,
    provider_connections: 4,
    connector_oauth_states: 3,
    connector_jobs: 4,
    ai_assessment_jobs: 5,
  };
  if (
    rows.length !== Object.keys(expectedPolicyCounts).length ||
    rows.some((row) => {
      const expectedCount = expectedPolicyCounts[String(row.relname)];
      return (
        expectedCount === undefined ||
        row.relrowsecurity !== true ||
        row.relforcerowsecurity !== true ||
        Number(row.policy_count) !== expectedCount ||
        Number(row.invalid_policies) !== 0
      );
    })
  ) {
    throw new Error(
      "Tenant RLS policies are missing, unqualified, or not forced; refusing to start.",
    );
  }

  const loginResult = await db.execute(sql`
    SELECT
      session_user::text AS session_role,
      current_user::text AS current_role,
      role.rolsuper,
      role.rolbypassrls,
      role.rolcanlogin,
      role.rolcreatedb,
      role.rolcreaterole,
      role.rolreplication,
      role.rolinherit,
      runtime.rolsuper AS runtime_is_superuser,
      runtime.rolbypassrls AS runtime_bypasses_rls,
      runtime.rolcanlogin AS runtime_can_login,
      runtime.rolcreatedb AS runtime_can_create_databases,
      runtime.rolcreaterole AS runtime_can_create_roles,
      runtime.rolreplication AS runtime_can_replicate,
      runtime.rolinherit AS runtime_inherits_privileges,
      worker.rolsuper AS worker_is_superuser,
      worker.rolbypassrls AS worker_bypasses_rls,
      worker.rolcanlogin AS worker_can_login,
      worker.rolcreatedb AS worker_can_create_databases,
      worker.rolcreaterole AS worker_can_create_roles,
      worker.rolreplication AS worker_can_replicate,
      worker.rolinherit AS worker_inherits_privileges,
      pg_has_role(session_user, 'app_runtime', 'MEMBER') AS can_set_runtime_role,
      pg_has_role(session_user, 'app_runtime', 'USAGE') AS inherits_runtime_privileges,
      pg_has_role(runtime.oid, worker.oid, 'MEMBER') AS runtime_can_set_worker_role,
      has_column_privilege(
        worker.oid, 'public.ai_assessment_jobs', 'result', 'SELECT'
      ) AS worker_can_read_job_result,
      has_column_privilege(
        worker.oid, 'public.ai_assessment_jobs', 'result', 'UPDATE'
      ) AS worker_can_write_job_result,
      has_column_privilege(
        worker.oid, 'public.ai_assessment_jobs', 'workspace_id', 'UPDATE'
      ) AS worker_can_change_tenant,
      has_column_privilege(
        worker.oid, 'public.ai_assessment_jobs', 'requested_by_user_id', 'UPDATE'
      ) AS worker_can_change_actor,
      has_column_privilege(
        worker.oid, 'public.ai_assessment_jobs', 'profile_id', 'UPDATE'
      ) AS worker_can_change_profile,
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
      NOT EXISTS (
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
        WHERE NOT (
          has_table_privilege(
            runtime.oid,
            format('public.%I', protected.table_name),
            'SELECT,INSERT,UPDATE,DELETE'
          )
        )
      ) AS runtime_has_required_table_grants,
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
        WHERE
          has_table_privilege(role.oid, format('public.%I', protected.table_name), 'SELECT')
          OR has_table_privilege(role.oid, format('public.%I', protected.table_name), 'INSERT')
          OR has_table_privilege(role.oid, format('public.%I', protected.table_name), 'UPDATE')
          OR has_table_privilege(role.oid, format('public.%I', protected.table_name), 'DELETE')
      ) AS login_has_direct_protected_table_access
    FROM pg_roles AS role
    CROSS JOIN pg_roles AS runtime
    CROSS JOIN pg_roles AS worker
    WHERE role.rolname = session_user
      AND role.rolname = ${appRuntimeLoginRoleName}
      AND runtime.rolname = 'app_runtime'
      AND worker.rolname = 'app_ai_assessment_worker'
  `);
  const login = loginResult.rows[0];
  if (
    !login ||
    login.session_role !== appRuntimeLoginRoleName ||
    login.current_role !== appRuntimeLoginRoleName ||
    login.rolsuper !== false ||
    login.rolbypassrls !== false ||
    login.rolcanlogin !== true ||
    login.rolcreatedb !== false ||
    login.rolcreaterole !== false ||
    login.rolreplication !== false ||
    login.rolinherit !== false ||
    login.runtime_is_superuser !== false ||
    login.runtime_bypasses_rls !== false ||
    login.runtime_can_login !== false ||
    login.runtime_can_create_databases !== false ||
    login.runtime_can_create_roles !== false ||
    login.runtime_can_replicate !== false ||
    login.runtime_inherits_privileges !== false ||
    login.worker_is_superuser !== false ||
    login.worker_bypasses_rls !== false ||
    login.worker_can_login !== false ||
    login.worker_can_create_databases !== false ||
    login.worker_can_create_roles !== false ||
    login.worker_can_replicate !== false ||
    login.worker_inherits_privileges !== false ||
    login.can_set_runtime_role !== true ||
    login.inherits_runtime_privileges !== false ||
    login.runtime_can_set_worker_role !== true ||
    login.worker_can_read_job_result !== false ||
    login.worker_can_write_job_result !== false ||
    login.worker_can_change_tenant !== false ||
    login.worker_can_change_actor !== false ||
    login.worker_can_change_profile !== false ||
    login.runtime_owns_protected_table !== false ||
    login.runtime_has_required_table_grants !== true ||
    login.login_has_direct_protected_table_access !== false
  ) {
    throw new Error(
      "The API must connect as a non-privileged login with no direct tenant-data access.",
    );
  }

  const effectiveRole = await db.transaction(async (tx) => {
    await tx.execute(sql`SET LOCAL ROLE app_runtime`);
    const result = await tx.execute(sql`SELECT current_user AS role_name`);
    return result.rows[0]?.role_name;
  });
  if (effectiveRole !== "app_runtime") {
    throw new Error("Could not enter the app_runtime database role.");
  }

  const effectiveWorkerRole = await db.transaction(async (tx) => {
    await tx.execute(sql`SET LOCAL ROLE app_runtime`);
    await tx.execute(sql`SET LOCAL ROLE app_ai_assessment_worker`);
    const result = await tx.execute(sql`SELECT current_user AS role_name`);
    return result.rows[0]?.role_name;
  });
  if (effectiveWorkerRole !== "app_ai_assessment_worker") {
    throw new Error("Could not enter the restricted assessment queue role.");
  }

  let workerResultColumnDenied = false;
  try {
    await db.transaction(async (tx) => {
      await tx.execute(sql`SET LOCAL ROLE app_runtime`);
      await tx.execute(sql`SET LOCAL ROLE app_ai_assessment_worker`);
      await tx.execute(
        sql`SELECT result FROM public.ai_assessment_jobs LIMIT 1`,
      );
    });
  } catch (error) {
    const directCode =
      typeof error === "object" && error !== null && "code" in error
        ? error.code
        : undefined;
    const cause =
      typeof error === "object" && error !== null && "cause" in error
        ? error.cause
        : undefined;
    const causeCode =
      typeof cause === "object" && cause !== null && "code" in cause
        ? cause.code
        : undefined;
    if (
      directCode === "42501" ||
      causeCode === "42501"
    ) {
      workerResultColumnDenied = true;
    } else {
      throw error;
    }
  }
  if (!workerResultColumnDenied) {
    throw new Error("The assessment queue role can read tenant result data.");
  }
}

type DatabaseTransaction = Parameters<Parameters<typeof db.transaction>[0]>[0];

export async function withAiAssessmentQueueTransaction<T>(
  leaseOwnerId: string | null,
  operation: (tx: DatabaseTransaction) => Promise<T>,
): Promise<T> {
  if (
    leaseOwnerId !== null &&
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      leaseOwnerId,
    )
  ) {
    throw new Error("Invalid assessment lease identifier.");
  }
  return db.transaction(async (tx) => {
    await tx.execute(sql`SET LOCAL ROLE app_runtime`);
    await tx.execute(sql`SET LOCAL ROLE app_ai_assessment_worker`);
    await tx.execute(
      sql`SELECT set_config('app.ai_assessment_lease_owner', ${leaseOwnerId ?? ""}, true)`,
    );
    return operation(tx);
  });
}

export * from "./schema";
