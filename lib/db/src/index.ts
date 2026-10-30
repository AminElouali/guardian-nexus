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
            OR NOT ('app_runtime' = ANY(p.roles))
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
        'connector_jobs'
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
      pg_has_role(session_user, 'app_runtime', 'MEMBER') AS can_set_runtime_role,
      pg_has_role(session_user, 'app_runtime', 'USAGE') AS inherits_runtime_privileges,
      has_table_privilege(session_user, 'public.workspaces', 'SELECT') AS direct_workspace_read,
      has_table_privilege(session_user, 'public.assets', 'SELECT') AS direct_asset_read,
      has_table_privilege(session_user, 'public.assets', 'INSERT') AS direct_asset_write
    FROM pg_roles AS role
    CROSS JOIN pg_roles AS runtime
    WHERE role.rolname = session_user
      AND role.rolname = ${appRuntimeLoginRoleName}
      AND runtime.rolname = 'app_runtime'
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
    login.can_set_runtime_role !== true ||
    login.inherits_runtime_privileges !== false ||
    login.direct_workspace_read !== false ||
    login.direct_asset_read !== false ||
    login.direct_asset_write !== false
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
}

export * from "./schema";
