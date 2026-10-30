import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const pool = new Pool({ connectionString: process.env.DATABASE_URL });
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
        'workspace_audit_events'
      )
    GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
  `);
  const expectedPolicyCounts: Record<string, number> = {
    workspaces: 2,
    workspace_memberships: 3,
    assets: 1,
    workspace_monthly_usage: 1,
    workspace_audit_events: 2,
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

  const roleResult = await db.execute(sql`
    SELECT rolsuper, rolbypassrls, rolcanlogin, rolcreatedb, rolcreaterole
    FROM pg_roles
    WHERE rolname = 'app_runtime'
  `);
  const role = roleResult.rows[0];
  if (
    !role ||
    role.rolsuper !== false ||
    role.rolbypassrls !== false ||
    role.rolcanlogin !== false ||
    role.rolcreatedb !== false ||
    role.rolcreaterole !== false
  ) {
    throw new Error("The app_runtime database role is not least-privileged.");
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
