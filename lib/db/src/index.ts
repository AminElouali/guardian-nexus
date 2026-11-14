import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import pg from "pg";
import * as schema from "./schema";
import { appRuntimeLoginRoleName } from "./schema/roles";
import { expectedRlsPolicyCounts } from "./rls-catalog-contract";
import {
  RlsRuntimeReadinessError,
  type RlsReadinessViolationCode,
} from "./rls-readiness-diagnostics";

export {
  RlsRuntimeReadinessError,
  safeRlsReadinessViolationCodes,
  rlsReadinessViolationCodes,
} from "./rls-readiness-diagnostics";
export type { RlsReadinessViolationCode } from "./rls-readiness-diagnostics";

const { Pool } = pg;

async function runRlsReadinessStep<T>(
  operation: () => Promise<T>,
  failureCode: RlsReadinessViolationCode,
): Promise<T> {
  try {
    return await operation();
  } catch {
    throw new RlsRuntimeReadinessError([failureCode]);
  }
}

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
  const { rows } = await runRlsReadinessStep(
    () => db.execute(sql`
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
        'ai_assessment_jobs',
        'host_boundary_attestation_challenges',
        'ai_assessment_approval_requests'
      )
    GROUP BY c.relname, c.relrowsecurity, c.relforcerowsecurity
  `),
    "table_catalog_query_failed",
  );
  const catalogViolations: RlsReadinessViolationCode[] = [];
  if (rows.length !== Object.keys(expectedRlsPolicyCounts).length) {
    catalogViolations.push("table_inventory_mismatch");
  }
  for (const row of rows) {
      const expectedCount =
        expectedRlsPolicyCounts[
          String(row.relname) as keyof typeof expectedRlsPolicyCounts
        ];
      if (expectedCount === undefined) {
        catalogViolations.push("table_inventory_mismatch");
      }
      if (row.relrowsecurity !== true) {
        catalogViolations.push("rls_disabled");
      }
      if (row.relforcerowsecurity !== true) {
        catalogViolations.push("rls_not_forced");
      }
      if (
        expectedCount === undefined ||
        Number(row.policy_count) !== expectedCount
      ) {
        catalogViolations.push("policy_count_mismatch");
      }
      if (Number(row.invalid_policies) !== 0) {
        catalogViolations.push("policy_contract_mismatch");
      }
  }
  if (catalogViolations.length > 0) {
    throw new RlsRuntimeReadinessError(catalogViolations);
  }

  const loginResult = await runRlsReadinessStep(
    () => db.execute(sql`
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
            'ai_assessment_jobs',
            'host_boundary_attestation_challenges',
            'ai_assessment_approval_requests'
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
          'ai_assessment_jobs',
          'host_boundary_attestation_challenges',
          'ai_assessment_approval_requests'
        ]) AS protected(table_name)
        WHERE NOT CASE
          WHEN protected.table_name = 'host_boundary_attestation_challenges'
          THEN has_table_privilege(
            runtime.oid,
            format('public.%I', protected.table_name),
            'SELECT,INSERT'
          )
            AND NOT has_table_privilege(
              runtime.oid,
              'public.host_boundary_attestation_challenges',
              'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.host_boundary_attestation_challenges',
              'consumed_at', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.host_boundary_attestation_challenges',
              'status', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.host_boundary_attestation_challenges',
              'response_sha256', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.host_boundary_attestation_challenges',
              'supervisor_id', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.host_boundary_attestation_challenges',
              'updated_at', 'UPDATE'
            )
            AND NOT EXISTS (
              SELECT 1
              FROM pg_attribute AS host_column
              WHERE host_column.attrelid = 'public.host_boundary_attestation_challenges'::regclass
                AND host_column.attnum > 0
                AND NOT host_column.attisdropped
                AND host_column.attname NOT IN (
                  'consumed_at',
                  'status',
                  'response_sha256',
                  'supervisor_id',
                  'updated_at'
                )
                AND has_column_privilege(
                  runtime.oid,
                  host_column.attrelid,
                  host_column.attnum,
                  'UPDATE'
                )
            )
          WHEN protected.table_name = 'ai_assessment_approval_requests'
          THEN has_table_privilege(
            runtime.oid,
            'public.ai_assessment_approval_requests',
            'SELECT,INSERT'
          )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'status', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'decided_by_user_id', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'decided_by_role', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'decided_at', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'simulated_at', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'simulation_result_code', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'simulation_result_sha256', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'replay_binding_sha256', 'UPDATE'
            )
            AND has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'updated_at', 'UPDATE'
            )
            AND NOT has_table_privilege(
              runtime.oid,
              'public.ai_assessment_approval_requests',
              'DELETE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'job_id', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'case_id', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'workspace_id', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'proposal_sha256', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'action_sha256', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'proposal_binding_sha256', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'requested_by_user_id', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'requested_by_role', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'binding_version', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'synthetic_action_ref', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'model_inference', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'execution_mode', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'tool_call_origin', 'UPDATE'
            )
            AND NOT has_column_privilege(
              runtime.oid, 'public.ai_assessment_approval_requests',
              'expires_at', 'UPDATE'
            )
          ELSE has_table_privilege(
            runtime.oid,
            format('public.%I', protected.table_name),
            'SELECT,INSERT,UPDATE,DELETE'
          )
        END
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
          'ai_assessment_jobs',
          'host_boundary_attestation_challenges',
          'ai_assessment_approval_requests'
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
  `),
    "role_catalog_query_failed",
  );
  const login = loginResult.rows[0];
  if (!login) {
    throw new RlsRuntimeReadinessError(["role_catalog_query_failed"]);
  }
  const roleViolations: RlsReadinessViolationCode[] = [];
  if (
    login.session_role !== appRuntimeLoginRoleName ||
    login.current_role !== appRuntimeLoginRoleName
  ) {
    roleViolations.push("runtime_login_identity_mismatch");
  }
  if (
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
    login.worker_inherits_privileges !== false
  ) {
    roleViolations.push("role_attributes_mismatch");
  }
  if (
    login.can_set_runtime_role !== true ||
    login.inherits_runtime_privileges !== false ||
    login.runtime_can_set_worker_role !== true
  ) {
    roleViolations.push("role_membership_mismatch");
  }
  if (
    login.worker_can_read_job_result !== false ||
    login.worker_can_write_job_result !== false ||
    login.worker_can_change_tenant !== false ||
    login.worker_can_change_actor !== false ||
    login.worker_can_change_profile !== false
  ) {
    roleViolations.push("worker_privileges_mismatch");
  }
  if (
    login.runtime_owns_protected_table !== false ||
    login.runtime_has_required_table_grants !== true
  ) {
    roleViolations.push("runtime_table_privileges_mismatch");
  }
  if (login.login_has_direct_protected_table_access !== false) {
    roleViolations.push("runtime_login_direct_table_access");
  }
  if (roleViolations.length > 0) {
    throw new RlsRuntimeReadinessError(roleViolations);
  }

  const effectiveRole = await runRlsReadinessStep(
    () =>
      db.transaction(async (tx) => {
        await tx.execute(sql`SET LOCAL ROLE app_runtime`);
        const result = await tx.execute(sql`SELECT current_user AS role_name`);
        return result.rows[0]?.role_name;
      }),
    "runtime_role_activation_failed",
  );
  if (effectiveRole !== "app_runtime") {
    throw new RlsRuntimeReadinessError(["runtime_role_activation_failed"]);
  }

  const effectiveWorkerRole = await runRlsReadinessStep(
    () =>
      db.transaction(async (tx) => {
        await tx.execute(sql`SET LOCAL ROLE app_runtime`);
        await tx.execute(sql`SET LOCAL ROLE app_ai_assessment_worker`);
        const result = await tx.execute(sql`SELECT current_user AS role_name`);
        return result.rows[0]?.role_name;
      }),
    "worker_role_activation_failed",
  );
  if (effectiveWorkerRole !== "app_ai_assessment_worker") {
    throw new RlsRuntimeReadinessError(["worker_role_activation_failed"]);
  }

  let workerResultColumnDenied = false;
  try {
    await db.transaction(async (tx) => {
      await tx.execute(sql`SET LOCAL ROLE app_runtime`);
      await tx.execute(sql`SET LOCAL ROLE app_ai_assessment_worker`);
      await tx.execute(
        sql`SELECT result FROM public.ai_assessment_jobs LIMIT 0`,
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
      throw new RlsRuntimeReadinessError([
        "worker_result_column_access_probe_failed",
      ]);
    }
  }
  if (!workerResultColumnDenied) {
    throw new RlsRuntimeReadinessError([
      "worker_result_column_access_not_denied",
    ]);
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
