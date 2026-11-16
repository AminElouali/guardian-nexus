import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { Pool, PoolClient } from "pg";
import {
  parseRlsCatalogContract,
  type RlsCatalogContract,
} from "@workspace/db/rls-catalog-audit";
import {
  deriveDrizzleRlsTableNames,
  readRlsCatalogPhaseSnapshot,
} from "@workspace/db/rls-catalog-phase-audit";
import {
  appendOnlyRuntimeGrantsAllowed,
} from "@workspace/db/rls-runtime-readiness";
import { readCatalogSnapshot } from "./verify-rls-catalog";
import {
  auditDevelopmentRlsCatalog,
  createDevelopmentRlsCatalogReport,
  parseDevelopmentRlsAuditArguments,
} from "../lib/development-rls-catalog-audit";

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../../../../");

async function loadContract(): Promise<RlsCatalogContract> {
  const schemaDirectory = path.join(repositoryRoot, "lib/db/src/schema");
  const schemaFileNames = (await readdir(schemaDirectory))
    .filter((name) => name.endsWith(".ts"))
    .sort();
  const [schemaFiles, rolesSource, bootstrapSource, policiesSql] =
    await Promise.all([
      Promise.all(schemaFileNames.map(async (name) => ({
        path: name,
        content: await readFile(path.join(schemaDirectory, name), "utf8"),
      }))),
      readFile(path.join(schemaDirectory, "roles.ts"), "utf8"),
      readFile(
        path.join(repositoryRoot, "lib/db/scripts/bootstrap-runtime-role.mjs"),
        "utf8",
      ),
      readFile(path.join(repositoryRoot, "lib/db/sql/rls-policies.sql"), "utf8"),
    ]);
  return parseRlsCatalogContract({
    schemaFiles,
    rolesSource,
    bootstrapSource,
    policiesSql,
  });
}

async function readAppendOnlyRuntimePrivileges(
  client: PoolClient,
  postgresMajor: number,
): Promise<Record<string, unknown>[]> {
  const maintainExpression = postgresMajor >= 17
    ? `COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'MAINTAIN')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false)`
    : "false";
  const { rows } = await client.query(`
    SELECT
      'workspace_approval_ledger'::text AS table_name,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'SELECT')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_select,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'INSERT')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_insert,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'UPDATE')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_update,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'DELETE')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_delete,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'TRUNCATE')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_truncate,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'REFERENCES')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_references,
      COALESCE((
        SELECT has_table_privilege(runtime.oid, ledger.oid, 'TRIGGER')
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
      ), false) AS can_trigger,
      ${maintainExpression} AS can_maintain,
      ${postgresMajor >= 17} AS maintain_supported,
      COALESCE((
        SELECT bool_or(has_column_privilege(
          runtime.oid, ledger.oid, attribute.attnum, 'UPDATE'
        ))
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = ledger.oid
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
      ), false) AS column_update,
      COALESCE((
        SELECT bool_or(has_column_privilege(
          runtime.oid, ledger.oid, attribute.attnum, 'REFERENCES'
        ))
          FROM pg_roles AS runtime
          CROSS JOIN pg_class AS ledger
          JOIN pg_namespace AS namespace ON namespace.oid = ledger.relnamespace
          JOIN pg_attribute AS attribute ON attribute.attrelid = ledger.oid
         WHERE runtime.rolname = 'app_runtime'
           AND namespace.nspname = 'public'
           AND ledger.relname = 'workspace_approval_ledger'
           AND attribute.attnum > 0
           AND NOT attribute.attisdropped
      ), false) AS column_references
  `);
  return rows;
}

function emitRefusal(code: string): void {
  const report = createDevelopmentRlsCatalogReport({
    generatedAt: new Date().toISOString(),
    databaseNameMatched: false,
    transactionReadOnly: false,
    postgresMajor: null,
    refusalCode: code,
  });
  process.stdout.write(`${JSON.stringify(report)}\n`);
  process.exitCode = 2;
}

async function main(): Promise<void> {
  const parsedArguments = parseDevelopmentRlsAuditArguments(
    process.argv.slice(2),
  );
  if (!parsedArguments.ok) {
    emitRefusal(parsedArguments.code);
    return;
  }

  let pool: Pool | undefined;
  let client: PoolClient | undefined;
  let transactionStarted = false;
  let databaseNameMatched = false;
  let transactionReadOnly = false;
  let runtimeLoginAuthenticated = false;
  let postgresMajor: number | null = null;
  try {
    const db = await import("@workspace/db");
    pool = db.pool;
    client = await pool.connect();
    await client.query("BEGIN TRANSACTION READ ONLY");
    transactionStarted = true;
    const identity = await client.query(
      `SELECT current_database() AS database_name,
              session_user::text AS session_role,
              current_user::text AS current_role,
              current_setting('transaction_read_only') AS read_only,
              floor(current_setting('server_version_num')::integer / 10000)::integer
                AS postgres_major`,
    );
    databaseNameMatched =
      identity.rows[0]?.database_name === parsedArguments.expectedDatabase;
    transactionReadOnly = identity.rows[0]?.read_only === "on";
    runtimeLoginAuthenticated =
      identity.rows[0]?.session_role === "app_runtime_login" &&
      identity.rows[0]?.current_role === "app_runtime_login";
    postgresMajor = Number(identity.rows[0]?.postgres_major);
    if (!Number.isSafeInteger(postgresMajor) || postgresMajor < 1) {
      postgresMajor = null;
    }
    if (!databaseNameMatched) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      const report = createDevelopmentRlsCatalogReport({
        generatedAt: new Date().toISOString(),
        databaseNameMatched: false,
        transactionReadOnly,
        postgresMajor,
        refusalCode: "development_database_identity_mismatch",
      });
      process.stdout.write(`${JSON.stringify(report)}\n`);
      process.exitCode = 2;
      return;
    }
    if (!runtimeLoginAuthenticated) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      const report = createDevelopmentRlsCatalogReport({
        generatedAt: new Date().toISOString(),
        databaseNameMatched,
        transactionReadOnly,
        runtimeLoginAuthenticated,
        postgresMajor,
        refusalCode: "runtime_login_identity_mismatch",
      });
      process.stdout.write(`${JSON.stringify(report)}\n`);
      process.exitCode = 2;
      return;
    }
    if (postgresMajor !== null && postgresMajor < 16) {
      await client.query("ROLLBACK");
      transactionStarted = false;
      const report = createDevelopmentRlsCatalogReport({
        generatedAt: new Date().toISOString(),
        databaseNameMatched,
        transactionReadOnly,
        runtimeLoginAuthenticated,
        postgresMajor,
        refusalCode: "postgres_version_unsupported",
      });
      process.stdout.write(`${JSON.stringify(report)}\n`);
      process.exitCode = 2;
      return;
    }
    if (!transactionReadOnly || postgresMajor === null) {
      throw new Error("read_only_transaction_failed");
    }

    const contract = await loadContract();
    const tableNames = deriveDrizzleRlsTableNames();
    const roleNames = Object.keys(contract.roles).sort();
    const [phaseSnapshot, { snapshot }, appendOnlyGrantRows] =
      await Promise.all([
        readRlsCatalogPhaseSnapshot(client, tableNames, roleNames),
        readCatalogSnapshot(client, tableNames, roleNames),
        readAppendOnlyRuntimePrivileges(client, postgresMajor),
      ]);
    const audit = auditDevelopmentRlsCatalog({
      contract,
      phaseSnapshot,
      catalogSnapshot: snapshot,
      appendOnlyGrantRows,
    });
    const report = createDevelopmentRlsCatalogReport({
      audit,
      generatedAt: new Date().toISOString(),
      databaseNameMatched,
      transactionReadOnly,
      runtimeLoginAuthenticated,
      postgresMajor,
    });
    await client.query("COMMIT");
    transactionStarted = false;
    process.stdout.write(`${JSON.stringify(report)}\n`);
    if (report.status !== "passed") process.exitCode = 1;
  } catch {
    if (transactionStarted && client) {
      await client.query("ROLLBACK").catch(() => undefined);
      transactionStarted = false;
    }
    const report = createDevelopmentRlsCatalogReport({
      generatedAt: new Date().toISOString(),
      databaseNameMatched,
      transactionReadOnly,
      runtimeLoginAuthenticated,
      postgresMajor,
      refusalCode: client ? "catalog_query_failed" : "runtime_connection_unavailable",
    });
    process.stdout.write(`${JSON.stringify(report)}\n`);
    process.exitCode = 1;
  } finally {
    client?.release();
    await pool?.end().catch(() => undefined);
  }
}

if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  void main();
}
