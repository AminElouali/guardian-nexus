import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { expectedRlsTableNames } from "@workspace/db/rls-catalog-contract";
import {
  auditRlsCatalog,
  parseRlsCatalogContract,
  type RlsCatalogSnapshot,
} from "@workspace/db/rls-catalog-audit";
import { isGitHubActionsApprovalLabTarget } from "../lib/approval-e2e-db-guard";

const { Pool } = pg;
const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(scriptDirectory, "../../../../");
const specialUpdateTables = [
  "ai_assessment_jobs",
  "host_boundary_attestation_challenges",
  "ai_assessment_approval_requests",
];
const privilegeNames = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

type QueryClient = Pick<pg.PoolClient, "query">;

async function loadContractSources() {
  const schemaDirectory = path.join(repositoryRoot, "lib/db/src/schema");
  const schemaFileNames = (await readdir(schemaDirectory))
    .filter((name) => name.endsWith(".ts"))
    .sort();
  const schemaFiles = await Promise.all(
    schemaFileNames.map(async (name) => ({
      path: name,
      content: await readFile(path.join(schemaDirectory, name), "utf8"),
    })),
  );
  const [rolesSource, bootstrapSource, policiesSql, rlsContractSource] =
    await Promise.all([
      readFile(path.join(schemaDirectory, "roles.ts"), "utf8"),
      readFile(
        path.join(repositoryRoot, "lib/db/scripts/bootstrap-runtime-role.mjs"),
        "utf8",
      ),
      readFile(
        path.join(repositoryRoot, "lib/db/sql/rls-policies.sql"),
        "utf8",
      ),
      readFile(
        path.join(repositoryRoot, "lib/db/src/rls-catalog-contract.ts"),
        "utf8",
      ),
    ]);
  return {
    schemaFiles,
    rolesSource,
    bootstrapSource,
    policiesSql,
    rlsContractSource,
  };
}

async function readCatalogSnapshot(
  client: QueryClient,
  tableNames: string[],
  roleNames: string[],
): Promise<{ snapshot: RlsCatalogSnapshot; postgresMajor: number }> {
  const [
    tableResult,
    policyResult,
    roleResult,
    membershipResult,
    pgHasRoleResult,
    privilegeResult,
    updateResult,
    columnResult,
    versionResult,
  ] = await Promise.all([
    client.query(
      `SELECT c.relname AS "tableName",
                pg_get_userbyid(c.relowner) AS owner,
                c.relrowsecurity AS "rlsEnabled",
                c.relforcerowsecurity AS "rlsForced"
           FROM pg_class AS c
           JOIN pg_namespace AS n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public'
            AND c.relname = ANY($1::text[])
            AND c.relkind IN ('r', 'p')
          ORDER BY c.relname`,
      [tableNames],
    ),
    client.query(
      `SELECT tablename AS "tableName",
                policyname AS "policyName",
                permissive,
                cmd AS command,
                roles,
                qual,
                with_check AS "withCheck"
           FROM pg_policies
          WHERE schemaname = 'public'
            AND tablename = ANY($1::text[])
          ORDER BY tablename, policyname`,
      [tableNames],
    ),
    client.query(
      `SELECT rolname AS "roleName",
                rolsuper, rolbypassrls, rolcanlogin, rolcreatedb,
                rolcreaterole, rolreplication, rolinherit
           FROM pg_roles
          WHERE rolname = ANY($1::text[])
          ORDER BY rolname`,
      [roleNames],
    ),
    client.query(
      `SELECT granted.rolname AS "grantedRole",
                member.rolname AS "memberRole",
                membership.admin_option AS "adminOption",
                membership.inherit_option AS "inheritOption",
                membership.set_option AS "setOption"
           FROM pg_auth_members AS membership
           JOIN pg_roles AS granted ON granted.oid = membership.roleid
           JOIN pg_roles AS member ON member.oid = membership.member
          WHERE granted.rolname = ANY($1::text[])
             OR member.rolname = ANY($1::text[])
          ORDER BY granted.rolname, member.rolname`,
      [roleNames],
    ),
    client.query(
      `SELECT member.rolname AS "memberRole",
                target.rolname AS "targetRole",
                pg_has_role(member.oid, target.oid, 'MEMBER') AS member,
                pg_has_role(member.oid, target.oid, 'USAGE') AS usage
           FROM pg_roles AS member
           CROSS JOIN pg_roles AS target
          WHERE member.rolname = ANY($1::text[])
            AND target.rolname = ANY($1::text[])
          ORDER BY member.rolname, target.rolname`,
      [roleNames],
    ),
    client.query(
      `SELECT role.rolname AS "roleName",
                table_names.table_name AS "tableName",
                privilege.name AS privilege,
                has_table_privilege(
                  role.oid,
                  format('public.%I', table_names.table_name),
                  privilege.name
                ) AS granted
           FROM pg_roles AS role
           CROSS JOIN unnest($1::text[]) AS table_names(table_name)
           CROSS JOIN unnest($2::text[]) AS privilege(name)
          WHERE role.rolname = ANY($3::text[])
          ORDER BY role.rolname, table_names.table_name, privilege.name`,
      [tableNames, privilegeNames, roleNames],
    ),
    client.query(
      `SELECT role.rolname AS "roleName",
                c.relname AS "tableName",
                attribute.attname AS "columnName",
                has_column_privilege(
                  role.oid, c.oid, attribute.attnum, 'UPDATE'
                ) AS granted
           FROM pg_roles AS role
           CROSS JOIN pg_class AS c
           JOIN pg_namespace AS n ON n.oid = c.relnamespace
           JOIN pg_attribute AS attribute ON attribute.attrelid = c.oid
          WHERE role.rolname = ANY($1::text[])
            AND n.nspname = 'public'
            AND c.relname = ANY($2::text[])
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
          ORDER BY role.rolname, c.relname, attribute.attnum`,
      [roleNames, specialUpdateTables],
    ),
    client.query(
      `SELECT c.relname AS "tableName",
                array_agg(attribute.attname ORDER BY attribute.attnum) AS "columnNames"
           FROM pg_class AS c
           JOIN pg_namespace AS n ON n.oid = c.relnamespace
           JOIN pg_attribute AS attribute ON attribute.attrelid = c.oid
          WHERE n.nspname = 'public'
            AND c.relname = ANY($1::text[])
            AND attribute.attnum > 0
            AND NOT attribute.attisdropped
          GROUP BY c.relname
          ORDER BY c.relname`,
      [specialUpdateTables],
    ),
    client.query(
      `SELECT current_setting('server_version_num')::integer AS version`,
    ),
  ]);

  const roles = roleResult.rows.map((row) => ({
    roleName: String(row.roleName),
    rolsuper: Boolean(row.rolsuper),
    rolbypassrls: Boolean(row.rolbypassrls),
    rolcanlogin: Boolean(row.rolcanlogin),
    rolcreatedb: Boolean(row.rolcreatedb),
    rolcreaterole: Boolean(row.rolcreaterole),
    rolreplication: Boolean(row.rolreplication),
    rolinherit: Boolean(row.rolinherit),
  }));

  const snapshot: RlsCatalogSnapshot = {
    tables: tableResult.rows.map((row) => ({
      tableName: String(row.tableName),
      owner: String(row.owner),
      rlsEnabled: Boolean(row.rlsEnabled),
      rlsForced: Boolean(row.rlsForced),
    })),
    policies: policyResult.rows.map((row) => ({
      tableName: String(row.tableName),
      policyName: String(row.policyName),
      permissive: String(row.permissive),
      command: String(row.command),
      roles: Array.isArray(row.roles) ? row.roles.map(String) : [],
      qual: row.qual === null ? null : String(row.qual),
      withCheck: row.withCheck === null ? null : String(row.withCheck),
    })),
    roles,
    memberships: membershipResult.rows.map((row) => ({
      grantedRole: String(row.grantedRole),
      memberRole: String(row.memberRole),
      adminOption: Boolean(row.adminOption),
      inheritOption: Boolean(row.inheritOption),
      setOption: Boolean(row.setOption),
    })),
    pgHasRole: pgHasRoleResult.rows.map((row) => ({
      memberRole: String(row.memberRole),
      targetRole: String(row.targetRole),
      member: Boolean(row.member),
      usage: Boolean(row.usage),
    })),
    tablePrivileges: privilegeResult.rows.map((row) => ({
      roleName: String(row.roleName),
      tableName: String(row.tableName),
      privilege: String(row.privilege) as (typeof privilegeNames)[number],
      granted: Boolean(row.granted),
    })),
    updateColumns: updateResult.rows.map((row) => ({
      roleName: String(row.roleName),
      tableName: String(row.tableName),
      columnName: String(row.columnName),
      granted: Boolean(row.granted),
    })),
    tableColumns: columnResult.rows.map((row) => ({
      tableName: String(row.tableName),
      columnNames: Array.isArray(row.columnNames)
        ? row.columnNames.map(String)
        : [],
    })),
  };

  const version = Number(versionResult.rows[0]?.version);
  return { snapshot, postgresMajor: Math.floor(version / 10000) };
}

async function writeReport(report: Record<string, unknown>): Promise<void> {
  const runnerTemporaryDirectory = process.env.RUNNER_TEMP;
  if (!runnerTemporaryDirectory) {
    throw new Error("CI runner report directory is unavailable.");
  }
  const reportPath = path.resolve(
    runnerTemporaryDirectory,
    "guardian-postgres-rls-catalog-report.json",
  );
  if (
    !reportPath.startsWith(
      `${path.resolve(runnerTemporaryDirectory)}${path.sep}`,
    )
  ) {
    throw new Error("CI runner report path is invalid.");
  }
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
}

async function main(): Promise<void> {
  if (!(await isGitHubActionsApprovalLabTarget(process.env, "approval-e2e"))) {
    console.error(
      "RLS catalog audit refused: CI disposable-target contract not met.",
    );
    process.exitCode = 1;
    return;
  }

  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    console.error(
      "RLS catalog audit refused: guarded CI target is incomplete.",
    );
    process.exitCode = 1;
    return;
  }
  if (!process.env.RUNNER_TEMP) {
    console.error(
      "RLS catalog audit refused: CI runner report directory is unavailable.",
    );
    process.exitCode = 1;
    return;
  }

  const reportBase = {
    reportVersion: 1,
    generatedAt: new Date().toISOString(),
    applicationRowsRead: false,
    credentialsIncluded: false,
    connectionCoordinatesIncluded: false,
    policySourceSha256: "",
    schemaSourceSha256: "",
    bootstrapSourceSha256: "",
    rlsContractSourceSha256: "",
    runtimePreflight: "omitted_catalog_only_audit",
    postgresMajor: null as number | null,
  };
  const pool = new Pool({
    connectionString: databaseUrl,
    max: 1,
    connectionTimeoutMillis: 5000,
    statement_timeout: 10000,
  });
  let report: Record<string, unknown> = { ...reportBase, status: "failed" };

  try {
    const sources = await loadContractSources();
    const policySourceSha256 = createHash("sha256")
      .update(sources.policiesSql)
      .digest("hex");
    const schemaSourceSha256 = createHash("sha256")
      .update(sources.schemaFiles.map((file) => file.content).join("\n"))
      .digest("hex");
    const bootstrapSourceSha256 = createHash("sha256")
      .update(sources.bootstrapSource)
      .digest("hex");
    const rlsContractSourceSha256 = createHash("sha256")
      .update(sources.rlsContractSource)
      .digest("hex");
    const contract = parseRlsCatalogContract(sources);
    const roleNames = Object.keys(contract.roles).sort();
    const { snapshot, postgresMajor } = await readCatalogSnapshot(
      pool,
      expectedRlsTableNames.map(String),
      roleNames,
    );
    const audit = auditRlsCatalog(contract, snapshot);

    report = {
      ...reportBase,
      generatedAt: new Date().toISOString(),
      policySourceSha256,
      schemaSourceSha256,
      bootstrapSourceSha256,
      rlsContractSourceSha256,
      postgresMajor,
      status: audit.passed ? "passed" : "failed",
      catalogAudit: audit,
    };
    await writeReport(report);
    if (report.status !== "passed") {
      console.error(
        "RLS catalog audit failed; inspect the sanitized job artifact.",
      );
      process.exitCode = 1;
      return;
    }
    console.log(
      `RLS catalog audit passed: ${audit.expectedTableCount} tables, ${audit.expectedPolicyCount} policies; sanitized artifact written.`,
    );
  } catch {
    report = {
      ...reportBase,
      generatedAt: new Date().toISOString(),
      status: "failed",
      failureCode: "catalog_audit_internal_or_query_failure",
    };
    await writeReport(report);
    console.error(
      "RLS catalog audit failed; inspect the sanitized job artifact.",
    );
    process.exitCode = 1;
  } finally {
    await pool.end().catch(() => undefined);
  }
}

void main();
