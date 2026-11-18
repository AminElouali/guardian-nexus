import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import type { PoolClient } from "pg";
import {
  expectedRlsTableNames,
  appendOnlyRlsTableNames,
} from "@workspace/db/rls-catalog-contract";
import {
  parseRlsCatalogContract,
  type RlsCatalogSnapshot,
} from "@workspace/db/rls-catalog-audit";
import {
  deriveRlsCatalogPhaseSnapshot,
  readRlsCatalogPhaseSnapshot,
  type RlsCatalogPhaseSnapshot,
} from "@workspace/db/rls-catalog-phase-audit";
import {
  createDevelopmentCatalogReadProgress,
  auditDevelopmentRlsCatalog,
  createDevelopmentCatalogQueryRunner,
  developmentCatalogObjectInventoryFromRows,
  type DevelopmentCatalogObjectInventory,
  createDevelopmentRlsCatalogReport,
  parseDevelopmentRlsAuditArguments,
  SafeCatalogQueryError,
} from "./development-rls-catalog-audit";
import { readCatalogSnapshot } from "../scripts/verify-rls-catalog";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../../",
);
const schemaDirectory = path.join(repositoryRoot, "lib/db/src/schema");
const contract = parseRlsCatalogContract({
  schemaFiles: readdirSync(schemaDirectory)
    .filter((name) => name.endsWith(".ts"))
    .sort()
    .map((name) => ({
      path: name,
      content: readFileSync(path.join(schemaDirectory, name), "utf8"),
    })),
  rolesSource: readFileSync(path.join(schemaDirectory, "roles.ts"), "utf8"),
  bootstrapSource: readFileSync(
    path.join(repositoryRoot, "lib/db/scripts/bootstrap-runtime-role.mjs"),
    "utf8",
  ),
  policiesSql: readFileSync(
    path.join(repositoryRoot, "lib/db/sql/rls-policies.sql"),
    "utf8",
  ),
});

function roleReachable(
  memberRole: string,
  targetRole: string,
  inheritOnly: boolean,
): boolean {
  if (memberRole === targetRole) return true;
  const visited = new Set([memberRole]);
  const pending = [memberRole];
  while (pending.length) {
    const current = pending.shift()!;
    for (const edge of contract.memberships) {
      if (
        edge.memberRole !== current ||
        (inheritOnly && !edge.inheritOption) ||
        visited.has(edge.grantedRole)
      ) continue;
      if (edge.grantedRole === targetRole) return true;
      visited.add(edge.grantedRole);
      pending.push(edge.grantedRole);
    }
  }
  return false;
}

function makeSnapshots(): {
  phaseSnapshot: RlsCatalogPhaseSnapshot;
  catalogSnapshot: RlsCatalogSnapshot;
  appendOnlyGrantRows: Record<string, unknown>[];
  objectInventory: DevelopmentCatalogObjectInventory;
} {
  const phaseSnapshot = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const roleNames = Object.keys(contract.roles);
  const specialTables = [
    "ai_assessment_jobs",
    "host_boundary_attestation_challenges",
    "ai_assessment_approval_requests",
  ];
  const privileges = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;
  const catalogSnapshot: RlsCatalogSnapshot = {
    tables: phaseSnapshot.tables.map((table) => ({
      tableName: table.tableName,
      owner: table.owner,
      rlsEnabled: table.rlsEnabled,
      rlsForced: table.rlsForced,
    })),
    policies: phaseSnapshot.policies,
    roles: phaseSnapshot.roles,
    memberships: phaseSnapshot.memberships,
    pgHasRole: roleNames.flatMap((memberRole) =>
      roleNames.map((targetRole) => ({
        memberRole,
        targetRole,
        member: roleReachable(memberRole, targetRole, false),
        usage: roleReachable(memberRole, targetRole, true),
      })),
    ),
    tablePrivileges: roleNames.flatMap((roleName) =>
      expectedRlsTableNames.flatMap((tableName) =>
        privileges.map((privilege) => ({
          roleName,
          tableName,
          privilege,
          granted: contract.grants.some((grant) =>
            grant.roleName === roleName &&
            grant.tableName === tableName &&
            grant.privilege === privilege &&
            grant.columns === undefined
          ),
        })),
      ),
    ),
    updateColumns: roleNames.flatMap((roleName) =>
      phaseSnapshot.columns
        .filter((column) => specialTables.includes(column.tableName))
        .map((column) => {
          const grant = contract.grants.find((candidate) =>
            candidate.roleName === roleName &&
            candidate.tableName === column.tableName &&
            candidate.privilege === "UPDATE"
          );
          return {
            roleName,
            tableName: column.tableName,
            columnName: column.columnName,
            granted: grant !== undefined &&
              (grant.columns === undefined ||
                grant.columns.includes(column.columnName)),
          };
        }),
    ),
    tableColumns: specialTables.map((tableName) => ({
      tableName,
      columnNames: phaseSnapshot.columns
        .filter((column) => column.tableName === tableName)
        .map((column) => column.columnName),
    })),
  };
  const appendOnlyGrantRows = appendOnlyRlsTableNames.map((table_name) => ({
    table_name,
    can_select: true,
    can_insert: true,
    can_update: false,
    can_delete: false,
    can_truncate: false,
    can_references: false,
    can_trigger: false,
    can_maintain: false,
    maintain_supported: false,
    column_update: false,
    column_references: false,
  }));
  const objectInventory: DevelopmentCatalogObjectInventory = {
    tables: phaseSnapshot.tables.map((table) =>
      `${table.schemaName}.${table.tableName}`
    ),
    indexes: phaseSnapshot.indexes.map((index) =>
      `${index.tableName}.${index.indexName}`
    ),
    constraints: phaseSnapshot.constraints.map((constraint) =>
      `${constraint.tableName}.${constraint.constraintName}`
    ),
    policies: phaseSnapshot.policies.map((policy) =>
      `${policy.tableName}.${policy.policyName}`
    ),
  };
  return {
    phaseSnapshot,
    catalogSnapshot,
    appendOnlyGrantRows,
    objectInventory,
  };
}

test("development RLS audit accepts the complete canonical catalog snapshot", () => {
  const snapshots = makeSnapshots();
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, true, audit.violationCodes.join(","));
  assert.equal(audit.expectedTableCount, 16);
  assert.equal(audit.expectedColumnCount, 173);
  assert.equal(audit.expectedIndexCount, 44);
  assert.equal(audit.expectedConstraintCount, 71);
  assert.equal(audit.expectedPolicyCount, 45);
  assert.equal(audit.expectedRoleCount, 3);
});

test("development RLS audit fails when the approval ledger is missing", () => {
  const snapshots = makeSnapshots();
  snapshots.phaseSnapshot.tables = snapshots.phaseSnapshot.tables.filter(
    (table) => table.tableName !== "workspace_approval_ledger",
  );
  snapshots.catalogSnapshot.tables =
    snapshots.catalogSnapshot.tables.filter(
      (table) => table.tableName !== "workspace_approval_ledger",
    );
  snapshots.objectInventory.tables = snapshots.objectInventory.tables.filter(
    (name) => name !== "public.workspace_approval_ledger",
  );
  snapshots.objectInventory.indexes = snapshots.objectInventory.indexes.filter(
    (name) => !name.startsWith("workspace_approval_ledger."),
  );
  snapshots.objectInventory.constraints =
    snapshots.objectInventory.constraints.filter(
      (name) => !name.startsWith("workspace_approval_ledger."),
    );
  snapshots.objectInventory.policies = snapshots.objectInventory.policies.filter(
    (name) => !name.startsWith("workspace_approval_ledger."),
  );
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, false);
  assert.ok(audit.violationCodes.includes("table_missing"));
  assert.ok(audit.violationCodes.includes("index_missing"));
  assert.ok(audit.violationCodes.includes("constraint_missing"));
  assert.ok(audit.violationCodes.includes("policy_missing"));
  assert.deepEqual(audit.objectDiffs.missing.tables, [
    "public.workspace_approval_ledger",
  ]);
  assert.ok(audit.objectDiffs.missing.indexes.length > 0);
  assert.ok(audit.objectDiffs.missing.constraints.length > 0);
  assert.ok(audit.objectDiffs.missing.policies.length > 0);
  assert.ok(audit.violationCodes.includes("table_inventory_mismatch"));
  assert.ok(audit.violationCodes.includes("protected_table_set_mismatch"));
});

test("missing ledger is listed while catalog and privilege reads complete", async () => {
  const source = makeSnapshots();
  source.phaseSnapshot.tables = source.phaseSnapshot.tables.filter(
    (table) => table.tableName !== "workspace_approval_ledger",
  );
  source.phaseSnapshot.columns = source.phaseSnapshot.columns.filter(
    (column) => column.tableName !== "workspace_approval_ledger",
  );
  source.phaseSnapshot.indexes = source.phaseSnapshot.indexes.filter(
    (index) => index.tableName !== "workspace_approval_ledger",
  );
  source.phaseSnapshot.constraints =
    source.phaseSnapshot.constraints.filter(
      (constraint) => constraint.tableName !== "workspace_approval_ledger",
    );
  source.phaseSnapshot.policies = source.phaseSnapshot.policies.filter(
    (policy) => policy.tableName !== "workspace_approval_ledger",
  );
  source.catalogSnapshot.tables = source.catalogSnapshot.tables.filter(
    (table) => table.tableName !== "workspace_approval_ledger",
  );
  source.catalogSnapshot.tablePrivileges =
    source.catalogSnapshot.tablePrivileges.map((privilege) =>
      privilege.tableName === "workspace_approval_ledger"
        ? { ...privilege, granted: false }
        : privilege
    );
  source.catalogSnapshot.updateColumns =
    source.catalogSnapshot.updateColumns.filter(
      (column) => column.tableName !== "workspace_approval_ledger",
    );
  source.catalogSnapshot.tableColumns =
    source.catalogSnapshot.tableColumns.filter(
      (table) => table.tableName !== "workspace_approval_ledger",
    );
  source.objectInventory.tables = source.objectInventory.tables.filter(
    (name) => name !== "public.workspace_approval_ledger",
  );
  source.objectInventory.indexes = source.objectInventory.indexes.filter(
    (name) => !name.startsWith("workspace_approval_ledger."),
  );
  source.objectInventory.constraints =
    source.objectInventory.constraints.filter(
      (name) => !name.startsWith("workspace_approval_ledger."),
    );
  source.objectInventory.policies = source.objectInventory.policies.filter(
    (name) => !name.startsWith("workspace_approval_ledger."),
  );

  const calls: string[] = [];
  const pendingResults = [
    { rows: [], rowCount: 0 },
    { rows: [{ database_name: "synthetic", read_only: "on" }], rowCount: 1 },
    { rows: source.phaseSnapshot.tables, rowCount: source.phaseSnapshot.tables.length },
    { rows: source.phaseSnapshot.columns, rowCount: source.phaseSnapshot.columns.length },
    { rows: source.phaseSnapshot.indexes, rowCount: source.phaseSnapshot.indexes.length },
    { rows: source.phaseSnapshot.constraints, rowCount: source.phaseSnapshot.constraints.length },
    { rows: source.phaseSnapshot.policies, rowCount: source.phaseSnapshot.policies.length },
    { rows: source.phaseSnapshot.roles, rowCount: source.phaseSnapshot.roles.length },
    { rows: source.phaseSnapshot.memberships, rowCount: source.phaseSnapshot.memberships.length },
    { rows: [{ maxIdentifierLength: source.phaseSnapshot.maxIdentifierLength }], rowCount: 1 },
    {
      rows: [
        ...source.objectInventory.tables.map((name) => {
          const [schemaName, objectName] = name.split(".");
          return { kind: "tables", schemaName, tableName: objectName, objectName };
        }),
        ...source.objectInventory.indexes.map((name) => {
          const [tableName, objectName] = name.split(".");
          return { kind: "indexes", schemaName: "public", tableName, objectName };
        }),
        ...source.objectInventory.constraints.map((name) => {
          const [tableName, objectName] = name.split(".");
          return { kind: "constraints", schemaName: "public", tableName, objectName };
        }),
        ...source.objectInventory.policies.map((name) => {
          const [tableName, objectName] = name.split(".");
          return { kind: "policies", schemaName: "public", tableName, objectName };
        }),
      ],
      rowCount: 0,
    },
    { rows: source.catalogSnapshot.tables, rowCount: source.catalogSnapshot.tables.length },
    { rows: source.catalogSnapshot.policies, rowCount: source.catalogSnapshot.policies.length },
    { rows: source.catalogSnapshot.roles, rowCount: source.catalogSnapshot.roles.length },
    { rows: source.catalogSnapshot.memberships, rowCount: source.catalogSnapshot.memberships.length },
    { rows: source.catalogSnapshot.pgHasRole, rowCount: source.catalogSnapshot.pgHasRole.length },
    {
      rows: source.catalogSnapshot.tablePrivileges,
      rowCount: source.catalogSnapshot.tablePrivileges.length,
    },
    { rows: source.catalogSnapshot.updateColumns, rowCount: source.catalogSnapshot.updateColumns.length },
    { rows: source.catalogSnapshot.tableColumns, rowCount: source.catalogSnapshot.tableColumns.length },
    { rows: [{ version: 160000 }], rowCount: 1 },
    {
      rows: [{
        table_name: "workspace_approval_ledger",
        can_select: false,
        can_insert: false,
        can_update: false,
        can_delete: false,
        can_truncate: false,
        can_references: false,
        can_trigger: false,
        can_maintain: false,
        maintain_supported: false,
        column_update: false,
        column_references: false,
      }],
      rowCount: 1,
    },
    { rows: [], rowCount: 0 },
  ];
  const client = {
    async query(sql: string) {
      calls.push(sql);
      const result = pendingResults.shift();
      assert.ok(result, "the read-only audit should complete every catalog query");
      return result;
    },
  };
  const pgClient = client as unknown as Pick<PoolClient, "query">;
  const progress = createDevelopmentCatalogReadProgress();
  const query = createDevelopmentCatalogQueryRunner(pgClient, progress);
  await query("transaction", "BEGIN TRANSACTION READ ONLY");
  await query("identity", "SELECT current_database()");
  const phase = await readRlsCatalogPhaseSnapshot(
    pgClient,
    expectedRlsTableNames,
    Object.keys(contract.roles),
    query,
  );
  const objectRows = await query("object_inventory", "SELECT public catalog names");
  const objectInventory = developmentCatalogObjectInventoryFromRows(
    objectRows.rows,
  );
  const { snapshot, postgresMajor } = await readCatalogSnapshot(
    pgClient,
    expectedRlsTableNames,
    Object.keys(contract.roles),
    query,
  );
  const appendOnlyGrantRows = await query(
    "append_only_privileges",
    "SELECT append-only privilege matrix",
  );
  await query("transaction", "COMMIT");

  const privilegeSql = calls.find((sql) => sql.includes("has_table_privilege"));
  assert.match(privilegeSql ?? "", /to_regclass/);
  assert.equal(postgresMajor, 16);
  assert.equal(
    snapshot.tablePrivileges.filter((row) =>
      row.tableName === "workspace_approval_ledger"
    ).every((row) => !row.granted),
    true,
  );
  const audit = auditDevelopmentRlsCatalog({
    contract,
    phaseSnapshot: phase,
    catalogSnapshot: snapshot,
    appendOnlyGrantRows: appendOnlyGrantRows.rows,
    objectInventory,
  });
  assert.ok(audit.violationCodes.includes("table_missing"));
  assert.deepEqual(audit.objectDiffs.missing.tables, [
    "public.workspace_approval_ledger",
  ]);
  assert.ok(audit.privilegeDifferences.length > 0);
  assert.equal(
    audit.privilegeDifferences.every(
      (difference) => difference.table === "workspace_approval_ledger",
    ),
    true,
  );
  assert.ok(progress.completedSteps.includes("columns"));
  assert.ok(progress.completedSteps.includes("privileges"));
  assert.ok(progress.completedSteps.includes("append_only_privileges"));
  assert.equal(pendingResults.length, 0);
});

test("development RLS audit fails if runtime receives table-level UPDATE", () => {
  const snapshots = makeSnapshots();
  const update = snapshots.catalogSnapshot.tablePrivileges.find((item) =>
    item.roleName === "app_runtime" &&
    item.tableName === "workspace_approval_ledger" &&
    item.privilege === "UPDATE"
  );
  assert.ok(update);
  update.granted = true;
  snapshots.appendOnlyGrantRows[0]!.can_update = true;
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, false);
  assert.ok(
    audit.violationCodes.includes("append_only_runtime_privilege_mismatch"),
  );
  assert.ok(
    audit.violationCodes.includes("table_privilege_mismatch"),
  );
});

test("safe report identifies privilege differences only with contract names", () => {
  const snapshots = makeSnapshots();
  const update = snapshots.catalogSnapshot.tablePrivileges.find((item) =>
    item.roleName === "app_runtime" &&
    item.tableName === "workspace_memberships" &&
    item.privilege === "UPDATE"
  );
  assert.ok(update);
  const expectedGranted = contract.grants.some((grant) =>
    grant.roleName === "app_runtime" &&
    grant.tableName === "workspace_memberships" &&
    grant.privilege === "UPDATE" &&
    grant.columns === undefined
  );
  update.granted = !expectedGranted;
  snapshots.catalogSnapshot.tablePrivileges.push({
    roleName: "private_role_sentinel",
    tableName: "private_table_sentinel",
    privilege: "SELECT",
    granted: true,
  });

  const audit = auditDevelopmentRlsCatalog({
    contract,
    ...snapshots,
  });
  assert.ok(
    audit.privilegeDifferences.some((difference) =>
      difference.role === "app_runtime" &&
      difference.table === "workspace_memberships" &&
      difference.privilege === "UPDATE" &&
      difference.scope === "table" &&
      difference.expectedGranted === expectedGranted &&
      difference.actualGranted === !expectedGranted
    ),
  );
  assert.equal(
    audit.privilegeDifferences.some((difference) =>
      difference.role === "private_role_sentinel" ||
      difference.table === "private_table_sentinel"
    ),
    false,
  );
  const report = createDevelopmentRlsCatalogReport({
    audit,
    expectedCounts: {
      tables: audit.expectedTableCount,
      columns: audit.expectedColumnCount,
      indexes: audit.expectedIndexCount,
      constraints: audit.expectedConstraintCount,
      policies: audit.expectedPolicyCount,
      roles: audit.expectedRoleCount,
    },
    generatedAt: "2026-11-17T00:00:00.000Z",
    databaseNameMatched: true,
    transactionReadOnly: true,
    runtimeLoginAuthenticated: true,
    postgresMajor: 16,
  });
  const serialized = JSON.stringify(report);
  assert.match(serialized, /"role":"app_runtime"/);
  assert.match(serialized, /"table":"workspace_memberships"/);
  assert.match(serialized, /"privilege":"UPDATE"/);
  assert.doesNotMatch(
    serialized,
    /private_role_sentinel|private_table_sentinel/,
  );
});

test("development RLS audit fails when FORCE ROW LEVEL SECURITY is absent", () => {
  const snapshots = makeSnapshots();
  const ledger = snapshots.phaseSnapshot.tables.find(
    (table) => table.tableName === "workspace_approval_ledger",
  );
  assert.ok(ledger);
  ledger.rlsForced = false;
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, false);
  assert.ok(audit.violationCodes.includes("table_rls_not_forced"));
});

test("catalog object comparison lists unexpected public object names", () => {
  const snapshots = makeSnapshots();
  snapshots.objectInventory.tables.push("public.unexpected_table");
  snapshots.objectInventory.indexes.push(
    "workspace_memberships.unexpected_index",
  );
  snapshots.objectInventory.constraints.push(
    "workspace_memberships.unexpected_constraint",
  );
  snapshots.objectInventory.policies.push(
    "workspace_memberships.unexpected_policy",
  );
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, false);
  assert.deepEqual(audit.objectDiffs.unexpected, {
    tables: ["public.unexpected_table"],
    indexes: ["workspace_memberships.unexpected_index"],
    constraints: ["workspace_memberships.unexpected_constraint"],
    policies: ["workspace_memberships.unexpected_policy"],
  });
  assert.ok(audit.violationCodes.includes("table_unexpected"));
  assert.ok(audit.violationCodes.includes("index_unexpected"));
  assert.ok(audit.violationCodes.includes("constraint_unexpected"));
  assert.ok(audit.violationCodes.includes("policy_unexpected"));
});

test("development RLS audit flags an outdated approval provenance constraint", () => {
  const snapshots = makeSnapshots();
  const expectedConstraint = snapshots.phaseSnapshot.constraints.find(
    (constraint) =>
      constraint.constraintName === "ai_assessment_approval_provenance_check",
  );
  assert.ok(expectedConstraint?.expression);
  assert.match(
    expectedConstraint.expression,
    /real_openai_compatible_qwen_inference/,
  );
  const actualConstraint = snapshots.phaseSnapshot.constraints.find(
    (constraint) =>
      constraint.constraintName === "ai_assessment_approval_provenance_check",
  );
  assert.ok(actualConstraint);
  actualConstraint.expression = "model_inference IS NULL";
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.provenanceConstraintOutdated, true);
  assert.ok(audit.violationCodes.includes("provenance_constraint_outdated"));
});

test("read-only audit CLI requires explicit confirmation and a database name", () => {
  assert.deepEqual(
    parseDevelopmentRlsAuditArguments([]),
    { ok: false, code: "read_only_confirmation_required" },
  );
  assert.deepEqual(
    parseDevelopmentRlsAuditArguments(["--confirm-read-only"]),
    { ok: false, code: "expected_database_required" },
  );
  assert.deepEqual(
    parseDevelopmentRlsAuditArguments([
      "--confirm-read-only",
      "--expected-database=guardian_dev",
    ]),
    { ok: true, expectedDatabase: "guardian_dev" },
  );
  assert.deepEqual(
    parseDevelopmentRlsAuditArguments([
      "--",
      "--confirm-read-only",
      "--expected-database=guardian_dev",
    ]),
    { ok: true, expectedDatabase: "guardian_dev" },
  );
  assert.equal(
    parseDevelopmentRlsAuditArguments([
      "--confirm-read-only",
      "--expected-database=guardian_dev",
      "--allow-write",
    ]).ok,
    false,
  );
});

test("read-only audit report exposes only safe status, counts, and fixed codes", () => {
  const snapshots = makeSnapshots();
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  const report = createDevelopmentRlsCatalogReport({
    audit,
    expectedCounts: {
      tables: audit.expectedTableCount,
      columns: audit.expectedColumnCount,
      indexes: audit.expectedIndexCount,
      constraints: audit.expectedConstraintCount,
      policies: audit.expectedPolicyCount,
      roles: audit.expectedRoleCount,
    },
    generatedAt: "2026-11-16T00:00:00.000Z",
    databaseNameMatched: true,
    transactionReadOnly: true,
    runtimeLoginAuthenticated: true,
    postgresMajor: 16,
  });
  assert.equal(report.status, "passed");
  assert.equal(report.applicationRowsRead, false);
  assert.equal(report.credentialsIncluded, false);
  assert.equal(report.connectionCoordinatesIncluded, false);
  assert.deepEqual(report.expected, {
    tables: 16,
    columns: 173,
    indexes: 44,
    constraints: 71,
    policies: 45,
    roles: 3,
  });
  assert.deepEqual(report.actual, {
    tables: 16,
    columns: 173,
    indexes: 44,
    constraints: 71,
    policies: 45,
    roles: 3,
  });
  assert.deepEqual(report.violationCodes, []);
  assert.deepEqual(report.privilegeDifferences, []);
  assert.doesNotMatch(JSON.stringify(report), /postgresql:|password|secret|localhost/i);
});

test("catalog failure reports its fixed step and sanitized SQLSTATE with prior counts", async () => {
  const progress = createDevelopmentCatalogReadProgress();
  const issuedQueries: string[] = [];
  const privateObjectName = "private_catalog_object_sentinel";
  const client = {
    async query(sql: string) {
      issuedQueries.push(sql);
      if (sql.includes("pg_auth_members")) {
        throw Object.assign(
          new Error(`permission denied for ${privateObjectName}`),
          { code: "42501" },
        );
      }
      if (sql.includes("relrowsecurity")) {
        return { rows: [], rowCount: 16 };
      }
      if (sql.includes("format_type(")) {
        return { rows: [], rowCount: 173 };
      }
      return { rows: [], rowCount: 0 };
    },
  };
  const query = createDevelopmentCatalogQueryRunner(
    client as unknown as Pick<PoolClient, "query">,
    progress,
  );
  await query(
    "rls_flags",
    "SELECT relrowsecurity FROM pg_class",
  );
  await query(
    "columns",
    "SELECT format_type(atttypid, atttypmod) FROM pg_attribute " +
      "WHERE EXISTS (SELECT 1 FROM pg_constraint)",
  );
  let failure: SafeCatalogQueryError | undefined;
  await assert.rejects(
    query("memberships", "SELECT * FROM pg_auth_members"),
    (error) => {
      assert.ok(error instanceof SafeCatalogQueryError);
      failure = error;
      assert.deepEqual(error.failure, {
        step: "memberships",
        sqlState: "42501",
        errorClass: "insufficient_privilege",
      });
      return true;
    },
  );
  await assert.rejects(
    query("roles", "SELECT * FROM pg_roles"),
    (error) => error instanceof SafeCatalogQueryError &&
      error.failure.step === "memberships",
  );
  assert.equal(issuedQueries.length, 3);
  assert.deepEqual(progress.completedSteps, ["rls_flags", "columns"]);
  assert.deepEqual(progress.actual, {
    tables: 16,
    columns: 173,
    indexes: null,
    constraints: null,
    policies: null,
    roles: null,
  });
  assert.ok(failure);
  const report = createDevelopmentRlsCatalogReport({
    expectedCounts: {
      tables: 16,
      columns: 173,
      indexes: 44,
      constraints: 71,
      policies: 45,
      roles: 3,
    },
    progress,
    failedQuery: failure.failure,
    generatedAt: "2026-11-16T00:00:00.000Z",
    databaseNameMatched: true,
    transactionReadOnly: true,
    runtimeLoginAuthenticated: true,
    postgresMajor: 16,
    refusalCode: "catalog_query_failed",
  });
  const serialized = JSON.stringify(report);
  assert.equal(report.expected.roles, 3);
  assert.deepEqual(report.failedQuery, {
    step: "memberships",
    sqlState: "42501",
    errorClass: "insufficient_privilege",
  });
  assert.match(serialized, /"completedSteps":\["rls_flags","columns"\]/);
  assert.doesNotMatch(serialized, /permission denied|private_catalog_object_sentinel/);
});
