import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
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
  type RlsCatalogPhaseSnapshot,
} from "@workspace/db/rls-catalog-phase-audit";
import {
  createDevelopmentCatalogReadProgress,
  auditDevelopmentRlsCatalog,
  createDevelopmentRlsCatalogReport,
  monitorDevelopmentCatalogReads,
  parseDevelopmentRlsAuditArguments,
  SafeCatalogQueryError,
} from "./development-rls-catalog-audit";

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
  return { phaseSnapshot, catalogSnapshot, appendOnlyGrantRows };
}

test("development RLS audit accepts the complete canonical catalog snapshot", () => {
  const snapshots = makeSnapshots();
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, true, audit.violationCodes.join(","));
  assert.equal(audit.expectedTableCount, 13);
  assert.equal(audit.expectedColumnCount, 149);
  assert.equal(audit.expectedIndexCount, 37);
  assert.equal(audit.expectedConstraintCount, 54);
  assert.equal(audit.expectedPolicyCount, 36);
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
  const audit = auditDevelopmentRlsCatalog({ contract, ...snapshots });
  assert.equal(audit.passed, false);
  assert.ok(audit.violationCodes.includes("table_inventory_mismatch"));
  assert.ok(audit.violationCodes.includes("protected_table_set_mismatch"));
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
    tables: 13,
    columns: 149,
    indexes: 37,
    constraints: 54,
    policies: 36,
    roles: 3,
  });
  assert.deepEqual(report.actual, {
    tables: 13,
    columns: 149,
    indexes: 37,
    constraints: 54,
    policies: 36,
    roles: 3,
  });
  assert.deepEqual(report.violationCodes, []);
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
        return { rows: [], rowCount: 13 };
      }
      if (sql.includes("format_type(")) {
        return { rows: [], rowCount: 149 };
      }
      return { rows: [], rowCount: 0 };
    },
  };
  const monitored = monitorDevelopmentCatalogReads(client, progress);
  await monitored.query(
    "SELECT relrowsecurity FROM pg_class",
  );
  await monitored.query(
    "SELECT format_type(atttypid, atttypmod) FROM pg_attribute",
  );
  let failure: SafeCatalogQueryError | undefined;
  await assert.rejects(
    monitored.query("SELECT * FROM pg_auth_members"),
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
    monitored.query("SELECT * FROM pg_roles"),
    (error) => error instanceof SafeCatalogQueryError &&
      error.failure.step === "memberships",
  );
  assert.equal(issuedQueries.length, 3);
  assert.deepEqual(progress.completedSteps, ["rls_flags", "columns"]);
  assert.deepEqual(progress.actual, {
    tables: 13,
    columns: 149,
    indexes: null,
    constraints: null,
    policies: null,
    roles: null,
  });
  assert.ok(failure);
  const report = createDevelopmentRlsCatalogReport({
    expectedCounts: {
      tables: 13,
      columns: 149,
      indexes: 37,
      constraints: 54,
      policies: 36,
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
