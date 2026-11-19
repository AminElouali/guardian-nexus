import {
  auditRlsCatalog,
  type RlsCatalogContract,
  type RlsCatalogSnapshot,
} from "@workspace/db/rls-catalog-audit";
import {
  auditRlsPostPushCatalog,
  deriveRlsCatalogPhaseSnapshot,
  type RlsCatalogQueryRunner,
  type RlsCatalogQueryStep,
  type RlsCatalogPhaseSnapshot,
} from "@workspace/db/rls-catalog-phase-audit";
import {
  appendOnlyRlsTableNames,
  expectedRlsTableNames,
} from "@workspace/db/rls-catalog-contract";
import { appendOnlyRuntimeGrantsAllowed } from "@workspace/db/rls-runtime-readiness";
import type { PoolClient } from "pg";

const safeViolationCodes = new Set([
  "append_only_runtime_privilege_mismatch",
  "read_only_confirmation_required",
  "expected_database_required",
  "invalid_arguments",
  "development_database_identity_mismatch",
  "runtime_login_identity_mismatch",
  "postgres_version_unsupported",
  "read_only_transaction_failed",
  "catalog_query_failed",
  "runtime_connection_unavailable",
  "protected_table_set_mismatch",
  "protected_table_owner_mismatch",
  "rls_not_enabled_and_forced",
  "policy_identity_or_count_mismatch",
  "policy_metadata_mismatch",
  "policy_predicate_shape_invalid",
  "policy_count_mismatch",
  "role_set_mismatch",
  "role_attribute_mismatch",
  "direct_role_membership_mismatch",
  "pg_has_role_mismatch",
  "table_privilege_mismatch",
  "table_privilege_matrix_incomplete",
  "column_update_mismatch",
  "column_insert_mismatch",
  "table_column_inventory_missing",
  "column_update_matrix_incomplete",
  "column_insert_matrix_incomplete",
  "table_inventory_mismatch",
  "column_inventory_mismatch",
  "constraint_columns_mismatch",
  "constraint_definition_mismatch",
  "constraint_flags_mismatch",
  "constraint_inventory_mismatch",
  "constraint_kind_mismatch",
  "constraint_on_delete_mismatch",
  "constraint_on_update_mismatch",
  "constraint_referenced_columns_mismatch",
  "constraint_reference_mismatch",
  "index_columns_mismatch",
  "index_definition_mismatch",
  "index_invalid",
  "index_inventory_mismatch",
  "index_method_mismatch",
  "index_predicate_mismatch",
  "index_uniqueness_mismatch",
  "policy_command_mismatch",
  "policy_identifier_collision",
  "policy_inventory_mismatch",
  "policy_permissive_mismatch",
  "policy_source_contract_mismatch",
  "policy_target_role_mismatch",
  "policy_using_expression_mismatch",
  "policy_with_check_expression_mismatch",
  "role_hardening_mismatch",
  "role_identifier_collision",
  "role_inventory_mismatch",
  "role_membership_mismatch",
  "table_missing",
  "table_unexpected",
  "index_missing",
  "index_unexpected",
  "constraint_missing",
  "constraint_unexpected",
  "policy_missing",
  "policy_unexpected",
  "provenance_constraint_outdated",
  "table_owner_mismatch",
  "table_rls_not_enabled",
  "table_rls_not_forced",
  "table_schema_mismatch",
]);

export type DevelopmentRlsCatalogAudit = {
  passed: boolean;
  expectedTableCount: number;
  expectedColumnCount: number;
  expectedIndexCount: number;
  expectedConstraintCount: number;
  expectedPolicyCount: number;
  expectedRoleCount: number;
  actualTableCount: number;
  actualColumnCount: number;
  actualIndexCount: number;
  actualPolicyCount: number;
  actualRoleCount: number;
  actualConstraintCount: number;
  objectDiffs: DevelopmentCatalogObjectDiff;
  privilegeDifferences: DevelopmentPrivilegeDifference[];
  provenanceConstraintOutdated: boolean;
  violationCodes: string[];
};

export type DevelopmentPrivilegeDifference = {
  role: string;
  table: string;
  privilege: string;
  column?: string;
  expectedGranted: boolean;
  actualGranted: boolean | null;
  scope: "table" | "column";
};

export type DevelopmentRlsCatalogCounts = {
  tables: number;
  columns: number;
  indexes: number;
  constraints: number;
  policies: number;
  roles: number;
};

export type DevelopmentRlsCatalogPartialCounts = {
  [K in keyof DevelopmentRlsCatalogCounts]: number | null;
};

export type DevelopmentCatalogQueryStep =
  | RlsCatalogQueryStep
  | "connection"
  | "catalog";

export type SafeCatalogQueryFailure = {
  step: DevelopmentCatalogQueryStep;
  sqlState: string | null;
  errorClass: string;
};

export type DevelopmentCatalogReadProgress = {
  completedSteps: DevelopmentCatalogQueryStep[];
  actual: DevelopmentRlsCatalogPartialCounts;
};

export type DevelopmentCatalogObjectKind =
  | "tables"
  | "indexes"
  | "constraints"
  | "policies";
export type DevelopmentCatalogObjectInventory = Record<
  DevelopmentCatalogObjectKind,
  string[]
>;
export type DevelopmentCatalogObjectDiff = {
  missing: DevelopmentCatalogObjectInventory;
  unexpected: DevelopmentCatalogObjectInventory;
};

const catalogTablePrivileges = [
  "SELECT",
  "INSERT",
  "UPDATE",
  "DELETE",
] as const;

function developmentPrivilegeDifferences(
  contract: RlsCatalogContract,
  snapshot: RlsCatalogSnapshot,
  appendOnlyGrantRows: readonly Record<string, unknown>[],
): DevelopmentPrivilegeDifference[] {
  const differences = new Map<string, DevelopmentPrivilegeDifference>();
  const addDifference = (
    difference: DevelopmentPrivilegeDifference,
  ): void => {
    if (difference.expectedGranted === difference.actualGranted) return;
    const key = [
      difference.scope,
      difference.role,
      difference.table,
      difference.privilege,
      difference.column ?? "",
    ].join(":");
    differences.set(key, difference);
  };
  const roles = Object.keys(contract.roles);
  const tables = new Set<string>(expectedRlsTableNames);
  for (const role of roles) {
    for (const table of expectedRlsTableNames) {
      for (const privilege of catalogTablePrivileges) {
        const expectedGranted = contract.grants.some((grant) =>
          grant.roleName === role &&
          grant.tableName === table &&
          grant.privilege === privilege &&
          grant.columns === undefined
        );
        const actual = snapshot.tablePrivileges.find((grant) =>
          grant.roleName === role &&
          grant.tableName === table &&
          grant.privilege === privilege
        );
        addDifference({
          role,
          table,
          privilege,
          expectedGranted,
          actualGranted: actual?.granted ?? null,
          scope: "table",
        });
      }
    }
  }

  for (const actual of snapshot.updateColumns) {
    if (
      !roles.includes(actual.roleName) ||
      !tables.has(actual.tableName)
    ) continue;
    const grant = contract.grants.find((candidate) =>
      candidate.roleName === actual.roleName &&
      candidate.tableName === actual.tableName &&
      candidate.privilege === "UPDATE"
    );
    const expectedGranted = grant !== undefined &&
      (grant.columns === undefined ||
        grant.columns.includes(actual.columnName));
    addDifference({
      role: actual.roleName,
      table: actual.tableName,
      privilege: "UPDATE",
      column: actual.columnName,
      expectedGranted,
      actualGranted: actual.granted,
      scope: "column",
    });
  }
  for (const actual of snapshot.insertColumns) {
    if (
      !roles.includes(actual.roleName) ||
      !tables.has(actual.tableName)
    ) continue;
    const grant = contract.grants.find((candidate) =>
      candidate.roleName === actual.roleName &&
      candidate.tableName === actual.tableName &&
      candidate.privilege === "INSERT"
    );
    const expectedGranted = grant !== undefined &&
      (grant.columns === undefined ||
        grant.columns.includes(actual.columnName));
    addDifference({
      role: actual.roleName,
      table: actual.tableName,
      privilege: "INSERT",
      column: actual.columnName,
      expectedGranted,
      actualGranted: actual.granted,
      scope: "column",
    });
  }

  const appendOnlyPrivilegeFields = [
    ["SELECT", "can_select", true, "table"],
    ["INSERT", "can_insert", true, "table"],
    ["UPDATE", "can_update", false, "table"],
    ["DELETE", "can_delete", false, "table"],
    ["TRUNCATE", "can_truncate", false, "table"],
    ["REFERENCES", "can_references", false, "table"],
    ["TRIGGER", "can_trigger", false, "table"],
    ["MAINTAIN", "can_maintain", false, "table"],
    ["UPDATE", "column_update", false, "column"],
    ["REFERENCES", "column_references", false, "column"],
  ] as const;
  for (const table of appendOnlyRlsTableNames) {
    const row = appendOnlyGrantRows.find(
      (candidate) => candidate.table_name === table,
    );
    for (
      const [privilege, field, expectedGranted, scope] of
        appendOnlyPrivilegeFields
    ) {
      if (
        privilege === "MAINTAIN" &&
        row?.maintain_supported !== true
      ) continue;
      const value = row?.[field];
      addDifference({
        role: "app_runtime",
        table,
        privilege,
        expectedGranted,
        actualGranted: typeof value === "boolean" ? value : null,
        scope,
      });
    }
  }
  return [...differences.values()].sort((left, right) =>
    `${left.role}:${left.table}:${left.privilege}:${left.scope}`.localeCompare(
      `${right.role}:${right.table}:${right.privilege}:${right.scope}`,
    )
  );
}

const objectKinds: DevelopmentCatalogObjectKind[] = [
  "tables",
  "indexes",
  "constraints",
  "policies",
];

export function emptyDevelopmentCatalogObjectDiff():
  DevelopmentCatalogObjectDiff {
  return {
    missing: { tables: [], indexes: [], constraints: [], policies: [] },
    unexpected: { tables: [], indexes: [], constraints: [], policies: [] },
  };
}

export function developmentCatalogObjectInventoryFromRows(
  rows: readonly Record<string, unknown>[],
): DevelopmentCatalogObjectInventory {
  const inventory = emptyDevelopmentCatalogObjectDiff().missing;
  for (const row of rows) {
    const kind = row.kind;
    if (
      kind !== "tables" &&
      kind !== "indexes" &&
      kind !== "constraints" &&
      kind !== "policies"
    ) continue;
    const objectName = typeof row.objectName === "string"
      ? row.objectName
      : null;
    if (objectName === null) continue;
    const identity = kind === "tables"
      ? typeof row.schemaName === "string"
        ? `${row.schemaName}.${objectName}`
        : null
      : typeof row.tableName === "string"
        ? `${row.tableName}.${objectName}`
        : null;
    if (identity !== null) inventory[kind].push(identity);
  }
  for (const kind of objectKinds) {
    inventory[kind] = [...new Set(inventory[kind])].sort();
  }
  return inventory;
}

export function compareDevelopmentCatalogObjects(
  contract: RlsCatalogContract,
  actual: DevelopmentCatalogObjectInventory,
  maxIdentifierLength: number,
): DevelopmentCatalogObjectDiff {
  const expected = deriveRlsCatalogPhaseSnapshot(
    contract,
    "final",
    maxIdentifierLength,
  );
  const expectedObjects: DevelopmentCatalogObjectInventory = {
    tables: expected.tables.map((item) =>
      `${item.schemaName}.${item.tableName}`
    ),
    indexes: expected.indexes.map((item) =>
      `${item.tableName}.${item.indexName}`
    ),
    constraints: expected.constraints.map((item) =>
      `${item.tableName}.${item.constraintName}`
    ),
    policies: expected.policies.map((item) =>
      `${item.tableName}.${item.policyName}`
    ),
  };
  const diff = emptyDevelopmentCatalogObjectDiff();
  for (const kind of objectKinds) {
    const expectedSet = new Set(expectedObjects[kind]);
    const actualSet = new Set(actual[kind]);
    diff.missing[kind] = [...expectedSet].filter((name) => !actualSet.has(name))
      .sort();
    diff.unexpected[kind] = [...actualSet].filter((name) =>
      !expectedSet.has(name)
    ).sort();
  }
  return diff;
}

export function createDevelopmentCatalogReadProgress(): DevelopmentCatalogReadProgress {
  return {
    completedSteps: [],
    actual: {
      tables: null,
      columns: null,
      indexes: null,
      constraints: null,
      policies: null,
      roles: null,
    },
  };
}

function resultRowCount(result: unknown): number {
  if (typeof result !== "object" || result === null) return 0;
  const candidate = result as { rowCount?: unknown; rows?: unknown };
  if (typeof candidate.rowCount === "number") return candidate.rowCount;
  return Array.isArray(candidate.rows) ? candidate.rows.length : 0;
}

function recordCatalogReadProgress(
  progress: DevelopmentCatalogReadProgress,
  step: DevelopmentCatalogQueryStep,
  result: unknown,
): void {
  if (!progress.completedSteps.includes(step)) {
    progress.completedSteps.push(step);
  }
  const count = resultRowCount(result);
  switch (step) {
    case "rls_flags":
    case "tables":
      progress.actual.tables = count;
      break;
    case "columns":
      progress.actual.columns = count;
      break;
    case "indexes":
      progress.actual.indexes = count;
      break;
    case "constraints":
      progress.actual.constraints = count;
      break;
    case "policies":
      progress.actual.policies = count;
      break;
    case "roles":
      progress.actual.roles = count;
      break;
  }
}

const errorClassForSqlState = (sqlState: string | null): string => {
  if (sqlState === null) return "non_postgresql_error";
  switch (sqlState) {
    case "42501":
      return "insufficient_privilege";
    case "42703":
      return "undefined_column";
    case "42704":
      return "undefined_object";
    case "42P01":
      return "undefined_table";
    case "42883":
      return "undefined_function";
    case "0A000":
      return "feature_not_supported";
    case "25006":
      return "read_only_violation";
    default:
      if (sqlState.startsWith("08")) return "connection_exception";
      if (sqlState.startsWith("28")) return "authentication_exception";
      if (sqlState.startsWith("42")) return "syntax_or_access_rule_error";
      if (sqlState.startsWith("53")) return "resource_exhaustion";
      return "other_postgresql_error";
  }
};

export function sanitizeCatalogQueryFailure(
  step: DevelopmentCatalogQueryStep,
  error: unknown,
): SafeCatalogQueryFailure {
  const candidate = typeof error === "object" && error !== null &&
      "code" in error
    ? (error as { code?: unknown }).code
    : undefined;
  const sqlState = typeof candidate === "string" &&
      /^[0-9A-Z]{5}$/.test(candidate)
    ? candidate
    : null;
  return { step, sqlState, errorClass: errorClassForSqlState(sqlState) };
}

export class SafeCatalogQueryError extends Error {
  constructor(readonly failure: SafeCatalogQueryFailure) {
    super("catalog_query_failed");
    this.name = "SafeCatalogQueryError";
  }
}

/**
 * Serializes catalog reads so a PostgreSQL transaction stops at its first
 * failed query. Only fixed steps, counts, SQLSTATE, and mapped classes remain.
 */
export function createDevelopmentCatalogQueryRunner(
  client: Pick<PoolClient, "query">,
  progress: DevelopmentCatalogReadProgress,
): RlsCatalogQueryRunner {
  let queue: Promise<void> = Promise.resolve();
  let firstFailure: SafeCatalogQueryFailure | null = null;
  return (step, sql, values) => {
    const operation = queue.then(async () => {
      if (firstFailure) throw new SafeCatalogQueryError(firstFailure);
      try {
        const result = await client.query(
          sql,
          values as unknown as never[],
        );
        recordCatalogReadProgress(progress, step, result);
        return result;
      } catch (error) {
        firstFailure ??= sanitizeCatalogQueryFailure(step, error);
        throw new SafeCatalogQueryError(firstFailure);
      }
    });
    queue = operation.then(() => undefined, () => undefined);
    return operation;
  };
}

function safeCode(value: string): string {
  const prefix = value.split(":", 1)[0]!;
  return safeViolationCodes.has(prefix)
    ? prefix
    : "catalog_contract_mismatch";
}

export function auditDevelopmentRlsCatalog(input: {
  contract: RlsCatalogContract;
  phaseSnapshot: RlsCatalogPhaseSnapshot;
  catalogSnapshot: RlsCatalogSnapshot;
  appendOnlyGrantRows: readonly Record<string, unknown>[];
  objectInventory: DevelopmentCatalogObjectInventory;
}): DevelopmentRlsCatalogAudit {
  const structuralAudit = auditRlsPostPushCatalog(
    input.contract,
    input.phaseSnapshot,
    "final",
  );
  const grantAudit = auditRlsCatalog(input.contract, input.catalogSnapshot);
  const privilegeDifferences = developmentPrivilegeDifferences(
    input.contract,
    input.catalogSnapshot,
    input.appendOnlyGrantRows,
  );
  const appendOnlyPrivilegesPassed = appendOnlyRuntimeGrantsAllowed(
    input.appendOnlyGrantRows,
  );
  const objectDiffs = compareDevelopmentCatalogObjects(
    input.contract,
    input.objectInventory,
    input.phaseSnapshot.maxIdentifierLength,
  );
  const provenanceConstraintName =
    "ai_assessment_approval_provenance_check";
  const expectedPhase = deriveRlsCatalogPhaseSnapshot(
    input.contract,
    "final",
    input.phaseSnapshot.maxIdentifierLength,
  );
  const expectedProvenance = expectedPhase.constraints.find((constraint) =>
    constraint.constraintName === provenanceConstraintName
  );
  const actualProvenance = input.phaseSnapshot.constraints.find((constraint) =>
    constraint.constraintName === provenanceConstraintName
  );
  const provenanceDiagnosticPrefix =
    "ai_assessment_approval_requests.ai_assessment_approval_provenance_check";
  const provenanceConstraintOutdated = !expectedProvenance ||
    !actualProvenance ||
    structuralAudit.diagnostics.some((diagnostic) =>
      diagnostic.startsWith("constraint_") &&
      diagnostic.includes(provenanceDiagnosticPrefix)
    );
  const violations = new Set<string>();
  for (const violation of structuralAudit.violations) {
    violations.add(safeCode(violation));
  }
  for (const violation of grantAudit.violations) {
    violations.add(safeCode(violation));
  }
  if (!appendOnlyPrivilegesPassed) {
    violations.add("append_only_runtime_privilege_mismatch");
  }
  for (const kind of objectKinds) {
    if (objectDiffs.missing[kind].length > 0) {
      violations.add(kind === "tables"
        ? "table_missing"
        : kind === "indexes"
        ? "index_missing"
        : kind === "constraints"
        ? "constraint_missing"
        : "policy_missing");
    }
    if (objectDiffs.unexpected[kind].length > 0) {
      violations.add(kind === "tables"
        ? "table_unexpected"
        : kind === "indexes"
        ? "index_unexpected"
        : kind === "constraints"
        ? "constraint_unexpected"
        : "policy_unexpected");
    }
  }
  if (provenanceConstraintOutdated) {
    violations.add("provenance_constraint_outdated");
  }
  return {
    passed: violations.size === 0,
    expectedTableCount: structuralAudit.expectedTableCount,
    expectedColumnCount: structuralAudit.expectedColumnCount,
    expectedIndexCount: structuralAudit.expectedIndexCount,
    expectedConstraintCount: structuralAudit.expectedConstraintCount,
    expectedPolicyCount: structuralAudit.expectedPolicyCount,
    expectedRoleCount: Object.keys(input.contract.roles).length,
    actualTableCount: input.phaseSnapshot.tables.length,
    actualColumnCount: input.phaseSnapshot.columns.length,
    actualIndexCount: input.phaseSnapshot.indexes.length,
    actualPolicyCount: input.phaseSnapshot.policies.length,
    actualRoleCount: input.phaseSnapshot.roles.length,
    actualConstraintCount: input.phaseSnapshot.constraints.length,
    objectDiffs,
    privilegeDifferences,
    provenanceConstraintOutdated,
    violationCodes: [...violations].sort(),
  };
}

export type DevelopmentRlsCatalogReport = {
  reportVersion: 1;
  auditType: "development_read_only";
  generatedAt: string;
  status: "passed" | "failed" | "refused";
  databaseNameMatched: boolean;
  transactionReadOnly: boolean;
  runtimeLoginAuthenticated: boolean;
  applicationRowsRead: false;
  credentialsIncluded: false;
  connectionCoordinatesIncluded: false;
  postgresMajor: number | null;
  expected: DevelopmentRlsCatalogCounts;
  actual: DevelopmentRlsCatalogPartialCounts;
  completedSteps: DevelopmentCatalogQueryStep[];
  failedQuery: SafeCatalogQueryFailure | null;
  objectDiffs: DevelopmentCatalogObjectDiff | null;
  privilegeDifferences: DevelopmentPrivilegeDifference[];
  violationCodes: string[];
};

export function createDevelopmentRlsCatalogReport(input: {
  audit?: DevelopmentRlsCatalogAudit;
  expectedCounts: DevelopmentRlsCatalogCounts;
  progress?: DevelopmentCatalogReadProgress;
  objectDiffs?: DevelopmentCatalogObjectDiff | null;
  failedQuery?: SafeCatalogQueryFailure | null;
  generatedAt: string;
  databaseNameMatched: boolean;
  transactionReadOnly: boolean;
  runtimeLoginAuthenticated?: boolean;
  postgresMajor: number | null;
  refusalCode?: string;
}): DevelopmentRlsCatalogReport {
  const audit = input.audit;
  const refusalCode = input.refusalCode
    ? safeCode(input.refusalCode)
    : undefined;
  return {
    reportVersion: 1,
    auditType: "development_read_only",
    generatedAt: input.generatedAt,
    status: refusalCode
      ? "refused"
      : audit?.passed &&
          input.databaseNameMatched &&
          input.transactionReadOnly &&
          input.runtimeLoginAuthenticated === true
        ? "passed"
        : "failed",
    databaseNameMatched: input.databaseNameMatched,
    transactionReadOnly: input.transactionReadOnly,
    runtimeLoginAuthenticated: input.runtimeLoginAuthenticated === true,
    applicationRowsRead: false,
    credentialsIncluded: false,
    connectionCoordinatesIncluded: false,
    postgresMajor: input.postgresMajor,
    expected: {
      tables: audit?.expectedTableCount ?? input.expectedCounts.tables,
      columns: audit?.expectedColumnCount ?? input.expectedCounts.columns,
      indexes: audit?.expectedIndexCount ?? input.expectedCounts.indexes,
      constraints: audit?.expectedConstraintCount ??
        input.expectedCounts.constraints,
      policies: audit?.expectedPolicyCount ?? input.expectedCounts.policies,
      roles: audit?.expectedRoleCount ?? input.expectedCounts.roles,
    },
    actual: {
      tables: audit?.actualTableCount ?? input.progress?.actual.tables ?? null,
      columns: audit?.actualColumnCount ??
        input.progress?.actual.columns ?? null,
      indexes: audit?.actualIndexCount ?? input.progress?.actual.indexes ??
        null,
      constraints: audit?.actualConstraintCount ??
        input.progress?.actual.constraints ?? null,
      policies: audit?.actualPolicyCount ??
        input.progress?.actual.policies ?? null,
      roles: audit?.actualRoleCount ?? input.progress?.actual.roles ?? null,
    },
    completedSteps: input.progress?.completedSteps ?? [],
    failedQuery: input.failedQuery ?? null,
    objectDiffs: input.audit?.objectDiffs ?? input.objectDiffs ?? null,
    privilegeDifferences: input.audit?.privilegeDifferences ?? [],
    violationCodes: refusalCode
      ? [refusalCode]
      : audit?.violationCodes ?? [],
  };
}

export function parseDevelopmentRlsAuditArguments(
  args: readonly string[],
):
  | { ok: true; expectedDatabase: string }
  | { ok: false; code: "read_only_confirmation_required" | "expected_database_required" | "invalid_arguments" } {
  const normalizedArgs = args[0] === "--" ? args.slice(1) : args;
  if (!normalizedArgs.includes("--confirm-read-only")) {
    return { ok: false, code: "read_only_confirmation_required" };
  }
  const databaseArguments = normalizedArgs.filter((arg) =>
    arg.startsWith("--expected-database="),
  );
  if (databaseArguments.length !== 1) {
    return { ok: false, code: "expected_database_required" };
  }
  if (normalizedArgs.length !== 2) {
    return { ok: false, code: "invalid_arguments" };
  }
  const expectedDatabase = databaseArguments[0]!.slice(
    "--expected-database=".length,
  );
  if (
    expectedDatabase.length === 0 ||
    expectedDatabase.length > 63 ||
    !/^[A-Za-z_][A-Za-z0-9_-]*$/.test(expectedDatabase)
  ) {
    return { ok: false, code: "expected_database_required" };
  }
  return { ok: true, expectedDatabase };
}
