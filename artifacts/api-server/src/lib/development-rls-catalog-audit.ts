import {
  auditRlsCatalog,
  type RlsCatalogContract,
  type RlsCatalogSnapshot,
} from "@workspace/db/rls-catalog-audit";
import {
  auditRlsPostPushCatalog,
  type RlsCatalogPhaseSnapshot,
} from "@workspace/db/rls-catalog-phase-audit";
import { appendOnlyRuntimeGrantsAllowed } from "@workspace/db/rls-runtime-readiness";

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
  "table_column_inventory_missing",
  "column_update_matrix_incomplete",
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
  violationCodes: string[];
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
  | "connection"
  | "transaction"
  | "identity"
  | "rls_flags"
  | "tables"
  | "columns"
  | "column_inventory"
  | "indexes"
  | "constraints"
  | "policies"
  | "roles"
  | "memberships"
  | "role_membership"
  | "privileges"
  | "column_privileges"
  | "append_only_privileges"
  | "settings"
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

function queryStepForSql(sql: string): DevelopmentCatalogQueryStep {
  const normalized = sql.toLowerCase();
  if (
    normalized.includes("workspace_approval_ledger") &&
    normalized.includes("has_table_privilege")
  ) return "append_only_privileges";
  if (normalized.includes("begin transaction read only")) return "transaction";
  if (normalized.includes("current_database()")) return "identity";
  if (normalized.includes("pg_auth_members")) return "memberships";
  if (normalized.includes("pg_has_role")) return "role_membership";
  if (normalized.includes("has_column_privilege")) return "column_privileges";
  if (normalized.includes("has_table_privilege")) return "privileges";
  if (normalized.includes("pg_policies")) return "policies";
  if (normalized.includes("pg_constraint")) return "constraints";
  if (normalized.includes("pg_index")) return "indexes";
  if (normalized.includes("format_type(")) return "columns";
  if (
    normalized.includes("array_agg(attribute.attname") &&
    normalized.includes("pg_attribute")
  ) return "column_inventory";
  if (normalized.includes("relrowsecurity")) return "rls_flags";
  if (normalized.includes("pg_roles")) return "roles";
  if (
    normalized.includes("max_identifier_length") ||
    normalized.includes("server_version_num")
  ) return "settings";
  return "catalog";
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
export function monitorDevelopmentCatalogReads<T extends object>(
  client: T,
  progress: DevelopmentCatalogReadProgress,
): T {
  let queue: Promise<void> = Promise.resolve();
  let firstFailure: SafeCatalogQueryFailure | null = null;
  return new Proxy(client, {
    get(target, property, receiver) {
      if (property !== "query") return Reflect.get(target, property, receiver);
      return (queryInput: unknown, values?: unknown[]) => {
        const sql = typeof queryInput === "string"
          ? queryInput
          : typeof queryInput === "object" && queryInput !== null &&
              "text" in queryInput &&
              typeof (queryInput as { text?: unknown }).text === "string"
            ? (queryInput as { text: string }).text
            : "";
        const step = queryStepForSql(sql);
        const operation = queue.then(async () => {
          if (firstFailure) throw new SafeCatalogQueryError(firstFailure);
          try {
            const query = (target as unknown as {
              query: (
                query: unknown,
                parameters?: unknown[],
              ) => Promise<unknown>;
            }).query;
            const result = await query.call(target, queryInput, values);
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
    },
  });
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
}): DevelopmentRlsCatalogAudit {
  const structuralAudit = auditRlsPostPushCatalog(
    input.contract,
    input.phaseSnapshot,
    "final",
  );
  const grantAudit = auditRlsCatalog(input.contract, input.catalogSnapshot);
  const appendOnlyPrivilegesPassed = appendOnlyRuntimeGrantsAllowed(
    input.appendOnlyGrantRows,
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
  return {
    passed: structuralAudit.passed && grantAudit.passed &&
      appendOnlyPrivilegesPassed,
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
  violationCodes: string[];
};

export function createDevelopmentRlsCatalogReport(input: {
  audit?: DevelopmentRlsCatalogAudit;
  expectedCounts: DevelopmentRlsCatalogCounts;
  progress?: DevelopmentCatalogReadProgress;
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
