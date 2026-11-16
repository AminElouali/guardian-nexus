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
import {
  expectedRlsPolicyCount,
  expectedRlsTableNames,
} from "@workspace/db/rls-catalog-contract";

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
  expectedPolicyCount: number;
  expectedRoleCount: number;
  actualTableCount: number;
  actualPolicyCount: number;
  actualRoleCount: number;
  actualConstraintCount: number;
  violationCodes: string[];
};

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
    expectedTableCount: expectedRlsTableNames.length,
    expectedPolicyCount: expectedRlsPolicyCount,
    expectedRoleCount: Object.keys(input.contract.roles).length,
    actualTableCount: input.phaseSnapshot.tables.length,
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
  expected: { tables: number; policies: number; roles: number };
  actual: {
    tables: number;
    policies: number;
    roles: number;
    constraints: number;
  };
  violationCodes: string[];
};

export function createDevelopmentRlsCatalogReport(input: {
  audit?: DevelopmentRlsCatalogAudit;
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
      tables: audit?.expectedTableCount ?? expectedRlsTableNames.length,
      policies: audit?.expectedPolicyCount ?? expectedRlsPolicyCount,
      roles: audit?.expectedRoleCount ?? 0,
    },
    actual: {
      tables: audit?.actualTableCount ?? 0,
      policies: audit?.actualPolicyCount ?? 0,
      roles: audit?.actualRoleCount ?? 0,
      constraints: audit?.actualConstraintCount ?? 0,
    },
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
