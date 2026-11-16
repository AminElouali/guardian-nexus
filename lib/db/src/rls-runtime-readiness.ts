import { sql } from "drizzle-orm";
import {
  appendOnlyRlsTableNames,
  expectedRlsPolicyCounts,
  expectedRlsTableNames,
} from "./rls-catalog-contract";
import {
  RlsRuntimeReadinessError,
  type RlsReadinessViolationCode,
} from "./rls-readiness-diagnostics";

export type RlsRuntimeCatalogRow = Record<string, unknown>;

export const rlsRuntimeTableNames = expectedRlsTableNames;
export const rlsRuntimeTableNamesSql = sql.join(
  rlsRuntimeTableNames.map((tableName) => sql`${tableName}`),
  sql`, `,
);

export const appendOnlyRlsTableNamesSql = sql.join(
  appendOnlyRlsTableNames.map((tableName) => sql`${tableName}`),
  sql`, `,
);

export type AppendOnlyRuntimeGrantRow = Record<string, unknown>;

export function appendOnlyRuntimeGrantsAllowed(
  rows: readonly AppendOnlyRuntimeGrantRow[],
): boolean {
  if (rows.length !== appendOnlyRlsTableNames.length) return false;

  const expectedNames = new Set<string>(appendOnlyRlsTableNames);
  const seenNames = new Set<string>();
  for (const row of rows) {
    if (
      typeof row.table_name !== "string" ||
      !expectedNames.has(row.table_name) ||
      seenNames.has(row.table_name)
    ) {
      return false;
    }
    seenNames.add(row.table_name);
    if (
      row.can_select !== true ||
      row.can_insert !== true ||
      row.can_update !== false ||
      row.can_delete !== false ||
      row.can_truncate !== false ||
      row.can_references !== false ||
      row.can_trigger !== false ||
      row.can_maintain !== false ||
      typeof row.maintain_supported !== "boolean" ||
      row.column_update !== false ||
      row.column_references !== false
    ) {
      return false;
    }
  }
  return seenNames.size === expectedNames.size;
}

export function assertRlsRuntimeCatalogReady(
  rows: readonly RlsRuntimeCatalogRow[],
): void {
  const catalogViolations: RlsReadinessViolationCode[] = [];
  if (rows.length !== rlsRuntimeTableNames.length) {
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
}
