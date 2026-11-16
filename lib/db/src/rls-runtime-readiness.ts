import { sql } from "drizzle-orm";
import {
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
