import assert from "node:assert/strict";
import test from "node:test";
import { PgDialect } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import {
  expectedRlsPolicyCounts,
  expectedRlsTableNames,
} from "./rls-catalog-contract";
import {
  assertRlsRuntimeCatalogReady,
  rlsRuntimeTableNames,
  rlsRuntimeTableNamesSql,
  type RlsRuntimeCatalogRow,
} from "./rls-runtime-readiness";
import { safeRlsReadinessViolationCodes } from "./rls-readiness-diagnostics";

const dialect = new PgDialect();

function validCatalogRows(): RlsRuntimeCatalogRow[] {
  return expectedRlsTableNames.map((relname) => ({
    relname,
    relrowsecurity: true,
    relforcerowsecurity: true,
    policy_count: expectedRlsPolicyCounts[relname],
    invalid_policies: 0,
  }));
}

function violationCodes(rows: readonly RlsRuntimeCatalogRow[]) {
  try {
    assertRlsRuntimeCatalogReady(rows);
    return [];
  } catch (error) {
    return safeRlsReadinessViolationCodes(error);
  }
}

test("runtime SQL inventory is generated from the shared RLS contract", () => {
  const query = dialect.sqlToQuery(sql`
    SELECT relname
    FROM pg_class
    WHERE relname IN (${rlsRuntimeTableNamesSql})
      AND relname = ANY(ARRAY[${rlsRuntimeTableNamesSql}])
      AND relname IN (
        SELECT unnest(ARRAY[${rlsRuntimeTableNamesSql}])
      )
  `);

  assert.deepEqual(rlsRuntimeTableNames, expectedRlsTableNames);
  assert.deepEqual(
    query.params,
    [...expectedRlsTableNames, ...expectedRlsTableNames, ...expectedRlsTableNames],
  );
});

test("runtime RLS readiness accepts the complete catalog contract", () => {
  assert.doesNotThrow(() => assertRlsRuntimeCatalogReady(validCatalogRows()));
});

test("runtime RLS readiness fails closed when a contract table is missing", () => {
  const rows = validCatalogRows().filter(
    (row) => row.relname !== "workspace_approval_ledger",
  );

  assert.ok(violationCodes(rows).includes("table_inventory_mismatch"));
});

test("runtime RLS readiness fails closed when an unexpected table is present", () => {
  const rows = validCatalogRows();
  rows[rows.length - 1] = {
    ...rows[rows.length - 1]!,
    relname: "unexpected_table",
  };

  assert.ok(violationCodes(rows).includes("table_inventory_mismatch"));
});

test("runtime RLS readiness fails closed when a policy count differs", () => {
  const rows = validCatalogRows();
  rows.find((row) => row.relname === "workspace_approval_ledger")!.policy_count =
    1;

  assert.ok(violationCodes(rows).includes("policy_count_mismatch"));
});
