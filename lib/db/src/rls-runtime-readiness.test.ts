import assert from "node:assert/strict";
import test from "node:test";
import { PgDialect } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import {
  expectedRlsPolicyCounts,
  expectedRlsTableNames,
  appendOnlyRlsTableNames,
} from "./rls-catalog-contract";
import {
  appendOnlyRuntimeGrantsAllowed,
  appendOnlyRlsTableNamesSql,
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

function validAppendOnlyGrantRows(): Record<string, unknown>[] {
  return appendOnlyRlsTableNames.map((table_name) => ({
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
}

function violationCodes(rows: readonly RlsRuntimeCatalogRow[]) {
  try {
    assertRlsRuntimeCatalogReady(rows);
    return [];
  } catch (error) {
    return safeRlsReadinessViolationCodes(error);
  }
}

test("append-only contract contains only runtime inventory tables", () => {
  assert.ok(
    appendOnlyRlsTableNames.every((name) => expectedRlsTableNames.includes(name)),
  );
  assert.ok(appendOnlyRlsTableNames.includes("workspace_approval_ledger"));
});

test("append-only privilege query inventory comes from its contract", () => {
  const query = dialect.sqlToQuery(sql`
    SELECT table_name
    FROM unnest(ARRAY[${appendOnlyRlsTableNamesSql}]) AS append_only(table_name)
  `);

  assert.deepEqual(query.params, [...appendOnlyRlsTableNames]);
});

test("append-only runtime grants allow only table SELECT and INSERT", () => {
  assert.equal(appendOnlyRuntimeGrantsAllowed(validAppendOnlyGrantRows()), true);
});

test("append-only runtime grants fail closed when SELECT is missing", () => {
  const rows = validAppendOnlyGrantRows();
  rows[0]!.can_select = false;
  assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
});

test("append-only runtime grants fail closed when INSERT is missing", () => {
  const rows = validAppendOnlyGrantRows();
  rows[0]!.can_insert = false;
  assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
});

for (const [privilege, property] of [
  ["UPDATE", "can_update"],
  ["DELETE", "can_delete"],
  ["TRUNCATE", "can_truncate"],
  ["REFERENCES", "can_references"],
  ["TRIGGER", "can_trigger"],
  ["MAINTAIN", "can_maintain"],
] as const) {
  test(`append-only runtime grants reject table-level ${privilege}`, () => {
    const rows = validAppendOnlyGrantRows();
    rows[0]![property] = true;
    if (privilege === "MAINTAIN") rows[0]!.maintain_supported = true;
    assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
  });
}

test("append-only runtime grants reject column-level UPDATE", () => {
  const rows = validAppendOnlyGrantRows();
  rows[0]!.column_update = true;
  assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
});

test("append-only runtime grants reject column-level REFERENCES", () => {
  const rows = validAppendOnlyGrantRows();
  rows[0]!.column_references = true;
  assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
});

test("append-only runtime grants reject a broad grant snapshot", () => {
  const rows = validAppendOnlyGrantRows();
  Object.assign(rows[0]!, {
    can_update: true,
    can_delete: true,
    can_truncate: true,
    can_references: true,
    can_trigger: true,
    can_maintain: true,
    maintain_supported: true,
    column_update: true,
    column_references: true,
  });
  assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
});

test("append-only runtime grants reject missing and unexpected table snapshots", () => {
  assert.equal(appendOnlyRuntimeGrantsAllowed([]), false);
  const rows = validAppendOnlyGrantRows();
  rows[0]!.table_name = "unexpected_table";
  assert.equal(appendOnlyRuntimeGrantsAllowed(rows), false);
});

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
