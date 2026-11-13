import { is } from "drizzle-orm";
import { PgDialect, PgTable, getTableConfig } from "drizzle-orm/pg-core";
import { parse } from "pgsql-ast-parser";
import * as schema from "./schema/index";
import {
  expectedDisposableRlsTableOwner,
} from "./rls-catalog-contract";
import type {
  ExpectedMembership,
  ExpectedRoleAttributes,
  RlsCatalogContract,
  RlsCatalogSnapshot,
} from "./rls-catalog-audit";

export type RlsCatalogPhaseTable = {
  tableName: string;
  schemaName: string;
  owner: string;
  rlsEnabled: boolean;
  rlsForced: boolean;
};

export type RlsCatalogPhaseColumn = {
  tableName: string;
  columnName: string;
  dataType: string;
  notNull: boolean;
  hasDefault: boolean;
  primaryKey: boolean;
};

export type RlsCatalogPhaseIndex = {
  tableName: string;
  indexName: string;
  unique: boolean;
  valid: boolean;
  method: string;
  columns: Array<string | null>;
  where: string | null;
};

export type RlsCatalogPhaseConstraint = {
  tableName: string;
  constraintName: string;
  kind: "check" | "foreign_key" | "primary_key" | "unique" | "exclusion";
  columns: string[];
  referencedTable: string | null;
  referencedColumns: string[];
  onDelete: string | null;
  onUpdate: string | null;
  expression: string | null;
  validated: boolean;
  deferrable: boolean;
  initiallyDeferred: boolean;
};

export type RlsCatalogPhaseSnapshot = {
  tables: RlsCatalogPhaseTable[];
  columns: RlsCatalogPhaseColumn[];
  indexes: RlsCatalogPhaseIndex[];
  constraints: RlsCatalogPhaseConstraint[];
  policies: RlsCatalogSnapshot["policies"];
  roles: Array<{ roleName: string } & ExpectedRoleAttributes>;
  memberships: ExpectedMembership[];
};

type ExpectedColumn = Omit<
  RlsCatalogPhaseColumn,
  "tableName"
>;
type ExpectedIndex = Omit<
  RlsCatalogPhaseIndex,
  "tableName" | "valid"
>;
type ExpectedConstraint = Omit<
  RlsCatalogPhaseConstraint,
  "tableName" | "validated" | "deferrable" | "initiallyDeferred"
>;
type ExpectedPolicy = {
  tableName: string;
  policyName: string;
  command: string;
  roles: string[];
  permissive: string;
  qual: string | null;
  withCheck: string | null;
};
type ExpectedTable = {
  tableName: string;
  schemaName: string;
  columns: ExpectedColumn[];
  indexes: ExpectedIndex[];
  constraints: ExpectedConstraint[];
  policies: ExpectedPolicy[];
  enableRLS: boolean;
};

export type RlsCatalogPhaseAudit = {
  passed: boolean;
  expectedTableCount: number;
  expectedColumnCount: number;
  expectedIndexCount: number;
  expectedConstraintCount: number;
  expectedPolicyCount: number;
  expectedRoleCount: number;
  violations: string[];
};

const dialect = new PgDialect();
const phaseRoleNames = new Set(["app_runtime", "app_ai_assessment_worker"]);

function sqlText(value: { toQuery: (config: unknown) => unknown } | undefined) {
  if (!value) return null;
  const query = dialect.sqlToQuery(value as never);
  if (query.params.length !== 0) {
    throw new Error("RLS schema expressions cannot contain query parameters.");
  }
  return query.sql;
}

function tableNameOf(table: PgTable): string {
  return getTableConfig(table).name;
}

function normalizeAst(value: unknown, baseTable: string): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeAst(item, baseTable));
  }
  if (!value || typeof value !== "object") return value;

  const node = value as Record<string, unknown>;
  if (
    node.type === "cast" &&
    node.to &&
    typeof node.to === "object" &&
    (node.to as Record<string, unknown>).name === "text" &&
    node.operand &&
    typeof node.operand === "object" &&
    (node.operand as Record<string, unknown>).type === "string"
  ) {
    return normalizeAst(node.operand, baseTable);
  }

  const normalized: Record<string, unknown> = {};
  for (const key of Object.keys(node).sort()) {
    const child = node[key];
    if (key === "table" && child && typeof child === "object") {
      const table = child as Record<string, unknown>;
      if (table.name === baseTable && !table.alias) continue;
    }
    normalized[key] = normalizeAst(child, baseTable);
  }
  return normalized;
}

export function canonicalizeRlsExpression(
  expression: string | null,
  baseTable: string,
): string | null {
  if (expression === null) return null;
  const ast = parse(expression, "expr");
  return JSON.stringify(normalizeAst(ast, baseTable));
}

function equalExpression(
  expected: string | null,
  actual: string | null,
  tableName: string,
): boolean {
  try {
    return (
      canonicalizeRlsExpression(expected, tableName) ===
      canonicalizeRlsExpression(actual, tableName)
    );
  } catch {
    return false;
  }
}

function requireNamedColumns(
  values: Array<{ name?: string }>,
  objectLabel: string,
): string[] {
  const names = values.map((value) => value.name);
  if (names.some((name) => typeof name !== "string" || !name)) {
    throw new Error(`Unsupported unnamed ${objectLabel} in Drizzle schema.`);
  }
  return names as string[];
}

function roleNamesForPolicy(value: unknown): string[] {
  const values = Array.isArray(value) ? value : [value ?? "public"];
  const names = values.map((role) => {
    if (typeof role === "string") return role;
    if (role && typeof role === "object" && "name" in role) {
      return String((role as { name: unknown }).name);
    }
    throw new Error("Unsupported policy role in Drizzle schema.");
  });
  if (names.some((name) => !name)) {
    throw new Error("Empty policy role in Drizzle schema.");
  }
  return names.sort();
}

function getExpectedTables(): ExpectedTable[] {
  const tableObjects = Object.values(schema).filter((value) =>
    is(value, PgTable),
  ) as PgTable[];
  if (tableObjects.length === 0) {
    throw new Error("Drizzle schema has no PostgreSQL tables.");
  }

  const result = tableObjects.map((table) => {
    const config = getTableConfig(table);
    const primaryKeyColumns = new Set([
      ...config.columns.filter((column) => column.primary).map((column) => column.name),
      ...config.primaryKeys.flatMap((key) =>
        key.columns.map((column) => column.name),
      ),
    ]);
    const columns: ExpectedColumn[] = config.columns.map((column) => ({
      columnName: column.name,
      dataType: column.getSQLType().toLowerCase(),
      notNull: column.notNull,
      hasDefault: column.hasDefault,
      primaryKey: primaryKeyColumns.has(column.name),
    }));

    const indexes: ExpectedIndex[] = config.indexes.map((index) => {
      const indexColumns = index.config.columns.map((column) => {
        if (!column || typeof column !== "object" || !("name" in column)) {
          throw new Error("Unsupported expression index in Drizzle schema.");
        }
        return String(column.name);
      });
      return {
        indexName: index.config.name ?? "",
        unique: index.config.unique,
        method: (index.config.method ?? "btree").toLowerCase(),
        columns: indexColumns,
        where: sqlText(index.config.where),
      };
    });

    const constraints: ExpectedConstraint[] = [
      ...config.checks.map((check) => ({
        constraintName: check.name,
        kind: "check" as const,
        columns: [],
        referencedTable: null,
        referencedColumns: [],
        onDelete: null,
        onUpdate: null,
        expression: sqlText(check.value),
      })),
      ...config.foreignKeys.map((foreignKey) => {
        const reference = foreignKey.reference();
        return {
          constraintName: foreignKey.getName(),
          kind: "foreign_key" as const,
          columns: reference.columns.map((column) => column.name),
          referencedTable: tableNameOf(reference.foreignTable),
          referencedColumns: reference.foreignColumns.map((column) => column.name),
          onDelete: foreignKey.onDelete ?? "no action",
          onUpdate: foreignKey.onUpdate ?? "no action",
          expression: null,
        };
      }),
      ...config.primaryKeys.map((primaryKey) => ({
        constraintName: primaryKey.getName(),
        kind: "primary_key" as const,
        columns: primaryKey.columns.map((column) => column.name),
        referencedTable: null,
        referencedColumns: [],
        onDelete: null,
        onUpdate: null,
        expression: null,
      })),
      ...config.uniqueConstraints.map((constraint) => ({
        constraintName: constraint.name,
        kind: "unique" as const,
        columns: constraint.columns.map((column) => column.name),
        referencedTable: null,
        referencedColumns: [],
        onDelete: null,
        onUpdate: null,
        expression: null,
      })),
    ];

    for (const column of config.columns.filter((candidate) => candidate.primary)) {
      if (!constraints.some((constraint) => constraint.kind === "primary_key")) {
        const primaryColumns = config.columns
          .filter((candidate) => candidate.primary)
          .map((candidate) => candidate.name);
        const primaryKeyName = `${config.name}_pkey`;
        constraints.push({
          constraintName: primaryKeyName,
          kind: "primary_key",
          columns: primaryColumns,
          referencedTable: null,
          referencedColumns: [],
          onDelete: null,
          onUpdate: null,
          expression: null,
        });
        indexes.push({
          indexName: primaryKeyName,
          unique: true,
          method: "btree",
          columns: primaryColumns,
          where: null,
        });
        break;
      }
    }
    for (const constraint of config.primaryKeys) {
      indexes.push({
        indexName: constraint.getName(),
        unique: true,
        method: "btree",
        columns: constraint.columns.map((column) => column.name),
        where: null,
      });
    }
    for (const constraint of config.uniqueConstraints) {
      indexes.push({
        indexName: constraint.name,
        unique: true,
        method: "btree",
        columns: constraint.columns.map((column) => column.name),
        where: null,
      });
    }

    const policies: ExpectedPolicy[] = config.policies.map((policy) => {
      return {
        tableName: config.name,
        policyName: policy.name,
        command: (policy.for ?? "all").toUpperCase(),
        roles: roleNamesForPolicy(policy.to),
        permissive: (policy.as ?? "permissive").toUpperCase(),
        qual: sqlText(policy.using),
        withCheck: sqlText(policy.withCheck),
      };
    });
    if (!config.enableRLS) {
      throw new Error("Every table in the protected Drizzle schema must enable RLS.");
    }
    return {
      tableName: config.name,
      schemaName: config.schema ?? "public",
      columns,
      indexes,
      constraints,
      policies,
      enableRLS: config.enableRLS,
    };
  });

  const names = result.map((table) => table.tableName);
  if (new Set(names).size !== names.length) {
    throw new Error("Drizzle schema contains duplicate PostgreSQL table names.");
  }
  return result.sort((left, right) => left.tableName.localeCompare(right.tableName));
}

function sorted(values: string[]): string {
  return [...values].sort().join("\u0000");
}

function policyKey(value: { tableName: string; policyName: string }): string {
  return `${value.tableName}.${value.policyName}`;
}

function membershipKey(value: ExpectedMembership): string {
  return [
    value.grantedRole,
    value.memberRole,
    value.adminOption,
    value.inheritOption,
    value.setOption,
  ].join(":");
}

function stableObjectKey(value: object): string {
  return JSON.stringify(value, Object.keys(value).sort());
}

export function auditRlsPostPushCatalog(
  contract: RlsCatalogContract,
  snapshot: RlsCatalogPhaseSnapshot,
): RlsCatalogPhaseAudit {
  const violations = new Set<string>();
  const expectedTables = getExpectedTables();
  const expectedTableNames = expectedTables.map((table) => table.tableName);
  const actualTableNames = snapshot.tables.map((table) => table.tableName);
  if (sorted(expectedTableNames) !== sorted(actualTableNames)) {
    violations.add("table_inventory_mismatch");
  }

  const expectedColumnRows = expectedTables.flatMap((table) =>
    table.columns.map((column) => ({ tableName: table.tableName, ...column })),
  );
  const actualColumnRows = snapshot.columns;
  const columnKey = (item: RlsCatalogPhaseColumn) =>
    [
      item.tableName,
      item.columnName,
      item.dataType.toLowerCase(),
      item.notNull,
      item.hasDefault,
      item.primaryKey,
    ].join(":");
  if (
    sorted(expectedColumnRows.map(columnKey)) !==
    sorted(actualColumnRows.map(columnKey))
  ) {
    violations.add("column_inventory_mismatch");
  }

  const expectedIndexes = expectedTables.flatMap((table) =>
    table.indexes.map((index) => ({ tableName: table.tableName, ...index })),
  );
  const actualIndexes = snapshot.indexes;
  if (expectedIndexes.length !== actualIndexes.length) {
    violations.add("index_inventory_mismatch");
  } else {
    const matched = new Set<string>();
    for (const expected of expectedIndexes) {
      const actual = actualIndexes.find(
        (candidate) =>
          candidate.tableName === expected.tableName &&
          candidate.indexName === expected.indexName,
      );
      if (
        !actual ||
        actual.unique !== expected.unique ||
        !actual.valid ||
        actual.method.toLowerCase() !== expected.method ||
        sorted(actual.columns.filter((column): column is string => column !== null)) !==
          sorted(expected.columns) ||
        actual.columns.some((column) => column === null) ||
        !equalExpression(expected.where, actual.where, expected.tableName)
      ) {
        violations.add("index_definition_mismatch");
      }
      matched.add(`${expected.tableName}.${expected.indexName}`);
    }
    if (
      actualIndexes.some(
        (actual) => !matched.has(`${actual.tableName}.${actual.indexName}`),
      )
    ) {
      violations.add("index_inventory_mismatch");
    }
  }

  const expectedConstraints = expectedTables.flatMap((table) =>
    table.constraints.map((constraint) => ({
      tableName: table.tableName,
      ...constraint,
    })),
  );
  const actualConstraints = snapshot.constraints;
  if (expectedConstraints.length !== actualConstraints.length) {
    violations.add("constraint_inventory_mismatch");
  }
  const constraintIdentity = (item: {
    tableName: string;
    constraintName: string;
  }) => `${item.tableName}.${item.constraintName}`;
  for (const expected of expectedConstraints) {
    const actual = actualConstraints.find(
      (candidate) => constraintIdentity(candidate) === constraintIdentity(expected),
    );
    if (
      !actual ||
      actual.kind !== expected.kind ||
      sorted(actual.columns) !== sorted(expected.columns) ||
      actual.referencedTable !== expected.referencedTable ||
      sorted(actual.referencedColumns) !== sorted(expected.referencedColumns) ||
      actual.onDelete !== expected.onDelete ||
      actual.onUpdate !== expected.onUpdate ||
      !actual.validated ||
      actual.deferrable ||
      actual.initiallyDeferred ||
      !equalExpression(expected.expression, actual.expression, expected.tableName)
    ) {
      violations.add("constraint_definition_mismatch");
    }
  }
  const expectedConstraintIds = new Set(expectedConstraints.map(constraintIdentity));
  if (
    actualConstraints.some(
      (actual) => !expectedConstraintIds.has(constraintIdentity(actual)),
    )
  ) {
    violations.add("constraint_inventory_mismatch");
  }

  const expectedPolicies = expectedTables.flatMap((table) => table.policies);
  const contractPolicies = new Map(
    contract.policies.map((policy) => [policyKey(policy), policy]),
  );
  if (expectedPolicies.length !== contract.policies.length) {
    violations.add("policy_source_contract_mismatch");
  }
  for (const expected of expectedPolicies) {
    const parsed = contractPolicies.get(policyKey(expected));
    if (
      !parsed ||
      parsed.command !== expected.command ||
      expected.roles.length !== 1 ||
      parsed.roleName !== expected.roles[0]
    ) {
      violations.add("policy_source_contract_mismatch");
    }
  }
  const actualPolicies = snapshot.policies;
  if (
    expectedPolicies.length !== actualPolicies.length ||
    new Set(actualPolicies.map(policyKey)).size !== actualPolicies.length
  ) {
    violations.add("policy_inventory_mismatch");
  }
  for (const expected of expectedPolicies) {
    const actual = actualPolicies.find(
      (candidate) => policyKey(candidate) === policyKey(expected),
    );
    if (!actual) continue;
    if (
      actual.command.toUpperCase() !== expected.command ||
      sorted(actual.roles) !== sorted(expected.roles) ||
      actual.permissive !== expected.permissive
    ) {
      violations.add("policy_definition_mismatch");
    }
    if (
      !equalExpression(expected.qual, actual.qual, expected.tableName) ||
      !equalExpression(expected.withCheck, actual.withCheck, expected.tableName)
    ) {
      violations.add("policy_expression_mismatch");
    }
  }

  for (const expected of expectedTables) {
    const actual = snapshot.tables.find(
      (candidate) => candidate.tableName === expected.tableName,
    );
    if (
      !actual ||
      actual.schemaName !== expected.schemaName ||
      actual.owner !== expectedDisposableRlsTableOwner ||
      !actual.rlsEnabled
    ) {
      violations.add("table_rls_or_owner_mismatch");
    }
  }

  const expectedRoles = Object.entries(contract.roles)
    .filter(([roleName]) => phaseRoleNames.has(roleName))
    .sort(([left], [right]) => left.localeCompare(right));
  const actualRoles = snapshot.roles
    .filter((role) => phaseRoleNames.has(role.roleName))
    .sort((left, right) => left.roleName.localeCompare(right.roleName));
  if (
    sorted(expectedRoles.map(([roleName]) => roleName)) !==
    sorted(actualRoles.map((role) => role.roleName))
  ) {
    violations.add("role_inventory_mismatch");
  }
  for (const [roleName, expected] of expectedRoles) {
    const actual = actualRoles.find((role) => role.roleName === roleName);
    if (
      !actual ||
      Object.entries(expected).some(
        ([key, value]) =>
          actual[key as keyof ExpectedRoleAttributes] !== value,
      )
    ) {
      violations.add("role_hardening_mismatch");
    }
  }

  const expectedMemberships = contract.memberships
    .filter(
      (membership) =>
        phaseRoleNames.has(membership.grantedRole) &&
        phaseRoleNames.has(membership.memberRole),
    )
    .map(membershipKey);
  const actualMemberships = snapshot.memberships
    .filter(
      (membership) =>
        phaseRoleNames.has(membership.grantedRole) &&
        phaseRoleNames.has(membership.memberRole),
    )
    .map(membershipKey);
  if (sorted(expectedMemberships) !== sorted(actualMemberships)) {
    violations.add("role_membership_mismatch");
  }

  return {
    passed: violations.size === 0,
    expectedTableCount: expectedTables.length,
    expectedColumnCount: expectedColumnRows.length,
    expectedIndexCount: expectedIndexes.length,
    expectedConstraintCount: expectedConstraints.length,
    expectedPolicyCount: expectedPolicies.length,
    expectedRoleCount: expectedRoles.length,
    violations: [...violations].sort(),
  };
}

export function deriveDrizzleRlsTableNames(): string[] {
  return getExpectedTables().map((table) => table.tableName);
}

export function deriveDrizzleRlsMetadataCounts(): {
  tableCount: number;
  columnCount: number;
  indexCount: number;
  constraintCount: number;
  policyCount: number;
} {
  const tables = getExpectedTables();
  return {
    tableCount: tables.length,
    columnCount: tables.reduce((total, table) => total + table.columns.length, 0),
    indexCount: tables.reduce((total, table) => total + table.indexes.length, 0),
    constraintCount: tables.reduce(
      (total, table) => total + table.constraints.length,
      0,
    ),
    policyCount: tables.reduce((total, table) => total + table.policies.length, 0),
  };
}

export function expectedPostPushRoleNames(
  contract: RlsCatalogContract,
): string[] {
  return Object.keys(contract.roles)
    .filter((roleName) => phaseRoleNames.has(roleName))
    .sort();
}
