import { is } from "drizzle-orm";
import { PgDialect, PgTable, getTableConfig } from "drizzle-orm/pg-core";
import { parse } from "pgsql-ast-parser";
import type { PoolClient } from "pg";
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
  maxIdentifierLength: number;
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
  stage: RlsCatalogAuditStage;
  expectedTableCount: number;
  expectedColumnCount: number;
  expectedIndexCount: number;
  expectedConstraintCount: number;
  expectedPolicyCount: number;
  expectedRoleCount: number;
  violations: string[];
  diagnostics: string[];
};

const dialect = new PgDialect();

export type RlsCatalogAuditStage = "post-schema" | "final";
const defaultPostgresMaxIdentifierLength = 63;

export function postgresIdentifier(
  value: string,
  maxBytes = defaultPostgresMaxIdentifierLength,
): string {
  let result = "";
  let usedBytes = 0;
  for (const codePoint of value) {
    const bytes = Buffer.byteLength(codePoint, "utf8");
    if (usedBytes + bytes > maxBytes) break;
    result += codePoint;
    usedBytes += bytes;
  }
  return result;
}

function sqlText(value: { toQuery: (config: unknown) => unknown } | undefined) {
  if (!value) return null;
  const query = dialect.sqlToQuery(value as never);
  if (query.params.length !== 0) {
    throw new Error("RLS schema expressions cannot contain query parameters.");
  }
  return query.sql;
}

function requireName(value: unknown, kind: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Unnamed ${kind} in Drizzle schema.`);
  }
  return value;
}

function tableNameOf(
  table: PgTable,
  maxIdentifierLength: number,
): string {
  return postgresIdentifier(
    getTableConfig(table).name,
    maxIdentifierLength,
  );
}

function normalizeAst(value: unknown, baseTable: string): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeAst(item, baseTable));
  }
  if (!value || typeof value !== "object") return value;

  const node = value as Record<string, unknown>;
  if (
    node.type === "ternary" &&
    node.op === "BETWEEN" &&
    node.value !== undefined &&
    node.lo !== undefined &&
    node.hi !== undefined
  ) {
    return normalizeAst(
      {
        type: "binary",
        left: {
          type: "binary",
          left: node.value,
          op: ">=",
          right: node.lo,
        },
        op: "AND",
        right: {
          type: "binary",
          left: node.value,
          op: "<=",
          right: node.hi,
        },
      },
      baseTable,
    );
  }
  if (
    node.type === "table" &&
    node.name &&
    typeof node.name === "object" &&
    typeof (node.name as Record<string, unknown>).name === "string"
  ) {
    const relation = node.name as Record<string, unknown>;
    if (relation.schema === undefined) {
      return normalizeAst(
        {
          ...node,
          name: { ...relation, schema: "public" },
        },
        baseTable,
      );
    }
  }
  if (
    node.type === "binary" &&
    node.op === "=" &&
    node.right &&
    typeof node.right === "object"
  ) {
    const right = node.right as Record<string, unknown>;
    const call = right.type === "call" ? (right as Record<string, unknown>) : null;
    const functionNode = call?.function;
    const args = call?.args;
    const arrayNode =
      Array.isArray(args) && args.length === 1 ? args[0] : undefined;
    if (
      functionNode &&
      typeof functionNode === "object" &&
      String((functionNode as Record<string, unknown>).name).toLowerCase() ===
        "any" &&
      arrayNode &&
      typeof arrayNode === "object" &&
      (arrayNode as Record<string, unknown>).type === "array" &&
      Array.isArray((arrayNode as Record<string, unknown>).expressions)
    ) {
      return normalizeAst(
        {
          type: "binary",
          left: node.left,
          op: "IN",
          right: {
            type: "list",
            expressions: (arrayNode as Record<string, unknown>).expressions,
          },
        },
        baseTable,
      );
    }
  }
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

function expressionMismatchCategories(
  expected: string | null,
  actual: string | null,
  tableName: string,
): string[] {
  if (expected === null || actual === null) {
    return expected === actual ? [] : ["presence"];
  }
  try {
    const left = JSON.parse(canonicalizeRlsExpression(expected, tableName) ?? "null");
    const right = JSON.parse(canonicalizeRlsExpression(actual, tableName) ?? "null");
    const categories = new Set<string>();
    const compare = (
      a: unknown,
      b: unknown,
      key = "",
      parentPath = "root",
    ): void => {
      if (Object.is(a, b)) return;
      const path = key ? `${parentPath}.${key}` : parentPath;
      if (Array.isArray(a) || Array.isArray(b)) {
        if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) {
          categories.add(`shape@${path}`);
          return;
        }
        a.forEach((value, index) =>
          compare(value, b[index], String(index), path),
        );
        return;
      }
      if (a && b && typeof a === "object" && typeof b === "object") {
        const leftObject = a as Record<string, unknown>;
        const rightObject = b as Record<string, unknown>;
        const keys = new Set([...Object.keys(leftObject), ...Object.keys(rightObject)]);
        for (const childKey of keys) {
          if (!(childKey in leftObject) || !(childKey in rightObject)) {
            categories.add(`shape@${path}.${childKey}`);
          } else {
            compare(leftObject[childKey], rightObject[childKey], childKey, path);
          }
        }
        return;
      }
      if (key === "op") categories.add(`operator@${path}`);
      else if (key === "name" || key === "schema") {
        categories.add(`identifier@${path}`);
      } else if (key === "value") categories.add(`literal@${path}`);
      else categories.add(`other@${path}`);
    };
    compare(left, right);
    return [...categories].sort();
  } catch {
    return ["unparseable"];
  }
}

function roleNamesForPolicy(
  value: unknown,
  maxIdentifierLength: number,
): string[] {
  const values = Array.isArray(value) ? value : [value ?? "public"];
  const names = values.map((role) => {
    if (typeof role === "string") {
      return postgresIdentifier(role, maxIdentifierLength);
    }
    if (role && typeof role === "object" && "name" in role) {
      return postgresIdentifier(
        String((role as { name: unknown }).name),
        maxIdentifierLength,
      );
    }
    throw new Error("Unsupported policy role in Drizzle schema.");
  });
  if (names.some((name) => !name)) {
    throw new Error("Empty policy role in Drizzle schema.");
  }
  return names.sort();
}

function getExpectedTables(
  maxIdentifierLength = defaultPostgresMaxIdentifierLength,
): ExpectedTable[] {
  const tableObjects = Object.values(schema).filter((value) =>
    is(value, PgTable),
  ) as PgTable[];
  if (tableObjects.length === 0) {
    throw new Error("Drizzle schema has no PostgreSQL tables.");
  }

  const result = tableObjects.map((table) => {
    const config = getTableConfig(table);
    const tableName = postgresIdentifier(config.name, maxIdentifierLength);
    const schemaName = postgresIdentifier(
      config.schema ?? "public",
      maxIdentifierLength,
    );
    const primaryKeyColumns = new Set([
      ...config.columns.filter((column) => column.primary).map((column) => column.name),
      ...config.primaryKeys.flatMap((key) =>
        key.columns.map((column) => column.name),
      ),
    ]);
    const columns: ExpectedColumn[] = config.columns.map((column) => ({
      columnName: postgresIdentifier(column.name, maxIdentifierLength),
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
        indexName: postgresIdentifier(
          requireName(index.config.name, "index"),
          maxIdentifierLength,
        ),
        unique: index.config.unique,
        method: (index.config.method ?? "btree").toLowerCase(),
        columns: indexColumns.map((name) =>
          postgresIdentifier(name, maxIdentifierLength),
        ),
        where: sqlText(index.config.where),
      };
    });

    const constraints: ExpectedConstraint[] = [
      ...config.checks.map((check) => ({
        constraintName: postgresIdentifier(
          requireName(check.name, "check constraint"),
          maxIdentifierLength,
        ),
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
          constraintName: postgresIdentifier(
            requireName(foreignKey.getName(), "foreign key"),
            maxIdentifierLength,
          ),
          kind: "foreign_key" as const,
          columns: reference.columns.map((column) =>
            postgresIdentifier(column.name, maxIdentifierLength),
          ),
          referencedTable: tableNameOf(
            reference.foreignTable,
            maxIdentifierLength,
          ),
          referencedColumns: reference.foreignColumns.map((column) =>
            postgresIdentifier(column.name, maxIdentifierLength),
          ),
          onDelete: foreignKey.onDelete ?? "no action",
          onUpdate: foreignKey.onUpdate ?? "no action",
          expression: null,
        };
      }),
      ...config.primaryKeys.map((primaryKey) => ({
        constraintName: postgresIdentifier(
          requireName(primaryKey.getName(), "primary key"),
          maxIdentifierLength,
        ),
        kind: "primary_key" as const,
        columns: primaryKey.columns.map((column) =>
          postgresIdentifier(column.name, maxIdentifierLength),
        ),
        referencedTable: null,
        referencedColumns: [],
        onDelete: null,
        onUpdate: null,
        expression: null,
      })),
      ...config.uniqueConstraints.map((constraint) => ({
        constraintName: postgresIdentifier(
          requireName(constraint.name, "unique constraint"),
          maxIdentifierLength,
        ),
        kind: "unique" as const,
        columns: constraint.columns.map((column) =>
          postgresIdentifier(column.name, maxIdentifierLength),
        ),
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
          .map((candidate) =>
            postgresIdentifier(candidate.name, maxIdentifierLength),
          );
        const primaryKeyName = postgresIdentifier(
          `${tableName}_pkey`,
          maxIdentifierLength,
        );
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
        indexName: postgresIdentifier(
          requireName(constraint.getName(), "primary key index"),
          maxIdentifierLength,
        ),
        unique: true,
        method: "btree",
        columns: constraint.columns.map((column) =>
          postgresIdentifier(column.name, maxIdentifierLength),
        ),
        where: null,
      });
    }
    for (const constraint of config.uniqueConstraints) {
      indexes.push({
        indexName: postgresIdentifier(
          requireName(constraint.name, "unique index"),
          maxIdentifierLength,
        ),
        unique: true,
        method: "btree",
        columns: constraint.columns.map((column) =>
          postgresIdentifier(column.name, maxIdentifierLength),
        ),
        where: null,
      });
    }

    const policies: ExpectedPolicy[] = config.policies.map((policy) => {
      return {
        tableName,
        policyName: postgresIdentifier(policy.name, maxIdentifierLength),
        command: (policy.for ?? "all").toUpperCase(),
        roles: roleNamesForPolicy(policy.to, maxIdentifierLength),
        permissive: (policy.as ?? "permissive").toUpperCase(),
        qual: sqlText(policy.using),
        withCheck: sqlText(policy.withCheck),
      };
    });
    if (!config.enableRLS) {
      throw new Error("Every table in the protected Drizzle schema must enable RLS.");
    }
    return {
      tableName,
      schemaName,
      columns,
      indexes,
      constraints,
      policies,
      enableRLS: config.enableRLS,
    };
  });

  const names = result.map((table) => `${table.schemaName}.${table.tableName}`);
  if (new Set(names).size !== names.length) {
    throw new Error("Drizzle schema contains duplicate PostgreSQL table identities.");
  }
  for (const table of result) {
    for (const identifiers of [
      table.columns.map((column) => column.columnName),
      table.indexes.map((index) => index.indexName),
      table.constraints.map((constraint) => constraint.constraintName),
      table.policies.map((policy) => policy.policyName),
    ]) {
      if (new Set(identifiers).size !== identifiers.length) {
        throw new Error(
          "PostgreSQL identifier truncation creates a schema name collision.",
        );
      }
    }
  }
  return result.sort((left, right) => left.tableName.localeCompare(right.tableName));
}

function sorted(values: string[]): string {
  return [...values].sort().join("\u0000");
}

export function orderedValuesEqual<T>(expected: T[], actual: T[]): boolean {
  return JSON.stringify(expected) === JSON.stringify(actual);
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

export function auditRlsPostPushCatalog(
  contract: RlsCatalogContract,
  snapshot: RlsCatalogPhaseSnapshot,
  stage: RlsCatalogAuditStage = "post-schema",
): RlsCatalogPhaseAudit {
  const violations = new Set<string>();
  const diagnostics = new Set<string>();
  const fail = (code: string, expectedObject: string) => {
    violations.add(code);
    diagnostics.add(`${code}:${expectedObject}`);
  };
  const expectedTables = getExpectedTables(snapshot.maxIdentifierLength);
  const expectedTableNames = expectedTables.map(
    (table) => `${table.schemaName}.${table.tableName}`,
  );
  const actualTableNames = snapshot.tables.map(
    (table) => `${table.schemaName}.${table.tableName}`,
  );
  if (sorted(expectedTableNames) !== sorted(actualTableNames)) {
    fail("table_inventory_mismatch", "table_inventory");
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
    fail("column_inventory_mismatch", "column_inventory");
  }

  const expectedIndexes = expectedTables.flatMap((table) =>
    table.indexes.map((index) => ({ tableName: table.tableName, ...index })),
  );
  const actualIndexes = snapshot.indexes;
  if (expectedIndexes.length !== actualIndexes.length) {
    fail("index_inventory_mismatch", "index_inventory");
  } else {
    const matched = new Set<string>();
    for (const expected of expectedIndexes) {
        const expectedId = `${expected.tableName}.${expected.indexName}`;
      const actual = actualIndexes.find(
        (candidate) =>
          candidate.tableName === expected.tableName &&
          candidate.indexName === expected.indexName,
      );
        if (!actual) {
          fail("index_definition_mismatch", expectedId);
          continue;
      }
        if (actual.unique !== expected.unique) {
          fail("index_uniqueness_mismatch", expectedId);
        }
        if (!actual.valid) fail("index_invalid", expectedId);
        if (actual.method.toLowerCase() !== expected.method) {
          fail("index_method_mismatch", expectedId);
        }
        if (
          !orderedValuesEqual(expected.columns, actual.columns) ||
          actual.columns.some((column) => column === null)
        ) {
          fail("index_columns_mismatch", expectedId);
        }
        if (!equalExpression(expected.where, actual.where, expected.tableName)) {
          fail("index_predicate_mismatch", expectedId);
        }
      matched.add(`${expected.tableName}.${expected.indexName}`);
    }
    if (
      actualIndexes.some(
        (actual) => !matched.has(`${actual.tableName}.${actual.indexName}`),
      )
    ) {
      fail("index_inventory_mismatch", "index_inventory");
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
    fail("constraint_inventory_mismatch", "constraint_inventory");
  }
  const constraintIdentity = (item: {
    tableName: string;
    constraintName: string;
  }) => `${item.tableName}.${item.constraintName}`;
  for (const expected of expectedConstraints) {
    const expectedId = constraintIdentity(expected);
    const actual = actualConstraints.find(
      (candidate) => constraintIdentity(candidate) === expectedId,
    );
    if (!actual) {
      fail("constraint_definition_mismatch", expectedId);
      continue;
    }
    if (actual.kind !== expected.kind) {
      fail("constraint_kind_mismatch", expectedId);
    }
    if (
      expected.kind !== "check" &&
      !orderedValuesEqual(expected.columns, actual.columns)
    ) {
      fail("constraint_columns_mismatch", expectedId);
    }
    if (actual.referencedTable !== expected.referencedTable) {
      fail("constraint_reference_mismatch", expectedId);
    }
    if (!orderedValuesEqual(expected.referencedColumns, actual.referencedColumns)) {
      fail("constraint_referenced_columns_mismatch", expectedId);
    }
    if (actual.onDelete !== expected.onDelete) {
      fail("constraint_on_delete_mismatch", expectedId);
    }
    if (actual.onUpdate !== expected.onUpdate) {
      fail("constraint_on_update_mismatch", expectedId);
    }
    if (!actual.validated || actual.deferrable || actual.initiallyDeferred) {
      fail("constraint_flags_mismatch", expectedId);
    }
    if (!equalExpression(expected.expression, actual.expression, expected.tableName)) {
      fail("constraint_expression_mismatch", expectedId);
    }
  }
  const expectedConstraintIds = new Set(expectedConstraints.map(constraintIdentity));
  if (
    actualConstraints.some(
      (actual) => !expectedConstraintIds.has(constraintIdentity(actual)),
    )
  ) {
      fail("constraint_inventory_mismatch", "constraint_inventory");
  }

  const expectedPolicies = expectedTables.flatMap((table) =>
    table.policies.map((policy) =>
      stage === "post-schema"
        ? { ...policy, qual: null, withCheck: null }
        : policy,
    ),
  );
  const contractPolicies = new Map(
    contract.policies.map((policy) => {
      const normalized = {
        ...policy,
        tableName: postgresIdentifier(
          policy.tableName,
          snapshot.maxIdentifierLength,
        ),
        policyName: postgresIdentifier(
          policy.policyName,
          snapshot.maxIdentifierLength,
        ),
        roleName: postgresIdentifier(
          policy.roleName,
          snapshot.maxIdentifierLength,
        ),
      };
      return [policyKey(normalized), normalized] as const;
    }),
  );
  if (contractPolicies.size !== contract.policies.length) {
    fail("policy_identifier_collision", "policy_inventory");
  }
  if (expectedPolicies.length !== contract.policies.length) {
    fail("policy_source_contract_mismatch", "policy_source_contract");
  }
  for (const expected of expectedPolicies) {
    const parsed = contractPolicies.get(policyKey(expected));
    if (
      !parsed ||
      parsed.command !== expected.command ||
      expected.roles.length !== 1 ||
      parsed.roleName !== expected.roles[0]
    ) {
      fail(
        "policy_source_contract_mismatch",
        `${expected.tableName}.${expected.policyName}`,
      );
    }
  }
  const actualPolicies = snapshot.policies;
  if (
    expectedPolicies.length !== actualPolicies.length ||
    new Set(actualPolicies.map(policyKey)).size !== actualPolicies.length
  ) {
    fail("policy_inventory_mismatch", "policy_inventory");
  }
  for (const expected of expectedPolicies) {
    const parsed = contractPolicies.get(policyKey(expected));
    const actual = actualPolicies.find(
      (candidate) => policyKey(candidate) === policyKey(expected),
    );
    if (!actual) continue;
    const expectedId = `${expected.tableName}.${expected.policyName}`;
    if (actual.command.toUpperCase() !== expected.command) {
      fail("policy_command_mismatch", expectedId);
    }
    if (sorted(actual.roles) !== sorted(expected.roles)) {
      fail("policy_target_role_mismatch", expectedId);
    }
    if (actual.permissive !== expected.permissive) {
      fail("policy_permissive_mismatch", expectedId);
    }
    if (stage === "post-schema") {
      if (!equalExpression(null, actual.qual, expected.tableName)) {
        fail("policy_using_expression_mismatch", expectedId);
      }
      if (!equalExpression(null, actual.withCheck, expected.tableName)) {
        fail("policy_with_check_expression_mismatch", expectedId);
      }
    } else if (parsed) {
      if (!equalExpression(parsed.qual, actual.qual, expected.tableName)) {
        for (const category of expressionMismatchCategories(
          parsed.qual,
          actual.qual,
          expected.tableName,
        )) {
          const [kind, path] = category.split("@");
          fail(
            `policy_using_expression_${kind}_mismatch`,
            `${expectedId}:${path ?? "root"}`,
          );
        }
      }
      if (
        !equalExpression(
          parsed.withCheck,
          actual.withCheck,
          expected.tableName,
        )
      ) {
        for (const category of expressionMismatchCategories(
          parsed.withCheck,
          actual.withCheck,
          expected.tableName,
        )) {
          const [kind, path] = category.split("@");
          fail(
            `policy_with_check_expression_${kind}_mismatch`,
            `${expectedId}:${path ?? "root"}`,
          );
        }
      }
    }
  }

  for (const expected of expectedTables) {
    const actual = snapshot.tables.find(
      (candidate) => candidate.tableName === expected.tableName,
    );
    const expectedId = `${expected.schemaName}.${expected.tableName}`;
    if (!actual) {
      fail("table_missing", expectedId);
      continue;
    }
    if (actual.schemaName !== expected.schemaName) {
      fail("table_schema_mismatch", expectedId);
    }
    if (actual.owner !== expectedDisposableRlsTableOwner) {
      fail("table_owner_mismatch", expectedId);
    }
    if (!actual.rlsEnabled) {
      fail("table_rls_not_enabled", expectedId);
    }
    if (stage === "final" && !actual.rlsForced) {
      fail("table_rls_not_forced", expectedId);
    }
  }

  const expectedRoles = Object.entries(contract.roles)
    .map(([roleName, attributes]) => [
      postgresIdentifier(roleName, snapshot.maxIdentifierLength),
      attributes,
    ] as const)
    .filter(([, attributes]) => stage === "final" || !attributes.rolcanlogin)
    .sort(([left], [right]) => left.localeCompare(right));
  if (
    new Set(expectedRoles.map(([roleName]) => roleName)).size !==
    expectedRoles.length
  ) {
    fail("role_identifier_collision", "role_inventory");
  }
  const actualRoles = snapshot.roles
    .filter((role) =>
      expectedRoles.some(([roleName]) => roleName === role.roleName),
    )
    .sort((left, right) => left.roleName.localeCompare(right.roleName));
  if (
    sorted(expectedRoles.map(([roleName]) => roleName)) !==
    sorted(actualRoles.map((role) => role.roleName))
  ) {
    fail("role_inventory_mismatch", "role_inventory");
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
      fail("role_hardening_mismatch", roleName);
    }
  }

  const expectedRoleNames = new Set(expectedRoles.map(([roleName]) => roleName));
  const expectedMemberships = contract.memberships
    .map((membership) => ({
      ...membership,
      grantedRole: postgresIdentifier(
        membership.grantedRole,
        snapshot.maxIdentifierLength,
      ),
      memberRole: postgresIdentifier(
        membership.memberRole,
        snapshot.maxIdentifierLength,
      ),
    }))
    .filter((membership) =>
      expectedRoleNames.has(membership.grantedRole) &&
      expectedRoleNames.has(membership.memberRole),
    )
    .map(membershipKey);
  const actualMemberships = snapshot.memberships
    .filter((membership) =>
      expectedRoleNames.has(membership.grantedRole) &&
      expectedRoleNames.has(membership.memberRole),
    )
    .map(membershipKey);
  if (sorted(expectedMemberships) !== sorted(actualMemberships)) {
    fail("role_membership_mismatch", "role_memberships");
  }

  return {
    passed: violations.size === 0,
    stage,
    expectedTableCount: expectedTables.length,
    expectedColumnCount: expectedColumnRows.length,
    expectedIndexCount: expectedIndexes.length,
    expectedConstraintCount: expectedConstraints.length,
    expectedPolicyCount: expectedPolicies.length,
    expectedRoleCount: expectedRoles.length,
    violations: [...violations].sort(),
    diagnostics: [...diagnostics].sort(),
  };
}

export type PostSchemaAuditBarrierReport = {
  stage: "post-schema";
  status: "passed" | "failed";
  counts: { tables: number; policies: number; roles: number };
  violationCodes: string[];
};

/**
 * A successful Drizzle process exit is not evidence that every DDL statement
 * was applied. Always read and audit the resulting catalog before RLS setup.
 */
export async function runPostSchemaAuditBarrier(
  contract: RlsCatalogContract,
  runDrizzlePush: () => Promise<number>,
  readSnapshot: () => Promise<RlsCatalogPhaseSnapshot>,
): Promise<{
  snapshot: RlsCatalogPhaseSnapshot;
  audit: RlsCatalogPhaseAudit;
  report: PostSchemaAuditBarrierReport;
}> {
  const exitCode = await runDrizzlePush();
  if (exitCode !== 0) {
    throw new Error("drizzle_push_failed");
  }
  const snapshot = await readSnapshot();
  const audit = auditRlsPostPushCatalog(contract, snapshot, "post-schema");
  return {
    snapshot,
    audit,
    report: {
      stage: "post-schema",
      status: audit.passed ? "passed" : "failed",
      counts: {
        tables: snapshot.tables.length,
        policies: snapshot.policies.length,
        roles: snapshot.roles.length,
      },
      violationCodes: audit.violations,
    },
  };
}

export function deriveDrizzleRlsTableNames(
  maxIdentifierLength = defaultPostgresMaxIdentifierLength,
): string[] {
  return getExpectedTables(maxIdentifierLength).map((table) => table.tableName);
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
  maxIdentifierLength = defaultPostgresMaxIdentifierLength,
): string[] {
  return Object.entries(contract.roles)
    .filter(([, attributes]) => attributes.rolcanlogin === false)
    .map(([roleName]) => postgresIdentifier(roleName, maxIdentifierLength))
    .sort();
}

/**
 * Builds a baseline directly from the loaded Drizzle schema for unit tests.
 * Post-schema Drizzle 0.31.11 emits policy shells; the later SQL stage applies
 * the predicates, which the final audit compares semantically.
 */
export function deriveRlsCatalogPhaseSnapshot(
  contract: RlsCatalogContract,
  stage: RlsCatalogAuditStage,
  maxIdentifierLength = defaultPostgresMaxIdentifierLength,
): RlsCatalogPhaseSnapshot {
  const tables = getExpectedTables(maxIdentifierLength);
  const roleEntries = Object.entries(contract.roles).filter(
    ([, attributes]) =>
      stage === "final" || !attributes.rolcanlogin,
  ).map(([roleName, attributes]) => [
    postgresIdentifier(roleName, maxIdentifierLength),
    attributes,
  ] as const);
  const roleNames = new Set(roleEntries.map(([roleName]) => roleName));
  const sqlPolicies = new Map(
    contract.policies.map((policy) => {
      const normalized = {
        ...policy,
        tableName: postgresIdentifier(
          policy.tableName,
          maxIdentifierLength,
        ),
        policyName: postgresIdentifier(
          policy.policyName,
          maxIdentifierLength,
        ),
        roleName: postgresIdentifier(
          policy.roleName,
          maxIdentifierLength,
        ),
      };
      return [policyKey(normalized), normalized] as const;
    }),
  );
  return {
    maxIdentifierLength,
    tables: tables.map((table) => ({
      tableName: table.tableName,
      schemaName: table.schemaName,
      owner: expectedDisposableRlsTableOwner,
      rlsEnabled: true,
      rlsForced: stage === "final",
    })),
    columns: tables.flatMap((table) =>
      table.columns.map((column) => ({
        tableName: table.tableName,
        ...column,
      })),
    ),
    indexes: tables.flatMap((table) =>
      table.indexes.map((index) => ({
        tableName: table.tableName,
        ...index,
        valid: true,
      })),
    ),
    constraints: tables.flatMap((table) =>
      table.constraints.map((constraint) => ({
        tableName: table.tableName,
        ...constraint,
        validated: true,
        deferrable: false,
        initiallyDeferred: false,
      })),
    ),
    policies: tables.flatMap((table) =>
      table.policies.map((policy) => {
        if (stage === "post-schema") {
          return { ...policy, qual: null, withCheck: null };
        }
        const source = sqlPolicies.get(policyKey(policy));
        if (!source) {
          throw new Error("RLS SQL policy source is incomplete.");
        }
        return {
          ...policy,
          command: source.command,
          roles: [source.roleName],
          permissive: source.permissive,
          qual: source.qual,
          withCheck: source.withCheck,
        };
      }),
    ),
    roles: roleEntries.map(([roleName, attributes]) => ({
      roleName,
      ...attributes,
    })),
    memberships: contract.memberships
      .map((membership) => ({
        ...membership,
        grantedRole: postgresIdentifier(
          membership.grantedRole,
          maxIdentifierLength,
        ),
        memberRole: postgresIdentifier(
          membership.memberRole,
          maxIdentifierLength,
        ),
      }))
      .filter(
        (membership) =>
          roleNames.has(membership.grantedRole) &&
          roleNames.has(membership.memberRole),
      ),
  };
}

/**
 * Reads only PostgreSQL catalogs. It intentionally does not select application
 * rows and is shared by the OIDC-guarded CI verifier and the isolated local lab.
 */
export async function readRlsCatalogPhaseSnapshot(
  client: Pick<PoolClient, "query">,
  tableNames: string[],
  roleNames: string[],
): Promise<RlsCatalogPhaseSnapshot> {
  const [
    tables,
    columns,
    indexes,
    constraints,
    policies,
    roles,
    memberships,
    settings,
  ] = await Promise.all([
    client.query(
      `SELECT n.nspname AS "schemaName",
              c.relname AS "tableName",
              pg_get_userbyid(c.relowner) AS owner,
              c.relrowsecurity AS "rlsEnabled",
              c.relforcerowsecurity AS "rlsForced"
         FROM pg_class AS c
         JOIN pg_namespace AS n ON n.oid = c.relnamespace
        WHERE c.relname = ANY($1::text[])
          AND c.relkind IN ('r', 'p')
        ORDER BY n.nspname, c.relname`,
      [tableNames],
    ),
    client.query(
      `SELECT c.relname AS "tableName",
              a.attname AS "columnName",
              format_type(a.atttypid, a.atttypmod) AS "dataType",
              a.attnotnull AS "notNull",
              a.atthasdef AS "hasDefault",
              EXISTS (
                SELECT 1 FROM pg_constraint AS pk
                 WHERE pk.conrelid = c.oid
                   AND pk.contype = 'p'
                   AND a.attnum = ANY(pk.conkey)
              ) AS "primaryKey"
         FROM pg_class AS c
         JOIN pg_namespace AS n ON n.oid = c.relnamespace
         JOIN pg_attribute AS a ON a.attrelid = c.oid
        WHERE c.relname = ANY($1::text[])
          AND c.relkind IN ('r', 'p')
          AND a.attnum > 0
          AND NOT a.attisdropped
        ORDER BY c.relname, a.attnum`,
      [tableNames],
    ),
    client.query(
      `SELECT table_class.relname AS "tableName",
              index_class.relname AS "indexName",
              index_info.indisunique AS "unique",
              index_info.indisvalid AS valid,
              access_method.amname AS method,
              ARRAY(
                SELECT attribute.attname::text
                  FROM unnest(index_info.indkey) WITH ORDINALITY
                       AS key_column(attnum, ordinal)
                  LEFT JOIN pg_attribute AS attribute
                    ON attribute.attrelid = table_class.oid
                   AND attribute.attnum = key_column.attnum
                 WHERE key_column.ordinal <= index_info.indnkeyatts
                 ORDER BY key_column.ordinal
              ) AS columns,
              pg_get_expr(index_info.indpred, index_info.indrelid) AS "where"
         FROM pg_index AS index_info
         JOIN pg_class AS table_class ON table_class.oid = index_info.indrelid
         JOIN pg_namespace AS table_namespace
           ON table_namespace.oid = table_class.relnamespace
         JOIN pg_class AS index_class ON index_class.oid = index_info.indexrelid
         JOIN pg_am AS access_method ON access_method.oid = index_class.relam
        WHERE table_class.relname = ANY($1::text[])
          AND table_namespace.nspname = 'public'
        ORDER BY table_class.relname, index_class.relname`,
      [tableNames],
    ),
    client.query(
      `SELECT table_class.relname AS "tableName",
              constraint_info.conname AS "constraintName",
              CASE constraint_info.contype
                WHEN 'c' THEN 'check'
                WHEN 'f' THEN 'foreign_key'
                WHEN 'p' THEN 'primary_key'
                WHEN 'u' THEN 'unique'
                WHEN 'x' THEN 'exclusion'
                ELSE 'unknown'
              END AS kind,
              ARRAY(
                SELECT attribute.attname::text
                  FROM unnest(constraint_info.conkey) WITH ORDINALITY
                       AS key_column(attnum, ordinal)
                  LEFT JOIN pg_attribute AS attribute
                    ON attribute.attrelid = constraint_info.conrelid
                   AND attribute.attnum = key_column.attnum
                 ORDER BY key_column.ordinal
              ) AS columns,
              referenced_class.relname AS "referencedTable",
              ARRAY(
                SELECT attribute.attname::text
                  FROM unnest(constraint_info.confkey) WITH ORDINALITY
                       AS key_column(attnum, ordinal)
                  LEFT JOIN pg_attribute AS attribute
                    ON attribute.attrelid = constraint_info.confrelid
                   AND attribute.attnum = key_column.attnum
                 ORDER BY key_column.ordinal
              ) AS "referencedColumns",
              CASE WHEN constraint_info.contype = 'f' THEN
                CASE constraint_info.confdeltype
                  WHEN 'r' THEN 'restrict'
                  WHEN 'c' THEN 'cascade'
                  WHEN 'n' THEN 'set null'
                  WHEN 'd' THEN 'set default'
                  ELSE 'no action'
                END
                ELSE NULL
              END AS "onDelete",
              CASE WHEN constraint_info.contype = 'f' THEN
                CASE constraint_info.confupdtype
                  WHEN 'r' THEN 'restrict'
                  WHEN 'c' THEN 'cascade'
                  WHEN 'n' THEN 'set null'
                  WHEN 'd' THEN 'set default'
                  ELSE 'no action'
                END
                ELSE NULL
              END AS "onUpdate",
              pg_get_expr(constraint_info.conbin, constraint_info.conrelid)
                AS expression,
              constraint_info.convalidated AS validated,
              constraint_info.condeferrable AS deferrable,
              constraint_info.condeferred AS "initiallyDeferred"
         FROM pg_constraint AS constraint_info
         JOIN pg_class AS table_class
           ON table_class.oid = constraint_info.conrelid
         JOIN pg_namespace AS table_namespace
           ON table_namespace.oid = table_class.relnamespace
         LEFT JOIN pg_class AS referenced_class
           ON referenced_class.oid = constraint_info.confrelid
        WHERE table_namespace.nspname = 'public'
          AND table_class.relname = ANY($1::text[])
        ORDER BY table_class.relname, constraint_info.conname`,
      [tableNames],
    ),
    client.query(
      `SELECT tablename AS "tableName",
              policyname AS "policyName",
              permissive,
              cmd AS command,
              roles::text[] AS roles,
              qual,
              with_check AS "withCheck"
         FROM pg_policies
        WHERE schemaname = 'public'
          AND tablename = ANY($1::text[])
        ORDER BY tablename, policyname`,
      [tableNames],
    ),
    client.query(
      `SELECT rolname AS "roleName",
              rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
              rolinherit, rolreplication, rolbypassrls
         FROM pg_roles
        WHERE rolname = ANY($1::text[])
        ORDER BY rolname`,
      [roleNames],
    ),
    client.query(
      `SELECT granted.rolname AS "grantedRole",
              member.rolname AS "memberRole",
              membership.admin_option AS "adminOption",
              membership.inherit_option AS "inheritOption",
              membership.set_option AS "setOption"
         FROM pg_auth_members AS membership
         JOIN pg_roles AS granted ON granted.oid = membership.roleid
         JOIN pg_roles AS member ON member.oid = membership.member
        WHERE granted.rolname = ANY($1::text[])
           OR member.rolname = ANY($1::text[])
        ORDER BY granted.rolname, member.rolname`,
      [roleNames],
    ),
    client.query(
      `SELECT current_setting('max_identifier_length')::integer
         AS "maxIdentifierLength"`,
    ),
  ]);

  const maxIdentifierLength = Number(
    settings.rows[0]?.maxIdentifierLength,
  );
  if (
    !Number.isInteger(maxIdentifierLength) ||
    maxIdentifierLength !== defaultPostgresMaxIdentifierLength
  ) {
    throw new Error("Unsupported PostgreSQL identifier length.");
  }

  const stringArray = (value: unknown): string[] =>
    Array.isArray(value) ? value.map(String) : [];
  const nullableStringArray = (value: unknown): Array<string | null> =>
    Array.isArray(value)
      ? value.map((item) => (item === null ? null : String(item)))
      : [];

  return {
    maxIdentifierLength,
    tables: tables.rows.map((row) => ({
      schemaName: String(row.schemaName),
      tableName: String(row.tableName),
      owner: String(row.owner),
      rlsEnabled: Boolean(row.rlsEnabled),
      rlsForced: Boolean(row.rlsForced),
    })),
    columns: columns.rows.map((row) => ({
      tableName: String(row.tableName),
      columnName: String(row.columnName),
      dataType: String(row.dataType).toLowerCase(),
      notNull: Boolean(row.notNull),
      hasDefault: Boolean(row.hasDefault),
      primaryKey: Boolean(row.primaryKey),
    })),
    indexes: indexes.rows.map((row) => ({
      tableName: String(row.tableName),
      indexName: String(row.indexName),
      unique: Boolean(row.unique),
      valid: Boolean(row.valid),
      method: String(row.method),
      columns: nullableStringArray(row.columns),
      where: row.where === null ? null : String(row.where),
    })),
    constraints: constraints.rows.map((row) => ({
      tableName: String(row.tableName),
      constraintName: String(row.constraintName),
      kind: String(row.kind) as RlsCatalogPhaseConstraint["kind"],
      columns: stringArray(row.columns),
      referencedTable:
        row.referencedTable === null ? null : String(row.referencedTable),
      referencedColumns: stringArray(row.referencedColumns),
      onDelete: row.onDelete === null ? null : String(row.onDelete),
      onUpdate: row.onUpdate === null ? null : String(row.onUpdate),
      expression: row.expression === null ? null : String(row.expression),
      validated: Boolean(row.validated),
      deferrable: Boolean(row.deferrable),
      initiallyDeferred: Boolean(row.initiallyDeferred),
    })),
    policies: policies.rows.map((row) => ({
      tableName: String(row.tableName),
      policyName: String(row.policyName),
      permissive: String(row.permissive).toUpperCase(),
      command: String(row.command).toUpperCase(),
      roles: stringArray(row.roles).sort(),
      qual: row.qual === null ? null : String(row.qual),
      withCheck: row.withCheck === null ? null : String(row.withCheck),
    })),
    roles: roles.rows.map((row) => ({
      roleName: String(row.roleName),
      rolcanlogin: Boolean(row.rolcanlogin),
      rolsuper: Boolean(row.rolsuper),
      rolcreatedb: Boolean(row.rolcreatedb),
      rolcreaterole: Boolean(row.rolcreaterole),
      rolinherit: Boolean(row.rolinherit),
      rolreplication: Boolean(row.rolreplication),
      rolbypassrls: Boolean(row.rolbypassrls),
    })),
    memberships: memberships.rows.map((row) => ({
      grantedRole: String(row.grantedRole),
      memberRole: String(row.memberRole),
      adminOption: Boolean(row.adminOption),
      inheritOption: Boolean(row.inheritOption),
      setOption: Boolean(row.setOption),
    })),
  };
}
