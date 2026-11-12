import {
  expectedDisposableRlsTableOwner,
  expectedRlsPolicyCounts,
} from "./rls-catalog-contract";

const tablePrivileges = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;
const specialUpdateTables = [
  "ai_assessment_jobs",
  "host_boundary_attestation_challenges",
  "ai_assessment_approval_requests",
] as const;
const applicationRoles = new Set([
  "app_runtime",
  "app_runtime_login",
  "app_ai_assessment_worker",
]);

type TablePrivilege = (typeof tablePrivileges)[number];

export type ExpectedPolicy = {
  policyName: string;
  tableName: string;
  command: string;
  roleName: string;
};

export type ExpectedMembership = {
  grantedRole: string;
  memberRole: string;
  adminOption: boolean;
  inheritOption: boolean;
  setOption: boolean;
};

export type ExpectedRoleAttributes = {
  rolcanlogin: boolean;
  rolsuper: boolean;
  rolcreatedb: boolean;
  rolcreaterole: boolean;
  rolinherit: boolean;
  rolreplication: boolean;
  rolbypassrls: boolean;
};

export type ExpectedGrant = {
  roleName: string;
  tableName: string;
  privilege: TablePrivilege;
  columns?: string[];
};

export type RlsCatalogSources = {
  schemaFiles: Array<{ path: string; content: string }>;
  rolesSource: string;
  bootstrapSource: string;
  policiesSql: string;
};

export type RlsCatalogContract = {
  policies: ExpectedPolicy[];
  memberships: ExpectedMembership[];
  roles: Record<string, ExpectedRoleAttributes>;
  grants: ExpectedGrant[];
};

export type RlsCatalogSnapshot = {
  tables: Array<{
    tableName: string;
    owner: string;
    rlsEnabled: boolean;
    rlsForced: boolean;
  }>;
  policies: Array<{
    tableName: string;
    policyName: string;
    permissive: string;
    command: string;
    roles: string[];
    qual: string | null;
    withCheck: string | null;
  }>;
  roles: Array<{ roleName: string } & ExpectedRoleAttributes>;
  memberships: ExpectedMembership[];
  pgHasRole: Array<{
    memberRole: string;
    targetRole: string;
    member: boolean;
    usage: boolean;
  }>;
  tablePrivileges: Array<{
    roleName: string;
    tableName: string;
    privilege: TablePrivilege;
    granted: boolean;
  }>;
  updateColumns: Array<{
    roleName: string;
    tableName: string;
    columnName: string;
    granted: boolean;
  }>;
  tableColumns: Array<{ tableName: string; columnNames: string[] }>;
};

function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const character of value) {
    if (character === "(") depth += 1;
    if (character === ")") depth -= 1;
    if (character === "," && depth === 0) {
      parts.push(current.trim());
      current = "";
    } else {
      current += character;
    }
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

function unquoteIdentifier(value: string): string {
  return value.trim().replace(/^"|"$/g, "");
}

function roleNamesByReference(source: string): Map<string, string> {
  const names = new Map<string, string>();
  for (const match of source.matchAll(
    /export\s+const\s+(\w+)\s*=\s*pgRole\(\s*"([^"]+)"\s*,?\s*\)/g,
  )) {
    names.set(match[1]!, match[2]!);
  }
  const loginName = source.match(
    /export\s+const\s+appRuntimeLoginRoleName\s*=\s*"([^"]+)"/,
  )?.[1];
  if (loginName) names.set("appRuntimeLoginRoleName", loginName);
  return names;
}

function parseRoleAttributes(
  source: string,
): Record<string, ExpectedRoleAttributes> {
  const result: Record<string, ExpectedRoleAttributes> = {};
  const optionPattern =
    /\b(?:CREATE|ALTER)\s+ROLE\s+([a-z_][a-z0-9_]*)\s+([\s\S]*?);/gi;
  for (const match of source.matchAll(optionPattern)) {
    const roleName = match[1]!;
    const options = match[2]!
      .toUpperCase()
      .match(
        /\b(?:NOLOGIN|LOGIN|SUPERUSER|NOSUPERUSER|CREATEDB|NOCREATEDB|CREATEROLE|NOCREATEROLE|REPLICATION|NOREPLICATION|INHERIT|NOINHERIT|BYPASSRLS|NOBYPASSRLS)\b/g,
      );
    if (!options) continue;
    const has = (option: string) => options.includes(option);
    result[roleName] = {
      rolcanlogin: has("LOGIN") && !has("NOLOGIN"),
      rolsuper: has("SUPERUSER") && !has("NOSUPERUSER"),
      rolcreatedb: has("CREATEDB") && !has("NOCREATEDB"),
      rolcreaterole: has("CREATEROLE") && !has("NOCREATEROLE"),
      rolinherit: has("INHERIT") && !has("NOINHERIT"),
      rolreplication: has("REPLICATION") && !has("NOREPLICATION"),
      rolbypassrls: has("BYPASSRLS") && !has("NOBYPASSRLS"),
    };
  }
  return result;
}

function parsePolicies(
  sources: RlsCatalogSources,
  roles: Map<string, string>,
): ExpectedPolicy[] {
  const drizzlePolicies: Array<{
    policyName: string;
    command: string;
    roleReference: string;
  }> = [];
  const drizzlePattern =
    /pgPolicy\(\s*"([^"]+)"\s*,\s*\{\s*for:\s*"([^"]+)"\s*,\s*to:\s*(\w+)/g;
  for (const file of sources.schemaFiles) {
    for (const match of file.content.matchAll(drizzlePattern)) {
      drizzlePolicies.push({
        policyName: match[1]!,
        command: match[2]!.toUpperCase(),
        roleReference: match[3]!,
      });
    }
  }

  const sqlPolicyTables = new Map<string, string>();
  const sqlPattern =
    /\b(?:CREATE|ALTER)\s+POLICY\s+("?[\w$]+"?)\s+ON\s+public\.("?[\w$]+"?)/gi;
  for (const match of sources.policiesSql.matchAll(sqlPattern)) {
    const policyName = unquoteIdentifier(match[1]!);
    const tableName = unquoteIdentifier(match[2]!);
    if (sqlPolicyTables.has(policyName)) {
      throw new Error(
        `Duplicate canonical SQL policy declaration: ${policyName}`,
      );
    }
    sqlPolicyTables.set(policyName, tableName);
  }

  if (drizzlePolicies.length !== 34 || sqlPolicyTables.size !== 34) {
    throw new Error(
      "Canonical Drizzle/SQL sources must declare 34 RLS policies.",
    );
  }
  const seen = new Set<string>();
  return drizzlePolicies.map((policy) => {
    if (seen.has(policy.policyName)) {
      throw new Error(
        `Duplicate Drizzle policy declaration: ${policy.policyName}`,
      );
    }
    seen.add(policy.policyName);
    const tableName = sqlPolicyTables.get(policy.policyName);
    const roleName = roles.get(policy.roleReference);
    if (!tableName || !roleName) {
      throw new Error(
        `Incomplete canonical policy mapping: ${policy.policyName}`,
      );
    }
    return { ...policy, tableName, roleName };
  });
}

function parseMemberships(source: string): ExpectedMembership[] {
  const memberships: ExpectedMembership[] = [];
  const pattern =
    /\bGRANT\s+([a-z_][a-z0-9_]*)\s+TO\s+([a-z_][a-z0-9_]*)\s+WITH\s+INHERIT\s+(TRUE|FALSE)\s*,\s*SET\s+(TRUE|FALSE)\s*;/gi;
  for (const match of source.matchAll(pattern)) {
    memberships.push({
      grantedRole: match[1]!,
      memberRole: match[2]!,
      adminOption: false,
      inheritOption: match[3]!.toUpperCase() === "TRUE",
      setOption: match[4]!.toUpperCase() === "TRUE",
    });
  }
  return memberships;
}

function parseGrants(sources: string[]): ExpectedGrant[] {
  type GrantKey = string;
  const grants = new Map<
    GrantKey,
    {
      roleName: string;
      tableName: string;
      privilege: TablePrivilege;
      columns?: Set<string>;
    }
  >();
  const statementPattern =
    /\b(GRANT|REVOKE)\s+([^;]*?)\s+ON\s+TABLE\s+([^;]*?)\s+(TO|FROM)\s+([a-z_][a-z0-9_]*)\s*;/gi;

  for (const source of sources) {
    const withoutLineComments = source.replace(/--[^\n]*/g, "");
    for (const match of withoutLineComments.matchAll(statementPattern)) {
      const action = match[1]!.toUpperCase();
      const privilegeText = match[2]!.trim();
      const tables = splitTopLevel(match[3]!).map((table) =>
        unquoteIdentifier(table.replace(/^public\./i, "")),
      );
      const roleName = match[5]!;
      if (
        action === "REVOKE" &&
        privilegeText.toUpperCase() === "ALL PRIVILEGES"
      ) {
        for (const tableName of tables) {
          for (const key of grants.keys()) {
            if (key.startsWith(`${roleName}:${tableName}:`)) grants.delete(key);
          }
        }
        continue;
      }
      for (const item of splitTopLevel(privilegeText)) {
        const parsed = item.match(
          /^(SELECT|INSERT|UPDATE|DELETE)(?:\s*\(([\s\S]*)\))?$/i,
        );
        if (!parsed) continue;
        const privilege = parsed[1]!.toUpperCase() as TablePrivilege;
        const columns = parsed[2]
          ? splitTopLevel(parsed[2]).map(unquoteIdentifier)
          : undefined;
        for (const tableName of tables) {
          const key = `${roleName}:${tableName}:${privilege}`;
          if (action === "REVOKE") {
            if (!columns) grants.delete(key);
            else {
              const existing = grants.get(key);
              for (const column of columns) existing?.columns?.delete(column);
            }
            continue;
          }
          const existing = grants.get(key);
          if (!columns) {
            grants.set(key, { roleName, tableName, privilege });
          } else if (existing && !existing.columns) {
            // A table-level grant already covers every column.
          } else {
            const columnSet = existing?.columns ?? new Set<string>();
            for (const column of columns) columnSet.add(column);
            grants.set(key, {
              roleName,
              tableName,
              privilege,
              columns: columnSet,
            });
          }
        }
      }
    }
  }

  return [...grants.values()].map(({ columns, ...grant }) => ({
    ...grant,
    ...(columns ? { columns: [...columns].sort() } : {}),
  }));
}

export function parseRlsCatalogContract(
  sources: RlsCatalogSources,
): RlsCatalogContract {
  const roles = roleNamesByReference(sources.rolesSource);
  const policies = parsePolicies(sources, roles);
  const roleAttributes = parseRoleAttributes(sources.bootstrapSource);
  if (Object.keys(roleAttributes).length !== 3) {
    throw new Error(
      "Canonical role bootstrap must declare exactly three roles.",
    );
  }
  const policyCounts = new Map<string, number>();
  for (const policy of policies) {
    policyCounts.set(
      policy.tableName,
      (policyCounts.get(policy.tableName) ?? 0) + 1,
    );
  }
  for (const [tableName, count] of Object.entries(expectedRlsPolicyCounts)) {
    if (policyCounts.get(tableName) !== count) {
      throw new Error(`Canonical policy count mismatch for ${tableName}.`);
    }
  }
  if (policyCounts.size !== Object.keys(expectedRlsPolicyCounts).length) {
    throw new Error(
      "Canonical policy sources contain an unexpected RLS table.",
    );
  }
  return {
    policies,
    memberships: parseMemberships(sources.bootstrapSource),
    roles: roleAttributes,
    grants: parseGrants([sources.policiesSql, sources.bootstrapSource]),
  };
}

function grantFor(
  contract: RlsCatalogContract,
  roleName: string,
  tableName: string,
  privilege: TablePrivilege,
): ExpectedGrant | undefined {
  return contract.grants.find(
    (grant) =>
      grant.roleName === roleName &&
      grant.tableName === tableName &&
      grant.privilege === privilege,
  );
}

function expectedMembershipValue(
  memberRole: string,
  targetRole: string,
  edges: ExpectedMembership[],
  inheritOnly: boolean,
): boolean {
  if (memberRole === targetRole) return true;
  const visited = new Set<string>([memberRole]);
  const pending = [memberRole];
  while (pending.length) {
    const current = pending.shift()!;
    for (const edge of edges) {
      if (
        edge.memberRole !== current ||
        (inheritOnly && !edge.inheritOption) ||
        visited.has(edge.grantedRole)
      ) {
        continue;
      }
      if (edge.grantedRole === targetRole) return true;
      visited.add(edge.grantedRole);
      pending.push(edge.grantedRole);
    }
  }
  return false;
}

function sortedKey(values: string[]): string {
  return [...values].sort().join(",");
}

export type RlsCatalogAudit = {
  passed: boolean;
  expectedTableCount: number;
  expectedPolicyCount: number;
  violations: string[];
  tables: RlsCatalogSnapshot["tables"];
  policies: RlsCatalogSnapshot["policies"];
  roles: RlsCatalogSnapshot["roles"];
  memberships: RlsCatalogSnapshot["memberships"];
  pgHasRole: RlsCatalogSnapshot["pgHasRole"];
  tablePrivileges: RlsCatalogSnapshot["tablePrivileges"];
  updateColumns: RlsCatalogSnapshot["updateColumns"];
  tableColumns: RlsCatalogSnapshot["tableColumns"];
  limitations: string[];
};

export function auditRlsCatalog(
  contract: RlsCatalogContract,
  snapshot: RlsCatalogSnapshot,
): RlsCatalogAudit {
  const violations: string[] = [];
  const expectedTables = Object.keys(expectedRlsPolicyCounts).sort();
  const appRoleNames = new Set(Object.keys(contract.roles));
  const actualTables = [...snapshot.tables].sort((a, b) =>
    a.tableName.localeCompare(b.tableName),
  );
  if (
    sortedKey(actualTables.map((table) => table.tableName)) !==
    sortedKey(expectedTables)
  ) {
    violations.push("protected_table_set_mismatch");
  }
  for (const tableName of expectedTables) {
    const table = actualTables.find(
      (candidate) => candidate.tableName === tableName,
    );
    if (!table) continue;
    if (
      table.owner !== expectedDisposableRlsTableOwner ||
      appRoleNames.has(table.owner) ||
      applicationRoles.has(table.owner)
    ) {
      violations.push(`protected_table_owner_mismatch:${tableName}`);
    }
    if (!table.rlsEnabled || !table.rlsForced) {
      violations.push(`rls_not_enabled_and_forced:${tableName}`);
    }
  }

  const policyKey = (policy: { tableName: string; policyName: string }) =>
    `${policy.tableName}.${policy.policyName}`;
  const expectedPolicies = new Map(
    contract.policies.map((policy) => [policyKey(policy), policy]),
  );
  const actualPolicies = new Map(
    snapshot.policies.map((policy) => [policyKey(policy), policy]),
  );
  if (
    expectedPolicies.size !== 34 ||
    actualPolicies.size !== 34 ||
    [...expectedPolicies.keys()].some((key) => !actualPolicies.has(key)) ||
    [...actualPolicies.keys()].some((key) => !expectedPolicies.has(key))
  ) {
    violations.push("policy_identity_or_count_mismatch");
  }
  for (const [key, expected] of expectedPolicies) {
    const actual = actualPolicies.get(key);
    if (!actual) continue;
    if (
      actual.command.toUpperCase() !== expected.command ||
      sortedKey(actual.roles) !== expected.roleName ||
      actual.permissive !== "PERMISSIVE"
    ) {
      violations.push(`policy_metadata_mismatch:${expected.policyName}`);
    }
    const needsQual = ["SELECT", "UPDATE", "DELETE", "ALL"].includes(
      expected.command,
    );
    const needsCheck = ["INSERT", "UPDATE", "ALL"].includes(expected.command);
    if (
      (needsQual && !actual.qual?.trim()) ||
      (!needsQual && actual.qual !== null) ||
      (needsCheck && !actual.withCheck?.trim()) ||
      (!needsCheck && actual.withCheck !== null)
    ) {
      violations.push(`policy_predicate_shape_invalid:${expected.policyName}`);
    }
  }
  for (const [tableName, expectedCount] of Object.entries(
    expectedRlsPolicyCounts,
  )) {
    const actualCount = snapshot.policies.filter(
      (policy) => policy.tableName === tableName,
    ).length;
    if (actualCount !== expectedCount) {
      violations.push(`policy_count_mismatch:${tableName}`);
    }
  }

  const expectedRoleNames = Object.keys(contract.roles).sort();
  const actualRoleNames = snapshot.roles.map((role) => role.roleName).sort();
  if (sortedKey(expectedRoleNames) !== sortedKey(actualRoleNames)) {
    violations.push("role_set_mismatch");
  }
  for (const actual of snapshot.roles) {
    const expected = contract.roles[actual.roleName];
    if (
      !expected ||
      Object.keys(expected).some(
        (attribute) =>
          actual[attribute as keyof ExpectedRoleAttributes] !==
          expected[attribute as keyof ExpectedRoleAttributes],
      )
    ) {
      violations.push(`role_attribute_mismatch:${actual.roleName}`);
    }
  }

  const membershipKey = (membership: ExpectedMembership) =>
    `${membership.grantedRole}:${membership.memberRole}:${membership.adminOption}:${membership.inheritOption}:${membership.setOption}`;
  const expectedMemberships = contract.memberships.map(membershipKey).sort();
  const actualMemberships = snapshot.memberships.map(membershipKey).sort();
  if (sortedKey(expectedMemberships) !== sortedKey(actualMemberships)) {
    violations.push("direct_role_membership_mismatch");
  }

  const roleNames = expectedRoleNames;
  for (const memberRole of roleNames) {
    for (const targetRole of roleNames) {
      const actual = snapshot.pgHasRole.find(
        (item) =>
          item.memberRole === memberRole && item.targetRole === targetRole,
      );
      const expectedMember = expectedMembershipValue(
        memberRole,
        targetRole,
        contract.memberships,
        false,
      );
      const expectedUsage = expectedMembershipValue(
        memberRole,
        targetRole,
        contract.memberships,
        true,
      );
      if (
        !actual ||
        actual.member !== expectedMember ||
        actual.usage !== expectedUsage
      ) {
        violations.push(`pg_has_role_mismatch:${memberRole}:${targetRole}`);
      }
    }
  }

  for (const actual of snapshot.tablePrivileges) {
    const sourceGrant = grantFor(
      contract,
      actual.roleName,
      actual.tableName,
      actual.privilege,
    );
    const expected =
      sourceGrant !== undefined && sourceGrant.columns === undefined;
    if (actual.granted !== expected) {
      violations.push(
        `table_privilege_mismatch:${actual.roleName}:${actual.tableName}:${actual.privilege}`,
      );
    }
  }
  for (const tableName of expectedTables) {
    for (const roleName of roleNames) {
      for (const privilege of tablePrivileges) {
        if (
          !snapshot.tablePrivileges.some(
            (item) =>
              item.roleName === roleName &&
              item.tableName === tableName &&
              item.privilege === privilege,
          )
        ) {
          violations.push(
            `table_privilege_matrix_incomplete:${roleName}:${tableName}`,
          );
        }
      }
    }
  }

  for (const actual of snapshot.updateColumns) {
    const grant = grantFor(
      contract,
      actual.roleName,
      actual.tableName,
      "UPDATE",
    );
    const expected =
      grant !== undefined &&
      (grant.columns === undefined ||
        grant.columns.includes(actual.columnName));
    if (actual.granted !== expected) {
      violations.push(
        `column_update_mismatch:${actual.roleName}:${actual.tableName}:${actual.columnName}`,
      );
    }
  }
  for (const tableName of specialUpdateTables) {
    const expectedColumns = snapshot.tableColumns.find(
      (item) => item.tableName === tableName,
    );
    if (!expectedColumns?.columnNames.length) {
      violations.push(`table_column_inventory_missing:${tableName}`);
      continue;
    }
    for (const roleName of roleNames) {
      const actualColumns = snapshot.updateColumns
        .filter(
          (item) => item.tableName === tableName && item.roleName === roleName,
        )
        .map((item) => item.columnName)
        .sort();
      if (sortedKey(actualColumns) !== sortedKey(expectedColumns.columnNames)) {
        violations.push(
          `column_update_matrix_incomplete:${roleName}:${tableName}`,
        );
      }
    }
  }

  return {
    passed: violations.length === 0,
    expectedTableCount: expectedTables.length,
    expectedPolicyCount: contract.policies.length,
    violations: [...new Set(violations)].sort(),
    tables: actualTables,
    policies: [...snapshot.policies].sort((a, b) =>
      policyKey(a).localeCompare(policyKey(b)),
    ),
    roles: [...snapshot.roles].sort((a, b) =>
      a.roleName.localeCompare(b.roleName),
    ),
    memberships: [...snapshot.memberships].sort((a, b) =>
      membershipKey(a).localeCompare(membershipKey(b)),
    ),
    pgHasRole: [...snapshot.pgHasRole].sort((a, b) =>
      `${a.memberRole}:${a.targetRole}`.localeCompare(
        `${b.memberRole}:${b.targetRole}`,
      ),
    ),
    tablePrivileges: [...snapshot.tablePrivileges].sort((a, b) =>
      `${a.roleName}:${a.tableName}:${a.privilege}`.localeCompare(
        `${b.roleName}:${b.tableName}:${b.privilege}`,
      ),
    ),
    updateColumns: [...snapshot.updateColumns].sort((a, b) =>
      `${a.roleName}:${a.tableName}:${a.columnName}`.localeCompare(
        `${b.roleName}:${b.tableName}:${b.columnName}`,
      ),
    ),
    tableColumns: [...snapshot.tableColumns].sort((a, b) =>
      a.tableName.localeCompare(b.tableName),
    ),
    limitations: [
      "Policy identity, command, target role, permissive mode, and predicate presence are checked against Drizzle/SQL sources.",
      "PostgreSQL-deparsed qual/with_check expressions are included for review but are not compared semantically to source expressions.",
      "The separate runtime preflight is required to validate its authenticated-role and restricted worker-role checks.",
    ],
  };
}
