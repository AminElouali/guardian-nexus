import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  auditRlsCatalog,
  parseRlsCatalogContract,
  type RlsCatalogSnapshot,
} from "./rls-catalog-audit";
import { expectedRlsPolicyCounts } from "./rls-catalog-contract";

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const schemaDirectory = path.join(repositoryRoot, "lib/db/src/schema");
const sources = {
  schemaFiles: readdirSync(schemaDirectory)
    .filter((name) => name.endsWith(".ts"))
    .sort()
    .map((name) => ({
      path: name,
      content: readFileSync(path.join(schemaDirectory, name), "utf8"),
    })),
  rolesSource: readFileSync(path.join(schemaDirectory, "roles.ts"), "utf8"),
  bootstrapSource: readFileSync(
    path.join(repositoryRoot, "lib/db/scripts/bootstrap-runtime-role.mjs"),
    "utf8",
  ),
  policiesSql: readFileSync(
    path.join(repositoryRoot, "lib/db/sql/rls-policies.sql"),
    "utf8",
  ),
};

const contract = parseRlsCatalogContract(sources);
const tableNames = Object.keys(expectedRlsPolicyCounts);
const specialTables = [
  "ai_assessment_jobs",
  "host_boundary_attestation_challenges",
  "ai_assessment_approval_requests",
];
const testColumns: Record<string, string[]> = {
  ai_assessment_jobs: [
    "id",
    "workspace_id",
    "requested_by_user_id",
    "profile_id",
    "status",
    "result",
  ],
  host_boundary_attestation_challenges: [
    "id",
    "consumed_at",
    "status",
    "response_sha256",
    "supervisor_id",
    "updated_at",
  ],
  ai_assessment_approval_requests: [
    "id",
    "status",
    "decided_by_user_id",
    "decided_by_role",
    "decided_at",
    "simulated_at",
    "simulation_result_code",
    "simulation_result_sha256",
    "replay_binding_sha256",
    "updated_at",
    "proposal_sha256",
    "workspace_id",
  ],
};
const privileges = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

function hasRole(
  memberRole: string,
  targetRole: string,
  edges: typeof contract.memberships,
  inheritedOnly: boolean,
): boolean {
  if (memberRole === targetRole) return true;
  const seen = new Set([memberRole]);
  const pending = [memberRole];
  while (pending.length) {
    const current = pending.shift()!;
    for (const edge of edges) {
      if (
        edge.memberRole !== current ||
        (inheritedOnly && !edge.inheritOption) ||
        seen.has(edge.grantedRole)
      ) {
        continue;
      }
      if (edge.grantedRole === targetRole) return true;
      seen.add(edge.grantedRole);
      pending.push(edge.grantedRole);
    }
  }
  return false;
}

function makeSnapshot(): RlsCatalogSnapshot {
  const roleNames = Object.keys(contract.roles);
  const tables = tableNames.map((tableName) => ({
    tableName,
    owner: "postgres",
    rlsEnabled: true,
    rlsForced: true,
  }));
  const policies = contract.policies.map((policy) => {
    const needsQual = ["SELECT", "UPDATE", "DELETE", "ALL"].includes(
      policy.command,
    );
    const needsCheck = ["INSERT", "UPDATE", "ALL"].includes(policy.command);
    return {
      tableName: policy.tableName,
      policyName: policy.policyName,
      permissive: "PERMISSIVE",
      command: policy.command,
      roles: [policy.roleName],
      qual: needsQual ? "(synthetic tenant predicate)" : null,
      withCheck: needsCheck ? "(synthetic tenant check)" : null,
    };
  });
  const roles = roleNames.map((roleName) => ({
    roleName,
    ...contract.roles[roleName]!,
  }));
  const memberships = [...contract.memberships];
  const pgHasRole = roleNames.flatMap((memberRole) =>
    roleNames.map((targetRole) => ({
      memberRole,
      targetRole,
      member: hasRole(memberRole, targetRole, memberships, false),
      usage: hasRole(memberRole, targetRole, memberships, true),
    })),
  );
  const tablePrivileges = roleNames.flatMap((roleName) =>
    tableNames.flatMap((tableName) =>
      privileges.map((privilege) => ({
        roleName,
        tableName,
        privilege,
        granted: contract.grants.some(
          (grant) =>
            grant.roleName === roleName &&
            grant.tableName === tableName &&
            grant.privilege === privilege &&
            grant.columns === undefined,
        ),
      })),
    ),
  );
  const tableColumns = specialTables.map((tableName) => ({
    tableName,
    columnNames: testColumns[tableName]!,
  }));
  const updateColumns = roleNames.flatMap((roleName) =>
    tableColumns.flatMap(({ tableName, columnNames }) =>
      columnNames.map((columnName) => {
        const grant = contract.grants.find(
          (candidate) =>
            candidate.roleName === roleName &&
            candidate.tableName === tableName &&
            candidate.privilege === "UPDATE",
        );
        return {
          roleName,
          tableName,
          columnName,
          granted:
            grant !== undefined &&
            (grant.columns === undefined || grant.columns.includes(columnName)),
        };
      }),
    ),
  );
  return {
    tables,
    policies,
    roles,
    memberships,
    pgHasRole,
    tablePrivileges,
    updateColumns,
    tableColumns,
  };
}

test("RLS catalog contract is derived from Drizzle, SQL and role bootstrap sources", () => {
  assert.equal(tableNames.length, 12);
  assert.equal(contract.policies.length, 34);
  assert.equal(
    contract.policies.filter(
      (policy) =>
        policy.tableName === "ai_assessment_jobs" &&
        policy.roleName === "app_ai_assessment_worker",
    ).length,
    2,
  );
  assert.ok(
    contract.policies
      .filter((policy) => policy.tableName !== "ai_assessment_jobs")
      .every((policy) => policy.roleName === "app_runtime"),
  );
  assert.ok(
    contract.policies
      .filter((policy) => policy.tableName === "ai_assessment_jobs")
      .filter((policy) => policy.roleName === "app_runtime").length === 3,
  );
  assert.deepEqual(contract.roles, {
    app_runtime: {
      rolcanlogin: false,
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolinherit: false,
      rolreplication: false,
      rolbypassrls: false,
    },
    app_ai_assessment_worker: {
      rolcanlogin: false,
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolinherit: false,
      rolreplication: false,
      rolbypassrls: false,
    },
    app_runtime_login: {
      rolcanlogin: true,
      rolsuper: false,
      rolcreatedb: false,
      rolcreaterole: false,
      rolinherit: false,
      rolreplication: false,
      rolbypassrls: false,
    },
  });
  assert.deepEqual(
    contract.grants
      .filter(
        (grant) =>
          grant.roleName === "app_runtime" &&
          grant.tableName === "host_boundary_attestation_challenges" &&
          grant.privilege === "UPDATE",
      )
      .map((grant) => grant.columns?.sort()),
    [
      [
        "consumed_at",
        "response_sha256",
        "status",
        "supervisor_id",
        "updated_at",
      ],
    ],
  );
  assert.deepEqual(
    contract.grants
      .find(
        (grant) =>
          grant.roleName === "app_runtime" &&
          grant.tableName === "ai_assessment_approval_requests" &&
          grant.privilege === "UPDATE",
      )
      ?.columns?.sort(),
    [
      "decided_at",
      "decided_by_role",
      "decided_by_user_id",
      "replay_binding_sha256",
      "simulated_at",
      "simulation_result_code",
      "simulation_result_sha256",
      "status",
      "updated_at",
    ],
  );
  assert.deepEqual(
    contract.grants
      .find(
        (grant) =>
          grant.roleName === "app_ai_assessment_worker" &&
          grant.tableName === "ai_assessment_jobs" &&
          grant.privilege === "UPDATE",
      )
      ?.columns?.sort(),
    [
      "attempts",
      "completed_at",
      "error_code",
      "heartbeat_at",
      "lease_expires_at",
      "lease_owner_id",
      "started_at",
      "status",
      "updated_at",
      "worker_slot",
    ],
  );
  assert.equal(
    contract.grants.some(
      (grant) =>
        grant.roleName === "app_ai_assessment_worker" &&
        grant.tableName !== "ai_assessment_jobs",
    ),
    false,
  );
  assert.deepEqual(
    contract.memberships.map(({ grantedRole, memberRole }) => [
      grantedRole,
      memberRole,
    ]),
    [
      ["app_ai_assessment_worker", "app_runtime"],
      ["app_runtime", "app_runtime_login"],
    ],
  );
});

test("complete synthetic PostgreSQL catalog snapshot satisfies the contract", () => {
  const report = auditRlsCatalog(contract, makeSnapshot());
  assert.equal(report.passed, true, report.violations.join(", "));
  assert.equal(report.expectedTableCount, 12);
  assert.equal(report.expectedPolicyCount, 34);
  assert.equal(report.policies.length, 34);
  assert.equal(report.tablePrivileges.length, 3 * 12 * 4);
  assert.equal(report.updateColumns.length, 3 * (6 + 6 + 12));
});

test("catalog audit fails closed for missing RLS, policy drift, role grants and column updates", () => {
  const cases: Array<[string, (snapshot: RlsCatalogSnapshot) => void]> = [
    [
      "RLS disabled",
      (snapshot) => {
        snapshot.tables[0]!.rlsEnabled = false;
      },
    ],
    [
      "forced RLS missing",
      (snapshot) => {
        snapshot.tables[0]!.rlsForced = false;
      },
    ],
    [
      "policy missing",
      (snapshot) => {
        snapshot.policies.pop();
      },
    ],
    [
      "policy target role changed",
      (snapshot) => {
        snapshot.policies[0]!.roles = [];
      },
    ],
    [
      "policy predicate missing",
      (snapshot) => {
        const selectPolicy = snapshot.policies.find(
          (policy) => policy.command === "SELECT",
        )!;
        selectPolicy.qual = null;
      },
    ],
    [
      "runtime table grant added",
      (snapshot) => {
        snapshot.tablePrivileges.find(
          (item) =>
            item.roleName === "app_runtime_login" &&
            item.tableName === "workspaces" &&
            item.privilege === "SELECT",
        )!.granted = true;
      },
    ],
    [
      "extra special-column UPDATE",
      (snapshot) => {
        snapshot.updateColumns.find(
          (item) =>
            item.roleName === "app_runtime" &&
            item.tableName === "host_boundary_attestation_challenges" &&
            item.columnName === "id",
        )!.granted = true;
      },
    ],
    [
      "unexpected role membership",
      (snapshot) => {
        snapshot.memberships.push({
          grantedRole: "app_ai_assessment_worker",
          memberRole: "app_runtime_login",
          adminOption: false,
          inheritOption: true,
          setOption: true,
        });
      },
    ],
  ];

  for (const [label, mutate] of cases) {
    const snapshot = makeSnapshot();
    mutate(snapshot);
    const report = auditRlsCatalog(contract, snapshot);
    assert.equal(report.passed, false, `${label} must fail closed`);
    assert.ok(
      report.violations.length > 0,
      `${label} must produce a violation`,
    );
  }
});
