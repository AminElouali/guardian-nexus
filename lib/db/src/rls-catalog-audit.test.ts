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
const roleNames = [
  "app_runtime",
  "app_ai_assessment_worker",
  "app_runtime_login",
] as const;
const fullRuntimeAccessTables = [
  "workspaces",
  "workspace_memberships",
  "assets",
  "workspace_monthly_usage",
  "workspace_audit_events",
  "workspace_integrations",
  "provider_connections",
  "connector_oauth_states",
  "connector_jobs",
  "ai_assessment_jobs",
] as const;
const fixedTableGrantKeys = new Set([
  ...fullRuntimeAccessTables.flatMap((tableName) =>
    ["SELECT", "INSERT", "UPDATE", "DELETE"].map(
      (privilege) => `app_runtime:${tableName}:${privilege}`,
    ),
  ),
  ...[
    "host_boundary_attestation_challenges",
    "ai_assessment_approval_requests",
    "workspace_approval_ledger",
    "workspace_action_rule_versions",
  ].flatMap((tableName) =>
    ["SELECT", "INSERT"].map(
      (privilege) => `app_runtime:${tableName}:${privilege}`,
    ),
  ),
  ...["workspace_action_rule_heads", "workspace_agents"].flatMap(
    (tableName) =>
      ["SELECT", "INSERT", "UPDATE"].map(
        (privilege) => `app_runtime:${tableName}:${privilege}`,
      ),
  ),
  "app_runtime:workspace_connector_credentials:SELECT",
  "app_runtime:workspace_connector_credentials:DELETE",
  "app_runtime:workspace_connector_executions:SELECT",
  "app_runtime:workspace_approval_receipts:SELECT",
]);
const specialTables = [
  "ai_assessment_jobs",
  "host_boundary_attestation_challenges",
  "ai_assessment_approval_requests",
  "workspace_connector_credentials",
  "workspace_connector_executions",
  "workspace_approval_receipts",
];
const insertTables = [
  "workspace_connector_credentials",
  "workspace_connector_executions",
  "workspace_approval_receipts",
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
  workspace_connector_credentials: [
    "id",
    "workspace_id",
    "service_id",
    "encrypted_secret",
    "nonce",
    "auth_tag",
    "encryption_key_id",
    "last_four",
    "created_by_user_id",
    "created_at",
  ],
  workspace_connector_executions: [
    "id",
    "workspace_id",
    "service_id",
    "credential_id",
    "idempotency_key_sha256",
    "action_type",
    "action_sha256",
    "receipt_id",
    "requested_by_user_id",
    "status",
    "response_summary",
    "failure_code",
    "created_at",
    "updated_at",
    "completed_at",
  ],
  workspace_approval_receipts: [
    "approval_id",
    "workspace_id",
    "receipt_id",
    "receipt_sha256",
    "signed_receipt",
    "approved_by_user_id",
    "created_at",
  ],
};
const fixedInsertColumnGrantKeys = new Set([
  ...[
    "workspace_id",
    "service_id",
    "encrypted_secret",
    "nonce",
    "auth_tag",
    "encryption_key_id",
    "last_four",
    "created_by_user_id",
  ].map((columnName) =>
    `app_runtime:workspace_connector_credentials:${columnName}`,
  ),
  ...[
    "workspace_id",
    "service_id",
    "credential_id",
    "idempotency_key_sha256",
    "action_type",
    "action_sha256",
    "receipt_id",
    "requested_by_user_id",
    "status",
  ].map((columnName) =>
    `app_runtime:workspace_connector_executions:${columnName}`,
  ),
  ...[
    "approval_id",
    "workspace_id",
    "receipt_id",
    "receipt_sha256",
    "signed_receipt",
    "approved_by_user_id",
  ].map((columnName) =>
    `app_runtime:workspace_approval_receipts:${columnName}`,
  ),
]);
const fixedUpdateColumnGrantKeys = new Set([
  ...[
    "id",
    "workspace_id",
    "requested_by_user_id",
    "profile_id",
    "status",
    "result",
  ].map((columnName) => `app_runtime:ai_assessment_jobs:${columnName}`),
  "app_ai_assessment_worker:ai_assessment_jobs:status",
  ...[
    "consumed_at",
    "status",
    "response_sha256",
    "supervisor_id",
    "updated_at",
  ].map((columnName) =>
    `app_runtime:host_boundary_attestation_challenges:${columnName}`,
  ),
  ...[
    "status",
    "decided_by_user_id",
    "decided_by_role",
    "decided_at",
    "simulated_at",
    "simulation_result_code",
    "simulation_result_sha256",
    "replay_binding_sha256",
    "updated_at",
  ].map((columnName) =>
    `app_runtime:ai_assessment_approval_requests:${columnName}`,
  ),
  ...[
    "status",
    "response_summary",
    "failure_code",
    "updated_at",
    "completed_at",
  ].map((columnName) =>
    `app_runtime:workspace_connector_executions:${columnName}`,
  ),
]);
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
        granted: fixedTableGrantKeys.has(
          `${roleName}:${tableName}:${privilege}`,
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
        return {
          roleName,
          tableName,
          columnName,
          granted: fixedUpdateColumnGrantKeys.has(
            `${roleName}:${tableName}:${columnName}`,
          ),
        };
      }),
    ),
  );
  const insertColumns = roleNames.flatMap((roleName) =>
    insertTables.flatMap((tableName) =>
      testColumns[tableName]!.map((columnName) => ({
        roleName,
        tableName,
        columnName,
        granted: fixedInsertColumnGrantKeys.has(
          `${roleName}:${tableName}:${columnName}`,
        ),
      })),
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
    insertColumns,
    tableColumns,
  };
}

test("RLS catalog contract is derived from Drizzle, SQL and role bootstrap sources", () => {
  assert.equal(tableNames.length, 19);
  assert.equal(contract.policies.length, 53);
  assert.deepEqual(
    contract.policies
      .filter((policy) => policy.tableName === "workspace_approval_ledger")
      .map(({ policyName, command, roleName }) => ({
        policyName,
        command,
        roleName,
      }))
      .sort((left, right) => left.policyName.localeCompare(right.policyName)),
    [
      {
        policyName: "workspace_approval_ledger_insert_owner_admin",
        command: "INSERT",
        roleName: "app_runtime",
      },
      {
        policyName: "workspace_approval_ledger_select_member",
        command: "SELECT",
        roleName: "app_runtime",
      },
    ],
  );
  assert.deepEqual(
    contract.grants.filter(
      (grant) => grant.tableName === "workspace_approval_ledger",
    ),
    [
      {
        roleName: "app_runtime",
        tableName: "workspace_approval_ledger",
        privilege: "SELECT",
      },
      {
        roleName: "app_runtime",
        tableName: "workspace_approval_ledger",
        privilege: "INSERT",
      },
    ],
  );
  assert.deepEqual(
    contract.grants.filter(
      (grant) => grant.tableName === "workspace_action_rule_versions",
    ),
    [
      {
        roleName: "app_runtime",
        tableName: "workspace_action_rule_versions",
        privilege: "SELECT",
      },
      {
        roleName: "app_runtime",
        tableName: "workspace_action_rule_versions",
        privilege: "INSERT",
      },
    ],
  );
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
    contract.grants.filter(
      (grant) =>
        grant.roleName === "app_runtime" &&
        grant.tableName === "workspace_connector_credentials",
    ),
    [
      {
        roleName: "app_runtime",
        tableName: "workspace_connector_credentials",
        privilege: "SELECT",
      },
      {
        roleName: "app_runtime",
        tableName: "workspace_connector_credentials",
        privilege: "DELETE",
      },
      {
        roleName: "app_runtime",
        tableName: "workspace_connector_credentials",
        privilege: "INSERT",
        columns: [
          "auth_tag",
          "created_by_user_id",
          "encrypted_secret",
          "encryption_key_id",
          "last_four",
          "nonce",
          "service_id",
          "workspace_id",
        ],
      },
    ],
  );
  assert.deepEqual(
    contract.grants.filter(
      (grant) =>
        grant.roleName === "app_runtime" &&
        grant.tableName === "workspace_connector_executions",
    ),
    [
      {
        roleName: "app_runtime",
        tableName: "workspace_connector_executions",
        privilege: "SELECT",
      },
      {
        roleName: "app_runtime",
        tableName: "workspace_connector_executions",
        privilege: "INSERT",
        columns: [
          "action_sha256",
          "action_type",
          "credential_id",
          "idempotency_key_sha256",
          "receipt_id",
          "requested_by_user_id",
          "service_id",
          "status",
          "workspace_id",
        ],
      },
      {
        roleName: "app_runtime",
        tableName: "workspace_connector_executions",
        privilege: "UPDATE",
        columns: [
          "completed_at",
          "failure_code",
          "response_summary",
          "status",
          "updated_at",
        ],
      },
    ],
  );
  assert.equal(
    contract.grants.some(
      (grant) =>
        grant.roleName === "app_runtime" &&
        grant.tableName === "workspace_connector_executions" &&
        grant.privilege === "DELETE",
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
  assert.equal(report.expectedTableCount, 19);
  assert.equal(report.expectedPolicyCount, 53);
  assert.equal(report.policies.length, 53);
  assert.equal(report.tablePrivileges.length, 3 * 19 * 4);
  assert.equal(report.updateColumns.length, 3 * (6 + 6 + 12 + 10 + 15 + 7));
  assert.equal(report.insertColumns.length, 3 * (10 + 15 + 7));
});

test("catalog audit checks exact execution UPDATE grants and complete column coverage", () => {
  const extraGrant = makeSnapshot();
  const unapprovedColumn = extraGrant.updateColumns.find(
    (item) =>
      item.roleName === "app_runtime" &&
      item.tableName === "workspace_connector_executions" &&
      item.columnName === "action_sha256",
  );
  assert.ok(unapprovedColumn);
  unapprovedColumn.granted = true;
  const extraGrantAudit = auditRlsCatalog(contract, extraGrant);
  assert.ok(
    extraGrantAudit.violations.includes(
      "column_update_mismatch:app_runtime:workspace_connector_executions:action_sha256",
    ),
  );

  const incompleteMatrix = makeSnapshot();
  incompleteMatrix.updateColumns = incompleteMatrix.updateColumns.filter(
    (item) =>
      !(
        item.roleName === "app_runtime" &&
        item.tableName === "workspace_connector_executions" &&
        item.columnName === "action_sha256"
      ),
  );
  const incompleteAudit = auditRlsCatalog(contract, incompleteMatrix);
  assert.ok(
    incompleteAudit.violations.includes(
      "column_update_matrix_incomplete:app_runtime:workspace_connector_executions",
    ),
  );
});

test("catalog audit checks exact connector INSERT grants and complete column coverage", () => {
  const extraInsert = makeSnapshot();
  const unauthorizedCredentialId = extraInsert.insertColumns.find(
    (item) =>
      item.roleName === "app_runtime" &&
      item.tableName === "workspace_connector_credentials" &&
      item.columnName === "id",
  );
  assert.ok(unauthorizedCredentialId);
  unauthorizedCredentialId.granted = true;
  const extraInsertAudit = auditRlsCatalog(contract, extraInsert);
  assert.ok(
    extraInsertAudit.violations.includes(
      "column_insert_mismatch:app_runtime:workspace_connector_credentials:id",
    ),
  );

  const missingInsert = makeSnapshot();
  const approvedCredentialWorkspaceId = missingInsert.insertColumns.find(
    (item) =>
      item.roleName === "app_runtime" &&
      item.tableName === "workspace_connector_credentials" &&
      item.columnName === "workspace_id",
  );
  assert.ok(approvedCredentialWorkspaceId);
  approvedCredentialWorkspaceId.granted = false;
  const missingInsertAudit = auditRlsCatalog(contract, missingInsert);
  assert.ok(
    missingInsertAudit.violations.includes(
      "column_insert_mismatch:app_runtime:workspace_connector_credentials:workspace_id",
    ),
  );

  const incompleteMatrix = makeSnapshot();
  incompleteMatrix.insertColumns = incompleteMatrix.insertColumns.filter(
    (item) =>
      !(
        item.roleName === "app_runtime" &&
        item.tableName === "workspace_connector_executions" &&
        item.columnName === "workspace_id"
      ),
  );
  const incompleteAudit = auditRlsCatalog(contract, incompleteMatrix);
  assert.ok(
    incompleteAudit.violations.includes(
      "column_insert_matrix_incomplete:app_runtime:workspace_connector_executions",
    ),
  );
});

test("catalog audit fails closed for missing RLS, policy drift, role grants and column permissions", () => {
  const cases: Array<[string, (snapshot: RlsCatalogSnapshot) => void]> = [
    [
      "unexpected table owner",
      (snapshot) => {
        snapshot.tables[0]!.owner = "unrecognized_owner";
      },
    ],
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
      "extra connector-column INSERT",
      (snapshot) => {
        snapshot.insertColumns.find(
          (item) =>
            item.roleName === "app_runtime" &&
            item.tableName === "workspace_connector_credentials" &&
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
