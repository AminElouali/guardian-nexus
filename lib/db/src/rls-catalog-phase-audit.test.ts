import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  auditRlsPostPushCatalog,
  canonicalizeRlsExpression,
  deriveRlsCatalogPhaseSnapshot,
  expectedPostPushRoleNames,
  orderedValuesEqual,
  postgresIdentifier,
  runPostSchemaAuditBarrier,
} from "./rls-catalog-phase-audit";
import { parseRlsCatalogContract } from "./rls-catalog-audit";

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

test("post-schema audit derives expected catalog from Drizzle and accepts policy shells", () => {
  const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "post-schema");
  const report = auditRlsPostPushCatalog(contract, snapshot, "post-schema");

  assert.equal(report.passed, true, report.violations.join(", "));
  assert.equal(report.expectedTableCount, 12);
  assert.equal(report.expectedPolicyCount, 34);
  assert.equal(report.stage, "post-schema");
  assert.deepEqual(expectedPostPushRoleNames(contract), [
    "app_ai_assessment_worker",
    "app_runtime",
  ]);
  assert.ok(snapshot.policies.every((policy) => policy.qual === null));
  assert.ok(snapshot.policies.every((policy) => policy.withCheck === null));
});

test("post-schema audit ignores memberships involving roles outside its stage", () => {
  const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "post-schema");
  snapshot.memberships.push({
    grantedRole: "app_runtime",
    memberRole: "app_runtime_login",
    adminOption: false,
    inheritOption: false,
    setOption: true,
  });

  const report = auditRlsPostPushCatalog(contract, snapshot, "post-schema");

  assert.equal(report.passed, true, report.violations.join(", "));
  assert.equal(report.violations.includes("role_membership_mismatch"), false);
});

test("Drizzle and policy SQL require expired approvals to have no decision timestamp", () => {
  const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const decisionCheck = snapshot.constraints.find(
    (constraint) =>
      constraint.constraintName === "ai_assessment_approval_decision_check",
  );
  assert.ok(decisionCheck?.expression);
  assert.match(
    decisionCheck.expression,
    /status["]? = 'expired'[\s\S]*decided_by_user_id["]? IS NULL[\s\S]*decided_by_role["]? IS NULL[\s\S]*decided_at["]? IS NULL/,
  );
  assert.match(
    sources.policiesSql,
    /OR \(status = 'expired'\s+AND decided_by_user_id IS NULL\s+AND decided_by_role IS NULL\s+AND decided_at IS NULL\)/,
  );
});

test("post-schema audit rejects omitted schema objects and invalid definitions", () => {
  const cases: Array<
    [string, (snapshot: ReturnType<typeof deriveRlsCatalogPhaseSnapshot>) => void]
  > = [
    ["table", (snapshot) => snapshot.tables.pop()],
    ["column", (snapshot) => snapshot.columns.pop()],
    ["index", (snapshot) => snapshot.indexes.pop()],
    ["constraint", (snapshot) => snapshot.constraints.pop()],
    ["policy", (snapshot) => snapshot.policies.pop()],
    [
      "index order",
      (snapshot) => {
        const composite = snapshot.indexes.find(
          (index) => index.columns.length > 1,
        );
        assert.ok(composite, "the Drizzle schema should include a composite index");
        composite.columns.reverse();
      },
    ],
    [
      "policy target role",
      (snapshot) => {
        snapshot.policies[0]!.roles = ["public"];
      },
    ],
    [
      "policy command",
      (snapshot) => {
        const policy = snapshot.policies.find((candidate) => candidate.command !== "DELETE");
        assert.ok(policy);
        policy.command = "DELETE";
      },
    ],
    [
      "policy permissive mode",
      (snapshot) => {
        snapshot.policies[0]!.permissive = "RESTRICTIVE";
      },
    ],
    [
      "unexpected policy predicate before SQL phase",
      (snapshot) => {
        snapshot.policies[0]!.qual = "true";
      },
    ],
    [
      "role hardening",
      (snapshot) => {
        snapshot.roles[0]!.rolbypassrls = true;
      },
    ],
    [
      "unexpected role membership",
      (snapshot) => {
        snapshot.memberships.push({
          grantedRole: "app_runtime",
          memberRole: "app_ai_assessment_worker",
          adminOption: true,
          inheritOption: true,
          setOption: true,
        });
      },
    ],
    [
      "RLS disabled",
      (snapshot) => {
        snapshot.tables[0]!.rlsEnabled = false;
      },
    ],
  ];

  for (const [label, mutate] of cases) {
    const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "post-schema");
    mutate(snapshot);
    const report = auditRlsPostPushCatalog(contract, snapshot, "post-schema");
    assert.equal(report.passed, false, `${label} must fail closed`);
    assert.ok(report.violations.length > 0);
  }
});

test("post-schema barrier rejects zero-exit Drizzle push when role hardening was skipped and reports violations", async () => {
  const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "post-schema");
  snapshot.roles = snapshot.roles.filter(
    (role) => role.roleName !== "app_runtime",
  );
  snapshot.policies = [];
  const observedSteps: string[] = [];

  const result = await runPostSchemaAuditBarrier(
    contract,
    async () => {
      observedSteps.push("drizzle_push_exit_0");
      return 0;
    },
    async () => {
      observedSteps.push("post_schema_audit");
      return snapshot;
    },
  );

  assert.deepEqual(observedSteps, [
    "drizzle_push_exit_0",
    "post_schema_audit",
  ]);
  assert.equal(result.audit.passed, false);
  assert.equal(result.report.stage, "post-schema");
  assert.equal(result.report.status, "failed");
  assert.ok(result.report.violationCodes.includes("role_inventory_mismatch"));
  assert.ok(result.report.violationCodes.includes("policy_inventory_mismatch"));
  assert.deepEqual(result.report.violationCodes, result.audit.violations);
});

test("ordered comparison rejects reordered composite constraint columns", () => {
  assert.equal(orderedValuesEqual(["tenant_id", "record_id"], [
    "record_id",
    "tenant_id",
  ]), false);
});

test("final audit compares policy ASTs and requires forced RLS and login role", () => {
  const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const report = auditRlsPostPushCatalog(contract, snapshot, "final");
  assert.equal(report.passed, true, report.violations.join(", "));
  assert.equal(report.stage, "final");
  assert.ok(snapshot.roles.some((role) => role.roleName === "app_runtime_login"));

  const changedPredicate = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const policyWithPredicate = changedPredicate.policies.find(
    (policy) => policy.qual !== null,
  );
  assert.ok(policyWithPredicate);
  policyWithPredicate.qual = "true";
  assert.equal(
    auditRlsPostPushCatalog(contract, changedPredicate, "final").passed,
    false,
  );

  const changedWithCheck = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const policyWithCheck = changedWithCheck.policies.find(
    (policy) => policy.withCheck !== null,
  );
  assert.ok(policyWithCheck);
  policyWithCheck.withCheck = "true";
  assert.equal(
    auditRlsPostPushCatalog(contract, changedWithCheck, "final").passed,
    false,
  );

  const alteredCommand = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const commandPolicy = alteredCommand.policies.find(
    (policy) => policy.command !== "DELETE",
  );
  assert.ok(commandPolicy);
  commandPolicy.command = "DELETE";
  assert.equal(
    auditRlsPostPushCatalog(contract, alteredCommand, "final").passed,
    false,
  );

  const alteredPermissive = deriveRlsCatalogPhaseSnapshot(contract, "final");
  alteredPermissive.policies[0]!.permissive = "RESTRICTIVE";
  assert.equal(
    auditRlsPostPushCatalog(contract, alteredPermissive, "final").passed,
    false,
  );

  const alteredRole = deriveRlsCatalogPhaseSnapshot(contract, "final");
  alteredRole.roles[0]!.rolbypassrls = true;
  assert.equal(
    auditRlsPostPushCatalog(contract, alteredRole, "final").passed,
    false,
  );

  const noForce = deriveRlsCatalogPhaseSnapshot(contract, "final");
  noForce.tables[0]!.rlsForced = false;
  assert.equal(auditRlsPostPushCatalog(contract, noForce, "final").passed, false);

  const noLogin = deriveRlsCatalogPhaseSnapshot(contract, "final");
  noLogin.roles = noLogin.roles.filter(
    (role) => role.roleName !== "app_runtime_login",
  );
  assert.equal(auditRlsPostPushCatalog(contract, noLogin, "final").passed, false);
});

test("unsupported policy expression syntax fails closed", () => {
  const snapshot = deriveRlsCatalogPhaseSnapshot(contract, "final");
  const policyWithPredicate = snapshot.policies.find(
    (policy) => policy.qual !== null,
  );
  assert.ok(policyWithPredicate);
  policyWithPredicate.qual = "unsupported (";
  const report = auditRlsPostPushCatalog(contract, snapshot, "final");
  assert.equal(report.passed, false);
  assert.ok(
    report.violations.some((code) =>
      code.startsWith("policy_using_expression_"),
    ),
  );
});

test("predicate canonicalization rejects unparsable catalog expressions", () => {
  assert.throws(() => canonicalizeRlsExpression("invalid (", "assets"));
});

test("predicate canonicalization handles PostgreSQL IN-to-ANY rewrites", () => {
  assert.equal(
    canonicalizeRlsExpression(
      "status IN ('queued'::text, 'done'::text)",
      "ai_assessment_jobs",
    ),
    canonicalizeRlsExpression(
      "status = ANY (ARRAY['queued'::text, 'done'::text])",
      "ai_assessment_jobs",
    ),
  );
});

test("predicate canonicalization handles PostgreSQL BETWEEN rewrites", () => {
  assert.equal(
    canonicalizeRlsExpression("attempts BETWEEN 0 AND 2", "ai_assessment_jobs"),
    canonicalizeRlsExpression(
      "attempts >= 0 AND attempts <= 2",
      "ai_assessment_jobs",
    ),
  );
});

test("predicate canonicalization equates explicit and default public schema", () => {
  assert.equal(
    canonicalizeRlsExpression(
      'EXISTS (SELECT 1 FROM "workspace_memberships" AS membership WHERE membership."workspace_id" = workspace_id)',
      "workspaces",
    ),
    canonicalizeRlsExpression(
      "EXISTS (SELECT 1 FROM public.workspace_memberships AS membership WHERE membership.workspace_id = workspace_id)",
      "workspaces",
    ),
  );
});

test("identifier comparison follows PostgreSQL byte-length truncation", () => {
  assert.equal(postgresIdentifier("n".repeat(70), 63), "n".repeat(63));
  assert.equal(postgresIdentifier("ab😀cd", 4), "ab");
});

test("CI keeps OIDC guard and post-schema barrier between push and RLS SQL", () => {
  const workflow = readFileSync(
    path.join(
      repositoryRoot,
      ".github/workflows/postgres-approval-lab.yml",
    ),
    "utf8",
  );
  const positions = [
    workflow.indexOf("on:\n  workflow_dispatch:"),
    workflow.indexOf("id-token: write"),
    workflow.indexOf("run harden-runtime-role:dev"),
    workflow.indexOf("run push"),
    workflow.indexOf("--stage=post-schema"),
    workflow.indexOf("run apply-rls-policies:dev"),
    workflow.lastIndexOf("verify-rls-catalog.ts"),
  ];
  assert.ok(positions.every((position) => position >= 0));
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b));
  assert.match(workflow, /verify-approval-lab-ci-target\.ts/);
  assert.match(workflow, /name: Audit complete disposable RLS catalog contract/);
  assert.doesNotMatch(workflow, /workflow_run:|pull_request:/);
});
