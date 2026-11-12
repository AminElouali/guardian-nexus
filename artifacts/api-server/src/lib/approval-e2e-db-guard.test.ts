import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  isExplicitDisposableApprovalDatabase,
  isGitHubActionsApprovalLabTarget,
} from "./approval-e2e-db-guard";

function githubRunEnvironment(stage: string) {
  const run = {
    GITHUB_RUN_ID: "123456789",
    GITHUB_RUN_ATTEMPT: "2",
    GITHUB_SHA: "a".repeat(40),
  };
  const adminPassword = `guardian-ci-${run.GITHUB_RUN_ID}-${run.GITHUB_RUN_ATTEMPT}-${run.GITHUB_SHA}`;
  const runtimePassword = `guardian-runtime-${run.GITHUB_RUN_ID}-${run.GITHUB_RUN_ATTEMPT}-${run.GITHUB_SHA}`;
  const common = {
    NODE_ENV: "development",
    CI: "true",
    GITHUB_ACTIONS: "true",
    GITHUB_WORKFLOW: "Guardian Nexus PostgreSQL Approval Lab",
    GITHUB_JOB: "postgres-approval-lab",
    ...run,
    GUARDIAN_APPROVAL_E2E_CI_SERVICE: "postgres",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_CI_STAGE: stage,
  };

  return {
    adminPassword,
    runtimePassword,
    common,
  };
}

function runIdForMarker(
  env: Readonly<Record<string, string | undefined>>,
): string {
  return `${env.GITHUB_RUN_ID}:${env.GITHUB_RUN_ATTEMPT}:${env.GITHUB_SHA}`;
}

test("GitHub Actions guard accepts only run-bound PostgreSQL lab targets", () => {
  const { adminPassword, runtimePassword, common } =
    githubRunEnvironment("bootstrap");
  const bootstrap = {
    ...common,
    DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/postgres`,
  };
  assert.equal(isGitHubActionsApprovalLabTarget(bootstrap), true);
  assert.equal(
    isGitHubActionsApprovalLabTarget({
      ...bootstrap,
      DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/workspace`,
    }),
    false,
    "bootstrap cannot target an application database",
  );

  const provision = {
    ...common,
    GUARDIAN_APPROVAL_E2E_CI_STAGE: "provision",
    DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/guardian_approval_lab_ci`,
  };
  assert.equal(isGitHubActionsApprovalLabTarget(provision), true);
  for (const unsafeTarget of [
    {
      ...provision,
      DATABASE_URL: `postgresql://postgres:${adminPassword}@db.example.invalid:5432/guardian_approval_lab_ci`,
    },
    {
      ...provision,
      DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5433/guardian_approval_lab_ci`,
    },
    {
      ...provision,
      DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/guardian_approval_lab_ci?host=db.example.invalid`,
    },
    {
      ...provision,
      DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/workspace`,
    },
    {
      ...provision,
      APP_RUNTIME_DATABASE_URL: `postgresql://app_runtime_login:${runtimePassword}@127.0.0.1:5432/guardian_approval_lab_ci`,
    },
    {
      ...provision,
      APP_RUNTIME_DB_PASSWORD: "not-the-run-bound-runtime-password",
    },
  ]) {
    assert.equal(
      isGitHubActionsApprovalLabTarget(unsafeTarget),
      false,
      "remote, overridden, wrong-port, shared, or mismatched targets fail closed",
    );
  }

  const { common: e2eCommon } = githubRunEnvironment("approval-e2e");
  const e2e = {
    ...e2eCommon,
    DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/guardian_approval_lab_ci`,
    APP_RUNTIME_DATABASE_URL: `postgresql://app_runtime_login:${runtimePassword}@127.0.0.1:5432/guardian_approval_lab_ci`,
  };
  assert.equal(isGitHubActionsApprovalLabTarget(e2e), true);
  assert.equal(isExplicitDisposableApprovalDatabase(e2e), true);
  const afterRuntimeConfigInitialization = {
    ...e2e,
    APP_RUNTIME_DATABASE_URL: undefined,
    GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED: `guardian-approval-lab:${runIdForMarker(e2e)}`,
  };
  assert.equal(
    isExplicitDisposableApprovalDatabase(afterRuntimeConfigInitialization),
    true,
    "the validated runtime target remains bound after db module initialization consumes its URL",
  );

  for (const unsafeTarget of [
    { ...e2e, GITHUB_JOB: "api-server" },
    { ...e2e, GITHUB_WORKFLOW: "other workflow" },
    { ...e2e, GITHUB_RUN_ID: "not-a-run-id" },
    { ...e2e, GUARDIAN_APPROVAL_E2E_CI_SERVICE: "other-service" },
    {
      ...e2e,
      APP_RUNTIME_DATABASE_URL: `postgresql://app_runtime_login:${runtimePassword}@db.example.invalid:5432/guardian_approval_lab_ci`,
    },
    {
      ...e2e,
      APP_RUNTIME_DATABASE_URL: `postgresql://app_runtime_login:${runtimePassword}@127.0.0.1:5432/workspace`,
    },
    {
      ...e2e,
      DATABASE_URL: `postgresql://postgres:shared-password@127.0.0.1:5432/guardian_approval_lab_ci`,
    },
    {
      ...e2e,
      GUARDIAN_APPROVAL_E2E_CI_STAGE: "provision",
    },
    {
      ...afterRuntimeConfigInitialization,
      GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED: "wrong-run",
    },
    {
      ...afterRuntimeConfigInitialization,
      PGHOST: "db.example.invalid",
    },
  ]) {
    assert.equal(
      isExplicitDisposableApprovalDatabase(unsafeTarget),
      false,
      "the E2E guard never falls back to a shared or mismatched URL in CI",
    );
  }

  assert.equal(
    isGitHubActionsApprovalLabTarget({
      ...bootstrap,
      GUARDIAN_APPROVAL_E2E_CI_STAGE: "unknown",
    }),
    false,
  );
  assert.equal(
    isGitHubActionsApprovalLabTarget({
      ...provision,
      REPLIT_DEPLOYMENT: "1",
    }),
    false,
  );
});

test("GitHub Actions lab workflow guards its isolated service before DB writes", () => {
  const workflow = readFileSync(
    new URL(
      "../../../../.github/workflows/postgres-approval-lab.yml",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(workflow, /name: Guardian Nexus PostgreSQL Approval Lab/);
  assert.match(workflow, /runs-on: ubuntu-24\.04/);
  assert.match(workflow, /postgres-approval-lab:/);
  assert.match(workflow, /image: postgres:16/);
  assert.match(workflow, /5432:5432/);
  assert.match(workflow, /permissions:\s+contents:\s+read/);
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(
    workflow,
    /Test the disposable-target guard offline[\s\S]*?approval-e2e-db-guard\.test\.ts[\s\S]*?Create the uniquely named lab database/,
    "the pure target-guard tests run before any DB creation",
  );
  assert.doesNotMatch(
    workflow,
    /\$\{\{\s*secrets\./,
    "the disposable lab does not use repository-provided database secrets",
  );
  assert.match(
    workflow,
    /verify-approval-lab-ci-target\.ts[\s\S]*?CREATE DATABASE guardian_approval_lab_ci;/,
    "the target guard precedes creation of the named database",
  );
  assert.match(
    workflow,
    /run: \|[\s\S]*?verify-approval-lab-ci-target\.ts[\s\S]*?pnpm --filter @workspace\/db run push[\s\S]*?apply-rls-policies:dev[\s\S]*?verify-runtime-role:dev/,
    "the schema and role/RLS commands follow the documented order",
  );
  assert.match(
    workflow,
    /verify-approval-lab-ci-target\.ts[\s\S]*?ai-assessment-synthetic-approval-e2e\.test\.ts/,
    "the target guard precedes the persistent approval test",
  );
  assert.match(
    workflow,
    /--emit-verification-marker[\s\S]*?export GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED/,
    "the pre-import target verification survives the runtime URL being consumed",
  );
});
