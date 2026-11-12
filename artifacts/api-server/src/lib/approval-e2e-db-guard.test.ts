import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { isExplicitDisposableApprovalDatabase } from "./approval-e2e-db-guard";

test("local approval lab requires explicit, loopback-only disposable opt-in", () => {
  const valid = {
    NODE_ENV: "development",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_DATABASE_NAME: "guardian_approval_lab_unit",
    DATABASE_URL:
      "postgresql://test-only-user:test-only-password@127.0.0.1:5432/guardian_approval_lab_unit",
    APP_RUNTIME_DATABASE_URL:
      "postgresql://app_runtime_login:test-only-runtime-password-0123456789abcdef@127.0.0.1:5432/guardian_approval_lab_unit",
  };
  assert.equal(isExplicitDisposableApprovalDatabase(valid), true);

  for (const unsafe of [
    { ...valid, DATABASE_URL: "postgresql://user:pass@db.example.invalid:5432/guardian_approval_lab_unit" },
    { ...valid, DATABASE_URL: "postgresql://user:pass@127.0.0.1:5432/workspace" },
    { ...valid, DATABASE_URL: `${valid.DATABASE_URL}?host=db.example.invalid` },
    {
      ...valid,
      APP_RUNTIME_DATABASE_URL:
        "postgresql://app_runtime_login:test-only-runtime-password-0123456789abcdef@db.example.invalid:5432/guardian_approval_lab_unit",
    },
    {
      ...valid,
      APP_RUNTIME_DATABASE_URL:
        "postgresql://app_runtime_login:test-only-runtime-password-0123456789abcdef@127.0.0.1:5432/workspace",
    },
    {
      ...valid,
      APP_RUNTIME_DATABASE_URL:
        "postgresql://app_runtime_login:test-only-runtime-password-0123456789abcdef@[::1]:5432/guardian_approval_lab_unit",
    },
    { ...valid, APP_RUNTIME_DATABASE_URL: undefined },
    { ...valid, PGHOST: "db.example.invalid" },
    { ...valid, APP_RUNTIME_DB_PASSWORD: "fallback-is-not-accepted" },
    { ...valid, REPLIT_DEPLOYMENT: "1" },
    {
      ...valid,
      GITHUB_ACTIONS: "true",
      GITHUB_REPOSITORY: "AminElouali/guardian-nexus",
      GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED:
        "guardian-approval-lab:123456789:2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    },
  ]) {
    assert.equal(isExplicitDisposableApprovalDatabase(unsafe), false);
  }
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
  assert.match(workflow, /permissions:\s+contents:\s+read\s+id-token:\s+write/);
  assert.match(workflow, /on:\s+workflow_dispatch:/);
  assert.doesNotMatch(
    workflow,
    /^\s*(?:push|pull_request):/m,
    "the privileged database job has no push or pull-request trigger",
  );
  assert.match(
    workflow,
    /github\.event_name == 'workflow_dispatch'[\s\S]*?github\.repository == 'AminElouali\/guardian-nexus'[\s\S]*?github\.ref_type == 'branch'[\s\S]*?github\.ref == 'refs\/heads\/main'/,
    "the job-level condition limits service creation to manual dispatch on trusted main",
  );
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
    /Test the disposable-target guard offline[\s\S]*?Test RLS catalog comparator offline[\s\S]*?Create the uniquely named lab database/,
    "offline target and catalog guards run before database creation",
  );
  assert.match(
    workflow,
    /verify-runtime-role:dev[\s\S]*?Audit complete disposable RLS catalog contract[\s\S]*?verify-rls-catalog\.ts[\s\S]*?Run persistent synthetic approval E2E/,
    "the catalog audit runs after provisioning and before the approval E2E",
  );
  assert.match(
    workflow,
    /Upload sanitized RLS catalog report[\s\S]*?actions\/upload-artifact@v4[\s\S]*?path:\s*\$\{\{\s*runner\.temp\s*\}\}\/guardian-postgres-rls-catalog-report\.json[\s\S]*?retention-days:\s*14/,
    "the sanitized catalog report is retained as a bounded job artifact",
  );
  const catalogAudit = readFileSync(
    new URL(
      "../../../../artifacts/api-server/src/scripts/verify-rls-catalog.ts",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(
    catalogAudit,
    /await isGitHubActionsApprovalLabTarget\(process\.env,\s*"approval-e2e"\)[\s\S]*?new Pool/,
    "the catalog script verifies OIDC before opening a connection",
  );
  assert.match(
    catalogAudit,
    /with_check AS "withCheck"[\s\S]*?FROM pg_policies/,
    "the report reads policy definitions without reading application rows",
  );
  assert.doesNotMatch(
    catalogAudit,
    /console\.(?:log|error)\([^)]*(?:databaseUrl|connectionString|process\.env)/i,
    "the script does not print connection data",
  );
  assert.doesNotMatch(
    catalogAudit,
    /assertRlsRuntimeReady|SELECT\s+result\s+FROM\s+public\.ai_assessment_jobs/i,
    "the catalog report does not invoke the application-row startup probe",
  );
  assert.doesNotMatch(
    `${workflow}\n${catalogAudit}`,
    /GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED|emit-verification-marker/,
    "no environment marker is accepted as OIDC proof",
  );
  const targetGuard = readFileSync(
    new URL(
      "../scripts/verify-approval-lab-ci-target.ts",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(
    targetGuard,
    /await diagnoseGitHubActionsApprovalLabTarget\(process\.env\)/,
    "the target guard awaits authenticated OIDC verification and safe diagnostics",
  );
  assert.match(
    targetGuard,
    /console\.error\(\s*JSON\.stringify\(\{\s*category:\s*decision\.category,\s*stage:\s*decision\.stage,?\s*\}\)\s*,?\s*\)/,
    "a rejected target prints only the safe category and stage identifier",
  );
  assert.match(
    targetGuard,
    /if \(!decision\.accepted\)[\s\S]*?process\.exitCode\s*=\s*1/,
    "a diagnostic rejection preserves a non-zero exit status",
  );
  assert.doesNotMatch(
    targetGuard,
    /console\.(?:log|error)\([^)]*(?:process\.env|DATABASE_URL|ACTIONS_ID_TOKEN_REQUEST_TOKEN|claims|requestUrl)/i,
    "the verifier never logs environment, token, claims, or connection data",
  );
  assert.doesNotMatch(
    targetGuard,
    /GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED|emit-verification-marker/,
    "the target guard does not generate a process-environment marker",
  );
  const approvalE2e = readFileSync(
    new URL("../ai-assessment-synthetic-approval-e2e.test.ts", import.meta.url),
    "utf8",
  );
  assert.match(
    approvalE2e,
    /await verifyExplicitDisposableApprovalDatabase\(process\.env\)[\s\S]*?await import\("@workspace\/db"\)/,
    "the E2E authenticates the job before importing the database pool",
  );
  assert.doesNotMatch(
    approvalE2e,
    /import\s+(?:\{[^}]*\}\s+from\s+)?["']@workspace\/db["']/,
    "the E2E has no static database import before the OIDC gate",
  );
});
