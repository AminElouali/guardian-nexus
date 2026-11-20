import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { generateKeyPairSync, sign as signJwt } from "node:crypto";
import { createServer } from "node:net";
import { test } from "node:test";
import os from "node:os";
import path from "node:path";
import {
  diagnoseGitHubActionsApprovalLabTarget,
  isExplicitDisposableApprovalDatabase,
} from "./approval-e2e-db-guard";
import {
  GITHUB_ACTIONS_OIDC_ISSUER,
  GITHUB_ACTIONS_RLS_AUDIENCE,
  GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
  GITHUB_ACTIONS_TRUSTED_REPOSITORY_OWNER_ID,
} from "./github-actions-oidc";

const testRepository = "AminElouali/guardian-nexus";
const testWorkflow = "Guardian Nexus PostgreSQL Approval Lab";
const ciSigningKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ciSigningJwk = {
  ...(ciSigningKey.publicKey.export({ format: "jwk" }) as {
    kty: string;
    n: string;
    e: string;
  }),
  kid: "test-approval-lab-key",
  use: "sig",
  alg: "RS256",
  key_ops: ["verify"],
};

function approvalLabWorkflowRef(ref: string): string {
  return `${testRepository}/.github/workflows/postgres-approval-lab.yml@${ref}`;
}

function signedApprovalLabToken(
  ref: string,
  overrides: Record<string, unknown> = {},
): string {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({
    alg: "RS256",
    kid: "test-approval-lab-key",
    typ: "JWT",
  })).toString("base64url");
  const payload = Buffer.from(JSON.stringify({
    iss: GITHUB_ACTIONS_OIDC_ISSUER,
    aud: GITHUB_ACTIONS_RLS_AUDIENCE,
    sub: `repo:${testRepository}:ref:${ref}`,
    repository: testRepository,
    repository_id: GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
    repository_owner: "AminElouali",
    repository_owner_id: GITHUB_ACTIONS_TRUSTED_REPOSITORY_OWNER_ID,
    event_name: "workflow_dispatch",
    ref,
    ref_type: "branch",
    workflow: testWorkflow,
    workflow_ref: approvalLabWorkflowRef(ref),
    workflow_sha: "c".repeat(40),
    sha: "a".repeat(40),
    run_id: "123456789",
    run_attempt: "2",
    jti: `test-jti-${ref}`,
    iat: now - 10,
    nbf: now - 10,
    exp: now + 240,
    ...overrides,
  })).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signature = signJwt(
    "RSA-SHA256",
    Buffer.from(signingInput),
    ciSigningKey.privateKey,
  ).toString("base64url");
  return `${signingInput}.${signature}`;
}

function approvalLabEnvironment(ref: string): Record<string, string> {
  const sha = "a".repeat(40);
  const runId = "123456789";
  const runAttempt = "2";
  const passwordSuffix = `${runId}-${runAttempt}-${sha}`;
  return {
    NODE_ENV: "development",
    CI: "true",
    GITHUB_ACTIONS: "true",
    GITHUB_WORKFLOW: testWorkflow,
    GITHUB_WORKFLOW_REF: approvalLabWorkflowRef(ref),
    GITHUB_JOB: "postgres-approval-lab",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: testRepository,
    GITHUB_REF: ref,
    GITHUB_REF_TYPE: "branch",
    GITHUB_RUN_ID: runId,
    GITHUB_RUN_ATTEMPT: runAttempt,
    GITHUB_SHA: sha,
    ACTIONS_ID_TOKEN_REQUEST_URL: "https://token.invalid/request",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "test-only-token-request",
    GUARDIAN_APPROVAL_E2E_CI_SERVICE: "postgres",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_CI_STAGE: "approval-e2e",
    DATABASE_URL:
      `postgresql://postgres:guardian-ci-${passwordSuffix}@127.0.0.1:5432/guardian_approval_lab_ci`,
    APP_RUNTIME_DATABASE_URL:
      `postgresql://app_runtime_login:guardian-runtime-${passwordSuffix}@127.0.0.1:5432/guardian_approval_lab_ci`,
  };
}

async function withTestJwks<T>(run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async () =>
    Response.json({ keys: [ciSigningJwk] })) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("local approval lab requires an explicit private Unix-socket target", async () => {
  const labRoot = mkdtempSync(path.join(os.tmpdir(), "guardian-nexus-pg-lab-"));
  chmodSync(labRoot, 0o700);
  const socketDirectory = path.join(labRoot, "socket");
  mkdirSync(socketDirectory, { mode: 0o700 });
  chmodSync(socketDirectory, 0o700);
  const socketPath = path.join(socketDirectory, ".s.PGSQL.5432");
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, resolve);
  });
  const databaseUrl = new URL(
    "postgresql://test-only-user:test-only-password@127.0.0.1:5432/guardian_approval_lab_unit",
  );
  databaseUrl.searchParams.set("host", socketDirectory);
  const runtimeUrl = new URL(
    "postgresql://app_runtime_login:test-only-runtime-password-0123456789abcdef@127.0.0.1:5432/guardian_approval_lab_unit",
  );
  runtimeUrl.searchParams.set("host", socketDirectory);
  const valid = {
    NODE_ENV: "development",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_DATABASE_NAME: "guardian_approval_lab_unit",
    DATABASE_URL: databaseUrl.toString(),
    APP_RUNTIME_DATABASE_URL: runtimeUrl.toString(),
  };
  try {
    assert.equal(isExplicitDisposableApprovalDatabase(valid), true);

    for (const unsafe of [
    { ...valid, DATABASE_URL: "postgresql://user:pass@db.example.invalid:5432/guardian_approval_lab_unit" },
    { ...valid, DATABASE_URL: "postgresql://user:pass@127.0.0.1:5432/workspace" },
    {
      ...valid,
      DATABASE_URL: `postgresql://test-only-user:test-only-password@127.0.0.1:5432/guardian_approval_lab_unit?host=db.example.invalid`,
    },
    {
      ...valid,
      DATABASE_URL: `${valid.DATABASE_URL}&host=${encodeURIComponent(socketDirectory)}`,
    },
    {
      ...valid,
      APP_RUNTIME_DATABASE_URL:
        `postgresql://app_runtime_login:test-only-runtime-password-0123456789abcdef@127.0.0.1:5432/guardian_approval_lab_unit?host=${encodeURIComponent(path.join(labRoot, "other-socket"))}`,
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
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    rmSync(labRoot, { recursive: true, force: true });
  }
});

test("CI target guard accepts main and fase refs with matching signed claims", async () => {
  await withTestJwks(async () => {
    for (const ref of ["refs/heads/main", "refs/heads/fase5-mcp-proxy"]) {
      const decision = await diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(ref),
        "approval-e2e",
        async () => signedApprovalLabToken(ref),
      );
      assert.deepEqual(decision, { accepted: true, stage: "approval-e2e" });
    }
  });
});

test("CI target guard rejects other branches before requesting an OIDC token", async () => {
  let tokenRequested = false;
  const decision = await diagnoseGitHubActionsApprovalLabTarget(
    approvalLabEnvironment("refs/heads/feature/proxy"),
    "approval-e2e",
    async () => {
      tokenRequested = true;
      return "";
    },
  );
  assert.deepEqual(decision, {
    accepted: false,
    category: "github_context_incompatible",
    stage: "approval-e2e",
  });
  assert.equal(tokenRequested, false);
});

test("CI target guard rejects signed branch claims that differ from GITHUB_REF", async () => {
  const env = approvalLabEnvironment("refs/heads/fase5-mcp-proxy");
  const decision = await withTestJwks(() =>
    diagnoseGitHubActionsApprovalLabTarget(
      env,
      "approval-e2e",
      async () =>
        signedApprovalLabToken("refs/heads/fase5-mcp-proxy", {
          ref: "refs/heads/main",
        }),
    )
  );
  assert.deepEqual(decision, {
    accepted: false,
    category: "claims_mismatch",
    subcategory: "claims_ref_mismatch",
    stage: "approval-e2e",
  });
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
    /github\.event_name == 'workflow_dispatch'[\s\S]*?github\.repository == 'AminElouali\/guardian-nexus'[\s\S]*?github\.ref_type == 'branch'[\s\S]*?\(github\.ref == 'refs\/heads\/main' \|\| startsWith\(github\.ref, 'refs\/heads\/fase'\)\)/,
    "the job-level condition limits service creation to manual dispatch on trusted main or fase branches",
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
    /Upload sanitized RLS catalog report[\s\S]*?actions\/upload-artifact@v4[\s\S]*?path:\s*\|[\s\S]*?guardian-postgres-rls-catalog-post-schema-report\.json[\s\S]*?guardian-postgres-rls-catalog-report\.json[\s\S]*?retention-days:\s*14/,
    "the two sanitized catalog reports are retained as bounded job artifacts",
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
    /const guardedStage = stage === "post-schema" \? "provision" : "approval-e2e";[\s\S]*?await isGitHubActionsApprovalLabTarget\(\s*process\.env,\s*guardedStage,\s*acquireGitHubActionsOidcToken/,
    "each catalog stage maps to its protected OIDC stage",
  );
  assert.ok(
    catalogAudit.indexOf("await isGitHubActionsApprovalLabTarget") <
      catalogAudit.indexOf("const pool = new Pool"),
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
    /await diagnoseGitHubActionsApprovalLabTarget\(\s*process\.env,\s*undefined,\s*acquireGitHubActionsOidcToken,?\s*\)/,
    "the target guard awaits authenticated OIDC verification and safe diagnostics",
  );
  assert.match(
    targetGuard,
    /console\.error\(\s*JSON\.stringify\(\{\s*category:\s*decision\.category,\s*subcategory:\s*decision\.subcategory,\s*stage:\s*decision\.stage,?\s*\}\)\s*,?\s*\)/,
    "a rejected target prints only safe category, subcategory, and stage identifiers",
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
    /await verifyExplicitDisposableApprovalDatabase\(\s*process\.env,\s*acquireGitHubActionsOidcToken,?\s*\)[\s\S]*?await import\("@workspace\/db"\)/,
    "the E2E authenticates the job before importing the database pool",
  );
  assert.doesNotMatch(
    approvalE2e,
    /import\s+(?:\{[^}]*\}\s+from\s+)?["']@workspace\/db["']/,
    "the E2E has no static database import before the OIDC gate",
  );
});
