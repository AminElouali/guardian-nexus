import assert from "node:assert/strict";
import { generateKeyPairSync, sign as signJwt } from "node:crypto";
import { test } from "node:test";
import { diagnoseGitHubActionsApprovalLabTarget } from "./approval-e2e-db-guard";
import {
  GITHUB_ACTIONS_OIDC_ISSUER,
  GITHUB_ACTIONS_RLS_AUDIENCE,
  GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
  GITHUB_ACTIONS_TRUSTED_REPOSITORY_OWNER_ID,
} from "./github-actions-oidc";

const repository = "AminElouali/guardian-nexus";
const workflow = "Guardian Nexus PostgreSQL Approval Lab";
const workflowPath = `${repository}/.github/workflows/postgres-approval-lab.yml`;
const sha = "a".repeat(40);
const runId = "123456789";
const runAttempt = "2";
const mainRef = "refs/heads/main";
const faseRef = "refs/heads/fase5-mcp-proxy";
const key = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicJwk = {
  ...(key.publicKey.export({ format: "jwk" }) as {
    kty: string;
    n: string;
    e: string;
  }),
  kid: "test-only-github-key",
  use: "sig",
  alg: "RS256",
  key_ops: ["verify"],
};

function tokenFor(ref: string): string {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const claims = {
    iss: GITHUB_ACTIONS_OIDC_ISSUER,
    aud: GITHUB_ACTIONS_RLS_AUDIENCE,
    sub: `repo:AminElouali@${GITHUB_ACTIONS_TRUSTED_REPOSITORY_OWNER_ID}/guardian-nexus@${GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID}:ref:${ref}`,
    repository,
    repository_id: GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
    repository_owner: "AminElouali",
    repository_owner_id: GITHUB_ACTIONS_TRUSTED_REPOSITORY_OWNER_ID,
    event_name: "workflow_dispatch",
    ref,
    ref_type: "branch",
    workflow,
    workflow_ref: `${workflowPath}@${ref}`,
    workflow_sha: "c".repeat(40),
    sha,
    run_id: runId,
    run_attempt: runAttempt,
    jti: "test-only-jti",
    iat: nowSeconds - 10,
    nbf: nowSeconds - 10,
    exp: nowSeconds + 240,
  };
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", kid: "test-only-github-key", typ: "JWT" }),
  ).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const input = `${header}.${payload}`;
  const signature = signJwt("RSA-SHA256", Buffer.from(input), key.privateKey);
  return `${input}.${signature.toString("base64url")}`;
}

function environment(ref: string, workflowRef = `${workflowPath}@${ref}`) {
  return {
    NODE_ENV: "development",
    CI: "true",
    GITHUB_ACTIONS: "true",
    GITHUB_WORKFLOW: workflow,
    GITHUB_WORKFLOW_REF: workflowRef,
    GITHUB_JOB: "postgres-approval-lab",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: repository,
    GITHUB_REF_TYPE: "branch",
    GITHUB_REF: ref,
    GITHUB_SHA: sha,
    GITHUB_RUN_ID: runId,
    GITHUB_RUN_ATTEMPT: runAttempt,
    GUARDIAN_APPROVAL_E2E_CI_SERVICE: "postgres",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_CI_STAGE: "bootstrap",
    DATABASE_URL: `postgresql://postgres:guardian-ci-${runId}-${runAttempt}-${sha}@127.0.0.1:5432/postgres`,
  };
}

async function withJwks<T>(run: () => Promise<T>): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: unknown) => {
    assert.equal(
      new URL(String(input)).href,
      "https://token.actions.githubusercontent.com/.well-known/jwks",
    );
    return new Response(JSON.stringify({ keys: [publicJwk] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("TEST ONLY CI lab accepts main and fase branches bound by signed claims", async () => {
  for (const ref of [mainRef, faseRef]) {
    const decision = await withJwks(() =>
      diagnoseGitHubActionsApprovalLabTarget(
        environment(ref),
        "bootstrap",
        async () => tokenFor(ref),
      ),
    );
    assert.deepEqual(decision, { accepted: true, stage: "bootstrap" });
  }
});

test("TEST ONLY CI lab rejects a token minted for a different branch", async () => {
  for (const [envRef, tokenRef] of [
    [faseRef, mainRef],
    [mainRef, faseRef],
    [faseRef, "refs/heads/fase6-other"],
  ] as const) {
    const decision = await withJwks(() =>
      diagnoseGitHubActionsApprovalLabTarget(
        environment(envRef),
        "bootstrap",
        async () => tokenFor(tokenRef),
      ),
    );
    assert.equal(decision.accepted, false);
    assert.equal(
      decision.accepted === false ? decision.category : undefined,
      "claims_mismatch",
    );
  }
});

test("TEST ONLY CI lab rejects other refs and mismatched workflow refs before OIDC", async () => {
  const cases = [
    environment("refs/heads/feature"),
    environment("refs/heads/Fase5"),
    environment("refs/heads/fase5 x"),
    environment("refs/heads/mainx"),
    environment(faseRef, `${workflowPath}@${mainRef}`),
  ];
  for (const env of cases) {
    let providerCalls = 0;
    const decision = await diagnoseGitHubActionsApprovalLabTarget(
      env,
      "bootstrap",
      async () => {
        providerCalls += 1;
        return tokenFor(faseRef);
      },
    );
    assert.deepEqual(decision, {
      accepted: false,
      category: "github_context_incompatible",
      stage: "bootstrap",
    });
    assert.equal(providerCalls, 0);
  }
});
