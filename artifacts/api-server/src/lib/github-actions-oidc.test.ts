import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  sign as signJwt,
} from "node:crypto";
import { test } from "node:test";
import {
  diagnoseGitHubActionsApprovalLabTarget,
  isExplicitDisposableApprovalDatabase,
  isGitHubActionsApprovalLabTarget,
} from "./approval-e2e-db-guard";
import {
  GITHUB_ACTIONS_OIDC_ISSUER,
  GITHUB_ACTIONS_RLS_AUDIENCE,
  GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
  requestVerifiedGitHubActionsClaims,
  requestVerifiedGitHubActionsClaimsDetailed,
  verifyGitHubActionsOidcToken,
  type ExpectedGitHubActionsOidcContext,
  type OidcFetchDependencies,
} from "./github-actions-oidc";

const now = 1_800_000_000;
const repository = "AminElouali/guardian-nexus";
const workflow = "Guardian Nexus PostgreSQL Approval Lab";
const workflowRef =
  `${repository}/.github/workflows/postgres-approval-lab.yml@refs/heads/main`;
const sha = "a".repeat(40);
const runId = "123456789";
const runAttempt = "2";
const expected: ExpectedGitHubActionsOidcContext = {
  repository,
  repositoryOwner: "AminElouali",
  workflow,
  workflowRef,
  ref: "refs/heads/main",
  eventName: "workflow_dispatch",
  sha,
  runId,
  runAttempt,
};

const primaryKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const alternateKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const primaryPublicJwk = {
  ...(primaryKey.publicKey.export({ format: "jwk" }) as {
    kty: string;
    n: string;
    e: string;
  }),
  kid: "test-only-github-key",
  use: "sig",
  alg: "RS256",
  key_ops: ["verify"],
};

function defaultClaims(overrides: Record<string, unknown> = {}) {
  return {
    iss: GITHUB_ACTIONS_OIDC_ISSUER,
    aud: GITHUB_ACTIONS_RLS_AUDIENCE,
    sub: `repo:${repository}:ref:refs/heads/main`,
    repository,
    repository_id: GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
    repository_owner: "AminElouali",
    repository_owner_id: "987654321",
    event_name: "workflow_dispatch",
    ref: "refs/heads/main",
    ref_type: "branch",
    workflow,
    workflow_ref: workflowRef,
    // GitHub's workflow file commit can predate the application revision.
    workflow_sha: "c".repeat(40),
    sha,
    run_id: runId,
    run_attempt: runAttempt,
    jti: "test-only-jti",
    iat: now - 10,
    nbf: now - 10,
    exp: now + 240,
    ...overrides,
  };
}

function signToken(
  claims: Record<string, unknown>,
  keyPair = primaryKey,
  headerOverrides: Record<string, unknown> = {},
): string {
  const header = {
    alg: "RS256",
    kid: "test-only-github-key",
    typ: "JWT",
    ...headerOverrides,
  };
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString(
    "base64url",
  );
  const encodedPayload = Buffer.from(JSON.stringify(claims)).toString(
    "base64url",
  );
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signJwt("RSA-SHA256", Buffer.from(signingInput), keyPair.privateKey);
  return `${signingInput}.${signature.toString("base64url")}`;
}

function makeDependencies(token: string): OidcFetchDependencies {
  return {
    nowEpochSeconds: now,
    fetchImpl: async (input, init) => {
      const url = new URL(input.toString());
      if (url.hostname === "pipelines.actions.githubusercontent.com") {
        assert.equal(
          url.searchParams.get("audience"),
          GITHUB_ACTIONS_RLS_AUDIENCE,
        );
        assert.equal(init?.redirect, "error");
        assert.match(
          new Headers(init?.headers).get("authorization") ?? "",
          /^Bearer test-only-/,
        );
        return new Response(JSON.stringify({ value: token }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      if (
        url.href ===
        "https://token.actions.githubusercontent.com/.well-known/jwks"
      ) {
        return new Response(JSON.stringify({ keys: [primaryPublicJwk] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      throw new Error("Unexpected test-only URL");
    },
  };
}

function actionsEnvironment(
  token: string,
  overrides: Record<string, string | undefined> = {},
) {
  return {
    ACTIONS_ID_TOKEN_REQUEST_URL:
        "https://pipelines.actions.githubusercontent.com/test-guid/_apis/actions/runners/runner-123/jobs/job-456/idtoken?api-version=2.0",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "test-only-request-bearer",
    ...overrides,
  };
}

function approvalLabEnvironment(
  stage: "bootstrap" | "provision" | "approval-e2e" = "bootstrap",
  overrides: Record<string, string | undefined> = {},
) {
  const adminPassword = `guardian-ci-${runId}-${runAttempt}-${sha}`;
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
    GITHUB_REF: "refs/heads/main",
    GITHUB_SHA: sha,
    GITHUB_RUN_ID: runId,
    GITHUB_RUN_ATTEMPT: runAttempt,
    GUARDIAN_APPROVAL_E2E_CI_SERVICE: "postgres",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_CI_STAGE: stage,
    ACTIONS_ID_TOKEN_REQUEST_URL:
      "https://pipelines.actions.githubusercontent.com/test-guid/_apis/actions/runners/runner-123/jobs/job-456/idtoken?api-version=2.0",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "test-only-request-bearer",
    DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/${stage === "bootstrap" ? "postgres" : "guardian_approval_lab_ci"}`,
    ...overrides,
  };
}

async function withMockedGlobalFetch<T>(
  fetchImpl: typeof fetch,
  run: () => Promise<T>,
): Promise<T> {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = fetchImpl;
  try {
    return await run();
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("TEST ONLY GitHub OIDC token verifies signature and exact trusted claims", () => {
  const claims = defaultClaims();
  const token = signToken(claims);
  const verified = verifyGitHubActionsOidcToken(
    token,
    { keys: [primaryPublicJwk] },
    expected,
    now,
  );
  assert.equal(verified?.repository, repository);
  assert.equal(verified?.repository_id, GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID);
  assert.equal(verified?.run_id, runId);
});

test("TEST ONLY GitHub OIDC rejects invalid signatures, keys, algorithms, and headers", () => {
  const validClaims = defaultClaims();
  const validToken = signToken(validClaims);
  const wrongSignatureToken = signToken(validClaims, alternateKey);
  assert.equal(
    verifyGitHubActionsOidcToken(
      wrongSignatureToken,
      { keys: [primaryPublicJwk] },
      expected,
      now,
    ),
    undefined,
  );
  assert.equal(
    verifyGitHubActionsOidcToken(
      validToken,
      {
        keys: [{ ...primaryPublicJwk, kid: "different-test-only-kid" }],
      },
      expected,
      now,
    ),
    undefined,
  );
  assert.equal(
    verifyGitHubActionsOidcToken(
      signToken(validClaims, primaryKey, { alg: "HS256" }),
      { keys: [primaryPublicJwk] },
      expected,
      now,
    ),
    undefined,
  );
  assert.equal(
    verifyGitHubActionsOidcToken(
      signToken(validClaims, primaryKey, {
        jku: "https://attacker.invalid/keys",
      }),
      { keys: [primaryPublicJwk] },
      expected,
      now,
    ),
    undefined,
  );
});

test("TEST ONLY GitHub OIDC rejects claim mismatches, expiry, and stale tokens", () => {
  const mismatches: Record<string, unknown>[] = [
    { iss: "https://issuer.invalid" },
    { aud: "another-audience" },
    { repository: "Contributor/guardian-nexus" },
    { repository_id: undefined },
    { repository_owner: "Contributor" },
    { event_name: "pull_request" },
    { ref: "refs/heads/feature" },
    { ref_type: "tag" },
    { workflow: "Other workflow" },
    { workflow_ref: `${repository}/.github/workflows/other.yml@refs/heads/main` },
    { workflow_sha: "not-a-workflow-commit" },
    { sha: "b".repeat(40) },
    { run_id: "987654321" },
    { run_attempt: "3" },
  ];

  for (const mismatch of mismatches) {
    assert.equal(
      verifyGitHubActionsOidcToken(
        signToken(defaultClaims(mismatch)),
        { keys: [primaryPublicJwk] },
        expected,
        now,
      ),
      undefined,
      `claim mismatch rejected: ${Object.keys(mismatch).join(",")}`,
    );
  }

  for (const timestamps of [
    { exp: now - 1 },
    { iat: now - 601 },
    { nbf: now + 31 },
    { exp: now + 601 },
  ]) {
    assert.equal(
      verifyGitHubActionsOidcToken(
        signToken(defaultClaims(timestamps)),
        { keys: [primaryPublicJwk] },
        expected,
        now,
      ),
      undefined,
      `invalid time claims rejected: ${Object.keys(timestamps).join(",")}`,
    );
  }
});

test("TEST ONLY GitHub OIDC pins the immutable canonical repository ID", () => {
  assert.equal(GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID, "1455418736");
  const cases: Array<[string, Record<string, unknown>]> = [
    ["correct string ID", { repository_id: GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID }],
    ["different ID", { repository_id: "1455418737" }],
    ["missing ID", { repository_id: undefined }],
    ["numeric JSON ID", { repository_id: 1455418736 }],
    ["leading-zero representation", { repository_id: "01455418736" }],
    ["whitespace representation", { repository_id: " 1455418736" }],
  ];

  for (const [label, override] of cases) {
    const claims = verifyGitHubActionsOidcToken(
      signToken(defaultClaims(override)),
      { keys: [primaryPublicJwk] },
      expected,
      now,
    );
    assert.equal(
      claims?.repository_id,
      label === "correct string ID"
        ? GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID
        : undefined,
      `repository ID case: ${label}`,
    );
  }
});

test("TEST ONLY token request requires Actions credentials and fixed official endpoints", async () => {
  const token = signToken(defaultClaims());
  let calls = 0;
  const dependencies = makeDependencies(token);
  const validEnv = actionsEnvironment(token);
  const claims = await requestVerifiedGitHubActionsClaims(
    validEnv,
    expected,
    dependencies,
  );
  assert.equal(claims?.event_name, "workflow_dispatch");

  const noToken = await requestVerifiedGitHubActionsClaims(
    { ACTIONS_ID_TOKEN_REQUEST_URL: validEnv.ACTIONS_ID_TOKEN_REQUEST_URL },
    expected,
    {
      ...dependencies,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("Must not fetch without runner token");
      },
    },
  );
  assert.equal(noToken, undefined);
  assert.equal(calls, 0);

  const untrustedEndpoint = await requestVerifiedGitHubActionsClaims(
    actionsEnvironment(token, {
      ACTIONS_ID_TOKEN_REQUEST_URL:
        "https://attacker.invalid/idtoken",
    }),
    expected,
    {
      ...dependencies,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("Must not fetch an untrusted endpoint");
      },
    },
  );
  assert.equal(untrustedEndpoint, undefined);
  assert.equal(calls, 0);

  const wrongApiVersion = await requestVerifiedGitHubActionsClaims(
    actionsEnvironment(token, {
      ACTIONS_ID_TOKEN_REQUEST_URL:
        "https://pipelines.actions.githubusercontent.com/test-guid/_apis/actions/idtoken?api-version=1.0",
    }),
    expected,
    {
      ...dependencies,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("Must not fetch an unsupported API version");
      },
    },
  );
  assert.equal(wrongApiVersion, undefined);
  assert.equal(calls, 0);

  const pathTraversal = await requestVerifiedGitHubActionsClaims(
    actionsEnvironment(token, {
      ACTIONS_ID_TOKEN_REQUEST_URL:
        "https://pipelines.actions.githubusercontent.com/test-guid/_apis/actions/../idtoken?api-version=2.0",
    }),
    expected,
    {
      ...dependencies,
      fetchImpl: async () => {
        calls += 1;
        throw new Error("Must not fetch an invalid Actions path");
      },
    },
  );
  assert.equal(pathTraversal, undefined);
  assert.equal(calls, 0);
});

test("TEST ONLY CI target diagnostics expose safe rejection categories and remain fail-closed", async () => {
  const missingContext = await diagnoseGitHubActionsApprovalLabTarget(
    {},
    undefined,
  );
  assert.deepEqual(missingContext, {
    accepted: false,
    category: "github_context_missing",
    stage: "unknown",
  });

  const incompatibleContext = await diagnoseGitHubActionsApprovalLabTarget(
    approvalLabEnvironment("bootstrap", {
      GITHUB_REF: "refs/heads/untrusted",
    }),
    "bootstrap",
  );
  assert.deepEqual(incompatibleContext, {
    accepted: false,
    category: "github_context_incompatible",
    stage: "bootstrap",
  });

  const unavailableOidc = await diagnoseGitHubActionsApprovalLabTarget(
    approvalLabEnvironment("bootstrap", {
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: undefined,
    }),
    "bootstrap",
  );
  assert.deepEqual(unavailableOidc, {
    accepted: false,
    category: "oidc_unavailable_or_invalid",
    stage: "bootstrap",
  });

  const actualNow = Math.floor(Date.now() / 1000);
  const claimsMismatchToken = signToken(
    defaultClaims({
      repository: "untrusted/fork",
      iat: actualNow - 10,
      nbf: actualNow - 10,
      exp: actualNow + 240,
    }),
  );
  const claimsMismatchFetch = makeDependencies(claimsMismatchToken).fetchImpl;
  assert.ok(claimsMismatchFetch);
  const claimsMismatch = await withMockedGlobalFetch(
    claimsMismatchFetch,
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(),
        "bootstrap",
      ),
  );
  assert.deepEqual(claimsMismatch, {
    accepted: false,
    category: "claims_mismatch",
    stage: "bootstrap",
  });

  const validToken = signToken(
    defaultClaims({
      iat: actualNow - 10,
      nbf: actualNow - 10,
      exp: actualNow + 240,
    }),
  );
  const validFetch = makeDependencies(validToken).fetchImpl;
  assert.ok(validFetch);
  const validTarget = await withMockedGlobalFetch(validFetch, () =>
    diagnoseGitHubActionsApprovalLabTarget(
      approvalLabEnvironment(),
      "bootstrap",
    ),
  );
  assert.deepEqual(validTarget, { accepted: true, stage: "bootstrap" });

  const databaseUrlMismatch = await withMockedGlobalFetch(validFetch, () =>
    diagnoseGitHubActionsApprovalLabTarget(
      approvalLabEnvironment("bootstrap", {
        DATABASE_URL:
          "postgresql://postgres:test-only-password@127.0.0.1:5432/not-postgres",
      }),
      "bootstrap",
    ),
  );
  assert.deepEqual(databaseUrlMismatch, {
    accepted: false,
    category: "database_url_mismatch",
    stage: "bootstrap",
  });

  const malformedTokenResult = await requestVerifiedGitHubActionsClaimsDetailed(
    actionsEnvironment("not-a-test-only-jwt"),
    expected,
    {
      nowEpochSeconds: actualNow,
      fetchImpl: makeDependencies("not-a-test-only-jwt").fetchImpl,
    },
  );
  assert.deepEqual(malformedTokenResult, {
    ok: false,
    category: "oidc_unavailable_or_invalid",
  });
  for (const result of [
    missingContext,
    incompatibleContext,
    unavailableOidc,
    claimsMismatch,
    databaseUrlMismatch,
  ]) {
    assert.equal(result.accepted, false);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(
      serialized,
      /postgresql|test-only-request-bearer|test-only-jti|guardian-ci-/,
    );
  }
});

test("CI target guard refuses environment-only context and forged markers", async () => {
  const adminPassword = `guardian-ci-${runId}-${runAttempt}-${sha}`;
  const runtimePassword = `guardian-runtime-${runId}-${runAttempt}-${sha}`;
  const env = {
    NODE_ENV: "development",
    CI: "true",
    GITHUB_ACTIONS: "true",
    GITHUB_WORKFLOW: workflow,
    GITHUB_WORKFLOW_REF: workflowRef,
    GITHUB_JOB: "postgres-approval-lab",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: repository,
    GITHUB_REF_TYPE: "branch",
    GITHUB_REF: "refs/heads/main",
    GITHUB_SHA: sha,
    GITHUB_RUN_ID: runId,
    GITHUB_RUN_ATTEMPT: runAttempt,
    GUARDIAN_APPROVAL_E2E_CI_SERVICE: "postgres",
    GUARDIAN_APPROVAL_E2E_DISPOSABLE: "1",
    GUARDIAN_APPROVAL_E2E_CI_STAGE: "approval-e2e",
    DATABASE_URL: `postgresql://postgres:${adminPassword}@127.0.0.1:5432/guardian_approval_lab_ci`,
    APP_RUNTIME_DATABASE_URL: `postgresql://app_runtime_login:${runtimePassword}@127.0.0.1:5432/guardian_approval_lab_ci`,
  };

  assert.equal(await isGitHubActionsApprovalLabTarget(env, "approval-e2e"), false);
  assert.equal(
    isExplicitDisposableApprovalDatabase({
      ...env,
      GUARDIAN_APPROVAL_E2E_CI_TARGET_VERIFIED:
        `guardian-approval-lab:${runId}:${runAttempt}:${sha}`,
    }),
    false,
    "a process-environment marker is never an OIDC substitute",
  );

  for (const unsafe of [
    { ...env, GITHUB_EVENT_NAME: "pull_request" },
    { ...env, GITHUB_REF: "refs/heads/feature" },
    { ...env, GITHUB_WORKFLOW_REF: `${repository}/other.yml@refs/heads/main` },
    { ...env, GITHUB_SHA: "b".repeat(40) },
    { ...env, GITHUB_RUN_ID: "987654321" },
    {
      ...env,
      DATABASE_URL:
        `postgresql://postgres:${adminPassword}@db.example.invalid:5432/guardian_approval_lab_ci`,
    },
    {
      ...env,
      APP_RUNTIME_DATABASE_URL:
        `postgresql://app_runtime_login:${runtimePassword}@127.0.0.1:5432/workspace`,
    },
    {
      ...env,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: undefined,
    },
  ]) {
    assert.equal(
      await isGitHubActionsApprovalLabTarget(unsafe, "approval-e2e"),
      false,
    );
  }
});
