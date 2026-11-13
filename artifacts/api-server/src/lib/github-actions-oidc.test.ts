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
  acquireGitHubActionsOidcToken,
  GITHUB_ACTIONS_OIDC_ISSUER,
  GITHUB_ACTIONS_RLS_AUDIENCE,
  GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID,
  verifyGitHubActionsOidcToken,
  verifyGitHubActionsOidcTokenDetailed,
  verifyGitHubActionsClaimsWithOfficialJwksDetailed,
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

function signTokenWithRawHeaderJson(
  headerJson: string,
  claims: Record<string, unknown>,
  keyPair = primaryKey,
): string {
  const encodedHeader = Buffer.from(headerJson, "utf8").toString("base64url");
  const encodedPayload = Buffer.from(JSON.stringify(claims)).toString(
    "base64url",
  );
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = signJwt(
    "RSA-SHA256",
    Buffer.from(signingInput),
    keyPair.privateKey,
  );
  return `${signingInput}.${signature.toString("base64url")}`;
}

function makeJwksDependencies(
  nowEpochSeconds = now,
): OidcFetchDependencies {
  return {
    nowEpochSeconds,
    fetchImpl: async (input, init) => {
      const url = new URL(input.toString());
      assert.equal(
        url.href,
        "https://token.actions.githubusercontent.com/.well-known/jwks",
      );
      assert.equal(
        new Headers(init?.headers).get("accept"),
        "application/json",
      );
      assert.equal(init?.redirect, "error");
      return new Response(JSON.stringify({ keys: [primaryPublicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  };
}

type SyntheticOidcFailure =
  | "jwks-failed";

function makeDiagnosticFetch(
  failure?: SyntheticOidcFailure,
): typeof fetch {
  return async (input) => {
    const url = new URL(input.toString());
    assert.equal(
      url.href,
      "https://token.actions.githubusercontent.com/.well-known/jwks",
    );
    if (failure === "jwks-failed") {
      return new Response("TEST ONLY unavailable JWKS", { status: 503 });
    }
    return new Response(JSON.stringify({ keys: [primaryPublicJwk] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
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

test("TEST ONLY OIDC verifier returns fixed safe JWT subcategories", () => {
  const sensitiveMarker = "TEST_ONLY_CLAIMS_MARKER_DO_NOT_LOG";
  const claims = defaultClaims({ jti: sensitiveMarker });
  const header = Buffer.from(
    JSON.stringify({
      alg: "RS256",
      kid: "test-only-github-key",
      typ: "JWT",
    }),
  ).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const placeholderSignature = Buffer.from(
    "TEST_ONLY_SIGNATURE_MARKER_DO_NOT_LOG",
  ).toString("base64url");
  const rawToken = (
    encodedHeader: string,
    encodedPayload: string,
    encodedSignature = placeholderSignature,
  ) => `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
  const malformedToken = "";
  const oversizedToken = "a".repeat(16_385);
  const segmentCountToken = "TEST_ONLY_TOKEN_MARKER_MALFORMED";
  const invalidHeaderEncodingToken = rawToken("!header!", payload);
  const invalidHeaderJsonToken = rawToken(
    Buffer.from("TEST_ONLY_HEADER_JSON_MARKER").toString("base64url"),
    payload,
  );
  const invalidHeaderShapeToken = rawToken(
    Buffer.from("[]").toString("base64url"),
    payload,
  );
  const invalidPayloadEncodingToken = rawToken(header, "!payload!");
  const invalidPayloadJsonToken = rawToken(
    header,
    Buffer.from("TEST_ONLY_PAYLOAD_JSON_MARKER").toString("base64url"),
  );
  const invalidPayloadShapeToken = rawToken(
    header,
    Buffer.from("[]").toString("base64url"),
  );
  const invalidSignatureEncodingToken = rawToken(header, payload, "!");
  const nonCanonicalSignatureToken = rawToken(header, payload, "AB");
  const validX5t = Buffer.alloc(20, 0x31).toString("base64url");
  const validX5tS256 = Buffer.alloc(32, 0x32).toString("base64url");
  const invalidX5tToken = signToken(claims, primaryKey, { x5t: "bad=" });
  const shortX5tToken = signToken(claims, primaryKey, {
    x5t: Buffer.alloc(19, 0x33).toString("base64url"),
  });
  const invalidX5tS256Token = signToken(claims, primaryKey, {
    "x5t#S256": Buffer.alloc(31, 0x34).toString("base64url"),
  });
  const disallowedAlgorithmToken = signToken(claims, primaryKey, {
    alg: "HS256",
  });
  const invalidKidToken = signToken(claims, primaryKey, { kid: undefined });
  const disallowedTypeToken = signToken(claims, primaryKey, { typ: "TEST" });
  const malformedCritToken = signToken(claims, primaryKey, {
    crit: "alg",
  });
  const emptyCritToken = signToken(claims, primaryKey, { crit: [] });
  const invalidCritElementToken = signToken(claims, primaryKey, {
    crit: [1],
  });
  const danglingCritToken = signToken(claims, primaryKey, {
    crit: ["test-only-extension"],
  });
  const duplicateCritToken = signToken(claims, primaryKey, {
    crit: ["test-only-extension", "test-only-extension"],
    "test-only-extension": "TEST_ONLY_CRITICAL_VALUE_DO_NOT_LOG",
  });
  const unsupportedCritToken = signToken(claims, primaryKey, {
    crit: ["test-only-extension"],
    "test-only-extension": "TEST_ONLY_CRITICAL_VALUE_DO_NOT_LOG",
  });
  const registeredAlgCritToken = signToken(claims, primaryKey, {
    crit: ["alg"],
  });
  const registeredKidCritToken = signToken(claims, primaryKey, {
    crit: ["kid"],
  });
  const registeredTypCritToken = signToken(claims, primaryKey, {
    crit: ["typ"],
  });
  const jkuToken = signToken(claims, primaryKey, {
    jku: "TEST_ONLY_REMOTE_KEY_REFERENCE_DO_NOT_LOG",
  });
  const jwkToken = signToken(claims, primaryKey, {
    jwk: { kty: "RSA", marker: "TEST_ONLY_EMBEDDED_KEY_DO_NOT_LOG" },
  });
  const x5uToken = signToken(claims, primaryKey, {
    x5u: "TEST_ONLY_REMOTE_CERTIFICATE_REFERENCE_DO_NOT_LOG",
  });
  const metadataToken = signToken(claims);
  const invalidRsaToken = signToken(claims);
  const invalidModulus = "TEST_ONLY_MODULUS_MARKER_INVALID";
  const invalidExponent = "TEST_ONLY_EXPONENT_MARKER_INVALID";
  const badSignatureToken = signToken(claims, alternateKey);

  const cases: Array<{
    token: string;
    jwks: { keys: unknown[] };
    subcategory: string;
  }> = [
    {
      token: malformedToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_token_invalid",
    },
    {
      token: oversizedToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_token_invalid",
    },
    {
      token: segmentCountToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_segment_count_invalid",
    },
    {
      token: invalidHeaderEncodingToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_header_base64url_invalid",
    },
    {
      token: invalidHeaderJsonToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_header_json_invalid",
    },
    {
      token: invalidHeaderShapeToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_header_json_invalid",
    },
    {
      token: invalidPayloadEncodingToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_payload_base64url_invalid",
    },
    {
      token: invalidPayloadJsonToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_payload_json_invalid",
    },
    {
      token: invalidPayloadShapeToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_payload_json_invalid",
    },
    {
      token: invalidSignatureEncodingToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_signature_base64url_invalid",
    },
    {
      token: nonCanonicalSignatureToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_signature_base64url_invalid",
    },
    {
      token: disallowedAlgorithmToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_algorithm_disallowed",
    },
    {
      token: invalidKidToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_kid_invalid",
    },
    {
      token: disallowedTypeToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_type_disallowed",
    },
    {
      token: invalidX5tToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_x5t_invalid",
    },
    {
      token: shortX5tToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_x5t_invalid",
    },
    {
      token: invalidX5tS256Token,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_x5t_s256_invalid",
    },
    {
      token: malformedCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_header_invalid",
    },
    {
      token: emptyCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_header_invalid",
    },
    {
      token: invalidCritElementToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_header_invalid",
    },
    {
      token: danglingCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_header_invalid",
    },
    {
      token: duplicateCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_header_invalid",
    },
    {
      token: unsupportedCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_parameter_unsupported",
    },
    {
      token: registeredAlgCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_parameter_registered",
    },
    {
      token: registeredKidCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_parameter_registered",
    },
    {
      token: registeredTypCritToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_critical_parameter_registered",
    },
    {
      token: jkuToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_key_reference_disallowed",
    },
    {
      token: jwkToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_key_reference_disallowed",
    },
    {
      token: x5uToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "jwt_key_reference_disallowed",
    },
    {
      token: metadataToken,
      jwks: { keys: [{ ...primaryPublicJwk, use: "enc" }] },
      subcategory: "jwk_metadata_incompatible",
    },
    {
      token: invalidRsaToken,
      jwks: {
        keys: [
          {
            ...primaryPublicJwk,
            n: invalidModulus,
            e: invalidExponent,
          },
        ],
      },
      subcategory: "rsa_key_invalid",
    },
    {
      token: badSignatureToken,
      jwks: { keys: [primaryPublicJwk] },
      subcategory: "signature_unverifiable",
    },
  ];
  const results = cases.map(({ token, jwks }) =>
    verifyGitHubActionsOidcTokenDetailed(token, jwks, expected, now),
  );
  for (const [index, result] of results.entries()) {
    assert.deepEqual(result, {
      ok: false,
      category: "oidc_jwt_header_key_signature_invalid",
      subcategory: cases[index].subcategory,
    });
  }

  const diagnostics = JSON.stringify(results);
  const sensitiveValues = [
    malformedToken,
    oversizedToken,
    segmentCountToken,
    invalidHeaderEncodingToken,
    invalidHeaderJsonToken,
    invalidHeaderShapeToken,
    invalidPayloadEncodingToken,
    invalidPayloadJsonToken,
    invalidPayloadShapeToken,
    invalidSignatureEncodingToken,
    nonCanonicalSignatureToken,
    disallowedAlgorithmToken,
    invalidKidToken,
    disallowedTypeToken,
    invalidX5tToken,
    shortX5tToken,
    invalidX5tS256Token,
    malformedCritToken,
    emptyCritToken,
    invalidCritElementToken,
    danglingCritToken,
    duplicateCritToken,
    unsupportedCritToken,
    registeredAlgCritToken,
    registeredKidCritToken,
    registeredTypCritToken,
    jkuToken,
    jwkToken,
    x5uToken,
    metadataToken,
    invalidRsaToken,
    badSignatureToken,
    placeholderSignature,
    badSignatureToken.split(".")[2],
    String(primaryPublicJwk.kid),
    sensitiveMarker,
    "TEST_ONLY_CRITICAL_VALUE_DO_NOT_LOG",
    "TEST_ONLY_REMOTE_KEY_REFERENCE_DO_NOT_LOG",
    "TEST_ONLY_EMBEDDED_KEY_DO_NOT_LOG",
    "TEST_ONLY_REMOTE_CERTIFICATE_REFERENCE_DO_NOT_LOG",
    String(primaryPublicJwk.n),
    String(primaryPublicJwk.e),
    invalidModulus,
    invalidExponent,
  ];
  for (const value of sensitiveValues.filter((value) => value.length > 0)) {
    assert.equal(diagnostics.includes(value), false);
  }
});

test("TEST ONLY accepts validated thumbprints and ignores unknown noncritical JOSE parameters", () => {
  const validX5t = Buffer.alloc(20, 0x41).toString("base64url");
  const validX5tS256 = Buffer.alloc(32, 0x42).toString("base64url");
  const validTokens = [
    signToken(defaultClaims(), primaryKey, { x5t: validX5t }),
    signToken(defaultClaims(), primaryKey, {
      "x5t#S256": validX5tS256,
    }),
    signToken(defaultClaims(), primaryKey, {
      x5t: validX5t,
      "x5t#S256": validX5tS256,
    }),
    signToken(defaultClaims(), primaryKey, {
      "test-only-noncritical": "TEST_ONLY_IGNORED_HEADER_VALUE",
    }),
  ];

  for (const token of validTokens) {
    assert.equal(
      verifyGitHubActionsOidcTokenDetailed(
        token,
        { keys: [primaryPublicJwk] },
        expected,
        now,
      ).ok,
      true,
    );
  }

  const wrongSigningKeyToken = signToken(defaultClaims(), alternateKey, {
    x5t: validX5t,
    "x5t#S256": validX5tS256,
  });
  assert.deepEqual(
    verifyGitHubActionsOidcTokenDetailed(
      wrongSigningKeyToken,
      { keys: [primaryPublicJwk] },
      expected,
      now,
    ),
    {
      ok: false,
      category: "oidc_jwt_header_key_signature_invalid",
      subcategory: "signature_unverifiable",
    },
  );
});

test("TEST ONLY duplicate JOSE header names use JSON.parse last-member semantics", () => {
  const claims = defaultClaims();
  const lastMemberRs256 = signTokenWithRawHeaderJson(
    '{"alg":"HS256","alg":"RS256","kid":"test-only-github-key","typ":"JWT"}',
    claims,
  );
  const lastMemberHs256 = signTokenWithRawHeaderJson(
    '{"alg":"RS256","alg":"HS256","kid":"test-only-github-key","typ":"JWT"}',
    claims,
  );

  assert.equal(
    verifyGitHubActionsOidcTokenDetailed(
      lastMemberRs256,
      { keys: [primaryPublicJwk] },
      expected,
      now,
    ).ok,
    true,
  );
  assert.deepEqual(
    verifyGitHubActionsOidcTokenDetailed(
      lastMemberHs256,
      { keys: [primaryPublicJwk] },
      expected,
      now,
    ),
    {
      ok: false,
      category: "oidc_jwt_header_key_signature_invalid",
      subcategory: "jwt_algorithm_disallowed",
    },
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

test("TEST ONLY @actions/core token acquisition pins the audience and suppresses toolkit output", async () => {
  const token = signToken(defaultClaims());
  const stdoutWrites: string[] = [];
  const originalWrite = process.stdout.write;
  process.stdout.write = ((chunk: string | Uint8Array) => {
    stdoutWrites.push(String(chunk));
    return true;
  }) as typeof process.stdout.write;

  try {
    const acquired = await acquireGitHubActionsOidcToken(async () => ({
      getIDToken: async (audience) => {
        assert.equal(audience, GITHUB_ACTIONS_RLS_AUDIENCE);
        process.stdout.write(`::add-mask::${token}\n`);
        process.stdout.write("##[debug]TEST ONLY request URL\n");
        return token;
      },
    }));
    assert.equal(acquired, token);
    assert.deepEqual(stdoutWrites, []);
    await assert.rejects(
      acquireGitHubActionsOidcToken(async () => ({
        getIDToken: async () => {
          throw new Error(`TEST ONLY ${token}`);
        },
      })),
      {
        message: "GitHub Actions OIDC token acquisition failed.",
      },
    );
    assert.deepEqual(stdoutWrites, []);
  } finally {
    process.stdout.write = originalWrite;
  }
});

test("TEST ONLY verifier accepts an in-memory token and fetches only fixed official JWKS", async () => {
  const token = signToken(defaultClaims());
  let calls = 0;
  const result = await verifyGitHubActionsClaimsWithOfficialJwksDetailed(
    token,
    expected,
    {
      ...makeJwksDependencies(),
      fetchImpl: async (input, init) => {
        calls += 1;
        assert.equal(
          new URL(input.toString()).href,
          "https://token.actions.githubusercontent.com/.well-known/jwks",
        );
        assert.equal(new Headers(init?.headers).get("accept"), "application/json");
        assert.equal(init?.redirect, "error");
        return new Response(JSON.stringify({ keys: [primaryPublicJwk] }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    },
  );
  assert.equal(result.ok, true);
  assert.equal(calls, 1);
  if (result.ok) assert.equal(result.claims.event_name, "workflow_dispatch");
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
    approvalLabEnvironment(),
    "bootstrap",
  );
  assert.deepEqual(unavailableOidc, {
    accepted: false,
    category: "oidc_request_credentials_invalid",
    stage: "bootstrap",
  });
  let rejectedContextProviderCalls = 0;
  await diagnoseGitHubActionsApprovalLabTarget(
    approvalLabEnvironment("bootstrap", {
      GITHUB_REF: "refs/heads/feature",
    }),
    "bootstrap",
    async () => {
      rejectedContextProviderCalls += 1;
      return "TEST ONLY token";
    },
  );
  assert.equal(rejectedContextProviderCalls, 0);

  const actualNow = Math.floor(Date.now() / 1000);
  const validToken = signToken(
    defaultClaims({
      iat: actualNow - 10,
      nbf: actualNow - 10,
      exp: actualNow + 240,
    }),
  );
  const requestFailed = await diagnoseGitHubActionsApprovalLabTarget(
    approvalLabEnvironment(),
    "bootstrap",
    async () => {
      throw new Error(`TEST ONLY ${validToken}`);
    },
  );
  assert.deepEqual(requestFailed, {
    accepted: false,
    category: "oidc_request_failed_or_timeout",
    stage: "bootstrap",
  });

  const responseInvalid = await diagnoseGitHubActionsApprovalLabTarget(
    approvalLabEnvironment(),
    "bootstrap",
    async () => "",
  );
  assert.deepEqual(responseInvalid, {
    accepted: false,
    category: "oidc_response_invalid",
    stage: "bootstrap",
  });

  const jwksFailed = await withMockedGlobalFetch(
    makeDiagnosticFetch("jwks-failed"),
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(),
        "bootstrap",
        async () => validToken,
      ),
  );
  assert.deepEqual(jwksFailed, {
    accepted: false,
    category: "oidc_jwks_failed",
    stage: "bootstrap",
  });

  const jwtInvalid = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(),
        "bootstrap",
        async () => "TEST ONLY malformed JWT",
      ),
  );
  assert.deepEqual(jwtInvalid, {
    accepted: false,
    category: "oidc_jwt_header_key_signature_invalid",
    subcategory: "jwt_segment_count_invalid",
    stage: "bootstrap",
  });

  const badSignatureToken = signToken(
    defaultClaims({
      iat: actualNow - 10,
      nbf: actualNow - 10,
      exp: actualNow + 240,
    }),
    alternateKey,
  );
  const badSignature = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(),
        "bootstrap",
        async () => badSignatureToken,
      ),
  );
  assert.deepEqual(badSignature, {
    accepted: false,
    category: "oidc_jwt_header_key_signature_invalid",
    subcategory: "signature_unverifiable",
    stage: "bootstrap",
  });

  const throwingExpected = new Proxy(expected, {
    get() {
      throw new Error("TEST ONLY unexpected verification exception");
    },
  }) as ExpectedGitHubActionsOidcContext;
  const unexpectedException = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      verifyGitHubActionsClaimsWithOfficialJwksDetailed(
        validToken,
        throwingExpected,
        { nowEpochSeconds: actualNow },
      ),
  );
  assert.deepEqual(unexpectedException, {
    ok: false,
    category: "oidc_verification_unexpected_exception",
  });
  const unexpectedGuardException =
    await diagnoseGitHubActionsApprovalLabTarget(
      approvalLabEnvironment(),
      "bootstrap",
      async () => {
        throw new Error("TEST ONLY unexpected acquisition exception");
      },
    );
  assert.deepEqual(unexpectedGuardException, {
    accepted: false,
    category: "oidc_request_failed_or_timeout",
    stage: "bootstrap",
  });

  const claimsMismatchToken = signToken(
    defaultClaims({
      repository: "untrusted/fork",
      iat: actualNow - 10,
      nbf: actualNow - 10,
      exp: actualNow + 240,
    }),
  );
  const claimsMismatch = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(),
        "bootstrap",
        async () => claimsMismatchToken,
      ),
  );
  assert.deepEqual(claimsMismatch, {
    accepted: false,
    category: "claims_mismatch",
    stage: "bootstrap",
  });

  const validTarget = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment(),
        "bootstrap",
        async () => validToken,
      ),
  );
  assert.deepEqual(validTarget, { accepted: true, stage: "bootstrap" });

  const databaseUrlMismatch = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      diagnoseGitHubActionsApprovalLabTarget(
        approvalLabEnvironment("bootstrap", {
          DATABASE_URL:
            "postgresql://postgres:test-only-password@127.0.0.1:5432/not-postgres",
        }),
        "bootstrap",
        async () => validToken,
      ),
  );
  assert.deepEqual(databaseUrlMismatch, {
    accepted: false,
    category: "database_url_mismatch",
    stage: "bootstrap",
  });

  const malformedTokenResult = await withMockedGlobalFetch(
    makeDiagnosticFetch(),
    () =>
      verifyGitHubActionsClaimsWithOfficialJwksDetailed(
        "not-a-test-only-jwt",
        expected,
        { nowEpochSeconds: actualNow },
      ),
  );
  assert.deepEqual(malformedTokenResult, {
    ok: false,
    category: "oidc_jwt_header_key_signature_invalid",
    subcategory: "jwt_segment_count_invalid",
  });
  for (const result of [
    missingContext,
    incompatibleContext,
    unavailableOidc,
    requestFailed,
    responseInvalid,
    jwksFailed,
    jwtInvalid,
    badSignature,
    unexpectedGuardException,
    claimsMismatch,
    databaseUrlMismatch,
  ]) {
    assert.equal(result.accepted, false);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(
      serialized,
      /postgresql|test-only-jti|guardian-ci-/,
    );
    assert.doesNotMatch(serialized, new RegExp(validToken));
  }
  assert.doesNotMatch(
    JSON.stringify(unexpectedException),
    /postgresql|test-only-jti|guardian-ci-/,
  );
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
