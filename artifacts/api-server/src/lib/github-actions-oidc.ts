import { createPublicKey, verify as verifySignature } from "node:crypto";

export const GITHUB_ACTIONS_RLS_AUDIENCE =
  "guardian-nexus-postgres-rls-catalog";
export const GITHUB_ACTIONS_OIDC_ISSUER =
  "https://token.actions.githubusercontent.com";
export const GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID = "1455418736";
const GITHUB_ACTIONS_OIDC_JWKS_URL =
  "https://token.actions.githubusercontent.com/.well-known/jwks";
const MAX_TOKEN_BYTES = 16_384;
const MAX_JSON_RESPONSE_BYTES = 65_536;
const MAX_JWKS_KEYS = 32;
const MAX_TOKEN_AGE_SECONDS = 600;
const CLOCK_SKEW_SECONDS = 30;

export interface ExpectedGitHubActionsOidcContext {
  repository: string;
  repositoryOwner: string;
  workflow: string;
  workflowRef: string;
  ref: string;
  eventName: string;
  sha: string;
  runId: string;
  runAttempt: string;
}

interface JsonWebKeySet {
  keys?: unknown;
}

interface RsaSigningJwk {
  kid?: unknown;
  kty?: unknown;
  use?: unknown;
  alg?: unknown;
  key_ops?: unknown;
  n?: unknown;
  e?: unknown;
}

export interface GitHubActionsOidcClaims {
  iss: string;
  aud: string;
  sub: string;
  repository: string;
  repository_id: string;
  repository_owner: string;
  repository_owner_id: string;
  event_name: string;
  ref: string;
  ref_type: string;
  workflow: string;
  workflow_ref: string;
  workflow_sha: string;
  sha: string;
  run_id: string;
  run_attempt: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
}

export interface OidcFetchDependencies {
  /** Test-only injection. Production callers must omit this field. */
  fetchImpl?: typeof fetch;
  /** Test-only clock injection. Production callers must omit this field. */
  nowEpochSeconds?: number;
}

export interface GitHubActionsCoreOidcClient {
  getIDToken(audience?: string): Promise<string>;
}

async function loadGitHubActionsCore(): Promise<GitHubActionsCoreOidcClient> {
  // Keep the package load deferred until the trusted CI context has passed the
  // guard. A non-literal specifier lets local typecheck run without installing
  // the CI-only package into the Replit workspace.
  const packageName: string = "@actions/core";
  return (await import(packageName)) as GitHubActionsCoreOidcClient;
}

/**
 * Acquire the fixed-audience token using the GitHub Actions toolkit. The
 * toolkit emits an add-mask command containing the token and may emit the
 * request URL in debug mode. Suppress stdout only for this short acquisition
 * window; the returned token remains in memory for verification.
 */
export async function acquireGitHubActionsOidcToken(
  loadCore: () => Promise<GitHubActionsCoreOidcClient> =
    loadGitHubActionsCore,
): Promise<string> {
  const originalWrite = process.stdout.write;
  process.stdout.write = ((...args: unknown[]) => {
    const callback = args.find(
      (argument): argument is (error?: Error | null) => void =>
        typeof argument === "function",
    );
    callback?.();
    return true;
  }) as typeof process.stdout.write;

  try {
    const core = await loadCore();
    const token = await core.getIDToken(GITHUB_ACTIONS_RLS_AUDIENCE);
    if (
      typeof token !== "string" ||
      token.length === 0 ||
      Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
    ) {
      throw new Error();
    }
    return token;
  } catch {
    // Do not forward toolkit errors: they can contain request metadata.
    throw new Error("GitHub Actions OIDC token acquisition failed.");
  } finally {
    process.stdout.write = originalWrite;
  }
}

export type GitHubActionsOidcFailureCategory =
  | "oidc_request_credentials_invalid"
  | "oidc_request_endpoint_rejected"
  | "oidc_request_failed_or_timeout"
  | "oidc_response_invalid"
  | "oidc_jwks_failed"
  | "oidc_jwt_header_key_signature_invalid"
  | "oidc_verification_unexpected_exception"
  | "claims_mismatch";

export type GitHubActionsOidcFailureSubcategory =
  | "jwt_structure_or_header_invalid"
  | "jwk_metadata_incompatible"
  | "rsa_key_invalid"
  | "signature_unverifiable";

export type GitHubActionsOidcResult =
  | { ok: true; claims: GitHubActionsOidcClaims }
  | {
      ok: false;
      category: GitHubActionsOidcFailureCategory;
      subcategory?: GitHubActionsOidcFailureSubcategory;
    };

function jwtVerificationFailure(
  subcategory: GitHubActionsOidcFailureSubcategory,
): GitHubActionsOidcResult {
  return {
    ok: false,
    category: "oidc_jwt_header_key_signature_invalid",
    subcategory,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function decodeJsonSegment(segment: string): Record<string, unknown> | undefined {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return undefined;
  try {
    const decoded = Buffer.from(segment, "base64url");
    if (
      decoded.length > MAX_TOKEN_BYTES ||
      decoded.toString("base64url") !== segment
    ) {
      return undefined;
    }
    const value: unknown = JSON.parse(decoded.toString("utf8"));
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

function isPositiveDecimalString(value: unknown): value is string {
  return typeof value === "string" && /^[1-9]\d*$/.test(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 2048;
}

function validateClaims(
  value: Record<string, unknown>,
  expected: ExpectedGitHubActionsOidcContext,
  nowEpochSeconds: number,
): GitHubActionsOidcClaims | undefined {
  const {
    iss,
    aud,
    sub,
    repository,
    repository_id,
    repository_owner,
    repository_owner_id,
    event_name,
    ref,
    ref_type,
    workflow,
    workflow_ref,
    workflow_sha,
    sha,
    run_id,
    run_attempt,
    jti,
    iat,
    nbf,
    exp,
  } = value;

  if (
    iss !== GITHUB_ACTIONS_OIDC_ISSUER ||
    aud !== GITHUB_ACTIONS_RLS_AUDIENCE ||
    sub !== `repo:${expected.repository}:ref:${expected.ref}` ||
    typeof repository !== "string" ||
    repository.toLowerCase() !== expected.repository.toLowerCase() ||
    typeof repository_owner !== "string" ||
    repository_owner.toLowerCase() !== expected.repositoryOwner.toLowerCase() ||
    !isPositiveDecimalString(repository_id) ||
    repository_id !== GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID ||
    !isPositiveDecimalString(repository_owner_id) ||
    event_name !== expected.eventName ||
    ref !== expected.ref ||
    ref_type !== "branch" ||
    workflow !== expected.workflow ||
    workflow_ref !== expected.workflowRef ||
    typeof sha !== "string" ||
    sha.toLowerCase() !== expected.sha.toLowerCase() ||
    typeof workflow_sha !== "string" ||
    !/^[a-f0-9]{40}$/i.test(workflow_sha) ||
    run_id !== expected.runId ||
    run_attempt !== expected.runAttempt ||
    !isNonEmptyString(jti) ||
    typeof iat !== "number" ||
    !Number.isInteger(iat) ||
    typeof nbf !== "number" ||
    !Number.isInteger(nbf) ||
    typeof exp !== "number" ||
    !Number.isInteger(exp) ||
    exp <= nowEpochSeconds ||
    iat > nowEpochSeconds + CLOCK_SKEW_SECONDS ||
    nbf > nowEpochSeconds + CLOCK_SKEW_SECONDS ||
    iat < nowEpochSeconds - MAX_TOKEN_AGE_SECONDS ||
    exp - iat > MAX_TOKEN_AGE_SECONDS ||
    exp <= iat ||
    nbf > exp
  ) {
    return undefined;
  }

  return value as unknown as GitHubActionsOidcClaims;
}

/**
 * Verifies a GitHub Actions OIDC JWT against an injected JWKS. The function is
 * pure apart from cryptographic verification; tests may use generated TEST ONLY
 * keys and can never alter production readiness.
 */
function verifyGitHubActionsOidcTokenUnchecked(
  token: string,
  jwks: JsonWebKeySet,
  expected: ExpectedGitHubActionsOidcContext,
  nowEpochSeconds = Math.floor(Date.now() / 1000),
): GitHubActionsOidcResult {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
  ) {
    return jwtVerificationFailure("jwt_structure_or_header_invalid");
  }
  const segments = token.split(".");
  if (segments.length !== 3) {
    return jwtVerificationFailure("jwt_structure_or_header_invalid");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeJsonSegment(encodedHeader);
  const payload = decodeJsonSegment(encodedPayload);
  if (!header || !payload || !/^[A-Za-z0-9_-]+$/.test(encodedSignature)) {
    return jwtVerificationFailure("jwt_structure_or_header_invalid");
  }
  if (
    header.alg !== "RS256" ||
    !isNonEmptyString(header.kid) ||
    (header.typ !== undefined && header.typ !== "JWT") ||
    Object.keys(header).some(
      (key) => !["alg", "kid", "typ"].includes(key),
    )
  ) {
    return jwtVerificationFailure("jwt_structure_or_header_invalid");
  }

  const keys = jwks.keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > MAX_JWKS_KEYS) {
    return { ok: false, category: "oidc_jwks_failed" };
  }
  const matchingKeys = keys.filter(
    (key): key is RsaSigningJwk =>
      isRecord(key) && key.kid === header.kid,
  );
  if (matchingKeys.length !== 1) {
    return { ok: false, category: "oidc_jwks_failed" };
  }

  const jwk = matchingKeys[0];
  if (
    jwk.kty !== "RSA" ||
    jwk.use !== "sig" ||
    jwk.alg !== "RS256" ||
    typeof jwk.n !== "string" ||
    typeof jwk.e !== "string" ||
    (jwk.key_ops !== undefined &&
      (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes("verify")))
  ) {
    return jwtVerificationFailure("jwk_metadata_incompatible");
  }

  let publicKey: ReturnType<typeof createPublicKey>;
  try {
    publicKey = createPublicKey({
      key: { kty: "RSA", n: jwk.n, e: jwk.e } as never,
      format: "jwk",
    });
  } catch {
    return jwtVerificationFailure("rsa_key_invalid");
  }
  if (
    publicKey.asymmetricKeyType !== "rsa" ||
    (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
  ) {
    return jwtVerificationFailure("rsa_key_invalid");
  }

  try {
    const signature = Buffer.from(encodedSignature, "base64url");
    if (
      signature.length === 0 ||
      signature.toString("base64url") !== encodedSignature ||
      !verifySignature(
        "RSA-SHA256",
        Buffer.from(`${encodedHeader}.${encodedPayload}`, "ascii"),
        publicKey,
        signature,
      )
    ) {
      return jwtVerificationFailure("signature_unverifiable");
    }
  } catch {
    return jwtVerificationFailure("signature_unverifiable");
  }

  const claims = validateClaims(payload, expected, nowEpochSeconds);
  return claims
    ? { ok: true, claims }
    : { ok: false, category: "claims_mismatch" };
}

export function verifyGitHubActionsOidcTokenDetailed(
  token: string,
  jwks: JsonWebKeySet,
  expected: ExpectedGitHubActionsOidcContext,
  nowEpochSeconds = Math.floor(Date.now() / 1000),
): GitHubActionsOidcResult {
  try {
    return verifyGitHubActionsOidcTokenUnchecked(
      token,
      jwks,
      expected,
      nowEpochSeconds,
    );
  } catch {
    return {
      ok: false,
      category: "oidc_verification_unexpected_exception",
    };
  }
}

export function verifyGitHubActionsOidcToken(
  token: string,
  jwks: JsonWebKeySet,
  expected: ExpectedGitHubActionsOidcContext,
  nowEpochSeconds = Math.floor(Date.now() / 1000),
): GitHubActionsOidcClaims | undefined {
  const result = verifyGitHubActionsOidcTokenDetailed(
    token,
    jwks,
    expected,
    nowEpochSeconds,
  );
  return result.ok ? result.claims : undefined;
}

async function readJsonResponse(
  response: Response,
): Promise<Record<string, unknown> | undefined> {
  if (!response.ok) return undefined;
  const declaredLength = Number(response.headers.get("content-length"));
  if (
    Number.isFinite(declaredLength) &&
    declaredLength > MAX_JSON_RESPONSE_BYTES
  ) {
    return undefined;
  }
  const body = await response.text();
  if (Buffer.byteLength(body, "utf8") > MAX_JSON_RESPONSE_BYTES) {
    return undefined;
  }
  try {
    const value: unknown = JSON.parse(body);
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Verifies a token already acquired in memory using only the fixed official
 * GitHub JWKS endpoint. The token and request URL are never returned, logged,
 * or persisted.
 */
async function verifyGitHubActionsClaimsWithOfficialJwksUnchecked(
  token: string,
  expected: ExpectedGitHubActionsOidcContext,
  dependencies: OidcFetchDependencies = {},
): Promise<GitHubActionsOidcResult> {
  const fetchImpl = dependencies.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    return { ok: false, category: "oidc_jwks_failed" };
  }
  const nowEpochSeconds =
    dependencies.nowEpochSeconds ?? Math.floor(Date.now() / 1000);

  let jwksResponse: Response;
  try {
    jwksResponse = await fetchImpl(GITHUB_ACTIONS_OIDC_JWKS_URL, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return { ok: false, category: "oidc_jwks_failed" };
  }

  let jwks: Record<string, unknown> | undefined;
  try {
    jwks = await readJsonResponse(jwksResponse);
  } catch {
    return { ok: false, category: "oidc_jwks_failed" };
  }
  if (!jwks) {
    return { ok: false, category: "oidc_jwks_failed" };
  }

  return verifyGitHubActionsOidcTokenDetailed(
    token,
    jwks,
    expected,
    nowEpochSeconds,
  );
}

export async function verifyGitHubActionsClaimsWithOfficialJwksDetailed(
  token: string,
  expected: ExpectedGitHubActionsOidcContext,
  dependencies: OidcFetchDependencies = {},
): Promise<GitHubActionsOidcResult> {
  try {
    return await verifyGitHubActionsClaimsWithOfficialJwksUnchecked(
      token,
      expected,
      dependencies,
    );
  } catch {
    return {
      ok: false,
      category: "oidc_verification_unexpected_exception",
    };
  }
}
