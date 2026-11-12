import { createPublicKey, verify as verifySignature } from "node:crypto";

export const GITHUB_ACTIONS_RLS_AUDIENCE =
  "guardian-nexus-postgres-rls-catalog";
export const GITHUB_ACTIONS_OIDC_ISSUER =
  "https://token.actions.githubusercontent.com";
const GITHUB_ACTIONS_OIDC_JWKS_URL =
  "https://token.actions.githubusercontent.com/.well-known/jwks";
const GITHUB_ACTIONS_OIDC_REQUEST_HOST =
  "pipelines.actions.githubusercontent.com";
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
export function verifyGitHubActionsOidcToken(
  token: string,
  jwks: JsonWebKeySet,
  expected: ExpectedGitHubActionsOidcContext,
  nowEpochSeconds = Math.floor(Date.now() / 1000),
): GitHubActionsOidcClaims | undefined {
  if (
    typeof token !== "string" ||
    token.length === 0 ||
    Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES
  ) {
    return undefined;
  }
  const segments = token.split(".");
  if (segments.length !== 3) return undefined;

  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const header = decodeJsonSegment(encodedHeader);
  const payload = decodeJsonSegment(encodedPayload);
  if (!header || !payload || !/^[A-Za-z0-9_-]+$/.test(encodedSignature)) {
    return undefined;
  }
  if (
    header.alg !== "RS256" ||
    !isNonEmptyString(header.kid) ||
    (header.typ !== undefined && header.typ !== "JWT") ||
    Object.keys(header).some(
      (key) => !["alg", "kid", "typ"].includes(key),
    )
  ) {
    return undefined;
  }

  const keys = jwks.keys;
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > MAX_JWKS_KEYS) {
    return undefined;
  }
  const matchingKeys = keys.filter(
    (key): key is RsaSigningJwk =>
      isRecord(key) && key.kid === header.kid,
  );
  if (matchingKeys.length !== 1) return undefined;

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
    return undefined;
  }

  try {
    const publicKey = createPublicKey({
      key: { kty: "RSA", n: jwk.n, e: jwk.e } as never,
      format: "jwk",
    });
    if (
      publicKey.asymmetricKeyType !== "rsa" ||
      (publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
    ) {
      return undefined;
    }
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
      return undefined;
    }
  } catch {
    return undefined;
  }

  return validateClaims(payload, expected, nowEpochSeconds);
}

function validatedActionsRequestUrl(
  value: string | undefined,
): URL | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    const path = url.pathname;
    const pathSegments = path.split("/");
    const validActionsPath =
      path.length <= 2048 &&
      !path.includes("%") &&
      !path.includes("\\") &&
      pathSegments[0] === "" &&
      pathSegments.length >= 5 &&
      /^[A-Za-z0-9-]+$/.test(pathSegments[1]) &&
      pathSegments[2] === "_apis" &&
      pathSegments[3] === "actions" &&
      pathSegments.at(-1) === "idtoken" &&
      pathSegments.slice(4, -1).every((segment) =>
        /^[A-Za-z0-9-]+$/.test(segment),
      );
    if (
      url.protocol !== "https:" ||
      url.hostname !== GITHUB_ACTIONS_OIDC_REQUEST_HOST ||
      (url.port !== "" && url.port !== "443") ||
      url.username !== "" ||
      url.password !== "" ||
      url.hash !== "" ||
      !validActionsPath
    ) {
      return undefined;
    }
    const queryKeys = [...url.searchParams.keys()];
    if (
      queryKeys.some((key) => !["api-version", "audience"].includes(key)) ||
      url.searchParams.getAll("api-version").length > 1 ||
      url.searchParams.getAll("audience").length > 1 ||
      url.searchParams.get("api-version") !== "2.0"
    ) {
      return undefined;
    }
    const suppliedAudience = url.searchParams.get("audience");
    if (
      suppliedAudience !== null &&
      suppliedAudience !== GITHUB_ACTIONS_RLS_AUDIENCE
    ) {
      return undefined;
    }
    url.searchParams.set("audience", GITHUB_ACTIONS_RLS_AUDIENCE);
    return url;
  } catch {
    return undefined;
  }
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
 * Requests a short-lived token from the Actions-provided endpoint, then checks
 * it using the fixed official GitHub JWKS URL. Neither the token nor either
 * request URL is returned, logged, or persisted.
 */
export async function requestVerifiedGitHubActionsClaims(
  env: Readonly<Record<string, string | undefined>>,
  expected: ExpectedGitHubActionsOidcContext,
  dependencies: OidcFetchDependencies = {},
): Promise<GitHubActionsOidcClaims | undefined> {
  const requestToken = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  const requestUrl = validatedActionsRequestUrl(
    env.ACTIONS_ID_TOKEN_REQUEST_URL,
  );
  if (
    !requestToken ||
    requestToken.length > MAX_TOKEN_BYTES ||
    !requestUrl
  ) {
    return undefined;
  }

  const fetchImpl = dependencies.fetchImpl ?? fetch;
  const nowEpochSeconds =
    dependencies.nowEpochSeconds ?? Math.floor(Date.now() / 1000);

  try {
    const tokenResponse = await fetchImpl(requestUrl, {
      method: "GET",
      headers: {
        Accept: "application/json",
        Authorization: `Bearer ${requestToken}`,
      },
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const tokenBody = await readJsonResponse(tokenResponse);
    const token = tokenBody?.value;
    if (typeof token !== "string" || token.length === 0) return undefined;

    const jwksResponse = await fetchImpl(GITHUB_ACTIONS_OIDC_JWKS_URL, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(5000),
    });
    const jwks = await readJsonResponse(jwksResponse);
    if (!jwks) return undefined;
    return verifyGitHubActionsOidcToken(
      token,
      jwks,
      expected,
      nowEpochSeconds,
    );
  } catch {
    return undefined;
  }
}
