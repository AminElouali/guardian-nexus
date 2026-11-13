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
  | "claims_issuer_mismatch"
  | "claims_audience_mismatch"
  | "claims_subject_mismatch"
  | "claims_repository_mismatch"
  | "claims_repository_id_mismatch"
  | "claims_repository_owner_mismatch"
  | "claims_repository_owner_id_invalid"
  | "claims_event_name_mismatch"
  | "claims_ref_mismatch"
  | "claims_ref_type_mismatch"
  | "claims_workflow_mismatch"
  | "claims_workflow_ref_mismatch"
  | "claims_sha_mismatch"
  | "claims_workflow_sha_invalid"
  | "claims_run_id_mismatch"
  | "claims_run_attempt_mismatch"
  | "claims_jti_invalid"
  | "claims_iat_invalid"
  | "claims_nbf_invalid"
  | "claims_exp_invalid"
  | "claims_expired"
  | "claims_iat_in_future"
  | "claims_nbf_in_future"
  | "claims_iat_too_old"
  | "claims_lifetime_too_long"
  | "claims_exp_not_after_iat"
  | "claims_nbf_after_exp"
  | "jwt_token_invalid"
  | "jwt_segment_count_invalid"
  | "jwt_header_base64url_invalid"
  | "jwt_header_json_invalid"
  | "jwt_payload_base64url_invalid"
  | "jwt_payload_json_invalid"
  | "jwt_signature_base64url_invalid"
  | "jwt_algorithm_disallowed"
  | "jwt_kid_invalid"
  | "jwt_type_disallowed"
  | "jwt_x5t_invalid"
  | "jwt_x5t_s256_invalid"
  | "jwt_critical_header_invalid"
  | "jwt_critical_parameter_registered"
  | "jwt_critical_parameter_unsupported"
  | "jwt_key_reference_disallowed"
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

type DecodedJsonSegment =
  | { ok: true; value: Record<string, unknown> }
  | { ok: false; reason: "base64url_invalid" | "json_invalid" };

function decodeJsonSegment(segment: string): DecodedJsonSegment {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) {
    return { ok: false, reason: "base64url_invalid" };
  }

  let decoded: Buffer;
  try {
    decoded = Buffer.from(segment, "base64url");
  } catch {
    return { ok: false, reason: "base64url_invalid" };
  }
  if (
    decoded.length > MAX_TOKEN_BYTES ||
    decoded.toString("base64url") !== segment
  ) {
    return { ok: false, reason: "base64url_invalid" };
  }

  let value: unknown;
  try {
    value = JSON.parse(decoded.toString("utf8"));
  } catch {
    return { ok: false, reason: "json_invalid" };
  }
  return isRecord(value)
    ? { ok: true, value }
    : { ok: false, reason: "json_invalid" };
}

function isPositiveDecimalString(value: unknown): value is string {
  return typeof value === "string" && /^[1-9]\d*$/.test(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 2048;
}

function isBase64UrlThumbprint(
  value: unknown,
  expectedBytes: number,
): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, "base64url");
  return (
    decoded.length === expectedBytes &&
    decoded.toString("base64url") === value
  );
}

const DANGEROUS_KEY_REFERENCE_PARAMETERS = new Set(["jku", "jwk", "x5u"]);
const REGISTERED_JWS_CRITICAL_PARAMETERS = new Set(["alg", "kid", "typ"]);

function criticalHeaderFailure(
  header: Record<string, unknown>,
):
  | "jwt_critical_header_invalid"
  | "jwt_critical_parameter_registered"
  | "jwt_critical_parameter_unsupported"
  | undefined {
  if (!Object.prototype.hasOwnProperty.call(header, "crit")) return undefined;
  const critical = header.crit;
  if (!Array.isArray(critical) || critical.length === 0) {
    return "jwt_critical_header_invalid";
  }

  const seen = new Set<string>();
  for (const parameter of critical) {
    if (
      typeof parameter !== "string" ||
      parameter.length === 0 ||
      parameter === "crit" ||
      seen.has(parameter) ||
      !Object.prototype.hasOwnProperty.call(header, parameter)
    ) {
      return "jwt_critical_header_invalid";
    }
    seen.add(parameter);
  }

  for (const parameter of seen) {
    if (REGISTERED_JWS_CRITICAL_PARAMETERS.has(parameter)) {
      return "jwt_critical_parameter_registered";
    }
    return "jwt_critical_parameter_unsupported";
  }
  return undefined;
}

function validateClaims(
  value: Record<string, unknown>,
  expected: ExpectedGitHubActionsOidcContext,
  nowEpochSeconds: number,
):
  | { ok: true; claims: GitHubActionsOidcClaims }
  | { ok: false; subcategory: GitHubActionsOidcFailureSubcategory } {
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

  if (iss !== GITHUB_ACTIONS_OIDC_ISSUER) {
    return { ok: false, subcategory: "claims_issuer_mismatch" };
  }
  if (aud !== GITHUB_ACTIONS_RLS_AUDIENCE) {
    return { ok: false, subcategory: "claims_audience_mismatch" };
  }
  if (sub !== `repo:${expected.repository}:ref:${expected.ref}`) {
    return { ok: false, subcategory: "claims_subject_mismatch" };
  }
  if (
    typeof repository !== "string" ||
    repository.toLowerCase() !== expected.repository.toLowerCase()
  ) {
    return { ok: false, subcategory: "claims_repository_mismatch" };
  }
  if (
    !isPositiveDecimalString(repository_id) ||
    repository_id !== GITHUB_ACTIONS_TRUSTED_REPOSITORY_ID
  ) {
    return { ok: false, subcategory: "claims_repository_id_mismatch" };
  }
  if (
    typeof repository_owner !== "string" ||
    repository_owner.toLowerCase() !== expected.repositoryOwner.toLowerCase()
  ) {
    return { ok: false, subcategory: "claims_repository_owner_mismatch" };
  }
  if (!isPositiveDecimalString(repository_owner_id)) {
    return { ok: false, subcategory: "claims_repository_owner_id_invalid" };
  }
  if (event_name !== expected.eventName) {
    return { ok: false, subcategory: "claims_event_name_mismatch" };
  }
  if (ref !== expected.ref) {
    return { ok: false, subcategory: "claims_ref_mismatch" };
  }
  if (ref_type !== "branch") {
    return { ok: false, subcategory: "claims_ref_type_mismatch" };
  }
  if (workflow !== expected.workflow) {
    return { ok: false, subcategory: "claims_workflow_mismatch" };
  }
  if (workflow_ref !== expected.workflowRef) {
    return { ok: false, subcategory: "claims_workflow_ref_mismatch" };
  }
  if (
    typeof sha !== "string" ||
    sha.toLowerCase() !== expected.sha.toLowerCase()
  ) {
    return { ok: false, subcategory: "claims_sha_mismatch" };
  }
  if (
    typeof workflow_sha !== "string" ||
    !/^[a-f0-9]{40}$/i.test(workflow_sha)
  ) {
    return { ok: false, subcategory: "claims_workflow_sha_invalid" };
  }
  if (run_id !== expected.runId) {
    return { ok: false, subcategory: "claims_run_id_mismatch" };
  }
  if (run_attempt !== expected.runAttempt) {
    return { ok: false, subcategory: "claims_run_attempt_mismatch" };
  }
  if (!isNonEmptyString(jti)) {
    return { ok: false, subcategory: "claims_jti_invalid" };
  }
  if (typeof iat !== "number" || !Number.isInteger(iat)) {
    return { ok: false, subcategory: "claims_iat_invalid" };
  }
  if (typeof nbf !== "number" || !Number.isInteger(nbf)) {
    return { ok: false, subcategory: "claims_nbf_invalid" };
  }
  if (typeof exp !== "number" || !Number.isInteger(exp)) {
    return { ok: false, subcategory: "claims_exp_invalid" };
  }
  if (exp <= nowEpochSeconds) {
    return { ok: false, subcategory: "claims_expired" };
  }
  if (iat > nowEpochSeconds + CLOCK_SKEW_SECONDS) {
    return { ok: false, subcategory: "claims_iat_in_future" };
  }
  if (nbf > nowEpochSeconds + CLOCK_SKEW_SECONDS) {
    return { ok: false, subcategory: "claims_nbf_in_future" };
  }
  if (iat < nowEpochSeconds - MAX_TOKEN_AGE_SECONDS) {
    return { ok: false, subcategory: "claims_iat_too_old" };
  }
  if (exp - iat > MAX_TOKEN_AGE_SECONDS) {
    return { ok: false, subcategory: "claims_lifetime_too_long" };
  }
  if (exp <= iat) {
    return { ok: false, subcategory: "claims_exp_not_after_iat" };
  }
  if (nbf > exp) {
    return { ok: false, subcategory: "claims_nbf_after_exp" };
  }

  return { ok: true, claims: value as unknown as GitHubActionsOidcClaims };
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
    return jwtVerificationFailure("jwt_token_invalid");
  }
  const segments = token.split(".");
  if (segments.length !== 3) {
    return jwtVerificationFailure("jwt_segment_count_invalid");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = segments;
  const decodedHeader = decodeJsonSegment(encodedHeader);
  if (!decodedHeader.ok) {
    return jwtVerificationFailure(
      decodedHeader.reason === "base64url_invalid"
        ? "jwt_header_base64url_invalid"
        : "jwt_header_json_invalid",
    );
  }
  const decodedPayload = decodeJsonSegment(encodedPayload);
  if (!decodedPayload.ok) {
    return jwtVerificationFailure(
      decodedPayload.reason === "base64url_invalid"
        ? "jwt_payload_base64url_invalid"
        : "jwt_payload_json_invalid",
    );
  }
  if (!/^[A-Za-z0-9_-]+$/.test(encodedSignature)) {
    return jwtVerificationFailure("jwt_signature_base64url_invalid");
  }
  const header = decodedHeader.value;
  const payload = decodedPayload.value;

  if (header.alg !== "RS256") {
    return jwtVerificationFailure("jwt_algorithm_disallowed");
  }
  if (!isNonEmptyString(header.kid)) {
    return jwtVerificationFailure("jwt_kid_invalid");
  }
  if (header.typ !== undefined && header.typ !== "JWT") {
    return jwtVerificationFailure("jwt_type_disallowed");
  }
  if (
    [...DANGEROUS_KEY_REFERENCE_PARAMETERS].some((key) =>
      Object.prototype.hasOwnProperty.call(header, key),
    )
  ) {
    return jwtVerificationFailure("jwt_key_reference_disallowed");
  }
  // RFC 7515 requires rejecting unsupported critical parameters. The verifier
  // fully processes alg/kid/typ; x5t values are format-checked below but are
  // not used for key selection or certificate binding, so they are not treated
  // as supported critical extensions.
  const criticalFailure = criticalHeaderFailure(header);
  if (criticalFailure) {
    return jwtVerificationFailure(criticalFailure);
  }
  // RFC 7515 permits ignoring unrecognized non-critical parameters. They are
  // deliberately never consumed as key material, URLs, or verification input.
  if (
    header.x5t !== undefined &&
    !isBase64UrlThumbprint(header.x5t, 20)
  ) {
    return jwtVerificationFailure("jwt_x5t_invalid");
  }
  if (
    header["x5t#S256"] !== undefined &&
    !isBase64UrlThumbprint(header["x5t#S256"], 32)
  ) {
    return jwtVerificationFailure("jwt_x5t_s256_invalid");
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
      signature.toString("base64url") !== encodedSignature
    ) {
      return jwtVerificationFailure("jwt_signature_base64url_invalid");
    }
    if (
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

  const claimsValidation = validateClaims(payload, expected, nowEpochSeconds);
  return claimsValidation.ok
    ? { ok: true, claims: claimsValidation.claims }
    : {
        ok: false,
        category: "claims_mismatch",
        subcategory: claimsValidation.subcategory,
      };
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
