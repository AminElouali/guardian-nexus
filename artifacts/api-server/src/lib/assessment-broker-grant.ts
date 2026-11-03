import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import {
  POLICY_LAB_PROFILE_IDS,
  QWEN_POLICY_LAB_PROFILE_IDS,
  type AssessmentProfileId,
} from "./ai-assessment-sandbox";

const GRANT_VERSION = "guardian-assessment-broker-grant-v1";
const MAX_TTL_MS = 60_000;
const GRANT_KEYS = [
  "version",
  "tokenId",
  "jobId",
  "workspaceId",
  "actorId",
  "leaseId",
  "leaseAttempt",
  "profileId",
  "immutableImageId",
  "requestSha256",
  "issuedAt",
  "expiresAt",
] as const;
const ALLOWED_PROFILES = new Set<AssessmentProfileId>([
  "guardian-local-agent-v1",
  "guardian-local-llm-qwen3-0.6b-v1",
  "guardian-local-llm-native-tools-v1",
  "guardian-local-llm-autonomous-tools-v1",
  ...POLICY_LAB_PROFILE_IDS,
  ...QWEN_POLICY_LAB_PROFILE_IDS,
]);

export type AssessmentBrokerGrantBinding = {
  jobId: string;
  workspaceId: string;
  actorId: string;
  leaseId: string;
  leaseAttempt: number;
  profileId: AssessmentProfileId;
  immutableImageId: string;
  requestSha256: string;
};

export type AssessmentBrokerGrant = AssessmentBrokerGrantBinding & {
  version: typeof GRANT_VERSION;
  tokenId: string;
  issuedAt: number;
  expiresAt: number;
};

export type BrokerGrantError =
  | "grant_secret_unavailable"
  | "grant_binding_invalid"
  | "grant_token_invalid"
  | "grant_signature_invalid"
  | "grant_expired"
  | "grant_binding_mismatch"
  | "grant_replay"
  | "grant_claim_unavailable";

export type BrokerGrantResult =
  | { ok: true; grant: AssessmentBrokerGrant }
  | { ok: false; error: BrokerGrantError };

function isBoundedId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 160 &&
    !/[\u0000-\u001f\u007f]/.test(value)
  );
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function isImmutableImageId(value: unknown): value is string {
  return typeof value === "string" && /^sha256:[a-f0-9]{64}$/.test(value);
}

function stablePayloadJson(grant: AssessmentBrokerGrant): string {
  return JSON.stringify({
    version: grant.version,
    tokenId: grant.tokenId,
    jobId: grant.jobId,
    workspaceId: grant.workspaceId,
    actorId: grant.actorId,
    leaseId: grant.leaseId,
    leaseAttempt: grant.leaseAttempt,
    profileId: grant.profileId,
    immutableImageId: grant.immutableImageId,
    requestSha256: grant.requestSha256,
    issuedAt: grant.issuedAt,
    expiresAt: grant.expiresAt,
  });
}

function secretKey(secret: string | undefined): Buffer | null {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32) {
    return null;
  }
  return Buffer.from(secret, "utf8");
}

function hmac(payload: string, key: Buffer): Buffer {
  return createHmac("sha256", key).update(payload, "utf8").digest();
}

export function createAssessmentBrokerGrant(
  binding: AssessmentBrokerGrantBinding,
  secret: string | undefined,
  nowMs = Date.now(),
  ttlMs = 30_000,
): BrokerGrantResult & { token?: string } {
  const key = secretKey(secret);
  if (!key) return { ok: false, error: "grant_secret_unavailable" };
  if (
    !isBoundedId(binding.jobId) ||
    !isBoundedId(binding.workspaceId) ||
    !isBoundedId(binding.actorId) ||
    !isBoundedId(binding.leaseId) ||
    !Number.isSafeInteger(binding.leaseAttempt) ||
    binding.leaseAttempt < 1 ||
    !ALLOWED_PROFILES.has(binding.profileId) ||
    !isImmutableImageId(binding.immutableImageId) ||
    !isSha256(binding.requestSha256) ||
    !Number.isSafeInteger(nowMs) ||
    !Number.isSafeInteger(ttlMs) ||
    ttlMs <= 0 ||
    ttlMs > MAX_TTL_MS
  ) {
    return { ok: false, error: "grant_binding_invalid" };
  }
  const grant: AssessmentBrokerGrant = {
    version: GRANT_VERSION,
    tokenId: randomUUID(),
    ...binding,
    issuedAt: nowMs,
    expiresAt: nowMs + ttlMs,
  };
  const payload = Buffer.from(stablePayloadJson(grant), "utf8").toString(
    "base64url",
  );
  const token = `${payload}.${hmac(payload, key).toString("base64url")}`;
  return { ok: true, grant, token };
}

function parseGrant(value: unknown): AssessmentBrokerGrant | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (
    Object.keys(record).sort().join(",") !== [...GRANT_KEYS].sort().join(",") ||
    record.version !== GRANT_VERSION ||
    !isBoundedId(record.tokenId) ||
    !isBoundedId(record.jobId) ||
    !isBoundedId(record.workspaceId) ||
    !isBoundedId(record.actorId) ||
    !isBoundedId(record.leaseId) ||
    !Number.isSafeInteger(record.leaseAttempt) ||
    (record.leaseAttempt as number) < 1 ||
    typeof record.profileId !== "string" ||
    !ALLOWED_PROFILES.has(record.profileId as AssessmentProfileId) ||
    !isImmutableImageId(record.immutableImageId) ||
    !isSha256(record.requestSha256) ||
    !Number.isSafeInteger(record.issuedAt) ||
    !Number.isSafeInteger(record.expiresAt)
  ) {
    return null;
  }
  return record as AssessmentBrokerGrant;
}

export async function verifyAndConsumeAssessmentBrokerGrant(
  token: string,
  secret: string | undefined,
  expected: AssessmentBrokerGrantBinding,
  // Production callers must back this with an atomic durable unique-token
  // insert; a process-local set is only suitable for unit tests.
  consumeTokenIdOnce: (tokenId: string, expiresAt: number) => Promise<boolean>,
  nowMs = Date.now(),
): Promise<BrokerGrantResult> {
  const key = secretKey(secret);
  if (!key) return { ok: false, error: "grant_secret_unavailable" };
  if (
    typeof token !== "string" ||
    token.length > 4096 ||
    typeof consumeTokenIdOnce !== "function"
  ) {
    return { ok: false, error: "grant_token_invalid" };
  }
  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "grant_token_invalid" };
  const [encodedPayload, encodedSignature] = parts;
  if (!encodedPayload || !encodedSignature) {
    return { ok: false, error: "grant_token_invalid" };
  }
  const payloadBytes = Buffer.from(encodedPayload, "base64url");
  const signatureBytes = Buffer.from(encodedSignature, "base64url");
  const expectedSignature = hmac(encodedPayload, key);
  if (
    signatureBytes.length !== expectedSignature.length ||
    !timingSafeEqual(signatureBytes, expectedSignature)
  ) {
    return { ok: false, error: "grant_signature_invalid" };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(payloadBytes.toString("utf8"));
  } catch {
    return { ok: false, error: "grant_token_invalid" };
  }
  const grant = parseGrant(parsed);
  if (!grant || stablePayloadJson(grant) !== payloadBytes.toString("utf8")) {
    return { ok: false, error: "grant_token_invalid" };
  }
  if (
    !Number.isSafeInteger(nowMs) ||
    grant.issuedAt > nowMs + 5_000 ||
    grant.expiresAt <= nowMs ||
    grant.expiresAt <= grant.issuedAt ||
    grant.expiresAt - grant.issuedAt > MAX_TTL_MS
  ) {
    return { ok: false, error: "grant_expired" };
  }
  if (
    grant.jobId !== expected.jobId ||
    grant.workspaceId !== expected.workspaceId ||
    grant.actorId !== expected.actorId ||
    grant.leaseId !== expected.leaseId ||
    grant.leaseAttempt !== expected.leaseAttempt ||
    grant.profileId !== expected.profileId ||
    grant.immutableImageId !== expected.immutableImageId ||
    grant.requestSha256 !== expected.requestSha256
  ) {
    return { ok: false, error: "grant_binding_mismatch" };
  }
  try {
    if (!(await consumeTokenIdOnce(grant.tokenId, grant.expiresAt))) {
      return { ok: false, error: "grant_replay" };
    }
  } catch {
    return { ok: false, error: "grant_claim_unavailable" };
  }
  return { ok: true, grant };
}
