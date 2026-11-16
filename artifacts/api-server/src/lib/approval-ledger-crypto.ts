import {
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";

export const APPROVAL_LEDGER_EVENT_DOMAIN =
  "guardian-nexus:approval-ledger-event:v1\n";
export const APPROVAL_RECEIPT_DOMAIN =
  "guardian-nexus:approval-receipt:v1\n";

export type CanonicalValue =
  | string
  | number
  | boolean
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

export type ApprovalReceiptPayloadV1 = {
  version: 1;
  keyId: string;
  receiptId: string;
  workspaceId: string;
  approvalId: string;
  proposalBindingSha256: string;
  actionSha256: string;
  requestedBy: string;
  approvedBy: string;
  approvedByRole: "owner" | "admin";
  issuedAt: string;
  expiresAt: string;
  nonce: string;
};

export type SignedApprovalReceiptV1 = {
  payload: ApprovalReceiptPayloadV1;
  payloadSha256: string;
  signature: string;
};

export type ApprovalReceiptV1Expectation = Pick<
  ApprovalReceiptPayloadV1,
  | "workspaceId"
  | "approvalId"
  | "proposalBindingSha256"
  | "actionSha256"
  | "requestedBy"
  | "approvedBy"
  | "approvedByRole"
>;

export type ApprovalLedgerEventPayloadV1 = {
  receiptId: string;
  receiptSha256: string;
  [key: string]: CanonicalValue;
};

export type ApprovalLedgerEventV1 = {
  version: 1;
  keyId: string;
  workspaceId: string;
  sequence: number;
  eventId: string;
  eventType: "approval.approved" | "approval.receipt_consumed";
  approvalId: string;
  previousEventSha256: string;
  occurredAt: string;
  payload: ApprovalLedgerEventPayloadV1;
};

export type SignedApprovalLedgerEventV1 = {
  event: ApprovalLedgerEventV1;
  eventSha256: string;
  signature: string;
};

export type ApprovalLedgerBundleV1 = {
  version: 1;
  events: readonly SignedApprovalLedgerEventV1[];
  receipts: readonly SignedApprovalReceiptV1[];
};

export const APPROVAL_LEDGER_CHECKPOINT_DOMAIN =
  "guardian-nexus:approval-ledger-checkpoint:v1\n";

export type ApprovalLedgerCheckpointV1 = {
  version: 1;
  keyId: string;
  workspaceId: string;
  sequence: number;
  headEventSha256: string;
  issuedAt: string;
};

export type SignedApprovalLedgerCheckpointV1 = {
  checkpoint: ApprovalLedgerCheckpointV1;
  checkpointSha256: string;
  signature: string;
};

export type TrustedApprovalLedgerPublicKey = {
  publicKey: KeyObject;
  validFrom: string;
  status: "active" | "retired" | "revoked";
  validUntil?: string;
  revokedAt?: string;
};

/**
 * A bare KeyObject is the legacy v1 trust-store form and remains valid for
 * historical verification. New registries should use dated key records.
 */
export type ApprovalLedgerTrustedKeys = ReadonlyMap<
  string,
  KeyObject | TrustedApprovalLedgerPublicKey
>;

export type LedgerVerificationCode =
  | "ok"
  | "invalid_bundle"
  | "unsupported_version"
  | "canonicalization_invalid"
  | "unknown_key"
  | "trusted_key_invalid"
  | "key_not_valid_at_signing_time"
  | "key_revoked_at_signing_time"
  | "event_order_invalid"
  | "event_hash_mismatch"
  | "event_signature_invalid"
  | "receipt_invalid"
  | "receipt_hash_mismatch"
  | "receipt_signature_invalid"
  | "receipt_expired"
  | "receipt_nonce_reused"
  | "receipt_replay"
  | "receipt_reference_mismatch"
  | "unsupported_event"
  | "checkpoint_invalid"
  | "checkpoint_hash_mismatch"
  | "checkpoint_signature_invalid"
  | "checkpoint_key_not_independent"
  | "checkpoint_head_mismatch";

export type LedgerVerificationResult =
  | { valid: true; code: "ok" }
  | { valid: false; code: Exclude<LedgerVerificationCode, "ok"> };

const SHA256_HEX = /^[a-f0-9]{64}$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const MAX_CANONICAL_DEPTH = 64;
const MAX_CANONICAL_NODES = 20_000;

function fail(code: Exclude<LedgerVerificationCode, "ok">): LedgerVerificationResult {
  return { valid: false, code };
}

function isPlainRecord(value: object): value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertUnicodeScalarString(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new TypeError("canonical_string_invalid");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("canonical_string_invalid");
    }
  }
}

function canonicalString(value: string): string {
  assertUnicodeScalarString(value);
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new TypeError("canonical_string_invalid");
  return encoded;
}

export function canonicalizeLedgerValue(value: CanonicalValue): string {
  let nodes = 0;

  const visit = (item: unknown, depth: number): string => {
    nodes += 1;
    if (nodes > MAX_CANONICAL_NODES || depth > MAX_CANONICAL_DEPTH) {
      throw new TypeError("canonical_value_limit");
    }
    if (typeof item === "string") return canonicalString(item);
    if (typeof item === "boolean") return item ? "true" : "false";
    if (typeof item === "number") {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) {
        throw new TypeError("canonical_integer_invalid");
      }
      return String(item);
    }
    if (Array.isArray(item)) {
      return `[${item.map((entry) => visit(entry, depth + 1)).join(",")}]`;
    }
    if (item === null || typeof item !== "object" || !isPlainRecord(item)) {
      throw new TypeError("canonical_value_invalid");
    }
    if (Reflect.ownKeys(item).length !== Object.keys(item).length) {
      throw new TypeError("canonical_object_invalid");
    }
    const keys = Object.keys(item).sort();
    const fields = keys.map((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(item, key);
      if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) {
        throw new TypeError("canonical_object_invalid");
      }
      assertUnicodeScalarString(key);
      return `${canonicalString(key)}:${visit(descriptor.value, depth + 1)}`;
    });
    return `{${fields.join(",")}}`;
  };

  return visit(value, 0);
}

function signingBytes(domain: string, value: CanonicalValue): Buffer {
  return Buffer.from(
    `${domain}${canonicalizeLedgerValue(value)}`,
    "utf8",
  );
}

function sha256(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function encodeSignature(signature: Buffer): string {
  return signature.toString("base64url");
}

export function signApprovalReceiptV1(
  payload: ApprovalReceiptPayloadV1,
  privateKey: KeyObject,
): SignedApprovalReceiptV1 {
  if (privateKey.asymmetricKeyType !== "ed25519" || !isReceiptPayload(payload)) {
    throw new TypeError("receipt_signing_input_invalid");
  }
  const bytes = signingBytes(APPROVAL_RECEIPT_DOMAIN, payload);
  return {
    payload,
    payloadSha256: sha256(bytes),
    signature: encodeSignature(cryptoSign(null, bytes, privateKey)),
  };
}

export function signApprovalLedgerEventV1(
  event: ApprovalLedgerEventV1,
  privateKey: KeyObject,
): SignedApprovalLedgerEventV1 {
  if (privateKey.asymmetricKeyType !== "ed25519" || !isLedgerEvent(event)) {
    throw new TypeError("event_signing_input_invalid");
  }
  const bytes = signingBytes(APPROVAL_LEDGER_EVENT_DOMAIN, event);
  return {
    event,
    eventSha256: sha256(bytes),
    signature: encodeSignature(cryptoSign(null, bytes, privateKey)),
  };
}

export function signApprovalLedgerCheckpointV1(
  checkpoint: ApprovalLedgerCheckpointV1,
  privateKey: KeyObject,
): SignedApprovalLedgerCheckpointV1 {
  if (
    privateKey.asymmetricKeyType !== "ed25519" ||
    !isLedgerCheckpoint(checkpoint)
  ) {
    throw new TypeError("checkpoint_signing_input_invalid");
  }
  const bytes = signingBytes(APPROVAL_LEDGER_CHECKPOINT_DOMAIN, checkpoint);
  return {
    checkpoint,
    checkpointSha256: sha256(bytes),
    signature: encodeSignature(cryptoSign(null, bytes, privateKey)),
  };
}

function decodeSignature(value: unknown): Buffer | null {
  if (typeof value !== "string" || !BASE64URL.test(value)) return null;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 64 && decoded.toString("base64url") === value
    ? decoded
    : null;
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) &&
    new Date(milliseconds).toISOString() === value;
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && SHA256_HEX.test(value);
}

function isKeyId(value: unknown): value is string {
  return typeof value === "string" && KEY_ID.test(value);
}

function hasExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
): boolean {
  const ownKeys = Reflect.ownKeys(value);
  return ownKeys.length === keys.length &&
    keys.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor?.enumerable === true && "value" in descriptor;
    });
}

function isLedgerEventPayload(
  value: unknown,
  eventType: unknown,
): value is ApprovalLedgerEventPayloadV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const payload = value as Record<string, unknown>;
  if (eventType === "approval.approved") {
    return hasExactKeys(payload, ["receiptId", "receiptSha256"]) &&
      typeof payload.receiptId === "string" && payload.receiptId.length > 0 &&
      isHash(payload.receiptSha256);
  }
  if (eventType === "approval.receipt_consumed") {
    return hasExactKeys(payload, [
      "receiptId", "receiptSha256", "nonce", "consumedAt",
    ]) &&
      typeof payload.receiptId === "string" && payload.receiptId.length > 0 &&
      isHash(payload.receiptSha256) &&
      typeof payload.nonce === "string" &&
      /^[A-Za-z0-9_-]{32,128}$/.test(payload.nonce) &&
      isCanonicalTimestamp(payload.consumedAt);
  }
  return false;
}

function isLedgerEvent(value: unknown): value is ApprovalLedgerEventV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const event = value as Record<string, unknown>;
  return hasExactKeys(event, [
    "version", "keyId", "workspaceId", "sequence", "eventId", "eventType",
    "approvalId", "previousEventSha256", "occurredAt", "payload",
  ]) &&
    event.version === 1 &&
    isKeyId(event.keyId) &&
    typeof event.workspaceId === "string" && event.workspaceId.length > 0 &&
    Number.isSafeInteger(event.sequence) && (event.sequence as number) > 0 &&
    typeof event.eventId === "string" && event.eventId.length > 0 &&
    typeof event.approvalId === "string" && event.approvalId.length > 0 &&
    (event.previousEventSha256 === "" || isHash(event.previousEventSha256)) &&
    isCanonicalTimestamp(event.occurredAt) &&
    isLedgerEventPayload(event.payload, event.eventType);
}

function getTrustedKey(
  keyId: unknown,
  trustedPublicKeys: ApprovalLedgerTrustedKeys,
  signedAt: unknown,
): { key: KeyObject } | {
  error:
    | "unknown_key"
    | "trusted_key_invalid"
    | "key_not_valid_at_signing_time"
    | "key_revoked_at_signing_time";
} {
  if (!isKeyId(keyId)) return { error: "unknown_key" };
  const configured = trustedPublicKeys.get(keyId);
  if (!configured) return { error: "unknown_key" };

  // Legacy v1 registries map key IDs directly to KeyObjects. They retain the
  // historical unbounded validity semantics for backwards compatibility.
  if (
    typeof configured === "object" &&
    configured !== null &&
    "asymmetricKeyType" in configured
  ) {
    return configured.asymmetricKeyType === "ed25519" &&
        configured.type === "public"
      ? { key: configured }
      : { error: "trusted_key_invalid" };
  }

  if (
    !configured ||
    typeof configured !== "object" ||
    !hasExactKeys(configured as unknown as Record<string, unknown>, [
      "publicKey",
      "validFrom",
      "status",
      ...("validUntil" in configured ? ["validUntil"] : []),
      ...("revokedAt" in configured ? ["revokedAt"] : []),
    ])
  ) {
    return { error: "trusted_key_invalid" };
  }
  const record = configured as TrustedApprovalLedgerPublicKey;
  if (
    !record.publicKey ||
    record.publicKey.asymmetricKeyType !== "ed25519" ||
    record.publicKey.type !== "public" ||
    !isCanonicalTimestamp(record.validFrom) ||
    !["active", "retired", "revoked"].includes(record.status) ||
    (record.validUntil !== undefined &&
      !isCanonicalTimestamp(record.validUntil)) ||
    (record.revokedAt !== undefined &&
      !isCanonicalTimestamp(record.revokedAt)) ||
    (record.status === "retired" && record.validUntil === undefined) ||
    (record.status === "revoked" && record.revokedAt === undefined) ||
    (record.status !== "revoked" && record.revokedAt !== undefined) ||
    (record.validUntil !== undefined &&
      Date.parse(record.validUntil) <= Date.parse(record.validFrom)) ||
    (record.revokedAt !== undefined &&
      Date.parse(record.revokedAt) < Date.parse(record.validFrom)) ||
    !isCanonicalTimestamp(signedAt)
  ) {
    return { error: "trusted_key_invalid" };
  }
  const signingTime = Date.parse(signedAt);
  if (
    signingTime < Date.parse(record.validFrom) ||
    (record.validUntil !== undefined &&
      signingTime >= Date.parse(record.validUntil))
  ) {
    return { error: "key_not_valid_at_signing_time" };
  }
  if (
    record.status === "revoked" &&
    signingTime >= Date.parse(record.revokedAt!)
  ) {
    return { error: "key_revoked_at_signing_time" };
  }
  return { key: record.publicKey };
}

function isLedgerCheckpoint(value: unknown): value is ApprovalLedgerCheckpointV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const checkpoint = value as Record<string, unknown>;
  return hasExactKeys(checkpoint, [
    "version",
    "keyId",
    "workspaceId",
    "sequence",
    "headEventSha256",
    "issuedAt",
  ]) &&
    checkpoint.version === 1 &&
    isKeyId(checkpoint.keyId) &&
    typeof checkpoint.workspaceId === "string" &&
    checkpoint.workspaceId.length > 0 &&
    Number.isSafeInteger(checkpoint.sequence) &&
    (checkpoint.sequence as number) > 0 &&
    isHash(checkpoint.headEventSha256) &&
    isCanonicalTimestamp(checkpoint.issuedAt);
}

function isSignedCheckpoint(
  value: unknown,
): value is SignedApprovalLedgerCheckpointV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const signed = value as Record<string, unknown>;
  return hasExactKeys(signed, [
    "checkpoint",
    "checkpointSha256",
    "signature",
  ]) &&
    isLedgerCheckpoint(signed.checkpoint) &&
    isHash(signed.checkpointSha256) &&
    typeof signed.signature === "string";
}

function trustedKeyError(
  resolution: Exclude<ReturnType<typeof getTrustedKey>, { key: KeyObject }>,
): LedgerVerificationResult {
  return fail(resolution.error);
}

function publicKeyBytes(key: KeyObject): Buffer | null {
  if (key.type !== "public" || key.asymmetricKeyType !== "ed25519") return null;
  try {
    return key.export({ format: "der", type: "spki" });
  } catch {
    return null;
  }
}

function checkpointKeyIndependence(
  candidate: KeyObject,
  keys: ApprovalLedgerTrustedKeys,
): "independent" | "same_key" | "invalid_registry" {
  const candidateBytes = publicKeyBytes(candidate);
  if (!candidateBytes) return "invalid_registry";
  for (const value of keys.values()) {
    if (!value || typeof value !== "object") return "invalid_registry";
    const key = "asymmetricKeyType" in value
      ? value as KeyObject
      : "publicKey" in value
      ? value.publicKey
      : null;
    if (!key || typeof key !== "object" || !("asymmetricKeyType" in key)) {
      return "invalid_registry";
    }
    const bytes = publicKeyBytes(key as KeyObject);
    if (!bytes) return "invalid_registry";
    if (bytes.equals(candidateBytes)) return "same_key";
  }
  return "independent";
}

function verifySignedValue(
  domain: string,
  value: CanonicalValue,
  digest: unknown,
  signature: unknown,
  key: KeyObject,
): "ok" | "hash_mismatch" | "signature_invalid" | "canonicalization_invalid" {
  let bytes: Buffer;
  try {
    bytes = signingBytes(domain, value);
  } catch {
    return "canonicalization_invalid";
  }
  if (!isHash(digest) || sha256(bytes) !== digest) return "hash_mismatch";
  const decoded = decodeSignature(signature);
  if (!decoded) return "signature_invalid";
  try {
    return cryptoVerify(null, bytes, key, decoded)
      ? "ok"
      : "signature_invalid";
  } catch {
    return "signature_invalid";
  }
}

function isReceiptPayload(value: unknown): value is ApprovalReceiptPayloadV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const receipt = value as Record<string, unknown>;
  return hasExactKeys(receipt, [
    "version", "keyId", "receiptId", "workspaceId", "approvalId",
    "proposalBindingSha256", "actionSha256", "requestedBy", "approvedBy",
    "approvedByRole", "issuedAt", "expiresAt", "nonce",
  ]) &&
    receipt.version === 1 &&
    isKeyId(receipt.keyId) &&
    typeof receipt.receiptId === "string" && receipt.receiptId.length > 0 &&
    typeof receipt.workspaceId === "string" && receipt.workspaceId.length > 0 &&
    typeof receipt.approvalId === "string" && receipt.approvalId.length > 0 &&
    isHash(receipt.proposalBindingSha256) &&
    isHash(receipt.actionSha256) &&
    typeof receipt.requestedBy === "string" && receipt.requestedBy.length > 0 &&
    typeof receipt.approvedBy === "string" && receipt.approvedBy.length > 0 &&
    receipt.requestedBy !== receipt.approvedBy &&
    (receipt.approvedByRole === "owner" || receipt.approvedByRole === "admin") &&
    isCanonicalTimestamp(receipt.issuedAt) &&
    isCanonicalTimestamp(receipt.expiresAt) &&
    Date.parse(receipt.issuedAt as string) < Date.parse(receipt.expiresAt as string) &&
    typeof receipt.nonce === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(receipt.nonce);
}

function isSignedReceipt(value: unknown): value is SignedApprovalReceiptV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const signed = value as Record<string, unknown>;
  return hasExactKeys(signed, ["payload", "payloadSha256", "signature"]) &&
    isReceiptPayload(signed.payload) &&
    isHash(signed.payloadSha256) &&
    typeof signed.signature === "string";
}

function isSignedEvent(value: unknown): value is SignedApprovalLedgerEventV1 {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      !isPlainRecord(value)) return false;
  const signed = value as Record<string, unknown>;
  if (!hasExactKeys(signed, ["event", "eventSha256", "signature"])) return false;
  const event = signed.event;
  if (!event || typeof event !== "object" || Array.isArray(event) ||
      !isPlainRecord(event)) return false;
  const record = event as Record<string, unknown>;
  return hasExactKeys(record, [
    "version", "keyId", "workspaceId", "sequence", "eventId", "eventType",
    "approvalId", "previousEventSha256", "occurredAt", "payload",
  ]) &&
    record.version === 1 &&
    isKeyId(record.keyId) &&
    typeof record.workspaceId === "string" && record.workspaceId.length > 0 &&
    Number.isSafeInteger(record.sequence) &&
    (record.sequence as number) > 0 &&
    typeof record.eventId === "string" && record.eventId.length > 0 &&
    (record.eventType === "approval.approved" ||
      record.eventType === "approval.receipt_consumed") &&
    typeof record.approvalId === "string" && record.approvalId.length > 0 &&
    (record.previousEventSha256 === "" || isHash(record.previousEventSha256)) &&
    isCanonicalTimestamp(record.occurredAt) &&
    record.payload !== null &&
    typeof record.payload === "object" &&
    !Array.isArray(record.payload) &&
    isHash(signed.eventSha256) &&
    typeof signed.signature === "string";
}

function resultForSignature(
  result: ReturnType<typeof verifySignedValue>,
  prefix: "event" | "receipt",
): LedgerVerificationResult | null {
  if (result === "ok") return null;
  if (result === "canonicalization_invalid") return fail("canonicalization_invalid");
  if (result === "hash_mismatch") {
    return fail(prefix === "event" ? "event_hash_mismatch" : "receipt_hash_mismatch");
  }
  return fail(prefix === "event" ? "event_signature_invalid" : "receipt_signature_invalid");
}

function payloadString(
  payload: ApprovalLedgerEventPayloadV1,
  key: string,
): string | null {
  const value = payload[key];
  return typeof value === "string" ? value : null;
}

/**
 * Verify one receipt against an out-of-band key map and the approval context.
 * When supplied, the signed approval event must bind this exact receipt and
 * context. This additive verifier shares the canonicalization and signature
 * primitives used by the bundle verifier; bundle verification is unchanged.
 */
export function verifyApprovalReceiptV1(
  signedReceipt: unknown,
  trustedPublicKeys: ApprovalLedgerTrustedKeys,
  expected: ApprovalReceiptV1Expectation,
  verificationTime: Date,
  approvedEvent?: SignedApprovalLedgerEventV1,
): LedgerVerificationResult {
  if (!Number.isFinite(verificationTime.getTime())) return fail("invalid_bundle");
  if (!isSignedReceipt(signedReceipt)) return fail("receipt_invalid");

  const receipt = signedReceipt.payload;
  const receiptKey = getTrustedKey(
    receipt.keyId,
    trustedPublicKeys,
    receipt.issuedAt,
  );
  if ("error" in receiptKey) return trustedKeyError(receiptKey);
  const receiptSignature = resultForSignature(
    verifySignedValue(
      APPROVAL_RECEIPT_DOMAIN,
      receipt,
      signedReceipt.payloadSha256,
      signedReceipt.signature,
      receiptKey.key,
    ),
    "receipt",
  );
  if (receiptSignature) return receiptSignature;

  if (
    receipt.workspaceId !== expected.workspaceId ||
    receipt.approvalId !== expected.approvalId ||
    receipt.proposalBindingSha256 !== expected.proposalBindingSha256 ||
    receipt.actionSha256 !== expected.actionSha256 ||
    receipt.requestedBy !== expected.requestedBy ||
    receipt.approvedBy !== expected.approvedBy ||
    receipt.approvedByRole !== expected.approvedByRole
  ) {
    return fail("receipt_reference_mismatch");
  }
  if (verificationTime.getTime() >= Date.parse(receipt.expiresAt)) {
    return fail("receipt_expired");
  }
  if (Date.parse(receipt.issuedAt) > verificationTime.getTime()) {
    return fail("receipt_invalid");
  }

  if (approvedEvent !== undefined) {
    if (
      !isSignedEvent(approvedEvent) ||
      !isLedgerEvent(approvedEvent.event) ||
      approvedEvent.event.eventType !== "approval.approved"
    ) {
      return fail("unsupported_event");
    }
    const event = approvedEvent.event;
    const eventKey = getTrustedKey(
      event.keyId,
      trustedPublicKeys,
      event.occurredAt,
    );
    if ("error" in eventKey) return trustedKeyError(eventKey);
    const eventSignature = resultForSignature(
      verifySignedValue(
        APPROVAL_LEDGER_EVENT_DOMAIN,
        event,
        approvedEvent.eventSha256,
        approvedEvent.signature,
        eventKey.key,
      ),
      "event",
    );
    if (eventSignature) return eventSignature;
    if (
      event.workspaceId !== receipt.workspaceId ||
      event.approvalId !== receipt.approvalId ||
      event.occurredAt !== receipt.issuedAt ||
      event.payload.receiptId !== receipt.receiptId ||
      event.payload.receiptSha256 !== signedReceipt.payloadSha256
    ) {
      return fail("receipt_reference_mismatch");
    }
  }

  return { valid: true, code: "ok" };
}

/**
 * Verify the signed event chain without requiring the receipt archive.
 *
 * The live consume gate uses this because receipts are client-held rather
 * than persisted. The supplied receipt is verified separately against its
 * approval event; portable bundle verification requires every receipt.
 */
export function verifyApprovalLedgerEventChainV1(
  events: readonly SignedApprovalLedgerEventV1[],
  trustedPublicKeys: ApprovalLedgerTrustedKeys,
): LedgerVerificationResult {
  if (!Array.isArray(events)) return fail("invalid_bundle");

  let previousHash = "";
  let workspaceId: string | null = null;
  const eventIds = new Set<string>();
  const issued = new Map<string, { approvalId: string; receiptSha256: string }>();
  const consumed = new Set<string>();

  for (let index = 0; index < events.length; index += 1) {
    const signedEvent = events[index];
    if (!isSignedEvent(signedEvent) || !isLedgerEvent(signedEvent.event)) {
      return fail("invalid_bundle");
    }

    const event = signedEvent.event;
    if (
      event.sequence !== index + 1 ||
      event.previousEventSha256 !== previousHash ||
      (workspaceId !== null && event.workspaceId !== workspaceId) ||
      eventIds.has(event.eventId)
    ) {
      return fail("event_order_invalid");
    }
    workspaceId = event.workspaceId;
    eventIds.add(event.eventId);

    const key = getTrustedKey(
      event.keyId,
      trustedPublicKeys,
      event.occurredAt,
    );
    if ("error" in key) return trustedKeyError(key);
    const signatureResult = resultForSignature(
      verifySignedValue(
        APPROVAL_LEDGER_EVENT_DOMAIN,
        event,
        signedEvent.eventSha256,
        signedEvent.signature,
        key.key,
      ),
      "event",
    );
    if (signatureResult) return signatureResult;

    const receiptId = payloadString(event.payload, "receiptId");
    const receiptSha256 = payloadString(event.payload, "receiptSha256");
    if (!receiptId || !receiptSha256) {
      return fail("receipt_reference_mismatch");
    }

    if (event.eventType === "approval.approved") {
      if (issued.has(receiptId)) return fail("receipt_reference_mismatch");
      issued.set(receiptId, {
        approvalId: event.approvalId,
        receiptSha256,
      });
    } else {
      const approved = issued.get(receiptId);
      if (
        !approved ||
        approved.approvalId !== event.approvalId ||
        approved.receiptSha256 !== receiptSha256 ||
        consumed.has(receiptId) ||
        event.occurredAt !== event.payload.consumedAt
      ) {
        return fail(consumed.has(receiptId) ? "receipt_replay" : "receipt_reference_mismatch");
      }
      consumed.add(receiptId);
    }
    previousHash = signedEvent.eventSha256;
  }

  return { valid: true, code: "ok" };
}

export function verifyApprovalLedgerBundleV1(
  bundle: ApprovalLedgerBundleV1,
  trustedPublicKeys: ApprovalLedgerTrustedKeys,
  verificationTime: Date,
): LedgerVerificationResult {
  if (!bundle || typeof bundle !== "object" || bundle.version !== 1 ||
      !Array.isArray(bundle.events) || !Array.isArray(bundle.receipts) ||
      !Number.isFinite(verificationTime.getTime())) {
    return fail("invalid_bundle");
  }

  const receiptsById = new Map<string, SignedApprovalReceiptV1>();
  const receiptIds = new Set<string>();
  const receiptNonces = new Set<string>();
  for (const signedReceipt of bundle.receipts) {
    if (!isSignedReceipt(signedReceipt) ||
        !isReceiptPayload(signedReceipt.payload)) {
      return fail("receipt_invalid");
    }
    const receipt = signedReceipt.payload;
    if (receiptIds.has(receipt.receiptId) || receiptNonces.has(receipt.nonce)) {
      return fail("receipt_nonce_reused");
    }
    receiptIds.add(receipt.receiptId);
    receiptNonces.add(receipt.nonce);
    const key = getTrustedKey(
      receipt.keyId,
      trustedPublicKeys,
      receipt.issuedAt,
    );
    if ("error" in key) return trustedKeyError(key);
    const signatureResult = resultForSignature(
      verifySignedValue(
        APPROVAL_RECEIPT_DOMAIN,
        receipt,
        signedReceipt.payloadSha256,
        signedReceipt.signature,
        key.key,
      ),
      "receipt",
    );
    if (signatureResult) return signatureResult;
    receiptsById.set(receipt.receiptId, signedReceipt);
  }

  let previousHash = "";
  let workspaceId: string | null = null;
  const issued = new Set<string>();
  const consumed = new Set<string>();
  const eventIds = new Set<string>();
  for (let index = 0; index < bundle.events.length; index += 1) {
    const signedEvent = bundle.events[index];
    if (!isSignedEvent(signedEvent)) return fail("invalid_bundle");
    const event = signedEvent.event;
    if (event.sequence !== index + 1 ||
        event.previousEventSha256 !== previousHash ||
        (workspaceId !== null && event.workspaceId !== workspaceId) ||
        eventIds.has(event.eventId)) {
      return fail("event_order_invalid");
    }
    workspaceId = event.workspaceId;
    eventIds.add(event.eventId);
    const key = getTrustedKey(
      event.keyId,
      trustedPublicKeys,
      event.occurredAt,
    );
    if ("error" in key) return trustedKeyError(key);
    const signatureResult = resultForSignature(
      verifySignedValue(
        APPROVAL_LEDGER_EVENT_DOMAIN,
        event,
        signedEvent.eventSha256,
        signedEvent.signature,
        key.key,
      ),
      "event",
    );
    if (signatureResult) return signatureResult;
    previousHash = signedEvent.eventSha256;

    const receiptId = payloadString(event.payload, "receiptId");
    const receiptSha256 = payloadString(event.payload, "receiptSha256");
    if (!receiptId || !isHash(receiptSha256)) {
      return fail("receipt_reference_mismatch");
    }
    const signedReceipt = receiptsById.get(receiptId);
    if (!signedReceipt || signedReceipt.payloadSha256 !== receiptSha256) {
      return fail("receipt_reference_mismatch");
    }
    const receipt = signedReceipt.payload;
    if (receipt.workspaceId !== event.workspaceId ||
        receipt.approvalId !== event.approvalId) {
      return fail("receipt_reference_mismatch");
    }

    if (event.eventType === "approval.approved") {
      if (!hasExactKeys(event.payload, ["receiptId", "receiptSha256"])) {
        return fail("unsupported_event");
      }
      if (receipt.issuedAt !== event.occurredAt) {
        return fail("receipt_reference_mismatch");
      }
      if (issued.has(receiptId)) return fail("receipt_reference_mismatch");
      issued.add(receiptId);
      continue;
    }
    if (!hasExactKeys(event.payload, [
      "receiptId", "receiptSha256", "nonce", "consumedAt",
    ])) return fail("unsupported_event");
    if (!issued.has(receiptId)) return fail("receipt_reference_mismatch");
    if (consumed.has(receiptId) ||
        payloadString(event.payload, "nonce") !== receipt.nonce) {
      return fail("receipt_replay");
    }
    const consumedAt = payloadString(event.payload, "consumedAt");
    if (!isCanonicalTimestamp(consumedAt) ||
        consumedAt !== event.occurredAt ||
        Date.parse(consumedAt) < Date.parse(receipt.issuedAt) ||
        Date.parse(consumedAt) >= Date.parse(receipt.expiresAt)) {
      return fail("receipt_expired");
    }
    consumed.add(receiptId);
  }

  if (issued.size !== receiptsById.size) return fail("receipt_reference_mismatch");
  for (const [receiptId, signedReceipt] of receiptsById) {
    if (!consumed.has(receiptId) &&
        verificationTime.getTime() >= Date.parse(signedReceipt.payload.expiresAt)) {
      return fail("receipt_expired");
    }
  }
  return { valid: true, code: "ok" };
}

export function verifyApprovalLedgerCheckpointV1(
  signedCheckpoint: unknown,
  checkpointTrustedKeys: ApprovalLedgerTrustedKeys,
): LedgerVerificationResult {
  if (!isSignedCheckpoint(signedCheckpoint)) return fail("checkpoint_invalid");
  const { checkpoint } = signedCheckpoint;
  const resolution = getTrustedKey(
    checkpoint.keyId,
    checkpointTrustedKeys,
    checkpoint.issuedAt,
  );
  if ("error" in resolution) return trustedKeyError(resolution);
  const result = verifySignedValue(
    APPROVAL_LEDGER_CHECKPOINT_DOMAIN,
    checkpoint,
    signedCheckpoint.checkpointSha256,
    signedCheckpoint.signature,
    resolution.key,
  );
  if (result === "canonicalization_invalid") {
    return fail("canonicalization_invalid");
  }
  if (result === "hash_mismatch") return fail("checkpoint_hash_mismatch");
  if (result !== "ok") return fail("checkpoint_signature_invalid");
  return { valid: true, code: "ok" };
}

/**
 * Verify a v1 bundle against a separately supplied, independently trusted
 * signed chain-head checkpoint. The bundle must end exactly at that head.
 */
export function verifyApprovalLedgerBundleWithCheckpointV1(
  bundle: ApprovalLedgerBundleV1,
  ledgerTrustedKeys: ApprovalLedgerTrustedKeys,
  verificationTime: Date,
  signedCheckpoint: unknown,
  checkpointTrustedKeys: ApprovalLedgerTrustedKeys,
): LedgerVerificationResult {
  const bundleResult = verifyApprovalLedgerBundleV1(
    bundle,
    ledgerTrustedKeys,
    verificationTime,
  );
  if (!bundleResult.valid) return bundleResult;

  const checkpointResult = verifyApprovalLedgerCheckpointV1(
    signedCheckpoint,
    checkpointTrustedKeys,
  );
  if (!checkpointResult.valid) return checkpointResult;

  const checkpoint = (signedCheckpoint as SignedApprovalLedgerCheckpointV1)
    .checkpoint;
  const checkpointKey = getTrustedKey(
    checkpoint.keyId,
    checkpointTrustedKeys,
    checkpoint.issuedAt,
  );
  if ("error" in checkpointKey) return trustedKeyError(checkpointKey);
  const independent = checkpointKeyIndependence(
    checkpointKey.key,
    ledgerTrustedKeys,
  );
  if (independent === "same_key") return fail("checkpoint_key_not_independent");
  if (independent === "invalid_registry") return fail("trusted_key_invalid");
  if (Date.parse(checkpoint.issuedAt) > verificationTime.getTime()) {
    return fail("checkpoint_invalid");
  }
  const head = bundle.events.at(-1);
  if (
    !head ||
    Date.parse(checkpoint.issuedAt) < Date.parse(head.event.occurredAt) ||
    bundle.events.length !== checkpoint.sequence ||
    head.event.workspaceId !== checkpoint.workspaceId ||
    head.event.sequence !== checkpoint.sequence ||
    head.eventSha256 !== checkpoint.headEventSha256
  ) {
    return fail("checkpoint_head_mismatch");
  }
  return { valid: true, code: "ok" };
}
