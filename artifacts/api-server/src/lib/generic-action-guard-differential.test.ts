import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { test } from "node:test";
import {
  signApprovalReceiptV1,
  verifyApprovalReceiptV1,
} from "./approval-ledger-crypto";
import { canonicalApprovalJson } from "./ai-assessment-approval-actions";
import { verifyApprovalReceiptOffline } from "../../../../lib/guardian-guard/index.mjs";

const receiptDomain = "guardian-nexus:approval-receipt:v1\n";
const expected = {
  workspaceId: "11111111-1111-4111-8111-111111111111",
  approvalId: "22222222-2222-4222-8222-222222222222",
  proposalBindingSha256: "a".repeat(64),
  actionSha256: "b".repeat(64),
  requestedBy: "synthetic-agent",
  approvedBy: "synthetic-admin",
  approvedByRole: "admin" as const,
};
const verificationTime = new Date("2026-05-04T12:00:01.000Z");

function fixture() {
  const pair = generateKeyPairSync("ed25519");
  const receipt = signApprovalReceiptV1({
    version: 1,
    keyId: "differential-key",
    receiptId: "33333333-3333-4333-8333-333333333333",
    ...expected,
    issuedAt: "2026-05-04T12:00:00.000Z",
    expiresAt: "2026-05-04T12:05:00.000Z",
    nonce: "A".repeat(43),
  }, pair.privateKey);
  return { pair, receipt };
}

function compare(
  receipt: unknown,
  publicKey: KeyObject,
  expectedContext = expected,
  at = verificationTime,
) {
  const project = verifyApprovalReceiptV1(
    receipt,
    new Map([["differential-key", publicKey]]),
    expectedContext,
    at,
  );
  const guard = verifyApprovalReceiptOffline(
    receipt,
    { "differential-key": publicKey },
    expectedContext,
    at,
  );
  assert.equal(guard.valid, project.valid);
  assert.equal(guard.code, project.code);
  return { project, guard };
}

test("guardian guard receipt verifier matches the project v1 verifier for valid and adversarial inputs", () => {
  const { pair, receipt } = fixture();
  assert.deepEqual(compare(receipt, pair.publicKey).guard, { valid: true, code: "ok" });

  const editedPayload = {
    ...receipt,
    payload: { ...receipt.payload, approvedBy: "other-admin" },
  };
  assert.notEqual(editedPayload.payload.approvedBy, receipt.payload.approvedBy);
  assert.equal(compare(editedPayload, pair.publicKey).guard.code, "receipt_hash_mismatch");

  const alteredSignature = {
    ...receipt,
    signature:
      (receipt.signature[0] === "A" ? "B" : "A") + receipt.signature.slice(1),
  };
  assert.notEqual(alteredSignature.signature, receipt.signature);
  assert.equal(compare(alteredSignature, pair.publicKey).guard.code, "receipt_signature_invalid");

  const nonCanonicalSignature = {
    ...receipt,
    signature: receipt.signature.slice(0, -1) + (receipt.signature.endsWith("A") ? "B" : "A"),
  };
  assert.notEqual(nonCanonicalSignature.signature, receipt.signature);
  assert.equal(compare(nonCanonicalSignature, pair.publicKey).guard.code, "receipt_signature_invalid");

  const wrongKey = generateKeyPairSync("ed25519");
  assert.equal(compare(receipt, wrongKey.publicKey).guard.code, "receipt_signature_invalid");

  const expired = compare(
    receipt,
    pair.publicKey,
    expected,
    new Date("2026-05-04T12:05:00.000Z"),
  );
  assert.equal(expired.guard.code, "receipt_expired");

  const unknownKeyResult = verifyApprovalReceiptOffline(
    receipt,
    {},
    expected,
    verificationTime,
  );
  assert.deepEqual(unknownKeyResult, { valid: false, code: "unknown_key" });

  const payload = receipt.payload;
  const wrongDomainBytes = Buffer.from(
    `wrong-domain\n${canonicalApprovalJson(payload)}`,
    "utf8",
  );
  const wrongDomain = {
    ...receipt,
    payloadSha256: createHash("sha256").update(wrongDomainBytes).digest("hex"),
    signature: sign(null, wrongDomainBytes, pair.privateKey).toString("base64url"),
  };
  assert.notEqual(wrongDomain.payloadSha256, receipt.payloadSha256);
  assert.equal(compare(wrongDomain, pair.publicKey).guard.code, "receipt_hash_mismatch");

  const extraField = {
    ...receipt,
    payload: { ...receipt.payload, extra: "not in v1" },
  };
  assert.equal(compare(extraField, pair.publicKey).guard.code, "receipt_invalid");
});
