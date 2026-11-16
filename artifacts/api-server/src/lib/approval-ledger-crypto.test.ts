import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
} from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { ConsumeWorkspaceAiAssessmentApprovalReceiptBody } from "@workspace/api-zod";
import {
  APPROVAL_LEDGER_EVENT_DOMAIN,
  APPROVAL_RECEIPT_DOMAIN,
  canonicalizeLedgerValue,
  signApprovalLedgerEventV1,
  signApprovalLedgerCheckpointV1,
  signApprovalReceiptV1,
  verifyApprovalReceiptV1,
  verifyApprovalLedgerCheckpointV1,
  verifyApprovalLedgerBundleWithCheckpointV1,
  verifyApprovalLedgerBundleV1,
  verifyApprovalLedgerEventChainV1,
  type ApprovalLedgerBundleV1,
  type ApprovalLedgerEventV1,
  type ApprovalLedgerCheckpointV1,
  type ApprovalReceiptPayloadV1,
  type SignedApprovalLedgerEventV1,
  type TrustedApprovalLedgerPublicKey,
} from "./approval-ledger-crypto.js";

type VectorFile = {
  testOnly: true;
  verificationTime: string;
  canonicalizationVector: {
    value: unknown;
    canonical: string;
  };
  trustedPublicKeys: Record<string, string>;
  bundle: ApprovalLedgerBundleV1;
};

const vectors = JSON.parse(
  readFileSync(new URL("./approval-ledger-v1.vectors.json", import.meta.url), "utf8"),
) as VectorFile;
const verificationTime = new Date(vectors.verificationTime);
const TEST_KEY_ID = "fixture-key-1";

// RFC 8032 test seed: intentionally public and TEST ONLY.
const TEST_SEED_A =
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const TEST_SEED_B =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const PKCS8_ED25519_SEED_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

function privateKeyFromTestSeed(seed: string) {
  return createPrivateKey({
    key: Buffer.concat([
      PKCS8_ED25519_SEED_PREFIX,
      Buffer.from(seed, "hex"),
    ]),
    format: "der",
    type: "pkcs8",
  });
}

const testPrivateKeyA = privateKeyFromTestSeed(TEST_SEED_A);
const testPrivateKeyB = privateKeyFromTestSeed(TEST_SEED_B);
const testPublicKeyA = createPublicKey(testPrivateKeyA);
const trustedKeysA = new Map([[TEST_KEY_ID, testPublicKeyA]]);
const receiptExpectation = {
  workspaceId: "workspace-test",
  approvalId: "approval-test",
  proposalBindingSha256: "0".repeat(64),
  actionSha256: "1".repeat(64),
  requestedBy: "requester-test",
  approvedBy: "approver-test",
  approvedByRole: "owner" as "owner" | "admin",
};

function cloneBundle(): ApprovalLedgerBundleV1 {
  return structuredClone(vectors.bundle);
}

function createTestReceipt(
  overrides: Partial<ApprovalReceiptPayloadV1> = {},
): ApprovalReceiptPayloadV1 {
  return {
    version: 1,
    keyId: TEST_KEY_ID,
    receiptId: "receipt-test",
    workspaceId: "workspace-test",
    approvalId: "approval-test",
    proposalBindingSha256: "0".repeat(64),
    actionSha256: "1".repeat(64),
    requestedBy: "requester-test",
    approvedBy: "approver-test",
    approvedByRole: "owner",
    issuedAt: "2026-11-16T10:00:00.000Z",
    expiresAt: "2026-11-16T10:05:00.000Z",
    nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    ...overrides,
  };
}

function createSignedBundle(
  receiptPayloads: readonly ApprovalReceiptPayloadV1[],
  consumedAt: string,
): ApprovalLedgerBundleV1 {
  const receipts = receiptPayloads.map((payload) =>
    signApprovalReceiptV1(payload, testPrivateKeyA),
  );
  const events: SignedApprovalLedgerEventV1[] = [];
  let previousEventSha256 = "";
  let sequence = 0;
  for (const signedReceipt of receipts) {
    const receipt = signedReceipt.payload;
    const eventBase = {
      version: 1 as const,
      keyId: TEST_KEY_ID,
      workspaceId: receipt.workspaceId,
      approvalId: receipt.approvalId,
    };
    const approved: ApprovalLedgerEventV1 = {
      ...eventBase,
      sequence: ++sequence,
      eventId: `event-${sequence}`,
      eventType: "approval.approved",
      previousEventSha256,
      occurredAt: receipt.issuedAt,
      payload: {
        receiptId: receipt.receiptId,
        receiptSha256: signedReceipt.payloadSha256,
      },
    };
    const signedApproved = signApprovalLedgerEventV1(
      approved,
      testPrivateKeyA,
    );
    events.push(signedApproved);
    previousEventSha256 = signedApproved.eventSha256;

    const consumed: ApprovalLedgerEventV1 = {
      ...eventBase,
      sequence: ++sequence,
      eventId: `event-${sequence}`,
      eventType: "approval.receipt_consumed",
      previousEventSha256,
      occurredAt: consumedAt,
      payload: {
        receiptId: receipt.receiptId,
        receiptSha256: signedReceipt.payloadSha256,
        nonce: receipt.nonce,
        consumedAt,
      },
    };
    const signedConsumed = signApprovalLedgerEventV1(
      consumed,
      testPrivateKeyA,
    );
    events.push(signedConsumed);
    previousEventSha256 = signedConsumed.eventSha256;
  }
  return { version: 1, events, receipts };
}

test("shared JSON vector has stable canonical bytes and valid Ed25519 signatures", () => {
  assert.equal(vectors.testOnly, true);
  assert.equal(
    canonicalizeLedgerValue(
      vectors.canonicalizationVector.value as never,
    ),
    vectors.canonicalizationVector.canonical,
  );
  assert.equal(
    createPublicKey(testPrivateKeyA).export({ format: "pem", type: "spki" }),
    vectors.trustedPublicKeys[TEST_KEY_ID],
  );
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(
      vectors.bundle,
      trustedKeysA,
      verificationTime,
    ),
    { valid: true, code: "ok" },
  );
});

test("event-chain verifier accepts the complete signed workspace chain", () => {
  assert.deepEqual(
    verifyApprovalLedgerEventChainV1(vectors.bundle.events, trustedKeysA),
    { valid: true, code: "ok" },
  );
});

test("event-chain verifier rejects reordering, missing events, and invalid signatures", () => {
  const reordered = [...structuredClone(vectors.bundle.events)].reverse();
  assert.deepEqual(
    verifyApprovalLedgerEventChainV1(reordered, trustedKeysA),
    { valid: false, code: "event_order_invalid" },
  );

  assert.deepEqual(
    verifyApprovalLedgerEventChainV1(vectors.bundle.events.slice(1), trustedKeysA),
    { valid: false, code: "event_order_invalid" },
  );

  const badSignature = [...structuredClone(vectors.bundle.events)];
  badSignature[0] = { ...badSignature[0], signature: "invalid" };
  assert.deepEqual(
    verifyApprovalLedgerEventChainV1(badSignature, trustedKeysA),
    { valid: false, code: "event_signature_invalid" },
  );
});

test("bundle verifier accepts historical signatures under a multi-key dated registry", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt({ keyId: "fixture-key-2" }),
    testPrivateKeyB,
  );
  const datedKeys = new Map<string, TrustedApprovalLedgerPublicKey>([
    [
      TEST_KEY_ID,
      {
        publicKey: testPublicKeyA,
        validFrom: "2026-11-16T09:00:00.000Z",
        validUntil: "2026-11-16T11:00:00.000Z",
        status: "retired",
      },
    ],
    [
      "fixture-key-2",
      {
        publicKey: createPublicKey(testPrivateKeyB),
        validFrom: "2026-11-16T10:00:00.000Z",
        status: "active",
      },
    ],
  ]);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      datedKeys,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: true, code: "ok" },
  );
});

test("bundle verifier supports an event chain spanning a planned key rotation", () => {
  const signedReceipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  const approved = signApprovalLedgerEventV1({
    version: 1,
    keyId: TEST_KEY_ID,
    workspaceId: signedReceipt.payload.workspaceId,
    sequence: 1,
    eventId: "rotation-approved",
    eventType: "approval.approved",
    approvalId: signedReceipt.payload.approvalId,
    previousEventSha256: "",
    occurredAt: signedReceipt.payload.issuedAt,
    payload: {
      receiptId: signedReceipt.payload.receiptId,
      receiptSha256: signedReceipt.payloadSha256,
    },
  }, testPrivateKeyA);
  const consumedEvent: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: "fixture-key-2",
    workspaceId: signedReceipt.payload.workspaceId,
    sequence: 2,
    eventId: "rotation-consumed",
    eventType: "approval.receipt_consumed",
    approvalId: signedReceipt.payload.approvalId,
    previousEventSha256: approved.eventSha256,
    occurredAt: "2026-11-16T10:01:00.000Z",
    payload: {
      receiptId: signedReceipt.payload.receiptId,
      receiptSha256: signedReceipt.payloadSha256,
      nonce: signedReceipt.payload.nonce,
      consumedAt: "2026-11-16T10:01:00.000Z",
    },
  };
  const consumed = signApprovalLedgerEventV1(
    consumedEvent,
    testPrivateKeyB,
  );
  const registry = new Map<string, TrustedApprovalLedgerPublicKey>([
    [
      TEST_KEY_ID,
      {
        publicKey: testPublicKeyA,
        validFrom: "2026-11-16T09:00:00.000Z",
        validUntil: "2026-11-16T10:00:30.000Z",
        status: "retired",
      },
    ],
    [
      "fixture-key-2",
      {
        publicKey: createPublicKey(testPrivateKeyB),
        validFrom: "2026-11-16T10:00:30.000Z",
        status: "active",
      },
    ],
  ]);
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(
      {
        version: 1,
        receipts: [signedReceipt],
        events: [approved, consumed],
      },
      registry,
      new Date("2026-11-16T10:02:00.000Z"),
    ),
    { valid: true, code: "ok" },
  );
});

test("dated key validity and revocation are evaluated at signature time", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  const tooNew = new Map<string, TrustedApprovalLedgerPublicKey>([
    [
      TEST_KEY_ID,
      {
        publicKey: testPublicKeyA,
        validFrom: "2026-11-16T10:00:01.000Z",
        status: "active",
      },
    ],
  ]);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      tooNew,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: false, code: "key_not_valid_at_signing_time" },
  );

  const revokedAfterSignature = new Map<string, TrustedApprovalLedgerPublicKey>([
    [
      TEST_KEY_ID,
      {
        publicKey: testPublicKeyA,
        validFrom: "2026-11-16T09:00:00.000Z",
        status: "revoked",
        revokedAt: "2026-11-16T10:00:30.000Z",
      },
    ],
  ]);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      revokedAfterSignature,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: true, code: "ok" },
  );

  const revokedBeforeSignature = new Map<string, TrustedApprovalLedgerPublicKey>([
    [
      TEST_KEY_ID,
      {
        publicKey: testPublicKeyA,
        validFrom: "2026-11-16T09:00:00.000Z",
        status: "revoked",
        revokedAt: "2026-11-16T09:59:59.000Z",
      },
    ],
  ]);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      revokedBeforeSignature,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: false, code: "key_revoked_at_signing_time" },
  );
});

function createSignedCheckpoint(
  overrides: Partial<ApprovalLedgerCheckpointV1> = {},
  signer = testPrivateKeyB,
) {
  const lastEvent = vectors.bundle.events.at(-1)!;
  return signApprovalLedgerCheckpointV1({
    version: 1,
    keyId: "checkpoint-fixture-key",
    workspaceId: lastEvent.event.workspaceId,
    sequence: lastEvent.event.sequence,
    headEventSha256: lastEvent.eventSha256,
    issuedAt: "2026-11-16T10:02:00.000Z",
    ...overrides,
  }, signer);
}

const checkpointKeys = new Map([
  ["checkpoint-fixture-key", createPublicKey(testPrivateKeyB)],
]);

test("separately trusted signed checkpoint verifies the exact v1 bundle head", () => {
  const checkpoint = createSignedCheckpoint();
  assert.deepEqual(
    verifyApprovalLedgerCheckpointV1(checkpoint, checkpointKeys),
    { valid: true, code: "ok" },
  );
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      vectors.bundle,
      trustedKeysA,
      verificationTime,
      checkpoint,
      checkpointKeys,
    ),
    { valid: true, code: "ok" },
  );
});

test("head checkpoint detects truncated, extended, reordered, or different-workspace exports", () => {
  const checkpoint = createSignedCheckpoint();
  const truncated = structuredClone(vectors.bundle);
  (truncated.events as SignedApprovalLedgerEventV1[]).pop();
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      truncated,
      trustedKeysA,
      verificationTime,
      checkpoint,
      checkpointKeys,
    ),
    { valid: false, code: "checkpoint_head_mismatch" },
  );

  const mismatchedWorkspace = createSignedCheckpoint({
    workspaceId: "another-workspace",
  });
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      vectors.bundle,
      trustedKeysA,
      verificationTime,
      mismatchedWorkspace,
      checkpointKeys,
    ),
    { valid: false, code: "checkpoint_head_mismatch" },
  );

  const wrongHead = createSignedCheckpoint({
    headEventSha256: "f".repeat(64),
  });
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      vectors.bundle,
      trustedKeysA,
      verificationTime,
      wrongHead,
      checkpointKeys,
    ),
    { valid: false, code: "checkpoint_head_mismatch" },
  );

  const wrongSequence = createSignedCheckpoint({ sequence: 1 });
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      vectors.bundle,
      trustedKeysA,
      verificationTime,
      wrongSequence,
      checkpointKeys,
    ),
    { valid: false, code: "checkpoint_head_mismatch" },
  );

  const futureCheckpoint = createSignedCheckpoint({
    issuedAt: "2026-11-16T10:03:00.000Z",
  });
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      vectors.bundle,
      trustedKeysA,
      verificationTime,
      futureCheckpoint,
      checkpointKeys,
    ),
    { valid: false, code: "checkpoint_invalid" },
  );
});

test("checkpoint verification rejects bad signature, unknown key, and untrusted checkpoint signer", () => {
  const checkpoint = createSignedCheckpoint();
  const invalidSignature = {
    ...checkpoint,
    signature: `${checkpoint.signature[0] === "A" ? "B" : "A"}${checkpoint.signature.slice(1)}`,
  };
  assert.deepEqual(
    verifyApprovalLedgerCheckpointV1(invalidSignature, checkpointKeys),
    { valid: false, code: "checkpoint_signature_invalid" },
  );
  assert.deepEqual(
    verifyApprovalLedgerCheckpointV1(checkpoint, trustedKeysA),
    { valid: false, code: "unknown_key" },
  );
  const alteredKeyId = createSignedCheckpoint({ keyId: "unknown-checkpoint-key" });
  assert.deepEqual(
    verifyApprovalLedgerCheckpointV1(alteredKeyId, checkpointKeys),
    { valid: false, code: "unknown_key" },
  );
});

test("single receipt verifier accepts a valid unexpired receipt", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: true, code: "ok" },
  );
});

test("consume body schema preserves and verifies issuer-signed canonical timestamp strings", () => {
  const payload = createTestReceipt({
    receiptId: "00000000-0000-4000-8000-000000000001",
    workspaceId: "00000000-0000-4000-8000-000000000002",
    approvalId: "00000000-0000-4000-8000-000000000003",
  });
  const signedReceipt = signApprovalReceiptV1(payload, testPrivateKeyA);
  const parsed = ConsumeWorkspaceAiAssessmentApprovalReceiptBody.parse({
    receipt: signedReceipt,
  });

  assert.equal(typeof parsed.receipt.payload.issuedAt, "string");
  assert.equal(typeof parsed.receipt.payload.expiresAt, "string");
  assert.deepEqual(parsed.receipt, signedReceipt);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      parsed.receipt,
      trustedKeysA,
      {
        workspaceId: payload.workspaceId,
        approvalId: payload.approvalId,
        proposalBindingSha256: payload.proposalBindingSha256,
        actionSha256: payload.actionSha256,
        requestedBy: payload.requestedBy,
        approvedBy: payload.approvedBy,
        approvedByRole: payload.approvedByRole,
      },
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: true, code: "ok" },
  );

  const nonCanonical = structuredClone(signedReceipt);
  nonCanonical.payload.issuedAt = "2026-11-16T10:00:00Z";
  assert.throws(() =>
    ConsumeWorkspaceAiAssessmentApprovalReceiptBody.parse({
      receipt: nonCanonical,
    }),
  );
});

test("single receipt verifier rejects an altered signature", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  receipt.signature = `${receipt.signature.slice(0, -1)}A`;
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: false, code: "receipt_signature_invalid" },
  );
});

test("single receipt verifier rejects a signature made with the wrong domain", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  receipt.signature = cryptoSign(
    null,
    Buffer.from(
      `${APPROVAL_LEDGER_EVENT_DOMAIN}${canonicalizeLedgerValue(receipt.payload)}`,
      "utf8",
    ),
    testPrivateKeyA,
  ).toString("base64url");
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: false, code: "receipt_signature_invalid" },
  );
});

test("single receipt verifier rejects expired receipts", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:05:00.000Z"),
    ),
    { valid: false, code: "receipt_expired" },
  );
});

test("single receipt verifier rejects a mismatched digest", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  receipt.payloadSha256 = "f".repeat(64);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: false, code: "receipt_hash_mismatch" },
  );
});

test("single receipt verifier rejects an unknown key ID", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt({ keyId: "other-test-key" }),
    testPrivateKeyA,
  );
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
    ),
    { valid: false, code: "unknown_key" },
  );
});

test("single receipt verifier binds workspace, approval, action, requester, and approver", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  const mismatches: Array<Partial<typeof receiptExpectation>> = [
    { workspaceId: "other-workspace" },
    { approvalId: "other-approval" },
    { actionSha256: "2".repeat(64) },
    { proposalBindingSha256: "3".repeat(64) },
    { requestedBy: "other-requester" },
    { approvedBy: "other-approver" },
    { approvedByRole: "admin" },
  ];
  for (const mismatch of mismatches) {
    assert.deepEqual(
      verifyApprovalReceiptV1(
        receipt,
        trustedKeysA,
        { ...receiptExpectation, ...mismatch },
        new Date("2026-11-16T10:01:00.000Z"),
      ),
      { valid: false, code: "receipt_reference_mismatch" },
    );
  }
});

test("single receipt verifier checks the signed approval event reference", () => {
  const receipt = signApprovalReceiptV1(
    createTestReceipt(),
    testPrivateKeyA,
  );
  const eventBase: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: TEST_KEY_ID,
    workspaceId: receipt.payload.workspaceId,
    sequence: 1,
    eventId: "event-for-receipt",
    eventType: "approval.approved",
    approvalId: receipt.payload.approvalId,
    previousEventSha256: "",
    occurredAt: receipt.payload.issuedAt,
    payload: {
      receiptId: receipt.payload.receiptId,
      receiptSha256: receipt.payloadSha256,
    },
  };
  const signedEvent = signApprovalLedgerEventV1(eventBase, testPrivateKeyA);
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
      signedEvent,
    ),
    { valid: true, code: "ok" },
  );
  const mismatchedEvent = signApprovalLedgerEventV1(
    {
      ...eventBase,
      payload: { ...eventBase.payload, receiptSha256: "f".repeat(64) },
    },
    testPrivateKeyA,
  );
  assert.deepEqual(
    verifyApprovalReceiptV1(
      receipt,
      trustedKeysA,
      receiptExpectation,
      new Date("2026-11-16T10:01:00.000Z"),
      mismatchedEvent,
    ),
    { valid: false, code: "receipt_reference_mismatch" },
  );
});

test("canonicalization rejects nulls, decimals, unsafe integers and negative zero", () => {
  for (const invalid of [null, 1.5, Number.MAX_SAFE_INTEGER + 1, -0]) {
    assert.throws(() => canonicalizeLedgerValue(invalid as never));
  }
});

test("editing a signed event field invalidates its digest", () => {
  const bundle = cloneBundle();
  (bundle.events[0]!.event.payload as Record<string, string>).receiptId =
    "receipt-edited";
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "event_hash_mismatch" },
  );
});

test("reordering signed events breaks the sequence and previous-hash chain", () => {
  const bundle = cloneBundle();
  (bundle.events as SignedApprovalLedgerEventV1[]).reverse();
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "event_order_invalid" },
  );
});

test("a valid signature made by a different key is rejected", () => {
  const bundle = cloneBundle();
  const original = bundle.events[0]!.event;
  const signedByOtherKey = signApprovalLedgerEventV1(
    original,
    testPrivateKeyB,
  );
  (bundle.events as SignedApprovalLedgerEventV1[])[0] = signedByOtherKey;
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "event_signature_invalid" },
  );
});

test("a signature using the receipt domain cannot authenticate a ledger event", () => {
  const bundle = cloneBundle();
  const event = bundle.events[0]!.event;
  const wrongDomainBytes = Buffer.from(
    `${APPROVAL_RECEIPT_DOMAIN}${canonicalizeLedgerValue(event)}`,
    "utf8",
  );
  const wrongDomainSignature = cryptoSign(
    null,
    wrongDomainBytes,
    testPrivateKeyA,
  ).toString("base64url");
  (bundle.events as SignedApprovalLedgerEventV1[])[0] = {
    ...bundle.events[0]!,
    signature: wrongDomainSignature,
  };
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "event_signature_invalid" },
  );
  assert.notEqual(
    APPROVAL_LEDGER_EVENT_DOMAIN,
    APPROVAL_RECEIPT_DOMAIN,
  );
});

test("a receipt consumed after its expiry is rejected", () => {
  const bundle = createSignedBundle(
    [
      createTestReceipt({
        expiresAt: "2026-11-16T10:00:30.000Z",
      }),
    ],
    "2026-11-16T10:01:00.000Z",
  );
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "receipt_expired" },
  );
});

test("a nonce repeated across receipts is rejected", () => {
  const repeatedNonce = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";
  const bundle = createSignedBundle(
    [
      createTestReceipt({
        receiptId: "receipt-one",
        approvalId: "approval-one",
        nonce: repeatedNonce,
      }),
      createTestReceipt({
        receiptId: "receipt-two",
        approvalId: "approval-two",
        nonce: repeatedNonce,
      }),
    ],
    "2026-11-16T10:01:00.000Z",
  );
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "receipt_nonce_reused" },
  );
});

test("a second consumption of the same receipt is rejected", () => {
  const bundle = cloneBundle();
  const firstReceipt = bundle.receipts[0]!;
  const previous = bundle.events.at(-1)!;
  const replayEvent: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: TEST_KEY_ID,
    workspaceId: firstReceipt.payload.workspaceId,
    sequence: 3,
    eventId: "event-replay",
    eventType: "approval.receipt_consumed",
    approvalId: firstReceipt.payload.approvalId,
    previousEventSha256: previous.eventSha256,
    occurredAt: "2026-11-16T10:01:30.000Z",
    payload: {
      receiptId: firstReceipt.payload.receiptId,
      receiptSha256: firstReceipt.payloadSha256,
      nonce: firstReceipt.payload.nonce,
      consumedAt: "2026-11-16T10:01:30.000Z",
    },
  };
  (bundle.events as SignedApprovalLedgerEventV1[]).push(
    signApprovalLedgerEventV1(replayEvent, testPrivateKeyA),
  );
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(bundle, trustedKeysA, verificationTime),
    { valid: false, code: "receipt_replay" },
  );
});

test("an unconsumed receipt is rejected after its validity window", () => {
  const bundle = cloneBundle();
  (bundle.events as SignedApprovalLedgerEventV1[]).pop();
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(
      bundle,
      trustedKeysA,
      new Date("2026-11-16T10:06:00.000Z"),
    ),
    { valid: false, code: "receipt_expired" },
  );
});
