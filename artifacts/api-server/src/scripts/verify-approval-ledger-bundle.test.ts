import assert from "node:assert/strict";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import {
  signApprovalLedgerCheckpointV1,
  signApprovalLedgerEventV1,
  signApprovalReceiptV1,
  verifyApprovalLedgerBundleV1,
  verifyApprovalLedgerBundleWithCheckpointV1,
  type ApprovalLedgerBundleV1,
  type ApprovalLedgerEventV1,
  type ApprovalLedgerTrustedKeys,
  type ApprovalReceiptPayloadV1,
} from "../lib/approval-ledger-crypto";

const scriptPath = fileURLToPath(
  new URL("./verify-approval-ledger-bundle.ts", import.meta.url),
);
const checkpointScriptPath = fileURLToPath(
  new URL("./create-approval-ledger-checkpoint.ts", import.meta.url),
);
const packageRoot = resolve(dirname(scriptPath), "../..");
const vectorPath = fileURLToPath(
  new URL("../lib/approval-ledger-v1.vectors.json", import.meta.url),
);
const TEST_SEED_B =
  "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const PKCS8_ED25519_SEED_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);
const checkpointPrivateKey = createPrivateKey({
  key: Buffer.concat([
    PKCS8_ED25519_SEED_PREFIX,
    Buffer.from(TEST_SEED_B, "hex"),
  ]),
  format: "der",
  type: "pkcs8",
});
const checkpointKeyId = "checkpoint-fixture-key";
const checkpointPublicPem = createPublicKey(checkpointPrivateKey).export({
  format: "pem",
  type: "spki",
}).toString();

function runIndependentVerifier(input: {
  directory: string;
  bundlePath: string;
  trustedKeysPath: string;
  checkpointPath: string;
  checkpointTrustedKeysPath: string;
  verificationTime: string;
}) {
  return spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      scriptPath,
      "--bundle",
      input.bundlePath,
      "--trusted-keys",
      input.trustedKeysPath,
      "--checkpoint",
      input.checkpointPath,
      "--checkpoint-trusted-keys",
      input.checkpointTrustedKeysPath,
      "--at",
      input.verificationTime,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: {
        PATH: process.env.PATH ?? "",
        HOME: input.directory,
        LANG: "C",
        LC_ALL: "C",
      },
    },
  );
}

function writeVerifierInputs(
  directory: string,
  options: { alterBundle?: (bundle: any) => void; checkpointSignature?: string } = {},
) {
  const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as {
    verificationTime: string;
    trustedPublicKeys: Record<string, string>;
    bundle: any;
  };
  const headEvent = vector.bundle.events.at(-1);
  const checkpoint = signApprovalLedgerCheckpointV1({
    version: 1,
    keyId: checkpointKeyId,
    workspaceId: headEvent.event.workspaceId,
    sequence: headEvent.event.sequence,
    headEventSha256: headEvent.eventSha256,
    issuedAt: vector.verificationTime,
  }, checkpointPrivateKey);
  if (options.checkpointSignature) {
    checkpoint.signature = options.checkpointSignature;
  }
  options.alterBundle?.(vector.bundle);
  const bundlePath = resolve(directory, "bundle.json");
  const trustedKeysPath = resolve(directory, "trusted-public-keys.json");
  const checkpointPath = resolve(directory, "checkpoint.json");
  const checkpointTrustedKeysPath = resolve(
    directory,
    "checkpoint-trusted-public-keys.json",
  );
  writeFileSync(bundlePath, JSON.stringify(vector.bundle), { mode: 0o600 });
  writeFileSync(
    trustedKeysPath,
    JSON.stringify(vector.trustedPublicKeys),
    { mode: 0o600 },
  );
  writeFileSync(checkpointPath, JSON.stringify(checkpoint), { mode: 0o600 });
  writeFileSync(
    checkpointTrustedKeysPath,
    JSON.stringify({ [checkpointKeyId]: checkpointPublicPem }),
    { mode: 0o600 },
  );
  return {
    directory,
    bundlePath,
    trustedKeysPath,
    checkpointPath,
    checkpointTrustedKeysPath,
    verificationTime: vector.verificationTime,
    bundle: vector.bundle,
    trustedPublicKeys: vector.trustedPublicKeys,
  };
}

type MutableBundle = {
  version: 1;
  events: any[];
  receipts: any[];
};

function createEphemeralBundleFixture() {
  const ledgerPair = generateKeyPairSync("ed25519");
  const checkpointPair = generateKeyPairSync("ed25519");
  const ledgerKeyId = "ephemeral-ledger-test-key";
  const checkpointKeyId = "ephemeral-checkpoint-test-key";
  const verificationTime = new Date("2026-11-17T14:34:01.000Z");
  const issuedAt = "2026-11-17T14:32:37.787Z";
  const consumedAt = "2026-11-17T14:33:55.611Z";
  const receiptPayload: ApprovalReceiptPayloadV1 = {
    version: 1,
    keyId: ledgerKeyId,
    receiptId: "ephemeral-receipt",
    workspaceId: "ephemeral-workspace",
    approvalId: "ephemeral-approval",
    proposalBindingSha256: "a".repeat(64),
    actionSha256: "b".repeat(64),
    requestedBy: "ephemeral-requester",
    approvedBy: "ephemeral-approver",
    approvedByRole: "admin",
    issuedAt,
    expiresAt: "2026-11-17T14:37:37.787Z",
    nonce: "ephemeralNonce0123456789abcdefghij",
  };
  const signedReceipt = signApprovalReceiptV1(
    receiptPayload,
    ledgerPair.privateKey,
  );
  const approvedEvent: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: ledgerKeyId,
    workspaceId: receiptPayload.workspaceId,
    sequence: 1,
    eventId: "ephemeral-approved-event",
    eventType: "approval.approved",
    approvalId: receiptPayload.approvalId,
    previousEventSha256: "",
    occurredAt: issuedAt,
    payload: {
      receiptId: receiptPayload.receiptId,
      receiptSha256: signedReceipt.payloadSha256,
    },
  };
  const signedApprovedEvent = signApprovalLedgerEventV1(
    approvedEvent,
    ledgerPair.privateKey,
  );
  const consumedEvent: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: ledgerKeyId,
    workspaceId: receiptPayload.workspaceId,
    sequence: 2,
    eventId: "ephemeral-consumed-event",
    eventType: "approval.receipt_consumed",
    approvalId: receiptPayload.approvalId,
    previousEventSha256: signedApprovedEvent.eventSha256,
    occurredAt: consumedAt,
    payload: {
      receiptId: receiptPayload.receiptId,
      receiptSha256: signedReceipt.payloadSha256,
      nonce: receiptPayload.nonce,
      consumedAt,
    },
  };
  const signedConsumedEvent = signApprovalLedgerEventV1(
    consumedEvent,
    ledgerPair.privateKey,
  );
  const bundle: ApprovalLedgerBundleV1 = {
    version: 1,
    events: [signedApprovedEvent, signedConsumedEvent],
    receipts: [signedReceipt],
  };
  const ledgerTrustedKeys: ApprovalLedgerTrustedKeys = new Map([
    [ledgerKeyId, ledgerPair.publicKey],
  ]);
  const checkpointTrustedKeys: ApprovalLedgerTrustedKeys = new Map([
    [checkpointKeyId, checkpointPair.publicKey],
  ]);
  const checkpointFor = (events: readonly any[]) => {
    const head = events.at(-1);
    assert.ok(head);
    return signApprovalLedgerCheckpointV1({
      version: 1,
      keyId: checkpointKeyId,
      workspaceId: head.event.workspaceId,
      sequence: head.event.sequence,
      headEventSha256: head.eventSha256,
      issuedAt: "2026-11-17T14:34:00.000Z",
    }, checkpointPair.privateKey);
  };

  return {
    bundle,
    ledgerPair,
    ledgerKeyId,
    ledgerTrustedKeys,
    checkpointFor,
    checkpointTrustedKeys,
    verificationTime,
  };
}

function assertBundleMutationCode(
  fixture: ReturnType<typeof createEphemeralBundleFixture>,
  mutate: (bundle: MutableBundle) => void,
  expectedCode: string,
  checkpoint = fixture.checkpointFor(fixture.bundle.events),
): void {
  const changed = structuredClone(fixture.bundle) as MutableBundle;
  mutate(changed);
  assert.notDeepEqual(changed, fixture.bundle, "mutation must change the fixture");
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      changed,
      fixture.ledgerTrustedKeys,
      fixture.verificationTime,
      checkpoint,
      fixture.checkpointTrustedKeys,
    ),
    { valid: false, code: expectedCode },
  );
}

test("ephemeral bundle verifies through the separately signed sequence-2 checkpoint", () => {
  const fixture = createEphemeralBundleFixture();
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      fixture.bundle,
      fixture.ledgerTrustedKeys,
      fixture.verificationTime,
      fixture.checkpointFor(fixture.bundle.events),
      fixture.checkpointTrustedKeys,
    ),
    { valid: true, code: "ok" },
  );
});

test("sequence-1 checkpoint rejects a full sequence-2 bundle", () => {
  const fixture = createEphemeralBundleFixture();
  const checkpoint = fixture.checkpointFor(fixture.bundle.events.slice(0, 1));
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      fixture.bundle,
      fixture.ledgerTrustedKeys,
      fixture.verificationTime,
      checkpoint,
      fixture.checkpointTrustedKeys,
    ),
    { valid: false, code: "checkpoint_head_mismatch" },
  );
});

test("sequence-1 prefix verifies against its sequence-1 checkpoint", () => {
  const fixture = createEphemeralBundleFixture();
  const prefix = {
    ...fixture.bundle,
    events: fixture.bundle.events.slice(0, 1),
  };
  const checkpoint = fixture.checkpointFor(prefix.events);
  assert.deepEqual(
    verifyApprovalLedgerBundleWithCheckpointV1(
      prefix,
      fixture.ledgerTrustedKeys,
      fixture.verificationTime,
      checkpoint,
      fixture.checkpointTrustedKeys,
    ),
    { valid: true, code: "ok" },
  );
});

test("sequence-2 checkpoint detects removal of the second event", () => {
  const fixture = createEphemeralBundleFixture();
  assertBundleMutationCode(
    fixture,
    (bundle) => bundle.events.pop(),
    "checkpoint_head_mismatch",
  );
});

test("bundle-only verification accepts a truncated tail without a checkpoint", () => {
  const fixture = createEphemeralBundleFixture();
  const truncated = {
    ...fixture.bundle,
    events: fixture.bundle.events.slice(0, 1),
  };
  // Known limitation: a self-contained prefix cannot prove that later events
  // exist. Only a separately trusted head checkpoint detects this truncation.
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(
      truncated,
      fixture.ledgerTrustedKeys,
      fixture.verificationTime,
    ),
    { valid: true, code: "ok" },
  );
});

test("bundle verifier reports each signed-history manipulation with its fixed code", async (t) => {
  const cases: Array<{
    name: string;
    expected: string;
    mutate: (bundle: MutableBundle) => void;
  }> = [
    {
      name: "changed previousEventSha256",
      expected: "event_order_invalid",
      mutate: (bundle) => {
        const value = bundle.events[1].event.previousEventSha256 as string;
        bundle.events[1].event.previousEventSha256 =
          `${value[0] === "0" ? "1" : "0"}${value.slice(1)}`;
      },
    },
    {
      name: "changed occurredAt on event one",
      expected: "event_hash_mismatch",
      mutate: (bundle) => {
        bundle.events[0].event.occurredAt = "2026-11-17T14:32:38.787Z";
      },
    },
    {
      name: "changed approvedBy on the receipt",
      expected: "receipt_hash_mismatch",
      mutate: (bundle) => {
        bundle.receipts[0].payload.approvedBy = "different-approver";
      },
    },
    {
      name: "events reordered",
      expected: "event_order_invalid",
      mutate: (bundle) => bundle.events.reverse(),
    },
    {
      name: "second event duplicated",
      expected: "event_order_invalid",
      mutate: (bundle) => bundle.events.push(structuredClone(bundle.events[1])),
    },
    {
      name: "first event signature character changed",
      expected: "event_signature_invalid",
      mutate: (bundle) => {
        const signature = bundle.events[0].signature as string;
        bundle.events[0].signature =
          `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
      },
    },
    {
      name: "receipt removed",
      expected: "receipt_reference_mismatch",
      mutate: (bundle) => bundle.receipts.pop(),
    },
    {
      name: "receiptSha256 changed in event one",
      expected: "event_hash_mismatch",
      mutate: (bundle) => {
        const value = bundle.events[0].event.payload.receiptSha256 as string;
        bundle.events[0].event.payload.receiptSha256 =
          `${value[0] === "0" ? "1" : "0"}${value.slice(1)}`;
      },
    },
  ];

  for (const item of cases) {
    await t.test(item.name, () => {
      const fixture = createEphemeralBundleFixture();
      assertBundleMutationCode(fixture, item.mutate, item.expected);
    });
  }
});

test("bundle verification rejects a different ephemeral ledger public key", () => {
  const fixture = createEphemeralBundleFixture();
  const otherPair = generateKeyPairSync("ed25519");
  assert.notDeepEqual(
    otherPair.publicKey.export({ format: "der", type: "spki" }),
    fixture.ledgerPair.publicKey.export({ format: "der", type: "spki" }),
  );
  assert.deepEqual(
    verifyApprovalLedgerBundleV1(
      fixture.bundle,
      new Map([[fixture.ledgerKeyId, otherPair.publicKey]]),
      fixture.verificationTime,
    ),
    { valid: false, code: "receipt_signature_invalid" },
  );
});

test("bundle CLI requires checkpoint and checkpoint-trusted-keys arguments", () => {
  const fixture = createEphemeralBundleFixture();
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-no-checkpoint-"));
  try {
    const bundlePath = resolve(directory, "bundle.json");
    const trustedKeysPath = resolve(directory, "trusted-keys.json");
    writeFileSync(bundlePath, JSON.stringify(fixture.bundle), { mode: 0o600 });
    writeFileSync(
      trustedKeysPath,
      JSON.stringify({
        [fixture.ledgerKeyId]: fixture.ledgerPair.publicKey.export({
          format: "pem",
          type: "spki",
        }).toString(),
      }),
      { mode: 0o600 },
    );
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        scriptPath,
        "--bundle",
        bundlePath,
        "--trusted-keys",
        trustedKeysPath,
        "--at",
        fixture.verificationTime.toISOString(),
      ],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env: {
          PATH: process.env.PATH ?? "",
          HOME: directory,
          LANG: "C",
          LC_ALL: "C",
        },
      },
    );
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), {
      valid: false,
      code: "invalid_bundle",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI verifies a portable bundle in a clean process without API or DB environment", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory);
    const result = runIndependentVerifier({
      ...input,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), { valid: true, code: "ok" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI rejects altered bundles with a fixed diagnostic only", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory, {
      alterBundle: (bundle) => {
        bundle.events[0].event.sequence += 1;
      },
    });
    const result = runIndependentVerifier(input);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.deepEqual(
      JSON.parse(result.stdout),
      { valid: false, code: "event_order_invalid" },
    );
    assert.equal(result.stdout.includes(directory), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI refuses to verify an archive without an external checkpoint", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory);
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        scriptPath,
        "--bundle",
        input.bundlePath,
        "--trusted-keys",
        input.trustedKeysPath,
        "--at",
        input.verificationTime,
      ],
      {
        cwd: packageRoot,
        encoding: "utf8",
        env: {
          PATH: process.env.PATH ?? "",
          HOME: directory,
          LANG: "C",
          LC_ALL: "C",
        },
      },
    );
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), {
      valid: false,
      code: "invalid_bundle",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI rejects a key id absent from the out-of-band trust store", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory);
    writeFileSync(
      input.trustedKeysPath,
      JSON.stringify({ "untrusted-test-key": Object.values(input.trustedPublicKeys)[0] }),
      { mode: 0o600 },
    );

    const result = runIndependentVerifier(input);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), {
      valid: false,
      code: "unknown_key",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI detects a truncated tail against a separately trusted checkpoint", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory, {
      alterBundle: (bundle) => {
        bundle.events.pop();
      },
    });
    const result = runIndependentVerifier(input);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), {
      valid: false,
      code: "checkpoint_head_mismatch",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI rejects an invalid checkpoint signature", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory, {
      checkpointSignature: "A".repeat(86),
    });
    const result = runIndependentVerifier(input);
    assert.equal(result.status, 1);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), {
      valid: false,
      code: "checkpoint_signature_invalid",
    });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("offline CLI accepts dated historical and rotated ledger keys", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const input = writeVerifierInputs(directory);
    const source = input.trustedPublicKeys["fixture-key-1"]!;
    const futureLedgerKey = generateKeyPairSync("ed25519").publicKey.export({
      format: "pem",
      type: "spki",
    }).toString();
    writeFileSync(
      input.trustedKeysPath,
      JSON.stringify({
        version: 1,
        keys: {
          "fixture-key-1": {
            publicKeyPem: source,
            validFrom: "2026-11-16T09:00:00.000Z",
            validUntil: "2026-11-16T11:00:00.000Z",
            status: "retired",
          },
          "unused-new-key": {
            publicKeyPem: futureLedgerKey,
            validFrom: "2026-11-16T11:00:00.000Z",
            status: "active",
          },
        },
      }),
      { mode: 0o600 },
    );
    const result = runIndependentVerifier(input);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { valid: true, code: "ok" });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("checkpoint generator accepts a private test key without exposing it", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-checkpoint-"));
  try {
    const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as {
      bundle: any;
      verificationTime: string;
    };
    const head = vector.bundle.events.at(-1);
    const privateKeyPath = resolve(directory, "checkpoint-test-private.pem");
    const outputPath = resolve(directory, "checkpoint.json");
    writeFileSync(
      privateKeyPath,
      checkpointPrivateKey.export({ format: "pem", type: "pkcs8" }),
      { mode: 0o600 },
    );
    const result = spawnSync(
      process.execPath,
      [
        "--import",
        "tsx",
        checkpointScriptPath,
        "--workspace-id",
        head.event.workspaceId,
        "--sequence",
        String(head.event.sequence),
        "--head-event-sha256",
        head.eventSha256,
        "--issued-at",
        vector.verificationTime,
        "--key-id",
        checkpointKeyId,
        "--private-key",
        privateKeyPath,
        "--out",
        outputPath,
      ],
      {
        encoding: "utf8",
        env: {
          PATH: process.env.PATH ?? "",
          HOME: directory,
          LANG: "C",
          LC_ALL: "C",
        },
      },
    );
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    assert.deepEqual(JSON.parse(result.stdout), { created: true, code: "ok" });
    const signedCheckpoint = JSON.parse(readFileSync(outputPath, "utf8")) as {
      checkpoint: { keyId: string };
      signature: string;
    };
    assert.equal(signedCheckpoint.checkpoint.keyId, checkpointKeyId);
    assert.equal(signedCheckpoint.signature.length, 86);
    assert.equal(statSync(outputPath).mode & 0o777, 0o600);
    assert.equal(JSON.stringify(signedCheckpoint).includes("PRIVATE KEY"), false);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
