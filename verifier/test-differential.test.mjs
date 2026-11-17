import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";

import {
  signApprovalLedgerCheckpointV1,
  signApprovalLedgerEventV1,
  signApprovalReceiptV1,
  verifyApprovalLedgerBundleV1,
} from "../artifacts/api-server/src/lib/approval-ledger-crypto.ts";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const API_DIR = resolve(REPO_ROOT, "artifacts/api-server");
const TS_CLI = resolve(
  API_DIR,
  "src/scripts/verify-approval-ledger-bundle.ts",
);
const PY_CLI = resolve(SCRIPT_DIR, "verify_approval_ledger.py");
const LEDGER_KEY_ID = "ephemeral-ledger-test";
const CHECKPOINT_KEY_ID = "ephemeral-checkpoint-test";
const VERIFY_AT = "2026-11-17T10:03:00.000Z";
const ISSUED_AT = "2026-11-17T10:00:00.000Z";
const CONSUMED_AT = "2026-11-17T10:01:00.000Z";
const EXPIRES_AT = "2026-11-17T10:05:00.000Z";

function ephemeralPair() {
  return generateKeyPairSync("ed25519");
}

function publicPem(pair) {
  return pair.publicKey.export({ format: "pem", type: "spki" }).toString();
}

function makeFixture({
  requestedBy = "requester-ephemeral",
  approvedBy = "approver-ephemeral",
} = {}) {
  const ledgerPair = ephemeralPair();
  const checkpointPair = ephemeralPair();
  const otherPair = ephemeralPair();
  const receipt = signApprovalReceiptV1(
    {
      version: 1,
      keyId: LEDGER_KEY_ID,
      receiptId: "receipt-ephemeral",
      workspaceId: "workspace-ephemeral",
      approvalId: "approval-ephemeral",
      proposalBindingSha256: "a".repeat(64),
      actionSha256: "b".repeat(64),
      requestedBy,
      approvedBy,
      approvedByRole: "admin",
      issuedAt: ISSUED_AT,
      expiresAt: EXPIRES_AT,
      nonce: "N".repeat(43),
    },
    ledgerPair.privateKey,
  );
  const approved = signApprovalLedgerEventV1(
    {
      version: 1,
      keyId: LEDGER_KEY_ID,
      workspaceId: receipt.payload.workspaceId,
      sequence: 1,
      eventId: "event-approved-ephemeral",
      eventType: "approval.approved",
      approvalId: receipt.payload.approvalId,
      previousEventSha256: "",
      occurredAt: ISSUED_AT,
      payload: {
        receiptId: receipt.payload.receiptId,
        receiptSha256: receipt.payloadSha256,
      },
    },
    ledgerPair.privateKey,
  );
  const consumed = signApprovalLedgerEventV1(
    {
      version: 1,
      keyId: LEDGER_KEY_ID,
      workspaceId: receipt.payload.workspaceId,
      sequence: 2,
      eventId: "event-consumed-ephemeral",
      eventType: "approval.receipt_consumed",
      approvalId: receipt.payload.approvalId,
      previousEventSha256: approved.eventSha256,
      occurredAt: CONSUMED_AT,
      payload: {
        receiptId: receipt.payload.receiptId,
        receiptSha256: receipt.payloadSha256,
        nonce: receipt.payload.nonce,
        consumedAt: CONSUMED_AT,
      },
    },
    ledgerPair.privateKey,
  );
  const bundle = { version: 1, events: [approved, consumed], receipts: [receipt] };
  const checkpointAt = "2026-11-17T10:02:00.000Z";
  const checkpoint2 = signApprovalLedgerCheckpointV1(
    {
      version: 1,
      keyId: CHECKPOINT_KEY_ID,
      workspaceId: receipt.payload.workspaceId,
      sequence: 2,
      headEventSha256: consumed.eventSha256,
      issuedAt: checkpointAt,
    },
    checkpointPair.privateKey,
  );
  const checkpoint1 = signApprovalLedgerCheckpointV1(
    {
      version: 1,
      keyId: CHECKPOINT_KEY_ID,
      workspaceId: receipt.payload.workspaceId,
      sequence: 1,
      headEventSha256: approved.eventSha256,
      issuedAt: "2026-11-17T10:00:01.000Z",
    },
    checkpointPair.privateKey,
  );
  return {
    bundle,
    ledgerPair,
    checkpointPair,
    otherPair,
    checkpoint1,
    checkpoint2,
    ledgerTrust: { [LEDGER_KEY_ID]: publicPem(ledgerPair) },
    checkpointTrust: { [CHECKPOINT_KEY_ID]: publicPem(checkpointPair) },
    otherTrust: { [LEDGER_KEY_ID]: publicPem(otherPair) },
  };
}

function clone(value) {
  return structuredClone(value);
}

function changedCharacter(value, index = 0) {
  const replacement = value[index] === "A" ? "B" : "A";
  return value.slice(0, index) + replacement + value.slice(index + 1);
}

function changedHex(value) {
  const replacement = value[0] === "a" ? "b" : "a";
  return replacement + value.slice(1);
}

function isolatedEnv() {
  const env = {
    PATH: process.env.PATH ?? "",
    LANG: "C",
    LC_ALL: "C",
  };
  if (process.env.HOME) env.HOME = process.env.HOME;
  return env;
}

function parseResult(result, label) {
  assert.equal(result.error, undefined, `${label}: child process launched`);
  assert.ok(
    result.status === 0 || result.status === 1,
    `${label}: expected verifier exit status 0 or 1`,
  );
  const lines = result.stdout.trim().split(/\r?\n/);
  assert.equal(lines.length, 1, `${label}: one JSON result line`);
  const parsed = JSON.parse(lines[0]);
  assert.equal(typeof parsed.valid, "boolean");
  assert.equal(typeof parsed.code, "string");
  assert.equal(parsed.valid, result.status === 0);
  return parsed;
}

function invokeVerifier(command, args, label) {
  const result = spawnSync(command, args, {
    cwd: API_DIR,
    env: isolatedEnv(),
    encoding: "utf8",
    timeout: 20_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  return parseResult(result, label);
}

function withTempDir(callback) {
  const dir = mkdtempSync(resolve(tmpdir(), "gn-ledger-differential-"));
  chmodSync(dir, 0o700);
  try {
    callback(dir);
  } finally {
    // Test material and all generated public trust files live only in this
    // private temporary directory. Generated private keys remain in memory.
    rmSync(dir, { recursive: true, force: true });
  }
}

function saveInputs(
  dir,
  name,
  bundleText,
  ledgerTrust,
  checkpoint,
  checkpointTrust,
  at = VERIFY_AT,
) {
  const root = resolve(dir, name);
  mkdirSync(root, { mode: 0o700 });
  const bundlePath = resolve(root, "bundle.json");
  const trustPath = resolve(root, "trusted-ledger-keys.json");
  writeFileSync(bundlePath, bundleText, { mode: 0o600 });
  writeFileSync(trustPath, JSON.stringify(ledgerTrust), { mode: 0o600 });
  const args = ["--bundle", bundlePath, "--trusted-keys", trustPath];
  if (checkpoint) {
    const checkpointPath = resolve(root, "checkpoint.json");
    const checkpointTrustPath = resolve(root, "trusted-checkpoint-keys.json");
    writeFileSync(checkpointPath, JSON.stringify(checkpoint), { mode: 0o600 });
    writeFileSync(
      checkpointTrustPath,
      JSON.stringify(checkpointTrust),
      { mode: 0o600 },
    );
    args.push(
      "--checkpoint",
      checkpointPath,
      "--checkpoint-trusted-keys",
      checkpointTrustPath,
    );
  }
  args.push("--at", at);
  return args;
}

function directTypeScriptResult(bundle, fixture, at = VERIFY_AT) {
  const trustedKeys = new Map([
    [LEDGER_KEY_ID, fixture.ledgerPair.publicKey],
  ]);
  return verifyApprovalLedgerBundleV1(bundle, trustedKeys, new Date(at));
}

test("standalone Python verifier matches the TypeScript verifier on ephemeral v1 vectors", (t) => {
  const fixture = makeFixture();
  const original = JSON.stringify(fixture.bundle);

  withTempDir((dir) => {
    const runPair = (
      name,
      bundleText,
      expectedCode,
      {
        checkpoint = fixture.checkpoint2,
        ledgerTrust = fixture.ledgerTrust,
        checkpointTrust = fixture.checkpointTrust,
        compareCli = true,
        at = VERIFY_AT,
      } = {},
    ) => {
      const pyArgs = saveInputs(
        dir,
        `${name}-py`,
        bundleText,
        ledgerTrust,
        checkpoint,
        checkpointTrust,
        at,
      );
      const py = invokeVerifier("python3", [PY_CLI, ...pyArgs], `${name}: Python`);
      const expected = { valid: expectedCode === "ok", code: expectedCode };
      assert.deepEqual(py, expected, `${name}: Python result`);

      if (compareCli) {
        const tsArgs = saveInputs(
          dir,
          `${name}-ts`,
          bundleText,
          ledgerTrust,
          checkpoint,
          checkpointTrust,
          at,
        );
        const ts = invokeVerifier(
          process.execPath,
          ["--import", "tsx", TS_CLI, ...tsArgs],
          `${name}: TypeScript CLI`,
        );
        assert.deepEqual(ts, expected, `${name}: TypeScript result`);
        assert.deepEqual(py, ts, `${name}: differential result`);
      } else {
        const direct = directTypeScriptResult(JSON.parse(bundleText), fixture, at);
        assert.deepEqual(
          direct,
          expected,
          `${name}: TypeScript library result`,
        );
        assert.deepEqual(
          py,
          { valid: direct.valid, code: direct.code },
          `${name}: Python vs TypeScript library`,
        );
      }
    };

    const assertChanged = (before, after, label) =>
      assert.notEqual(JSON.stringify(before), JSON.stringify(after), `${label} mutation`);

    runPair("complete bundle with sequence-2 checkpoint", original, "ok");

    const alteredCheckpointHead = clone(fixture.checkpoint2);
    alteredCheckpointHead.checkpoint.headEventSha256 = changedHex(
      alteredCheckpointHead.checkpoint.headEventSha256,
    );
    assertChanged(alteredCheckpointHead, fixture.checkpoint2, "checkpoint head hash");
    runPair(
      "changed checkpoint head digest",
      original,
      "checkpoint_hash_mismatch",
      { checkpoint: alteredCheckpointHead },
    );

    const invalidCheckpointSignature = clone(fixture.checkpoint2);
    invalidCheckpointSignature.signature = changedCharacter(
      invalidCheckpointSignature.signature,
    );
    assertChanged(invalidCheckpointSignature, fixture.checkpoint2, "checkpoint signature");
    runPair("altered checkpoint signature", original, "checkpoint_signature_invalid", {
      checkpoint: invalidCheckpointSignature,
    });

    runPair(
      "sequence-1 checkpoint against full bundle",
      original,
      "checkpoint_head_mismatch",
      { checkpoint: fixture.checkpoint1 },
    );

    const prefix1 = clone(fixture.bundle);
    prefix1.events = prefix1.events.slice(0, 1);
    assertChanged(prefix1, fixture.bundle, "prefix sequence 1");
    runPair(
      "sequence-1 prefix with sequence-1 checkpoint",
      JSON.stringify(prefix1),
      "ok",
      { checkpoint: fixture.checkpoint1 },
    );
    runPair(
      "truncated prefix without checkpoint is accepted by bundle verifier",
      JSON.stringify(prefix1),
      "ok",
      { checkpoint: null, compareCli: false },
    );
    runPair(
      "truncated prefix with sequence-2 checkpoint",
      JSON.stringify(prefix1),
      "checkpoint_head_mismatch",
    );

    const previousHash = clone(fixture.bundle);
    previousHash.events[1].event.previousEventSha256 = changedHex(
      previousHash.events[1].event.previousEventSha256,
    );
    assertChanged(previousHash, fixture.bundle, "previousEventSha256");
    runPair("changed previousEventSha256", JSON.stringify(previousHash), "event_order_invalid");

    const changedTime = clone(fixture.bundle);
    changedTime.events[0].event.occurredAt = "2026-11-17T10:00:00.001Z";
    assertChanged(changedTime, fixture.bundle, "occurredAt");
    runPair("changed event occurredAt", JSON.stringify(changedTime), "event_hash_mismatch");

    const changedApprover = clone(fixture.bundle);
    changedApprover.receipts[0].payload.approvedBy = "different-approver";
    assertChanged(changedApprover, fixture.bundle, "approvedBy");
    runPair("changed receipt approvedBy", JSON.stringify(changedApprover), "receipt_hash_mismatch");

    const reversed = clone(fixture.bundle);
    reversed.events.reverse();
    assertChanged(reversed, fixture.bundle, "event ordering");
    runPair("reversed events", JSON.stringify(reversed), "event_order_invalid");

    const duplicated = clone(fixture.bundle);
    duplicated.events.push(clone(duplicated.events[1]));
    assertChanged(duplicated, fixture.bundle, "duplicate event");
    runPair("duplicated event", JSON.stringify(duplicated), "event_order_invalid");

    const badEventSignature = clone(fixture.bundle);
    badEventSignature.events[0].signature = changedCharacter(
      badEventSignature.events[0].signature,
    );
    assertChanged(badEventSignature, fixture.bundle, "event signature");
    runPair("altered event signature", JSON.stringify(badEventSignature), "event_signature_invalid");

    const withoutReceipt = clone(fixture.bundle);
    withoutReceipt.receipts = [];
    assertChanged(withoutReceipt, fixture.bundle, "receipt removed");
    runPair("removed receipt", JSON.stringify(withoutReceipt), "receipt_reference_mismatch");

    const changedReceiptHash = clone(fixture.bundle);
    changedReceiptHash.events[0].event.payload.receiptSha256 = changedHex(
      changedReceiptHash.events[0].event.payload.receiptSha256,
    );
    assertChanged(changedReceiptHash, fixture.bundle, "receiptSha256");
    runPair("changed event receiptSha256", JSON.stringify(changedReceiptHash), "event_hash_mismatch");

    runPair(
      "untrusted different ledger public key",
      original,
      "receipt_signature_invalid",
      { ledgerTrust: fixture.otherTrust },
    );
    runPair(
      "unknown ledger key id",
      original,
      "unknown_key",
      { ledgerTrust: { "other-ephemeral": publicPem(fixture.otherPair) } },
    );

    const unknownCheckpointKeyTrust = {
      "different-checkpoint-id": publicPem(fixture.otherPair),
    };
    runPair(
      "unknown checkpoint key id",
      original,
      "unknown_key",
      { checkpointTrust: unknownCheckpointKeyTrust },
    );

    const checkpointSignedByLedgerKey = signApprovalLedgerCheckpointV1(
      fixture.checkpoint2.checkpoint,
      fixture.ledgerPair.privateKey,
    );
    runPair(
      "checkpoint key reused from ledger trust",
      original,
      "checkpoint_key_not_independent",
      {
        checkpoint: checkpointSignedByLedgerKey,
        checkpointTrust: {
          [CHECKPOINT_KEY_ID]: fixture.ledgerTrust[LEDGER_KEY_ID],
        },
      },
    );

    const noncanonicalSignature = clone(fixture.bundle);
    const signature = noncanonicalSignature.receipts[0].signature;
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIndex = alphabet.indexOf(signature.at(-1));
    const noncanonicalLast = alphabet[(lastIndex & 0b111100) | 1];
    noncanonicalSignature.receipts[0].signature =
      signature.slice(0, -1) + noncanonicalLast;
    assertChanged(noncanonicalSignature, fixture.bundle, "noncanonical base64url");
    runPair(
      "noncanonical base64url signature",
      JSON.stringify(noncanonicalSignature),
      "receipt_signature_invalid",
    );

    const extraReceiptField = clone(fixture.bundle);
    extraReceiptField.receipts[0].payload.unexpected = "extra";
    assertChanged(extraReceiptField, fixture.bundle, "extra receipt field");
    runPair("receipt with extra field", JSON.stringify(extraReceiptField), "receipt_invalid");

    const duplicateReceipt = clone(fixture.bundle);
    duplicateReceipt.receipts.push(clone(duplicateReceipt.receipts[0]));
    assertChanged(duplicateReceipt, fixture.bundle, "duplicate receipt");
    runPair("duplicate receipt and nonce", JSON.stringify(duplicateReceipt), "receipt_nonce_reused");

    const expiredUnconsumed = clone(fixture.bundle);
    expiredUnconsumed.events = expiredUnconsumed.events.slice(0, 1);
    assertChanged(expiredUnconsumed, fixture.bundle, "unconsumed history");
    runPair(
      "unconsumed receipt after expiry",
      JSON.stringify(expiredUnconsumed),
      "receipt_expired",
      { checkpoint: null, compareCli: false, at: "2026-11-17T10:06:00.000Z" },
    );

    const duplicateJson = original.replace(
      '"version":1',
      '"version":1,"version":1',
    );
    assert.notEqual(duplicateJson, original, "duplicate-key raw JSON mutation");
    runPair("duplicate JSON key", duplicateJson, "invalid_bundle");

    const versionedLedgerTrust = {
      version: 1,
      keys: {
        [LEDGER_KEY_ID]: {
          publicKeyPem: fixture.ledgerTrust[LEDGER_KEY_ID],
          validFrom: "2026-11-17T09:00:00.000Z",
          status: "active",
        },
      },
    };
    const versionedCheckpointTrust = {
      version: 1,
      keys: {
        [CHECKPOINT_KEY_ID]: {
          publicKeyPem: fixture.checkpointTrust[CHECKPOINT_KEY_ID],
          validFrom: "2026-11-17T09:00:00.000Z",
          status: "active",
        },
      },
    };
    runPair("versioned trust stores", original, "ok", {
      ledgerTrust: versionedLedgerTrust,
      checkpointTrust: versionedCheckpointTrust,
    });

    const notYetValidLedgerTrust = {
      version: 1,
      keys: {
        [LEDGER_KEY_ID]: {
          publicKeyPem: fixture.ledgerTrust[LEDGER_KEY_ID],
          validFrom: "2026-11-17T10:00:00.001Z",
          status: "active",
        },
      },
    };
    runPair(
      "dated key outside validity at signing time",
      original,
      "key_not_valid_at_signing_time",
      { ledgerTrust: notYetValidLedgerTrust },
    );

    const unicodeFixture = makeFixture({
      requestedBy: "requester-🛡",
      approvedBy: "approver-\u2028-例",
    });
    runPair(
      "canonical Unicode values",
      JSON.stringify(unicodeFixture.bundle),
      "ok",
      {
        ledgerTrust: unicodeFixture.ledgerTrust,
        checkpoint: unicodeFixture.checkpoint2,
        checkpointTrust: unicodeFixture.checkpointTrust,
      },
    );

    const cliWithoutCheckpoint = saveInputs(
      dir,
      "cli-requires-checkpoint",
      original,
      fixture.ledgerTrust,
      null,
      fixture.checkpointTrust,
    );
    const noCheckpointResult = invokeVerifier(
      process.execPath,
      ["--import", "tsx", TS_CLI, ...cliWithoutCheckpoint],
      "TypeScript CLI without checkpoint",
    );
    assert.deepEqual(noCheckpointResult, {
      valid: false,
      code: "invalid_bundle",
    });
  });
});
