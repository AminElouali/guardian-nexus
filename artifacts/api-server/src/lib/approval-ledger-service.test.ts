import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { loadApprovalLedgerSigningKeys } from "./approval-ledger-keys.js";

test("approval ledger signing accepts only Ed25519 private keys", () => {
  const pair = generateKeyPairSync("ed25519");
  const keys = loadApprovalLedgerSigningKeys(
    pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
  );
  assert.equal(keys.privateKey.asymmetricKeyType, "ed25519");
  assert.equal(keys.publicKey.asymmetricKeyType, "ed25519");
});

test("missing and malformed approval ledger keys fail closed without echoing input", () => {
  const malformed = "TEST_ONLY_PRIVATE_KEY_SENTINEL";
  assert.throws(
    () => loadApprovalLedgerSigningKeys(""),
    (error: unknown) =>
      error instanceof Error &&
      error.message === "approval_ledger_key_unavailable" &&
      !error.message.includes(malformed),
  );
  assert.throws(
    () => loadApprovalLedgerSigningKeys(malformed),
    (error: unknown) =>
      error instanceof Error &&
      error.message === "approval_ledger_key_invalid" &&
      !error.message.includes(malformed),
  );
});

test("a valid non-Ed25519 private key is rejected", () => {
  const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const pem = rsa.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  assert.throws(
    () => loadApprovalLedgerSigningKeys(pem),
    (error: unknown) =>
      error instanceof Error && error.message === "approval_ledger_key_invalid",
  );
});
