import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import {
  buildApprovalLedgerPublicKeyReport,
} from "./print-approval-ledger-public-key";

test("public-key report contains only the Ed25519 public trust material", () => {
  const pair = generateKeyPairSync("ed25519");
  const privatePem = pair.privateKey.export({
    format: "pem",
    type: "pkcs8",
  }).toString();
  const report = buildApprovalLedgerPublicKeyReport(privatePem);
  assert.equal(report.status, "ok");
  if (report.status !== "ok") return;

  assert.equal(report.keyId, "guardian-nexus-approval-ledger-v1");
  assert.match(report.publicKeyPem, /^-----BEGIN PUBLIC KEY-----/);
  assert.match(report.spkiDerSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(report.trustedKeys, {
    [report.keyId]: report.publicKeyPem,
  });
  const output = JSON.stringify(report);
  assert.doesNotMatch(output, /BEGIN PRIVATE KEY/);
  const privateBody = privatePem
    .split(/\r?\n/)
    .filter((line) => !line.startsWith("-----"))
    .join("");
  assert.doesNotMatch(output, new RegExp(privateBody));
});

test("public-key command output contains only a fixed code for missing or malformed input", () => {
  const missing = buildApprovalLedgerPublicKeyReport("");
  assert.deepEqual(missing, {
    status: "no ok",
    code: "key_unavailable",
  });

  const malformedSentinel = "PRIVATE-KEY-SENTINEL-MUST-NOT-LEAK";
  const malformed = buildApprovalLedgerPublicKeyReport(malformedSentinel);
  assert.deepEqual(malformed, {
    status: "no ok",
    code: "key_invalid",
  });
  assert.doesNotMatch(JSON.stringify(malformed), /PRIVATE-KEY-SENTINEL/);
});

test("public-key command rejects another private-key algorithm without exposing it", () => {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const privatePem = pair.privateKey.export({
    format: "pem",
    type: "pkcs8",
  }).toString();
  const report = buildApprovalLedgerPublicKeyReport(privatePem);
  assert.deepEqual(report, {
    status: "no ok",
    code: "key_invalid",
  });
  assert.doesNotMatch(JSON.stringify(report), /BEGIN PRIVATE KEY/);
  assert.doesNotMatch(JSON.stringify(report), /BEGIN RSA PRIVATE KEY/);
});
