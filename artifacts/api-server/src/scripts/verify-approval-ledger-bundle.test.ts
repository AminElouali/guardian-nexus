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
