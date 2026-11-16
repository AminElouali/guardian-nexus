import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const scriptPath = fileURLToPath(
  new URL("./verify-approval-ledger-bundle.ts", import.meta.url),
);
const packageRoot = resolve(dirname(scriptPath), "../..");
const vectorPath = fileURLToPath(
  new URL("../lib/approval-ledger-v1.vectors.json", import.meta.url),
);

function runIndependentVerifier(input: {
  directory: string;
  bundlePath: string;
  trustedKeysPath: string;
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

test("offline CLI verifies a portable bundle in a clean process without API or DB environment", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as {
      verificationTime: string;
      trustedPublicKeys: Record<string, string>;
      bundle: unknown;
    };
    const bundlePath = resolve(directory, "bundle.json");
    const trustedKeysPath = resolve(directory, "trusted-public-keys.json");
    writeFileSync(bundlePath, JSON.stringify(vector.bundle), { mode: 0o600 });
    writeFileSync(
      trustedKeysPath,
      JSON.stringify(vector.trustedPublicKeys),
      { mode: 0o600 },
    );

    const result = runIndependentVerifier({
      directory,
      bundlePath,
      trustedKeysPath,
      verificationTime: vector.verificationTime,
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
    const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as {
      verificationTime: string;
      trustedPublicKeys: Record<string, string>;
      bundle: {
        events: Array<{ event: { sequence: number } }>;
        receipts: unknown[];
        version: 1;
      };
    };
    vector.bundle.events[0].event.sequence += 1;
    const bundlePath = resolve(directory, "altered-bundle.json");
    const trustedKeysPath = resolve(directory, "trusted-public-keys.json");
    writeFileSync(bundlePath, JSON.stringify(vector.bundle), { mode: 0o600 });
    writeFileSync(
      trustedKeysPath,
      JSON.stringify(vector.trustedPublicKeys),
      { mode: 0o600 },
    );

    const result = runIndependentVerifier({
      directory,
      bundlePath,
      trustedKeysPath,
      verificationTime: vector.verificationTime,
    });
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

test("offline CLI rejects a key id absent from the out-of-band trust store", () => {
  const directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-verifier-"));
  try {
    const vector = JSON.parse(readFileSync(vectorPath, "utf8")) as {
      verificationTime: string;
      trustedPublicKeys: Record<string, string>;
      bundle: unknown;
    };
    const bundlePath = resolve(directory, "bundle.json");
    const trustedKeysPath = resolve(directory, "trusted-public-keys.json");
    writeFileSync(bundlePath, JSON.stringify(vector.bundle), { mode: 0o600 });
    writeFileSync(
      trustedKeysPath,
      JSON.stringify({ "untrusted-test-key": Object.values(vector.trustedPublicKeys)[0] }),
      { mode: 0o600 },
    );

    const result = runIndependentVerifier({
      directory,
      bundlePath,
      trustedKeysPath,
      verificationTime: vector.verificationTime,
    });
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
