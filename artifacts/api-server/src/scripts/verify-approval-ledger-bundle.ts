import { createPublicKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyApprovalLedgerBundleV1,
  type ApprovalLedgerBundleV1,
} from "../lib/approval-ledger-crypto";

const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const MAX_TRUST_STORE_BYTES = 256 * 1024;
const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

type CliResult = { valid: boolean; code: string };

function parseArguments(args: readonly string[]): {
  bundlePath: string;
  trustedKeysPath: string;
  verificationTime: Date;
} | null {
  let bundlePath: string | undefined;
  let trustedKeysPath: string | undefined;
  let verificationTime = new Date();
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value || value.startsWith("--")) return null;
    if (flag === "--bundle" && !bundlePath) bundlePath = value;
    else if (flag === "--trusted-keys" && !trustedKeysPath) {
      trustedKeysPath = value;
    } else if (flag === "--at") {
      const parsed = new Date(value);
      if (
        !Number.isFinite(parsed.getTime()) ||
        parsed.toISOString() !== value
      ) {
        return null;
      }
      verificationTime = parsed;
    } else {
      return null;
    }
    index += 1;
  }
  return bundlePath && trustedKeysPath
    ? { bundlePath, trustedKeysPath, verificationTime }
    : null;
}

function parseTrustedKeys(value: unknown): Map<string, KeyObject> | null {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return null;
  }
  const keys = new Map<string, KeyObject>();
  for (const [keyId, pem] of Object.entries(value)) {
    if (
      !KEY_ID_PATTERN.test(keyId) ||
      typeof pem !== "string" ||
      pem.length > 16_384 ||
      !pem.startsWith("-----BEGIN PUBLIC KEY-----") ||
      pem.includes("PRIVATE KEY")
    ) {
      return null;
    }
    try {
      const key = createPublicKey(pem);
      if (key.asymmetricKeyType !== "ed25519") return null;
      keys.set(keyId, key);
    } catch {
      return null;
    }
  }
  return keys.size > 0 ? keys : null;
}

export function verifyApprovalLedgerBundleFiles(
  bundlePath: string,
  trustedKeysPath: string,
  verificationTime = new Date(),
): CliResult {
  try {
    const bundleBytes = readFileSync(bundlePath);
    const trustBytes = readFileSync(trustedKeysPath);
    if (
      bundleBytes.length > MAX_BUNDLE_BYTES ||
      trustBytes.length > MAX_TRUST_STORE_BYTES
    ) {
      return { valid: false, code: "invalid_bundle" };
    }
    const bundle = JSON.parse(bundleBytes.toString("utf8")) as ApprovalLedgerBundleV1;
    const trustedKeys = parseTrustedKeys(
      JSON.parse(trustBytes.toString("utf8")) as unknown,
    );
    if (!trustedKeys) return { valid: false, code: "unknown_key" };
    return verifyApprovalLedgerBundleV1(
      bundle,
      trustedKeys,
      verificationTime,
    );
  } catch {
    return { valid: false, code: "invalid_bundle" };
  }
}

function printResult(result: CliResult): void {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.valid) process.exitCode = 1;
}

function runCli(): void {
  const parsed = parseArguments(process.argv.slice(2));
  if (!parsed) {
    printResult({ valid: false, code: "invalid_bundle" });
    return;
  }
  printResult(
    verifyApprovalLedgerBundleFiles(
      resolve(parsed.bundlePath),
      resolve(parsed.trustedKeysPath),
      parsed.verificationTime,
    ),
  );
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  runCli();
}
