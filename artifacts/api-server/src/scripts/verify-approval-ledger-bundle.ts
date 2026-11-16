import { createPublicKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  verifyApprovalLedgerBundleWithCheckpointV1,
  type ApprovalLedgerTrustedKeys,
  type ApprovalLedgerBundleV1,
} from "../lib/approval-ledger-crypto";

const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const MAX_TRUST_STORE_BYTES = 256 * 1024;
const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const CANONICAL_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

type CliResult = { valid: boolean; code: string };

function parseArguments(args: readonly string[]): {
  bundlePath: string;
  trustedKeysPath: string;
  checkpointPath: string;
  checkpointTrustedKeysPath: string;
  verificationTime: Date;
} | null {
  let bundlePath: string | undefined;
  let trustedKeysPath: string | undefined;
  let checkpointPath: string | undefined;
  let checkpointTrustedKeysPath: string | undefined;
  let verificationTime = new Date();
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    const value = args[index + 1];
    if (!value || value.startsWith("--")) return null;
    if (flag === "--bundle" && !bundlePath) bundlePath = value;
    else if (flag === "--trusted-keys" && !trustedKeysPath) {
      trustedKeysPath = value;
    } else if (flag === "--checkpoint" && !checkpointPath) {
      checkpointPath = value;
    } else if (
      flag === "--checkpoint-trusted-keys" &&
      !checkpointTrustedKeysPath
    ) {
      checkpointTrustedKeysPath = value;
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
  return bundlePath && trustedKeysPath && checkpointPath &&
      checkpointTrustedKeysPath
    ? {
        bundlePath,
        trustedKeysPath,
        checkpointPath,
        checkpointTrustedKeysPath,
        verificationTime,
      }
    : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function parsePublicPem(value: unknown): KeyObject | null {
  if (
    typeof value !== "string" ||
    value.length > 16_384 ||
    !value.startsWith("-----BEGIN PUBLIC KEY-----") ||
    value.includes("PRIVATE KEY")
  ) return null;
  try {
    const key = createPublicKey(value);
    return key.type === "public" && key.asymmetricKeyType === "ed25519"
      ? key
      : null;
  } catch {
    return null;
  }
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== "string" || !CANONICAL_TIMESTAMP.test(value)) return false;
  try {
    return new Date(value).toISOString() === value;
  } catch {
    return false;
  }
}

function parseTrustedKeys(value: unknown): ApprovalLedgerTrustedKeys | null {
  if (!isRecord(value)) return null;
  let source: Record<string, unknown>;
  let dated = false;
  if (
    Object.keys(value).length === 2 &&
    value.version === 1 &&
    isRecord(value.keys)
  ) {
    source = value.keys;
    dated = true;
  } else {
    source = value;
  }

  const keys = new Map<string, KeyObject>();
  const datedKeys = new Map<
    string,
    {
      publicKey: KeyObject;
      validFrom: string;
      status: "active" | "retired" | "revoked";
      validUntil?: string;
      revokedAt?: string;
    }
  >();
  for (const [keyId, config] of Object.entries(source)) {
    if (!KEY_ID_PATTERN.test(keyId)) return null;
    if (!dated) {
      const key = parsePublicPem(config);
      if (!key) return null;
      keys.set(keyId, key);
      continue;
    }
    if (!isRecord(config)) return null;
    const names = Object.keys(config);
    const allowedNames = new Set([
      "publicKeyPem",
      "validFrom",
      "status",
      "validUntil",
      "revokedAt",
    ]);
    if (
      names.some((name) => !allowedNames.has(name)) ||
      !names.includes("publicKeyPem") ||
      !names.includes("validFrom") ||
      !names.includes("status")
    ) return null;
    const publicKey = parsePublicPem(config.publicKeyPem);
    if (
      !publicKey ||
      !isCanonicalTimestamp(config.validFrom) ||
      !["active", "retired", "revoked"].includes(String(config.status))
    ) return null;
    const record: {
      publicKey: KeyObject;
      validFrom: string;
      status: "active" | "retired" | "revoked";
      validUntil?: string;
      revokedAt?: string;
    } = {
      publicKey,
      validFrom: config.validFrom,
      status: config.status as "active" | "retired" | "revoked",
    };
    if (config.validUntil !== undefined) {
      if (!isCanonicalTimestamp(config.validUntil)) return null;
      record.validUntil = config.validUntil;
    }
    if (config.revokedAt !== undefined) {
      if (!isCanonicalTimestamp(config.revokedAt)) return null;
      record.revokedAt = config.revokedAt;
    }
    if (
      (record.status === "retired" && !record.validUntil) ||
      (record.status === "revoked" && !record.revokedAt) ||
      (record.status !== "revoked" && record.revokedAt) ||
      (record.validUntil &&
        Date.parse(record.validUntil) <= Date.parse(record.validFrom)) ||
      (record.revokedAt &&
        Date.parse(record.revokedAt) < Date.parse(record.validFrom))
    ) return null;
    datedKeys.set(keyId, record);
  }
  if (dated ? datedKeys.size === 0 : keys.size === 0) return null;
  return dated ? datedKeys : keys;
}

export function verifyApprovalLedgerBundleFiles(
  bundlePath: string,
  trustedKeysPath: string,
  checkpointPath: string,
  checkpointTrustedKeysPath: string,
  verificationTime = new Date(),
): CliResult {
  try {
    const bundleBytes = readFileSync(bundlePath);
    const trustBytes = readFileSync(trustedKeysPath);
    const checkpointBytes = readFileSync(checkpointPath);
    const checkpointTrustBytes = readFileSync(checkpointTrustedKeysPath);
    if (
      bundleBytes.length > MAX_BUNDLE_BYTES ||
      trustBytes.length > MAX_TRUST_STORE_BYTES ||
      checkpointBytes.length > 256 * 1024 ||
      checkpointTrustBytes.length > MAX_TRUST_STORE_BYTES
    ) {
      return { valid: false, code: "invalid_bundle" };
    }
    const bundle = JSON.parse(bundleBytes.toString("utf8")) as ApprovalLedgerBundleV1;
    const trustedKeys = parseTrustedKeys(
      JSON.parse(trustBytes.toString("utf8")) as unknown,
    );
    const checkpoint = JSON.parse(checkpointBytes.toString("utf8")) as unknown;
    const checkpointTrustedKeys = parseTrustedKeys(
      JSON.parse(checkpointTrustBytes.toString("utf8")) as unknown,
    );
    if (!trustedKeys || !checkpointTrustedKeys) {
      return { valid: false, code: "trusted_key_invalid" };
    }
    return verifyApprovalLedgerBundleWithCheckpointV1(
      bundle,
      trustedKeys,
      verificationTime,
      checkpoint,
      checkpointTrustedKeys,
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
      resolve(parsed.checkpointPath),
      resolve(parsed.checkpointTrustedKeysPath),
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
