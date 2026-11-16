import {
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import {
  lstatSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  signApprovalLedgerCheckpointV1,
  type ApprovalLedgerCheckpointV1,
} from "../lib/approval-ledger-crypto";

const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;
const HASH_PATTERN = /^[a-f0-9]{64}$/;
const CANONICAL_TIMESTAMP =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

type Options = {
  workspaceId: string;
  sequence: number;
  headHash: string;
  issuedAt: string;
  keyId: string;
  privateKeyPath: string;
  outputPath: string;
};

function parseArguments(args: readonly string[]): Options | null {
  const values = new Map<string, string>();
  const supported = new Set([
    "--workspace-id",
    "--sequence",
    "--head-event-sha256",
    "--issued-at",
    "--key-id",
    "--private-key",
    "--out",
  ]);
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (
      !supported.has(flag ?? "") ||
      !value ||
      value.startsWith("--") ||
      values.has(flag!)
    ) return null;
    values.set(flag!, value);
  }
  const workspaceId = values.get("--workspace-id");
  const sequenceValue = values.get("--sequence");
  const headHash = values.get("--head-event-sha256");
  const issuedAt = values.get("--issued-at");
  const keyId = values.get("--key-id");
  const privateKeyPath = values.get("--private-key");
  const outputPath = values.get("--out");
  if (
    !workspaceId ||
    !sequenceValue ||
    !headHash ||
    !issuedAt ||
    !keyId ||
    !privateKeyPath ||
    !outputPath ||
    !/^[1-9]\d*$/.test(sequenceValue) ||
    !HASH_PATTERN.test(headHash) ||
    !CANONICAL_TIMESTAMP.test(issuedAt) ||
    !KEY_ID_PATTERN.test(keyId)
  ) return null;
  const sequence = Number(sequenceValue);
  if (!Number.isSafeInteger(sequence)) return null;
  try {
    if (new Date(issuedAt).toISOString() !== issuedAt) return null;
  } catch {
    return null;
  }
  return {
    workspaceId,
    sequence,
    headHash,
    issuedAt,
    keyId,
    privateKeyPath,
    outputPath,
  };
}

function readSigningKey(path: string): KeyObject | null {
  try {
    const resolved = resolve(path);
    const metadata = lstatSync(resolved);
    if (
      !metadata.isFile() ||
      metadata.isSymbolicLink() ||
      (metadata.mode & 0o077) !== 0 ||
      metadata.size > 16_384
    ) return null;
    const key = createPrivateKey(readFileSync(resolved));
    return key.asymmetricKeyType === "ed25519" && key.type === "private"
      ? key
      : null;
  } catch {
    return null;
  }
}

export function createApprovalLedgerCheckpointFile(
  options: Options,
): boolean {
  const privateKey = readSigningKey(options.privateKeyPath);
  if (!privateKey) return false;
  const checkpoint: ApprovalLedgerCheckpointV1 = {
    version: 1,
    keyId: options.keyId,
    workspaceId: options.workspaceId,
    sequence: options.sequence,
    headEventSha256: options.headHash,
    issuedAt: options.issuedAt,
  };
  try {
    const signed = signApprovalLedgerCheckpointV1(checkpoint, privateKey);
    writeFileSync(
      resolve(options.outputPath),
      `${JSON.stringify(signed)}\n`,
      { encoding: "utf8", flag: "wx", mode: 0o600 },
    );
    return true;
  } catch {
    return false;
  }
}

function runCli(): void {
  const options = parseArguments(process.argv.slice(2));
  const written = options ? createApprovalLedgerCheckpointFile(options) : false;
  process.stdout.write(
    `${JSON.stringify({ created: written, code: written ? "ok" : "checkpoint_generation_failed" })}\n`,
  );
  if (!written) process.exitCode = 1;
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  runCli();
}
