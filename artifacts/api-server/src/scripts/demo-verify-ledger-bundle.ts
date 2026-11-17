import { generateKeyPairSync } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const DEMO_CHECKPOINT_KEY_ID = "guardian-demo-checkpoint-v1";
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(scriptDirectory, "../..");
const verifierPath = resolve(scriptDirectory, "verify-approval-ledger-bundle.ts");
const checkpointGeneratorPath = resolve(
  scriptDirectory,
  "create-approval-ledger-checkpoint.ts",
);

type VerificationResult = { valid: boolean; code: string };

function parseArguments(args: readonly string[]): {
  bundlePath: string;
  trustedKeysPath: string;
} | null {
  const values = new Map<string, string>();
  const normalized = args[0] === "--" ? args.slice(1) : args;
  if (normalized.length !== 4) return null;
  for (let index = 0; index < normalized.length; index += 2) {
    const flag = normalized[index];
    const value = normalized[index + 1];
    if (
      (flag !== "--bundle" && flag !== "--trusted-keys") ||
      !value ||
      value.startsWith("--") ||
      values.has(flag)
    ) return null;
    values.set(flag, value);
  }
  const bundlePath = values.get("--bundle");
  const trustedKeysPath = values.get("--trusted-keys");
  return bundlePath && trustedKeysPath ? { bundlePath, trustedKeysPath } : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}

function childEnvironment(home: string): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH ?? "",
    HOME: home,
    LANG: "C",
    LC_ALL: "C",
  };
}

function readChildResult(result: ReturnType<typeof spawnSync>): VerificationResult {
  try {
    const parsed = JSON.parse(result.stdout.toString("utf8")) as unknown;
    if (
      isRecord(parsed) &&
      typeof parsed.valid === "boolean" &&
      typeof parsed.code === "string"
    ) {
      return { valid: parsed.valid, code: parsed.code };
    }
  } catch {
    // Return only a fixed diagnostic; never forward a child's stderr.
  }
  return { valid: false, code: "invalid_bundle" };
}

function runVerifier(
  bundlePath: string,
  trustedKeysPath: string,
  checkpointPath: string,
  checkpointTrustedKeysPath: string,
  home: string,
  verificationTime: string,
): VerificationResult {
  const result = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      verifierPath,
      "--bundle",
      bundlePath,
      "--trusted-keys",
      trustedKeysPath,
      "--checkpoint",
      checkpointPath,
      "--checkpoint-trusted-keys",
      checkpointTrustedKeysPath,
      "--at",
      verificationTime,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment(home),
      maxBuffer: 1024 * 1024,
    },
  );
  if (result.error) return { valid: false, code: "invalid_bundle" };
  return readChildResult(result);
}

function createDemoCheckpoint(
  head: { workspaceId: string; sequence: number; eventSha256: string },
  issuedAt: string,
  directory: string,
): {
  checkpointPath: string;
  checkpointTrustedKeysPath: string;
  verificationTime: string;
} | null {
  const keyPair = generateKeyPairSync("ed25519");
  const privateKeyPath = resolve(directory, "demo-checkpoint-private.pem");
  const checkpointPath = resolve(directory, "demo-checkpoint.json");
  const checkpointTrustedKeysPath = resolve(
    directory,
    "demo-checkpoint-trusted-keys.json",
  );
  writeFileSync(
    privateKeyPath,
    keyPair.privateKey.export({ format: "pem", type: "pkcs8" }),
    { mode: 0o600, flag: "wx" },
  );
  const publicKeyPem = keyPair.publicKey.export({
    format: "pem",
    type: "spki",
  }).toString();
  writeFileSync(
    checkpointTrustedKeysPath,
    JSON.stringify({ [DEMO_CHECKPOINT_KEY_ID]: publicKeyPem }),
    { mode: 0o600, flag: "wx" },
  );

  const result = spawnSync(
    process.execPath,
    [
      "--import",
      "tsx",
      checkpointGeneratorPath,
      "--workspace-id",
      head.workspaceId,
      "--sequence",
      String(head.sequence),
      "--head-event-sha256",
      head.eventSha256,
      "--issued-at",
      issuedAt,
      "--key-id",
      DEMO_CHECKPOINT_KEY_ID,
      "--private-key",
      privateKeyPath,
      "--out",
      checkpointPath,
    ],
    {
      cwd: packageRoot,
      encoding: "utf8",
      env: childEnvironment(directory),
      maxBuffer: 1024 * 1024,
    },
  );
  if (result.error) return null;
  try {
    const generated = JSON.parse(result.stdout) as unknown;
    return isRecord(generated) &&
        generated.created === true &&
        generated.code === "ok"
      ? { checkpointPath, checkpointTrustedKeysPath, verificationTime: issuedAt }
      : null;
  } catch {
    return null;
  }
}

function writeBundleCopy(directory: string, name: string, bundle: unknown): string {
  const path = resolve(directory, `${name}.json`);
  writeFileSync(path, JSON.stringify(bundle), { mode: 0o600, flag: "wx" });
  return path;
}

function printRow(label: string, result: VerificationResult, expected?: string): boolean {
  const status = result.valid ? "ACEPTADO" : "RECHAZADO";
  console.log(`| ${label} | ${status} | ${result.code} |`);
  return expected === undefined || result.code === expected;
}

function runDemo(): void {
  const parsed = parseArguments(process.argv.slice(2));
  if (!parsed) {
    console.log("Uso: demo:verify-ledger-bundle --bundle <bundle.json> --trusted-keys <trusted-keys.json>");
    process.exitCode = 2;
    return;
  }

  let directory: string | undefined;
  try {
    const bundleBytes = readFileSync(resolve(parsed.bundlePath));
    if (bundleBytes.length > MAX_BUNDLE_BYTES) {
      console.log("Demostración detenida: bundle inválido o demasiado grande.");
      process.exitCode = 1;
      return;
    }
    const bundle = JSON.parse(bundleBytes.toString("utf8")) as unknown;
    if (
      !isRecord(bundle) ||
      bundle.version !== 1 ||
      !Array.isArray(bundle.events) ||
      bundle.events.length === 0 ||
      !Array.isArray(bundle.receipts)
    ) {
      console.log("Demostración detenida: bundle inválido.");
      process.exitCode = 1;
      return;
    }
    const last = bundle.events.at(-1);
    if (
      !isRecord(last) ||
      !isRecord(last.event) ||
      typeof last.event.workspaceId !== "string" ||
      !Number.isSafeInteger(last.event.sequence) ||
      (last.event.sequence as number) < 1 ||
      typeof last.eventSha256 !== "string" ||
      typeof last.event.occurredAt !== "string"
    ) {
      console.log("Demostración detenida: cabeza del bundle inválida.");
      process.exitCode = 1;
      return;
    }
    const headTime = Date.parse(last.event.occurredAt);
    if (
      !Number.isFinite(headTime) ||
      new Date(headTime).toISOString() !== last.event.occurredAt
    ) {
      console.log("Demostración detenida: tiempo de cabeza inválido.");
      process.exitCode = 1;
      return;
    }
    const verificationTime = new Date(headTime + 1).toISOString();

    directory = mkdtempSync(resolve(tmpdir(), "guardian-ledger-demo-"));
    chmodSync(directory, 0o700);
    const checkpointFiles = createDemoCheckpoint({
      workspaceId: last.event.workspaceId,
      sequence: last.event.sequence as number,
      eventSha256: last.eventSha256,
    }, verificationTime, directory);
    if (!checkpointFiles) {
      console.log("Demostración detenida: no se pudo crear el checkpoint DEMO.");
      process.exitCode = 1;
      return;
    }

    const bundlePath = resolve(parsed.bundlePath);
    const trustedKeysPath = resolve(parsed.trustedKeysPath);
    console.log("Checkpoint: DEMO, autoanclado con una clave efímera local.");
    console.log("No prueba que el bundle sea el más reciente.");
    console.log("No sustituye un checkpoint distribuido por un canal externo confiable.");
    console.log("| Prueba | Resultado | Código |");
    console.log("|---|---|---|");

    const original = runVerifier(
      bundlePath,
      trustedKeysPath,
      checkpointFiles.checkpointPath,
      checkpointFiles.checkpointTrustedKeysPath,
      directory,
      checkpointFiles.verificationTime,
    );
    let allExpected = printRow("Bundle recibido", original, "ok");

    const withoutLastEvent = structuredClone(bundle) as {
      events: unknown[];
      [key: string]: unknown;
    };
    withoutLastEvent.events.pop();
    const truncatedPath = writeBundleCopy(
      directory,
      "without-last-event",
      withoutLastEvent,
    );
    allExpected =
      printRow(
        "Eliminar último evento",
        runVerifier(
          truncatedPath,
          trustedKeysPath,
          checkpointFiles.checkpointPath,
          checkpointFiles.checkpointTrustedKeysPath,
          directory,
          checkpointFiles.verificationTime,
        ),
        "checkpoint_head_mismatch",
      ) && allExpected;

    const alteredEvent = structuredClone(bundle) as {
      events: Array<{ event: Record<string, unknown> }>;
      [key: string]: unknown;
    };
    const event = alteredEvent.events[0]?.event;
    if (!event || typeof event.approvalId !== "string") {
      console.log("| Alterar contenido del evento | NO EJECUTADO | fixture_invalid |");
      allExpected = false;
    } else {
      event.approvalId =
        `${event.approvalId[0] === "a" ? "b" : "a"}${event.approvalId.slice(1)}`;
      const alteredEventPath = writeBundleCopy(
        directory,
        "altered-event",
        alteredEvent,
      );
      allExpected =
        printRow(
          "Alterar contenido del evento",
          runVerifier(
            alteredEventPath,
            trustedKeysPath,
            checkpointFiles.checkpointPath,
            checkpointFiles.checkpointTrustedKeysPath,
            directory,
            checkpointFiles.verificationTime,
          ),
          "event_hash_mismatch",
        ) && allExpected;
    }

    const withoutReceipt = structuredClone(bundle) as {
      receipts: unknown[];
      [key: string]: unknown;
    };
    if (withoutReceipt.receipts.length === 0) {
      console.log("| Quitar recibo | NO EJECUTADO | fixture_invalid |");
      allExpected = false;
    } else {
      withoutReceipt.receipts.pop();
      const withoutReceiptPath = writeBundleCopy(
        directory,
        "without-receipt",
        withoutReceipt,
      );
      allExpected =
        printRow(
          "Quitar recibo",
          runVerifier(
            withoutReceiptPath,
            trustedKeysPath,
            checkpointFiles.checkpointPath,
            checkpointFiles.checkpointTrustedKeysPath,
            directory,
            checkpointFiles.verificationTime,
          ),
          "receipt_reference_mismatch",
        ) && allExpected;
    }

    if (!allExpected) process.exitCode = 1;
  } catch {
    console.log("Demostración fallida: error local saneado.");
    process.exitCode = 1;
  } finally {
    if (directory) rmSync(directory, { recursive: true, force: true });
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  runDemo();
}
