import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  ApprovalLedgerError,
  APPROVAL_LEDGER_KEY_ID,
  loadApprovalLedgerSigningKeys,
} from "../lib/approval-ledger-keys";

export type ApprovalLedgerPublicKeyReport =
  | {
      status: "ok";
      keyId: string;
      publicKeyPem: string;
      spkiDerSha256: string;
      trustedKeys: Record<string, string>;
    }
  | {
      status: "no ok";
      code: "key_unavailable" | "key_invalid";
    };

export function buildApprovalLedgerPublicKeyReport(
  privateKeyPem?: string,
): ApprovalLedgerPublicKeyReport {
  try {
    const { publicKey } = loadApprovalLedgerSigningKeys(privateKeyPem);
    const spkiDer = publicKey.export({ type: "spki", format: "der" });
    const publicKeyPem = publicKey.export({
      type: "spki",
      format: "pem",
    }).toString();
    return {
      status: "ok",
      keyId: APPROVAL_LEDGER_KEY_ID,
      publicKeyPem,
      spkiDerSha256: createHash("sha256").update(spkiDer).digest("hex"),
      trustedKeys: { [APPROVAL_LEDGER_KEY_ID]: publicKeyPem },
    };
  } catch (error) {
    const code = error instanceof ApprovalLedgerError &&
        error.code === "key_unavailable"
      ? "key_unavailable"
      : "key_invalid";
    return { status: "no ok", code };
  }
}

function runCli(): void {
  const report = buildApprovalLedgerPublicKeyReport();
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.status !== "ok") process.exitCode = 1;
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  runCli();
}
