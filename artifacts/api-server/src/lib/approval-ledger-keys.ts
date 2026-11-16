import {
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";

export const APPROVAL_LEDGER_KEY_ID = "guardian-nexus-approval-ledger-v1";

export type ApprovalLedgerErrorCode =
  | "key_unavailable"
  | "key_invalid"
  | "receipt_invalid"
  | "receipt_expired"
  | "receipt_already_consumed"
  | "approval_event_missing"
  | "approval_event_invalid"
  | "receipt_reference_mismatch"
  | "ledger_insert_failed";

export class ApprovalLedgerError extends Error {
  constructor(readonly code: ApprovalLedgerErrorCode) {
    super(`approval_ledger_${code}`);
    this.name = "ApprovalLedgerError";
  }
}

export type ApprovalLedgerSigningKeys = {
  privateKey: KeyObject;
  publicKey: KeyObject;
};

export function loadApprovalLedgerSigningKeys(
  pem = process.env.APPROVAL_LEDGER_ED25519_PRIVATE_KEY,
): ApprovalLedgerSigningKeys {
  if (!pem) throw new ApprovalLedgerError("key_unavailable");
  try {
    const privateKey = createPrivateKey(pem);
    if (privateKey.asymmetricKeyType !== "ed25519") {
      throw new ApprovalLedgerError("key_invalid");
    }
    return { privateKey, publicKey: createPublicKey(privateKey) };
  } catch {
    throw new ApprovalLedgerError("key_invalid");
  }
}
