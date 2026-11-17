import { z } from "zod";
import type {
  SignedApprovalLedgerEventV1,
  SignedApprovalReceiptV1,
} from "@workspace/api-client-react";

export const MAX_APPROVAL_RECEIPT_JSON_BYTES = 16 * 1024;

const canonicalTimestampPattern =
  /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

const canonicalTimestamp = z
  .string()
  .regex(canonicalTimestampPattern)
  .refine((value) => {
    const timestamp = Date.parse(value);
    return Number.isFinite(timestamp) && new Date(timestamp).toISOString() === value;
  });

const receiptPayloadSchema = z
  .object({
    version: z.literal(1),
    keyId: z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/),
    receiptId: z.uuid(),
    workspaceId: z.uuid(),
    approvalId: z.uuid(),
    proposalBindingSha256: z.string().regex(/^[a-f0-9]{64}$/),
    actionSha256: z.string().regex(/^[a-f0-9]{64}$/),
    requestedBy: z.string().min(1),
    approvedBy: z.string().min(1),
    approvedByRole: z.enum(["owner", "admin"]),
    issuedAt: canonicalTimestamp,
    expiresAt: canonicalTimestamp,
    nonce: z.string().min(32).max(128).regex(/^[A-Za-z0-9_-]+$/),
  })
  .strict()
  .refine((payload) => payload.requestedBy !== payload.approvedBy)
  .refine((payload) => Date.parse(payload.issuedAt) < Date.parse(payload.expiresAt));

const signedReceiptSchema = z
  .object({
    payload: receiptPayloadSchema,
    payloadSha256: z.string().regex(/^[a-f0-9]{64}$/),
    signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
  })
  .strict();

export type SavedReceiptImportFailure =
  | "too_large"
  | "invalid_json"
  | "not_receipt"
  | "extra_fields"
  | "invalid_receipt"
  | "duplicate"
  | "no_matching_event"
  | "event_mismatch";

export type SavedReceiptImportResult =
  | {
      ok: true;
      approvalId: string;
      receipt: SignedApprovalReceiptV1;
    }
  | {
      ok: false;
      failure: SavedReceiptImportFailure;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasUnexpectedKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
): boolean {
  return Object.keys(record).some((key) => !allowedKeys.includes(key));
}

export function importSavedApprovalReceipt(
  jsonText: string,
  events: SignedApprovalLedgerEventV1[],
  existingReceipts: Array<{
    approvalId: string;
    receipt: SignedApprovalReceiptV1;
  }>,
): SavedReceiptImportResult {
  if (new TextEncoder().encode(jsonText).byteLength > MAX_APPROVAL_RECEIPT_JSON_BYTES) {
    return { ok: false, failure: "too_large" };
  }

  let candidate: unknown;
  try {
    candidate = JSON.parse(jsonText);
  } catch {
    return { ok: false, failure: "invalid_json" };
  }

  if (!isRecord(candidate) || !isRecord(candidate.payload)) {
    return { ok: false, failure: "not_receipt" };
  }
  if (
    hasUnexpectedKeys(candidate, ["payload", "payloadSha256", "signature"]) ||
    hasUnexpectedKeys(candidate.payload, [
      "version",
      "keyId",
      "receiptId",
      "workspaceId",
      "approvalId",
      "proposalBindingSha256",
      "actionSha256",
      "requestedBy",
      "approvedBy",
      "approvedByRole",
      "issuedAt",
      "expiresAt",
      "nonce",
    ])
  ) {
    return { ok: false, failure: "extra_fields" };
  }

  const parsed = signedReceiptSchema.safeParse(candidate);
  if (!parsed.success) {
    return { ok: false, failure: "invalid_receipt" };
  }
  const receipt = parsed.data as SignedApprovalReceiptV1;
  const payload = receipt.payload;

  if (
    existingReceipts.some(
      ({ approvalId, receipt: existing }) =>
        approvalId === payload.approvalId ||
        existing.payload.receiptId === payload.receiptId,
    )
  ) {
    return { ok: false, failure: "duplicate" };
  }

  const matchingEvents = events.filter(
    (signedEvent) =>
      signedEvent.event.eventType === "approval.approved" &&
      signedEvent.event.payload.receiptId === payload.receiptId,
  );
  if (matchingEvents.length === 0) {
    return { ok: false, failure: "no_matching_event" };
  }
  if (matchingEvents.length !== 1) {
    return { ok: false, failure: "event_mismatch" };
  }

  const event = matchingEvents[0]!.event;
  if (
    event.workspaceId !== payload.workspaceId ||
    event.approvalId !== payload.approvalId ||
    event.payload.receiptSha256 !== receipt.payloadSha256
  ) {
    return { ok: false, failure: "event_mismatch" };
  }

  return { ok: true, approvalId: payload.approvalId, receipt };
}

export function savedReceiptImportFailureMessage(
  failure: SavedReceiptImportFailure,
): string {
  switch (failure) {
    case "too_large":
      return "El recibo supera el límite de 16 KiB.";
    case "invalid_json":
      return "El contenido no es JSON válido.";
    case "not_receipt":
      return "El JSON no contiene un recibo firmado v1.";
    case "extra_fields":
      return "El recibo contiene campos no permitidos.";
    case "invalid_receipt":
      return "Los campos del recibo no cumplen el formato v1.";
    case "duplicate":
      return "Este recibo ya está cargado en esta sesión.";
    case "no_matching_event":
      return "El recibo no corresponde a ningún evento aprobado de este espacio.";
    case "event_mismatch":
      return "El recibo no coincide con el evento del registro; no se añadió.";
  }
}
