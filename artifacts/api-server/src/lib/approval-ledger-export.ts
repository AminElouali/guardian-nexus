import type {
  ApprovalLedgerBundleV1,
  SignedApprovalLedgerEventV1,
  SignedApprovalReceiptV1,
} from "./approval-ledger-crypto";

export type ApprovalLedgerBundleAssemblyCode =
  | "ok"
  | "receipt_missing"
  | "receipt_unexpected"
  | "receipt_duplicate"
  | "event_reference_mismatch";

export type ApprovalLedgerBundleAssemblyResult =
  | { ok: true; bundle: ApprovalLedgerBundleV1; code: "ok" }
  | { ok: false; code: Exclude<ApprovalLedgerBundleAssemblyCode, "ok"> };

/**
 * Attach the caller-held receipt archive to all workspace ledger events.
 * Receipts are deliberately not persisted by the server; cryptographic
 * verification remains the responsibility of the offline verifier.
 */
export function assembleApprovalLedgerBundleV1(
  events: readonly SignedApprovalLedgerEventV1[],
  receipts: readonly SignedApprovalReceiptV1[],
): ApprovalLedgerBundleAssemblyResult {
  const approvals = new Map<
    string,
    { workspaceId: string; approvalId: string; receiptSha256: string }
  >();
  const consumed = new Set<string>();

  for (const signedEvent of events) {
    const event = signedEvent?.event;
    const receiptId = event?.payload?.receiptId;
    const receiptSha256 = event?.payload?.receiptSha256;
    if (
      typeof receiptId !== "string" ||
      typeof receiptSha256 !== "string" ||
      (event.eventType !== "approval.approved" &&
        event.eventType !== "approval.receipt_consumed") ||
      event.workspaceId.length === 0 ||
      event.approvalId.length === 0
    ) {
      return { ok: false, code: "event_reference_mismatch" };
    }

    if (event.eventType === "approval.approved") {
      if (approvals.has(receiptId)) {
        return { ok: false, code: "event_reference_mismatch" };
      }
      approvals.set(receiptId, {
        workspaceId: event.workspaceId,
        approvalId: event.approvalId,
        receiptSha256,
      });
      continue;
    }

    const approval = approvals.get(receiptId);
    if (
      !approval ||
      approval.workspaceId !== event.workspaceId ||
      approval.approvalId !== event.approvalId ||
      approval.receiptSha256 !== receiptSha256 ||
      consumed.has(receiptId)
    ) {
      return { ok: false, code: "event_reference_mismatch" };
    }
    consumed.add(receiptId);
  }

  const receiptsById = new Map<string, SignedApprovalReceiptV1>();
  for (const receipt of receipts) {
    const receiptId = receipt?.payload?.receiptId;
    if (typeof receiptId !== "string") {
      return { ok: false, code: "receipt_unexpected" };
    }
    if (receiptsById.has(receiptId)) {
      return { ok: false, code: "receipt_duplicate" };
    }
    receiptsById.set(receiptId, receipt);
  }

  if (receiptsById.size < approvals.size) {
    return { ok: false, code: "receipt_missing" };
  }
  if (receiptsById.size > approvals.size) {
    return { ok: false, code: "receipt_unexpected" };
  }
  for (const [receiptId, approval] of approvals) {
    const receipt = receiptsById.get(receiptId);
    if (!receipt) return { ok: false, code: "receipt_missing" };
    if (
      receipt.payloadSha256 !== approval.receiptSha256 ||
      receipt.payload.workspaceId !== approval.workspaceId ||
      receipt.payload.approvalId !== approval.approvalId
    ) {
      return { ok: false, code: "event_reference_mismatch" };
    }
  }
  const orderedReceipts = [...approvals.keys()].map(
    (receiptId) => receiptsById.get(receiptId)!,
  );

  return {
    ok: true,
    code: "ok",
    bundle: { version: 1, events: [...events], receipts: orderedReceipts },
  };
}
