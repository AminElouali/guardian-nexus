import { randomBytes, randomUUID } from "node:crypto";
import { and, desc, eq, gt, isNull, sql } from "drizzle-orm";
import {
  aiAssessmentApprovalRequestsTable,
  workspaceApprovalLedgerTable,
} from "@workspace/db";
import type { TenantTransaction } from "./tenant-db";
import {
  APPROVAL_LEDGER_KEY_ID,
  ApprovalLedgerError,
  loadApprovalLedgerSigningKeys,
} from "./approval-ledger-keys";
import {
  canonicalizeLedgerValue,
  signApprovalLedgerEventV1,
  signApprovalReceiptV1,
  verifyApprovalReceiptV1,
  type ApprovalLedgerEventV1,
  type ApprovalReceiptV1Expectation,
  type SignedApprovalLedgerEventV1,
  type SignedApprovalReceiptV1,
} from "./approval-ledger-crypto";

export const APPROVAL_LEDGER_RECEIPT_TTL_MS = 5 * 60 * 1_000;
const WORKSPACE_LOCK_NAMESPACE = 0x474e4150;

type LedgerRow = typeof workspaceApprovalLedgerTable.$inferInsert;
type ApprovedRequestUpdate = Pick<
  typeof aiAssessmentApprovalRequestsTable.$inferInsert,
  | "status"
  | "decidedByUserId"
  | "decidedByRole"
  | "decidedAt"
  | "simulatedAt"
  | "simulationResultCode"
  | "simulationResultSha256"
  | "replayBindingSha256"
  | "updatedAt"
>;

export type ApprovalLedgerInsert = (
  tx: TenantTransaction,
  row: LedgerRow,
) => Promise<void>;

async function acquireWorkspaceLedgerLock(
  tx: TenantTransaction,
  workspaceId: string,
): Promise<{ sequence: number; previousEventSha256: string }> {
  await tx.execute(
    sql`SELECT pg_advisory_xact_lock(${WORKSPACE_LOCK_NAMESPACE}, hashtext(${workspaceId}))`,
  );
  const [head] = await tx
    .select({
      sequence: workspaceApprovalLedgerTable.sequence,
      eventHash: workspaceApprovalLedgerTable.eventHash,
    })
    .from(workspaceApprovalLedgerTable)
    .where(eq(workspaceApprovalLedgerTable.workspaceId, workspaceId))
    .orderBy(desc(workspaceApprovalLedgerTable.sequence))
    .limit(1);
  return {
    sequence: (head?.sequence ?? 0) + 1,
    previousEventSha256: head?.eventHash ?? "",
  };
}

async function insertLedgerRow(
  tx: TenantTransaction,
  row: LedgerRow,
): Promise<void> {
  await tx.insert(workspaceApprovalLedgerTable).values(row);
}

function ledgerRowFromSignedEvent(
  event: SignedApprovalLedgerEventV1,
): LedgerRow {
  return {
    workspaceId: event.event.workspaceId,
    sequence: event.event.sequence,
    eventType: event.event.eventType,
    approvalId: event.event.approvalId,
    receiptId: event.event.payload.receiptId,
    payloadCanonical: canonicalizeLedgerValue(event.event),
    previousHash: event.event.previousEventSha256,
    eventHash: event.eventSha256,
    keyId: event.event.keyId,
    signature: event.signature,
    createdAt: new Date(event.event.occurredAt),
  };
}

export async function updateApprovedRequestAndAppendReceipt(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    approvalId: string;
    expectedBindingSha256: string;
    now: Date;
    actorUserId: string;
    actorRole: "owner" | "admin";
    update: ApprovedRequestUpdate;
    approval: {
      actionSha256: string | null;
      requestedByUserId: string;
    };
  },
  insertRow: ApprovalLedgerInsert = insertLedgerRow,
): Promise<
  | { approval: typeof aiAssessmentApprovalRequestsTable.$inferSelect; receipt: SignedApprovalReceiptV1 }
  | null
> {
  const [updated] = await tx
    .update(aiAssessmentApprovalRequestsTable)
    .set(input.update)
    .where(
      and(
        eq(aiAssessmentApprovalRequestsTable.id, input.approvalId),
        eq(aiAssessmentApprovalRequestsTable.workspaceId, input.workspaceId),
        eq(aiAssessmentApprovalRequestsTable.status, "pending"),
        eq(
          aiAssessmentApprovalRequestsTable.proposalBindingSha256,
          input.expectedBindingSha256,
        ),
        gt(aiAssessmentApprovalRequestsTable.expiresAt, input.now),
        isNull(aiAssessmentApprovalRequestsTable.simulatedAt),
      ),
    )
    .returning();
  if (!updated) return null;

  // Key loading and all cryptographic/storage work happen after the conditional
  // update. Any failure throws inside the caller's transaction and rolls it back.
  const { privateKey } = loadApprovalLedgerSigningKeys();
  const head = await acquireWorkspaceLedgerLock(tx, input.workspaceId);
  const receiptIssuedAt = new Date();
  const issuedAt = receiptIssuedAt.toISOString();
  const receipt = signApprovalReceiptV1(
    {
      version: 1,
      keyId: APPROVAL_LEDGER_KEY_ID,
      receiptId: randomUUID(),
      workspaceId: input.workspaceId,
      approvalId: input.approvalId,
      proposalBindingSha256: input.expectedBindingSha256,
      actionSha256: input.approval.actionSha256 ?? "",
      requestedBy: input.approval.requestedByUserId,
      approvedBy: input.actorUserId,
      approvedByRole: input.actorRole,
      issuedAt,
      expiresAt: new Date(
        receiptIssuedAt.getTime() + APPROVAL_LEDGER_RECEIPT_TTL_MS,
      ).toISOString(),
      nonce: randomBytes(32).toString("base64url"),
    },
    privateKey,
  );
  const event: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: APPROVAL_LEDGER_KEY_ID,
    workspaceId: input.workspaceId,
    sequence: head.sequence,
    eventId: randomUUID(),
    eventType: "approval.approved",
    approvalId: input.approvalId,
    previousEventSha256: head.previousEventSha256,
    occurredAt: issuedAt,
    payload: {
      receiptId: receipt.payload.receiptId,
      receiptSha256: receipt.payloadSha256,
    },
  };
  await insertRow(tx, ledgerRowFromSignedEvent(
    signApprovalLedgerEventV1(event, privateKey),
  ));
  return { approval: updated, receipt };
}

function parseStoredApprovedEvent(row: {
  workspaceId: string;
  sequence: number;
  eventType: string;
  approvalId: string;
  receiptId: string;
  payloadCanonical: string;
  previousHash: string;
  eventHash: string;
  keyId: string;
  signature: string;
}): SignedApprovalLedgerEventV1 | null {
  try {
    const event: unknown = JSON.parse(row.payloadCanonical);
    if (!event || typeof event !== "object" || Array.isArray(event)) return null;
    const record = event as Record<string, unknown>;
    if (
      record.workspaceId !== row.workspaceId ||
      record.sequence !== row.sequence ||
      record.eventType !== row.eventType ||
      record.approvalId !== row.approvalId ||
      record.previousEventSha256 !== row.previousHash ||
      record.keyId !== row.keyId ||
      !record.payload ||
      typeof record.payload !== "object" ||
      Array.isArray(record.payload) ||
      (record.payload as Record<string, unknown>).receiptId !== row.receiptId
    ) {
      return null;
    }
    return {
      event: record as unknown as ApprovalLedgerEventV1,
      eventSha256: row.eventHash,
      signature: row.signature,
    };
  } catch {
    return null;
  }
}

export async function consumeApprovalReceipt(
  tx: TenantTransaction,
  input: {
    workspaceId: string;
    approvalId: string;
    receipt: unknown;
    expected: ApprovalReceiptV1Expectation;
  },
): Promise<{ receiptId: string; consumedEventSha256: string } | null> {
  const { privateKey, publicKey } = loadApprovalLedgerSigningKeys();
  const trustedKeys = new Map([[APPROVAL_LEDGER_KEY_ID, publicKey]]);
  const preliminary = verifyApprovalReceiptV1(
    input.receipt,
    trustedKeys,
    input.expected,
    new Date(),
  );
  if (!preliminary.valid) {
    if (preliminary.code === "receipt_expired") {
      throw new ApprovalLedgerError("receipt_expired");
    }
    if (preliminary.code === "unknown_key") {
      throw new ApprovalLedgerError("key_invalid");
    }
    throw new ApprovalLedgerError("receipt_invalid");
  }
  const receipt = input.receipt as SignedApprovalReceiptV1;
  const head = await acquireWorkspaceLedgerLock(tx, input.workspaceId);
  const [approvedRow] = await tx
    .select()
    .from(workspaceApprovalLedgerTable)
    .where(
      and(
        eq(workspaceApprovalLedgerTable.workspaceId, input.workspaceId),
        eq(workspaceApprovalLedgerTable.approvalId, input.approvalId),
        eq(workspaceApprovalLedgerTable.receiptId, receipt.payload.receiptId),
        eq(workspaceApprovalLedgerTable.eventType, "approval.approved"),
      ),
    )
    .limit(1);
  if (!approvedRow) throw new ApprovalLedgerError("approval_event_missing");
  const approvedEvent = parseStoredApprovedEvent(approvedRow);
  if (!approvedEvent) throw new ApprovalLedgerError("approval_event_invalid");
  const verified = verifyApprovalReceiptV1(
    receipt,
    trustedKeys,
    input.expected,
    new Date(),
    approvedEvent,
  );
  if (!verified.valid) {
    if (verified.code === "receipt_expired") {
      throw new ApprovalLedgerError("receipt_expired");
    }
    if (verified.code === "unknown_key") {
      throw new ApprovalLedgerError("key_invalid");
    }
    throw new ApprovalLedgerError("receipt_reference_mismatch");
  }

  const [consumed] = await tx
    .select({ sequence: workspaceApprovalLedgerTable.sequence })
    .from(workspaceApprovalLedgerTable)
    .where(
      and(
        eq(workspaceApprovalLedgerTable.workspaceId, input.workspaceId),
        eq(workspaceApprovalLedgerTable.receiptId, receipt.payload.receiptId),
        eq(
          workspaceApprovalLedgerTable.eventType,
          "approval.receipt_consumed",
        ),
      ),
    )
    .limit(1);
  if (consumed) throw new ApprovalLedgerError("receipt_already_consumed");

  const consumedAt = new Date().toISOString();
  const event: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: APPROVAL_LEDGER_KEY_ID,
    workspaceId: input.workspaceId,
    sequence: head.sequence,
    eventId: randomUUID(),
    eventType: "approval.receipt_consumed",
    approvalId: input.approvalId,
    previousEventSha256: head.previousEventSha256,
    occurredAt: consumedAt,
    payload: {
      receiptId: receipt.payload.receiptId,
      receiptSha256: receipt.payloadSha256,
      nonce: receipt.payload.nonce,
      consumedAt,
    },
  };
  const signedEvent = signApprovalLedgerEventV1(event, privateKey);
  try {
    await insertLedgerRow(tx, ledgerRowFromSignedEvent(signedEvent));
  } catch (error) {
    if (
      error &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "23505"
    ) {
      throw new ApprovalLedgerError("receipt_already_consumed");
    }
    throw new ApprovalLedgerError("ledger_insert_failed");
  }
  return {
    receiptId: receipt.payload.receiptId,
    consumedEventSha256: signedEvent.eventSha256,
  };
}
