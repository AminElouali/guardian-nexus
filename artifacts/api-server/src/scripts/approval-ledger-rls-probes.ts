import assert from "node:assert/strict";
import {
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from "node:crypto";
import type { Pool, PoolClient } from "pg";
import {
  canonicalizeLedgerValue,
  signApprovalLedgerEventV1,
  type ApprovalLedgerEventV1,
} from "../lib/approval-ledger-crypto";

const TEST_DIGEST = "a".repeat(64);
const TEST_KEY_ID = "local-ledger-probe";
const SAFE_PROBE_FAILURE_CODES = new Set([
  "approval_ledger_probe_fixture_seed_failed",
  "approval_ledger_probe_other_workspace_seed_failed",
  "approval_ledger_probe_runtime_setup_failed",
  "approval_ledger_probe_owner_approval_insert_failed",
  "approval_ledger_probe_owner_receipt_consumed_insert_failed",
  "approval_ledger_probe_owner_select_failed",
  "approval_ledger_probe_cross_tenant_read_failed",
  "approval_ledger_probe_cross_tenant_insert_failed",
  "approval_ledger_probe_duplicate_sequence_failed",
  "approval_ledger_probe_duplicate_consumption_failed",
  "approval_ledger_probe_admin_insert_failed",
  "approval_ledger_probe_update_denied_failed",
  "approval_ledger_probe_delete_denied_failed",
  "approval_ledger_probe_truncate_denied_failed",
  "approval_ledger_probe_viewer_insert_failed",
  "approval_ledger_probe_workspace_delete_protected_failed",
  "approval_ledger_probe_count_failed",
  "approval_ledger_probe_failed",
]);

type LedgerRow = {
  workspaceId: string;
  sequence: number;
  eventType: ApprovalLedgerEventV1["eventType"];
  approvalId: string;
  receiptId: string;
  payloadCanonical: string;
  previousHash: string;
  eventHash: string;
  keyId: string;
  signature: string;
  createdAt: string;
};

function makeLedgerRow(input: {
  workspaceId: string;
  sequence: number;
  eventType: ApprovalLedgerEventV1["eventType"];
  approvalId: string;
  receiptId: string;
  previousHash: string;
  keyPair: { privateKey: KeyObject };
}): LedgerRow {
  const occurredAt = new Date().toISOString();
  const event: ApprovalLedgerEventV1 = {
    version: 1,
    keyId: TEST_KEY_ID,
    workspaceId: input.workspaceId,
    sequence: input.sequence,
    eventId: randomUUID(),
    eventType: input.eventType,
    approvalId: input.approvalId,
    previousEventSha256: input.previousHash,
    occurredAt,
    payload: input.eventType === "approval.approved"
      ? {
          receiptId: input.receiptId,
          receiptSha256: TEST_DIGEST,
        }
      : {
          receiptId: input.receiptId,
          receiptSha256: TEST_DIGEST,
          nonce: randomUUID().replaceAll("-", ""),
          consumedAt: occurredAt,
        },
  };
  const signed = signApprovalLedgerEventV1(
    event,
    input.keyPair.privateKey,
  );
  return {
    workspaceId: event.workspaceId,
    sequence: event.sequence,
    eventType: event.eventType,
    approvalId: event.approvalId,
    receiptId: input.receiptId,
    payloadCanonical: canonicalizeLedgerValue(event),
    previousHash: event.previousEventSha256,
    eventHash: signed.eventSha256,
    keyId: event.keyId,
    signature: signed.signature,
    createdAt: event.occurredAt,
  };
}

async function insertLedgerRow(
  client: PoolClient,
  row: LedgerRow,
): Promise<void> {
  await client.query(
    `INSERT INTO public.workspace_approval_ledger (
       workspace_id, sequence, event_type, approval_id, receipt_id,
       payload_canonical, previous_hash, event_hash, key_id, signature,
       created_at
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
    [
      row.workspaceId,
      row.sequence,
      row.eventType,
      row.approvalId,
      row.receiptId,
      row.payloadCanonical,
      row.previousHash,
      row.eventHash,
      row.keyId,
      row.signature,
      row.createdAt,
    ],
  );
}

async function setRuntimeContext(
  client: PoolClient,
  userId: string,
  workspaceId: string,
): Promise<void> {
  await client.query(
    `SELECT set_config('app.user_id', $1, true),
            set_config('app.workspace_id', $2, true)`,
    [userId, workspaceId],
  );
}

let savepointSequence = 0;

async function expectSqlState(
  client: PoolClient,
  expectedCode: string,
  operation: () => Promise<unknown>,
): Promise<void> {
  const savepoint = `ledger_probe_${++savepointSequence}`;
  await client.query(`SAVEPOINT ${savepoint}`);
  let observedCode: unknown;
  try {
    await operation();
  } catch (error) {
    observedCode =
      typeof error === "object" && error !== null && "code" in error
        ? error.code
        : undefined;
  }
  await client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`);
  await client.query(`RELEASE SAVEPOINT ${savepoint}`);
  assert.equal(observedCode, expectedCode, "unexpected PostgreSQL probe result");
}

async function insertWorkspaceFixture(
  pool: Pool,
  workspaceId: string,
  creatorUserId: string,
  members: Array<{ userId: string; role: "owner" | "admin" | "viewer" }>,
): Promise<void> {
  await pool.query(
    `INSERT INTO public.workspaces (id, name, created_by_user_id)
     VALUES ($1, 'Synthetic approval ledger probe', $2)`,
    [workspaceId, creatorUserId],
  );
  for (const member of members) {
    await pool.query(
      `INSERT INTO public.workspace_memberships
         (workspace_id, user_id, role)
       VALUES ($1, $2, $3)`,
      [workspaceId, member.userId, member.role],
    );
  }
}

export function safeApprovalLedgerRlsProbeFailureCode(
  error: unknown,
): string {
  if (
    error instanceof Error &&
    SAFE_PROBE_FAILURE_CODES.has(error.message)
  ) {
    return error.message;
  }
  return "approval_ledger_probe_failed";
}

/**
 * Runs only against the caller-verified, disposable local lab database.
 * It returns counts only; no fixture identifiers or row contents are logged.
 */
export async function runApprovalLedgerRlsProbes(
  pool: Pool,
): Promise<{ passed: true; probeCount: number }> {
  const ownerUserId = `ledger-owner-${randomUUID()}`;
  const adminUserId = `ledger-admin-${randomUUID()}`;
  const viewerUserId = `ledger-viewer-${randomUUID()}`;
  const otherOwnerUserId = `ledger-other-owner-${randomUUID()}`;
  const workspaceId = randomUUID();
  const otherWorkspaceId = randomUUID();
  const approvalId = randomUUID();
  const firstReceiptId = randomUUID();
  const adminReceiptId = randomUUID();
  const otherReceiptId = randomUUID();
  const keyPair = generateKeyPairSync("ed25519");
  let probeCount = 0;
  let currentProbe = "fixture_seed";

  try {
    currentProbe = "fixture_seed";
    await insertWorkspaceFixture(pool, workspaceId, ownerUserId, [
      { userId: ownerUserId, role: "owner" },
      { userId: adminUserId, role: "admin" },
      { userId: viewerUserId, role: "viewer" },
    ]);
    await insertWorkspaceFixture(pool, otherWorkspaceId, otherOwnerUserId, [
      { userId: otherOwnerUserId, role: "owner" },
    ]);

    currentProbe = "other_workspace_seed";
    const otherWorkspaceRow = makeLedgerRow({
      workspaceId: otherWorkspaceId,
      sequence: 1,
      eventType: "approval.approved",
      approvalId: randomUUID(),
      receiptId: otherReceiptId,
      previousHash: "",
      keyPair,
    });
    const seedClient = await pool.connect();
    try {
      await insertLedgerRow(seedClient, otherWorkspaceRow);
    } finally {
      seedClient.release();
    }
    const seededOtherRows = await pool.query(
      `SELECT count(*)::integer AS count
         FROM public.workspace_approval_ledger
        WHERE workspace_id = $1`,
      [otherWorkspaceId],
    );
    assert.equal(seededOtherRows.rows[0]?.count, 1);

    const client = await pool.connect();
    try {
      currentProbe = "runtime_setup";
      await client.query("BEGIN");
      await client.query("SET LOCAL ROLE app_runtime");
      await setRuntimeContext(client, ownerUserId, workspaceId);
      currentProbe = "owner_approval_insert";
      const firstApproved = makeLedgerRow({
        workspaceId,
        sequence: 1,
        eventType: "approval.approved",
        approvalId,
        receiptId: firstReceiptId,
        previousHash: "",
        keyPair,
      });
      await insertLedgerRow(client, firstApproved);
      probeCount += 1;

      currentProbe = "owner_receipt_consumed_insert";
      const firstConsumed = makeLedgerRow({
        workspaceId,
        sequence: 2,
        eventType: "approval.receipt_consumed",
        approvalId,
        receiptId: firstReceiptId,
        previousHash: firstApproved.eventHash,
        keyPair,
      });
      await insertLedgerRow(client, firstConsumed);
      probeCount += 1;

      currentProbe = "owner_select";
      const ownRows = await client.query(
        `SELECT count(*)::integer AS count
           FROM public.workspace_approval_ledger
          WHERE workspace_id = $1`,
        [workspaceId],
      );
      assert.equal(ownRows.rows[0]?.count, 2);
      probeCount += 1;

      currentProbe = "cross_tenant_read";
      const hiddenOtherRows = await client.query(
        `SELECT sequence
           FROM public.workspace_approval_ledger
          WHERE workspace_id = $1`,
        [otherWorkspaceId],
      );
      assert.equal(hiddenOtherRows.rowCount, 0);
      probeCount += 1;

      currentProbe = "cross_tenant_insert";
      const crossTenantInsert = makeLedgerRow({
        workspaceId: otherWorkspaceId,
        sequence: 2,
        eventType: "approval.approved",
        approvalId: randomUUID(),
        receiptId: randomUUID(),
        previousHash: otherWorkspaceRow.eventHash,
        keyPair,
      });
      await expectSqlState(client, "42501", () =>
        insertLedgerRow(client, crossTenantInsert),
      );
      probeCount += 1;

      currentProbe = "duplicate_sequence";
      const duplicateSequence = makeLedgerRow({
        workspaceId,
        sequence: 1,
        eventType: "approval.approved",
        approvalId,
        receiptId: randomUUID(),
        previousHash: "",
        keyPair,
      });
      await expectSqlState(client, "23505", () =>
        insertLedgerRow(client, duplicateSequence),
      );
      probeCount += 1;

      currentProbe = "duplicate_consumption";
      const duplicateConsumption = makeLedgerRow({
        workspaceId,
        sequence: 3,
        eventType: "approval.receipt_consumed",
        approvalId,
        receiptId: firstReceiptId,
        previousHash: firstConsumed.eventHash,
        keyPair,
      });
      await expectSqlState(client, "23505", () =>
        insertLedgerRow(client, duplicateConsumption),
      );
      probeCount += 1;

      currentProbe = "admin_insert";
      const forbiddenRow = makeLedgerRow({
        workspaceId,
        sequence: 3,
        eventType: "approval.approved",
        approvalId,
        receiptId: adminReceiptId,
        previousHash: firstConsumed.eventHash,
        keyPair,
      });
      await setRuntimeContext(client, adminUserId, workspaceId);
      await insertLedgerRow(client, forbiddenRow);
      probeCount += 1;

      currentProbe = "viewer_insert";
      const viewerRow = makeLedgerRow({
        workspaceId,
        sequence: 4,
        eventType: "approval.approved",
        approvalId,
        receiptId: randomUUID(),
        previousHash: forbiddenRow.eventHash,
        keyPair,
      });
      await setRuntimeContext(client, viewerUserId, workspaceId);
      await expectSqlState(client, "42501", () =>
        insertLedgerRow(client, viewerRow),
      );
      probeCount += 1;

      currentProbe = "update_denied";
      await setRuntimeContext(client, ownerUserId, workspaceId);
      await expectSqlState(client, "42501", () =>
        client.query(
          `UPDATE public.workspace_approval_ledger
              SET event_type = 'approval.receipt_consumed'
            WHERE workspace_id = $1`,
          [workspaceId],
        ),
      );
      probeCount += 1;
      currentProbe = "delete_denied";
      await expectSqlState(client, "42501", () =>
        client.query(
          "DELETE FROM public.workspace_approval_ledger WHERE workspace_id = $1",
          [workspaceId],
        ),
      );
      probeCount += 1;
      currentProbe = "truncate_denied";
      await expectSqlState(client, "42501", () =>
        client.query("TRUNCATE TABLE public.workspace_approval_ledger"),
      );
      probeCount += 1;

      currentProbe = "runtime_setup";
      await client.query("COMMIT");
    } catch {
      await client.query("ROLLBACK").catch(() => undefined);
      throw new Error(`approval_ledger_probe_${currentProbe}_failed`);
    } finally {
      client.release();
    }

    currentProbe = "workspace_delete_protected";
    const deleteClient = await pool.connect();
    try {
      await deleteClient.query("BEGIN");
      await expectSqlState(deleteClient, "23503", () =>
        deleteClient.query(
          "DELETE FROM public.workspaces WHERE id = $1",
          [workspaceId],
        ),
      );
      await deleteClient.query("ROLLBACK");
      probeCount += 1;
    } catch {
      await deleteClient.query("ROLLBACK").catch(() => undefined);
      throw new Error("approval_ledger_workspace_delete_probe_failed");
    } finally {
      deleteClient.release();
    }

    currentProbe = "probe_count";
    assert.equal(probeCount, 13);
    return { passed: true, probeCount };
  } catch {
    const code = `approval_ledger_probe_${currentProbe}_failed`;
    throw new Error(SAFE_PROBE_FAILURE_CODES.has(code)
      ? code
      : "approval_ledger_probe_failed");
  }
}
