import { sql, type SQLWrapper } from "drizzle-orm";
import {
  bigint,
  check,
  foreignKey,
  index,
  pgPolicy,
  pgTable,
  primaryKey,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { appRuntimeRole } from "./roles";
import { membershipsTable, workspacesTable } from "./workspaces";

function memberScope(workspaceId: SQLWrapper) {
  return sql`
    ${workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM ${membershipsTable} AS membership
      WHERE membership.workspaceId = ${workspaceId}
        AND membership.userId = NULLIF(current_setting('app.user_id', true), '')
    )
  `;
}

export const workspaceApprovalLedgerTable = pgTable(
  "workspace_approval_ledger",
  {
    workspaceId: uuid("workspace_id").notNull(),
    sequence: bigint("sequence", { mode: "number" }).notNull(),
    eventType: text("event_type").notNull(),
    approvalId: text("approval_id").notNull(),
    receiptId: text("receipt_id").notNull(),
    /**
     * Stores the entire canonical ApprovalLedgerEventV1 envelope as UTF-8
     * text, preserving the exact bytes used for its digest and signature.
     */
    payloadCanonical: text("payload_canonical").notNull(),
    previousHash: text("previous_hash").notNull().default(""),
    eventHash: text("event_hash").notNull(),
    keyId: text("key_id").notNull(),
    signature: text("signature").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    primaryKey({
      name: "workspace_approval_ledger_pkey",
      columns: [table.workspaceId, table.sequence],
    }),
    foreignKey({
      name: "workspace_approval_ledger_workspace_id_workspaces_id_fk",
      columns: [table.workspaceId],
      foreignColumns: [workspacesTable.id],
    }),
    uniqueIndex("workspace_approval_ledger_consumed_receipt_uidx")
      .on(table.receiptId)
      .where(sql`${table.eventType} = 'approval.receipt_consumed'`),
    index("workspace_approval_ledger_approval_idx").on(
      table.workspaceId,
      table.approvalId,
      table.sequence,
    ),
    check(
      "workspace_approval_ledger_sequence_check",
      sql`${table.sequence} > 0`,
    ),
    check(
      "workspace_approval_ledger_event_type_check",
      sql`${table.eventType} IN ('approval.approved', 'approval.receipt_consumed')`,
    ),
    check(
      "workspace_approval_ledger_ids_check",
      sql`${table.approvalId} <> '' AND ${table.receiptId} <> ''`,
    ),
    check(
      "workspace_approval_ledger_hashes_check",
      sql`
        (${table.previousHash} = '' OR ${table.previousHash} ~ '^[a-f0-9]{64}$')
        AND ${table.eventHash} ~ '^[a-f0-9]{64}$'
        AND ${table.keyId} ~ '^[A-Za-z0-9._-]{1,64}$'
      `,
    ),
    check(
      "workspace_approval_ledger_signature_check",
      sql`${table.signature} ~ '^[A-Za-z0-9_-]{85}[AQgw]$'`,
    ),
    check(
      "workspace_approval_ledger_payload_binding_check",
      sql`
        jsonb_typeof(${table.payloadCanonical}::jsonb) = 'object'
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'workspaceId') = ${table.workspaceId}::text
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'sequence') = ${table.sequence}::text
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'eventType') = ${table.eventType}
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'approvalId') = ${table.approvalId}
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'previousEventSha256') = ${table.previousHash}
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'keyId') = ${table.keyId}
        AND jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'payload', 'receiptId') = ${table.receiptId}
        AND ${table.createdAt} = jsonb_extract_path_text(${table.payloadCanonical}::jsonb, 'occurredAt')::timestamp with time zone
      `,
    ),
    pgPolicy("workspace_approval_ledger_select_member", {
      for: "select",
      to: appRuntimeRole,
      using: memberScope(table.workspaceId),
    }),
    pgPolicy("workspace_approval_ledger_insert_owner_admin", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${memberScope(table.workspaceId)}
        AND EXISTS (
          SELECT 1
          FROM ${membershipsTable} AS actor_membership
          WHERE actor_membership.workspaceId = ${table.workspaceId}
            AND actor_membership.userId = NULLIF(current_setting('app.user_id', true), '')
            AND actor_membership.role IN ('owner', 'admin')
        )
      `,
    }),
  ],
).enableRLS();

export type WorkspaceApprovalLedgerEventRow =
  typeof workspaceApprovalLedgerTable.$inferSelect;
