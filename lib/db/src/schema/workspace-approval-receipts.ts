import { sql } from "drizzle-orm";
import {
  check,
  foreignKey,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { appRuntimeRole } from "./roles";
import { aiAssessmentApprovalRequestsTable, aiAssessmentJobsTable } from "./ai-assessment-jobs";
import { workspaceAgentsTable } from "./workspace-agents";
import { membershipsTable, workspacesTable } from "./workspaces";

const currentUserId = sql`NULLIF(current_setting('app.user_id', true), '')`;
const currentWorkspaceId = sql`NULLIF(current_setting('app.workspace_id', true), '')`;
const currentAgentId = sql`NULLIF(current_setting('app.agent_id', true), '')`;

export const workspaceApprovalReceiptsTable = pgTable(
  "workspace_approval_receipts",
  {
    approvalId: uuid("approval_id").primaryKey(),
    workspaceId: uuid("workspace_id").notNull(),
    receiptId: text("receipt_id").notNull(),
    receiptSha256: text("receipt_sha256").notNull(),
    signedReceipt: jsonb("signed_receipt")
      .$type<Record<string, unknown>>()
      .notNull(),
    approvedByUserId: text("approved_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "workspace_approval_receipts_workspace_id_workspaces_id_fk",
      columns: [table.workspaceId],
      foreignColumns: [workspacesTable.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "workspace_approval_receipts_approval_id_approval_requests_id_fk",
      columns: [table.approvalId],
      foreignColumns: [aiAssessmentApprovalRequestsTable.id],
    }).onDelete("cascade"),
    uniqueIndex("workspace_approval_receipts_receipt_id_uidx").on(
      table.receiptId,
    ),
    check(
      "workspace_approval_receipts_receipt_id_check",
      sql`${table.receiptId} ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
    ),
    check(
      "workspace_approval_receipts_receipt_sha256_check",
      sql`${table.receiptSha256} ~ '^[a-f0-9]{64}$'`,
    ),
    check(
      "workspace_approval_receipts_approved_by_check",
      sql`${table.approvedByUserId} <> ''`,
    ),
    check(
      "workspace_approval_receipts_signed_binding_check",
      sql`
        jsonb_typeof(${table.signedReceipt}) = 'object'
        AND jsonb_typeof(${table.signedReceipt}->'payload') = 'object'
        AND ${table.signedReceipt}->>'payloadSha256' = ${table.receiptSha256}
        AND ${table.signedReceipt}->'payload'->>'receiptId' = ${table.receiptId}
        AND ${table.signedReceipt}->'payload'->>'workspaceId' = ${table.workspaceId}::text
        AND ${table.signedReceipt}->'payload'->>'approvalId' = ${table.approvalId}::text
        AND ${table.signedReceipt}->'payload'->>'approvedBy' = ${table.approvedByUserId}
      `,
    ),
    pgPolicy("workspace_approval_receipts_select_agent_execution", {
      for: "select",
      to: appRuntimeRole,
      using: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND ${currentAgentId} IS NOT NULL
        AND EXISTS (
          SELECT 1
          FROM ${workspaceAgentsTable} AS agent
          WHERE agent.id::text = ${currentAgentId}
            AND agent.workspaceId = ${table.workspaceId}
            AND agent.principalUserId = ${currentUserId}
            AND agent.revokedAt IS NULL
        )
        AND EXISTS (
          SELECT 1
          FROM ${aiAssessmentApprovalRequestsTable} AS approval
          JOIN ${aiAssessmentJobsTable} AS job
            ON job.id = approval.jobId
           AND job.workspaceId = approval.workspaceId
          WHERE approval.id = ${table.approvalId}
            AND approval.workspaceId = ${table.workspaceId}
            AND approval.status = 'approved'
            AND approval.requestedByUserId = ${currentUserId}
            AND job.result->>'agentId' = ${currentAgentId}
        )
      `,
    }),
    pgPolicy("workspace_approval_receipts_insert_approver", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND ${table.approvedByUserId} = ${currentUserId}
        AND current_setting('app.approval_receipt_writer', true) = '1'
        AND EXISTS (
          SELECT 1
          FROM ${membershipsTable} AS approver
          WHERE approver.workspaceId = ${table.workspaceId}
            AND approver.userId = ${currentUserId}
            AND approver.role IN ('owner', 'admin')
        )
        AND EXISTS (
          SELECT 1
          FROM ${aiAssessmentApprovalRequestsTable} AS approval
          WHERE approval.id = ${table.approvalId}
            AND approval.workspaceId = ${table.workspaceId}
            AND approval.status = 'approved'
            AND approval.decidedByUserId = ${currentUserId}
            AND approval.actionSha256 =
              ${table.signedReceipt}->'payload'->>'actionSha256'
            AND approval.proposalBindingSha256 =
              ${table.signedReceipt}->'payload'->>'proposalBindingSha256'
            AND approval.requestedByUserId =
              ${table.signedReceipt}->'payload'->>'requestedBy'
        )
      `,
    }),
  ],
).enableRLS();

export type WorkspaceApprovalReceipt =
  typeof workspaceApprovalReceiptsTable.$inferSelect;
