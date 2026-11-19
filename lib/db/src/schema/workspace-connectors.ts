import { sql } from "drizzle-orm";
import {
  check,
  foreignKey,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { APPROVAL_ACTION_REFS } from "../approval-action-catalog";
import { appRuntimeRole } from "./roles";
import { membershipsTable, workspacesTable } from "./workspaces";

const actionRefList = sql.raw(
  APPROVAL_ACTION_REFS.map((value) => `'${value}'`).join(", "),
);
const currentUserId = sql`NULLIF(current_setting('app.user_id', true), '')`;
const currentWorkspaceId = sql`NULLIF(current_setting('app.workspace_id', true), '')`;
const connectorExecutionWriter = sql`current_setting('app.connector_execution_writer', true) = '1'`;

function workspaceMemberScope(workspaceColumn: unknown) {
  return sql`
    ${workspaceColumn as never}::text = ${currentWorkspaceId}
    AND EXISTS (
      SELECT 1
      FROM "workspace_memberships" AS membership
      WHERE membership."workspace_id" = ${workspaceColumn as never}
        AND membership."user_id" = ${currentUserId}
    )
  `;
}

function workspaceAdminScope(workspaceColumn: unknown) {
  return sql`
    ${workspaceColumn as never}::text = ${currentWorkspaceId}
    AND EXISTS (
      SELECT 1
      FROM "workspace_memberships" AS membership
      WHERE membership."workspace_id" = ${workspaceColumn as never}
        AND membership."user_id" = ${currentUserId}
        AND membership."role" IN ('owner', 'admin')
    )
  `;
}

export const workspaceConnectorCredentialsTable = pgTable(
  "workspace_connector_credentials",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id").notNull(),
    serviceId: text("service_id").notNull(),
    encryptedSecret: text("encrypted_secret").notNull(),
    nonce: text("nonce").notNull(),
    authTag: text("auth_tag").notNull(),
    encryptionKeyId: text("encryption_key_id").notNull(),
    lastFour: text("last_four").notNull(),
    createdByUserId: text("created_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    foreignKey({
      name: "workspace_connector_credentials_workspace_id_workspaces_id_fk",
      columns: [table.workspaceId],
      foreignColumns: [workspacesTable.id],
    }).onDelete("cascade"),
    uniqueIndex("workspace_connector_credentials_workspace_service_uidx").on(
      table.workspaceId,
      table.serviceId,
    ),
    uniqueIndex("workspace_connector_credentials_nonce_uidx").on(table.nonce),
    check(
      "workspace_connector_credentials_service_id_check",
      sql`${table.serviceId} ~ '^[a-z0-9][a-z0-9._-]{0,63}$'`,
    ),
    check(
      "workspace_connector_credentials_ciphertext_check",
      sql`${table.encryptedSecret} ~ '^[A-Za-z0-9_-]+$' AND length(${table.encryptedSecret}) BETWEEN 8 AND 5462`,
    ),
    check(
      "workspace_connector_credentials_nonce_check",
      sql`${table.nonce} ~ '^[A-Za-z0-9_-]{16}$'`,
    ),
    check(
      "workspace_connector_credentials_auth_tag_check",
      sql`${table.authTag} ~ '^[A-Za-z0-9_-]{22}$'`,
    ),
    check(
      "workspace_connector_credentials_key_id_check",
      sql`${table.encryptionKeyId} ~ '^[A-Za-z0-9._-]{1,64}$'`,
    ),
    check(
      "workspace_connector_credentials_last_four_check",
      sql`length(${table.lastFour}) = 4`,
    ),
    pgPolicy("workspace_connector_credentials_select_admin", {
      for: "select",
      to: appRuntimeRole,
      using: workspaceAdminScope(table.workspaceId),
    }),
    pgPolicy("workspace_connector_credentials_insert_admin", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${table.createdByUserId} = ${currentUserId}
      `,
    }),
    pgPolicy("workspace_connector_credentials_delete_admin", {
      for: "delete",
      to: appRuntimeRole,
      using: workspaceAdminScope(table.workspaceId),
    }),
  ],
).enableRLS();

export const workspaceConnectorExecutionsTable = pgTable(
  "workspace_connector_executions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id").notNull(),
    serviceId: text("service_id").notNull(),
    credentialId: uuid("credential_id"),
    idempotencyKeySha256: text("idempotency_key_sha256").notNull(),
    actionType: text("action_type").notNull(),
    actionSha256: text("action_sha256").notNull(),
    receiptId: text("receipt_id").notNull(),
    requestedByUserId: text("requested_by_user_id").notNull(),
    status: text("status").notNull().default("pending"),
    responseSummary: text("response_summary"),
    failureCode: text("failure_code"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    completedAt: timestamp("completed_at", { withTimezone: true }),
  },
  (table) => [
    foreignKey({
      name: "workspace_connector_executions_workspace_id_workspaces_id_fk",
      columns: [table.workspaceId],
      foreignColumns: [workspacesTable.id],
    }).onDelete("cascade"),
    foreignKey({
      name: "workspace_connector_executions_credential_id_credentials_id_fk",
      columns: [table.credentialId],
      foreignColumns: [workspaceConnectorCredentialsTable.id],
    }).onDelete("set null"),
    uniqueIndex("workspace_connector_executions_idempotency_uidx").on(
      table.workspaceId,
      table.serviceId,
      table.idempotencyKeySha256,
    ),
    check(
      "workspace_connector_executions_service_id_check",
      sql`${table.serviceId} ~ '^[a-z0-9][a-z0-9._-]{0,63}$'`,
    ),
    check(
      "workspace_connector_executions_idempotency_hash_check",
      sql`${table.idempotencyKeySha256} ~ '^[a-f0-9]{64}$'`,
    ),
    check(
      "workspace_connector_executions_action_type_check",
      sql`${table.actionType} IN (${actionRefList})`,
    ),
    check(
      "workspace_connector_executions_action_hash_check",
      sql`${table.actionSha256} ~ '^[a-f0-9]{64}$'`,
    ),
    check(
      "workspace_connector_executions_receipt_id_check",
      sql`${table.receiptId} ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
    ),
    check(
      "workspace_connector_executions_status_check",
      sql`${table.status} IN ('pending', 'executed', 'failed')`,
    ),
    check(
      "workspace_connector_executions_response_summary_check",
      sql`${table.responseSummary} IS NULL OR length(${table.responseSummary}) <= 512`,
    ),
    check(
      "workspace_connector_executions_failure_code_check",
      sql`${table.failureCode} IS NULL OR ${table.failureCode} ~ '^[a-z0-9_]{1,64}$'`,
    ),
    check(
      "workspace_connector_executions_completion_state_check",
      sql`
        (${table.status} = 'pending'
          AND ${table.completedAt} IS NULL
          AND ${table.failureCode} IS NULL
          AND ${table.responseSummary} IS NULL)
        OR (${table.status} = 'executed'
          AND ${table.completedAt} IS NOT NULL
          AND ${table.failureCode} IS NULL)
        OR (${table.status} = 'failed'
          AND ${table.completedAt} IS NOT NULL
          AND ${table.failureCode} IS NOT NULL)
      `,
    ),
    pgPolicy("workspace_connector_executions_select_member", {
      for: "select",
      to: appRuntimeRole,
      using: workspaceMemberScope(table.workspaceId),
    }),
    pgPolicy("workspace_connector_executions_insert_admin", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${table.requestedByUserId} = ${currentUserId}
        AND ${table.status} = 'pending'
        AND ${table.responseSummary} IS NULL
        AND ${table.failureCode} IS NULL
        AND ${table.completedAt} IS NULL
      `,
    }),
    pgPolicy("workspace_connector_executions_complete_pending", {
      for: "update",
      to: appRuntimeRole,
      using: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${connectorExecutionWriter}
        AND ${table.status} = 'pending'
      `,
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${connectorExecutionWriter}
        AND ${table.status} IN ('executed', 'failed')
        AND ${table.completedAt} IS NOT NULL
      `,
    }),
  ],
).enableRLS();

export type WorkspaceConnectorCredential =
  typeof workspaceConnectorCredentialsTable.$inferSelect;
export type WorkspaceConnectorExecution =
  typeof workspaceConnectorExecutionsTable.$inferSelect;
