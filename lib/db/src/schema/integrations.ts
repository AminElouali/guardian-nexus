import { sql } from "drizzle-orm";
import {
  check,
  index,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { appRuntimeRole } from "./roles";
import { workspacesTable } from "./workspaces";

const currentUserId = sql`NULLIF(current_setting('app.user_id', true), '')`;
const currentWorkspaceId = sql`NULLIF(current_setting('app.workspace_id', true), '')`;
const workspaceOwner = (workspaceId: unknown) => sql`
  EXISTS (
    SELECT 1
    FROM "workspace_memberships" AS membership
    WHERE membership."workspace_id" = ${workspaceId}
      AND membership."user_id" = ${currentUserId}
      AND membership."role" = 'owner'
  )
`;

export const workspaceIntegrationsTable = pgTable(
  "workspace_integrations",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    externalAccountId: text("external_account_id").notNull(),
    setupKey: text("setup_key").notNull(),
    status: text("status").notNull(),
    externalId: text("external_id"),
    requestedPermissions: jsonb("requested_permissions")
      .$type<string[]>()
      .notNull()
      .default(sql`'[]'::jsonb`),
    createdByUserId: text("created_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("workspace_integrations_setup_key_idx").on(
      table.workspaceId,
      table.provider,
      table.setupKey,
    ),
    uniqueIndex("workspace_integrations_external_id_idx")
      .on(table.externalId)
      .where(sql`${table.externalId} IS NOT NULL`),
    index("workspace_integrations_workspace_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
    check(
      "workspace_integrations_provider_check",
      sql`${table.provider} IN ('microsoft', 'aws')`,
    ),
    check(
      "workspace_integrations_status_check",
      sql`${table.status} IN (
        'awaiting_app_registration',
        'ready_for_admin_consent',
        'awaiting_runtime_identity',
        'ready_for_role_trust',
        'connected',
        'revoked'
      )`,
    ),
    pgPolicy("workspace_integrations_select_member", {
      for: "select",
      to: appRuntimeRole,
      using: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND EXISTS (
          SELECT 1
          FROM "workspace_memberships" AS membership
          WHERE membership."workspace_id" = ${table.workspaceId}
            AND membership."user_id" = ${currentUserId}
        )
      `,
    }),
    pgPolicy("workspace_integrations_insert_owner", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND ${table.createdByUserId} = ${currentUserId}
        AND ${workspaceOwner(table.workspaceId)}
      `,
    }),
    pgPolicy("workspace_integrations_update_owner", {
      for: "update",
      to: appRuntimeRole,
      using: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND ${workspaceOwner(table.workspaceId)}
      `,
      withCheck: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND ${workspaceOwner(table.workspaceId)}
      `,
    }),
  ],
).enableRLS();

export type WorkspaceIntegration =
  typeof workspaceIntegrationsTable.$inferSelect;
