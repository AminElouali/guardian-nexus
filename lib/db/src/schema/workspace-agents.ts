import { sql } from "drizzle-orm";
import {
  check,
  index,
  integer,
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

function workspaceAdminScope(workspaceColumn: unknown) {
  return sql`
    ${workspaceColumn as never}::text = ${currentWorkspaceId}
    AND EXISTS (
      SELECT 1
      FROM "workspace_memberships" AS actor_membership
      WHERE actor_membership."workspace_id" = ${workspaceColumn as never}
        AND actor_membership."user_id" = ${currentUserId}
        AND actor_membership."role" IN ('owner', 'admin')
    )
  `;
}

export const workspaceAgentsTable = pgTable(
  "workspace_agents",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    displayName: text("display_name").notNull(),
    principalUserId: text("principal_user_id").notNull(),
    credentialSha256: text("credential_sha256").notNull(),
    credentialVersion: integer("credential_version").notNull().default(1),
    createdByUserId: text("created_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("workspace_agents_credential_sha256_uidx").on(
      table.credentialSha256,
    ),
    index("workspace_agents_workspace_created_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
    check(
      "workspace_agents_display_name_check",
      sql`length(btrim(${table.displayName})) BETWEEN 1 AND 120`,
    ),
    check(
      "workspace_agents_credential_hash_check",
      sql`${table.credentialSha256} ~ '^[a-f0-9]{64}$'`,
    ),
    check(
      "workspace_agents_credential_version_check",
      sql`${table.credentialVersion} > 0`,
    ),
    pgPolicy("workspace_agents_select_admin", {
      for: "select",
      to: appRuntimeRole,
      using: workspaceAdminScope(table.workspaceId),
    }),
    pgPolicy("workspace_agents_authenticate_exact_credential", {
      for: "select",
      to: appRuntimeRole,
      using: sql`
        ${table.workspaceId}::text = ${currentWorkspaceId}
        AND ${table.credentialSha256} =
          NULLIF(current_setting('app.agent_credential_sha256', true), '')
        AND ${table.revokedAt} IS NULL
      `,
    }),
    pgPolicy("workspace_agents_insert_admin", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${table.createdByUserId} = ${currentUserId}
        AND ${table.principalUserId} = ${currentUserId}
      `,
    }),
    pgPolicy("workspace_agents_update_admin", {
      for: "update",
      to: appRuntimeRole,
      using: workspaceAdminScope(table.workspaceId),
      withCheck: workspaceAdminScope(table.workspaceId),
    }),
  ],
).enableRLS();

export type WorkspaceAgent = typeof workspaceAgentsTable.$inferSelect;
