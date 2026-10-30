import { sql } from "drizzle-orm";
import {
  index,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uuid,
} from "drizzle-orm/pg-core";
import { workspacesTable } from "./workspaces";

export const workspaceAuditEventsTable = pgTable(
  "workspace_audit_events",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    actorUserId: text("actor_user_id").notNull(),
    action: text("action").notNull(),
    resourceType: text("resource_type").notNull(),
    resourceId: text("resource_id"),
    metadata: jsonb("metadata")
      .$type<Record<string, string | number | boolean | null>>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("workspace_audit_events_workspace_created_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
    pgPolicy("workspace_audit_events_select_scope", {
      for: "select",
      to: "app_runtime",
      using: sql`
        ${table.workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
        AND EXISTS (
          SELECT 1
          FROM "workspace_memberships" AS membership
          WHERE membership."workspace_id" = ${table.workspaceId}
            AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
        )
      `,
    }),
    pgPolicy("workspace_audit_events_insert_scope", {
      for: "insert",
      to: "app_runtime",
      withCheck: sql`
        ${table.workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
        AND ${table.actorUserId} = NULLIF(current_setting('app.user_id', true), '')
        AND EXISTS (
          SELECT 1
          FROM "workspace_memberships" AS membership
          WHERE membership."workspace_id" = ${table.workspaceId}
            AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
        )
      `,
    }),
  ],
).enableRLS();

export type WorkspaceAuditEvent = typeof workspaceAuditEventsTable.$inferSelect;
