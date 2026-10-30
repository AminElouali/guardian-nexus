import {
  check,
  index,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

const currentUserId = sql`NULLIF(current_setting('app.user_id', true), '')`;
const currentWorkspaceId = sql`NULLIF(current_setting('app.workspace_id', true), '')`;

export const workspacesTable = pgTable(
  "workspaces",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    name: text("name").notNull(),
    planId: text("plan_id").notNull().default("small"),
    createdByUserId: text("created_by_user_id"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    pgPolicy("workspaces_select_member", {
      for: "select",
      to: "app_runtime",
      using: sql`
        ${table.createdByUserId} = ${currentUserId}
        OR EXISTS (
          SELECT 1
          FROM "workspace_memberships" AS membership
          WHERE membership."workspace_id" = ${table.id}
            AND membership."user_id" = ${currentUserId}
        )
      `,
    }),
    pgPolicy("workspaces_insert_creator", {
      for: "insert",
      to: "app_runtime",
      withCheck: sql`${table.createdByUserId} = ${currentUserId}`,
    }),
  ],
).enableRLS();

export const membershipsTable = pgTable(
  "workspace_memberships",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull(),
    role: text("role").notNull().default("viewer"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("workspace_memberships_workspace_user_idx").on(
      table.workspaceId,
      table.userId,
    ),
    index("workspace_memberships_user_idx").on(table.userId),
    check(
      "workspace_memberships_role_check",
      sql`${table.role} IN ('owner', 'admin', 'analyst', 'viewer')`,
    ),
    pgPolicy("workspace_memberships_select_scoped", {
      for: "select",
      to: "app_runtime",
      using: sql`
        ${table.userId} = ${currentUserId}
        OR ${table.workspaceId}::text = ${currentWorkspaceId}
      `,
    }),
    pgPolicy("workspace_memberships_insert_self", {
      for: "insert",
      to: "app_runtime",
      withCheck: sql`
        ${table.userId} = ${currentUserId}
        AND ${table.workspaceId}::text = ${currentWorkspaceId}
      `,
    }),
    pgPolicy("workspace_memberships_update_scoped", {
      for: "update",
      to: "app_runtime",
      using: sql`${table.workspaceId}::text = ${currentWorkspaceId}`,
      withCheck: sql`${table.workspaceId}::text = ${currentWorkspaceId}`,
    }),
  ],
).enableRLS();

export const insertWorkspaceSchema = createInsertSchema(workspacesTable).omit({
  id: true,
  createdByUserId: true,
  createdAt: true,
});
export type InsertWorkspace = z.infer<typeof insertWorkspaceSchema>;
export type Workspace = typeof workspacesTable.$inferSelect;
export type Membership = typeof membershipsTable.$inferSelect;
