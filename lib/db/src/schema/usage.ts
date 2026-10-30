import {
  date,
  index,
  integer,
  pgPolicy,
  pgTable,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";
import { workspacesTable } from "./workspaces";
import { appRuntimeRole } from "./roles";

export const monthlyUsageTable = pgTable(
  "workspace_monthly_usage",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    monthStart: date("month_start", { mode: "string" }).notNull(),
    scansUsed: integer("scans_used").notNull().default(0),
    tokensUsed: integer("tokens_used").notNull().default(0),
    apiRequestsUsed: integer("api_requests_used").notNull().default(0),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (table) => [
    uniqueIndex("workspace_monthly_usage_workspace_month_idx").on(
      table.workspaceId,
      table.monthStart,
    ),
    index("workspace_monthly_usage_month_idx").on(table.monthStart),
    pgPolicy("workspace_monthly_usage_scope", {
      for: "all",
      to: appRuntimeRole,
      using: sql`
        ${table.workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
        AND EXISTS (
          SELECT 1
          FROM "workspace_memberships" AS membership
          WHERE membership."workspace_id" = ${table.workspaceId}
            AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
        )
      `,
      withCheck: sql`
        ${table.workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
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
