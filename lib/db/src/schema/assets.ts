import { sql } from "drizzle-orm";
import { index, pgPolicy, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";
import { workspacesTable } from "./workspaces";

export const assetsTable = pgTable(
  "assets",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    type: text("type").notNull(),
    environment: text("environment").notNull(),
    criticality: text("criticality").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("assets_workspace_created_idx").on(table.workspaceId, table.createdAt),
    pgPolicy("assets_workspace_scope", {
      for: "all",
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

export const insertAssetSchema = createInsertSchema(assetsTable).omit({
  id: true,
  createdAt: true,
});
export type InsertAsset = z.infer<typeof insertAssetSchema>;
export type Asset = typeof assetsTable.$inferSelect;
