import { sql } from "drizzle-orm";
import {
  check,
  foreignKey,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  primaryKey,
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

export const workspaceActionRuleVersionsTable = pgTable(
  "workspace_action_rule_versions",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    actionType: text("action_type").notNull(),
    version: integer("version").notNull(),
    ruleDocument: jsonb("rule_document")
      .$type<Record<string, unknown>>()
      .notNull(),
    createdByUserId: text("created_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("workspace_action_rule_versions_workspace_action_version_uidx")
      .on(table.workspaceId, table.actionType, table.version),
    index("workspace_action_rule_versions_workspace_created_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
    check(
      "workspace_action_rule_versions_action_type_check",
      sql`${table.actionType} IN (${actionRefList})`,
    ),
    check(
      "workspace_action_rule_versions_version_check",
      sql`${table.version} > 0`,
    ),
    check(
      "workspace_action_rule_versions_document_check",
      sql`jsonb_typeof(${table.ruleDocument}) = 'object'`,
    ),
    pgPolicy("workspace_action_rule_versions_select_member", {
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
    pgPolicy("workspace_action_rule_versions_insert_admin", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${table.createdByUserId} = ${currentUserId}
      `,
    }),
  ],
).enableRLS();

export const workspaceActionRuleHeadsTable = pgTable(
  "workspace_action_rule_heads",
  {
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    actionType: text("action_type").notNull(),
    activeVersion: integer("active_version"),
    draftVersion: integer("draft_version"),
    updatedByUserId: text("updated_by_user_id").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (table) => [
    primaryKey({
      name: "workspace_action_rule_heads_pkey",
      columns: [table.workspaceId, table.actionType],
    }),
    foreignKey({
      name: "workspace_action_rule_heads_active_version_fk",
      columns: [table.workspaceId, table.actionType, table.activeVersion],
      foreignColumns: [
        workspaceActionRuleVersionsTable.workspaceId,
        workspaceActionRuleVersionsTable.actionType,
        workspaceActionRuleVersionsTable.version,
      ],
    }),
    foreignKey({
      name: "workspace_action_rule_heads_draft_version_fk",
      columns: [table.workspaceId, table.actionType, table.draftVersion],
      foreignColumns: [
        workspaceActionRuleVersionsTable.workspaceId,
        workspaceActionRuleVersionsTable.actionType,
        workspaceActionRuleVersionsTable.version,
      ],
    }),
    check(
      "workspace_action_rule_heads_action_type_check",
      sql`${table.actionType} IN (${actionRefList})`,
    ),
    check(
      "workspace_action_rule_heads_versions_check",
      sql`(${table.activeVersion} IS NULL OR ${table.activeVersion} > 0)
          AND (${table.draftVersion} IS NULL OR ${table.draftVersion} > 0)`,
    ),
    check(
      "workspace_action_rule_heads_version_state_check",
      sql`${table.activeVersion} IS NULL
          OR ${table.draftVersion} IS NULL
          OR ${table.activeVersion} <> ${table.draftVersion}`,
    ),
    pgPolicy("workspace_action_rule_heads_select_member", {
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
    pgPolicy("workspace_action_rule_heads_insert_admin", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${table.updatedByUserId} = ${currentUserId}
      `,
    }),
    pgPolicy("workspace_action_rule_heads_update_admin", {
      for: "update",
      to: appRuntimeRole,
      using: workspaceAdminScope(table.workspaceId),
      withCheck: sql`
        ${workspaceAdminScope(table.workspaceId)}
        AND ${table.updatedByUserId} = ${currentUserId}
      `,
    }),
  ],
).enableRLS();

export type WorkspaceActionRuleHead =
  typeof workspaceActionRuleHeadsTable.$inferSelect;
export type WorkspaceActionRuleVersion =
  typeof workspaceActionRuleVersionsTable.$inferSelect;
