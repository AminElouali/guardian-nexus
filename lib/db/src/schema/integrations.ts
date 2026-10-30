import { sql, type SQLWrapper } from "drizzle-orm";
import {
  check,
  integer,
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

const tenantScope = (workspaceId: SQLWrapper) => sql`
  ${workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
  AND EXISTS (
    SELECT 1
    FROM "workspace_memberships" AS membership
    WHERE membership."workspace_id" = ${workspaceId}
      AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
  )
`;

const currentUserId = sql`NULLIF(current_setting('app.user_id', true), '')`;
const workspaceOwner = (workspaceId: SQLWrapper) => sql`
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
      using: tenantScope(table.workspaceId),
    }),
    pgPolicy("workspace_integrations_insert_owner", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${tenantScope(table.workspaceId)}
        AND ${table.createdByUserId} = ${currentUserId}
        AND ${workspaceOwner(table.workspaceId)}
      `,
    }),
    pgPolicy("workspace_integrations_update_owner", {
      for: "update",
      to: appRuntimeRole,
      using: sql`
        ${tenantScope(table.workspaceId)}
        AND ${workspaceOwner(table.workspaceId)}
      `,
      withCheck: sql`
        ${tenantScope(table.workspaceId)}
        AND ${workspaceOwner(table.workspaceId)}
      `,
    }),
  ],
).enableRLS();

export type WorkspaceIntegration =
  typeof workspaceIntegrationsTable.$inferSelect;

export const providerConnectionsTable = pgTable(
  "provider_connections",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    provider: text("provider").notNull(),
    status: text("status").notNull().default("pending"),
    externalTenantId: text("external_tenant_id"),
    awsAccountId: text("aws_account_id"),
    awsRoleArn: text("aws_role_arn"),
    awsExternalId: text("aws_external_id"),
    grantedScopes: text("granted_scopes").array().notNull().default(sql`'{}'`),
    encryptedRefreshToken: text("encrypted_refresh_token"),
    tokenExpiresAt: timestamp("token_expires_at", { withTimezone: true }),
    consentedByUserId: text("consented_by_user_id"),
    consentedAt: timestamp("consented_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    nextProviderRequestAt: timestamp("next_provider_request_at", {
      withTimezone: true,
    }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("provider_connections_workspace_provider_idx").on(
      table.workspaceId,
      table.provider,
    ),
    index("provider_connections_workspace_status_idx").on(
      table.workspaceId,
      table.status,
    ),
    check(
      "provider_connections_provider_check",
      sql`${table.provider} IN ('microsoft_graph', 'aws')`,
    ),
    check(
      "provider_connections_status_check",
      sql`${table.status} IN ('pending', 'active', 'revoked')`,
    ),
    pgPolicy("provider_connections_select_scope", {
      for: "select",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
    }),
    pgPolicy("provider_connections_insert_scope", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: tenantScope(table.workspaceId),
    }),
    pgPolicy("provider_connections_update_scope", {
      for: "update",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
      withCheck: tenantScope(table.workspaceId),
    }),
    pgPolicy("provider_connections_delete_scope", {
      for: "delete",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
    }),
  ],
).enableRLS();

export const connectorOAuthStatesTable = pgTable(
  "connector_oauth_states",
  {
    nonceHash: text("nonce_hash").primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    index("connector_oauth_states_workspace_idx").on(table.workspaceId),
    pgPolicy("connector_oauth_states_select_scope", {
      for: "select",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
    }),
    pgPolicy("connector_oauth_states_insert_scope", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${tenantScope(table.workspaceId)}
        AND ${table.userId} = NULLIF(current_setting('app.user_id', true), '')
      `,
    }),
    pgPolicy("connector_oauth_states_delete_scope", {
      for: "delete",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
    }),
  ],
).enableRLS();

export const connectorJobsTable = pgTable(
  "connector_jobs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    providerConnectionId: uuid("provider_connection_id")
      .notNull()
      .references(() => providerConnectionsTable.id, { onDelete: "cascade" }),
    kind: text("kind").notNull(),
    status: text("status").notNull().default("queued"),
    idempotencyKey: text("idempotency_key").notNull(),
    attempts: integer("attempts").notNull().default(0),
    maxAttempts: integer("max_attempts").notNull().default(5),
    runAfter: timestamp("run_after", { withTimezone: true })
      .notNull()
      .defaultNow(),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    lastError: text("last_error"),
    metadata: jsonb("metadata")
      .$type<Record<string, string | number | boolean | null>>()
      .notNull()
      .default(sql`'{}'::jsonb`),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("connector_jobs_workspace_idempotency_idx").on(
      table.workspaceId,
      table.providerConnectionId,
      table.idempotencyKey,
    ),
    index("connector_jobs_claim_idx").on(table.status, table.runAfter),
    check(
      "connector_jobs_status_check",
      sql`${table.status} IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')`,
    ),
    pgPolicy("connector_jobs_select_scope", {
      for: "select",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
    }),
    pgPolicy("connector_jobs_insert_scope", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: tenantScope(table.workspaceId),
    }),
    pgPolicy("connector_jobs_update_scope", {
      for: "update",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
      withCheck: tenantScope(table.workspaceId),
    }),
    pgPolicy("connector_jobs_delete_scope", {
      for: "delete",
      to: appRuntimeRole,
      using: tenantScope(table.workspaceId),
    }),
  ],
).enableRLS();
