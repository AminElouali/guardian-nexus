import { sql, type SQLWrapper } from "drizzle-orm";
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
import { appRuntimeRole } from "./roles";
import { membershipsTable, workspacesTable } from "./workspaces";

function ownerAdminScope(workspaceId: SQLWrapper) {
  return sql`
    ${workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
    AND EXISTS (
      SELECT 1
      FROM ${membershipsTable} AS membership
      WHERE membership.workspaceId = ${workspaceId}
        AND membership.userId = NULLIF(current_setting('app.user_id', true), '')
        AND membership.role IN ('owner', 'admin')
    )
  `;
}

export const hostAttestationChallengesTable = pgTable(
  "host_boundary_attestation_challenges",
  {
    id: uuid("id").primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    nonceSha256: text("nonce_sha256").notNull(),
    runtimeCommit: text("runtime_commit").notNull(),
    runtimeDigestSha256: text("runtime_digest_sha256").notNull(),
    issuedByUserId: text("issued_by_user_id").notNull(),
    issuedAt: timestamp("issued_at", { withTimezone: true }).notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    consumedAt: timestamp("consumed_at", { withTimezone: true }),
    status: text("status").notNull().default("issued"),
    responseSha256: text("response_sha256"),
    supervisorId: text("supervisor_id"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (table) => [
    uniqueIndex("host_boundary_attestation_nonce_sha256_idx").on(
      table.nonceSha256,
    ),
    index("host_boundary_attestation_workspace_expiry_idx").on(
      table.workspaceId,
      table.expiresAt,
    ),
    check(
      "host_boundary_attestation_hashes_check",
      sql`${table.nonceSha256} ~ '^[a-f0-9]{64}$'
        AND ${table.runtimeDigestSha256} ~ '^[a-f0-9]{64}$'
        AND (${table.responseSha256} IS NULL OR ${table.responseSha256} ~ '^[a-f0-9]{64}$')
        AND ${table.runtimeCommit} ~ '^([a-f0-9]{40}|[a-f0-9]{64})$'`,
    ),
    check(
      "host_boundary_attestation_expiry_check",
      sql`${table.expiresAt} > ${table.issuedAt}`,
    ),
    check(
      "host_boundary_attestation_status_check",
      sql`
        (${table.status} = 'issued'
          AND ${table.consumedAt} IS NULL
          AND ${table.responseSha256} IS NULL
          AND ${table.supervisorId} IS NULL)
        OR (${table.status} IN ('verified', 'rejected', 'expired')
          AND ${table.consumedAt} IS NOT NULL)
      `,
    ),
    pgPolicy("host_boundary_attestation_select_owner", {
      for: "select",
      to: appRuntimeRole,
      using: ownerAdminScope(table.workspaceId),
    }),
    pgPolicy("host_boundary_attestation_insert_owner", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${ownerAdminScope(table.workspaceId)}
        AND ${table.issuedByUserId} = NULLIF(current_setting('app.user_id', true), '')
        AND ${table.status} = 'issued'
        AND ${table.consumedAt} IS NULL
        AND ${table.responseSha256} IS NULL
        AND ${table.supervisorId} IS NULL
      `,
    }),
    pgPolicy("host_boundary_attestation_update_owner", {
      for: "update",
      to: appRuntimeRole,
      using: sql`
        ${ownerAdminScope(table.workspaceId)}
        AND ${table.status} = 'issued'
        AND ${table.consumedAt} IS NULL
      `,
      withCheck: sql`
        ${ownerAdminScope(table.workspaceId)}
        AND ${table.status} IN ('verified', 'rejected', 'expired')
        AND ${table.consumedAt} IS NOT NULL
      `,
    }),
  ],
).enableRLS();

export type HostAttestationChallengeRow =
  typeof hostAttestationChallengesTable.$inferSelect;
