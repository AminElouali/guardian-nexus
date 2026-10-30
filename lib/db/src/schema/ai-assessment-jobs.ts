import { sql, type SQLWrapper } from "drizzle-orm";
import {
  check,
  index,
  integer,
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

export type AiAssessmentEvidence = {
  evidenceVersion: 1;
  source: "isolated_local_lab";
  engine: "garak";
  engineVersion: string;
  profileId: "guardian-local-agent-v1";
  probeClasses: string[];
  generationsPerProbe: 1;
  probeRequests: 1;
  reportRecordCount: number;
  reportRecordTypes: Record<string, number>;
  positiveDetectorScores: number;
  findings: Array<{
    probeClass: string;
    detector: string;
    positiveScores: number;
  }>;
  reportSha256: string;
  reportBytes: number;
  network: {
    networkMode: "docker-network-none";
    interfaces: string[];
    activeNonLoopbackInterfaces: string[];
    publicIpv4: "blocked";
    publicIpv6: "blocked";
    publicDns: "blocked";
    loopbackOnly: true;
  };
  startedAt: string;
  completedAt: string;
  durationSeconds: number;
  promptsStored: false;
  responsesStored: false;
  externalCalls: 0;
  customerDataUsed: false;
  findingSummary: string;
};

const memberScope = (workspaceId: SQLWrapper) => sql`
  ${workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
  AND EXISTS (
    SELECT 1
    FROM "workspace_memberships" AS membership
    WHERE membership."workspace_id" = ${workspaceId}
      AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
  )
`;

const ownerOrAdminScope = (workspaceId: SQLWrapper) => sql`
  ${memberScope(workspaceId)}
  AND EXISTS (
    SELECT 1
    FROM "workspace_memberships" AS membership
    WHERE membership."workspace_id" = ${workspaceId}
      AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
      AND membership."role" IN ('owner', 'admin')
  )
`;

export const aiAssessmentJobsTable = pgTable(
  "ai_assessment_jobs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    requestedByUserId: text("requested_by_user_id").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    profileId: text("profile_id").notNull().default("guardian-local-agent-v1"),
    status: text("status").notNull().default("queued"),
    attempts: integer("attempts").notNull().default(0),
    workerVersion: text("worker_version")
      .notNull()
      .default("guardian-ai-assessment-lab-0.1.0"),
    engineVersion: text("engine_version"),
    result: jsonb("result").$type<AiAssessmentEvidence>(),
    errorCode: text("error_code"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("ai_assessment_jobs_workspace_idempotency_idx").on(
      table.workspaceId,
      table.idempotencyKey,
    ),
    index("ai_assessment_jobs_workspace_created_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
    index("ai_assessment_jobs_status_lease_idx").on(
      table.status,
      table.leaseExpiresAt,
    ),
    check(
      "ai_assessment_jobs_status_check",
      sql`${table.status} IN ('queued', 'running', 'succeeded', 'failed')`,
    ),
    check(
      "ai_assessment_jobs_profile_check",
      sql`${table.profileId} = 'guardian-local-agent-v1'`,
    ),
    check(
      "ai_assessment_jobs_attempts_check",
      sql`${table.attempts} BETWEEN 0 AND 2`,
    ),
    pgPolicy("ai_assessment_jobs_select_member", {
      for: "select",
      to: appRuntimeRole,
      using: memberScope(table.workspaceId),
    }),
    pgPolicy("ai_assessment_jobs_insert_owner", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${ownerOrAdminScope(table.workspaceId)}
        AND ${table.requestedByUserId} = NULLIF(current_setting('app.user_id', true), '')
      `,
    }),
    pgPolicy("ai_assessment_jobs_update_owner", {
      for: "update",
      to: appRuntimeRole,
      using: ownerOrAdminScope(table.workspaceId),
      withCheck: ownerOrAdminScope(table.workspaceId),
    }),
  ],
).enableRLS();

export type AiAssessmentJob = typeof aiAssessmentJobsTable.$inferSelect;
