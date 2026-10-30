import { and, eq, inArray, lte, or, sql } from "drizzle-orm";
import {
  connectorJobsTable,
  providerConnectionsTable,
} from "@workspace/db";
import { withWorkspaceUserTransaction } from "./tenant-db";
import { reserveWorkspaceUsageInTransaction } from "./usage";

export class ProviderRateLimitError extends Error {
  constructor(public readonly retryAfterSeconds: number) {
    super(`Provider request throttled; retry after ${retryAfterSeconds} seconds.`);
    this.name = "ProviderRateLimitError";
  }
}

export function parseRetryAfter(
  value: string | null | undefined,
  now = Date.now(),
): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.max(1, Math.ceil(seconds));
  }
  const date = Date.parse(value);
  if (!Number.isFinite(date)) return undefined;
  return Math.max(1, Math.ceil((date - now) / 1000));
}

export function retryDelaySeconds(
  attempts: number,
  retryAfterSeconds?: number,
): number {
  const exponential = Math.min(3600, 2 ** Math.min(Math.max(attempts, 1), 12));
  return Math.max(exponential, retryAfterSeconds ?? 0);
}

export async function reserveProviderRequest(
  userId: string,
  workspaceId: string,
  connectionId: string,
): Promise<void> {
  const now = new Date();
  const nextAllowed = new Date(now.getTime() + 1_000);
  const result = await withWorkspaceUserTransaction(
    userId,
    workspaceId,
    async (tx) => {
      const [reserved] = await tx
        .update(providerConnectionsTable)
        .set({ nextProviderRequestAt: nextAllowed, updatedAt: now })
        .where(
          and(
            eq(providerConnectionsTable.id, connectionId),
            inArray(providerConnectionsTable.status, ["pending", "active"]),
            or(
              sql`${providerConnectionsTable.nextProviderRequestAt} IS NULL`,
              lte(providerConnectionsTable.nextProviderRequestAt, now),
            ),
          ),
        )
        .returning({ id: providerConnectionsTable.id });
      if (reserved) return { allowed: true as const };

      const [current] = await tx
        .select({ nextAt: providerConnectionsTable.nextProviderRequestAt })
        .from(providerConnectionsTable)
        .where(
          and(
            eq(providerConnectionsTable.id, connectionId),
            inArray(providerConnectionsTable.status, ["pending", "active"]),
          ),
        )
        .limit(1);
      if (!current) return { allowed: false as const, retryAfter: 1 };
      return {
        allowed: false as const,
        retryAfter: Math.max(
          1,
          Math.ceil(((current.nextAt?.getTime() ?? now.getTime()) - now.getTime()) / 1000),
        ),
      };
    },
  );
  if (!result.authorized) throw new Error("Workspace access denied");
  if (!result.value.allowed) {
    throw new ProviderRateLimitError(result.value.retryAfter);
  }
}

export async function enqueueConnectorJob(input: {
  userId: string;
  workspaceId: string;
  connectionId: string;
  kind: string;
  idempotencyKey: string;
  metadata?: Record<string, string | number | boolean | null>;
}) {
  if (!/^[\w:.-]{8,128}$/.test(input.idempotencyKey)) {
    throw new Error("A valid idempotency key is required.");
  }
  const result = await withWorkspaceUserTransaction(
    input.userId,
    input.workspaceId,
    async (tx) => {
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(hashtextextended(${`${input.workspaceId}:${input.connectionId}:${input.idempotencyKey}`}, 0))`,
      );
      const [racedExisting] = await tx
        .select()
        .from(connectorJobsTable)
        .where(
          and(
            eq(connectorJobsTable.workspaceId, input.workspaceId),
            eq(connectorJobsTable.providerConnectionId, input.connectionId),
            eq(connectorJobsTable.idempotencyKey, input.idempotencyKey),
          ),
        )
        .limit(1);
      if (racedExisting) return { kind: "existing" as const, job: racedExisting };

      const [connection] = await tx
        .select({ id: providerConnectionsTable.id })
        .from(providerConnectionsTable)
        .where(
          and(
            eq(providerConnectionsTable.id, input.connectionId),
            eq(providerConnectionsTable.status, "active"),
          ),
        )
        .limit(1);
      if (!connection) return { kind: "not-authorized" as const };

      await reserveWorkspaceUsageInTransaction(tx, input.workspaceId, {
        scans: 1,
      });
      const [job] = await tx
        .insert(connectorJobsTable)
        .values({
          workspaceId: input.workspaceId,
          providerConnectionId: input.connectionId,
          kind: input.kind,
          idempotencyKey: input.idempotencyKey,
          metadata: input.metadata ?? {},
        })
        .onConflictDoNothing({
          target: [
            connectorJobsTable.workspaceId,
            connectorJobsTable.providerConnectionId,
            connectorJobsTable.idempotencyKey,
          ],
        })
        .returning();
      if (job) return { kind: "created" as const, job };
      const [duplicate] = await tx
        .select()
        .from(connectorJobsTable)
        .where(
          and(
            eq(connectorJobsTable.workspaceId, input.workspaceId),
            eq(connectorJobsTable.providerConnectionId, input.connectionId),
            eq(connectorJobsTable.idempotencyKey, input.idempotencyKey),
          ),
        )
        .limit(1);
      return duplicate
        ? { kind: "existing" as const, job: duplicate }
        : { kind: "not-authorized" as const };
    },
  );
  if (!result.authorized) throw new Error("Workspace access denied");
  return result.value;
}

export async function rescheduleConnectorJob(input: {
  userId: string;
  workspaceId: string;
  jobId: string;
  retryAfter?: string | null;
  errorCode: string;
}) {
  const result = await withWorkspaceUserTransaction(
    input.userId,
    input.workspaceId,
    async (tx) => {
      const [job] = await tx
        .select()
        .from(connectorJobsTable)
        .where(
          and(
            eq(connectorJobsTable.id, input.jobId),
            eq(connectorJobsTable.workspaceId, input.workspaceId),
            eq(connectorJobsTable.status, "running"),
          ),
        )
        .for("update")
        .limit(1);
      if (!job) return undefined;
      const [connection] = await tx
        .select({ status: providerConnectionsTable.status })
        .from(providerConnectionsTable)
        .where(eq(providerConnectionsTable.id, job.providerConnectionId))
        .limit(1);
      if (connection?.status !== "active") {
        const [cancelled] = await tx
          .update(connectorJobsTable)
          .set({ status: "cancelled", leaseExpiresAt: null, updatedAt: new Date() })
          .where(eq(connectorJobsTable.id, job.id))
          .returning();
        return cancelled;
      }
      const nextAttempt = job.attempts + 1;
      const exhausted = nextAttempt >= job.maxAttempts;
      const delay = retryDelaySeconds(
        nextAttempt,
        parseRetryAfter(input.retryAfter),
      );
      const [updated] = await tx
        .update(connectorJobsTable)
        .set({
          attempts: nextAttempt,
          status: exhausted ? "failed" : "queued",
          runAfter: new Date(Date.now() + delay * 1_000),
          lastError: /^[A-Za-z0-9_.-]{1,80}$/.test(input.errorCode)
            ? input.errorCode
            : "provider_error",
          leaseExpiresAt: null,
          updatedAt: new Date(),
        })
        .where(eq(connectorJobsTable.id, job.id))
        .returning();
      return updated;
    },
  );
  if (!result.authorized) throw new Error("Workspace access denied");
  return result.value;
}
