import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { CreateWorkspaceAiAssessmentLabJobResponse } from "@workspace/api-zod";
import {
  aiAssessmentJobsTable,
  withAiAssessmentQueueTransaction,
  workspaceAuditEventsTable,
  type AiAssessmentEvidence,
} from "@workspace/db";
import { withWorkspaceUserTransaction } from "./tenant-db";
import { logger } from "./logger";

const IMAGE = "guardian-ai-assessment:local";
const WORKER_VERSION = "guardian-ai-assessment-lab-0.2.0";
const MAX_RUNTIME_MS = 135_000;
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_ATTEMPTS = 2;
const LEASE_DURATION_MS = 45_000;
const HEARTBEAT_INTERVAL_MS = 10_000;
const QUEUE_POLL_INTERVAL_MS = 2_000;
const JOB_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type JobOwner = {
  jobId: string;
  workspaceId: string;
  actorUserId: string;
};

export type ClaimedJob = JobOwner & {
  attempts: number;
  leaseOwnerId: string;
  startedAt: Date;
};

export type ExhaustedJob = JobOwner & { attempts: number };
export type QueueClaim = { job: ClaimedJob | null; exhausted: ExhaustedJob[] };

let draining = false;
let queuePollTimer: NodeJS.Timeout | null = null;
let queueWorkerEnabled = false;

export type LocalWorkerAvailability = {
  status: "ready" | "unavailable" | "disabled";
  workerVersion: string;
  reasonCode: string | null;
};

export function getLocalWorkerAvailability(): LocalWorkerAvailability {
  if (
    process.env.NODE_ENV !== "development" ||
    process.env.REPLIT_DEPLOYMENT === "1"
  ) {
    return {
      status: "disabled",
      workerVersion: WORKER_VERSION,
      reasonCode: "development_only",
    };
  }

  try {
    const result = spawnSync("docker", ["image", "inspect", IMAGE], {
      stdio: "ignore",
      timeout: 2_000,
    });
    if (result.error?.message.includes("ENOENT")) {
      return {
        status: "unavailable",
        workerVersion: WORKER_VERSION,
        reasonCode: "docker_not_available",
      };
    }
    if (result.status !== 0) {
      return {
        status: "unavailable",
        workerVersion: WORKER_VERSION,
        reasonCode: "worker_image_not_built",
      };
    }
    return {
      status: "ready",
      workerVersion: WORKER_VERSION,
      reasonCode: null,
    };
  } catch {
    return {
      status: "unavailable",
      workerVersion: WORKER_VERSION,
      reasonCode: "docker_readiness_check_failed",
    };
  }
}

export function enqueueLocalAssessmentJob(_item: JobOwner): boolean {
  if (
    process.env.GUARDIAN_AI_ASSESSMENT_QUEUE_ENABLED === "false" ||
    getLocalWorkerAvailability().status !== "ready"
  ) {
    return false;
  }
  startLocalAssessmentQueueWorker();
  void drainQueue();
  return true;
}

export function startLocalAssessmentQueueWorker(): void {
  if (
    queuePollTimer ||
    process.env.GUARDIAN_AI_ASSESSMENT_QUEUE_ENABLED === "false" ||
    getLocalWorkerAvailability().status !== "ready"
  ) {
    return;
  }
  queueWorkerEnabled = true;
  queuePollTimer = setInterval(() => {
    void drainQueue();
  }, QUEUE_POLL_INTERVAL_MS);
  queuePollTimer.unref();
  void drainQueue();
}

export function isAiAssessmentJobRetryable(
  status: string,
  attempts: number,
): boolean {
  return status === "failed" && attempts < MAX_ATTEMPTS;
}

function dockerRunArgs(containerName: string): string[] {
  return [
    "run",
    "--rm",
    "--init",
    "--pull=never",
    `--name=${containerName}`,
    "--network=none",
    "--read-only",
    "--cpus=0.5",
    "--memory=768m",
    "--memory-swap=768m",
    "--pids-limit=64",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges",
    "--user=65532:65532",
    "--log-driver=none",
    "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
    IMAGE,
  ];
}

function getContainerName(jobId: string): string {
  if (!JOB_ID_PATTERN.test(jobId)) {
    throw new Error("invalid_assessment_job_id");
  }
  return `guardian-ai-lab-${jobId}`;
}

function killDockerContainer(jobId: string): void {
  const killer = spawn(
    "docker",
    ["kill", "--signal=KILL", getContainerName(jobId)],
    {
      stdio: "ignore",
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? "/tmp",
      },
    },
  );
  killer.on("error", () => undefined);
}

function runDockerAssessment(jobId: string): Promise<AiAssessmentEvidence> {
  const containerName = getContainerName(jobId);
  const staleContainerCleanup = spawnSync(
    "docker",
    ["rm", "--force", containerName],
    {
      stdio: "ignore",
      timeout: 3_000,
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? "/tmp",
      },
    },
  );
  if (staleContainerCleanup.error) {
    return Promise.reject(
      new Error(
        staleContainerCleanup.error.message.includes("ENOENT")
          ? "docker_not_available"
          : "docker_cleanup_failed",
      ),
    );
  }
  return new Promise((resolve, reject) => {
    let stdout = "";
    let stdoutBytes = 0;
    let timedOut = false;
    const child = spawn("docker", dockerRunArgs(containerName), {
      stdio: ["ignore", "pipe", "ignore"],
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        HOME: process.env.HOME ?? "/tmp",
      },
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      killDockerContainer(jobId);
      child.kill("SIGKILL");
    }, MAX_RUNTIME_MS);

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        child.kill("SIGKILL");
        return;
      }
      stdout += chunk.toString("utf8");
    });
    child.on("error", () => {
      clearTimeout(timeout);
      reject(new Error("docker_not_available"));
    });
    child.on("close", (code) => {
      clearTimeout(timeout);
      if (timedOut) {
        reject(new Error("worker_timeout"));
        return;
      }
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        reject(new Error("worker_output_limit_exceeded"));
        return;
      }
      if (code !== 0) {
        let workerErrorCode = "container_execution_failed";
        try {
          const lastLine = stdout.trim().split("\n").at(-1);
          const parsed = lastLine ? JSON.parse(lastLine) as { errorCode?: unknown } : {};
          if (
            typeof parsed.errorCode === "string" &&
            /^[a-z0-9_]{1,64}$/.test(parsed.errorCode)
          ) {
            workerErrorCode = parsed.errorCode;
          }
        } catch {
          // Do not persist raw container output or stderr.
        }
        reject(new Error(workerErrorCode));
        return;
      }

      try {
        const output = JSON.parse(stdout.trim()) as unknown;
        const parsedResult =
          CreateWorkspaceAiAssessmentLabJobResponse.shape.result.safeParse(
            output,
          );
        if (!parsedResult.success || parsedResult.data === null) {
          reject(new Error("worker_output_invalid"));
          return;
        }
        const parsedEvidence = parsedResult.data;
        const evidence: AiAssessmentEvidence = {
          ...parsedEvidence,
          startedAt: parsedEvidence.startedAt.toISOString(),
          completedAt: parsedEvidence.completedAt.toISOString(),
        };
        if (
          evidence.source !== "isolated_local_lab" ||
          evidence.profileId !== "guardian-local-agent-v1" ||
          evidence.engineVersion !== "0.17.1" ||
          evidence.probeRequests !== 1 ||
          evidence.network.networkMode !== "docker-network-none" ||
          evidence.network.publicIpv4 !== "blocked" ||
          !["blocked", "unavailable"].includes(evidence.network.publicIpv6) ||
          evidence.network.publicDns !== "blocked" ||
          !evidence.network.loopbackOnly ||
          evidence.network.activeNonLoopbackInterfaces.length > 0 ||
          evidence.externalCalls !== 0 ||
          evidence.customerDataUsed
        ) {
          reject(new Error("worker_evidence_failed_validation"));
          return;
        }
        resolve(evidence);
      } catch {
        reject(new Error("worker_output_invalid"));
      }
    });
  });
}

async function updateJob(
  item: ClaimedJob,
  update: {
    status: "succeeded" | "failed";
    result?: AiAssessmentEvidence | null;
    engineVersion?: string | null;
    errorCode?: string | null;
    auditAction?: string;
  },
): Promise<boolean> {
  const access = await withWorkspaceUserTransaction(
    item.actorUserId,
    item.workspaceId,
    async (tx, membership) => {
      if (membership.role !== "owner" && membership.role !== "admin") return false;
      const [updated] = await tx
        .update(aiAssessmentJobsTable)
        .set({
          status: update.status,
          result: update.result,
          engineVersion: update.engineVersion,
          errorCode: update.errorCode,
          leaseOwnerId: null,
          leaseExpiresAt: null,
          heartbeatAt: null,
          workerSlot: null,
          completedAt: new Date(),
          updatedAt: new Date(),
        })
        .where(
          sql`
            ${aiAssessmentJobsTable.id} = ${item.jobId}
            AND ${aiAssessmentJobsTable.workspaceId} = ${item.workspaceId}
            AND ${aiAssessmentJobsTable.status} = 'running'
            AND ${aiAssessmentJobsTable.leaseOwnerId} = ${item.leaseOwnerId}
          `,
        )
        .returning({ id: aiAssessmentJobsTable.id });
      if (!updated) return false;
      if (update.auditAction) {
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId: item.workspaceId,
          actorUserId: item.actorUserId,
          action: update.auditAction,
          resourceType: "ai_assessment_job",
          resourceId: item.jobId,
          metadata: {
            profileId: "guardian-local-agent-v1",
            status: update.status,
            attempts: item.attempts,
            errorCode: update.errorCode ?? null,
            engineVersion: update.engineVersion ?? null,
          },
        });
      }
      return true;
    },
  );
  return access.authorized && access.value;
}

type QueueCandidate = {
  jobId: string;
  workspaceId: string;
  actorUserId: string;
  status: "queued" | "running";
  attempts: number;
  startedAt: Date | null;
};

function getDatabaseErrorCode(error: unknown): string | null {
  if (typeof error !== "object" || error === null) return null;
  const record = error as { code?: unknown; cause?: { code?: unknown } };
  const code = record.code ?? record.cause?.code;
  return typeof code === "string" ? code : null;
}

export async function claimNextAssessmentJob(): Promise<QueueClaim> {
  const leaseOwnerId = randomUUID();
  try {
    return await withAiAssessmentQueueTransaction(leaseOwnerId, async (tx) => {
      const exhausted: ExhaustedJob[] = [];
      for (let index = 0; index < 16; index += 1) {
        const active = await tx.execute(sql`
          SELECT id
          FROM public.ai_assessment_jobs
          WHERE status = 'running' AND lease_expires_at > now()
          LIMIT 1
        `);
        if (active.rows.length > 0) return { job: null, exhausted };

        const candidates = await tx.execute(sql`
          SELECT
            id::text AS "jobId",
            workspace_id::text AS "workspaceId",
            requested_by_user_id AS "actorUserId",
            status,
            attempts,
            started_at AS "startedAt"
          FROM public.ai_assessment_jobs
          WHERE status = 'queued'
             OR (
               status = 'running'
               AND (lease_expires_at IS NULL OR lease_expires_at <= now())
             )
          ORDER BY created_at ASC
          LIMIT 1
          FOR UPDATE SKIP LOCKED
        `);
        const candidate = candidates.rows[0] as QueueCandidate | undefined;
        if (!candidate) return { job: null, exhausted };

        const owner: JobOwner = {
          jobId: candidate.jobId,
          workspaceId: candidate.workspaceId,
          actorUserId: candidate.actorUserId,
        };
        if (candidate.attempts >= MAX_ATTEMPTS) {
          await tx.execute(sql`
            UPDATE public.ai_assessment_jobs
            SET status = 'failed',
                error_code = 'worker_lease_expired',
                completed_at = now(),
                lease_owner_id = NULL,
                lease_expires_at = NULL,
                heartbeat_at = NULL,
                worker_slot = NULL,
                updated_at = now()
            WHERE id = ${candidate.jobId}::uuid
          `);
          exhausted.push({ ...owner, attempts: candidate.attempts });
          continue;
        }

        const attempts = candidate.attempts + 1;
        const startedAt = candidate.startedAt ?? new Date();
        const claimed = await tx.execute(sql`
          UPDATE public.ai_assessment_jobs
          SET status = 'running',
              attempts = ${attempts},
              lease_owner_id = ${leaseOwnerId}::uuid,
              lease_expires_at = now() + (${LEASE_DURATION_MS} * interval '1 millisecond'),
              heartbeat_at = now(),
              worker_slot = 1,
              started_at = COALESCE(started_at, ${startedAt}),
              completed_at = NULL,
              error_code = NULL,
              updated_at = now()
          WHERE id = ${candidate.jobId}::uuid
          RETURNING id
        `);
        if (claimed.rows.length !== 1) continue;
        return {
          job: {
            ...owner,
            attempts,
            leaseOwnerId,
            startedAt,
          },
          exhausted,
        };
      }
      return { job: null, exhausted };
    });
  } catch (error) {
    if (getDatabaseErrorCode(error) === "23505") {
      return { job: null, exhausted: [] };
    }
    throw error;
  }
}

export async function renewAssessmentJobLease(item: ClaimedJob): Promise<boolean> {
  return withAiAssessmentQueueTransaction(item.leaseOwnerId, async (tx) => {
    const result = await tx.execute(sql`
      UPDATE public.ai_assessment_jobs
      SET lease_expires_at = now() + (${LEASE_DURATION_MS} * interval '1 millisecond'),
          heartbeat_at = now(),
          updated_at = now()
      WHERE id = ${item.jobId}::uuid
        AND status = 'running'
        AND lease_owner_id = ${item.leaseOwnerId}::uuid
      RETURNING id
    `);
    return result.rows.length === 1;
  });
}

async function failClaimedJob(
  item: ClaimedJob,
  errorCode: string,
): Promise<void> {
  await withAiAssessmentQueueTransaction(item.leaseOwnerId, async (tx) => {
    await tx.execute(sql`
      UPDATE public.ai_assessment_jobs
      SET status = 'failed',
          error_code = ${errorCode},
          completed_at = now(),
          lease_owner_id = NULL,
          lease_expires_at = NULL,
          heartbeat_at = NULL,
          worker_slot = NULL,
          updated_at = now()
      WHERE id = ${item.jobId}::uuid
        AND status = 'running'
        AND lease_owner_id = ${item.leaseOwnerId}::uuid
    `);
  });
}

async function recordLeaseExhaustedAudit(item: ExhaustedJob): Promise<void> {
  await withWorkspaceUserTransaction(
    item.actorUserId,
    item.workspaceId,
    async (tx, membership) => {
      if (membership.role !== "owner" && membership.role !== "admin") return;
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId: item.workspaceId,
        actorUserId: item.actorUserId,
        action: "ai_assessment.lab.lease_expired",
        resourceType: "ai_assessment_job",
        resourceId: item.jobId,
        metadata: {
          status: "failed",
          attempts: item.attempts,
          maxAttempts: MAX_ATTEMPTS,
        },
      });
    },
  );
}

async function processJob(item: ClaimedJob): Promise<void> {
  const access = await withWorkspaceUserTransaction(
    item.actorUserId,
    item.workspaceId,
    async (tx, membership) => {
      if (membership.role !== "owner" && membership.role !== "admin") {
        return false;
      }
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId: item.workspaceId,
        actorUserId: item.actorUserId,
        action:
          item.attempts > 1
            ? "ai_assessment.lab.recovered"
            : "ai_assessment.lab.started",
        resourceType: "ai_assessment_job",
        resourceId: item.jobId,
        metadata: {
          profileId: "guardian-local-agent-v1",
          workerVersion: WORKER_VERSION,
          attempt: item.attempts,
        },
      });
      return true;
    },
  );
  if (!access.authorized || !access.value) {
    await failClaimedJob(item, "workspace_authorization_lost");
    return;
  }

  let leaseLost = false;
  let heartbeatInFlight = false;
  const heartbeat = setInterval(() => {
    if (leaseLost || heartbeatInFlight) return;
    heartbeatInFlight = true;
    void renewAssessmentJobLease(item)
      .then((renewed) => {
        if (!renewed) {
          leaseLost = true;
          killDockerContainer(item.jobId);
        }
      })
      .catch(() => {
        leaseLost = true;
        killDockerContainer(item.jobId);
      })
      .finally(() => {
        heartbeatInFlight = false;
      });
  }, HEARTBEAT_INTERVAL_MS);
  heartbeat.unref();

  try {
    const evidence = await runDockerAssessment(item.jobId);
    if (leaseLost) return;
    const saved = await updateJob(item, {
      status: "succeeded",
      result: evidence,
      engineVersion: evidence.engineVersion,
      errorCode: null,
      auditAction: "ai_assessment.lab.completed",
    });
    if (!saved) killDockerContainer(item.jobId);
  } catch (error) {
    if (leaseLost) return;
    const rawCode = error instanceof Error ? error.message : "worker_failed";
    const errorCode = /^[a-z0-9_]{1,64}$/.test(rawCode)
      ? rawCode
      : "worker_failed";
    await updateJob(item, {
      status: "failed",
      result: null,
      engineVersion: null,
      errorCode,
      auditAction: "ai_assessment.lab.failed",
    });
  } finally {
    clearInterval(heartbeat);
  }
}

async function drainQueue(): Promise<void> {
  if (draining || !queueWorkerEnabled) return;
  draining = true;
  try {
    const claim = await claimNextAssessmentJob();
    for (const exhausted of claim.exhausted) {
      await recordLeaseExhaustedAudit(exhausted);
    }
    if (claim.job) await processJob(claim.job);
  } catch {
    logger.error(
      { errorCode: "assessment_queue_tick_failed" },
      "Durable assessment queue tick failed",
    );
  } finally {
    draining = false;
  }
}

export const AI_ASSESSMENT_JOB_MAX_ATTEMPTS = MAX_ATTEMPTS;
