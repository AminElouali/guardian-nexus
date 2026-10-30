import { spawn, spawnSync } from "node:child_process";
import { and, eq } from "drizzle-orm";
import { CreateWorkspaceAiAssessmentLabJobResponse } from "@workspace/api-zod";
import {
  aiAssessmentJobsTable,
  workspaceAuditEventsTable,
  type AiAssessmentEvidence,
} from "@workspace/db";
import { withWorkspaceUserTransaction } from "./tenant-db";

const IMAGE = "guardian-ai-assessment:local";
const WORKER_VERSION = "guardian-ai-assessment-lab-0.1.0";
const MAX_RUNTIME_MS = 135_000;
const MAX_STDOUT_BYTES = 64 * 1024;
const MAX_QUEUE_SIZE = 32;
const MAX_ATTEMPTS = 2;

type QueueItem = {
  jobId: string;
  workspaceId: string;
  actorUserId: string;
};

const queue: QueueItem[] = [];
const queuedIds = new Set<string>();
let draining = false;

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

export function enqueueLocalAssessmentJob(item: QueueItem): boolean {
  if (queuedIds.has(item.jobId)) return true;
  if (queue.length >= MAX_QUEUE_SIZE) return false;
  queue.push(item);
  queuedIds.add(item.jobId);
  void drainQueue();
  return true;
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

function runDockerAssessment(jobId: string): Promise<AiAssessmentEvidence> {
  const containerName = `guardian-ai-lab-${jobId}`;
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
      const killer = spawn("docker", ["kill", "--signal=KILL", containerName], {
        stdio: "ignore",
        env: {
          PATH: process.env.PATH ?? "/usr/bin:/bin",
          HOME: process.env.HOME ?? "/tmp",
        },
      });
      killer.on("error", () => undefined);
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
  item: QueueItem,
  update: {
    status: "running" | "succeeded" | "failed";
    attempts?: number;
    result?: AiAssessmentEvidence | null;
    engineVersion?: string | null;
    errorCode?: string | null;
    startedAt?: Date | null;
    completedAt?: Date | null;
    leaseExpiresAt?: Date | null;
    auditAction?: string;
  },
): Promise<void> {
  const access = await withWorkspaceUserTransaction(
    item.actorUserId,
    item.workspaceId,
    async (tx, membership) => {
      if (membership.role !== "owner" && membership.role !== "admin") return false;
      await tx
        .update(aiAssessmentJobsTable)
        .set({
          status: update.status,
          attempts: update.attempts,
          result: update.result,
          engineVersion: update.engineVersion,
          errorCode: update.errorCode,
          startedAt: update.startedAt,
          completedAt: update.completedAt,
          leaseExpiresAt: update.leaseExpiresAt,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(aiAssessmentJobsTable.id, item.jobId),
            eq(aiAssessmentJobsTable.workspaceId, item.workspaceId),
          ),
        );
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
            attempts: update.attempts ?? 0,
            errorCode: update.errorCode ?? null,
            engineVersion: update.engineVersion ?? null,
          },
        });
      }
      return true;
    },
  );
  if (!access.authorized || !access.value) {
    throw new Error("job_workspace_authorization_lost");
  }
}

async function processJob(item: QueueItem): Promise<void> {
  const access = await withWorkspaceUserTransaction(
    item.actorUserId,
    item.workspaceId,
    async (tx, membership) => {
      if (membership.role !== "owner" && membership.role !== "admin") return null;
      const [job] = await tx
        .select()
        .from(aiAssessmentJobsTable)
        .where(
          and(
            eq(aiAssessmentJobsTable.id, item.jobId),
            eq(aiAssessmentJobsTable.workspaceId, item.workspaceId),
            eq(aiAssessmentJobsTable.status, "queued"),
          ),
        )
        .limit(1);
      if (!job || job.attempts >= MAX_ATTEMPTS) return null;
      const startedAt = new Date();
      const attempts = job.attempts + 1;
      await tx
        .update(aiAssessmentJobsTable)
        .set({
          status: "running",
          attempts,
          startedAt,
          completedAt: null,
          leaseExpiresAt: new Date(startedAt.getTime() + MAX_RUNTIME_MS + 15_000),
          errorCode: null,
          result: null,
          updatedAt: startedAt,
        })
        .where(eq(aiAssessmentJobsTable.id, job.id));
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId: item.workspaceId,
        actorUserId: item.actorUserId,
        action: "ai_assessment.lab.started",
        resourceType: "ai_assessment_job",
        resourceId: item.jobId,
        metadata: {
          profileId: "guardian-local-agent-v1",
          workerVersion: WORKER_VERSION,
          attempt: attempts,
        },
      });
      return { attempts, startedAt };
    },
  );
  if (!access.authorized || !access.value) return;

  try {
    const evidence = await runDockerAssessment(item.jobId);
    await updateJob(item, {
      status: "succeeded",
      attempts: access.value.attempts,
      result: evidence,
      engineVersion: evidence.engineVersion,
      errorCode: null,
      startedAt: access.value.startedAt,
      completedAt: new Date(),
      leaseExpiresAt: null,
      auditAction: "ai_assessment.lab.completed",
    });
  } catch (error) {
    const rawCode = error instanceof Error ? error.message : "worker_failed";
    const errorCode = /^[a-z0-9_]{1,64}$/.test(rawCode)
      ? rawCode
      : "worker_failed";
    await updateJob(item, {
      status: "failed",
      attempts: access.value.attempts,
      result: null,
      engineVersion: null,
      errorCode,
      startedAt: access.value.startedAt,
      completedAt: new Date(),
      leaseExpiresAt: null,
      auditAction: "ai_assessment.lab.failed",
    });
  }
}

async function drainQueue(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    while (queue.length > 0) {
      const item = queue.shift();
      if (!item) continue;
      queuedIds.delete(item.jobId);
      try {
        await processJob(item);
      } catch {
        // Durable queued/running state is recovered by the tenant-scoped list
        // endpoint after the lease expires; never crash the API on job failure.
      }
    }
  } finally {
    draining = false;
    if (queue.length > 0) void drainQueue();
  }
}

export const AI_ASSESSMENT_JOB_MAX_ATTEMPTS = MAX_ATTEMPTS;
