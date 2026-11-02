import { and, desc, eq, sql } from "drizzle-orm";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  CreateWorkspaceAiAssessmentLabJobBody,
  CreateWorkspaceAiAssessmentLabJobParams,
  CreateWorkspaceAiAssessmentLabJobResponse,
  GetWorkspaceAiAssessmentLabAvailabilityParams,
  GetWorkspaceAiAssessmentLabAvailabilityResponse,
  ListWorkspaceAiAssessmentLabJobsParams,
  ListWorkspaceAiAssessmentLabJobsResponse,
  RetryWorkspaceAiAssessmentLabJobParams,
  RetryWorkspaceAiAssessmentLabJobResponse,
} from "@workspace/api-zod";
import {
  aiAssessmentJobsTable,
  workspaceAuditEventsTable,
  type AiAssessmentJob,
} from "@workspace/db";
import { canRunAiEvaluation } from "../lib/access-control";
import {
  AI_ASSESSMENT_JOB_MAX_ATTEMPTS,
  AI_ASSESSMENT_WORKER_VERSION,
  GARAK_PROFILE_ID,
  isAssessmentProfileAvailable,
  enqueueLocalAssessmentJob,
  getLocalWorkerAvailability,
  isAiAssessmentJobRetryable,
  type AssessmentProfileId,
} from "../lib/ai-assessment-worker";
import { withWorkspaceUserTransaction } from "../lib/tenant-db";
import { UsageQuotaError, reserveWorkspaceUsageInTransaction } from "../lib/usage";
import { requireAuth } from "../middlewares/requireAuth";

const routes: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_HISTORY = 20;
const MAX_PENDING_PER_WORKSPACE = 3;

function formatJob(job: AiAssessmentJob) {
  return CreateWorkspaceAiAssessmentLabJobResponse.parse({
    id: job.id,
    status: job.status,
    profileId: job.profileId,
    workerVersion: job.workerVersion,
    attempts: job.attempts,
    engineVersion: job.engineVersion,
    result: job.result,
    errorCode: job.errorCode,
    createdAt: job.createdAt,
    startedAt: job.startedAt,
    completedAt: job.completedAt,
  });
}

routes.get(
  "/workspaces/:workspaceId/ai-security-assessments/lab/availability",
  async (req, res): Promise<void> => {
    const params = GetWorkspaceAiAssessmentLabAvailabilityParams.safeParse(
      req.params,
    );
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async () => true,
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(
      GetWorkspaceAiAssessmentLabAvailabilityResponse.parse(
        getLocalWorkerAvailability(),
      ),
    );
  },
);

routes.get(
  "/workspaces/:workspaceId/ai-security-assessments/lab/jobs",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceAiAssessmentLabJobsParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const { workspaceId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        const jobs = await tx
          .select()
          .from(aiAssessmentJobsTable)
          .where(eq(aiAssessmentJobsTable.workspaceId, workspaceId))
          .orderBy(desc(aiAssessmentJobsTable.createdAt))
          .limit(MAX_HISTORY);
        return { jobs, canRun: canRunAiEvaluation(membership.role) };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(
      ListWorkspaceAiAssessmentLabJobsResponse.parse(
        access.value.jobs.map(formatJob),
      ),
    );
  },
);

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/lab/jobs",
  async (req, res): Promise<void> => {
    const params = CreateWorkspaceAiAssessmentLabJobParams.safeParse(req.params);
    const body = CreateWorkspaceAiAssessmentLabJobBody.safeParse(req.body);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !body.success
    ) {
      res.status(400).json({ error: "Invalid laboratory assessment request" });
      return;
    }
    const profileId = body.data.profileId ?? GARAK_PROFILE_ID;
    if (!isAssessmentProfileAvailable(profileId)) {
      res.status(503).json({
        error: "Requested isolated local assessment profile is unavailable",
      });
      return;
    }

    const { workspaceId } = params.data;
    try {
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        workspaceId,
        async (tx, membership) => {
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }
          const [existing] = await tx
            .select()
            .from(aiAssessmentJobsTable)
            .where(
              and(
                eq(aiAssessmentJobsTable.workspaceId, workspaceId),
                eq(
                  aiAssessmentJobsTable.idempotencyKey,
                  body.data.idempotencyKey,
                ),
              ),
            )
            .limit(1);
          if (existing) {
            return existing.profileId === profileId
              ? { kind: "existing" as const, job: existing }
              : { kind: "idempotency_conflict" as const };
          }

          const pending = await tx
            .select({ id: aiAssessmentJobsTable.id })
            .from(aiAssessmentJobsTable)
            .where(
              and(
                eq(aiAssessmentJobsTable.workspaceId, workspaceId),
                sql`${aiAssessmentJobsTable.status} IN ('queued', 'running')`,
              ),
            )
            .limit(MAX_PENDING_PER_WORKSPACE);
          if (pending.length >= MAX_PENDING_PER_WORKSPACE) {
            return { kind: "queue_full" as const };
          }

          const [inserted] = await tx
            .insert(aiAssessmentJobsTable)
            .values({
              workspaceId,
              requestedByUserId: req.authUserId!,
              idempotencyKey: body.data.idempotencyKey,
              profileId,
              workerVersion: AI_ASSESSMENT_WORKER_VERSION,
              status: "queued",
            })
            .onConflictDoNothing({
              target: [
                aiAssessmentJobsTable.workspaceId,
                aiAssessmentJobsTable.idempotencyKey,
              ],
            })
            .returning();
          if (!inserted) {
            const [raced] = await tx
              .select()
              .from(aiAssessmentJobsTable)
              .where(
                and(
                  eq(aiAssessmentJobsTable.workspaceId, workspaceId),
                  eq(
                    aiAssessmentJobsTable.idempotencyKey,
                    body.data.idempotencyKey,
                  ),
                ),
              )
              .limit(1);
            return raced
              ? raced.profileId === profileId
                ? { kind: "existing" as const, job: raced }
                : { kind: "idempotency_conflict" as const }
              : { kind: "queue_full" as const };
          }

          await reserveWorkspaceUsageInTransaction(tx, workspaceId, {
            scans: 1,
            apiRequests: 1,
          });
          await tx.insert(workspaceAuditEventsTable).values({
            workspaceId,
            actorUserId: req.authUserId!,
            action: "ai_assessment.lab.requested",
            resourceType: "ai_assessment_job",
            resourceId: inserted.id,
            metadata: {
              profileId: inserted.profileId,
              workerVersion: inserted.workerVersion,
              environment: "development_lab",
            },
          });
          return { kind: "created" as const, job: inserted };
        },
      );
      if (!access.authorized) {
        res.status(403).json({ error: "Workspace membership required" });
        return;
      }
      if (access.value.kind === "forbidden") {
        res.status(403).json({
          error: "Workspace owner or admin role required",
        });
        return;
      }
      if (access.value.kind === "queue_full") {
        res.setHeader("Retry-After", "3");
        res.status(409).json({ error: "Laboratory assessment queue is full" });
        return;
      }
      if (access.value.kind === "idempotency_conflict") {
        res.status(409).json({
          error: "Idempotency key already belongs to another assessment profile",
        });
        return;
      }
      if (
        access.value.job.status === "queued" &&
        access.value.job.attempts < AI_ASSESSMENT_JOB_MAX_ATTEMPTS
      ) {
        enqueueLocalAssessmentJob({
          jobId: access.value.job.id,
          workspaceId,
          actorUserId: req.authUserId!,
        });
      }
      res.status(202).json(formatJob(access.value.job));
    } catch (error) {
      if (error instanceof UsageQuotaError) {
        res.status(409).json({ error: "Workspace monthly scan quota reached" });
        return;
      }
      req.log.error(
        { errorCode: "lab_job_request_failed" },
        "Laboratory assessment request could not be recorded",
      );
      res.status(500).json({ error: "Laboratory assessment request failed" });
    }
  },
);

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/lab/jobs/:jobId/retry",
  async (req, res): Promise<void> => {
    const params = RetryWorkspaceAiAssessmentLabJobParams.safeParse(req.params);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !UUID_PATTERN.test(params.data.jobId)
    ) {
      res.status(400).json({ error: "Invalid laboratory job ID" });
      return;
    }
    const { workspaceId, jobId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [job] = await tx
          .select()
          .from(aiAssessmentJobsTable)
          .where(
            and(
              eq(aiAssessmentJobsTable.id, jobId),
              eq(aiAssessmentJobsTable.workspaceId, workspaceId),
            ),
          )
          .limit(1);
        if (!job) return { kind: "missing" as const };
        if (
          !isAssessmentProfileAvailable(
            job.profileId as AssessmentProfileId,
          )
        ) {
          return { kind: "worker_unavailable" as const };
        }
        if (!isAiAssessmentJobRetryable(job.status, job.attempts)) {
          return { kind: "not_retryable" as const };
        }
        await tx
          .update(aiAssessmentJobsTable)
          .set({
            status: "queued",
            result: null,
            errorCode: null,
            startedAt: null,
            completedAt: null,
            leaseOwnerId: null,
            leaseExpiresAt: null,
            heartbeatAt: null,
            workerSlot: null,
            updatedAt: new Date(),
          })
          .where(eq(aiAssessmentJobsTable.id, jobId));
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId,
          actorUserId: req.authUserId!,
          action: "ai_assessment.lab.retry_queued",
          resourceType: "ai_assessment_job",
          resourceId: jobId,
          metadata: {
            attempts: job.attempts,
            maxAttempts: AI_ASSESSMENT_JOB_MAX_ATTEMPTS,
          },
        });
        const [updated] = await tx
          .select()
          .from(aiAssessmentJobsTable)
          .where(eq(aiAssessmentJobsTable.id, jobId))
          .limit(1);
        return { kind: "queued" as const, job: updated };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({
        error: "Workspace owner or admin role required",
      });
      return;
    }
    if (access.value.kind === "missing") {
      res.status(404).json({ error: "Laboratory job not found" });
      return;
    }
    if (access.value.kind === "worker_unavailable") {
      res.status(503).json({
        error: "Requested isolated local assessment profile is unavailable",
      });
      return;
    }
    if (access.value.kind === "not_retryable") {
      res.status(409).json({ error: "Laboratory job is not retryable" });
      return;
    }
    if (!access.value.job) {
      res.status(500).json({ error: "Laboratory job update failed" });
      return;
    }
    enqueueLocalAssessmentJob({
      jobId,
      workspaceId,
      actorUserId: req.authUserId!,
    });
    res.status(202).json(
      RetryWorkspaceAiAssessmentLabJobResponse.parse(
        formatJob(access.value.job),
      ),
    );
  },
);

export function createAiAssessmentLabRouter(
  authMiddleware: RequestHandler = requireAuth,
): IRouter {
  const router: IRouter = Router();
  router.use("/workspaces", authMiddleware);
  router.use(routes);
  return router;
}

export default createAiAssessmentLabRouter();
