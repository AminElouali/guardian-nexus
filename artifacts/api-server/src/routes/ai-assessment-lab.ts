import { and, desc, eq, gt, isNull, lte, sql } from "drizzle-orm";
import { createHash } from "node:crypto";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  CreateWorkspaceAiAssessmentLabJobBody,
  CreateWorkspaceAiAssessmentLabJobParams,
  CreateWorkspaceAiAssessmentLabJobResponse,
  DecideWorkspaceAiAssessmentApprovalBody,
  DecideWorkspaceAiAssessmentApprovalParams,
  DecideWorkspaceAiAssessmentApprovalResponse,
  GetWorkspaceAiAssessmentLabAvailabilityParams,
  GetWorkspaceAiAssessmentLabAvailabilityResponse,
  ListWorkspaceAiAssessmentLabJobsParams,
  ListWorkspaceAiAssessmentLabJobsResponse,
  ListWorkspaceAiAssessmentApprovalsParams,
  ListWorkspaceAiAssessmentApprovalsResponse,
  RetryWorkspaceAiAssessmentLabJobParams,
  RetryWorkspaceAiAssessmentLabJobResponse,
} from "@workspace/api-zod";
import {
  aiAssessmentApprovalRequestsTable,
  aiAssessmentJobsTable,
  workspaceAuditEventsTable,
  type AiAssessmentJob,
} from "@workspace/db";
import {
  canonicalApprovalJson,
  createSyntheticApprovalSimulationReceipt,
  computeApprovalProposalBindingV2,
  computeApprovalReplayBinding,
  getAllowlistedSyntheticApprovalAction,
  type SyntheticApprovalActionRef,
} from "../lib/ai-assessment-approval-actions";
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
const MAX_APPROVAL_HISTORY = 50;

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

function formatApproval(
  approval: {
  id: string;
  jobId: string;
  caseId: string;
  proposalSha256: string;
  actionSha256: string | null;
  proposalBindingSha256: string;
  requestedByUserId: string;
    requestedByRole: string | null;
    bindingVersion: number;
    syntheticActionRef: string | null;
  status: string;
  expiresAt: Date;
  decidedByUserId: string | null;
    decidedByRole: string | null;
  decidedAt: Date | null;
    simulatedAt: Date | null;
    simulationResultCode: string | null;
    simulationResultSha256: string | null;
    replayBindingSha256: string | null;
    createdAt: Date;
  },
  execution: "not_performed" | "simulated_once" = "not_performed",
  canCurrentUserDecide = false,
) {
  return {
    ...approval,
    execution:
      execution === "simulated_once" ||
      (approval.simulatedAt !== null &&
        approval.simulationResultCode !== null &&
        approval.simulationResultSha256 !== null &&
        approval.replayBindingSha256 !== null)
        ? "synthetic_action_simulated_once"
        : "not_performed",
    status:
      approval.status === "pending" && approval.expiresAt <= new Date()
        ? "expired"
        : approval.status,
    canCurrentUserDecide:
      canCurrentUserDecide &&
      approval.status === "pending" &&
      approval.expiresAt > new Date(),
  };
}

function computeApprovalBinding(approval: {
  workspaceId: string;
  jobId: string;
  caseId: string;
  proposalSha256: string;
  actionSha256: string | null;
  bindingVersion: number;
  syntheticActionRef: string | null;
  requestedByUserId: string;
  requestedByRole: string | null;
  expiresAt: Date;
}): string {
  if (
    approval.bindingVersion === 2 &&
    approval.syntheticActionRef &&
    approval.actionSha256 &&
    approval.requestedByRole
  ) {
    return computeApprovalProposalBindingV2({
      workspaceId: approval.workspaceId,
      jobId: approval.jobId,
      caseId: approval.caseId,
      proposalSha256: approval.proposalSha256,
      actionSha256: approval.actionSha256,
      syntheticActionRef:
        approval.syntheticActionRef as SyntheticApprovalActionRef,
      requestedByUserId: approval.requestedByUserId,
      requestedByRole: approval.requestedByRole,
      expiresAt: approval.expiresAt,
    });
  }
  return createHash("sha256")
    .update(
      JSON.stringify([
        approval.workspaceId,
        approval.jobId,
        approval.caseId,
        approval.proposalSha256,
        approval.actionSha256,
      ]),
    )
    .digest("hex");
}

function verifyPersistedApprovalEvidence(
  approval: {
    workspaceId: string;
    jobId: string;
    caseId: string;
    proposalSha256: string;
    actionSha256: string | null;
    syntheticActionRef: string | null;
    requestedByUserId: string;
  },
  job: AiAssessmentJob | undefined,
) {
  if (
    !job ||
    job.status !== "succeeded" ||
    job.requestedByUserId !== approval.requestedByUserId ||
    !job.result ||
    !approval.syntheticActionRef
  ) {
    return null;
  }
  const raw = job.result as unknown as Record<string, unknown>;
  if (
    raw.engine !== "guardian_qwen_policy_lab" ||
    raw.profileId !== job.profileId ||
    typeof raw.evidenceSha256 !== "string"
  ) {
    return null;
  }
  const { evidenceSha256, ...unsigned } = raw;
  if (
    createHash("sha256")
      .update(canonicalApprovalJson(unsigned), "utf8")
      .digest("hex") !== evidenceSha256 ||
    !Array.isArray(raw.cases)
  ) {
    return null;
  }
  const caseRecord = raw.cases.find(
    (value) =>
      !!value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      (value as Record<string, unknown>).caseId === approval.caseId,
  );
  if (!caseRecord || typeof caseRecord !== "object" || Array.isArray(caseRecord)) {
    return null;
  }
  const item = caseRecord as Record<string, unknown>;
  const caseDigest = item.caseEvidenceSha256;
  const unsignedCase = { ...item, caseEvidenceSha256: "" };
  const digestValid =
    typeof caseDigest === "string" &&
    createHash("sha256")
      .update(canonicalApprovalJson(unsignedCase), "utf8")
      .digest("hex") === caseDigest;
  const proof = getAllowlistedSyntheticApprovalAction(
    approval.syntheticActionRef,
    job.profileId,
    approval.caseId,
    typeof item.proposedTool === "string" ? item.proposedTool : null,
  );
  if (
    !digestValid ||
    !proof ||
    item.syntheticActionRef !== approval.syntheticActionRef ||
    item.actionSha256 !== approval.actionSha256 ||
    item.proposalSha256 !== approval.proposalSha256 ||
    proof.actionSha256 !== approval.actionSha256 ||
    proof.proposalSha256 !== approval.proposalSha256 ||
    item.decision !== "require_approval" ||
    item.dispatchStatus !== "approval_required_before_dispatch" ||
    !Array.isArray(item.toolEvents) ||
    item.toolEvents.length !== 0 ||
    item.unauthorizedActionExecuted !== false ||
    !item.policyOff ||
    typeof item.policyOff !== "object" ||
    (item.policyOff as Record<string, unknown>).executed !== false
  ) {
    return null;
  }
  return proof;
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

routes.get(
  "/workspaces/:workspaceId/ai-security-assessments/approvals",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceAiAssessmentApprovalsParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const { workspaceId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        const now = new Date();
        const canDecide = canRunAiEvaluation(membership.role);
        const approvals = await tx
          .select()
          .from(aiAssessmentApprovalRequestsTable)
          .where(eq(aiAssessmentApprovalRequestsTable.workspaceId, workspaceId))
          .orderBy(desc(aiAssessmentApprovalRequestsTable.createdAt))
          .limit(MAX_APPROVAL_HISTORY);
        return {
          approvals: approvals.map((approval) =>
            formatApproval(
              approval,
              approval.simulatedAt ? "simulated_once" : "not_performed",
              canDecide && approval.requestedByUserId !== req.authUserId,
            ),
          ),
          canDecide,
        };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(
      ListWorkspaceAiAssessmentApprovalsResponse.parse({
        ...access.value,
        execution: "laboratory_only",
      }),
    );
  },
);

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/approvals/:approvalId/decision",
  async (req, res): Promise<void> => {
    const params = DecideWorkspaceAiAssessmentApprovalParams.safeParse(req.params);
    const body = DecideWorkspaceAiAssessmentApprovalBody.safeParse(req.body);
    if (
      !params.success ||
      !body.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !UUID_PATTERN.test(params.data.approvalId)
    ) {
      res.status(400).json({ error: "Invalid approval decision request" });
      return;
    }
    const { workspaceId, approvalId } = params.data;
    const now = new Date();
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [approval] = await tx
          .select()
          .from(aiAssessmentApprovalRequestsTable)
          .where(
            and(
              eq(aiAssessmentApprovalRequestsTable.id, approvalId),
              eq(aiAssessmentApprovalRequestsTable.workspaceId, workspaceId),
            ),
          )
          .limit(1);
        if (!approval) return { kind: "missing" as const };
        if (approval.status !== "pending") {
          return { kind: "already_decided" as const };
        }
        if (approval.requestedByUserId === req.authUserId) {
          return { kind: "self_approval" as const };
        }
        if (approval.expiresAt <= now) {
          const [expired] = await tx
            .update(aiAssessmentApprovalRequestsTable)
            .set({ status: "expired", updatedAt: now })
            .where(
              and(
                eq(aiAssessmentApprovalRequestsTable.id, approvalId),
                eq(aiAssessmentApprovalRequestsTable.workspaceId, workspaceId),
                eq(aiAssessmentApprovalRequestsTable.status, "pending"),
                lte(aiAssessmentApprovalRequestsTable.expiresAt, now),
              ),
            )
            .returning();
          if (expired) {
            await tx.insert(workspaceAuditEventsTable).values({
              workspaceId,
              actorUserId: req.authUserId!,
              action: "ai_assessment.approval_expired",
              resourceType: "ai_assessment_approval",
              resourceId: approvalId,
              metadata: { jobId: approval.jobId, caseId: approval.caseId },
            });
          }
          return { kind: "expired" as const };
        }
        const expectedBinding = computeApprovalBinding(approval);
        if (
          approval.proposalBindingSha256 !== expectedBinding ||
          body.data.proposalBindingSha256 !== expectedBinding
        ) {
          return { kind: "binding_mismatch" as const };
        }
        const status = body.data.decision === "approve" ? "approved" : "denied";
        let simulationReceipt:
          | ReturnType<typeof createSyntheticApprovalSimulationReceipt>
          | null = null;
        let replayBindingSha256: string | null = null;
        if (
          status === "approved" &&
          approval.bindingVersion === 2 &&
          approval.syntheticActionRef &&
          approval.actionSha256
        ) {
          const [job] = await tx
            .select()
            .from(aiAssessmentJobsTable)
            .where(
              and(
                eq(aiAssessmentJobsTable.id, approval.jobId),
                eq(aiAssessmentJobsTable.workspaceId, workspaceId),
              ),
            )
            .limit(1);
          const proof = verifyPersistedApprovalEvidence(approval, job);
          if (!proof) return { kind: "evidence_invalid" as const };
          simulationReceipt = createSyntheticApprovalSimulationReceipt(proof);
          if (!simulationReceipt) return { kind: "evidence_invalid" as const };
          replayBindingSha256 = computeApprovalReplayBinding({
            proposalBindingSha256: expectedBinding,
            decision: "approved",
            decidedByUserId: req.authUserId!,
            decidedByRole: membership.role,
            decidedAt: now,
            simulationResultCode: simulationReceipt.resultCode,
            simulationResultSha256: simulationReceipt.resultSha256,
          });
        } else if (
          status === "approved" &&
          approval.bindingVersion === 2
        ) {
          return { kind: "evidence_invalid" as const };
        }
        const [updated] = await tx
          .update(aiAssessmentApprovalRequestsTable)
          .set({
            status,
            decidedByUserId: req.authUserId!,
            decidedByRole: membership.role,
            decidedAt: now,
            simulatedAt: simulationReceipt ? now : null,
            simulationResultCode: simulationReceipt?.resultCode ?? null,
            simulationResultSha256: simulationReceipt?.resultSha256 ?? null,
            replayBindingSha256,
            updatedAt: now,
          })
          .where(
            and(
              eq(aiAssessmentApprovalRequestsTable.id, approvalId),
              eq(aiAssessmentApprovalRequestsTable.workspaceId, workspaceId),
              eq(aiAssessmentApprovalRequestsTable.status, "pending"),
              eq(
                aiAssessmentApprovalRequestsTable.proposalBindingSha256,
                expectedBinding,
              ),
              gt(aiAssessmentApprovalRequestsTable.expiresAt, now),
              isNull(aiAssessmentApprovalRequestsTable.simulatedAt),
            ),
          )
          .returning();
        if (!updated) return { kind: "already_decided" as const };
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId,
          actorUserId: req.authUserId!,
          action: `ai_assessment.approval_${status}`,
          resourceType: "ai_assessment_approval",
          resourceId: approvalId,
          metadata: {
            jobId: approval.jobId,
            caseId: approval.caseId,
            proposalSha256: approval.proposalSha256,
            proposalBindingSha256: expectedBinding,
            decidedByRole: membership.role,
            syntheticActionRef: approval.syntheticActionRef,
            simulationResultCode: simulationReceipt?.resultCode ?? null,
            simulationResultSha256: simulationReceipt?.resultSha256 ?? null,
            simulationBeforeStateSha256: simulationReceipt?.beforeStateSha256 ?? null,
            simulationAfterStateSha256: simulationReceipt?.afterStateSha256 ?? null,
            replayBindingSha256,
            externalSideEffect: false,
          },
        });
        return {
          kind: "decided" as const,
          approval: updated,
          execution: simulationReceipt
            ? "synthetic_action_simulated_once"
            : status === "denied"
              ? "not_performed_denied"
              : "decision_only",
        };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden" || access.value.kind === "self_approval") {
      res.status(403).json({ error: "A different workspace owner or admin must decide this request" });
      return;
    }
    if (access.value.kind === "missing") {
      res.status(404).json({ error: "Approval not found in this workspace" });
      return;
    }
    if (
      access.value.kind === "already_decided" ||
      access.value.kind === "expired" ||
      access.value.kind === "binding_mismatch" ||
      access.value.kind === "evidence_invalid"
    ) {
      res.status(409).json({ error: `Approval is ${access.value.kind}` });
      return;
    }
    if (access.value.kind !== "decided") {
      res.status(500).json({ error: "Approval decision failed" });
      return;
    }
    res.json(
      DecideWorkspaceAiAssessmentApprovalResponse.parse({
        approval: formatApproval(
          access.value.approval,
          access.value.execution === "synthetic_action_simulated_once"
            ? "simulated_once"
            : "not_performed",
        ),
        execution: access.value.execution,
      }),
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
      const errorDetails = {
        errorCode: "lab_job_request_failed",
        errorType: error instanceof Error ? error.name : "UnknownError",
        sqlState:
          error &&
          typeof error === "object" &&
          "code" in error &&
          typeof error.code === "string" &&
          /^[0-9A-Z]{5}$/.test(error.code)
            ? error.code
            : undefined,
        constraint:
          error &&
          typeof error === "object" &&
          "constraint" in error &&
          typeof error.constraint === "string" &&
          /^[a-z0-9_]{1,80}$/i.test(error.constraint)
            ? error.constraint
            : undefined,
      };
      if (req.log?.error) {
        req.log.error(
          errorDetails,
          "Laboratory assessment request could not be recorded",
        );
      } else {
        console.error(
          "Laboratory assessment request could not be recorded",
          errorDetails,
        );
      }
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
