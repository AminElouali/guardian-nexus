import { and, desc, eq, gt, isNull, lte, sql } from "drizzle-orm";
import { createHash } from "node:crypto";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  SubmitWorkspaceAgentActionIntentBody,
  SubmitWorkspaceAgentActionIntentParams,
  SubmitWorkspaceAgentActionIntentResponse,
  CreateWorkspaceAiAssessmentLabJobBody,
  CreateWorkspaceAiAssessmentLabJobParams,
  CreateWorkspaceAiAssessmentLabJobResponse,
  PreviewWorkspaceAiAssessmentPolicyLabBody,
  PreviewWorkspaceAiAssessmentPolicyLabParams,
  PreviewWorkspaceAiAssessmentPolicyLabResponse,
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
  computeApprovalProposalBindingV3,
  computeApprovalReplayBinding,
  getAllowlistedSyntheticApprovalAction,
  isApprovalDecisionWindowOpen,
  resolveApprovalEvidenceProvenance,
  type SyntheticApprovalActionRef,
} from "../lib/ai-assessment-approval-actions";
import { canRunAiEvaluation } from "../lib/access-control";
import {
  PolicyLabPreviewError,
  runPolicyLabPreview,
} from "../lib/policy-lab-preview";
import {
  buildAgentActionIntent,
  deriveAgentActionIdempotencyKey,
  getAgentActionScenario,
  type AgentActionIntentRole,
  type AgentActionScenarioId,
} from "../lib/guardian-agent-action-adapter";
import {
  AI_ASSESSMENT_JOB_MAX_ATTEMPTS,
  AI_ASSESSMENT_WORKER_VERSION,
  GARAK_PROFILE_ID,
  isAiAssessmentJobRetryable,
} from "../lib/assessment-queue-contract";
import {
  decideAssessmentWorkerAdmission,
  enqueueLocalAssessmentJob,
  getLocalWorkerAvailability,
  isAssessmentProfileAvailable,
} from "../lib/assessment-worker-api-gate";
import type { AssessmentProfileId } from "../lib/ai-assessment-sandbox";
import { withWorkspaceUserTransaction } from "../lib/tenant-db";
import { UsageQuotaError, reserveWorkspaceUsageInTransaction } from "../lib/usage";
import { logger } from "../lib/logger";
import { requireAuth } from "../middlewares/requireAuth";
import {
  computeCurrentHostRuntimeIdentity,
  createHostAttestationChallenge,
  getCurrentApiServiceIdentity,
  hostAttestationResponseEnvelopeSchema,
  loadPinnedHostTrustAnchor,
} from "../lib/host-attestation-protocol";
import { createHostAttestationNonceRepository } from "../lib/host-attestation-persistence";

const routes: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function hasOnlyPolicyPreviewProfile(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const keys = Object.keys(value);
  return keys.length === 1 && keys[0] === "profileId";
}

const MAX_HISTORY = 20;
const MAX_PENDING_PER_WORKSPACE = 3;
const MAX_APPROVAL_HISTORY = 50;

function bodyHasOnlyKeys(
  value: unknown,
  allowedKeys: readonly string[],
): boolean {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) => allowedKeys.includes(key))
  );
}

type LabJobRequestBinding = {
  idempotencyKey: string;
  auditMetadata?: Record<string, string | number | boolean>;
  responseMetadata?: unknown;
};

type LabJobRequestOutcome =
  | {
      kind:
        | "not_member"
        | "forbidden"
        | "worker_unavailable"
        | "queue_full"
        | "idempotency_conflict";
    }
  | {
      kind: "job";
      job: AiAssessmentJob;
      bindingMetadata: unknown;
    };

export type LabJobRequestDependencies = {
  withWorkspaceUserTransaction: typeof withWorkspaceUserTransaction;
  reserveWorkspaceUsageInTransaction: typeof reserveWorkspaceUsageInTransaction;
  enqueueLocalAssessmentJob: typeof enqueueLocalAssessmentJob;
};

export async function requestLabJob(
  input: {
    userId: string;
    workspaceId: string;
    profileId: AssessmentProfileId;
    idempotencyKey: string;
    bindingForRole?: (role: string) => LabJobRequestBinding;
  },
  dependencies: Partial<LabJobRequestDependencies> = {},
): Promise<LabJobRequestOutcome> {
  const runWorkspaceTransaction =
    dependencies.withWorkspaceUserTransaction ?? withWorkspaceUserTransaction;
  const reserveUsage =
    dependencies.reserveWorkspaceUsageInTransaction ??
    reserveWorkspaceUsageInTransaction;
  const enqueueJob =
    dependencies.enqueueLocalAssessmentJob ?? enqueueLocalAssessmentJob;
  const access = await runWorkspaceTransaction(
    input.userId,
    input.workspaceId,
    async (tx, membership) => {
      if (!canRunAiEvaluation(membership.role)) {
        return { kind: "forbidden" as const };
      }
      if (
        input.bindingForRole &&
        membership.role !== "owner" &&
        membership.role !== "admin"
      ) {
        return { kind: "forbidden" as const };
      }
      if (!decideAssessmentWorkerAdmission(input.profileId).admitted) {
        return { kind: "worker_unavailable" as const };
      }
      const binding = input.bindingForRole?.(membership.role);
      const idempotencyKey = binding?.idempotencyKey ?? input.idempotencyKey;
      const [existing] = await tx
        .select()
        .from(aiAssessmentJobsTable)
        .where(
          and(
            eq(aiAssessmentJobsTable.workspaceId, input.workspaceId),
            eq(aiAssessmentJobsTable.idempotencyKey, idempotencyKey),
          ),
        )
        .limit(1);
      if (existing) {
        return existing.profileId === input.profileId
          ? {
              kind: "job" as const,
              job: existing,
              bindingMetadata: binding?.responseMetadata,
            }
          : { kind: "idempotency_conflict" as const };
      }

      const pending = await tx
        .select({ id: aiAssessmentJobsTable.id })
        .from(aiAssessmentJobsTable)
        .where(
          and(
            eq(aiAssessmentJobsTable.workspaceId, input.workspaceId),
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
          workspaceId: input.workspaceId,
          requestedByUserId: input.userId,
          idempotencyKey,
          profileId: input.profileId,
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
              eq(aiAssessmentJobsTable.workspaceId, input.workspaceId),
              eq(aiAssessmentJobsTable.idempotencyKey, idempotencyKey),
            ),
          )
          .limit(1);
        return raced
          ? raced.profileId === input.profileId
            ? {
                kind: "job" as const,
                job: raced,
                bindingMetadata: binding?.responseMetadata,
              }
            : { kind: "idempotency_conflict" as const }
          : { kind: "queue_full" as const };
      }

      await reserveUsage(tx, input.workspaceId, {
        scans: 1,
        apiRequests: 1,
      });
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId: input.workspaceId,
        actorUserId: input.userId,
        action: "ai_assessment.lab.requested",
        resourceType: "ai_assessment_job",
        resourceId: inserted.id,
        metadata: {
          profileId: inserted.profileId,
          workerVersion: inserted.workerVersion,
          environment: "development_lab",
          ...binding?.auditMetadata,
        },
      });
      return {
        kind: "job" as const,
        job: inserted,
        bindingMetadata: binding?.responseMetadata,
      };
    },
  );
  if (!access.authorized) return { kind: "not_member" };
  const outcome = access.value;
  if (
    outcome.kind === "job" &&
    outcome.job.status === "queued" &&
    outcome.job.attempts < AI_ASSESSMENT_JOB_MAX_ATTEMPTS
  ) {
    enqueueJob({
      jobId: outcome.job.id,
      workspaceId: input.workspaceId,
      actorUserId: input.userId,
    });
  }
  return outcome;
}

export function sendLabJobRequestError(
  res: import("express").Response,
  outcome: Exclude<LabJobRequestOutcome, { kind: "job" }>,
): boolean {
  switch (outcome.kind) {
    case "not_member":
      res.status(403).json({ error: "Workspace membership required" });
      return true;
    case "forbidden":
      res.status(403).json({ error: "Workspace owner or admin role required" });
      return true;
    case "worker_unavailable":
      res.status(503).json({
        error: "Requested isolated local assessment profile is unavailable",
      });
      return true;
    case "queue_full":
      res.setHeader("Retry-After", "3");
      res.status(409).json({ error: "Laboratory assessment queue is full" });
      return true;
    case "idempotency_conflict":
      res.status(409).json({
        error: "Idempotency key already belongs to another assessment profile",
      });
      return true;
  }
}

function handleLabJobRequestFailure(
  req: import("express").Request,
  res: import("express").Response,
  error: unknown,
): void {
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
    req.log.error(errorDetails, "Laboratory assessment request failed");
  } else {
    logger.error(errorDetails, "Laboratory assessment request failed");
  }
  res.status(500).json({ error: "Laboratory assessment request failed" });
}

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
    modelInference: boolean | null;
    executionMode: string | null;
    toolCallOrigin: string | null;
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
  const now = new Date();
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
      approval.status === "pending" &&
      !isApprovalDecisionWindowOpen(
        approval.status,
        approval.expiresAt,
        now,
      )
        ? "expired"
        : approval.status,
    canCurrentUserDecide:
      canCurrentUserDecide &&
      isApprovalDecisionWindowOpen(
        approval.status,
        approval.expiresAt,
        now,
      ),
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
  modelInference: boolean | null;
  executionMode: string | null;
  toolCallOrigin: string | null;
  requestedByUserId: string;
  requestedByRole: string | null;
  expiresAt: Date;
}): string {
  if (
    approval.bindingVersion === 3 &&
    approval.syntheticActionRef &&
    approval.actionSha256 &&
    approval.requestedByRole &&
    approval.modelInference !== null &&
    approval.executionMode &&
    approval.toolCallOrigin
  ) {
    const provenance = resolveApprovalEvidenceProvenance({
      engine:
        approval.modelInference === true
          ? "guardian_qwen_policy_lab"
          : "guardian_policy_lab",
      executionMode: approval.executionMode,
      modelInference: approval.modelInference,
      toolCallOrigin: approval.toolCallOrigin,
    });
    if (!provenance) return "";
    return computeApprovalProposalBindingV3({
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
      ...provenance,
    });
  }
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
    bindingVersion: number;
    modelInference: boolean | null;
    executionMode: string | null;
    toolCallOrigin: string | null;
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
  const isQwenEvidence = raw.engine === "guardian_qwen_policy_lab";
  const isDeterministicPolicyEvidence =
    raw.engine === "guardian_policy_lab" &&
    raw.executionMode === "deterministic_fixture" &&
    raw.modelInference === false;
  if (approval.bindingVersion === 2 && isQwenEvidence) {
    // Legacy Qwen approvals are readable, but cannot be consumed because v2
    // did not bind inference mode or the native/adapted tool-call origin.
    return null;
  }
  if (
    (!isQwenEvidence && !isDeterministicPolicyEvidence) ||
    raw.profileId !== job.profileId ||
    typeof raw.evidenceSha256 !== "string"
  ) {
    return null;
  }
  if (
    isQwenEvidence &&
    (![
      "guardian-policy-engine-synthetic-v2",
      "guardian-policy-engine-synthetic-v3",
    ].includes(
      String((raw.versions as Record<string, unknown> | null)?.policy),
    ) ||
      raw.executionMode !== "real_local_qwen_inference" ||
      raw.proposalOriginScope !==
        "qwen_marker_adapter_or_runtime_tool_calls_only")
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
  if (approval.bindingVersion === 3) {
    const provenance = resolveApprovalEvidenceProvenance({
      engine: raw.engine,
      executionMode: raw.executionMode,
      modelInference: raw.modelInference,
      toolCallOrigin: item.toolCallOrigin ?? raw.proposalOrigin,
    });
    if (
      !provenance ||
      approval.modelInference !== provenance.modelInference ||
      approval.executionMode !== provenance.executionMode ||
      approval.toolCallOrigin !== provenance.toolCallOrigin
    ) {
      return null;
    }
  }
  const caseDigest = item.caseEvidenceSha256;
  const unsignedCase = { ...item };
  if (isQwenEvidence) {
    // The Qwen runner includes an empty digest field in the canonical payload;
    // the deterministic policy lab hashes the case before adding that field.
    unsignedCase.caseEvidenceSha256 = "";
  } else {
    delete unsignedCase.caseEvidenceSha256;
  }
  const digestValid =
    typeof caseDigest === "string" &&
    createHash("sha256")
      .update(canonicalApprovalJson(unsignedCase), "utf8")
      .digest("hex") === caseDigest;
  const policyOn =
    item.policyOn && typeof item.policyOn === "object"
      ? (item.policyOn as Record<string, unknown>)
      : null;
  const toolTrace =
    item.toolTrace && typeof item.toolTrace === "object"
      ? (item.toolTrace as Record<string, unknown>)
      : null;
  const policyOnTrace =
    toolTrace?.policyOn && typeof toolTrace.policyOn === "object"
      ? (toolTrace.policyOn as Record<string, unknown>)
      : null;
  const policyOff =
    item.policyOff && typeof item.policyOff === "object"
      ? (item.policyOff as Record<string, unknown>)
      : null;
  const proposedTool =
    typeof item.proposedTool === "string"
      ? item.proposedTool
      : typeof item.tool === "string"
        ? item.tool
        : null;
  const proof = getAllowlistedSyntheticApprovalAction(
    approval.syntheticActionRef,
    job.profileId,
    approval.caseId,
    proposedTool,
  );
  const decision = isQwenEvidence ? item.decision : policyOn?.decision;
  const dispatchStatus = isQwenEvidence
    ? item.dispatchStatus
    : policyOnTrace?.dispatchStatus;
  const noDispatchedTools = isQwenEvidence
    ? Array.isArray(item.toolEvents) && item.toolEvents.length === 0
    : policyOnTrace?.invoked === false &&
      Array.isArray(policyOnTrace.events) &&
      policyOnTrace.events.length === 0;
  const policyOffHasNoExecution =
    policyOff?.executed === false &&
    (isQwenEvidence || policyOff?.mode === "counterfactual_clone_only");
  const trustedScopeValid =
    !isQwenEvidence ||
    raw.engineVersion !== "guardian-agent-qwen-policy-lab-v1.10.0" ||
    (item.trustedGoalScopeStatus === "matched" &&
      typeof item.trustedGoalScopeSha256 === "string" &&
      /^[a-f0-9]{64}$/.test(item.trustedGoalScopeSha256));
  if (
    !digestValid ||
    !proof ||
    !trustedScopeValid ||
    item.syntheticActionRef !== approval.syntheticActionRef ||
    item.actionSha256 !== approval.actionSha256 ||
    item.proposalSha256 !== approval.proposalSha256 ||
    proof.actionSha256 !== approval.actionSha256 ||
    proof.proposalSha256 !== approval.proposalSha256 ||
    decision !== "require_approval" ||
    dispatchStatus !== "approval_required_before_dispatch" ||
    !noDispatchedTools ||
    item.unauthorizedActionExecuted !== false ||
    !policyOffHasNoExecution ||
    (isDeterministicPolicyEvidence &&
      (item.instructionProvenance !== "trusted_user_request" ||
        item.rawArgumentsStored !== false ||
        item.rawInstructionStored !== false ||
        policyOn?.proposed !== true ||
        policyOn?.attempted !== true ||
        policyOn?.authorized !== false ||
        policyOn?.executed !== false))
  ) {
    return null;
  }
  return proof;
}

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/host-attestation/challenges",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    if (typeof workspaceId !== "string" || !UUID_PATTERN.test(workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    try {
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        workspaceId,
        async (tx, membership) => {
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }
          const protocol = createHostAttestationChallenge({
            repository: createHostAttestationNonceRepository(tx),
            loadTrustAnchor: loadPinnedHostTrustAnchor,
            getRuntimeIdentity: computeCurrentHostRuntimeIdentity,
            getApiIdentity: getCurrentApiServiceIdentity,
          });
          const challenge = await protocol.issue({
            workspaceId,
            issuedByUserId: req.authUserId!,
          });
          await tx.insert(workspaceAuditEventsTable).values({
            workspaceId,
            actorUserId: req.authUserId!,
            action: "ai_assessment.host_attestation.challenge_issued",
            resourceType: "host_attestation_challenge",
            resourceId: challenge.id,
            metadata: {
              runtimeCommit: challenge.runtimeCommit,
              runtimeDigestSha256: challenge.runtimeDigestSha256,
              expiresAt: challenge.expiresAt,
            },
          });
          return { kind: "challenge" as const, challenge };
        },
      );
      if (!access.authorized) {
        res.status(403).json({ error: "Workspace membership required" });
        return;
      }
      if (access.value.kind === "forbidden") {
        res.status(403).json({ error: "Workspace owner or admin role required" });
        return;
      }
      res.status(201).json({
        ...access.value.challenge,
        hostBoundaryReady: false,
        integratedAssessmentReady: false,
        workerAdmission: "disabled",
      });
    } catch {
      res.status(503).json({
        error: "Independent host attestation prerequisites are unavailable",
      });
    }
  },
);

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/host-attestation/challenges/:challengeId/responses",
  async (req, res): Promise<void> => {
    const workspaceId = req.params.workspaceId;
    const challengeId = req.params.challengeId;
    if (
      typeof workspaceId !== "string" ||
      !UUID_PATTERN.test(workspaceId) ||
      typeof challengeId !== "string" ||
      !UUID_PATTERN.test(challengeId)
    ) {
      res.status(400).json({ error: "Invalid workspace or challenge ID" });
      return;
    }
    const envelope = hostAttestationResponseEnvelopeSchema.safeParse(req.body);
    if (!envelope.success) {
      res.status(400).json({ error: "Invalid host attestation response" });
      return;
    }
    try {
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        workspaceId,
        async (tx, membership) => {
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }
          const protocol = createHostAttestationChallenge({
            repository: createHostAttestationNonceRepository(tx),
            loadTrustAnchor: loadPinnedHostTrustAnchor,
            getRuntimeIdentity: computeCurrentHostRuntimeIdentity,
            getApiIdentity: getCurrentApiServiceIdentity,
          });
          const result = await protocol.respond({
            workspaceId,
            challengeId,
            envelope: envelope.data,
          });
          await tx.insert(workspaceAuditEventsTable).values({
            workspaceId,
            actorUserId: req.authUserId!,
            action: "ai_assessment.host_attestation.response_recorded",
            resourceType: "host_attestation_challenge",
            resourceId: challengeId,
            metadata: {
              attestationStatus: result.attestationStatus,
              reasonCode: result.reasonCode,
              hostBoundaryReady: false,
              integratedAssessmentReady: false,
            },
          });
          return { kind: "result" as const, result };
        },
      );
      if (!access.authorized) {
        res.status(403).json({ error: "Workspace membership required" });
        return;
      }
      if (access.value.kind === "forbidden") {
        res.status(403).json({ error: "Workspace owner or admin role required" });
        return;
      }
      if (
        access.value.result.attestationStatus === "prerequisite_unavailable"
      ) {
        res.status(503).json({
          error: "Independent host attestation prerequisites are unavailable",
          ...access.value.result,
        });
        return;
      }
      res.status(200).json(access.value.result);
    } catch {
      res.status(503).json({
        error: "Host attestation could not be recorded safely",
      });
    }
  },
);

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

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/lab/policy-preview",
  async (req, res): Promise<void> => {
    if (process.env.NODE_ENV !== "development") {
      res.status(404).json({ error: "Policy preview is development-only" });
      return;
    }
    const params = PreviewWorkspaceAiAssessmentPolicyLabParams.safeParse(
      req.params,
    );
    const body = PreviewWorkspaceAiAssessmentPolicyLabBody.safeParse(req.body);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !hasOnlyPolicyPreviewProfile(req.body) ||
      !body.success
    ) {
      res.status(400).json({ error: "Invalid policy preview request" });
      return;
    }

    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (_tx, membership) => canRunAiEvaluation(membership.role),
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (!access.value) {
      res.status(403).json({
        error: "Workspace owner or admin role required",
      });
      return;
    }

    try {
      const evidence = await runPolicyLabPreview(body.data.profileId);
      res.setHeader("Cache-Control", "no-store");
      res.status(200).json(
        PreviewWorkspaceAiAssessmentPolicyLabResponse.parse({
          source: "fresh_deterministic_policy_preview",
          evidence,
        }),
      );
    } catch (error) {
      const code =
        error instanceof PolicyLabPreviewError
          ? error.code
          : "policy_preview_runner_failed";
      logger.warn(
        { code, profileId: body.data.profileId },
        "Deterministic policy preview did not complete",
      );
      if (code === "policy_preview_busy") {
        res.setHeader("Retry-After", "2");
        res.status(429).json({ error: "Policy preview already running" });
        return;
      }
      res.status(503).json({
        error: "Deterministic policy preview unavailable",
        code,
      });
    }
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
  "/workspaces/:workspaceId/ai-security-assessments/lab/jobs/:jobId",
  async (req, res): Promise<void> => {
    const params = CreateWorkspaceAiAssessmentLabJobParams.safeParse({
      workspaceId: req.params.workspaceId,
    });
    const jobId = req.params.jobId;
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      typeof jobId !== "string" ||
      !UUID_PATTERN.test(jobId)
    ) {
      res.status(400).json({ error: "Invalid workspace or job ID" });
      return;
    }
    const { workspaceId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx) => {
        const [job] = await tx
          .select()
          .from(aiAssessmentJobsTable)
          .where(
            and(
              eq(aiAssessmentJobsTable.workspaceId, workspaceId),
              eq(aiAssessmentJobsTable.id, jobId),
            ),
          )
          .limit(1);
        return job ?? null;
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (!access.value) {
      res.status(404).json({ error: "Laboratory job not found" });
      return;
    }
    res.json(formatJob(access.value));
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
        if (!isApprovalDecisionWindowOpen(approval.status, approval.expiresAt, now)) {
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
          [2, 3].includes(approval.bindingVersion) &&
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
          [2, 3].includes(approval.bindingVersion)
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

export function createLabJobPostHandler(
  submitLabJob: typeof requestLabJob = requestLabJob,
): RequestHandler {
  return async (req, res): Promise<void> => {
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

    const { workspaceId } = params.data;
    try {
      const outcome = await submitLabJob({
        userId: req.authUserId!,
        workspaceId,
        profileId,
        idempotencyKey: body.data.idempotencyKey,
      });
      if (outcome.kind !== "job") {
        sendLabJobRequestError(res, outcome);
        return;
      }
      res.status(202).json(formatJob(outcome.job));
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
  };
}

routes.post(
  "/workspaces/:workspaceId/ai-security-assessments/lab/jobs",
  createLabJobPostHandler(),
);

routes.post(
  "/workspaces/:workspaceId/agent-action-adapter/intents",
  async (req, res): Promise<void> => {
    const params = SubmitWorkspaceAgentActionIntentParams.safeParse(req.params);
    const body = SubmitWorkspaceAgentActionIntentBody.safeParse(req.body);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !body.success ||
      !bodyHasOnlyKeys(req.body, [
        "contractVersion",
        "scenarioId",
        "idempotencyKey",
      ])
    ) {
      res.status(400).json({ error: "Invalid external-agent scenario request" });
      return;
    }

    const scenarioId = body.data.scenarioId as AgentActionScenarioId;
    const scenario = getAgentActionScenario(scenarioId);
    try {
      const outcome = await requestLabJob({
        userId: req.authUserId!,
        workspaceId: params.data.workspaceId,
        profileId: scenario.profileId,
        idempotencyKey: body.data.idempotencyKey,
        bindingForRole: (role) => {
          const actorRole = role as AgentActionIntentRole;
          const actionIntent = buildAgentActionIntent(scenarioId, {
            actorUserId: req.authUserId!,
            actorRole,
            workspaceId: params.data.workspaceId,
          });
          return {
            idempotencyKey: deriveAgentActionIdempotencyKey({
              scenarioId,
              actorUserId: req.authUserId!,
              actorRole,
              callerKey: body.data.idempotencyKey,
            }),
            auditMetadata: {
              adapterVersion: "guardian-agent-intent-adapter-v1",
              scenarioId,
              intentSha256: actionIntent.intentSha256,
            },
            responseMetadata: actionIntent,
          };
        },
      });
      if (outcome.kind !== "job") {
        sendLabJobRequestError(res, outcome);
        return;
      }
      const formattedJob = formatJob(outcome.job);
      res.status(202).json(
        SubmitWorkspaceAgentActionIntentResponse.parse({
          adapterVersion: "guardian-agent-intent-adapter-v1",
          source: "fixed_synthetic_scenario",
          decisionStatus: "pending_worker_evaluation",
          externalDispatch: false,
          actionIntent: outcome.bindingMetadata,
          job: {
            id: formattedJob.id,
            status: formattedJob.status,
            profileId: formattedJob.profileId,
            workerVersion: formattedJob.workerVersion,
            createdAt: formattedJob.createdAt,
          },
        }),
      );
    } catch (error) {
      handleLabJobRequestFailure(req, res, error);
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
