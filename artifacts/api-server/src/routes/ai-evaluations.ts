import { randomUUID } from "node:crypto";
import { and, desc, eq } from "drizzle-orm";
import { Router, type IRouter } from "express";
import {
  workspaceAuditEventsTable,
  type WorkspaceAuditEvent,
} from "@workspace/db";
import {
  ListWorkspaceAiEvaluationsParams,
  ListWorkspaceAiEvaluationsResponse,
  RunWorkspaceMockAiEvaluationParams,
  RunWorkspaceMockAiEvaluationResponse,
} from "@workspace/api-zod";
import { canRunAiEvaluation } from "../lib/access-control";
import {
  acquireMockEvaluationSlot,
  MOCK_EVALUATOR_MAX_CHECKS,
  MOCK_EVALUATOR_MAX_DURATION_MS,
  MOCK_EVALUATOR_VERSION,
  runLocalMockEvaluation,
} from "../lib/ai-evaluation";
import { withWorkspaceUserTransaction } from "../lib/tenant-db";
import { UsageQuotaError, reserveWorkspaceUsageInTransaction } from "../lib/usage";
import { requireAuth } from "../middlewares/requireAuth";

const router: IRouter = Router();
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const AUDIT_ACTION = "ai_evaluation.mock.completed";
const MAX_HISTORY = 20;

function getCheckSummaries(event: WorkspaceAuditEvent) {
  const rawChecks = event.metadata.checks;
  if (typeof rawChecks !== "string") {
    throw new Error("Stored AI evaluation evidence is malformed.");
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(rawChecks);
  } catch {
    throw new Error("Stored AI evaluation evidence is malformed.");
  }
  return ListWorkspaceAiEvaluationsResponse.element.shape.checks.parse(decoded);
}

function formatEvaluation(event: WorkspaceAuditEvent) {
  if (!event.resourceId) {
    throw new Error("Stored AI evaluation evidence is missing its identifier.");
  }
  const checks = getCheckSummaries(event);
  return {
    id: event.resourceId,
    engine: "guardian_mock" as const,
    execution: "simulated" as const,
    version: MOCK_EVALUATOR_VERSION,
    checks,
    passedChecks: checks.filter((check) => check.status === "passed").length,
    failedChecks: checks.filter((check) => check.status === "failed").length,
    createdAt: event.createdAt,
  };
}

router.use("/workspaces", requireAuth);

router.get(
  "/workspaces/:workspaceId/ai-evaluations",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceAiEvaluationsParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const { workspaceId } = params.data;
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      workspaceId,
      async (tx) =>
        tx
          .select()
          .from(workspaceAuditEventsTable)
          .where(
            and(
              eq(workspaceAuditEventsTable.workspaceId, workspaceId),
              eq(workspaceAuditEventsTable.action, AUDIT_ACTION),
            ),
          )
          .orderBy(desc(workspaceAuditEventsTable.createdAt))
          .limit(MAX_HISTORY),
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(ListWorkspaceAiEvaluationsResponse.parse(
      access.value.map(formatEvaluation),
    ));
  },
);

router.post(
  "/workspaces/:workspaceId/ai-evaluations/mock",
  async (req, res): Promise<void> => {
    const params = RunWorkspaceMockAiEvaluationParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid workspace ID" });
      return;
    }
    const releaseSlot = acquireMockEvaluationSlot();
    if (!releaseSlot) {
      res.setHeader("Retry-After", "1");
      res.status(429).json({ error: "AI evaluation capacity is busy" });
      return;
    }

    const { workspaceId } = params.data;
    try {
      const runId = randomUUID();
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        workspaceId,
        async (tx, membership) => {
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }

          await reserveWorkspaceUsageInTransaction(tx, workspaceId, {
            scans: 1,
            apiRequests: 1,
          });
          const startedAt = Date.now();
          const result = runLocalMockEvaluation();
          if (Date.now() - startedAt > MOCK_EVALUATOR_MAX_DURATION_MS) {
            throw new Error("Mock evaluation exceeded its fixed time budget.");
          }
          if (result.checks.length > MOCK_EVALUATOR_MAX_CHECKS) {
            throw new Error("Mock evaluation exceeded its fixed check budget.");
          }

          await tx.insert(workspaceAuditEventsTable).values({
            workspaceId,
            actorUserId: req.authUserId!,
            action: AUDIT_ACTION,
            resourceType: "ai_evaluation",
            resourceId: runId,
            metadata: {
              engine: result.engine,
              execution: result.execution,
              version: result.version,
              checks: JSON.stringify(result.checks),
              promptsStored: false,
              responsesStored: false,
              garakInvoked: false,
            },
          });

          return {
            kind: "created" as const,
            run: {
              id: runId,
              ...result,
              createdAt: new Date(),
            },
          };
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
      res.status(201).json(
        RunWorkspaceMockAiEvaluationResponse.parse(access.value.run),
      );
    } catch (error) {
      if (error instanceof UsageQuotaError) {
        res.status(409).json({ error: "Workspace monthly scan quota reached" });
        return;
      }
      req.log.error({ err: error }, "AI mock evaluation could not be recorded");
      res.status(500).json({ error: "AI mock evaluation could not be completed" });
    } finally {
      releaseSlot();
    }
  },
);

export default router;
