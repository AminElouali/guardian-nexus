import { and, eq, isNull, sql } from "drizzle-orm";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  workspaceActionRuleVersionsTable,
  workspaceAgentsTable,
  getStarterWorkspaceRuleTemplates,
  validateWorkspaceActionRuleDocument,
} from "@workspace/db";
import {
  ActivateWorkspaceActionRuleDraftParams,
  ActivateWorkspaceActionRuleDraftResponse,
  CreateWorkspaceAgentActionProposalBody,
  CreateWorkspaceAgentActionProposalParams,
  CreateWorkspaceAgentActionProposalResponse,
  CreateWorkspaceAgentBody,
  CreateWorkspaceAgentParams,
  CreateWorkspaceAgentResponse,
  ListWorkspaceActionRulesParams,
  ListWorkspaceActionRulesResponse,
  ListWorkspaceAgentsParams,
  ListWorkspaceAgentsResponse,
  RevokeWorkspaceAgentParams,
  RevokeWorkspaceAgentResponse,
  RollbackWorkspaceActionRuleBody,
  RollbackWorkspaceActionRuleParams,
  RollbackWorkspaceActionRuleResponse,
  SaveWorkspaceActionRuleDraftBody,
  SaveWorkspaceActionRuleDraftParams,
  SaveWorkspaceActionRuleDraftResponse,
  SimulateWorkspaceActionRuleBody,
  SimulateWorkspaceActionRuleParams,
  SimulateWorkspaceActionRuleResponse,
  RotateWorkspaceAgentCredentialParams,
  RotateWorkspaceAgentCredentialResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";
import { canRunAiEvaluation } from "../lib/access-control";
import {
  activateWorkspaceActionRule,
  createWorkspaceActionRuleVersion,
  getActiveWorkspaceActionRule,
  listWorkspaceActionRuleStates,
  rollbackWorkspaceActionRule,
  toWorkspaceActionRuleSimulation,
} from "../lib/workspace-action-rules";
import { hashWorkspaceAgentCredential, issueWorkspaceAgentCredential } from "../lib/workspace-agent-credentials";
import {
  createGenericActionProposalInTransaction,
} from "../lib/generic-action-proposal-service";
import {
  withAgentWorkspaceTransaction,
  withWorkspaceUserTransaction,
} from "../lib/tenant-db";
import { formatApproval } from "./ai-assessment-lab";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function publicAgent(agent: typeof workspaceAgentsTable.$inferSelect) {
  return {
    id: agent.id,
    displayName: agent.displayName,
    principalUserId: agent.principalUserId,
    credentialVersion: agent.credentialVersion,
    createdAt: agent.createdAt,
    revokedAt: agent.revokedAt,
    lastUsedAt: agent.lastUsedAt,
  };
}

export function createWorkspaceGovernanceRouter(
  authMiddleware: RequestHandler = requireAuth,
): IRouter {
const router: IRouter = Router();
router.use("/workspaces", authMiddleware);

router.get(
  "/workspaces/:workspaceId/action-rules",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceActionRulesParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid workspace identifier" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      (tx) => listWorkspaceActionRuleStates(tx, params.data.workspaceId),
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(ListWorkspaceActionRulesResponse.parse({
      actions: access.value,
      starterTemplates: getStarterWorkspaceRuleTemplates(),
    }));
  },
);

router.put(
  "/workspaces/:workspaceId/action-rules/:actionType/draft",
  async (req, res): Promise<void> => {
    const params = SaveWorkspaceActionRuleDraftParams.safeParse(req.params);
    const body = SaveWorkspaceActionRuleDraftBody.safeParse(req.body);
    if (!params.success || !body.success) {
      res.status(400).json({ error: "Invalid action rule draft" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        return createWorkspaceActionRuleVersion(tx, {
          workspaceId: params.data.workspaceId,
          actionType: params.data.actionType,
          actorUserId: req.authUserId!,
          document: body.data,
          activate: false,
        });
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind === "invalid") {
      res.status(400).json({
        error: "Action rule document rejected",
        code: "invalid_rule_document",
        violations: access.value.issues,
      });
      return;
    }
    if (access.value.kind !== "created") {
      res.status(503).json({ error: "Rule version could not be saved" });
      return;
    }
    res.status(201).json(
      SaveWorkspaceActionRuleDraftResponse.parse({
        actionType: access.value.version.actionType,
        versionId: access.value.version.id,
        version: access.value.version.version,
        rules: access.value.version.ruleDocument.rules,
        createdAt: access.value.version.createdAt,
        active: false,
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/action-rules/:actionType/activate",
  async (req, res): Promise<void> => {
    const params = ActivateWorkspaceActionRuleDraftParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid action rule identifier" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        return activateWorkspaceActionRule(tx, {
          workspaceId: params.data.workspaceId,
          actionType: params.data.actionType,
          actorUserId: req.authUserId!,
        });
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind === "no_draft") {
      res.status(409).json({ error: "No draft rule version is available" });
      return;
    }
    if (access.value.kind !== "activated") {
      res.status(503).json({ error: "Rule activation failed" });
      return;
    }
    res.json(
      ActivateWorkspaceActionRuleDraftResponse.parse({
        actionType: access.value.version.actionType,
        versionId: access.value.version.id,
        version: access.value.version.version,
        rules: access.value.version.ruleDocument.rules,
        createdAt: access.value.version.createdAt,
        active: true,
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/action-rules/:actionType/rollback",
  async (req, res): Promise<void> => {
    const params = RollbackWorkspaceActionRuleParams.safeParse(req.params);
    const body = RollbackWorkspaceActionRuleBody.safeParse(req.body);
    if (!params.success || !body.success) {
      res.status(400).json({ error: "Invalid rule rollback request" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        return rollbackWorkspaceActionRule(tx, {
          workspaceId: params.data.workspaceId,
          actionType: params.data.actionType,
          actorUserId: req.authUserId!,
          sourceVersion: body.data.version,
        });
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind === "not_found") {
      res.status(404).json({ error: "Historical rule version not found" });
      return;
    }
    if (access.value.kind !== "rolled_back") {
      res.status(503).json({ error: "Rule rollback failed" });
      return;
    }
    res.status(201).json(
      RollbackWorkspaceActionRuleResponse.parse({
        actionType: access.value.version.actionType,
        versionId: access.value.version.id,
        version: access.value.version.version,
        rules: access.value.version.ruleDocument.rules,
        createdAt: access.value.version.createdAt,
        active: true,
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/action-rules/:actionType/simulate",
  async (req, res): Promise<void> => {
    const params = SimulateWorkspaceActionRuleParams.safeParse(req.params);
    const body = SimulateWorkspaceActionRuleBody.safeParse(req.body);
    if (!params.success || !body.success) {
      res.status(400).json({ error: "Invalid rule simulation request" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx) => {
        const active = body.data.versionId
          ? null
          : await getActiveWorkspaceActionRule(
              tx,
              params.data.workspaceId,
              params.data.actionType,
            );
        const selectedVersionId = body.data.versionId ?? active?.activeVersionId ?? null;
        let selectedDocument = active?.document ?? null;
        if (body.data.versionId) {
          const [version] = await tx
            .select()
            .from(workspaceActionRuleVersionsTable)
            .where(
              and(
                eq(workspaceActionRuleVersionsTable.workspaceId, params.data.workspaceId),
                eq(workspaceActionRuleVersionsTable.actionType, params.data.actionType),
                eq(workspaceActionRuleVersionsTable.id, body.data.versionId),
              ),
            )
            .limit(1);
          if (!version) return { kind: "not_found" as const };
          const validation = validateWorkspaceActionRuleDocument(
            params.data.actionType,
            version.ruleDocument,
          );
          selectedDocument = validation.ok ? validation.document : null;
        }
        return {
          kind: "simulated" as const,
          result: toWorkspaceActionRuleSimulation({
            actionType: params.data.actionType,
            args: body.data.arguments,
            versionId: selectedVersionId,
            document: selectedDocument,
          }),
        };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "not_found") {
      res.status(404).json({ error: "Rule version not found" });
      return;
    }
    res.json(SimulateWorkspaceActionRuleResponse.parse(access.value.result));
  },
);

router.get(
  "/workspaces/:workspaceId/agents",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceAgentsParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid workspace identifier" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const agents = await tx
          .select()
          .from(workspaceAgentsTable)
          .where(eq(workspaceAgentsTable.workspaceId, params.data.workspaceId))
          .orderBy(workspaceAgentsTable.createdAt);
        return { kind: "listed" as const, agents };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    res.json(
      ListWorkspaceAgentsResponse.parse({
        agents: access.value.agents.map(publicAgent),
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/agents",
  async (req, res): Promise<void> => {
    const params = CreateWorkspaceAgentParams.safeParse(req.params);
    const body = CreateWorkspaceAgentBody.safeParse(req.body);
    if (!params.success || !body.success) {
      res.status(400).json({ error: "Invalid agent registration request" });
      return;
    }
    const issued = issueWorkspaceAgentCredential();
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [agent] = await tx
          .insert(workspaceAgentsTable)
          .values({
            workspaceId: params.data.workspaceId,
            displayName: body.data.displayName.trim(),
            principalUserId: req.authUserId!,
            credentialSha256: issued.credentialSha256,
            credentialVersion: 1,
            createdByUserId: req.authUserId!,
          })
          .returning();
        return agent
          ? { kind: "created" as const, agent }
          : { kind: "failed" as const };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind !== "created") {
      res.status(503).json({ error: "Agent could not be registered" });
      return;
    }
    res.status(201).json(
      CreateWorkspaceAgentResponse.parse({
        agent: publicAgent(access.value.agent),
        credential: issued.credential,
        shownOnce: true,
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/agents/:agentId/rotate",
  async (req, res): Promise<void> => {
    const params = RotateWorkspaceAgentCredentialParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid agent credential rotation request" });
      return;
    }
    const issued = issueWorkspaceAgentCredential();
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [agent] = await tx
          .update(workspaceAgentsTable)
          .set({
            credentialSha256: issued.credentialSha256,
            credentialVersion: sql`${workspaceAgentsTable.credentialVersion} + 1`,
            revokedAt: null,
          })
          .where(
            and(
              eq(workspaceAgentsTable.workspaceId, params.data.workspaceId),
              eq(workspaceAgentsTable.id, params.data.agentId),
            ),
          )
          .returning();
        return agent
          ? { kind: "rotated" as const, agent }
          : { kind: "not_found" as const };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind !== "rotated") {
      res.status(404).json({ error: "Active agent not found" });
      return;
    }
    res.json(
      RotateWorkspaceAgentCredentialResponse.parse({
        agent: publicAgent(access.value.agent),
        credential: issued.credential,
        shownOnce: true,
      }),
    );
  },
);

router.post(
  "/workspaces/:workspaceId/agents/:agentId/revoke",
  async (req, res): Promise<void> => {
    const params = RevokeWorkspaceAgentParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid agent revocation request" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [agent] = await tx
          .update(workspaceAgentsTable)
          .set({ revokedAt: new Date() })
          .where(
            and(
              eq(workspaceAgentsTable.workspaceId, params.data.workspaceId),
              eq(workspaceAgentsTable.id, params.data.agentId),
              isNull(workspaceAgentsTable.revokedAt),
            ),
          )
          .returning();
        return agent
          ? { kind: "revoked" as const, agent }
          : { kind: "not_found" as const };
      },
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind !== "revoked") {
      res.status(404).json({ error: "Active agent not found" });
      return;
    }
    res.json(
      RevokeWorkspaceAgentResponse.parse({ agent: publicAgent(access.value.agent) }),
    );
  },
);

router.post(
  "/agent/workspaces/:workspaceId/action-proposals",
  async (req, res): Promise<void> => {
    const params = CreateWorkspaceAgentActionProposalParams.safeParse(req.params);
    const body = CreateWorkspaceAgentActionProposalBody.safeParse(req.body);
    if (!params.success || !body.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid agent action proposal request" });
      return;
    }
    const authorization = req.get("authorization") ?? "";
    const match = /^Bearer ([^\s]+)$/.exec(authorization);
    const credentialHash = match
      ? hashWorkspaceAgentCredential(match[1])
      : null;
    if (!credentialHash) {
      res.status(401).json({ error: "Agent authentication required" });
      return;
    }
    const access = await withAgentWorkspaceTransaction(
      params.data.workspaceId,
      credentialHash,
      async (tx, agent, membership) =>
        createGenericActionProposalInTransaction(tx, {
          workspaceId: params.data.workspaceId,
          actorUserId: agent.principalUserId,
          actorRole: membership.role,
          agentId: agent.id,
          actionType: body.data.actionType,
          arguments: body.data.arguments,
          idempotencyKey: body.data.idempotencyKey,
        }),
    );
    if (!access.authorized) {
      res.status(401).json({ error: "Agent authentication failed" });
      return;
    }
    const outcome = access.value;
    if (outcome.kind === "invalid_action") {
      res.status(400).json({
        error: "Action proposal rejected by the catalog or saved rule contract",
        code: outcome.code,
        ...(outcome.issues.length ? { violations: outcome.issues } : {}),
      });
      return;
    }
    if (outcome.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (outcome.kind === "idempotency_conflict") {
      res.status(409).json({ error: "Idempotency key is bound to another proposal" });
      return;
    }
    if (outcome.kind === "pending_limit") {
      res.status(429).json({ error: "Pending approval limit reached" });
      return;
    }
    if (outcome.kind === "persistence_failed") {
      res.status(503).json({ error: "Proposal could not be recorded" });
      return;
    }
    if (outcome.kind === "terminal") {
      res.json(
        CreateWorkspaceAgentActionProposalResponse.parse({
          decision: outcome.decision,
          reasonCode: outcome.reasonCode,
          actionType: outcome.actionType,
          actionSha256: outcome.actionSha256,
          ruleId: outcome.ruleId,
          ruleVersionId: outcome.ruleVersionId,
          approval: null,
          execution: "not_performed",
          externalSideEffect: false,
          idempotent: false,
        }),
      );
      return;
    }
    const details = {
      agentId: outcome.evidence.agentId,
      actionType: outcome.evidence.actionType,
      summary: outcome.evidence.summary,
      messagePreview: outcome.evidence.messagePreview,
      appliedRule: outcome.evidence.ruleId,
      ruleVersionId: outcome.evidence.ruleVersionId ?? null,
      synthetic: true as const,
    };
    res
      .status(outcome.kind === "created" ? 201 : 200)
      .json(
        CreateWorkspaceAgentActionProposalResponse.parse({
          decision: "require_approval",
          reasonCode: "human_approval_required",
          actionType: outcome.evidence.actionType,
          actionSha256: outcome.evidence.actionSha256,
          ruleId: outcome.evidence.ruleId,
          ruleVersionId: outcome.evidence.ruleVersionId,
          approval: formatApproval(
            outcome.approval,
            "not_performed",
            false,
            details,
          ),
          execution: "not_performed",
          externalSideEffect: false,
          idempotent: outcome.kind === "existing",
        }),
      );
  },
);

return router;
}

export default createWorkspaceGovernanceRouter();
