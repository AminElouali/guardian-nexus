import { and, eq, isNull, sql } from "drizzle-orm";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  workspaceAuditEventsTable,
  workspaceActionRuleVersionsTable,
  workspaceAgentsTable,
  buildWorkspaceActionRuleProfileDocuments,
  getWorkspaceActionRuleProfiles,
  validateWorkspaceActionRuleDocument,
  getStarterWorkspaceRuleTemplates,
} from "@workspace/db";
import {
  ApplyWorkspaceActionRuleProfileDraftParams,
  ApplyWorkspaceActionRuleProfileDraftBody,
  ApplyWorkspaceActionRuleProfileDraftResponse,
  ActivateWorkspaceActionRuleDraftParams,
  ActivateWorkspaceActionRuleDraftResponse,
  GetWorkspaceActionRuleHistoryImpactParams,
  GetWorkspaceActionRuleHistoryImpactResponse,
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
  ListWorkspaceConnectorCredentialsParams,
  ListWorkspaceConnectorCredentialsResponse,
  ReplaceWorkspaceConnectorCredentialParams,
  ReplaceWorkspaceConnectorCredentialBody,
  ReplaceWorkspaceConnectorCredentialResponse,
  DisconnectWorkspaceConnectorCredentialParams,
  ExecuteWorkspaceConnectorActionParams,
  ExecuteWorkspaceConnectorActionBody,
  ExecuteWorkspaceConnectorActionResponse,
} from "@workspace/api-zod";
import { requireAuth } from "../middlewares/requireAuth";
import { logger } from "../lib/logger";
import { canRunAiEvaluation } from "../lib/access-control";
import {
  activateWorkspaceActionRule,
  createWorkspaceActionRuleVersion,
  getActiveWorkspaceActionRule,
  listWorkspaceActionRuleStates,
  rollbackWorkspaceActionRule,
  toWorkspaceActionRuleSimulation,
} from "../lib/workspace-action-rules";
import { getWorkspaceRuleHistoryImpact } from "../lib/workspace-rule-history-impact";
import { hashWorkspaceAgentCredential, issueWorkspaceAgentCredential } from "../lib/workspace-agent-credentials";
import { createWorkspaceAgentAttemptLimiter } from "../lib/workspace-agent-attempt-limiter";
import {
  createGenericActionProposalInTransaction,
} from "../lib/generic-action-proposal-service";
import {
  withAgentWorkspaceTransaction,
  withWorkspaceUserTransaction,
} from "../lib/tenant-db";
import { formatApproval } from "./ai-assessment-lab";
import {
  ConnectorVaultError,
} from "../lib/workspace-connector-vault";
import {
  disconnectWorkspaceConnectorCredential,
  listWorkspaceConnectorCredentialStatuses,
  replaceWorkspaceConnectorCredential,
} from "../lib/workspace-connector-credentials";
import {
  executeWorkspaceConnectorAction,
  mapConnectorExecutionError,
  type ConnectorExecutionAdapter,
} from "../lib/workspace-connector-executions";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const agentAttemptLimiter = createWorkspaceAgentAttemptLimiter();

function safeConnectorCredentialFailure(
  error: unknown,
  stage: string,
): Record<string, string> {
  const safeStage = /^[a-z_]{1,32}$/.test(stage) ? stage : "unknown";
  if (error instanceof ConnectorVaultError) {
    return { failureStage: safeStage, errorCode: error.code };
  }
  if (error && typeof error === "object") {
    const candidate = error as {
      code?: unknown;
      constraint?: unknown;
      table?: unknown;
      name?: unknown;
    };
    if (typeof candidate.code === "string" && /^[0-9A-Z]{5}$/.test(candidate.code)) {
      const details: Record<string, string> = {
        failureStage: safeStage,
        sqlState: candidate.code,
      };
      if (
        typeof candidate.constraint === "string" &&
        /^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(candidate.constraint)
      ) {
        details.constraint = candidate.constraint;
      }
      if (
        typeof candidate.table === "string" &&
        /^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(candidate.table)
      ) {
        details.table = candidate.table;
      }
      return details;
    }
    const errorName =
      typeof candidate.name === "string" &&
      /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(candidate.name)
        ? candidate.name
        : "Error";
    return { failureStage: safeStage, errorName };
  }
  return { failureStage: safeStage, errorName: "Error" };
}

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
  options: {
    connectorAdapters?: ReadonlyMap<string, ConnectorExecutionAdapter>;
  } = {},
): IRouter {
const router: IRouter = Router();
const connectorAdapters = options.connectorAdapters ?? new Map();
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
      ruleProfiles: getWorkspaceActionRuleProfiles(),
    }));
  },
);

router.post(
  "/workspaces/:workspaceId/action-rules/profiles/:profileId/draft",
  async (req, res): Promise<void> => {
    const params = ApplyWorkspaceActionRuleProfileDraftParams.safeParse(req.params);
    const body = ApplyWorkspaceActionRuleProfileDraftBody.safeParse(req.body);
    if (!params.success || !body.success) {
      res.status(400).json({ error: "El límite debe ser positivo y no superar 10.000 €." });
      return;
    }
    const profile = buildWorkspaceActionRuleProfileDocuments(
      params.data.profileId,
      body.data.refundLimitCents,
    );
    if (!profile.ok) {
      res.status(400).json({
        error: profile.issues.includes("refund_limit_out_of_range")
          ? "El límite debe ser positivo y no superar 10.000 €."
          : "La plantilla seleccionada no está disponible.",
        code: profile.issues[0] ?? "invalid_rule_profile",
      });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const versions = [];
        for (const item of profile.documents) {
          const created = await createWorkspaceActionRuleVersion(tx, {
            workspaceId: params.data.workspaceId,
            actionType: item.actionType,
            actorUserId: req.authUserId!,
            document: item.document,
            activate: false,
          });
          if (created.kind !== "created") {
            throw new Error("rule_profile_draft_transaction_failed");
          }
          versions.push({
            actionType: created.version.actionType,
            versionId: created.version.id,
            version: created.version.version,
            createdAt: created.version.createdAt,
            active: false as const,
          });
        }
        return { kind: "created" as const, versions };
      },
    ).catch(() => null);
    if (!access) {
      res.status(503).json({ error: "No se pudo guardar el borrador de la plantilla." });
      return;
    }
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    if (access.value.kind === "forbidden") {
      res.status(403).json({ error: "Workspace administrator required" });
      return;
    }
    if (access.value.kind !== "created") {
      res.status(503).json({ error: "No se pudo guardar el borrador de la plantilla." });
      return;
    }
    res.status(201).json(
      ApplyWorkspaceActionRuleProfileDraftResponse.parse({
        profileId: profile.profile.id,
        refundLimitCents: body.data.refundLimitCents,
        versions: access.value.versions,
      }),
    );
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
        active: false,
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
  "/workspaces/:workspaceId/action-rules/:actionType/history-impact",
  async (req, res): Promise<void> => {
    const params = GetWorkspaceActionRuleHistoryImpactParams.safeParse(req.params);
    if (!params.success) {
      res.status(400).json({ error: "Invalid rule history comparison request" });
      return;
    }
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      (tx) => getWorkspaceRuleHistoryImpact(
        tx,
        params.data.workspaceId,
        params.data.actionType,
      ),
    );
    if (!access.authorized) {
      res.status(403).json({ error: "Workspace membership required" });
      return;
    }
    res.json(GetWorkspaceActionRuleHistoryImpactResponse.parse(access.value));
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
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const issued = issueWorkspaceAgentCredential();
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
        if (agent) {
          await tx.insert(workspaceAuditEventsTable).values({
            workspaceId: params.data.workspaceId,
            actorUserId: req.authUserId!,
            action: "workspace.agent.created",
            resourceType: "workspace_agent",
            resourceId: agent.id,
            metadata: {
              agentId: agent.id,
              credentialVersion: agent.credentialVersion,
            },
          });
        }
        return agent
          ? { kind: "created" as const, agent, credential: issued.credential }
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
        credential: access.value.credential,
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
    const access = await withWorkspaceUserTransaction(
      req.authUserId!,
      params.data.workspaceId,
      async (tx, membership) => {
        if (!canRunAiEvaluation(membership.role)) {
          return { kind: "forbidden" as const };
        }
        const [existingAgent] = await tx
          .select()
          .from(workspaceAgentsTable)
          .where(
            and(
              eq(workspaceAgentsTable.workspaceId, params.data.workspaceId),
              eq(workspaceAgentsTable.id, params.data.agentId),
            ),
          )
          .for("update")
          .limit(1);
        if (!existingAgent) return { kind: "not_found" as const };
        const issued = issueWorkspaceAgentCredential();
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
        if (agent) {
          await tx.insert(workspaceAuditEventsTable).values({
            workspaceId: params.data.workspaceId,
            actorUserId: req.authUserId!,
            action: "workspace.agent.credential_rotated",
            resourceType: "workspace_agent",
            resourceId: agent.id,
            metadata: {
              agentId: agent.id,
              credentialVersion: agent.credentialVersion,
              previousCredentialInvalidated: true,
            },
          });
        }
        return agent
          ? { kind: "rotated" as const, agent, credential: issued.credential }
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
        credential: access.value.credential,
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
        if (!agent) return { kind: "not_found" as const };
        await tx.insert(workspaceAuditEventsTable).values({
          workspaceId: params.data.workspaceId,
          actorUserId: req.authUserId!,
          action: "workspace.agent.revoked",
          resourceType: "workspace_agent",
          resourceId: agent.id,
          metadata: {
            agentId: agent.id,
            credentialVersion: agent.credentialVersion,
          },
        });
        return { kind: "revoked" as const, agent };
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
    const attempt = agentAttemptLimiter.consume(
      `${params.data.workspaceId}:${req.ip || "unknown"}`,
    );
    if (!attempt.allowed) {
      res.setHeader("Retry-After", String(attempt.retryAfterSeconds));
      res.status(429).json({
        error: "Agent authentication temporarily limited",
      });
      return;
    }
    const authorization = req.get("authorization") ?? "";
    const match = /^Bearer ([^\s]+)$/.exec(authorization);
    const credentialHash = match
      ? hashWorkspaceAgentCredential(match[1])
      : null;
    if (!credentialHash) {
      res.status(401).json({ error: "Agent authentication failed" });
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

router.get(
  "/workspaces/:workspaceId/connector-credentials",
  async (req, res): Promise<void> => {
    const params = ListWorkspaceConnectorCredentialsParams.safeParse(req.params);
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid connector request" });
      return;
    }
    try {
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        params.data.workspaceId,
        async (tx, membership) => {
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }
          return {
            kind: "listed" as const,
            credentials: await listWorkspaceConnectorCredentialStatuses(
              tx,
              params.data.workspaceId,
            ),
          };
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
        ListWorkspaceConnectorCredentialsResponse.parse({
          credentials: access.value.credentials.map((credential) => ({
            serviceId: credential.serviceId,
            configured: true,
            lastFour: credential.lastFour,
            encryptionKeyId: credential.encryptionKeyId,
            createdAt: credential.createdAt,
          })),
        }),
      );
    } catch {
      res.status(503).json({ error: "Connection status is unavailable" });
    }
  },
);

router.put(
  "/workspaces/:workspaceId/connector-credentials/:serviceId",
  async (req, res): Promise<void> => {
    const params = ReplaceWorkspaceConnectorCredentialParams.safeParse(req.params);
    const body = ReplaceWorkspaceConnectorCredentialBody.safeParse(req.body);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !body.success
    ) {
      res.status(400).json({ error: "Invalid connector credential request" });
      return;
    }
    let failureStage = "workspace_transaction";
    try {
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        params.data.workspaceId,
        async (tx, membership) => {
          failureStage = "authorization";
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }
          failureStage = "credential_save";
          const saved = await replaceWorkspaceConnectorCredential(tx, {
            workspaceId: params.data.workspaceId,
            actorUserId: req.authUserId!,
            serviceId: params.data.serviceId,
            secret: body.data.secret,
            onStage: (stage) => {
              failureStage = stage;
            },
          });
          return saved;
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
      const response = ReplaceWorkspaceConnectorCredentialResponse.parse({
        serviceId: access.value.credential.serviceId,
        configured: true,
        lastFour: access.value.credential.lastFour,
        encryptionKeyId: access.value.credential.encryptionKeyId,
        createdAt: access.value.credential.createdAt,
      });
      res
        .status(access.value.kind === "created" ? 201 : 200)
        .json(response);
    } catch (error) {
      if (
        error instanceof ConnectorVaultError &&
        error.code === "credential_input_invalid"
      ) {
        res.status(400).json({ error: "Credential value is invalid" });
        return;
      }
      const diagnostic = safeConnectorCredentialFailure(error, failureStage);
      const diagnosticCode =
        diagnostic.errorCode ??
        diagnostic.sqlState ??
        diagnostic.errorName ??
        "Error";
      const diagnosticObject = diagnostic.constraint
        ? ` constraint=${diagnostic.constraint}`
        : diagnostic.table
          ? ` table=${diagnostic.table}`
          : "";
      logger.error(
        diagnostic,
        `workspace_connector_credential_save_failed stage=${diagnostic.failureStage} code=${diagnosticCode}${diagnosticObject}`,
      );
      res.status(503).json({ error: "Credential vault is unavailable" });
    }
  },
);

router.delete(
  "/workspaces/:workspaceId/connector-credentials/:serviceId",
  async (req, res): Promise<void> => {
    const params = DisconnectWorkspaceConnectorCredentialParams.safeParse(
      req.params,
    );
    if (!params.success || !UUID_PATTERN.test(params.data.workspaceId)) {
      res.status(400).json({ error: "Invalid connector request" });
      return;
    }
    try {
      const access = await withWorkspaceUserTransaction(
        req.authUserId!,
        params.data.workspaceId,
        async (tx, membership) => {
          if (!canRunAiEvaluation(membership.role)) {
            return { kind: "forbidden" as const };
          }
          return {
            kind: "disconnected" as const,
            deleted: await disconnectWorkspaceConnectorCredential(tx, {
              workspaceId: params.data.workspaceId,
              actorUserId: req.authUserId!,
              serviceId: params.data.serviceId,
            }),
          };
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
      if (!access.value.deleted) {
        res.status(404).json({ error: "Configured credential not found" });
        return;
      }
      res.sendStatus(204);
    } catch {
      res.status(503).json({ error: "Credential could not be disconnected" });
    }
  },
);

router.post(
  "/workspaces/:workspaceId/connector-credentials/:serviceId/executions",
  async (req, res): Promise<void> => {
    const params = ExecuteWorkspaceConnectorActionParams.safeParse(req.params);
    const body = ExecuteWorkspaceConnectorActionBody.safeParse(req.body);
    if (
      !params.success ||
      !UUID_PATTERN.test(params.data.workspaceId) ||
      !body.success
    ) {
      res.status(400).json({ error: "Invalid connector execution request" });
      return;
    }
    try {
      const result = await executeWorkspaceConnectorAction({
        workspaceId: params.data.workspaceId,
        userId: req.authUserId!,
        serviceId: params.data.serviceId,
        idempotencyKey: body.data.idempotencyKey,
        actionType: body.data.actionType,
        arguments: body.data.arguments,
        receipt: body.data.receipt,
        adapters: connectorAdapters,
      });
      const response = ExecuteWorkspaceConnectorActionResponse.parse(result);
      res.status(result.status === "pending" ? 202 : 200).json(response);
    } catch (error) {
      const code = mapConnectorExecutionError(error);
      const status =
        code === "workspace_membership_required" ||
        code === "workspace_admin_required"
          ? 403
          : code === "connector_unavailable" ||
              code === "vault_keyring_unavailable" ||
              code === "credential_unavailable" ||
              code === "execution_unavailable"
            ? 503
            : 409;
      res.status(status).json({
        error: "Connector execution was not performed",
        code,
      });
    }
  },
);

return router;
}

export default createWorkspaceGovernanceRouter();
