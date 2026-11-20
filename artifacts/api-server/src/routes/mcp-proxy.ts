import { createHash } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { Router, type IRouter, type RequestHandler } from "express";
import {
  aiAssessmentApprovalRequestsTable,
  aiAssessmentJobsTable,
  workspaceAuditEventsTable,
} from "@workspace/db";
import {
  classifyMcpToolCall,
  getGuardianMcpToolDefinition,
  listGuardianMcpToolDefinitions,
  type GuardianMcpToolDefinition,
} from "../lib/mcp-tool-classifier";
import {
  McpJsonRpcParseError,
  parseMcpJsonRpcRequest,
} from "../lib/mcp-json-rpc";
import { hashWorkspaceAgentCredential } from "../lib/workspace-agent-credentials";
import { workspaceAgentAttemptLimiter } from "../lib/workspace-agent-attempt-limiter";
import {
  createGenericActionProposalInTransaction,
} from "../lib/generic-action-proposal-service";
import {
  getActiveWorkspaceActionRule,
} from "../lib/workspace-action-rules";
import {
  withAgentWorkspaceTransaction,
} from "../lib/tenant-db";
import {
  readWorkspaceApprovalReceiptForAgent,
} from "../lib/approval-ledger-service";
import {
  executeWorkspaceConnectorAction,
  mapConnectorExecutionError,
  type ConnectorExecutionAdapter,
} from "../lib/workspace-connector-executions";
import { verifyGenericActionEvidence } from "../lib/generic-action-evidence";

const MCP_SERVER_ID = "guardian-demo-mcp";
const TOOL_STATUS = "guardian_approval_status";
const GUARDIAN_MCP_PROTOCOL_VERSION = "2025-03-26";
const GUARDIAN_MCP_SERVER_NAME = "Guardian Nexus";
const MAX_DESTINATION_MS = 5_000;
const MAX_RESPONSE_TEXT_BYTES = 4_096;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export type McpDestination = {
  call(input: {
    toolName: string;
    arguments: Record<string, string | number | boolean>;
    signal: AbortSignal;
  }): Promise<{ text: string }>;
};

export type McpProxyRouterOptions = {
  destinations?: ReadonlyMap<string, McpDestination>;
  authRateLimiter?: typeof workspaceAgentAttemptLimiter;
  executeConnector?: typeof executeWorkspaceConnectorAction;
  destinationTimeoutMs?: number;
};

type JsonRpcId = string | number;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function rpcError(
  res: Parameters<RequestHandler>[1],
  id: JsonRpcId | null,
  code: number,
  message: string,
): void {
  res.status(200).json({
    jsonrpc: "2.0",
    id,
    error: { code, message },
  });
}

function rpcToolResult(
  res: Parameters<RequestHandler>[1],
  id: JsonRpcId,
  text: string,
  isError = false,
  structuredContent?: Record<string, unknown>,
): void {
  res.status(200).json({
    jsonrpc: "2.0",
    id,
    result: {
      content: [{ type: "text", text: responseTextWithinLimit(text) }],
      isError,
      ...(structuredContent ? { structuredContent } : {}),
    },
  });
}

function guardianApprovalStatusDefinition(): GuardianMcpToolDefinition {
  return {
    serverId: MCP_SERVER_ID,
    name: TOOL_STATUS,
    actionType: "guardian_approval_status",
    description: "Consulta el estado de una solicitud creada por este agente.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        approval_id: { type: "string", pattern: UUID_RE.source },
      },
      required: ["approval_id"],
    },
  };
}

function allToolDefinitions(
  demoDestinationRegistered: boolean,
): GuardianMcpToolDefinition[] {
  return [
    ...(demoDestinationRegistered
      ? listGuardianMcpToolDefinitions(MCP_SERVER_ID)
      : []),
    guardianApprovalStatusDefinition(),
  ];
}

function mcpToolDescriptor(definition: GuardianMcpToolDefinition) {
  return {
    name: definition.name,
    description: definition.description,
    inputSchema: definition.inputSchema,
  };
}

function responseTextWithinLimit(value: string): string {
  let result = "";
  let bytes = 0;
  for (const codePoint of value) {
    const length = Buffer.byteLength(codePoint, "utf8");
    if (bytes + length > MAX_RESPONSE_TEXT_BYTES) break;
    result += codePoint;
    bytes += length;
  }
  return result;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

async function recordMcpDecisionAudit(
  workspaceId: string,
  credentialSha256: string,
  input: {
    reasonCode: string;
    toolName?: string;
    requestText: string;
    decision: "deny" | "rejected";
  },
): Promise<void> {
  await withAgentWorkspaceTransaction(
    workspaceId,
    credentialSha256,
    async (tx, agent) => {
      await tx.insert(workspaceAuditEventsTable).values({
        workspaceId,
        actorUserId: agent.principalUserId,
        action: "mcp.tool_call_decision",
        resourceType: "mcp_tool_call",
        metadata: {
          decision: input.decision,
          reasonCode: input.reasonCode,
          serverId: MCP_SERVER_ID,
          ...(input.toolName
            ? { toolNameSha256: sha256(input.toolName) }
            : {}),
          requestSha256: sha256(input.requestText),
          synthetic: true,
          externalSideEffect: false,
        },
      });
    },
  );
}

function toolCallArguments(
  params: Record<string, unknown>,
  rawArgumentsJson: string | null,
): { ok: true; name: string } | { ok: false } {
  if (
    typeof params.name !== "string" ||
    !rawArgumentsJson ||
    !isRecord(params.arguments) ||
    Object.keys(params).some((key) => key !== "name" && key !== "arguments")
  ) {
    return { ok: false };
  }
  return { ok: true, name: params.name };
}

export function createMcpProxyRouter(
  options: McpProxyRouterOptions = {},
): IRouter {
  const router: IRouter = Router();
  const destinations = options.destinations ?? new Map<string, McpDestination>();
  const limiter = options.authRateLimiter ?? workspaceAgentAttemptLimiter;
  const executeConnector = options.executeConnector ??
    executeWorkspaceConnectorAction;
  const destinationTimeoutMs =
    Number.isInteger(options.destinationTimeoutMs) &&
      options.destinationTimeoutMs! > 0
      ? Math.min(options.destinationTimeoutMs!, MAX_DESTINATION_MS)
      : MAX_DESTINATION_MS;

  router.post(
    "/workspaces/:workspaceId/mcp",
    async (req, res): Promise<void> => {
      let parsedRequest: ReturnType<typeof parseMcpJsonRpcRequest>;
      try {
        parsedRequest = parseMcpJsonRpcRequest(req.body);
      } catch (error) {
        const code = error instanceof McpJsonRpcParseError
          ? error.code
          : "invalid_json";
        res.status(400).json({ error: "Invalid MCP request", code });
        return;
      }
      const { value: rpc, rawArgumentsJson } = parsedRequest;
      const id = rpc.id as JsonRpcId | undefined;
      if (id === undefined) {
        if (
          rpc.method === "notifications/initialized" &&
          (rpc.params === undefined ||
            (isRecord(rpc.params) && Object.keys(rpc.params).length === 0))
        ) {
          res.status(202).end();
          return;
        }
        res.status(400).json({ error: "Invalid MCP request" });
        return;
      }
      const workspaceId = req.params.workspaceId;
      if (!UUID_RE.test(workspaceId)) {
        res.status(400).json({ error: "Invalid MCP request" });
        return;
      }
      const limiterResult = limiter.consume(
        `${workspaceId}:${req.ip || "unknown"}`,
      );
      if (!limiterResult.allowed) {
        res.setHeader("Retry-After", String(limiterResult.retryAfterSeconds));
        res.status(429).json({ error: "MCP authentication temporarily limited" });
        return;
      }
      const authorization = req.get("authorization") ?? "";
      const token = /^Bearer (gnx_agent_v1_[A-Za-z0-9_-]{43})$/.exec(
        authorization,
      )?.[1];
      const credentialSha256 = token
        ? hashWorkspaceAgentCredential(token)
        : null;
      if (!credentialSha256) {
        res.status(401).json({ error: "Agent authentication failed" });
        return;
      }

      const auth = await withAgentWorkspaceTransaction(
        workspaceId,
        credentialSha256,
        async (_tx, agent) => ({ agentId: agent.id, principalUserId: agent.principalUserId }),
      );
      if (!auth.authorized) {
        res.status(401).json({ error: "Agent authentication failed" });
        return;
      }

      if (rpc.method === "initialize") {
        res.status(200).json({
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion: GUARDIAN_MCP_PROTOCOL_VERSION,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: GUARDIAN_MCP_SERVER_NAME, version: "1.0" },
          },
        });
        return;
      }
      if (rpc.method === "tools/list") {
        res.status(200).json({
          jsonrpc: "2.0",
          id,
          result: {
            tools: allToolDefinitions(
              destinations.has(MCP_SERVER_ID),
            ).map(mcpToolDescriptor),
          },
        });
        return;
      }
      if (rpc.method !== "tools/call" || !isRecord(rpc.params)) {
        rpcError(res, id, -32601, "Método no disponible.");
        return;
      }
      const args = toolCallArguments(rpc.params, rawArgumentsJson);
      if (!args.ok) {
        await recordMcpDecisionAudit(workspaceId, credentialSha256, {
          decision: "rejected",
          reasonCode: "invalid_tool_call_arguments",
          requestText: typeof req.body === "string" ? req.body : "",
        });
        rpcError(res, id, -32602, "Argumentos no válidos.");
        return;
      }
      if (args.name === TOOL_STATUS) {
        const approvalId = rpc.params.arguments &&
            isRecord(rpc.params.arguments) &&
            Object.keys(rpc.params.arguments).length === 1 &&
            Object.hasOwn(rpc.params.arguments, "approval_id") &&
            typeof rpc.params.arguments.approval_id === "string"
          ? rpc.params.arguments.approval_id
          : null;
        if (!approvalId || !UUID_RE.test(approvalId)) {
          rpcError(res, id, -32602, "Argumentos no válidos.");
          return;
        }
        const statusResult = await withAgentWorkspaceTransaction(
          workspaceId,
          credentialSha256,
          async (tx, agent) => {
            const [approval] = await tx
              .select()
              .from(aiAssessmentApprovalRequestsTable)
              .where(
                and(
                  eq(aiAssessmentApprovalRequestsTable.workspaceId, workspaceId),
                  eq(aiAssessmentApprovalRequestsTable.id, approvalId),
                ),
              )
              .limit(1);
            if (!approval) return null;
            const [job] = await tx
              .select({ result: aiAssessmentJobsTable.result })
              .from(aiAssessmentJobsTable)
              .where(
                and(
                  eq(aiAssessmentJobsTable.workspaceId, workspaceId),
                  eq(aiAssessmentJobsTable.id, approval.jobId),
                ),
              )
              .limit(1);
            const actionType = approval.syntheticActionRef;
            const profileId = actionType === "guardian.support.reply.send.v1"
              ? "guardian-agent-lab-customer-service-v1"
              : actionType === "guardian.email.send.external.v1"
                ? "guardian-agent-lab-email-v1"
                : null;
            const evidence = profileId
              ? verifyGenericActionEvidence(job?.result, {
                  workspaceId,
                  requestedByUserId: approval.requestedByUserId,
                  actionType: actionType!,
                  actionSha256: approval.actionSha256 ?? "",
                  proposalSha256: approval.proposalSha256,
                  profileId,
                })
              : null;
            if (!evidence || evidence.agentId !== agent.id) return null;
            const status = approval.status === "pending" &&
                approval.expiresAt.getTime() <= Date.now()
              ? "expired"
              : approval.status;
            return {
              approvalId: approval.id,
              status,
              expiresAt: approval.expiresAt.toISOString(),
            };
          },
        );
        if (!statusResult.authorized || !statusResult.value) {
          rpcError(res, id, -32004, "Solicitud no disponible.");
          return;
        }
        rpcToolResult(
          res,
          id,
          `Estado: ${statusResult.value.status}.`,
          false,
          statusResult.value,
        );
        return;
      }

      const classification = classifyMcpToolCall({
        serverId: MCP_SERVER_ID,
        toolName: args.name,
        argumentsJson: rawArgumentsJson,
      });
      if (
        classification.status !== "classified" ||
        !classification.validatedArguments ||
        !classification.canonicalInputSha256
      ) {
        await recordMcpDecisionAudit(workspaceId, credentialSha256, {
          decision: "deny",
          reasonCode: classification.reasonCode,
          toolName: args.name,
          requestText: rawArgumentsJson ?? "",
        });
        rpcToolResult(
          res,
          id,
          `Acción bloqueada (${classification.reasonCode}).`,
          true,
          { reasonCode: classification.reasonCode },
        );
        return;
      }
      const toolDefinition = getGuardianMcpToolDefinition(
        MCP_SERVER_ID,
        args.name,
      );
      const destination = destinations.get(MCP_SERVER_ID);
      if (!toolDefinition || !destination) {
        await recordMcpDecisionAudit(workspaceId, credentialSha256, {
          decision: "rejected",
          reasonCode: "destination_unavailable",
          toolName: args.name,
          requestText: rawArgumentsJson ?? "",
        });
        rpcToolResult(res, id, "Destino no disponible en este entorno.", true, {
          reasonCode: "destination_unavailable",
        });
        return;
      }

      const proposal = await withAgentWorkspaceTransaction(
        workspaceId,
        credentialSha256,
        async (tx, agent, membership) => {
          const activeRule = await getActiveWorkspaceActionRule(
            tx,
            workspaceId,
            classification.actionType,
          );
          const idempotencyKey = createHash("sha256")
            .update(
              `${workspaceId}\n${agent.id}\n${MCP_SERVER_ID}\n${args.name}\n${classification.canonicalInputSha256}\n${activeRule?.activeVersionId ?? "no-active-rule"}`,
              "utf8",
            )
            .digest("hex");
          const outcome = await createGenericActionProposalInTransaction(tx, {
            workspaceId,
            actorUserId: agent.principalUserId,
            actorRole: membership.role,
            agentId: agent.id,
            actionType: classification.actionType,
            arguments: classification.validatedArguments,
            idempotencyKey,
            escalateAllowToApproval: true,
          });
          return { outcome, agentId: agent.id, principalUserId: agent.principalUserId, idempotencyKey };
        },
      );
      if (!proposal.authorized) {
        res.status(401).json({ error: "Agent authentication failed" });
        return;
      }
      const { outcome } = proposal.value;
      if (outcome.kind === "terminal") {
        rpcToolResult(
          res,
          id,
          `Acción bloqueada (${outcome.reasonCode}).`,
          true,
          { reasonCode: outcome.reasonCode },
        );
        return;
      }
      if (outcome.kind !== "created" && outcome.kind !== "existing") {
        rpcToolResult(
          res,
          id,
          "No se pudo crear la solicitud de aprobación.",
          true,
          { reasonCode: outcome.kind },
        );
        return;
      }
      const approval = outcome.approval;
      if (approval.status === "pending") {
        if (approval.expiresAt.getTime() <= Date.now()) {
          rpcToolResult(res, id, "La solicitud de aprobación ha caducado.", true, {
            reasonCode: "approval_expired",
            approvalId: approval.id,
          });
          return;
        }
        rpcToolResult(
          res,
          id,
          "Pendiente de aprobación humana. Vuelve a llamar con la misma herramienta y los mismos argumentos cuando se apruebe.",
          false,
          { approvalId: approval.id, status: "pending", retryWithSameArguments: true },
        );
        return;
      }
      if (approval.status !== "approved") {
        rpcToolResult(
          res,
          id,
          approval.status === "expired"
            ? "La solicitud de aprobación ha caducado."
            : "La solicitud fue rechazada.",
          true,
          { reasonCode: `approval_${approval.status}` },
        );
        return;
      }

      const storedReceipt = await withAgentWorkspaceTransaction(
        workspaceId,
        credentialSha256,
        (tx) => readWorkspaceApprovalReceiptForAgent(
          tx,
          workspaceId,
          approval.id,
        ),
      );
      if (!storedReceipt.authorized || !storedReceipt.value) {
        rpcToolResult(
          res,
          id,
          "No hay un recibo verificable para esta aprobación.",
          true,
          { reasonCode: "approval_receipt_unavailable" },
        );
        return;
      }

      const adapter: ConnectorExecutionAdapter = {
        serviceId: MCP_SERVER_ID,
        async execute(execution) {
          const controller = new AbortController();
          let timer: ReturnType<typeof setTimeout> | undefined;
          try {
            const timeout = new Promise<never>((_resolve, reject) => {
              timer = setTimeout(() => {
                controller.abort();
                reject(new Error("mcp_destination_timeout"));
              }, destinationTimeoutMs);
            });
            const response = await Promise.race([
              destination.call({
                toolName: args.name,
                arguments: execution.arguments,
                signal: controller.signal,
              }),
              timeout,
            ]);
            return {
              resultCode: "mcp_destination_completed",
              summary: "MCP destination returned a response.",
              responseText: response.text,
            };
          } finally {
            if (timer) clearTimeout(timer);
          }
        },
      };
      try {
        const execution = await executeConnector({
          workspaceId,
          userId: proposal.value.principalUserId,
          serviceId: MCP_SERVER_ID,
          actionType: classification.actionType,
          arguments: classification.validatedArguments,
          receipt: storedReceipt.value,
          idempotencyKey: `mcp-${proposal.value.idempotencyKey}`,
          adapters: new Map([[MCP_SERVER_ID, adapter]]),
        });
        if (execution.status !== "executed") {
          rpcToolResult(
            res,
            id,
            "La ejecución fue rechazada.",
            true,
            { reasonCode: execution.failureCode ?? "execution_failed" },
          );
          return;
        }
        rpcToolResult(
          res,
          id,
          responseTextWithinLimit(
              execution.responseSummary ??
                execution.responseText ??
                "Acción ejecutada.",
          ),
          false,
          { status: "executed", replayed: execution.replayed },
        );
      } catch (error) {
        const reason = mapConnectorExecutionError(error);
        rpcToolResult(
          res,
          id,
          "La ejecución fue rechazada.",
          true,
          { reasonCode: reason },
        );
      }
    },
  );
  router.use(
    (
      _error: unknown,
      _req: Parameters<RequestHandler>[0],
      res: Parameters<RequestHandler>[1],
      _next: Parameters<RequestHandler>[2],
    ) => {
      if (!res.headersSent) {
        res.status(503).json({ error: "MCP service temporarily unavailable" });
      }
    },
  );
  return router;
}
