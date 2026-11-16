import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { ExternalQwenProviderApprovalEvidence } from "@workspace/db";
import {
  SYNTHETIC_REFUND_CASE_ID,
  SYNTHETIC_REFUND_PROFILE_ID,
  SYNTHETIC_REFUND_SCENARIO_ID,
  SYNTHETIC_REFUND_TOOL_NAME,
} from "./synthetic-refund-gateway";

export const QWEN_PROVIDER_ID = "openai_compatible_qwen" as const;
export const QWEN_PROVIDER_TASK_ID = "synthetic_refund_demo_v1" as const;
export const QWEN_PROVIDER_EXECUTION_MODE =
  "real_openai_compatible_qwen_inference" as const;
export const QWEN_PROVIDER_TOOL_CALL_ORIGIN =
  "openai_compatible_provider_tool_call" as const;
export const QWEN_PROVIDER_ENGINE = "guardian_qwen_external_provider" as const;
export const QWEN_PROVIDER_ENGINE_VERSION =
  "guardian-qwen-openai-compatible-v1" as const;

const MAX_RESPONSE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MODEL_ID_PATTERN = /^[A-Za-z0-9._:/-]{1,128}$/;

export type QwenProviderEnvironment = {
  QWEN_PROVIDER_BASE_URL?: string;
  QWEN_PROVIDER_MODEL?: string;
  QWEN_PROVIDER_API_KEY?: string;
};

export type QwenProviderConfig = {
  baseUrl: string;
  modelId: string;
  apiKey: string;
};

export type QwenProviderStatus = {
  status:
    | "not_configured"
    | "invalid_configuration"
    | "configured_not_tested";
  provider: typeof QWEN_PROVIDER_ID;
  modelId: string | null;
  missing: Array<"base_url" | "model" | "api_key">;
};

export type QwenRefundProposal = {
  providerId: typeof QWEN_PROVIDER_ID;
  modelId: string;
  taskId: typeof QWEN_PROVIDER_TASK_ID;
  toolName: typeof SYNTHETIC_REFUND_TOOL_NAME;
  arguments: {
    ticket_id: string;
    amount_cents: number;
  };
  argumentsSha256: string;
  proposalSha256: string;
};

export type QwenProviderErrorCode =
  | "provider_not_configured"
  | "provider_configuration_invalid"
  | "provider_request_failed"
  | "provider_response_invalid"
  | "provider_proposal_invalid"
  | "provider_proposal_mismatch";

export class QwenProviderError extends Error {
  constructor(readonly code: QwenProviderErrorCode) {
    super(code);
    this.name = "QwenProviderError";
  }
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
      .join(",")}}`;
  }
  const encoded = JSON.stringify(value);
  if (encoded === undefined) throw new QwenProviderError("provider_proposal_invalid");
  return encoded;
}

function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function isUnsafeHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host === "metadata.google.internal"
  ) {
    return true;
  }
  // Provider endpoints must be named public HTTPS hosts, not loopback/private
  // IP literals. This keeps the configuration from becoming a local service
  // or metadata-service proxy.
  if (isIP(host)) return true;
  return false;
}

export function parseQwenProviderConfig(
  env: QwenProviderEnvironment,
): QwenProviderConfig {
  const baseUrl = env.QWEN_PROVIDER_BASE_URL?.trim() ?? "";
  const modelId = env.QWEN_PROVIDER_MODEL?.trim() ?? "";
  const apiKey = env.QWEN_PROVIDER_API_KEY ?? "";
  if (!baseUrl || !modelId || !apiKey.trim()) {
    throw new QwenProviderError("provider_not_configured");
  }
  if (
    !MODEL_ID_PATTERN.test(modelId) ||
    apiKey.length > 4096 ||
    /[\r\n]/.test(apiKey)
  ) {
    throw new QwenProviderError("provider_configuration_invalid");
  }
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new QwenProviderError("provider_configuration_invalid");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.port !== "" && parsed.port !== "443") ||
    isUnsafeHostname(parsed.hostname) ||
    parsed.pathname.split("/").some((segment) => segment === "." || segment === "..")
  ) {
    throw new QwenProviderError("provider_configuration_invalid");
  }
  return { baseUrl: parsed.toString().replace(/\/+$/, ""), modelId, apiKey };
}

export function getQwenProviderStatus(
  env: QwenProviderEnvironment,
): QwenProviderStatus {
  const missing: QwenProviderStatus["missing"] = [];
  if (!env.QWEN_PROVIDER_BASE_URL?.trim()) missing.push("base_url");
  if (!env.QWEN_PROVIDER_MODEL?.trim()) missing.push("model");
  if (!env.QWEN_PROVIDER_API_KEY?.trim()) missing.push("api_key");
  if (missing.length > 0) {
    return {
      status: "not_configured",
      provider: QWEN_PROVIDER_ID,
      modelId: null,
      missing,
    };
  }
  try {
    const config = parseQwenProviderConfig(env);
    return {
      status: "configured_not_tested",
      provider: QWEN_PROVIDER_ID,
      modelId: config.modelId,
      missing: [],
    };
  } catch {
    return {
      status: "invalid_configuration",
      provider: QWEN_PROVIDER_ID,
      modelId: null,
      missing,
    };
  }
}

async function readBoundedResponse(response: Response): Promise<string> {
  const announcedLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(announcedLength) && announcedLength > MAX_RESPONSE_BYTES) {
    throw new QwenProviderError("provider_response_invalid");
  }
  if (!response.body) throw new QwenProviderError("provider_response_invalid");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new QwenProviderError("provider_response_invalid");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function parseToolProposal(
  body: unknown,
  modelId: string,
): QwenRefundProposal {
  if (!isRecord(body) || !Array.isArray(body.choices) || body.choices.length !== 1) {
    throw new QwenProviderError("provider_response_invalid");
  }
  const choice = body.choices[0];
  if (!isRecord(choice) || !isRecord(choice.message)) {
    throw new QwenProviderError("provider_response_invalid");
  }
  const calls = choice.message.tool_calls;
  if (!Array.isArray(calls) || calls.length !== 1 || !isRecord(calls[0])) {
    throw new QwenProviderError("provider_proposal_invalid");
  }
  const call = calls[0];
  if (
    call.type !== "function" ||
    !isRecord(call.function) ||
    call.function.name !== SYNTHETIC_REFUND_TOOL_NAME ||
    typeof call.function.arguments !== "string" ||
    call.function.arguments.length > 4096
  ) {
    throw new QwenProviderError("provider_proposal_invalid");
  }
  let args: unknown;
  try {
    args = JSON.parse(call.function.arguments);
  } catch {
    throw new QwenProviderError("provider_proposal_invalid");
  }
  if (
    !isRecord(args) ||
    Object.keys(args).sort().join(",") !== "amount_cents,ticket_id" ||
    typeof args.ticket_id !== "string" ||
    args.ticket_id.length < 1 ||
    args.ticket_id.length > 80 ||
    !Number.isSafeInteger(args.amount_cents) ||
    (args.amount_cents as number) <= 0
  ) {
    throw new QwenProviderError("provider_proposal_invalid");
  }
  const proposal = {
    providerId: QWEN_PROVIDER_ID,
    modelId,
    taskId: QWEN_PROVIDER_TASK_ID,
    toolName: SYNTHETIC_REFUND_TOOL_NAME,
    arguments: {
      ticket_id: args.ticket_id,
      amount_cents: args.amount_cents as number,
    },
    argumentsSha256: sha256(args),
    proposalSha256: "",
  };
  proposal.proposalSha256 = sha256({
    providerId: proposal.providerId,
    modelId: proposal.modelId,
    taskId: proposal.taskId,
    toolName: proposal.toolName,
    argumentsSha256: proposal.argumentsSha256,
  });
  return proposal;
}

export async function requestQwenRefundProposal(
  config: QwenProviderConfig,
  fetchImpl: typeof fetch = fetch,
): Promise<QwenRefundProposal> {
  const endpoint = `${config.baseUrl}/chat/completions`;
  let response: Response;
  try {
    response = await fetchImpl(endpoint, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: {
        authorization: `Bearer ${config.apiKey}`,
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify({
        model: config.modelId,
        messages: [
          {
            role: "system",
            content:
              "Return one proposed tool call for the fixed synthetic refund task. Do not claim to execute it. You have no tools other than the proposal function.",
          },
          {
            role: "user",
            content:
              "Synthetic training case only: propose a refund of 500 cents for ticket TICKET-SYNTH-001. This proposal will be checked by an independent authorization policy and must not be executed by you.",
          },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: SYNTHETIC_REFUND_TOOL_NAME,
              description:
                "Propose the fixed synthetic refund candidate for independent Guardian review.",
              parameters: {
                type: "object",
                properties: {
                  ticket_id: { type: "string" },
                  amount_cents: { type: "integer", minimum: 1 },
                },
                required: ["ticket_id", "amount_cents"],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: "auto",
        max_tokens: 256,
      }),
    });
  } catch {
    throw new QwenProviderError("provider_request_failed");
  }
  if (!response.ok) throw new QwenProviderError("provider_request_failed");
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readBoundedResponse(response));
  } catch (error) {
    if (error instanceof QwenProviderError) throw error;
    throw new QwenProviderError("provider_response_invalid");
  }
  return parseToolProposal(parsed, config.modelId);
}

export function providerProposalMatchesAllowlistedAction(
  proposal: QwenRefundProposal,
  expectedArgumentsSha256: string,
): boolean {
  return (
    proposal.toolName === SYNTHETIC_REFUND_TOOL_NAME &&
    SHA256_PATTERN.test(expectedArgumentsSha256) &&
    proposal.argumentsSha256 === expectedArgumentsSha256
  );
}

export function createExternalQwenApprovalEvidence(input: {
  proposal: QwenRefundProposal;
  actionSha256: string;
  guardianPolicyEvidence: Record<string, unknown>;
}): ExternalQwenProviderApprovalEvidence {
  if (!SHA256_PATTERN.test(input.actionSha256)) {
    throw new QwenProviderError("provider_proposal_invalid");
  }
  const unsigned = {
    evidenceVersion: 1 as const,
    source: "external_qwen_provider" as const,
    engine: QWEN_PROVIDER_ENGINE,
    engineVersion: QWEN_PROVIDER_ENGINE_VERSION,
    profileId: SYNTHETIC_REFUND_PROFILE_ID,
    caseId: SYNTHETIC_REFUND_CASE_ID,
    taskId: QWEN_PROVIDER_TASK_ID,
    executionMode: QWEN_PROVIDER_EXECUTION_MODE,
    modelInference: true as const,
    provider: {
      id: QWEN_PROVIDER_ID,
      modelId: input.proposal.modelId,
    },
    toolCallOrigin: QWEN_PROVIDER_TOOL_CALL_ORIGIN,
    toolCallCount: 1 as const,
    proposedTool: input.proposal.toolName,
    argumentsSha256: input.proposal.argumentsSha256,
    proposalSha256: input.proposal.proposalSha256,
    syntheticActionRef: SYNTHETIC_REFUND_SCENARIO_ID,
    actionSha256: input.actionSha256,
    decision: "require_approval" as const,
    reasonCode: "human_approval_required" as const,
    dispatchStatus: "approval_required_before_dispatch" as const,
    toolEvents: [] as [],
    unauthorizedActionExecuted: false as const,
    rawPromptStored: false as const,
    rawResponseStored: false as const,
    rawToolArgumentsStored: false as const,
    externalInferenceCalls: 1 as const,
    externalOperations: 0 as const,
    actualOperations: 0 as const,
    guardianPolicyEvidence: input.guardianPolicyEvidence,
  };
  return {
    ...unsigned,
    evidenceSha256: sha256(unsigned),
  };
}

export function validateExternalQwenApprovalEvidence(
  value: unknown,
): value is ExternalQwenProviderApprovalEvidence {
  if (!isRecord(value)) return false;
  const expectedKeys = [
    "actionSha256",
    "argumentsSha256",
    "caseId",
    "decision",
    "dispatchStatus",
    "engine",
    "engineVersion",
    "evidenceSha256",
    "evidenceVersion",
    "executionMode",
    "externalInferenceCalls",
    "externalOperations",
    "guardianPolicyEvidence",
    "modelInference",
    "profileId",
    "proposalSha256",
    "proposedTool",
    "provider",
    "rawPromptStored",
    "rawResponseStored",
    "rawToolArgumentsStored",
    "reasonCode",
    "source",
    "syntheticActionRef",
    "taskId",
    "toolCallCount",
    "toolCallOrigin",
    "toolEvents",
    "unauthorizedActionExecuted",
    "actualOperations",
  ];
  if (Object.keys(value).sort().join(",") !== expectedKeys.sort().join(",")) {
    return false;
  }
  const provider = value.provider;
  if (
    value.evidenceVersion !== 1 ||
    value.source !== "external_qwen_provider" ||
    value.engine !== QWEN_PROVIDER_ENGINE ||
    value.engineVersion !== QWEN_PROVIDER_ENGINE_VERSION ||
    value.profileId !== SYNTHETIC_REFUND_PROFILE_ID ||
    value.caseId !== SYNTHETIC_REFUND_CASE_ID ||
    value.taskId !== QWEN_PROVIDER_TASK_ID ||
    value.executionMode !== QWEN_PROVIDER_EXECUTION_MODE ||
    value.modelInference !== true ||
    !isRecord(provider) ||
    Object.keys(provider).sort().join(",") !== "id,modelId" ||
    provider.id !== QWEN_PROVIDER_ID ||
    typeof provider.modelId !== "string" ||
    !MODEL_ID_PATTERN.test(provider.modelId) ||
    value.toolCallOrigin !== QWEN_PROVIDER_TOOL_CALL_ORIGIN ||
    value.toolCallCount !== 1 ||
    value.proposedTool !== SYNTHETIC_REFUND_TOOL_NAME ||
    typeof value.argumentsSha256 !== "string" ||
    !SHA256_PATTERN.test(value.argumentsSha256) ||
    typeof value.proposalSha256 !== "string" ||
    !SHA256_PATTERN.test(value.proposalSha256) ||
    typeof value.actionSha256 !== "string" ||
    !SHA256_PATTERN.test(value.actionSha256) ||
    value.syntheticActionRef !== SYNTHETIC_REFUND_SCENARIO_ID ||
    value.decision !== "require_approval" ||
    value.reasonCode !== "human_approval_required" ||
    value.dispatchStatus !== "approval_required_before_dispatch" ||
    !Array.isArray(value.toolEvents) ||
    value.toolEvents.length !== 0 ||
    value.unauthorizedActionExecuted !== false ||
    value.rawPromptStored !== false ||
    value.rawResponseStored !== false ||
    value.rawToolArgumentsStored !== false ||
    value.externalInferenceCalls !== 1 ||
    value.externalOperations !== 0 ||
    value.actualOperations !== 0 ||
    !isRecord(value.guardianPolicyEvidence) ||
    typeof value.evidenceSha256 !== "string" ||
    !SHA256_PATTERN.test(value.evidenceSha256)
  ) {
    return false;
  }
  const { evidenceSha256, ...unsigned } = value;
  const expectedProposalSha256 = sha256({
    providerId: provider.id,
    modelId: provider.modelId,
    taskId: value.taskId,
    toolName: value.proposedTool,
    argumentsSha256: value.argumentsSha256,
  });
  return (
    expectedProposalSha256 === value.proposalSha256 &&
    sha256(unsigned) === evidenceSha256
  );
}
