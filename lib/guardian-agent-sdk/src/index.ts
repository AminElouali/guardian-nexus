export const GUARDIAN_NEXUS_SDK_VERSION = "0.2.0" as const;

export const AGENT_ACTION_SCENARIOS = [
  "email.allowed_draft",
  "email.untrusted_send",
  "finance.untrusted_transfer",
  "finance.trusted_bank_change_approval",
] as const;

export type AgentActionScenario = (typeof AGENT_ACTION_SCENARIOS)[number];

export const QWEN_AGENT_PROFILE_IDS = [
  "guardian-agent-qwen-lab-email-v1",
  "guardian-agent-qwen-lab-database-v1",
  "guardian-agent-qwen-lab-finance-v1",
  "guardian-agent-qwen-lab-customer-service-v1",
  "guardian-agent-qwen-lab-programming-v1",
  "guardian-agent-qwen-lab-browser-v1",
  "guardian-agent-qwen-lab-infrastructure-v1",
  "guardian-agent-qwen-lab-multiagent-v1",
] as const;

export type QwenAgentProfileId = (typeof QWEN_AGENT_PROFILE_IDS)[number];
export type QwenAgentVertical =
  | "email"
  | "database"
  | "finance"
  | "customer_service"
  | "programming"
  | "browser"
  | "infrastructure"
  | "multiagent";
export type QwenToolCallOrigin =
  | "guardian_qwen_native_markup_adapter"
  | "unparsed_qwen_native_markup"
  | "runtime_message_tool_calls"
  | "no_tool_call";
export type QwenPolicyDecision =
  | "allow"
  | "deny"
  | "require_approval"
  | "no_proposal";

export interface QwenPolicyCaseSummary {
  caseId: string;
  label: "benign" | "adversarial";
  language: "en" | "es";
  toolChoice: "auto";
  toolCallOrigin: QwenToolCallOrigin;
  toolCallCount: number;
  proposedTool: string | null;
  decision: QwenPolicyDecision;
  dispatchStatus:
    | "not_invoked"
    | "simulated_execution"
    | "blocked_by_policy_before_dispatch"
    | "approval_required_before_dispatch"
    | "blocked_by_adapter_validation"
    | "blocked_by_parser";
  simulatedExecution: boolean;
  caseEvidenceSha256: string;
}

export interface QwenPolicyLabReport {
  source: "qwen_local_policy_lab";
  engine: "guardian_qwen_policy_lab";
  engineVersion: string;
  profileId: QwenAgentProfileId;
  verticalId: QwenAgentVertical;
  executionMode: "real_local_qwen_inference";
  toolChoice: "auto";
  evidenceSha256: string;
  counts: {
    cases: number;
    directRuntimeToolCallCases: number;
    adaptedQwenMarkerCases: number;
    unparsedMarkerCases: number;
    noToolCallCases: number;
    allow: number;
    deny: number;
    requireApproval: number;
    noProposal: number;
    simulatedExecutions: number;
  };
  cases: QwenPolicyCaseSummary[];
}

export interface QwenEvaluationSubmission {
  source: "qwen_local_policy_lab_profile";
  executionMode: "not_yet_verified";
  externalDispatch: false;
  job: Pick<
    GuardianNexusJob,
    "id" | "status" | "profileId" | "workerVersion" | "createdAt"
  > & { profileId: QwenAgentProfileId };
}

export interface QwenEvaluationCompletion {
  job: Pick<
    GuardianNexusJob,
    | "id"
    | "status"
    | "profileId"
    | "workerVersion"
    | "attempts"
    | "engineVersion"
    | "createdAt"
    | "startedAt"
    | "completedAt"
  > & { profileId: QwenAgentProfileId };
  report: QwenPolicyLabReport;
}

export type ApprovalDecision = "approve" | "deny";
export type JobStatus = "queued" | "running" | "succeeded" | "failed";

const QWEN_PROFILE_VERTICAL: Record<QwenAgentProfileId, QwenAgentVertical> = {
  "guardian-agent-qwen-lab-email-v1": "email",
  "guardian-agent-qwen-lab-database-v1": "database",
  "guardian-agent-qwen-lab-finance-v1": "finance",
  "guardian-agent-qwen-lab-customer-service-v1": "customer_service",
  "guardian-agent-qwen-lab-programming-v1": "programming",
  "guardian-agent-qwen-lab-browser-v1": "browser",
  "guardian-agent-qwen-lab-infrastructure-v1": "infrastructure",
  "guardian-agent-qwen-lab-multiagent-v1": "multiagent",
};

export interface GuardianNexusJob {
  id: string;
  status: JobStatus;
  profileId: string;
  workerVersion: string;
  attempts: number;
  engineVersion: string | null;
  result: unknown | null;
  errorCode: string | null;
  createdAt: string;
  startedAt: string | null;
  completedAt: string | null;
}

export interface AgentActionSubmission {
  adapterVersion: "guardian-agent-intent-adapter-v1";
  source: "fixed_synthetic_scenario";
  decisionStatus: "pending_worker_evaluation";
  externalDispatch: false;
  actionIntent: {
    contractVersion: "guardian-action-intent-v1";
    agentId: "guardian-synthetic-external-agent-v1";
    actorUserId: string;
    actorRole: "owner" | "admin";
    workspaceId: string;
    scenarioId: AgentActionScenario;
    caseId: string;
    toolId: string;
    operation: string;
    resourceType: string;
    resourceId: string;
    sensitivity: string;
    instructionProvenance: string;
    requiredPermissions: string[];
    intentSha256: string;
  };
  job: Pick<
    GuardianNexusJob,
    "id" | "status" | "profileId" | "workerVersion" | "createdAt"
  >;
}

export interface GuardianNexusApproval {
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
  status: "pending" | "approved" | "denied" | "expired";
  expiresAt: string;
  decidedByUserId: string | null;
  decidedByRole: string | null;
  decidedAt: string | null;
  simulatedAt: string | null;
  simulationResultCode: string | null;
  simulationResultSha256: string | null;
  execution?: "synthetic_action_simulated_once" | "not_performed";
  replayBindingSha256?: string | null;
}

export interface ApprovalDecisionResult {
  approval: GuardianNexusApproval;
  execution: "synthetic_action_simulated_once" | "not_performed";
}

export interface GuardianNexusClientOptions {
  /** API origin or API base URL. Plain HTTP is allowed only for loopback labs. */
  baseUrl: string;
  workspaceId: string;
  /** Supply a short-lived token from the host application's auth session. */
  getAccessToken: () => Promise<string | null> | string | null;
  fetch?: typeof fetch;
  /** Bounded network/5xx retries. Intent retries reuse the same idempotency key. */
  maxRetries?: number;
}

export class GuardianNexusSdkError extends Error {
  readonly status: number | null;
  readonly code: string;
  readonly retryAfterMs: number | null;

  constructor(
    code: string,
    status: number | null = null,
    retryAfterMs: number | null = null,
  ) {
    super(code);
    this.name = "GuardianNexusSdkError";
    this.code = code;
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

function safeApiCode(value: unknown): string {
  const approvalErrors: Record<string, string> = {
    "Approval is already_decided": "approval_already_decided",
    "Approval is expired": "approval_expired",
    "Approval is binding_mismatch": "approval_binding_mismatch",
    "Approval is evidence_invalid": "approval_evidence_invalid",
  };
  if (
    typeof value === "string" &&
    Object.prototype.hasOwnProperty.call(approvalErrors, value)
  ) {
    return approvalErrors[value]!;
  }
  if (
    typeof value === "string" &&
    value.length <= 80 &&
    /^[a-zA-Z0-9_.-]+$/.test(value)
  ) {
    return value;
  }
  return "request_rejected";
}

function resolveApiBase(baseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new GuardianNexusSdkError("invalid_base_url");
  }
  const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);
  if (
    !["https:", "http:"].includes(parsed.protocol) ||
    (parsed.protocol === "http:" && !loopbackHosts.has(parsed.hostname)) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new GuardianNexusSdkError("insecure_or_invalid_base_url");
  }
  const path = parsed.pathname.replace(/\/+$/, "");
  const originAndPath = `${parsed.origin}${path}`;
  return path.endsWith("/api") ? originAndPath : `${originAndPath}/api`;
}

function expectJob(value: unknown): GuardianNexusJob {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !isUuid(value.id) ||
    !["queued", "running", "succeeded", "failed"].includes(
      String(value.status),
    ) ||
    typeof value.profileId !== "string" ||
    typeof value.workerVersion !== "string" ||
    typeof value.attempts !== "number" ||
    !(typeof value.engineVersion === "string" || value.engineVersion === null) ||
    !(value.result === null || "result" in value) ||
    !(typeof value.errorCode === "string" || value.errorCode === null) ||
    typeof value.createdAt !== "string" ||
    !(typeof value.startedAt === "string" || value.startedAt === null) ||
    !(typeof value.completedAt === "string" || value.completedAt === null)
  ) {
    throw new GuardianNexusSdkError("invalid_job_response");
  }
  return value as unknown as GuardianNexusJob;
}

function expectApproval(value: unknown): GuardianNexusApproval {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    !isUuid(value.id) ||
    typeof value.jobId !== "string" ||
    !isUuid(value.jobId) ||
    typeof value.caseId !== "string" ||
    typeof value.proposalSha256 !== "string" ||
    typeof value.proposalBindingSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.proposalBindingSha256) ||
    typeof value.requestedByUserId !== "string" ||
    !["pending", "approved", "denied", "expired"].includes(
      String(value.status),
    ) ||
    typeof value.expiresAt !== "string" ||
    ("execution" in value &&
      value.execution !== "synthetic_action_simulated_once" &&
      value.execution !== "not_performed") ||
    ("replayBindingSha256" in value &&
      value.replayBindingSha256 !== null &&
      !isSha256(value.replayBindingSha256))
  ) {
    throw new GuardianNexusSdkError("invalid_approval_response");
  }
  return value as unknown as GuardianNexusApproval;
}

const QWEN_CASE_ORIGINS = new Set<string>([
  "guardian_qwen_native_markup_adapter",
  "unparsed_qwen_native_markup",
  "runtime_message_tool_calls",
  "no_tool_call",
]);
const QWEN_CASE_DECISIONS = new Set<string>([
  "allow",
  "deny",
  "require_approval",
  "no_proposal",
]);
const QWEN_DISPATCH_STATUSES = new Set<string>([
  "not_invoked",
  "simulated_execution",
  "blocked_by_policy_before_dispatch",
  "approval_required_before_dispatch",
  "blocked_by_adapter_validation",
  "blocked_by_parser",
]);

function isSha256(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function requireBooleanFields(
  value: Record<string, unknown>,
  fields: string[],
): boolean {
  return fields.every((field) => value[field] === true);
}

function expectQwenPolicyReport(
  value: unknown,
  expectedProfileId: QwenAgentProfileId,
): QwenPolicyLabReport {
  if (
    !isRecord(value) ||
    value.evidenceVersion !== 1 ||
    value.source !== "qwen_local_policy_lab" ||
    value.engine !== "guardian_qwen_policy_lab" ||
    typeof value.engineVersion !== "string" ||
    !/^guardian-agent-qwen-policy-lab-v\d+(?:\.\d+)*$/.test(
      value.engineVersion,
    ) ||
    value.profileId !== expectedProfileId ||
    value.verticalId !== QWEN_PROFILE_VERTICAL[expectedProfileId] ||
    value.executionMode !== "real_local_qwen_inference" ||
    value.proposalOriginScope !==
      "qwen_marker_adapter_or_runtime_tool_calls_only" ||
    !isSha256(value.evidenceSha256) ||
    !isRecord(value.provider) ||
    value.provider.id !== "local_qwen_gguf" ||
    value.provider.toolChoice !== "auto" ||
    !isRecord(value.network) ||
    value.network.networkMode !== "docker-network-none" ||
    value.network.loopbackOnly !== true ||
    value.network.publicIpv4 !== "blocked" ||
    value.network.publicDns !== "blocked" ||
    !["blocked", "unavailable"].includes(
      String(value.network.publicIpv6),
    ) ||
    !isRecord(value.limits) ||
    value.limits.concurrency !== 1 ||
    value.limits.pids !== 64 ||
    value.limits.cpuCores !== 1 ||
    value.limits.memoryMiB !== 1536 ||
    value.limits.network !== "docker-network-none" ||
    value.limits.externalCalls !== 0 ||
    value.limits.actualOperations !== 0 ||
    value.limits.customerDataUsed !== false ||
    value.limits.secretsMounted !== false ||
    value.limits.rawPromptsStored !== false ||
    value.limits.rawResponsesStored !== false ||
    value.limits.rawToolArgumentsStored !== false ||
    value.limits.maxToolCallsPerCase !== 1 ||
    value.limits.maxModelCallsPerCase !== 1 ||
    value.limits.maxCompletionTokensPerCall !== 96 ||
    !isRecord(value.limits.verifiedContainerLimits) ||
    value.limits.verifiedContainerLimits.cpuLimitVerified !== true ||
    value.limits.verifiedContainerLimits.pidsLimitVerified !== true ||
    value.limits.verifiedContainerLimits.memoryLimitVerified !== true ||
    !isRecord(value.selfChecks) ||
    !requireBooleanFields(value.selfChecks, [
      "allCallsUsedAuto",
      "noForcedToolSelection",
      "onlyRealLocalQwenInference",
      "policyBeforeDispatch",
      "deniedCallsNeverDispatched",
      "policyOffCloneOnly",
      "noRawPromptsResponsesOrArguments",
    ]) ||
    !isRecord(value.summary) ||
    !Array.isArray(value.cases) ||
    value.cases.length < 2 ||
    value.cases.length > 7
  ) {
    throw new GuardianNexusSdkError("invalid_qwen_policy_evidence");
  }

  const summary = value.summary;
  const cases: QwenPolicyCaseSummary[] = [];
  for (const rawCase of value.cases) {
    if (
      !isRecord(rawCase) ||
      typeof rawCase.caseId !== "string" ||
      rawCase.caseId.length < 1 ||
      rawCase.caseId.length > 100 ||
      !["benign", "adversarial"].includes(String(rawCase.label)) ||
      !["en", "es"].includes(String(rawCase.language)) ||
      rawCase.toolChoice !== "auto" ||
      !QWEN_CASE_ORIGINS.has(String(rawCase.toolCallOrigin)) ||
      !Number.isInteger(rawCase.toolCallCount) ||
      (rawCase.toolCallCount as number) < 0 ||
      (rawCase.toolCallCount as number) > 16 ||
      !(typeof rawCase.proposedTool === "string" ||
        rawCase.proposedTool === null) ||
      !QWEN_CASE_DECISIONS.has(String(rawCase.decision)) ||
      !QWEN_DISPATCH_STATUSES.has(String(rawCase.dispatchStatus)) ||
      rawCase.unauthorizedActionExecuted !== false ||
      rawCase.rawPromptStored !== false ||
      rawCase.rawResponseStored !== false ||
      rawCase.rawArgumentsStored !== false ||
      !isSha256(rawCase.policyOnStateBeforeSha256) ||
      !isSha256(rawCase.policyOnStateAfterSha256) ||
      !isSha256(rawCase.caseEvidenceSha256) ||
      !Array.isArray(rawCase.toolEvents) ||
      rawCase.toolEvents.length > 2 ||
      !isRecord(rawCase.policyOff) ||
      rawCase.policyOff.mode !== "counterfactual_clone_only" ||
      rawCase.policyOff.executed !== false ||
      typeof rawCase.policyOff.wouldExecute !== "boolean" ||
      !isSha256(rawCase.policyOff.stateBeforeSha256) ||
      !isSha256(rawCase.policyOff.stateAfterSha256)
    ) {
      throw new GuardianNexusSdkError("invalid_qwen_policy_case");
    }

    let simulatedExecution = false;
    for (const event of rawCase.toolEvents) {
      if (
        !isRecord(event) ||
        !["authorization_attempt", "denied", "executed"].includes(
          String(event.phase),
        ) ||
        !["not_checked", "allowed", "denied"].includes(
          String(event.authorization),
        ) ||
        typeof event.executed !== "boolean" ||
        event.simulatedOnly !== true ||
        event.externalSideEffect !== false ||
        !isSha256(event.argumentsSha256) ||
        typeof event.resultCode !== "string"
      ) {
        throw new GuardianNexusSdkError("invalid_qwen_tool_event");
      }
      if (event.executed) {
        simulatedExecution = true;
        if (
          rawCase.decision !== "allow" ||
          rawCase.dispatchStatus !== "simulated_execution"
        ) {
          throw new GuardianNexusSdkError("invalid_qwen_dispatch_state");
        }
      }
    }
    if (
      (rawCase.decision === "deny" ||
        rawCase.decision === "require_approval" ||
        rawCase.decision === "no_proposal") &&
      simulatedExecution
    ) {
      throw new GuardianNexusSdkError("invalid_qwen_dispatch_state");
    }
    if (
      rawCase.dispatchStatus === "simulated_execution" &&
      !simulatedExecution
    ) {
      throw new GuardianNexusSdkError("invalid_qwen_dispatch_state");
    }
    cases.push({
      caseId: rawCase.caseId,
      label: rawCase.label as "benign" | "adversarial",
      language: rawCase.language as "en" | "es",
      toolChoice: "auto",
      toolCallOrigin: rawCase.toolCallOrigin as QwenToolCallOrigin,
      toolCallCount: rawCase.toolCallCount as number,
      proposedTool: rawCase.proposedTool as string | null,
      decision: rawCase.decision as QwenPolicyDecision,
      dispatchStatus: rawCase.dispatchStatus as QwenPolicyCaseSummary["dispatchStatus"],
      simulatedExecution,
      caseEvidenceSha256: rawCase.caseEvidenceSha256,
    });
  }

  const countOrigin = (origin: QwenToolCallOrigin) =>
    cases.filter((item) => item.toolCallOrigin === origin).length;
  const countDecision = (decision: QwenPolicyDecision) =>
    cases.filter((item) => item.decision === decision).length;
  const counts = {
    cases: cases.length,
    directRuntimeToolCallCases: countOrigin("runtime_message_tool_calls"),
    adaptedQwenMarkerCases: countOrigin(
      "guardian_qwen_native_markup_adapter",
    ),
    unparsedMarkerCases: countOrigin("unparsed_qwen_native_markup"),
    noToolCallCases: countOrigin("no_tool_call"),
    allow: countDecision("allow"),
    deny: countDecision("deny"),
    requireApproval: countDecision("require_approval"),
    noProposal: countDecision("no_proposal"),
    simulatedExecutions: cases.filter((item) => item.simulatedExecution).length,
  };
  if (
    !Number.isInteger(summary.modelCalls) ||
    summary.modelCalls !== cases.length ||
    value.limits.maxCases !== cases.length ||
    summary.sampleCount !== cases.length ||
    summary.benignCases !== cases.filter((item) => item.label === "benign").length ||
    summary.adversarialCases !==
      cases.filter((item) => item.label === "adversarial").length ||
    summary.noToolCalls !== counts.noToolCallCases ||
    !Number.isInteger(summary.runtimeMessageToolCalls) ||
    summary.runtimeMessageToolCalls !== counts.directRuntimeToolCallCases ||
    !Number.isInteger(summary.adaptedQwenMarkupCalls) ||
    summary.adaptedQwenMarkupCalls !== counts.adaptedQwenMarkerCases ||
    summary.simulatedExecutions !== counts.simulatedExecutions ||
    summary.externalCalls !== 0 ||
    summary.unauthorizedExecutions !== 0 ||
    summary.policyOffExecutions !== 0
  ) {
    throw new GuardianNexusSdkError("inconsistent_qwen_policy_summary");
  }

  return {
    source: "qwen_local_policy_lab",
    engine: "guardian_qwen_policy_lab",
    engineVersion: value.engineVersion,
    profileId: expectedProfileId,
    verticalId: value.verticalId as QwenAgentVertical,
    executionMode: "real_local_qwen_inference",
    toolChoice: "auto",
    evidenceSha256: value.evidenceSha256,
    counts,
    cases,
  };
}

function retryDelay(response: Response, fallbackMs: number): number {
  const value = response.headers.get("retry-after");
  if (!value) return fallbackMs;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(5_000, seconds * 1_000);
  }
  const at = Date.parse(value);
  return Number.isFinite(at)
    ? Math.max(0, Math.min(5_000, at - Date.now()))
    : fallbackMs;
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new GuardianNexusSdkError("request_aborted"));
      return;
    }
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      "abort",
      () => {
        clearTimeout(timer);
        reject(new GuardianNexusSdkError("request_aborted"));
      },
      { once: true },
    );
  });
}

export class GuardianNexusClient {
  private readonly apiBase: string;
  private readonly fetcher: typeof fetch;
  private readonly maxRetries: number;

  constructor(private readonly options: GuardianNexusClientOptions) {
    if (!isUuid(options.workspaceId)) {
      throw new GuardianNexusSdkError("invalid_workspace_id");
    }
    this.apiBase = resolveApiBase(options.baseUrl);
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.maxRetries = Math.max(0, Math.min(3, options.maxRetries ?? 2));
  }

  async submitIntent(input: {
    scenarioId: AgentActionScenario;
    idempotencyKey: string;
    signal?: AbortSignal;
  }): Promise<AgentActionSubmission> {
    if (
      !AGENT_ACTION_SCENARIOS.includes(input.scenarioId) ||
      !/^[A-Za-z0-9._:-]{16,128}$/.test(input.idempotencyKey)
    ) {
      throw new GuardianNexusSdkError("invalid_intent_request");
    }
    const value = await this.request(
      `/workspaces/${this.options.workspaceId}/agent-action-adapter/intents`,
      {
        method: "POST",
        body: JSON.stringify({
          contractVersion: "guardian-action-intent-v1",
          scenarioId: input.scenarioId,
          idempotencyKey: input.idempotencyKey,
        }),
        signal: input.signal,
        retryable: true,
      },
    );
    if (
      !isRecord(value) ||
      value.adapterVersion !== "guardian-agent-intent-adapter-v1" ||
      value.source !== "fixed_synthetic_scenario" ||
      value.decisionStatus !== "pending_worker_evaluation" ||
      value.externalDispatch !== false ||
      !isRecord(value.actionIntent) ||
      !isRecord(value.job) ||
      typeof value.job.id !== "string" ||
      !isUuid(value.job.id)
    ) {
      throw new GuardianNexusSdkError("invalid_intent_response");
    }
    return value as unknown as AgentActionSubmission;
  }

  async submitQwenEvaluation(input: {
    profileId: QwenAgentProfileId;
    idempotencyKey: string;
    signal?: AbortSignal;
  }): Promise<QwenEvaluationSubmission> {
    if (
      !QWEN_AGENT_PROFILE_IDS.includes(input.profileId) ||
      !/^[A-Za-z0-9._:-]{16,128}$/.test(input.idempotencyKey)
    ) {
      throw new GuardianNexusSdkError("invalid_qwen_evaluation_request");
    }
    const value = await this.request(
      `/workspaces/${this.options.workspaceId}/ai-security-assessments/lab/jobs`,
      {
        method: "POST",
        body: JSON.stringify({
          profileId: input.profileId,
          idempotencyKey: input.idempotencyKey,
        }),
        signal: input.signal,
        retryable: true,
      },
    );
    const job = expectJob(value);
    if (job.profileId !== input.profileId) {
      throw new GuardianNexusSdkError("qwen_profile_response_mismatch");
    }
    return {
      source: "qwen_local_policy_lab_profile",
      executionMode: "not_yet_verified",
      externalDispatch: false,
      job: {
        id: job.id,
        status: job.status,
        profileId: input.profileId,
        workerVersion: job.workerVersion,
        createdAt: job.createdAt,
      },
    };
  }

  async getJob(jobId: string, signal?: AbortSignal): Promise<GuardianNexusJob> {
    if (!isUuid(jobId)) throw new GuardianNexusSdkError("invalid_job_id");
    const value = await this.request(
      `/workspaces/${this.options.workspaceId}/ai-security-assessments/lab/jobs/${jobId}`,
      { method: "GET", signal, retryable: true },
    );
    return expectJob(value);
  }

  async waitForJob(
    jobId: string,
    options: {
      intervalMs?: number;
      maxAttempts?: number;
      signal?: AbortSignal;
    } = {},
  ): Promise<GuardianNexusJob> {
    const intervalMs = Math.max(50, Math.min(5_000, options.intervalMs ?? 500));
    const maxAttempts = Math.max(1, Math.min(120, options.maxAttempts ?? 60));
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      const job = await this.getJob(jobId, options.signal);
      if (job.status === "succeeded" || job.status === "failed") return job;
      if (attempt + 1 < maxAttempts) await delay(intervalMs, options.signal);
    }
    throw new GuardianNexusSdkError("job_poll_timeout");
  }

  async waitForQwenEvaluation(
    jobId: string,
    profileId: QwenAgentProfileId,
    options: {
      intervalMs?: number;
      maxAttempts?: number;
      signal?: AbortSignal;
    } = {},
  ): Promise<QwenEvaluationCompletion> {
    if (!QWEN_AGENT_PROFILE_IDS.includes(profileId)) {
      throw new GuardianNexusSdkError("invalid_qwen_profile_id");
    }
    const job = await this.waitForJob(jobId, options);
    if (job.status !== "succeeded") {
      throw new GuardianNexusSdkError("qwen_evaluation_failed");
    }
    if (job.profileId !== profileId) {
      throw new GuardianNexusSdkError("qwen_profile_response_mismatch");
    }
    const report = expectQwenPolicyReport(job.result, profileId);
    return {
      job: {
        id: job.id,
        status: "succeeded",
        profileId,
        workerVersion: job.workerVersion,
        attempts: job.attempts,
        engineVersion: job.engineVersion,
        createdAt: job.createdAt,
        startedAt: job.startedAt,
        completedAt: job.completedAt,
      },
      report,
    };
  }

  async listApprovals(signal?: AbortSignal): Promise<GuardianNexusApproval[]> {
    const value = await this.request(
      `/workspaces/${this.options.workspaceId}/ai-security-assessments/approvals`,
      { method: "GET", signal, retryable: true },
    );
    const approvals = Array.isArray(value)
      ? value
      : isRecord(value) && Array.isArray(value.approvals)
        ? value.approvals
        : null;
    if (!approvals) {
      throw new GuardianNexusSdkError("invalid_approval_list_response");
    }
    return approvals.map(expectApproval);
  }

  async decideApproval(input: {
    approvalId: string;
    decision: ApprovalDecision;
    proposalBindingSha256: string;
    signal?: AbortSignal;
  }): Promise<ApprovalDecisionResult> {
    if (
      !isUuid(input.approvalId) ||
      !["approve", "deny"].includes(input.decision) ||
      !/^[a-f0-9]{64}$/.test(input.proposalBindingSha256)
    ) {
      throw new GuardianNexusSdkError("invalid_approval_decision");
    }
    const value = await this.request(
      `/workspaces/${this.options.workspaceId}/ai-security-assessments/approvals/${input.approvalId}/decision`,
      {
        method: "POST",
        body: JSON.stringify({
          decision: input.decision,
          proposalBindingSha256: input.proposalBindingSha256,
        }),
        signal: input.signal,
        // Approval is a one-shot state transition. The server rejects replay;
        // callers should inspect the resulting state instead of retrying it.
        retryable: false,
      },
    );
    if (!isRecord(value) || !isRecord(value.approval)) {
      throw new GuardianNexusSdkError("invalid_approval_decision_response");
    }
    const approval = expectApproval(value.approval);
    if (
      value.execution !== "synthetic_action_simulated_once" &&
      value.execution !== "not_performed"
    ) {
      throw new GuardianNexusSdkError("invalid_approval_execution_response");
    }
    if (
      value.execution === "synthetic_action_simulated_once" &&
      (approval.status !== "approved" ||
        approval.execution !== "synthetic_action_simulated_once" ||
        !approval.simulatedAt ||
        !isSha256(approval.simulationResultSha256) ||
        !isSha256(approval.replayBindingSha256))
    ) {
      throw new GuardianNexusSdkError("invalid_approval_replay_evidence");
    }
    return {
      approval,
      execution: value.execution,
    };
  }

  private async request(
    path: string,
    input: {
      method: "GET" | "POST";
      body?: string;
      signal?: AbortSignal;
      retryable: boolean;
    },
  ): Promise<unknown> {
    const maxAttempts = input.retryable ? this.maxRetries + 1 : 1;
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      if (input.signal?.aborted) {
        throw new GuardianNexusSdkError("request_aborted");
      }
      let token: string | null;
      try {
        token = await this.options.getAccessToken();
      } catch {
        throw new GuardianNexusSdkError("access_token_unavailable");
      }
      if (typeof token !== "string" || token.length < 1 || token.length > 8_192) {
        throw new GuardianNexusSdkError("authentication_required", 401);
      }
      const headers = new Headers({
        accept: "application/json",
        authorization: `Bearer ${token}`,
      });
      if (input.body !== undefined) {
        headers.set("content-type", "application/json");
      }
      let response: Response;
      try {
        response = await this.fetcher(`${this.apiBase}${path}`, {
          method: input.method,
          headers,
          body: input.body,
          signal: input.signal,
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
        });
      } catch {
        if (attempt + 1 < maxAttempts && !input.signal?.aborted) {
          await delay(Math.min(1_000, 100 * 2 ** attempt), input.signal);
          continue;
        }
        throw new GuardianNexusSdkError(
          input.signal?.aborted ? "request_aborted" : "network_error",
        );
      }
      if (response.ok) {
        if (response.status === 204) return null;
        try {
          return await response.json();
        } catch {
          throw new GuardianNexusSdkError("invalid_json_response", response.status);
        }
      }
      const retryableStatus =
        response.status === 408 ||
        response.status === 425 ||
        response.status === 429 ||
        response.status >= 500;
      if (
        retryableStatus &&
        attempt + 1 < maxAttempts &&
        !input.signal?.aborted
      ) {
        await delay(
          retryDelay(response, Math.min(1_000, 100 * 2 ** attempt)),
          input.signal,
        );
        continue;
      }
      let code = "request_rejected";
      try {
        const body = await response.json();
        if (isRecord(body)) code = safeApiCode(body.error ?? body.code);
      } catch {
        // Never expose or retain a raw response body in SDK errors.
      }
      throw new GuardianNexusSdkError(code, response.status);
    }
    throw new GuardianNexusSdkError("request_retry_exhausted");
  }
}

export function createIdempotencyKey(): string {
  if (!globalThis.crypto?.randomUUID) {
    throw new GuardianNexusSdkError("secure_random_unavailable");
  }
  return globalThis.crypto.randomUUID();
}
