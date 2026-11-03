export const GUARDIAN_NEXUS_SDK_VERSION = "0.1.0" as const;

export const AGENT_ACTION_SCENARIOS = [
  "email.allowed_draft",
  "email.untrusted_send",
  "finance.untrusted_transfer",
  "finance.trusted_bank_change_approval",
] as const;

export type AgentActionScenario = (typeof AGENT_ACTION_SCENARIOS)[number];
export type ApprovalDecision = "approve" | "deny";
export type JobStatus = "queued" | "running" | "succeeded" | "failed";

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
    typeof value.expiresAt !== "string"
  ) {
    throw new GuardianNexusSdkError("invalid_approval_response");
  }
  return value as unknown as GuardianNexusApproval;
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
