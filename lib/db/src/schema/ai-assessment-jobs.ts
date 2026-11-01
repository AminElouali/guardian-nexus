import { sql, type SQLWrapper } from "drizzle-orm";
import {
  check,
  index,
  integer,
  jsonb,
  pgPolicy,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";
import { aiAssessmentWorkerRole, appRuntimeRole } from "./roles";
import { workspacesTable } from "./workspaces";

export type GuardianVerificationObjective =
  | "untrusted_text_present"
  | "synthetic_data_propagated"
  | "untrusted_instruction_obeyed"
  | "action_attempted"
  | "unauthorized_action_attempted"
  | "action_executed"
  | "policy_violation";

export type GuardianVerificationMetric = {
  scenarioId:
    | "synthetic_data_exfiltration"
    | "unauthorized_tool_operation"
    | "indirect_document_injection";
  split: "calibration" | "holdout";
  objective: GuardianVerificationObjective;
  sampleCount: number;
  positiveSupport: number;
  negativeSupport: number;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
  precision: { numerator: number; denominator: number; value: number };
  recall: { numerator: number; denominator: number; value: number };
  falsePositiveRate: { numerator: number; denominator: number; value: number };
  falseNegativeRate: { numerator: number; denominator: number; value: number };
  accuracy: { numerator: number; denominator: number; value: number };
};

export type GuardianVerificationOperation =
  | "email.send.external"
  | "email.send.team"
  | "workspace.admin.disable_audit"
  | "documents.read.local"
  | "documents.read.untrusted";

export type GuardianVerificationCaseEvidence = {
  caseId: string;
  expectedMask: number;
  observedMask: number;
  caseEvidenceSha256: string;
};

export type GuardianVerificationEvidence = {
  engine: "guardian_verification";
  version: string;
  suiteVersion: string;
  agentVersion: string;
  policyVersion: string;
  oracleVersion: string;
  mode: "deterministic_synthetic_local_agent";
  objectiveBitOrder: GuardianVerificationObjective[];
  scenarios: Array<{
    scenarioId: GuardianVerificationMetric["scenarioId"];
    policyId: string;
  }>;
  sampleCount: number;
  seedCount: number;
  splitSampleCounts: { calibration: number; holdout: number };
  metrics: GuardianVerificationMetric[];
  toolCallSummary: {
    total: number;
    authorized: number;
    denied: number;
    executed: number;
    stateChanges: number;
    unauthorizedActionAttempts: number;
    policyViolations: number;
    operationCounts: Record<string, number>;
    byOperation: Array<{
      operation: GuardianVerificationOperation;
      calls: number;
      authorized: number;
      denied: number;
      executed: number;
      policyAllowed: number;
      policyDenied: number;
      stateChanges: number;
      targetActions: number;
      syntheticDataObserved: number;
      policyViolations: number;
    }>;
  };
  anomalyCount: number;
  selfChecks: {
    status: "passed";
    allToolCallsInstrumented: true;
    deniedCallsHaveNoSideEffects: true;
    scenarioPolicyOracleIndependentOfToolGrant: true;
    unknownOperationsRejected: true;
    rawSyntheticContentStored: false;
  };
  caseEvidence: GuardianVerificationCaseEvidence[];
  suiteEvidenceSha256: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  limits: {
    maxRuntimeSeconds: 15;
    maxSamples: 144;
    concurrency: 1;
  };
  syntheticOnly: true;
  rawPromptsStored: false;
  rawResponsesStored: false;
  externalCalls: 0;
  customerDataUsed: false;
  interpretation: string;
};

export type AiAssessmentEvidence = {
  evidenceVersion: 1;
  source: "isolated_local_lab";
  engine: "garak";
  engineVersion: string;
  profileId: "guardian-local-agent-v1";
  probeClasses: string[];
  generationsPerProbe: 1;
  probeRequests: 1;
  reportRecordCount: number;
  reportRecordTypes: Record<string, number>;
  positiveDetectorScores: number;
  findings: Array<{
    probeClass: string;
    detector: string;
    positiveScores: number;
  }>;
  reportSha256: string;
  reportBytes: number;
  network: {
    networkMode: "docker-network-none";
    interfaces: string[];
    activeNonLoopbackInterfaces: string[];
    publicIpv4: "blocked";
    publicIpv6: "blocked" | "unavailable";
    ipv6Capability: "kernel_protocol_unavailable" | "socket_and_route_tested";
    publicDns: "blocked";
    loopbackOnly: true;
  };
  startedAt: string;
  completedAt: string;
  durationSeconds: number;
  promptsStored: false;
  responsesStored: false;
  externalCalls: 0;
  customerDataUsed: false;
  findingSummary: string;
  guardianVerification?: GuardianVerificationEvidence;
};

export type GuardianLocalLlmEvidence = {
  evidenceVersion: 1;
  source: "isolated_local_lab";
  engine: "local_llm_lab";
  engineVersion: "guardian-local-llm-tool-adapter-v1";
  profileId: "guardian-local-llm-qwen3-0.6b-v1";
  executionMode: "real_local_llm_inference";
  toolInvocationMode: "structured_json_emulation";
  taskId: "synthetic_invoice_summary_v1";
  provider: {
    id: "local_qwen_gguf";
    modelId: "Qwen/Qwen3-0.6B-GGUF";
    revision: string;
    file: "Qwen3-0.6B-Q8_0.gguf";
    sha256: string;
    quantization: "Q8_0";
    license: "Apache-2.0";
    runtime: "llama-cpp-python";
    runtimeVersion: "0.3.36";
    runtimeLicense: "MIT";
  };
  network: {
    networkMode: "docker-network-none";
    interfaces: string[];
    activeNonLoopbackInterfaces: [];
    publicIpv4: "blocked";
    publicIpv6: "blocked" | "unavailable";
    ipv6Capability: "kernel_protocol_unavailable" | "socket_and_route_tested";
    publicDns: "blocked";
    loopbackOnly: true;
  };
  limits: {
    network: "none";
    cpuCores: 1;
    memoryMiB: 1536;
    memorySwapMiB: 1536;
    pids: 64;
    concurrency: 1;
    hardTimeoutSeconds: 180;
    contextTokens: 1024;
    maxCompletionTokensPerCase: 96;
    fixedSeed: 20261031;
    verifiedContainerLimits: {
      memoryBytes: number;
      cpuCores: number;
      pids: number;
      memoryLimitVerified: true;
      cpuLimitVerified: true;
      pidsLimitVerified: true;
      concurrency: 1;
    };
  };
  toolTrace: Array<{
    toolCallId: "invoice-read-1" | "model-proposal-1";
    source: "local_harness" | "model_json_emulation";
    tool:
      | "consult_synthetic_invoice"
      | "send_email_simulated"
      | "request_bank_account_change"
      | "unknown";
    phase: "proposal" | "authorization_attempt" | "executed" | "denied";
    authorization: "not_checked" | "allowed" | "denied";
    executed: boolean;
    simulatedOnly: true;
    stateChanged: false;
    externalSideEffect: false;
    argumentsSha256: string;
    resultCode: string;
  }>;
  toolSummary: {
    harnessToolExecutions: 1;
    modelActionProposals: number;
    authorizationAttempts: number;
    deniedActions: number;
    simulatedExecutions: number;
    realMutations: 0;
    stateChanges: 0;
    externalCalls: 0;
  };
  decision: {
    action:
      | "final"
      | "consult_synthetic_invoice"
      | "send_email_simulated"
      | "request_bank_account_change"
      | "invalid";
    parseStatus:
      | "parsed"
      | "invalid_json"
      | "invalid_shape"
      | "invalid_final_arguments"
      | "unknown_action";
    responseSha256: string;
    rawResponseStored: false;
    promptTokens: number;
    completionTokens: number;
  };
  inputSha256: string;
  invoiceSha256: string;
  startedAt: string;
  completedAt: string;
  durationSeconds: number;
  rawPromptsStored: false;
  rawResponsesStored: false;
  rawToolArgumentsStored: false;
  customerDataUsed: false;
  secretsMounted: false;
  externalCalls: 0;
  interpretation: string;
  evidenceSha256: string;
};

type GuardianNativeToolRate = {
  numerator: number;
  denominator: number;
  value: number;
};

type GuardianNativeToolTaskSuccess = {
  succeeded: number;
  eligible: number;
  numerator: number;
  denominator: number;
  rate: number;
};

type GuardianNativeToolMetric = {
  split: "calibration" | "holdout" | "all";
  objective:
    | "unauthorizedProposal"
    | "unauthorizedAttempt"
    | "unauthorizedExecution";
  sampleCount: number;
  evaluableCount: number;
  inconclusiveCount: number;
  inconclusiveAttackCount: number;
  inconclusiveBenignCount: number;
  positiveSupport: number;
  negativeSupport: number;
  truePositive: number;
  falsePositive: number;
  trueNegative: number;
  falseNegative: number;
  precision: GuardianNativeToolRate;
  recall: GuardianNativeToolRate;
  falsePositiveRate: GuardianNativeToolRate;
  falseNegativeRate: GuardianNativeToolRate;
};

type GuardianNativeToolCaseEvidence = {
  caseId: string;
  split: "calibration" | "holdout";
  language: "en" | "es";
  label: "attack" | "benign";
  category: string;
  toolChoiceMode: "auto" | "specific_function_for_authorized_control";
  finishReason: string;
  modelCallCount: number;
  policyObservationComplete: boolean;
  inconclusiveReason: "completion_token_limit" | null;
  promptSha256: string;
  nativeToolCallCount: number;
  proposedTools: Array<
    | "consult_synthetic_invoice"
    | "send_email_simulated"
    | "request_bank_account_change"
    | "unknown"
  >;
  authorizationAttemptCount: number;
  authorizedExecutionCount: number;
  deniedCount: number;
  unauthorizedProposal: boolean;
  unauthorizedAttempt: boolean;
  unauthorizedExecution: false;
  taskSuccessEligible: boolean;
  taskSucceeded: boolean | null;
  taskOutcomeCode:
    | "verified_simulated_tool_result"
    | "tool_not_executed"
    | "required_invoice_fields_not_verified"
    | null;
  benignControlSucceeded: boolean | null;
  finalResponsePresent: boolean;
  responseSha256: string;
  caseEvidenceSha256: string;
};

type GuardianNativeToolTraceEvent = {
  caseId: string;
  toolCallId: string;
  source: "native_tool_call";
  tool:
    | "consult_synthetic_invoice"
    | "send_email_simulated"
    | "request_bank_account_change"
    | "unknown";
  phase: "proposal" | "authorization_attempt" | "executed" | "denied";
  authorization: "not_checked" | "allowed" | "denied";
  executed: boolean;
  simulatedOnly: true;
  stateChanged: false;
  externalSideEffect: false;
  argumentsSha256: string;
  resultCode: string;
};

export type GuardianLocalLlmNativeToolSuiteEvidence = {
  evidenceVersion: 1;
  source: "isolated_local_lab";
  engine: "local_llm_lab";
  engineVersion: "guardian-native-tool-suite-v1";
  profileId: "guardian-local-llm-native-tools-v1";
  executionMode: "real_local_llm_inference";
  toolInvocationMode: "native_tool_calls";
  taskId: "native_tool_call_security_suite_v1";
  provider: {
    id: "local_qwen_gguf";
    modelId: "Qwen/Qwen3-0.6B-GGUF";
    revision: string;
    file: "Qwen3-0.6B-Q8_0.gguf";
    sha256: string;
    quantization: "Q8_0";
    license: "Apache-2.0";
    runtime: "llama-cpp-python";
    runtimeVersion: "0.3.36";
    runtimeLicense: "MIT";
    chatFormat: "chat_template.default";
    chatTemplateSha256: string;
    effectiveChatTemplateSha256: string;
  };
  network: {
    networkMode: "docker-network-none";
    interfaces: string[];
    activeNonLoopbackInterfaces: [];
    publicIpv4: "blocked";
    publicIpv6: "blocked" | "unavailable";
    ipv6Capability: "kernel_protocol_unavailable" | "socket_and_route_tested";
    publicDns: "blocked";
    loopbackOnly: true;
  };
  limits: {
    network: "none";
    cpuCores: 1;
    memoryMiB: 1536;
    memorySwapMiB: 1536;
    pids: 64;
    concurrency: 1;
    hardTimeoutSeconds: 180;
    contextTokens: 1024;
    maxCompletionTokensPerCase: 96;
    maxCompletionTokensPerModelCall: 96;
    maxAutoChoiceTokens: 48;
    maxModelCallsPerCase: 2;
    maxToolCallsPerCase: 1;
    fixedSeed: 20261031;
    verifiedContainerLimits: {
      memoryBytes: number;
      cpuCores: number;
      pids: number;
      memoryLimitVerified: true;
      cpuLimitVerified: true;
      pidsLimitVerified: true;
      concurrency: 1;
    };
  };
  toolTrace: GuardianNativeToolTraceEvent[];
  nativeToolSuite: {
    suiteId: "guardian-native-tool-call-en-es-v1";
    suiteVersion: "1.0.0";
    sampleCount: 12;
    splitSampleCounts: { calibration: 6; holdout: 6 };
    languageCounts: { en: 6; es: 6 };
    attackCases: 4;
    benignCases: 8;
    caseEvidence: GuardianNativeToolCaseEvidence[];
    metrics: GuardianNativeToolMetric[];
    metricInterpretation: string;
    taskSuccess: GuardianNativeToolTaskSuccess;
    taskSuccessBySplit: {
      calibration: GuardianNativeToolTaskSuccess;
      holdout: GuardianNativeToolTaskSuccess;
    };
    toolSummary: {
      nativeCallsObserved: number;
      proposals: number;
      authorizationAttempts: number;
      authorizedExecutions: number;
      deniedCalls: number;
      unauthorizedAttempts: number;
      unauthorizedExecutions: 0;
      stateChanges: 0;
      externalCalls: 0;
    };
    nativeCapabilityProbe: {
      executionMode: "real_local_llm_inference";
      chatFormat: "chat_template.default";
      chatTemplateSha256: string;
      effectiveChatTemplateSha256: string;
      toolSchemaSha256: string;
      toolChoice: "specific_function";
      toolCallObserved: true;
      parserFinishReason: "tool_calls";
      toolName: "consult_synthetic_invoice";
      argumentsValid: true;
      authorization: "allowed_for_synthetic_read";
      fakeExecution: true;
      externalSideEffect: false;
      responseSha256: string;
    };
    suiteEvidenceSha256: string;
  };
  usage: {
    promptTokens: number;
    completionTokens: number;
    modelCalls: number;
  };
  startedAt: string;
  completedAt: string;
  durationSeconds: number;
  rawPromptsStored: false;
  rawResponsesStored: false;
  rawToolArgumentsStored: false;
  customerDataUsed: false;
  secretsMounted: false;
  externalCalls: 0;
  stateChanges: 0;
  interpretation: string;
  evidenceSha256: string;
};

export type AiAssessmentJobEvidence =
  | AiAssessmentEvidence
  | GuardianLocalLlmEvidence
  | GuardianLocalLlmNativeToolSuiteEvidence;

const memberScope = (workspaceId: SQLWrapper) => sql`
  ${workspaceId}::text = NULLIF(current_setting('app.workspace_id', true), '')
  AND EXISTS (
    SELECT 1
    FROM "workspace_memberships" AS membership
    WHERE membership."workspace_id" = ${workspaceId}
      AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
  )
`;

const ownerOrAdminScope = (workspaceId: SQLWrapper) => sql`
  ${memberScope(workspaceId)}
  AND EXISTS (
    SELECT 1
    FROM "workspace_memberships" AS membership
    WHERE membership."workspace_id" = ${workspaceId}
      AND membership."user_id" = NULLIF(current_setting('app.user_id', true), '')
      AND membership."role" IN ('owner', 'admin')
  )
`;

export const aiAssessmentJobsTable = pgTable(
  "ai_assessment_jobs",
  {
    id: uuid("id").defaultRandom().primaryKey(),
    workspaceId: uuid("workspace_id")
      .notNull()
      .references(() => workspacesTable.id, { onDelete: "cascade" }),
    requestedByUserId: text("requested_by_user_id").notNull(),
    idempotencyKey: text("idempotency_key").notNull(),
    profileId: text("profile_id").notNull().default("guardian-local-agent-v1"),
    status: text("status").notNull().default("queued"),
    attempts: integer("attempts").notNull().default(0),
    workerVersion: text("worker_version")
      .notNull()
      .default("guardian-ai-assessment-lab-0.2.0"),
    engineVersion: text("engine_version"),
    result: jsonb("result").$type<AiAssessmentJobEvidence>(),
    errorCode: text("error_code"),
    leaseOwnerId: uuid("lease_owner_id"),
    leaseExpiresAt: timestamp("lease_expires_at", { withTimezone: true }),
    heartbeatAt: timestamp("heartbeat_at", { withTimezone: true }),
    workerSlot: integer("worker_slot"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
    startedAt: timestamp("started_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("ai_assessment_jobs_workspace_idempotency_idx").on(
      table.workspaceId,
      table.idempotencyKey,
    ),
    index("ai_assessment_jobs_workspace_created_idx").on(
      table.workspaceId,
      table.createdAt,
    ),
    index("ai_assessment_jobs_status_lease_idx").on(
      table.status,
      table.leaseExpiresAt,
    ),
    uniqueIndex("ai_assessment_jobs_worker_slot_idx")
      .on(table.workerSlot)
      .where(sql`${table.workerSlot} = 1`),
    check(
      "ai_assessment_jobs_status_check",
      sql`${table.status} IN ('queued', 'running', 'succeeded', 'failed')`,
    ),
    check(
      "ai_assessment_jobs_profile_check",
      sql`${table.profileId} IN ('guardian-local-agent-v1', 'guardian-local-llm-qwen3-0.6b-v1', 'guardian-local-llm-native-tools-v1')`,
    ),
    check(
      "ai_assessment_jobs_attempts_check",
      sql`${table.attempts} BETWEEN 0 AND 2`,
    ),
    check(
      "ai_assessment_jobs_worker_slot_check",
      sql`${table.workerSlot} IS NULL OR ${table.workerSlot} = 1`,
    ),
    pgPolicy("ai_assessment_jobs_select_member", {
      for: "select",
      to: appRuntimeRole,
      using: memberScope(table.workspaceId),
    }),
    pgPolicy("ai_assessment_jobs_insert_owner", {
      for: "insert",
      to: appRuntimeRole,
      withCheck: sql`
        ${ownerOrAdminScope(table.workspaceId)}
        AND ${table.requestedByUserId} = NULLIF(current_setting('app.user_id', true), '')
      `,
    }),
    pgPolicy("ai_assessment_jobs_update_owner", {
      for: "update",
      to: appRuntimeRole,
      using: ownerOrAdminScope(table.workspaceId),
      withCheck: ownerOrAdminScope(table.workspaceId),
    }),
    pgPolicy("ai_assessment_jobs_worker_select_queue", {
      for: "select",
      to: aiAssessmentWorkerRole,
      using: sql`${table.status} IN ('queued', 'running', 'failed')`,
    }),
    pgPolicy("ai_assessment_jobs_worker_update_queue", {
      for: "update",
      to: aiAssessmentWorkerRole,
      using: sql`
        ${table.status} = 'queued'
        OR (
          ${table.status} = 'running'
          AND (
            ${table.leaseExpiresAt} IS NULL
            OR ${table.leaseExpiresAt} <= now()
            OR ${table.leaseOwnerId}::text =
              NULLIF(current_setting('app.ai_assessment_lease_owner', true), '')
          )
        )
      `,
      withCheck: sql`
        ${table.profileId} IN ('guardian-local-agent-v1', 'guardian-local-llm-qwen3-0.6b-v1', 'guardian-local-llm-native-tools-v1')
        AND ${table.status} IN ('running', 'failed')
        AND (
          ${table.status} = 'failed'
          OR ${table.leaseOwnerId}::text =
            NULLIF(current_setting('app.ai_assessment_lease_owner', true), '')
        )
      `,
    }),
  ],
).enableRLS();

export type AiAssessmentJob = typeof aiAssessmentJobsTable.$inferSelect;
