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
  policyComparison?: GuardianPolicyComparisonEvidence;
};

type GuardianPolicyComparisonProposal = {
  caseId: "controlled_allow_invoice_read" | "controlled_deny_bank_change";
  tool: "consult_synthetic_invoice" | "request_bank_account_change";
  argumentsSha256: string;
  proposalSha256: string;
  stateBeforeSha256: string;
  expectedDecision: "allow" | "deny";
};

export type GuardianPolicyComparisonEvidence = {
  source: "synthetic_controlled_proposals_not_llm";
  version: "guardian-policy-counterfactual-1";
  fixedSeed: 20261101;
  sampleCount: 2;
  proposals: GuardianPolicyComparisonProposal[];
  caseSetSha256: string;
  initialSyntheticStateSha256: string;
  policyVersion: string;
  policyOn: {
    mode: "policy_enforced";
    sampleCount: 2;
    cases: Array<{
      caseId: GuardianPolicyComparisonProposal["caseId"];
      policyDecision: "allow" | "deny";
      proposed: true;
      attempted: true;
      authorized: boolean;
      executed: boolean;
      simulatedOnly: true;
      eventPhases: Array<
        "proposed" | "authorization_attempt" | "authorized" | "denied" | "executed"
      >;
    }>;
    summary: {
      proposed: 2;
      attempted: 2;
      allowed: number;
      denied: number;
      simulatedExecutions: number;
      actualOperationExecutions: 0;
      persistentStateChanges: 0;
      externalCalls: 0;
    };
    armEvidenceSha256: string;
  };
  policyOff: {
    mode: "counterfactual_without_enforcement";
    sampleCount: 2;
    cases: Array<{
      caseId: GuardianPolicyComparisonProposal["caseId"];
      policyDecision: "bypassed_counterfactual";
      proposed: true;
      attempted: true;
      authorized: null;
      executed: false;
      counterfactualWouldExecute: boolean;
      counterfactualCloneStateChanged: boolean;
      counterfactualStateAfterSha256: string;
      simulatedOnly: true;
      eventPhases: Array<
        | "proposed"
        | "authorization_attempt"
        | "policy_bypassed"
        | "counterfactual_would_execute"
        | "counterfactual_rejected"
      >;
    }>;
    summary: {
      proposed: 2;
      attempted: 2;
      authorizationBypassed: 2;
      counterfactualWouldExecute: number;
      counterfactualCloneStateChanges: number;
      actualOperationExecutions: 0;
      persistentStateChanges: 0;
      externalCalls: 0;
    };
    armEvidenceSha256: string;
  };
  selfChecks: {
    sameCasesAndProposals: true;
    sameInitialState: true;
    expectedAllowAndDenyObserved: true;
    policyOffIsCloneOnly: true;
    noPersistentOrExternalEffects: true;
    rawArgumentsStored: false;
  };
  actualOperationExecutions: 0;
  persistentStateChanges: 0;
  externalCalls: 0;
  rawPromptsStored: false;
  rawResponsesStored: false;
  rawArgumentsStored: false;
  startedAt: string;
  completedAt: string;
  interpretation: string;
  evidenceSha256: string;
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
      | "read_synthetic_document"
      | "read_synthetic_email"
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
      | "read_synthetic_document"
      | "read_synthetic_email"
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
  agentDomain?: "email" | "documents" | "finance";
  split: "calibration" | "holdout";
  language: "en" | "es";
  label: "attack" | "benign";
  category: string;
  toolChoiceMode: "auto" | "specific_function_for_authorized_control";
  toolCallOrigin?:
    | "guardian_qwen_native_markup_adapter"
    | "runtime_message_tool_calls"
    | "test_provider_message_tool_calls"
    | "unparsed_qwen_native_markup"
    | "not_observed";
  finishReason: string;
  modelCallCount: number;
  policyObservationComplete: boolean;
  inconclusiveReason: "completion_token_limit" | null;
  promptSha256: string;
  nativeToolCallCount: number;
  proposedTools: Array<
    | "consult_synthetic_invoice"
    | "read_synthetic_document"
    | "read_synthetic_email"
    | "send_email_simulated"
    | "request_bank_account_change"
    | "unknown"
  >;
  argumentsValid?: boolean;
  policyAllowed?: boolean;
  simulatedExecution?: boolean;
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
    | "read_synthetic_document"
    | "read_synthetic_email"
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

type GuardianQwenPolicyRate = {
  numerator: number;
  denominator: number;
  value: number;
};

type GuardianQwenPolicyPair = {
  caseId: string;
  split: "calibration" | "holdout";
  language: "en" | "es";
  label: "attack" | "benign";
  toolCallId: string;
  toolChoiceMode: "auto";
  toolCallOrigin:
    | "guardian_qwen_native_markup_adapter"
    | "runtime_message_tool_calls"
    | "test_provider_message_tool_calls";
  finishReason: string;
  tool:
    | "consult_synthetic_invoice"
    | "read_synthetic_document"
    | "read_synthetic_email"
    | "send_email_simulated"
    | "request_bank_account_change"
    | "unknown";
  argumentsValid: boolean;
  argumentsSha256: string;
  proposalSha256: string;
  policyOn: {
    proposalSha256: string;
    attempted: boolean;
    authorized: boolean;
    denied: boolean;
    simulatedExecution: boolean;
    resultCode: string;
    simulatedOnly: true;
  };
  policyOff: {
    proposalSha256: string;
    attempted: true;
    authorizationBypassed: true;
    counterfactualWouldExecute: boolean;
    counterfactualCloneStateChanged: boolean;
    counterfactualStateBeforeSha256: string;
    counterfactualStateAfterSha256: string;
    resultCode: string;
    executed: false;
    simulatedOnly: true;
  };
  actualOperationExecutions: 0;
  persistentStateChanges: 0;
  externalCalls: 0;
  rawArgumentsStored: false;
  pairEvidenceSha256: string;
};

type GuardianQwenPolicyComparisonEvidence = {
  source: "real_local_qwen_proposals" | "test_double_proposals";
  version: "guardian-qwen-policy-paired-v1";
  executionMode: "real_local_llm_inference" | "test_double_only";
  toolChoiceMode: "auto";
  forcedCallsIncluded: false;
  policyVersion: "guardian-tool-adapter-policy-1";
  fixedSeed: number;
  scenarioCount: number;
  proposalCount: number;
  pairedProposalCount: number;
  unpairedProposalCount: number;
  pairs: GuardianQwenPolicyPair[];
  policyOnSummary: {
    proposalCount: number;
    attempts: number;
    authorizations: number;
    denials: number;
    simulatedExecutions: number;
    actualOperationExecutions: 0;
    persistentStateChanges: 0;
    externalCalls: 0;
  };
  policyOffSummary: {
    proposalCount: number;
    attempts: number;
    authorizationBypassed: number;
    counterfactualWouldExecute: number;
    counterfactualCloneStateChanges: number;
    actualOperationExecutions: 0;
    persistentStateChanges: 0;
    externalCalls: 0;
  };
  metrics: Record<string, GuardianQwenPolicyRate>;
  denominators: {
    scenarios: number;
    benignScenarios: number;
    attackScenarios: number;
    observedProposals: number;
    validExpectedBenignProposals: number;
    authorizationAttempts: number;
  };
  caseSetSha256: string;
  initialSyntheticStateSha256: string;
  selfChecks: {
    sameProposalIdentityInBothArms: boolean;
    sameInitialStatePerPair: boolean;
    policyOffNeverExecutes: boolean;
    noActualPersistentOrExternalEffects: boolean;
    rawArgumentsStored: false;
  };
  actualOperationExecutions: 0;
  persistentStateChanges: 0;
  externalCalls: 0;
  rawArgumentsStored: false;
  interpretation: string;
  comparisonEvidenceSha256: string;
};

type GuardianLocalLlmToolSuiteEvidenceBase = {
  evidenceVersion: 1;
  source: "isolated_local_lab";
  engine: "local_llm_lab";
  engineVersion:
    | "guardian-native-tool-suite-v1"
    | "guardian-autonomous-tool-selection-v1"
    | "guardian-autonomous-tool-selection-v1.1"
    | "guardian-autonomous-tool-selection-v1.2"
    | "guardian-autonomous-tool-selection-v1.3"
    | "guardian-autonomous-tool-selection-v1.4";
  profileId:
    | "guardian-local-llm-native-tools-v1"
    | "guardian-local-llm-autonomous-tools-v1";
  executionMode: "real_local_llm_inference";
  toolInvocationMode: "native_tool_calls";
  taskId:
    | "native_tool_call_security_suite_v1"
    | "autonomous_tool_selection_en_es_v1";
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
    maxCompletionTokensPerCase: 96 | 128;
    maxCompletionTokensPerModelCall: 96 | 128;
    maxAutoChoiceTokens: 48 | 128;
    maxModelCallsPerCase: 1 | 2;
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
    suiteId: string;
    suiteVersion: "1.0.0" | "1.1.0" | "1.2.0" | "1.3.0" | "1.4.0" | "1.5.0";
    sampleCount: number;
    splitSampleCounts: { calibration: number; holdout: number };
    languageCounts: { en: number; es: number };
    attackCases: number;
    benignCases: number;
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
    toolCallParsing?: {
      protocol: "qwen_gguf_tool_call_markup";
      adapterVersion: "guardian-qwen-native-markup-v1";
      runtime: string;
      strictTaggedJsonOnly: true;
      callsAdapted: number;
      callsReturnedDirectlyByRuntime: number;
      unparsedMarkupCases: number;
    };
    policyComparison?: GuardianQwenPolicyComparisonEvidence;
    previousForcedSuiteEvidenceSha256?: string;
    nativeCapabilityProbe: {
      executionMode: "real_local_llm_inference";
      chatFormat: "chat_template.default";
      chatTemplateSha256: string;
      effectiveChatTemplateSha256: string;
      toolSchemaSha256: string;
      toolChoice: "specific_function" | "auto";
      toolCallObserved: boolean;
      parserFinishReason: "tool_calls" | "stop" | "length";
      toolName:
        | "consult_synthetic_invoice"
        | "read_synthetic_document"
        | "read_synthetic_email"
        | "send_email_simulated"
        | "request_bank_account_change"
        | "unknown"
        | "none";
      argumentsValid: boolean;
      authorization:
        | "allowed_for_synthetic_read"
        | "allowed_for_synthetic_tool"
        | "denied"
        | "not_observed";
      fakeExecution: boolean;
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

export type GuardianLocalLlmNativeToolSuiteEvidence = Omit<
  GuardianLocalLlmToolSuiteEvidenceBase,
  "engineVersion" | "profileId" | "taskId"
> & {
  engineVersion: "guardian-native-tool-suite-v1";
  profileId: "guardian-local-llm-native-tools-v1";
  taskId: "native_tool_call_security_suite_v1";
};

export type GuardianLocalLlmAutonomousToolSelectionEvidence = Omit<
  GuardianLocalLlmToolSuiteEvidenceBase,
  "engineVersion" | "profileId" | "taskId"
> & {
  engineVersion:
    | "guardian-autonomous-tool-selection-v1"
    | "guardian-autonomous-tool-selection-v1.1"
    | "guardian-autonomous-tool-selection-v1.2"
    | "guardian-autonomous-tool-selection-v1.3"
    | "guardian-autonomous-tool-selection-v1.4";
  profileId: "guardian-local-llm-autonomous-tools-v1";
  taskId: "autonomous_tool_selection_en_es_v1";
};

export type GuardianAgentPolicyLabEvidence = {
  evidenceVersion: 1 | 2;
  source: "synthetic_policy_scenarios";
  engine: "guardian_policy_lab";
  engineVersion: "guardian-agent-policy-lab-v1" | "guardian-agent-policy-lab-v2";
  profileId:
    | "guardian-agent-lab-email-v1"
    | "guardian-agent-lab-database-v1"
    | "guardian-agent-lab-finance-v1"
    | "guardian-agent-lab-programming-v1"
    | "guardian-agent-lab-customer-service-v1"
    | "guardian-agent-lab-browser-v1"
    | "guardian-agent-lab-infrastructure-v1"
    | "guardian-agent-lab-multiagent-v1";
  verticalId:
    | "email"
    | "database"
    | "finance"
    | "programming"
    | "customer_service"
    | "browser"
    | "infrastructure"
    | "multiagent";
  verticalLabel: string;
  executionMode: "deterministic_fixture";
  proposalOrigin: "controlled_fixture_not_llm";
  modelInference: false;
  agentIdentity: {
    agentId: string;
    agentType: "deterministic_synthetic_agent";
    actorId: "SYNTHETIC-LAB-OPERATOR";
    actorType: "synthetic_user";
    tenantContext: "SYNTHETIC-WORKSPACE";
    parentAgentId: string | null;
    permissions: string[];
    identityPreservedAcrossDelegation: true;
  };
  versions: {
    policy:
      | "guardian-policy-engine-synthetic-v1"
      | "guardian-policy-engine-synthetic-v2";
    corpus: "guardian-agent-lab-corpus-v1";
    oracle: "guardian-policy-oracle-v1";
    toolAdapter?: "guardian-synthetic-tool-adapter-v1";
  };
  seed: number;
  sampleCount: 2;
  cases: Array<{
    caseId: string;
    label: "benign" | "adversarial";
    language: "en" | "es";
    tool: string;
    operation: string;
    resourceType: string;
    resourceId: string;
    resourceWorkspaceId: string;
    sensitivity: "public" | "internal" | "confidential" | "restricted";
    instructionProvenance:
      | "trusted_user_request"
      | "untrusted_email"
      | "untrusted_document"
      | "untrusted_ticket"
      | "untrusted_web_content"
      | "delegated_agent";
    agentId: string;
    actorId: "SYNTHETIC-LAB-OPERATOR";
    actorType: "synthetic_user" | "delegated_agent";
    grantedPermissions: string[];
    requestedPermissions: string[];
    requiredPermissions: string[];
    actionSha256: string;
    proposalSha256: string;
    policyOn: {
      decision: "allow" | "deny" | "require_approval";
      reasonCode: string;
      proposed: true;
      attempted: true;
      authorized: boolean;
      executed: boolean;
      simulatedOnly: true;
      stateChanged: boolean;
      stateBeforeSha256: string;
      stateAfterSha256: string;
      eventPhases: Array<
        | "proposed"
        | "attempted"
        | "authorization_check"
        | "allow"
        | "deny"
        | "require_approval"
        | "authorized"
        | "executed"
      >;
    };
    policyOff: {
      mode: "counterfactual_clone_only";
      decision: "bypassed_counterfactual";
      proposed: true;
      attempted: true;
      authorized: null;
      executed: false;
      counterfactualWouldExecute: true;
      counterfactualCloneStateChanged: boolean;
      stateBeforeSha256: string;
      stateAfterSha256: string;
      simulatedOnly: true;
      eventPhases: string[];
    };
    toolTrace?: {
      adapterVersion: "guardian-synthetic-tool-adapter-v1";
      toolName: string;
      policyOn: {
        invoked: boolean;
        dispatchStatus:
          | "simulated_execution"
          | "adapter_validation_denied"
          | "approval_required_before_dispatch"
          | "blocked_by_policy_before_dispatch";
        events: Array<{
          toolCallId: string;
          source: "guardian_policy_lab_fixture";
          tool: string;
          phase: "authorization_attempt" | "denied" | "executed";
          authorization: "not_checked" | "allowed" | "denied";
          executed: boolean;
          simulatedOnly: true;
          stateChanged: false;
          externalSideEffect: false;
          argumentsSha256: string;
          resultCode: string;
        }>;
        externalSideEffect: false;
        persistentStateMutation: false;
      };
      policyOff: {
        invoked: false;
        dispatchStatus: "counterfactual_clone_only";
        events: [];
        externalSideEffect: false;
        persistentStateMutation: false;
      };
    };
    delegation: {
      isDelegatedAction: boolean;
      originalActorPreserved: true;
      parentAgentId: string | null;
      permissionElevationRequested: boolean;
      permissionElevationAllowed: false;
    };
    unauthorizedActionExecuted: false;
    rawArgumentsStored: false;
    rawInstructionStored: false;
    caseEvidenceSha256: string;
  }>;
  summary: {
    sampleCount: number;
    benignCases: number;
    adversarialCases: number;
    proposed: number;
    attempted: number;
    allowed: number;
    denied: number;
    requiresApproval: number;
    simulatedExecutions: number;
    unauthorizedExecutions: 0;
    policyOffCounterfactualWouldExecute: number;
    policyOffCloneStateChanges: number;
    actualOperations: 0;
    persistentStateChanges: 0;
    externalCalls: 0;
  };
  selfChecks: Record<string, boolean>;
  selfCheckStatus: "passed" | "failed";
  suiteEvidenceSha256: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  limits: {
    network: "docker-network-none";
    concurrency: 1;
    maxCases: 2;
    customerDataUsed: false;
    secretsMounted: false;
    modelWeightsMounted: false;
    dockerSocketMounted: false;
    externalCalls: 0;
    actualOperations: 0;
    rawPromptsStored: false;
    rawResponsesStored: false;
    rawArgumentsStored: false;
  };
  interpretation: string;
  evidenceSha256: string;
};

export type GuardianQwenPolicyLabEvidence = {
  evidenceVersion: 1;
  source: "qwen_local_policy_lab";
  engine: "guardian_qwen_policy_lab";
  engineVersion:
    | "guardian-agent-qwen-policy-lab-v1"
    | "guardian-agent-qwen-policy-lab-v1.1.0";
  profileId:
    | "guardian-agent-qwen-lab-email-v1"
    | "guardian-agent-qwen-lab-database-v1"
    | "guardian-agent-qwen-lab-finance-v1";
  verticalId: "email" | "database" | "finance";
  executionMode: "real_local_qwen_inference";
  proposalOriginScope: "qwen_marker_adapter_or_runtime_tool_calls_only";
  agentIdentity: {
    agentId: string;
    agentType: "local_qwen_agent";
    actorId: "SYNTHETIC-LAB-OPERATOR";
    tenantContext: "SYNTHETIC-WORKSPACE";
    permissions: string[];
  };
  versions: {
    policy: "guardian-policy-engine-synthetic-v2";
    toolAdapter: "guardian-synthetic-tool-adapter-v1";
    corpus:
      | "guardian-qwen-policy-lab-en-es-v1"
      | "guardian-qwen-policy-lab-en-es-v1.1.0";
    modelRuntime: string;
    toolMarkupAdapter: "guardian-qwen-native-markup-v1";
  };
  provider: {
    id: "local_qwen_gguf";
    modelId: string;
    revision: string;
    file: string;
    sha256: string;
    quantization: string;
    runtime: string;
    runtimeVersion: string;
    chatTemplateSha256: string;
    toolChoice: "auto";
  };
  network: Record<string, unknown>;
  limits: Record<string, unknown>;
  cases: Array<{
    caseId: string;
    label: "benign" | "adversarial";
    language: "en" | "es";
    promptSha256: string;
    toolChoice: "auto";
    finishReason: string;
    toolCallOrigin:
      | "guardian_qwen_native_markup_adapter"
      | "unparsed_qwen_native_markup"
      | "runtime_message_tool_calls"
      | "no_tool_call";
    toolCallCount: number;
    proposedTool: string | null;
    proposalSha256: string | null;
    decision: "allow" | "deny" | "require_approval" | "no_proposal";
    reasonCode: string;
    dispatchStatus: string;
    toolEvents: Array<{
      phase: string;
      authorization: string;
      executed: boolean;
      simulatedOnly: true;
      externalSideEffect: false;
      argumentsSha256: string;
      resultCode: string;
    }>;
    policyOnStateBeforeSha256: string;
    policyOnStateAfterSha256: string;
    policyOff: {
      mode: "counterfactual_clone_only";
      wouldExecute: boolean;
      executed: false;
      stateBeforeSha256: string;
      stateAfterSha256: string;
    };
    unauthorizedActionExecuted: false;
    rawPromptStored: false;
    rawResponseStored: false;
    rawArgumentsStored: false;
    caseEvidenceSha256: string;
  }>;
  summary: Record<string, number>;
  selfChecks: Record<string, boolean>;
  startedAt: Date | string;
  completedAt: Date | string;
  durationSeconds: number;
  interpretation: string;
  evidenceSha256: string;
};

export type AiAssessmentJobEvidence =
  | AiAssessmentEvidence
  | GuardianLocalLlmEvidence
  | GuardianLocalLlmNativeToolSuiteEvidence
  | GuardianLocalLlmAutonomousToolSelectionEvidence
  | GuardianAgentPolicyLabEvidence
  | GuardianQwenPolicyLabEvidence;

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
      sql`${table.profileId} IN ('guardian-local-agent-v1', 'guardian-local-llm-qwen3-0.6b-v1', 'guardian-local-llm-native-tools-v1', 'guardian-local-llm-autonomous-tools-v1', 'guardian-agent-lab-email-v1', 'guardian-agent-lab-database-v1', 'guardian-agent-lab-finance-v1', 'guardian-agent-lab-programming-v1', 'guardian-agent-lab-customer-service-v1', 'guardian-agent-lab-browser-v1', 'guardian-agent-lab-infrastructure-v1', 'guardian-agent-lab-multiagent-v1', 'guardian-agent-qwen-lab-email-v1', 'guardian-agent-qwen-lab-database-v1', 'guardian-agent-qwen-lab-finance-v1')`,
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
        ${table.profileId} IN ('guardian-local-agent-v1', 'guardian-local-llm-qwen3-0.6b-v1', 'guardian-local-llm-native-tools-v1', 'guardian-local-llm-autonomous-tools-v1', 'guardian-agent-lab-email-v1', 'guardian-agent-lab-database-v1', 'guardian-agent-lab-finance-v1', 'guardian-agent-lab-programming-v1', 'guardian-agent-lab-customer-service-v1', 'guardian-agent-lab-browser-v1', 'guardian-agent-lab-infrastructure-v1', 'guardian-agent-lab-multiagent-v1', 'guardian-agent-qwen-lab-email-v1', 'guardian-agent-qwen-lab-database-v1', 'guardian-agent-qwen-lab-finance-v1')
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
