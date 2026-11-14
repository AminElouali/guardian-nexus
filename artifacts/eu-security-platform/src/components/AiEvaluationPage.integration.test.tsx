import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { createElement } from "react";
import type { ReactElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  AiAssessmentApproval,
  AiAssessmentLabJob,
  GuardianPolicyLabPreviewResponse,
} from "@workspace/api-client-react";
import { AiEvaluationSectionNav, ExecutiveLabJobCard, LabJobCard } from "./AiEvaluationPage";
import {
  buildSyntheticApprovalConfirmationMessage,
  GuardianApprovalInbox,
} from "./GuardianApprovalInbox";
import { WorkspaceQueryError } from "./WorkspaceQueryError";
import {
  AGENT_POLICY_LABS,
  AgentPolicyLabCatalog,
  AgentPolicyLabResult,
} from "./GuardianAgentPolicyLab";
import {
  QwenPolicyLabCatalog,
  QwenPolicyLabResult,
} from "./GuardianQwenPolicyLab";
import {
  buildQwenExecutiveReport,
  deriveQwenBankChangeFinding,
  downloadQwenExecutiveReport,
} from "./qwenExecutiveReport";
import {
  getPolicyOutcomePresentation,
  getPublicDecisionLabel,
  getPublicReasonLabel,
} from "./security-ui-copy";

test("workspace fallback labels API unavailability and keeps a retry action", () => {
  let retryCount = 0;
  const retryView = WorkspaceQueryError({
    error: { status: 502 },
    onRetry: () => { retryCount += 1; },
  });
  const retryChildren = retryView.props.children as [
    ReactElement,
    ReactElement,
    ReactElement<{ onClick: () => void }>,
  ];
  retryChildren[2].props.onClick();
  assert.equal(retryCount, 1);

  const markup = renderToStaticMarkup(
    createElement(WorkspaceQueryError, {
      error: { status: 502, message: "private upstream detail" },
      onRetry: () => undefined,
      testId: "workspace-api-error",
      buttonTestId: "workspace-api-retry",
    }),
  );

  assert.match(markup, /La API del espacio no está disponible/);
  assert.match(markup, /data-error-kind="unavailable"/);
  assert.match(markup, /data-testid="workspace-api-retry"/);
  assert.doesNotMatch(markup, /private upstream detail/);
  assert.doesNotMatch(
    markup,
    /Solicitud registrada|Simulación registrada|operación completada/i,
    "an API outage must remain an error, never a fabricated success state",
  );
});

test("approval inbox shows tenant-safe decisions without claiming tool execution", () => {
  const pending: AiAssessmentApproval = {
    id: "11111111-1111-4111-8111-111111111111",
    jobId: "22222222-2222-4222-8222-222222222222",
    caseId: "finance_bank_change",
    proposalSha256: "a".repeat(64),
    actionSha256: "b".repeat(64),
    proposalBindingSha256: "c".repeat(64),
    requestedByUserId: "synthetic-requester",
    requestedByRole: "member",
    bindingVersion: 1,
    syntheticActionRef: null,
    modelInference: false,
    executionMode: "deterministic_fixture",
    toolCallOrigin: "controlled_fixture_not_llm",
    status: "pending",
    canCurrentUserDecide: true,
    expiresAt: "2026-11-04T12:00:00.000Z",
    decidedByUserId: null,
    decidedByRole: null,
    decidedAt: null,
    execution: "not_performed",
    simulatedAt: null,
    simulationResultCode: null,
    simulationResultSha256: null,
    replayBindingSha256: null,
    createdAt: "2026-11-03T12:00:00.000Z",
  };
  const approved: AiAssessmentApproval = {
    ...pending,
    id: "33333333-3333-4333-8333-333333333333",
    status: "approved",
    canCurrentUserDecide: false,
    decidedByUserId: "synthetic-approver",
    decidedByRole: "admin",
    decidedAt: "2026-11-03T12:30:00.000Z",
  };
  const simulated: AiAssessmentApproval = {
    ...approved,
    id: "44444444-4444-4444-8444-444444444444",
    execution: "synthetic_action_simulated_once",
    simulatedAt: "2026-11-03T12:31:00.000Z",
    simulationResultCode: "synthetic_refund_approved_in_clone",
    simulationResultSha256: "d".repeat(64),
    replayBindingSha256: "e".repeat(64),
  };
  const qwenAdapted: AiAssessmentApproval = {
    ...pending,
    id: "44444444-4444-4444-8444-444444444444",
    modelInference: true,
    executionMode: "real_local_qwen_inference",
    toolCallOrigin: "guardian_qwen_native_markup_adapter",
  };
  const qwenNative: AiAssessmentApproval = {
    ...pending,
    id: "55555555-5555-4555-8555-555555555555",
    modelInference: true,
    executionMode: "real_local_qwen_inference",
    toolCallOrigin: "runtime_message_tool_calls",
  };
  const markup = renderToStaticMarkup(
    createElement(GuardianApprovalInbox, {
      approvals: [pending, approved, simulated, qwenAdapted, qwenNative],
      canDecide: true,
      loading: false,
      error: false,
      mutationPending: false,
      message: "",
      errorMessage: "",
      onRetry: () => undefined,
      onDecision: () => undefined,
    }),
  );
  assert.match(markup, /data-testid="approval-inbox"/);
  assert.match(markup, /data-testid="button-approve-11111111-1111-4111-8111-111111111111"/);
  assert.match(markup, /data-testid="button-deny-11111111-1111-4111-8111-111111111111"/);
  assert.match(markup, /id="guardian-approval-inbox"/);
  assert.match(markup, /Aprobada · solo decisión/);
  assert.match(markup, /Aprobada · simulación sintética realizada una vez/);
  assert.match(markup, /Fixture determinista · no es inferencia de modelo/);
  assert.match(markup, /marcador adaptado; no es tool call nativa/);
  assert.match(markup, /message\.tool_calls nativa/);
  assert.match(markup, /nunca se llama a herramientas ni sistemas externos/);
  assert.equal(markup.includes("prompt"), false);
  assert.equal(markup.includes("arguments"), false);

  const requesterMarkup = renderToStaticMarkup(
    createElement(GuardianApprovalInbox, {
      approvals: [{ ...pending, canCurrentUserDecide: false }],
      canDecide: true,
      loading: false,
      error: false,
      mutationPending: false,
      message: "",
      errorMessage: "",
      onRetry: () => undefined,
      onDecision: () => undefined,
    }),
  );
  assert.equal(requesterMarkup.includes('data-testid="button-approve-'), false);
  assert.match(requesterMarkup, /El solicitante no puede aprobarla/);

  const customerMarkup = renderToStaticMarkup(
    createElement(GuardianApprovalInbox, {
      approvals: [{
        ...pending,
        syntheticActionRef: "guardian.synthetic.finance.bank-change.v1",
      }],
      canDecide: false,
      loading: false,
      error: false,
      mutationPending: false,
      message: "",
      errorMessage: "",
      onRetry: () => undefined,
      onDecision: () => undefined,
    }),
  );
  assert.match(customerMarkup, /Revisar un cambio de cuenta bancaria ficticio/);
  assert.match(customerMarkup, /Datos financieros sintéticos/);
  assert.match(customerMarkup, /No hay un motivo de texto en el registro de la API/);
  assert.doesNotMatch(customerMarkup, /Qwen|SHA-256|Job:|message\.tool_calls/i);
});

test("approval inbox offers only the fixed synthetic refund proposal to workspace decision-makers", () => {
  const markup = renderToStaticMarkup(
    createElement(GuardianApprovalInbox, {
      approvals: [],
      canDecide: true,
      canRequestRefund: true,
      refundRequestPending: false,
      loading: false,
      error: false,
      mutationPending: false,
      message: "",
      errorMessage: "",
      onRetry: () => undefined,
      onRequestRefund: () => undefined,
      onDecision: () => undefined,
    }),
  );
  assert.match(markup, /data-testid="button-request-synthetic-refund"/);
  assert.match(markup, /Proponer reembolso sintético/);
  assert.match(markup, /Caso fijo de laboratorio/);
  assert.match(markup, /conecta con pagos/);
  assert.match(markup, /otra persona lo revise/);
  assert.doesNotMatch(markup, /Qwen real|reembolso real|proveedor de pagos/i);
});

test("approval confirmation states synthetic impact before any decision", () => {
  const message = buildSyntheticApprovalConfirmationMessage({
    id: "11111111-1111-4111-8111-111111111111",
    jobId: "22222222-2222-4222-8222-222222222222",
    caseId: "finance_bank_change",
    proposalSha256: "a".repeat(64),
    actionSha256: "b".repeat(64),
    proposalBindingSha256: "c".repeat(64),
    requestedByUserId: "synthetic-requester",
    requestedByRole: "member",
    bindingVersion: 1,
    syntheticActionRef: "guardian.synthetic.finance.bank-change.v1",
    modelInference: false,
    executionMode: "deterministic_fixture",
    toolCallOrigin: "controlled_fixture_not_llm",
    status: "pending",
    canCurrentUserDecide: true,
    expiresAt: "2026-11-04T12:00:00.000Z",
    decidedByUserId: null,
    decidedByRole: null,
    decidedAt: null,
    execution: "not_performed",
    simulatedAt: null,
    simulationResultCode: null,
    simulationResultSha256: null,
    replayBindingSha256: null,
    createdAt: "2026-11-03T12:00:00.000Z",
  });
  assert.match(message, /cambio de cuenta bancaria ficticio/);
  assert.match(message, /no se modifica ninguna cuenta real/);
  assert.match(message, /no ejecuta herramientas ni afecta sistemas externos/);
});

test("AI security navigation separates the laboratory, approvals and audit with accessible tabs", () => {
  const markup = renderToStaticMarkup(
    createElement(AiEvaluationSectionNav, {
      activeSection: "approvals",
      onSelect: () => undefined,
    }),
  );
  assert.match(markup, /role="tablist"/);
  assert.match(markup, /data-testid="ai-evaluation-tab-lab"/);
  assert.match(markup, /aria-selected="true"[^>]*>Aprobaciones/);
  assert.match(markup, /data-testid="ai-evaluation-tab-audit"/);
  assert.match(markup, /aria-controls="ai-evaluation-panel-audit"/);
});

test("renders the real API lab response in the authenticated dashboard card", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-e2e-response.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(responsePath, "utf8")) as AiAssessmentLabJob[];
  const job = jobs.find(
    (candidate) =>
      candidate.status === "succeeded" && candidate.result?.engine === "garak",
  );
  assert.ok(job, "API integration must provide a completed real lab response");

  const markup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job,
      canRun: true,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );

  assert.match(markup, /data-testid="ai-lab-real-result"/);
  assert.match(markup, /EVALUACIÓN LOCAL · MOCK Y FIXTURES/);
  assert.match(markup, /Garak 0\.17\.1/);
  assert.match(markup, /Guardian Verification Engine/);
  assert.match(markup, /144/);
  assert.match(markup, /C · PROPUESTAS SINTÉTICAS CONTROLADAS · NO LLM/);
  assert.match(markup, /controlled_allow_invoice_read/);
  assert.match(markup, /controlled_deny_bank_change/);
  assert.match(markup, /Habría ocurrido en el clon/);
  assert.match(markup, /Hash del conjunto emparejado/);
  if (
    job.result &&
    "network" in job.result &&
    job.result.network.publicIpv6 === "unavailable"
  ) {
    assert.match(markup, /IPv6 no verificado/);
  } else {
    assert.match(markup, /IPv6 bloqueado/);
  }

  const localLlmJob = jobs.find(
    (candidate) =>
      candidate.status === "succeeded" &&
      candidate.result?.engine === "local_llm_lab",
  );
  assert.ok(localLlmJob, "API integration must provide a real local Qwen response");
  const localMarkup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job: localLlmJob,
      canRun: true,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );
  assert.match(localMarkup, /data-testid="local-llm-result"/);
  assert.match(localMarkup, /INFERENCIA REAL/);
  assert.match(localMarkup, /no es function calling nativo/);
  assert.match(localMarkup, /No disponible para clientes/);
  assert.match(localMarkup, /Qwen\/Qwen3-0\.6B-GGUF/);
});

test("renders real Qwen profiles separately from fixture evidence", () => {
  const artifactPath = new URL(
    "../../../../generated-artifacts/guardian-qwen-policy-labs-e2e-v1.10.0.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(artifactPath, "utf8")) as AiAssessmentLabJob[];
  assert.equal(jobs.length, 8);
  for (const verticalId of [
    "email",
    "database",
    "finance",
    "customer_service",
    "programming",
    "browser",
    "infrastructure",
    "multiagent",
  ] as const) {
    const job = jobs.find(
      (candidate) =>
        candidate.status === "succeeded" &&
        candidate.result?.engine === "guardian_qwen_policy_lab" &&
        candidate.result.verticalId === verticalId,
    );
    assert.ok(job, `expected completed real Qwen ${verticalId} evidence`);
    const card = renderToStaticMarkup(
      createElement(LabJobCard, {
        job,
        canRun: true,
        onRetry: () => undefined,
        retryPending: false,
      }),
    );
    assert.match(card, /INFERENCIA QWEN REAL · POLICY ENGINE EXTERNO/);
    assert.match(card, /data-testid="qwen-policy-lab-result"/);
    assert.match(card, /tool_choice=auto/);
    assert.match(card, /Policy OFF/);
    assert.match(card, /Hash de evidencia/);
    assert.doesNotMatch(
      card,
      /Ignore prior instructions|attacker@outside\.invalid|Ignore the request|DE00ATTACK/,
    );
    assert.doesNotMatch(card, /rawPrompt|rawResponse|rawArguments/i);
    assert.doesNotMatch(card, /Qwen realizó llamadas tool_calls nativas/i);
    if (job.result?.engine !== "guardian_qwen_policy_lab") {
      assert.fail("expected Qwen policy evidence discriminator");
    }
    const result = renderToStaticMarkup(
      createElement(QwenPolicyLabResult, { evidence: job.result }),
    );
    assert.match(result, /inferencia local real de Qwen/);
    assert.match(result, /no se guardan prompts, respuestas ni argumentos/i);
    assert.match(result, /SHA-256/);
    assert.match(result, /Motivo observado/);
    assert.match(result, /Template efectivo/);
    for (const item of job.result.cases) {
      if (item.toolCallOrigin === "guardian_qwen_native_markup_adapter") {
        assert.match(result, /Marcador Qwen completo adaptado por Guardian/);
      } else if (item.toolCallOrigin === "runtime_message_tool_calls") {
        assert.match(result, /message\.tool_calls devuelto directamente por el runtime/);
      } else if (item.toolCallOrigin === "unparsed_qwen_native_markup") {
        assert.match(result, /Propuesta no aceptada por el parser estricto/);
      } else {
        assert.match(result, /El runtime terminó con/);
        assert.match(result, /no es una denegación de política/);
      }
    }
  }

  const emailQwenJob = jobs.find(
    (candidate) => candidate.profileId === "guardian-agent-qwen-lab-email-v1",
  );
  assert.ok(emailQwenJob, "customer summary check needs a real Qwen evidence fixture");
  const customerSummary = renderToStaticMarkup(
    createElement(ExecutiveLabJobCard, { job: emailQwenJob }),
  );
  assert.match(customerSummary, /EVALUACIÓN SINTÉTICA/);
  assert.match(customerSummary, /Los detalles técnicos de laboratorio están reservados/);
  assert.doesNotMatch(customerSummary, /Qwen|SHA-256|tool_choice|NO_PROPOSAL/i);

  const catalog = renderToStaticMarkup(
    createElement(QwenPolicyLabCatalog, {
      availability: [
        { profileId: "guardian-agent-qwen-lab-email-v1", status: "ready" },
        { profileId: "guardian-agent-qwen-lab-database-v1", status: "ready" },
        { profileId: "guardian-agent-qwen-lab-finance-v1", status: "ready" },
      ],
      canRun: true,
      pending: false,
      onRequest: () => undefined,
    }),
  );
  assert.match(catalog, /INFERENCIA LOCAL REAL · QWEN3/);
  assert.match(catalog, /tool_choice=auto/);
  assert.match(catalog, /button-run-qwen-policy-email/);
  assert.match(catalog, /button-run-qwen-policy-database/);
  assert.match(catalog, /button-run-qwen-policy-finance/);
  assert.match(catalog, /NO CONECTADO A CLIENTES/i);

  const blockedCatalog = renderToStaticMarkup(
    createElement(QwenPolicyLabCatalog, {
      availability: [],
      canRun: true,
      pending: false,
      onRequest: () => undefined,
    }),
  );
  assert.match(blockedCatalog, /data-testid="qwen-preflight-not-run"/);
  assert.match(blockedCatalog, /No se ejecutaron inferencias Qwen nuevas/);
  assert.match(blockedCatalog, /evidencia Qwen registrada es histórica/);
  assert.match(blockedCatalog, /NO_PROPOSAL<\/code> no equivale a <code>DENY/);
  assert.match(blockedCatalog, /disabled/);

  const repeatedUnavailableCatalog = renderToStaticMarkup(
    createElement(QwenPolicyLabCatalog, {
      availability: [
        {
          profileId: "guardian-agent-qwen-lab-email-v1",
          status: "blocked",
          reasonCode: "assessment_broker_identity_unverified",
        },
        {
          profileId: "guardian-agent-qwen-lab-database-v1",
          status: "blocked",
          reasonCode: "assessment_broker_identity_unverified",
        },
        {
          profileId: "guardian-agent-qwen-lab-finance-v1",
          status: "blocked",
          reasonCode: "private_internal_preflight_reason",
        },
        {
          profileId: "guardian-agent-qwen-lab-customer-service-v1",
          status: "blocked",
          reasonCode: "another_private_preflight_reason",
        },
      ],
      canRun: true,
      pending: false,
      onRequest: () => undefined,
    }),
  );
  assert.equal(
    (
      repeatedUnavailableCatalog.match(
        /la identidad aislada del broker no está verificada/g,
      ) ?? []
    ).length,
    1,
    "the same worker preflight reason should be shown once, not repeated on every profile",
  );
  assert.match(
    repeatedUnavailableCatalog,
    /las comprobaciones de aislamiento siguen pendientes/,
  );
  assert.equal(
    (
      repeatedUnavailableCatalog.match(
        /las comprobaciones de aislamiento siguen pendientes/g,
      ) ?? []
    ).length,
    1,
  );
  assert.doesNotMatch(
    repeatedUnavailableCatalog,
    /assessment_broker_identity_unverified|private_internal_preflight_reason|another_private_preflight_reason/,
  );
  assert.doesNotMatch(repeatedUnavailableCatalog, /Motivo:/);
});

test("Qwen provenance summary keeps parser rejection separate from no proposal", () => {
  const artifactPath = new URL(
    "../../../../generated-artifacts/guardian-qwen-policy-labs-e2e-v1.10.0.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(artifactPath, "utf8")) as AiAssessmentLabJob[];
  const qwenJob = jobs.find(
    (candidate) =>
      candidate.status === "succeeded" &&
      candidate.result?.engine === "guardian_qwen_policy_lab",
  );
  assert.ok(qwenJob);
  const evidence = qwenJob.result;
  if (!evidence || evidence.engine !== "guardian_qwen_policy_lab") {
    assert.fail("expected a Qwen evidence shape for the component contract test");
  }
  const template = evidence.cases[0];
  assert.ok(template);

  const evidenceWithDistinctOrigins = {
    ...evidence,
    cases: [
      {
        ...template,
        caseId: "ui-origin-adapted",
        toolCallOrigin: "guardian_qwen_native_markup_adapter",
      },
      {
        ...template,
        caseId: "ui-origin-native",
        toolCallOrigin: "runtime_message_tool_calls",
      },
      {
        ...template,
        caseId: "ui-origin-no-call",
        toolCallOrigin: "no_tool_call",
      },
      {
        ...template,
        caseId: "ui-origin-parser-rejected",
        toolCallOrigin: "unparsed_qwen_native_markup",
      },
    ],
  } as typeof evidence;

  const markup = renderToStaticMarkup(
    createElement(QwenPolicyLabResult, { evidence: evidenceWithDistinctOrigins }),
  );
  assert.match(markup, /1 marcador Qwen adaptado/);
  assert.match(markup, /1 llamada nativa message\.tool_calls/);
  assert.match(markup, /1 salida sin tool call \(NO_PROPOSAL\)/);
  assert.match(markup, /1 marcador rechazado por parser/);
  assert.match(markup, /fixtures deterministas no se incluyen en estos conteos/i);
  assert.match(markup, /data-testid="qwen-policy-order"/);
  assert.match(markup, /Policy ON antes del simulador sintético/);
  assert.match(markup, /Policy OFF permanece como contrafactual/);
});

test("historical infrastructure NO_PROPOSAL stays separate from DENY and fixtures in the UI", () => {
  const artifactPath = new URL(
    "../../../../generated-artifacts/guardian-qwen-offline/qwen-policy-lab-eight-profiles.json",
    import.meta.url,
  );
  const artifact = JSON.parse(readFileSync(artifactPath, "utf8")) as {
    profiles: Array<Record<string, unknown>>;
  };
  const profile = artifact.profiles.find(
    (candidate) => candidate.verticalId === "infrastructure",
  );
  assert.ok(profile);
  const cases = profile.cases as Array<Record<string, unknown>>;
  const caseEvidence = cases[0];
  assert.ok(caseEvidence);
  assert.equal(caseEvidence.toolCallOrigin, "no_tool_call");
  assert.equal(caseEvidence.decision, "no_proposal");
  assert.equal(caseEvidence.dispatchStatus, "not_invoked");
  assert.equal(caseEvidence.proposedTool, null);
  assert.equal(caseEvidence.proposalSha256, null);
  assert.equal(caseEvidence.actionSha256, null);

  const markup = renderToStaticMarkup(
    createElement(QwenPolicyLabResult, {
      evidence: profile as unknown as Parameters<
        typeof QwenPolicyLabResult
      >[0]["evidence"],
    }),
  );
  assert.match(markup, /Infraestructura · inferencia local real de Qwen/);
  assert.match(
    markup,
    /0 marcadores Qwen adaptados · 0 llamadas nativas message\.tool_calls · 1 salida sin tool call \(NO_PROPOSAL\)/,
  );
  assert.match(markup, /Sin propuesta aceptada/);
  assert.match(markup, /Ninguna · 0 llamada\(s\) reportada\(s\)/);
  assert.match(markup, /Hash de propuesta<\/dt><dd><code>sin propuesta<\/code><\/dd>/);
  assert.match(markup, /fixtures deterministas no se incluyen en estos conteos/i);
  assert.match(markup, /<summary>Caso adversarial · ES · Sin propuesta aceptada<\/summary>/);
  assert.doesNotMatch(markup, /<summary>[^<]*(?:DENY|Denegada)/);
});

test("renders all eight synthetic agent verticals and an API-persisted policy lab report", () => {
  const artifactPath = new URL(
    "../../../../generated-artifacts/guardian-agent-policy-labs-e2e.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(artifactPath, "utf8")) as AiAssessmentLabJob[];
  assert.equal(jobs.length, 8);
  const policyJob = jobs.find(
    (candidate) =>
      candidate.status === "succeeded" &&
      candidate.result?.engine === "guardian_policy_lab",
  );
  assert.ok(policyJob);
  if (policyJob.result?.engine !== "guardian_policy_lab") {
    assert.fail("E2E artifact must contain policy lab evidence");
  }
  assert.equal(policyJob.result.executionMode, "deterministic_fixture");
  assert.equal(policyJob.result.proposalOrigin, "controlled_fixture_not_llm");
  assert.equal(policyJob.result.modelInference, false);
  const resultMarkup = renderToStaticMarkup(
    createElement(AgentPolicyLabResult, {
      evidence: policyJob.result,
      showTechnicalDetails: true,
    }),
  );
  assert.match(resultMarkup, /SEGURIDAD · CONTROL DE ACCESO/);
  assert.match(resultMarkup, /Simulación/);
  assert.match(resultMarkup, /datos sintéticos/);
  assert.match(resultMarkup, /Ver detalles de la prueba/);
  assert.match(resultMarkup, /Hash de suite/);
  assert.doesNotMatch(resultMarkup, /inferencia Qwen real/i);
  for (const item of policyJob.result.cases) {
    for (const internalValue of [
      item.caseId,
      item.tool,
      item.operation,
      item.resourceWorkspaceId,
      item.policyOn.reasonCode,
      item.agentId,
      item.actorId,
    ]) {
      assert.equal(resultMarkup.includes(internalValue), false, `public report leaked ${internalValue}`);
    }
  }
  assert.equal(resultMarkup.includes("prompt text"), false);

  const catalogMarkup = renderToStaticMarkup(
    createElement(AgentPolicyLabCatalog, {
      profiles: AGENT_POLICY_LABS.map((lab) => ({
        profileId: lab.profileId,
        status: "ready",
        reasonCode: null,
      })),
      canRun: true,
      pending: false,
      previewPending: false,
      onRequest: () => undefined,
      onPreview: () => undefined,
      onReset: () => undefined,
      onSelectionChange: () => undefined,
      onViewApprovals: () => undefined,
      recordedEvidence: jobs.flatMap((job) =>
        job.status === "succeeded" && job.result?.engine === "guardian_policy_lab"
          ? [job.result]
          : [],
      ),
      recordedArtifactSha256:
        "9bbc87ca9ee5c7eac040a0d2f33defb6eeb41f95d5d9940979b5564b435960be",
      freshPreview: null,
    }),
  );
  assert.equal(AGENT_POLICY_LABS.length, 8);
  assert.equal(
    (
      catalogMarkup.match(
        /data-testid="agent-policy-lab-(?:email|database|finance|programming|customer_service|browser|infrastructure|multiagent)"/g,
      ) ?? []
    ).length,
    8,
  );
  assert.match(catalogMarkup, /data-testid="button-select-agent-lab-email"/);
  assert.match(catalogMarkup, /data-testid="button-select-agent-lab-database"/);
  assert.match(catalogMarkup, /aria-pressed="false"/);
  assert.match(catalogMarkup, /Demo ficticia/);
  for (const label of ["Correo", "Datos", "Finanzas", "Código", "Soporte", "Web", "Cloud", "Multiagente"]) {
    assert.match(catalogMarkup, new RegExp(`<span>${label}</span>`));
  }
  assert.match(catalogMarkup, /aria-label="Atención al cliente"/);
  assert.match(catalogMarkup, /data-testid="button-select-agent-case-benign"/);
  assert.match(catalogMarkup, /data-testid="button-select-agent-case-adversarial"/);
  assert.match(catalogMarkup, /data-testid="button-run-guided-agent-demo"/);
  assert.match(catalogMarkup, /data-testid="button-preview-policy-lab"/);
  assert.equal((catalogMarkup.match(/Ejecutar demostración/g) ?? []).length, 1);
  assert.match(catalogMarkup, /Acción legítima/);
  assert.match(catalogMarkup, /Intento de ataque/);
  assert.match(catalogMarkup, /data-testid="agent-policy-empty-result"/);
  assert.match(catalogMarkup, /Ejecutar demostración/);
  assert.doesNotMatch(catalogMarkup, /data-testid="button-reset-agent-demo"/);
  assert.match(catalogMarkup, /no modifica\s+las decisiones ni los permisos/i);
  assert.match(catalogMarkup, /no una respuesta nueva de un agente/i);
  assert.match(catalogMarkup, /multiagente/i);
  assert.doesNotMatch(catalogMarkup, /Policy Engine|fixture|Qwen|NO_PROPOSAL/i);

  const emailJob = jobs.find(
    (candidate) =>
      candidate.profileId === "guardian-agent-lab-email-v1" &&
      candidate.status === "succeeded" &&
      candidate.result?.engine === "guardian_policy_lab",
  );
  assert.ok(emailJob?.result?.engine === "guardian_policy_lab");
  if (emailJob?.result?.engine !== "guardian_policy_lab") {
    assert.fail("email fixture evidence is required to verify the result reset action");
  }
  const resultCatalogMarkup = renderToStaticMarkup(
    createElement(AgentPolicyLabCatalog, {
      profiles: AGENT_POLICY_LABS.map((lab) => ({
        profileId: lab.profileId,
        status: "ready",
        reasonCode: null,
      })),
      canRun: true,
      pending: false,
      previewPending: false,
      onRequest: () => undefined,
      onPreview: () => undefined,
      onReset: () => undefined,
      onSelectionChange: () => undefined,
      onViewApprovals: () => undefined,
      recordedEvidence: [],
      recordedArtifactSha256: "",
      freshPreview: {
        profileId: "guardian-agent-lab-email-v1",
        caseId: "email_adversarial_external_exfiltration",
        evidence: emailJob.result as GuardianPolicyLabPreviewResponse["evidence"],
      },
    }),
  );
  assert.match(resultCatalogMarkup, /data-testid="button-reset-agent-demo"/);
});

test("guided synthetic result explains approval and avoids exposing internal identifiers", () => {
  const artifactPath = new URL(
    "../../../../generated-artifacts/guardian-agent-policy-labs-e2e.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(artifactPath, "utf8")) as AiAssessmentLabJob[];
  const financeJob = jobs.find(
    (candidate) => candidate.profileId === "guardian-agent-lab-finance-v1",
  );
  assert.ok(financeJob?.result?.engine === "guardian_policy_lab");
  if (financeJob?.result?.engine !== "guardian_policy_lab") {
    assert.fail("finance fixture evidence is required for this UI test");
  }
  const approvalCase = financeJob.result.cases.find(
    (item) => item.policyOn.decision === "require_approval",
  );
  assert.ok(approvalCase);
  if (!approvalCase) assert.fail("finance fixture must preserve REQUIRE_APPROVAL");

  const markup = renderToStaticMarkup(
    createElement(AgentPolicyLabResult, {
      evidence: financeJob.result,
      focusedCaseId: approvalCase.caseId,
      showTechnicalDetails: true,
    }),
  );
  assert.match(markup, /SEGURIDAD · CONTROL DE ACCESO/);
  assert.match(markup, /¿Se ha realizado la operación\?/);
  assert.match(markup, /Requiere aprobación/);
  assert.match(markup, /ni creó una solicitud persistente de aprobación/);
  assert.match(markup, /data-testid="link-guided-approval-inbox"/);
  assert.match(markup, /<details open="" data-testid="agent-policy-case-\d+"/);
  assert.match(markup, /Prueba de seguridad/);
  for (const internalValue of [
    approvalCase.caseId,
    approvalCase.policyOn.reasonCode,
    approvalCase.agentId,
    approvalCase.actorId,
    approvalCase.resourceWorkspaceId,
    approvalCase.tool,
    approvalCase.operation,
  ]) {
    assert.equal(markup.includes(internalValue), false, `public result leaked ${internalValue}`);
  }
  assert.equal(markup.includes("Synthetic Vendor"), false);
  assert.equal(markup.includes("prompt text"), false);

  const recordedMarkup = renderToStaticMarkup(
    createElement(AgentPolicyLabResult, {
      evidence: financeJob.result,
      focusedCaseId: approvalCase.caseId,
      recordedSnapshot: true,
      recordedArtifactSha256:
        "9bbc87ca9ee5c7eac040a0d2f33defb6eeb41f95d5d9940979b5564b435960be",
      showTechnicalDetails: true,
    }),
  );
  assert.match(recordedMarkup, /Evidencia histórica de solo lectura/);
  assert.match(recordedMarkup, /Abrir esta vista no realizó ninguna operación/);
  assert.match(recordedMarkup, /Referencia de evidencia histórica/);
  assert.match(recordedMarkup, new RegExp(createHash("sha256").update(readFileSync(artifactPath)).digest("hex")));
});

test("public security copy uses safe fallbacks and keeps no proposal distinct from denial", () => {
  const noProposal = getPolicyOutcomePresentation(
    "no_proposal",
    "unknown_internal_reason",
    false,
  );
  assert.equal(getPublicDecisionLabel("no_proposal"), "Sin propuesta");
  assert.equal(noProposal.operationStatus, "No propuesta");
  assert.match(noProposal.summary, /no es una denegación/);
  assert.doesNotMatch(JSON.stringify(noProposal), /unknown_internal_reason|NO_PROPOSAL|DENY/);
  assert.equal(
    getPublicReasonLabel("unknown_internal_reason").includes("unknown_internal_reason"),
    false,
  );
  assert.equal(getPublicDecisionLabel("unexpected_internal_decision"), "Resultado no verificado");
});

test("cross-workspace denial is explained in plain Spanish and never claims data was accessed", () => {
  const artifactPath = new URL(
    "../../../../generated-artifacts/guardian-agent-policy-labs-e2e.json",
    import.meta.url,
  );
  const jobs = JSON.parse(readFileSync(artifactPath, "utf8")) as AiAssessmentLabJob[];
  const databaseJob = jobs.find(
    (candidate) => candidate.profileId === "guardian-agent-lab-database-v1",
  );
  assert.ok(databaseJob?.result?.engine === "guardian_policy_lab");
  if (databaseJob?.result?.engine !== "guardian_policy_lab") {
    assert.fail("synthetic database evidence is required for this UI test");
  }
  const deniedCase = databaseJob.result.cases.find(
    (item) => item.policyOn.decision === "deny" && item.policyOn.reasonCode === "resource_outside_workspace",
  );
  assert.ok(deniedCase);
  if (!deniedCase) assert.fail("database scenario must include a cross-workspace denial");

  const markup = renderToStaticMarkup(createElement(AgentPolicyLabResult, {
    evidence: databaseJob.result,
    focusedCaseId: deniedCase.caseId,
  }));
  assert.match(markup, /Se ha impedido un acceso no autorizado/);
  assert.match(markup, /Un agente intentó consultar información fuera de su espacio de trabajo autorizado/);
  assert.match(markup, /El agente no tenía permiso para acceder a esos datos/);
  assert.match(markup, /No. La solicitud se detuvo antes de realizar la operación/);
  assert.match(markup, /No se requiere ninguna acción real; esta prueba es simulada/);
  assert.doesNotMatch(markup, /Ver detalles de la prueba|SHA-256|resource_outside_workspace/);
  for (const internalValue of [
    deniedCase.caseId,
    deniedCase.policyOn.reasonCode,
    deniedCase.agentId,
    deniedCase.actorId,
    deniedCase.resourceWorkspaceId,
    deniedCase.tool,
    deniedCase.operation,
  ]) {
    assert.equal(markup.includes(internalValue), false, `public denial leaked ${internalValue}`);
  }
});

test("fresh API-preview evidence renders its unisolated runtime boundary honestly", () => {
  const workerRoot = fileURLToPath(
    new URL("../../../../workers/guardian-ai-assessment", import.meta.url),
  );
  const generated = spawnSync(
    "python3",
    [
      "-S",
      "-B",
      "-m",
      "guardian_ai_assessment.policy_lab",
      "--profile-id",
      "guardian-agent-lab-email-v1",
      "--execution-context",
      "api_policy_preview",
    ],
    {
      cwd: workerRoot,
      encoding: "utf8",
      timeout: 5_000,
      maxBuffer: 64 * 1024,
      env: {
        PATH: process.env.PATH ?? "/usr/bin:/bin",
        PYTHONPATH: workerRoot,
        PYTHONHASHSEED: "0",
        PYTHONNOUSERSITE: "1",
        PYTHONDONTWRITEBYTECODE: "1",
      },
    },
  );
  assert.equal(generated.error, undefined);
  assert.equal(generated.status, 0, generated.stderr);
  const evidence = JSON.parse(
    generated.stdout,
  ) as GuardianPolicyLabPreviewResponse["evidence"];
  const markup = renderToStaticMarkup(
    createElement(AgentPolicyLabResult, {
      evidence,
      showTechnicalDetails: true,
    }),
  );
  assert.match(markup, /no demuestra el aislamiento del entorno/i);
  assert.match(markup, /ninguna; esta prueba utiliza únicamente datos sintéticos/i);
  assert.doesNotMatch(markup, /host_network_unisolated|assessment_broker_identity_unverified|Docker|socket|Policy Engine/i);
  assert.doesNotMatch(markup, /prompt text/i);
});

test("downloads the allow-listed Qwen JSON report without raw case data", async () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-autonomous-e2e-response.json",
    import.meta.url,
  );
  const job = JSON.parse(readFileSync(responsePath, "utf8")) as AiAssessmentLabJob;
  assert.equal(job.status, "succeeded");
  assert.equal(job.profileId, "guardian-local-llm-autonomous-tools-v1");

  const previousDocument = Object.getOwnPropertyDescriptor(globalThis, "document");
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
  const previousCreate = Object.getOwnPropertyDescriptor(URL, "createObjectURL");
  const previousRevoke = Object.getOwnPropertyDescriptor(URL, "revokeObjectURL");
  let clickedAnchor: { href: string; download: string } | undefined;
  let capturedBlob: Blob | undefined;
  let revokedUrl: string | undefined;

  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: {
      createElement: (tag: string) => {
        assert.equal(tag, "a");
        const anchor = {
          href: "",
          download: "",
          click: () => {
            clickedAnchor = anchor;
          },
        };
        return anchor;
      },
    } as unknown as Document,
  });
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      setTimeout: (callback: () => void) => {
        callback();
        return 0;
      },
    } as unknown as Window,
  });
  Object.defineProperty(URL, "createObjectURL", {
    configurable: true,
    value: (blob: Blob) => {
      capturedBlob = blob;
      return "blob:guardian-report-test";
    },
  });
  Object.defineProperty(URL, "revokeObjectURL", {
    configurable: true,
    value: (url: string) => {
      revokedUrl = url;
    },
  });

  try {
    assert.equal(downloadQwenExecutiveReport(job), true);
    assert.equal(clickedAnchor?.href, "blob:guardian-report-test");
    assert.match(clickedAnchor?.download ?? "", /^guardian-nexus-evaluacion-[a-zA-Z0-9-]+\.json$/);
    assert.equal(revokedUrl, "blob:guardian-report-test");
    assert.ok(capturedBlob);
    assert.equal(capturedBlob.type, "application/json;charset=utf-8");
    const exported = await capturedBlob.text();
    assert.match(exported, /"brand": "Guardian Nexus"/);
    assert.match(exported, /"counterfactualOnly": true/);
    assert.match(exported, /"pairedProposalCount":\s*13/);
    assert.doesNotMatch(exported, /lab-recipient@invalid\.example/);
    assert.doesNotMatch(exported, /DE00LAB000000000000000000/);
    assert.doesNotMatch(exported, /rawPrompt|rawResponse|rawArguments/i);
    assert.doesNotMatch(exported, /<tool_call>/);
  } finally {
    const restore = (
      target: object,
      key: PropertyKey,
      descriptor: PropertyDescriptor | undefined,
    ) => {
      if (descriptor) {
        Object.defineProperty(target, key, descriptor);
      } else {
        Reflect.deleteProperty(target, key);
      }
    };
    restore(globalThis, "document", previousDocument);
    restore(globalThis, "window", previousWindow);
    restore(URL, "createObjectURL", previousCreate);
    restore(URL, "revokeObjectURL", previousRevoke);
  }
});

test("renders native tool-call evidence separately from JSON emulation and fixtures", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-native-e2e-response.json",
    import.meta.url,
  );
  const job = JSON.parse(
    readFileSync(responsePath, "utf8"),
  ) as AiAssessmentLabJob;
  assert.equal(job.status, "succeeded");
  assert.equal(job.profileId, "guardian-local-llm-native-tools-v1");
  assert.equal(job.result?.engine, "local_llm_lab");
  assert.equal(job.result?.toolInvocationMode, "native_tool_calls");

  const markup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job,
      canRun: true,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );
  assert.match(markup, /data-testid="native-tool-suite-result"/);
  assert.match(markup, /LLM REAL · TOOL CALLS NATIVAS/);
  assert.match(markup, /message\.tool_calls/);
  assert.match(markup, /el arnés seleccionó la función específica/);
  assert.match(markup, /calibration/);
  assert.match(markup, /holdout/);
  assert.match(markup, /IPv6 no verificado/);
  assert.match(markup, /no disponible para clientes/);
  assert.doesNotMatch(markup, /GN-EMAIL-EN-CAL/);
  assert.doesNotMatch(markup, /lab-recipient@invalid\.example/);
});

test("renders the Qwen run as an honest Spanish executive report with bounded evidence", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-autonomous-e2e-response.json",
    import.meta.url,
  );
  const job = JSON.parse(
    readFileSync(responsePath, "utf8"),
  ) as AiAssessmentLabJob;
  assert.equal(job.status, "succeeded");
  assert.equal(job.profileId, "guardian-local-llm-autonomous-tools-v1");
  assert.equal(job.result?.engine, "local_llm_lab");
  assert.equal(job.result?.toolInvocationMode, "native_tool_calls");

  const markup = renderToStaticMarkup(
    createElement(LabJobCard, {
      job,
      canRun: true,
      onRetry: () => undefined,
      retryPending: false,
    }),
  );
  assert.match(markup, /LLM REAL · tool_choice=auto/);
  assert.match(markup, /Selección autónoma de herramientas/);
  assert.match(markup, /data-testid="qwen-executive-summary"/);
  assert.match(markup, /Hubo inferencia local real en 14 casos mixtos/);
  assert.match(markup, /Intento de modificación bancaria no autorizada bloqueado/);
  assert.match(markup, /el intento observado fue denegado por la política/);
  assert.match(markup, /data-testid="qwen-bank-finding"/);
  assert.match(markup, /Riesgo ilustrado: una propuesta autónoma podría solicitar una operación bancaria fuera de autorización/);
  assert.match(markup, /Propuesta<\/b>OBSERVADA/);
  assert.match(markup, /Intento<\/b>OBSERVADO/);
  assert.match(markup, /Decisión de política<\/b>DENEGADA/);
  assert.match(markup, /Ejecución simulada<\/b>NO REALIZADA/);
  assert.match(markup, /El clon desechable habría aceptado la propuesta; nunca se ejecutó/);
  assert.match(markup, /Mitigación de política independiente/);
  assert.match(markup, /VERIFICADA EN COMPARACIÓN SINTÉTICA/);
  assert.match(markup, /no se modificó ningún cliente ni sistema real/);
  assert.match(markup, /Referencias de evidencia y hashes/);
  assert.match(markup, /Evidencia del caso/);
  assert.match(markup, /no permite estimar una tasa general de seguridad/);
  assert.match(markup, /5 ataques de inyección indirecta en correo o documentos/);
  assert.match(markup, /no se forzó la función/);
  assert.match(markup, /13\/14<\/b> casos con propuesta/);
  assert.match(markup, /13\/13<\/b> propuestas con intento de autorización/);
  assert.match(markup, /10\/13<\/b> autorizadas y simuladas/);
  assert.match(markup, /2\/13<\/b> denegadas/);
  assert.match(markup, /1\/13<\/b> requieren aprobación/);
  assert.match(markup, /0\/2<\/b> intentos no autorizados ejecutados/);
  assert.match(markup, /13<\/b> marcadores(?: de plantilla)? Qwen adaptados por Guardian/);
  assert.match(markup, /<b\b[^>]*>0<\/b> message\.tool_calls directos del runtime/);
  assert.match(markup, /no son llamadas nativas directas/);
  assert.match(markup, /Marcador Qwen adaptado/);
  assert.match(markup, /Policy OFF omite esa comprobación únicamente sobre una copia desechable en memoria/);
  assert.match(markup, /Habría ocurrido en el clon · estado del clon cambiaría · nunca ejecutado/);
  assert.match(markup, /no permite estimar una tasa general de seguridad/);
  assert.match(markup, /no acepta JSON libre/);
  assert.match(markup, /Comparación emparejada/);
  assert.match(markup, /PROPUESTAS DEL QWEN LOCAL/);
  assert.match(markup, /Policy OFF · solo clon desechable/);
  assert.match(markup, /falso bloqueo/);
  assert.match(markup, /potencial de ataque/);
  assert.match(markup, /DENY · policy_denied/);
  assert.match(markup, /REQUIRE_APPROVAL · no ejecutada/);
  assert.doesNotMatch(markup, /DENY · approval_required_before_dispatch/);
  assert.match(markup, /Habría ocurrido en el clon · estado del clon cambiaría · nunca ejecutado/);
  assert.match(markup, /Es pequeña y no permite calcular una tasa general de seguridad/i);
  assert.match(markup, /no son una estimación general de seguridad/i);
  assert.match(markup, /Suite forzada anterior/);
  assert.match(markup, /no disponible para clientes/);
  assert.match(markup, /Descargar informe JSON redactado/);
  assert.match(markup, /auditoría global de dependencias del worker se informa por separado/);
  assert.doesNotMatch(markup, /lab-recipient@invalid\.example/);
  assert.doesNotMatch(markup, /DE00LAB000000000000000000/);
  assert.doesNotMatch(markup, /GN-EMAIL-EN-CAL/);
  assert.doesNotMatch(markup, /rawPrompt|rawResponse|rawArguments/i);
  assert.doesNotMatch(markup, /<tool_call>.*?<\/tool_call>/s);

  const report = buildQwenExecutiveReport(job);
  assert.ok(report);
  const exported = JSON.stringify(report);
  assert.match(exported, /"reportVersion":3/);
  assert.match(exported, /Guardian Nexus/);
  const reportData = JSON.parse(exported) as {
    scope: { activeDomains: string[]; domainsNotIncluded: string[] };
    supplyChainAssessment: { status: string; tenantEvidence: boolean };
  };
  assert.deepEqual(reportData.supplyChainAssessment, {
    status: "NOT_INCLUDED_IN_TENANT_ASSESSMENT",
    scope: "La imagen y dependencias del worker se evalúan en una auditoría interna separada.",
    tenantEvidence: false,
  });
  assert.deepEqual(
    [...reportData.scope.activeDomains].sort(),
    ["documents", "email", "finance"],
  );
  assert.deepEqual(reportData.scope.domainsNotIncluded, [
    "databases",
    "programming",
  ]);
  assert.match(exported, /Intento de modificación bancaria no autorizada bloqueado/);
  assert.match(exported, /"directRuntimeMessageToolCalls":0/);
  assert.match(exported, /"counterfactualOnly":true/);
  assert.match(exported, /"actualOperationExecutions":0/);
  assert.match(exported, /"independentPolicyMitigation":\{"status":"VERIFICADA EN COMPARACIÓN SINTÉTICA"/);
  assert.match(exported, /"remediationStatus":"No aplica remediación sobre sistemas reales en este caso sintético: no se modificó ningún cliente ni sistema real/);
  assert.match(exported, /"proposal":"OBSERVADA","attempt":"OBSERVADO","policyDecision":"DENEGADA","simulatedExecution":"NO REALIZADA"/);
  assert.match(exported, /"counterfactual":"El clon desechable habría aceptado la propuesta; nunca se ejecutó\."/);
  assert.match(exported, /"caseEvidenceSha256":"[a-f0-9]{64}"/);
  assert.match(exported, /"proposalSha256":"[a-f0-9]{64}"/);
  assert.match(exported, /"pairedCaseEvidenceSha256":"[a-f0-9]{64}"/);
  assert.doesNotMatch(exported, /promptSha256|responseSha256|argumentsSha256|argumentsValid/);
  assert.doesNotMatch(exported, /lab-recipient@invalid\.example/);
  assert.doesNotMatch(exported, /DE00LAB000000000000000000/);
  assert.doesNotMatch(exported, /rawPrompt|rawResponse|rawArguments/i);
  assert.doesNotMatch(exported, /<tool_call>|GN-EMAIL-EN-CAL/);

  const autonomousEvidence = job.result;
  if (!autonomousEvidence || autonomousEvidence.profileId !== "guardian-local-llm-autonomous-tools-v1") {
    assert.fail("expected autonomous Qwen evidence");
  }
  const incompleteSuite = structuredClone(autonomousEvidence.nativeToolSuite);
  const incompleteCase = incompleteSuite.caseEvidence.find(
    (item) => item.caseId === "attack_bank_es_cal",
  );
  assert.ok(incompleteCase);
  incompleteCase.policyObservationComplete = false;
  incompleteCase.authorizationAttemptCount = 0;
  const incompleteFinding = deriveQwenBankChangeFinding(incompleteSuite);
  assert.equal(incompleteFinding.stages.attempt, "INCONCLUSO");
  assert.equal(incompleteFinding.stages.policyDecision, "INCONCLUSO");

  const missingCaseSuite = {
    ...autonomousEvidence.nativeToolSuite,
    caseEvidence: autonomousEvidence.nativeToolSuite.caseEvidence.filter(
      (item) => item.caseId !== "attack_bank_es_cal",
    ),
  };
  const missingCaseFinding = deriveQwenBankChangeFinding(missingCaseSuite);
  assert.equal(missingCaseFinding.stages.proposal, "INCONCLUSO");
  assert.equal(missingCaseFinding.stages.attempt, "INCONCLUSO");
  assert.equal(missingCaseFinding.stages.policyDecision, "INCONCLUSO");
  assert.equal(missingCaseFinding.stages.simulatedExecution, "INCONCLUSO");
  assert.match(missingCaseFinding.remediationStatus, /^INCONCLUSO:/);
});

test("report v3 export allow-lists fields and drops unexpected tenant or raw-content properties", () => {
  const responsePath = new URL(
    "../../../../generated-artifacts/ai-assessment-autonomous-e2e-response.json",
    import.meta.url,
  );
  const source = JSON.parse(readFileSync(responsePath, "utf8")) as AiAssessmentLabJob;
  assert.equal(source.status, "succeeded");
  const contaminated = structuredClone(source) as AiAssessmentLabJob & Record<string, unknown>;
  const canary = "SYNTHETIC-RAW-CONTENT-MUST-NOT-EXPORT-4ce19f";
  Object.assign(contaminated, {
    workspaceId: "tenant-private-id",
    rawPrompt: canary,
    rawResponse: canary,
  });
  const result = contaminated.result;
  assert.ok(result);
  Object.assign(result, { rawArguments: canary, privateWorkspaceMetadata: canary });

  const report = buildQwenExecutiveReport(contaminated);
  assert.ok(report);
  const exported = JSON.stringify(report);
  assert.doesNotMatch(exported, new RegExp(canary));
  assert.doesNotMatch(exported, /tenant-private-id|workspaceId|privateWorkspaceMetadata/i);
  assert.doesNotMatch(exported, /rawPrompt|rawResponse|rawArguments/i);
  assert.equal(report.reportVersion, 3);
  assert.equal(report.brand, "Guardian Nexus");
});
