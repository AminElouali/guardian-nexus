import { createHash } from "node:crypto";
import {
  evaluateApprovalAction,
  getApprovalActionDefinition,
  type GenericActionGatewayEvidence,
} from "@workspace/db/approval-action-catalog";
import {
  evaluateWorkspaceActionRule,
  type WorkspaceActionRuleDocument,
  type WorkspaceRuleEvaluationContext,
} from "@workspace/db/workspace-action-rule-engine";
import { canonicalApprovalJson } from "./ai-assessment-approval-actions";

type GenericActionInput = {
  workspaceId: string;
  requestedByUserId: string;
  actionType: string;
  args: Record<string, string | number | boolean>;
  ruleId: string;
  agentId?: string;
  summary: string;
  messagePreview: string;
};

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalApprovalJson(value), "utf8")
    .digest("hex");
}

const evaluationWindows = new Set([60, 300, 900, 3600, 86400]);

function isRuleEvaluationContext(
  value: unknown,
): value is WorkspaceRuleEvaluationContext {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) return false;
  const context = value as Record<string, unknown>;
  if (
    Reflect.ownKeys(context).length !== 3 ||
    !Object.hasOwn(context, "dataSensitivity") ||
    !Object.hasOwn(context, "environment") ||
    !Object.hasOwn(context, "actionCountsByWindow") ||
    ![null, "normal", "sensitive"].includes(context.dataSensitivity as null | string) ||
    ![null, "test", "production"].includes(context.environment as null | string)
  ) return false;
  const counts = context.actionCountsByWindow;
  if (
    !counts ||
    typeof counts !== "object" ||
    Array.isArray(counts) ||
    Object.getPrototypeOf(counts) !== Object.prototype
  ) return false;
  return Reflect.ownKeys(counts).every((key) => {
    if (typeof key !== "string" || !/^(60|300|900|3600|86400)$/.test(key)) {
      return false;
    }
    const count = (counts as Record<string, unknown>)[key];
    return count === null ||
      (typeof count === "number" &&
        Number.isSafeInteger(count) &&
        count >= 0 &&
        count <= 100_000);
  });
}

export function hashGenericActionArguments(
  actionType: string,
  args: Record<string, string | number | boolean>,
): { argumentsSha256: string; actionSha256: string } {
  const argumentsSha256 = sha256(args);
  return {
    argumentsSha256,
    actionSha256: sha256({ actionType, argumentsSha256 }),
  };
}

export function genericActionProposalSha256(input: {
  workspaceId: string;
  requestedByUserId: string;
  actionType: string;
  actionSha256: string;
  ruleId: string;
  ruleVersionId?: string;
}): string {
  return sha256(input);
}

export function createGenericActionEvidence(
  input: GenericActionInput,
): GenericActionGatewayEvidence | null {
  if (
    input.actionType !== "guardian.support.reply.send.v1" &&
    input.actionType !== "guardian.email.send.external.v1" &&
    input.actionType !== "guardian.synthetic.support.refund.v1"
  ) {
    return null;
  }
  const evaluated = evaluateApprovalAction(input.actionType, input.args);
  if (
    !evaluated.ok ||
    evaluated.decision !== "require_approval" ||
    !evaluated.ruleId ||
    evaluated.ruleId !== input.ruleId
  ) {
    return null;
  }
  const { argumentsSha256, actionSha256 } = hashGenericActionArguments(
    input.actionType,
    evaluated.args,
  );
  const display = genericActionDisplay(input.actionType, evaluated.args);
  if (!display) return null;
  const proposalSha256 = genericActionProposalSha256({
    workspaceId: input.workspaceId,
    requestedByUserId: input.requestedByUserId,
    actionType: input.actionType,
    actionSha256,
    ruleId: evaluated.ruleId,
  });
  const unsigned: Omit<GenericActionGatewayEvidence, "evidenceSha256"> = {
    engine: "guardian_action_gateway",
    engineVersion: "guardian-action-catalog-v1",
    profileId:
      input.actionType === "guardian.email.send.external.v1"
        ? "guardian-agent-lab-email-v1"
        : "guardian-agent-lab-customer-service-v1",
    executionMode: "deterministic_fixture",
    modelInference: false,
    toolCallOrigin: "controlled_fixture_not_llm",
    evidenceVersion: 1,
    actionType: input.actionType,
    arguments: evaluated.args,
    actionSha256,
    argumentsSha256,
    proposalSha256,
    ruleId: evaluated.ruleId,
    decision: "require_approval",
    agentId: input.agentId ?? display.agentId,
    synthetic: true,
    summary: input.summary.slice(0, 500),
    messagePreview: input.messagePreview.slice(0, 500),
    requestedByUserId: input.requestedByUserId,
    workspaceId: input.workspaceId,
  };
  return { ...unsigned, evidenceSha256: sha256(unsigned) };
}

export function createWorkspaceRuleActionEvidence(input: {
  workspaceId: string;
  requestedByUserId: string;
  actionType: string;
  args: Record<string, string | number | boolean>;
  ruleId: string;
  ruleVersionId: string;
  ruleDocument: WorkspaceActionRuleDocument;
  ruleEvaluationContext?: WorkspaceRuleEvaluationContext;
  allowEscalation?: boolean;
  summary: string;
  messagePreview: string;
  agentId: string;
}): GenericActionGatewayEvidence | null {
  const action = evaluateApprovalAction(input.actionType, input.args);
  if (!action.ok) return null;
  const decision = evaluateWorkspaceActionRule({
    actionType: input.actionType,
    arguments: action.args,
    document: input.ruleDocument,
    ruleVersionId: input.ruleVersionId,
    context: input.ruleEvaluationContext,
  });
  const escalatedAllow =
    decision.decision === "allow" &&
    input.allowEscalation === true &&
    getApprovalActionDefinition(input.actionType)?.requiresIndependentApprover ===
      true;
  if (
    (decision.decision !== "require_approval" && !escalatedAllow) ||
    !decision.ruleId ||
    decision.ruleId !== input.ruleId
  ) {
    return null;
  }
  const { argumentsSha256, actionSha256 } = hashGenericActionArguments(
    input.actionType,
    action.args,
  );
  const proposalSha256 = genericActionProposalSha256({
    workspaceId: input.workspaceId,
    requestedByUserId: input.requestedByUserId,
    actionType: input.actionType,
    actionSha256,
    ruleId: input.ruleId,
    ruleVersionId: input.ruleVersionId,
  });
  const ruleDocumentSha256 = sha256(input.ruleDocument);
  const unsigned: Omit<GenericActionGatewayEvidence, "evidenceSha256"> = {
    engine: "guardian_action_gateway",
    engineVersion: "guardian-workspace-rules-v2",
    profileId: getApprovalActionDefinition(input.actionType)!.profileId,
    executionMode: "deterministic_fixture",
    modelInference: false,
    toolCallOrigin: "controlled_fixture_not_llm",
    evidenceVersion: 2,
    actionType: input.actionType,
    arguments: action.args,
    actionSha256,
    argumentsSha256,
    proposalSha256,
    ruleId: input.ruleId,
    decision: "require_approval",
    agentId: input.agentId,
    synthetic: true,
    summary: input.summary.slice(0, 500),
    messagePreview: input.messagePreview.slice(0, 500),
    requestedByUserId: input.requestedByUserId,
    workspaceId: input.workspaceId,
    ruleVersionId: input.ruleVersionId,
    ruleDocumentSha256,
    ruleDocument: input.ruleDocument,
    ...(input.ruleEvaluationContext
      ? { ruleEvaluationContext: input.ruleEvaluationContext }
      : {}),
    ...(escalatedAllow
      ? { decisionEscalation: "rule_allow_escalated_to_approval" as const }
      : {}),
  };
  return { ...unsigned, evidenceSha256: sha256(unsigned) };
}

export function genericActionDisplay(
  actionType: string,
  args: Record<string, string | number | boolean>,
): { summary: string; messagePreview: string; agentId: string } | null {
  const definition = getApprovalActionDefinition(actionType);
  if (!definition?.syntheticTemplateText) return null;
  if (actionType === "guardian.email.send.external.v1") {
    return {
      summary: `Correo sintético a ${String(args.to)} mediante la plantilla ${String(args.template_id)}.`,
      messagePreview: definition.syntheticTemplateText,
      agentId: "agent-fixture-email-demo-v1",
    };
  }
  if (actionType === "guardian.support.reply.send.v1") {
    const euros = (Number(args.compensation_cents) / 100).toFixed(2);
    return {
      summary: `Respuesta sintética para ${String(args.ticket_id)} a ${String(args.recipient_email)}; compensación ${euros} EUR.`,
      messagePreview: definition.syntheticTemplateText,
      agentId: "agent-fixture-support-demo-v1",
    };
  }
  if (actionType === "guardian.synthetic.support.refund.v1") {
    return {
      summary: `Reembolso sintético de ${(Number(args.amount_cents) / 100).toFixed(2)} EUR para ${String(args.ticket_id)}.`,
      messagePreview: definition.syntheticTemplateText,
      agentId: "agent-fixture-refund-demo-v1",
    };
  }
  if (actionType === "guardian.synthetic.finance.bank-change.v1") {
    return {
      summary: `Cambio bancario sintético para ${String(args.account_id)}.`,
      messagePreview: definition.syntheticTemplateText,
      agentId: "agent-fixture-bank-change-demo-v1",
    };
  }
  return {
    summary: `${definition.label} (propuesta sintética; sin servicio real).`,
    messagePreview: definition.syntheticTemplateText,
    agentId: `agent-fixture-${definition.service}-demo-v1`,
  };
}

export function verifyGenericActionEvidence(
  value: unknown,
  expected: {
    workspaceId: string;
    requestedByUserId: string;
    actionType: string;
    actionSha256: string;
    proposalSha256: string;
    profileId: string;
    agentId?: string;
  },
): GenericActionGatewayEvidence | null {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value)
  ) {
    return null;
  }
  const evidence = value as Partial<GenericActionGatewayEvidence>;
  const v1Keys = [
    "engine",
    "engineVersion",
    "profileId",
    "executionMode",
    "modelInference",
    "toolCallOrigin",
    "evidenceVersion",
    "actionType",
    "arguments",
    "actionSha256",
    "argumentsSha256",
    "proposalSha256",
    "ruleId",
    "decision",
    "agentId",
    "synthetic",
    "summary",
    "messagePreview",
    "requestedByUserId",
    "workspaceId",
    "evidenceSha256",
  ];
  const evidenceVersion =
    typeof (value as { evidenceVersion?: unknown }).evidenceVersion === "number"
      ? (value as { evidenceVersion: number }).evidenceVersion
      : 0;
  const hasDecisionEscalation =
    evidenceVersion === 2 && Object.hasOwn(value, "decisionEscalation");
  const hasRuleEvaluationContext =
    evidenceVersion === 2 && Object.hasOwn(value, "ruleEvaluationContext");
  const expectedKeys = evidenceVersion === 2
    ? [
      ...v1Keys,
      "ruleVersionId",
      "ruleDocumentSha256",
      "ruleDocument",
      ...(hasDecisionEscalation ? ["decisionEscalation"] : []),
      ...(hasRuleEvaluationContext ? ["ruleEvaluationContext"] : []),
    ]
    : v1Keys;
  if (
    Reflect.ownKeys(value).length !== expectedKeys.length ||
    expectedKeys.some((key) => !Object.hasOwn(value, key)) ||
    Reflect.ownKeys(value).some(
      (key) => typeof key !== "string" || !expectedKeys.includes(key),
    )
  ) {
    return null;
  }
  const { evidenceSha256, ...unsigned } = evidence;
  if (
    evidence.engine !== "guardian_action_gateway" ||
    (evidence.evidenceVersion === 1 &&
      evidence.engineVersion !== "guardian-action-catalog-v1") ||
    (evidence.evidenceVersion === 2 &&
      evidence.engineVersion !== "guardian-workspace-rules-v2") ||
    evidence.executionMode !== "deterministic_fixture" ||
    evidence.modelInference !== false ||
    evidence.toolCallOrigin !== "controlled_fixture_not_llm" ||
    (evidence.evidenceVersion !== 1 && evidence.evidenceVersion !== 2) ||
    evidence.decision !== "require_approval" ||
    evidence.synthetic !== true ||
    typeof evidence.agentId !== "string" ||
    evidence.agentId.length < 1 ||
    evidence.agentId.length > 120 ||
    evidence.workspaceId !== expected.workspaceId ||
    evidence.requestedByUserId !== expected.requestedByUserId ||
    evidence.actionType !== expected.actionType ||
    evidence.actionSha256 !== expected.actionSha256 ||
    evidence.proposalSha256 !== expected.proposalSha256 ||
    evidence.profileId !== expected.profileId ||
    typeof evidence.ruleId !== "string" ||
    typeof evidence.summary !== "string" ||
    typeof evidence.messagePreview !== "string" ||
    typeof evidence.evidenceSha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(evidence.actionSha256) ||
    !/^[a-f0-9]{64}$/.test(evidence.argumentsSha256 ?? "") ||
    sha256(unsigned) !== evidenceSha256
  ) {
    return null;
  }
  const evaluated = evaluateApprovalAction(evidence.actionType, evidence.arguments);
  if (
    !evaluated.ok ||
    (evidence.evidenceVersion === 1 &&
      ((evidence.actionType !== "guardian.support.reply.send.v1" &&
        evidence.actionType !== "guardian.email.send.external.v1" &&
        evidence.actionType !== "guardian.synthetic.support.refund.v1") ||
        evaluated.decision !== "require_approval" ||
        evaluated.ruleId !== evidence.ruleId))
  ) {
    return null;
  }
  if (
    evidence.evidenceVersion === 2 &&
    (!evidence.ruleVersionId ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(evidence.ruleVersionId) ||
      !evidence.ruleDocument ||
      evidence.ruleDocument.version !== 1 ||
      sha256(evidence.ruleDocument) !== evidence.ruleDocumentSha256 ||
      (hasRuleEvaluationContext &&
        !isRuleEvaluationContext(evidence.ruleEvaluationContext)))
  ) {
    return null;
  }
  const effectiveDecision = evidence.evidenceVersion === 2
    ? evaluateWorkspaceActionRule({
        actionType: evidence.actionType,
        arguments: evaluated.args,
        document: evidence.ruleDocument!,
        ruleVersionId: evidence.ruleVersionId!,
        context: hasRuleEvaluationContext
          ? evidence.ruleEvaluationContext
          : undefined,
      })
    : null;
  if (
    effectiveDecision &&
    ((effectiveDecision.decision !== "require_approval" &&
      !(
        effectiveDecision.decision === "allow" &&
        evidence.decisionEscalation === "rule_allow_escalated_to_approval" &&
        getApprovalActionDefinition(evidence.actionType)
          ?.requiresIndependentApprover === true
      )) ||
      effectiveDecision.ruleId !== evidence.ruleId ||
      effectiveDecision.ruleVersionId !== evidence.ruleVersionId)
  ) {
    return null;
  }
  if (
    evidence.decisionEscalation !== undefined &&
    evidence.decisionEscalation !== "rule_allow_escalated_to_approval"
  ) {
    return null;
  }
  const hashes = hashGenericActionArguments(evidence.actionType, evaluated.args);
  const display = genericActionDisplay(evidence.actionType, evaluated.args);
  const v1AgentIdentityMatches = evidence.evidenceVersion !== 1
    ? true
    : evidence.actionType === "guardian.synthetic.support.refund.v1"
      ? expected.agentId !== undefined
        ? evidence.agentId === expected.agentId
        : evidence.agentId === display?.agentId ||
          /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
            .test(evidence.agentId)
      : evidence.agentId === display?.agentId;
  if (
    !display ||
    !v1AgentIdentityMatches ||
    display.summary !== evidence.summary ||
    display.messagePreview !== evidence.messagePreview ||
    hashes.argumentsSha256 !== evidence.argumentsSha256 ||
    hashes.actionSha256 !== evidence.actionSha256 ||
    genericActionProposalSha256({
      workspaceId: expected.workspaceId,
      requestedByUserId: expected.requestedByUserId,
      actionType: expected.actionType,
      actionSha256: expected.actionSha256,
      ruleId: evidence.ruleId,
      ...(evidence.evidenceVersion === 2 && evidence.ruleVersionId
        ? { ruleVersionId: evidence.ruleVersionId }
        : {}),
    }) !== evidence.proposalSha256
  ) {
    return null;
  }
  return evidence as GenericActionGatewayEvidence;
}
