import { createHash } from "node:crypto";
import {
  evaluateApprovalAction,
  getApprovalActionDefinition,
  type GenericActionGatewayEvidence,
} from "@workspace/db/approval-action-catalog";
import { canonicalApprovalJson } from "./ai-assessment-approval-actions";

type GenericActionInput = {
  workspaceId: string;
  requestedByUserId: string;
  actionType: string;
  args: Record<string, string | number | boolean>;
  ruleId: string;
  summary: string;
  messagePreview: string;
};

function sha256(value: unknown): string {
  return createHash("sha256")
    .update(canonicalApprovalJson(value), "utf8")
    .digest("hex");
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
}): string {
  return sha256(input);
}

export function createGenericActionEvidence(
  input: GenericActionInput,
): GenericActionGatewayEvidence | null {
  if (
    input.actionType !== "guardian.support.reply.send.v1" &&
    input.actionType !== "guardian.email.send.external.v1"
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
      input.actionType === "guardian.support.reply.send.v1"
        ? "guardian-agent-lab-customer-service-v1"
        : "guardian-agent-lab-email-v1",
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
    agentId:
      input.actionType === "guardian.support.reply.send.v1"
        ? "agent-fixture-support-demo-v1"
        : "agent-fixture-email-demo-v1",
    synthetic: true,
    summary: input.summary.slice(0, 500),
    messagePreview: input.messagePreview.slice(0, 500),
    requestedByUserId: input.requestedByUserId,
    workspaceId: input.workspaceId,
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
  return null;
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
  const expectedKeys = [
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
    evidence.engineVersion !== "guardian-action-catalog-v1" ||
    evidence.executionMode !== "deterministic_fixture" ||
    evidence.modelInference !== false ||
    evidence.toolCallOrigin !== "controlled_fixture_not_llm" ||
    evidence.evidenceVersion !== 1 ||
    evidence.decision !== "require_approval" ||
    evidence.synthetic !== true ||
    (evidence.agentId !== "agent-fixture-support-demo-v1" &&
      evidence.agentId !== "agent-fixture-email-demo-v1") ||
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
    (evidence.actionType !== "guardian.support.reply.send.v1" &&
      evidence.actionType !== "guardian.email.send.external.v1") ||
    !evaluated.ok ||
    evaluated.decision !== "require_approval" ||
    evaluated.ruleId !== evidence.ruleId
  ) {
    return null;
  }
  const hashes = hashGenericActionArguments(evidence.actionType, evaluated.args);
  const display = genericActionDisplay(evidence.actionType, evaluated.args);
  if (
    !display ||
    display.agentId !== evidence.agentId ||
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
    }) !== evidence.proposalSha256
  ) {
    return null;
  }
  return evidence as GenericActionGatewayEvidence;
}
