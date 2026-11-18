export type ApprovalActionDecision = "allow" | "deny" | "require_approval";
export type ApprovalActionValue = string | number | boolean;

export type GenericActionGatewayEvidence = {
  engine: "guardian_action_gateway";
  engineVersion: "guardian-action-catalog-v1" | "guardian-workspace-rules-v2";
  profileId:
    | "guardian-agent-lab-email-v1"
    | "guardian-agent-lab-customer-service-v1";
  executionMode: "deterministic_fixture";
  modelInference: false;
  toolCallOrigin: "controlled_fixture_not_llm";
  evidenceVersion: 1 | 2;
  actionType: string;
  arguments: Record<string, ApprovalActionValue>;
  actionSha256: string;
  argumentsSha256: string;
  proposalSha256: string;
  ruleId: string;
  decision: "require_approval";
  agentId: string;
  synthetic: true;
  summary: string;
  messagePreview: string;
  requestedByUserId: string;
  workspaceId: string;
  ruleVersionId?: string | null;
  ruleDocumentSha256?: string | null;
  ruleDocument?: {
    version: 1;
    rules: Array<{
      id: string;
      decision: ApprovalActionDecision;
      when: {
        all?: Array<{
          field: string;
          op: "eq" | "gt" | "lte";
          value: string | number | boolean;
        }>;
        any?: Array<{
          field: string;
          op: "eq" | "gt" | "lte";
          value: string | number | boolean;
        }>;
      };
    }>;
  } | null;
  evidenceSha256: string;
};

type PropertyRule = {
  type: "string" | "integer" | "boolean";
  required?: boolean;
  min?: number;
  max?: number;
  maxLength?: number;
  pattern?: RegExp;
  enum?: readonly (string | number | boolean)[];
};

type ActionRule = {
  id: string;
  conditionText: string;
  decision: ApprovalActionDecision;
  when: {
    all?: readonly {
      field: string;
      op: "eq" | "gt" | "lte";
      value: string | number | boolean;
    }[];
    any?: readonly {
      field: string;
      op: "eq" | "gt" | "lte";
      value: string | number | boolean;
    }[];
  };
};

export type ApprovalActionDefinition = {
  actionType: string;
  label: string;
  description: string;
  riskClass: "low" | "medium" | "high";
  riskCategories: readonly (
    | "money"
    | "internal_email"
    | "external_email"
    | "customer_data"
    | "infrastructure"
  )[];
  defaultDecision: "deny";
  allowedApproverRoles: readonly ("owner" | "admin")[];
  receiptExpirySeconds: number;
  requiresIndependentApprover: boolean;
  syntheticTemplateText?: string;
  argumentSchema: {
    type: "object";
    additionalProperties: false;
    properties: Readonly<Record<string, PropertyRule>>;
  };
  rules: readonly ActionRule[];
};

const sandboxRecipient = /^[A-Za-z0-9._+-]+@(?:example\.test|guardian\.invalid)$/;
const syntheticTicket = /^TICKET-SYNTH-[A-Z0-9-]{1,40}$/;
const syntheticAccount = /^LAB-ACCOUNT-[A-Z0-9-]{1,32}$/;

// This is the shared source of action identifiers and policy templates. The
// database CHECK is generated from APPROVAL_ACTION_REFS below; SQL deployments
// mirror that exact list in lib/db/sql/rls-policies.sql.
export const APPROVAL_ACTION_CATALOG: readonly ApprovalActionDefinition[] = [
  {
    actionType: "guardian.synthetic.support.refund.v1",
    label: "Reembolso sintético",
    description: "Fixture existente; solo simula cambios en memoria.",
    riskClass: "medium",
    riskCategories: ["money", "customer_data"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El reembolso solo se evalúa en un clon de memoria.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        ticket_id: { type: "string", required: true, pattern: syntheticTicket },
        amount_cents: { type: "integer", required: true, min: 1, max: 1000000 },
      },
    },
    rules: [
      { id: "refund.fixture.requires-independent-approval.v1", conditionText: "Importe de la fixture dentro del límite sintético", decision: "require_approval", when: {} },
    ],
  },
  {
    actionType: "guardian.synthetic.finance.bank-change.v1",
    label: "Cambio bancario sintético",
    description: "Fixture existente; solo simula cambios en memoria.",
    riskClass: "high",
    riskCategories: ["money", "infrastructure"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    syntheticTemplateText: "[SYNTHETIC] El cambio bancario solo se evalúa en un clon de memoria.",
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        account_id: { type: "string", required: true, pattern: syntheticAccount },
        new_iban: { type: "string", required: true, pattern: /^DE00LAB[0-9A-Z]{16}$/ },
      },
    },
    rules: [
      { id: "bank-change.fixture.requires-independent-approval.v1", conditionText: "Cambio bancario de laboratorio", decision: "require_approval", when: {} },
    ],
  },
  {
    actionType: "guardian.support.reply.send.v1",
    label: "Responder a soporte",
    description: "Solo ejemplos sintéticos dirigidos a dominios de prueba.",
    riskClass: "medium",
    riskCategories: ["customer_data", "internal_email", "external_email"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        ticket_id: { type: "string", required: true, pattern: syntheticTicket },
        recipient_email: { type: "string", required: true, maxLength: 254, pattern: sandboxRecipient },
        recipient_type: { type: "string", required: true, enum: ["internal", "external"] },
        compensation_cents: { type: "integer", required: true, min: 0, max: 1000000 },
        template_id: { type: "string", required: true, enum: ["synthetic-support-reply-v1"] },
      },
    },
    syntheticTemplateText:
      "[SYNTHETIC] Gracias por contactar con soporte. Este mensaje solo se captura en el buzón local de pruebas.",
    rules: [
      { id: "support.compensation.over-50-eur.deny.v1", conditionText: "Compensación superior a 50 EUR", decision: "deny", when: { any: [{ field: "compensation_cents", op: "gt", value: 5000 }] } },
      { id: "support.internal.no-compensation.allow.v1", conditionText: "Destinatario interno y sin compensación", decision: "allow", when: { all: [{ field: "recipient_type", op: "eq", value: "internal" }, { field: "compensation_cents", op: "eq", value: 0 }] } },
      { id: "support.external-or-compensation.approval.v1", conditionText: "Destinatario externo o compensación de hasta 50 EUR", decision: "require_approval", when: {} },
    ],
  },
  {
    actionType: "guardian.email.send.external.v1",
    label: "Enviar correo externo de prueba",
    description: "Entrega solo a un buzón sandbox local; no usa proveedores externos.",
    riskClass: "high",
    riskCategories: ["external_email"],
    defaultDecision: "deny",
    allowedApproverRoles: ["owner", "admin"],
    receiptExpirySeconds: 300,
    requiresIndependentApprover: true,
    argumentSchema: {
      type: "object",
      additionalProperties: false,
      properties: {
        to: { type: "string", required: true, maxLength: 254, pattern: sandboxRecipient },
        template_id: { type: "string", required: true, enum: ["guardian-demo-email-v1"] },
      },
    },
    syntheticTemplateText:
      "[SYNTHETIC] Mensaje de prueba de Guardian Nexus. Capturado localmente; no se entrega a un proveedor externo.",
    rules: [
      { id: "external-email.sandbox.requires-independent-approval.v1", conditionText: "Correo de prueba enviado únicamente al buzón sandbox", decision: "require_approval", when: {} },
    ],
  },
] as const;

export const APPROVAL_ACTION_REFS = APPROVAL_ACTION_CATALOG.map(
  (action) => action.actionType,
) as readonly string[];

export type CatalogActionRef = (typeof APPROVAL_ACTION_CATALOG)[number]["actionType"];

export function getApprovalActionDefinition(
  actionType: string,
): ApprovalActionDefinition | undefined {
  return APPROVAL_ACTION_CATALOG.find((action) => action.actionType === actionType);
}

export function validateApprovalActionArguments(
  definition: ApprovalActionDefinition,
  value: unknown,
): { ok: true; args: Record<string, ApprovalActionValue> } | { ok: false; issues: string[] } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, issues: ["arguments_not_object"] };
  }
  const input = value as Record<string, unknown>;
  const allowedKeys = new Set(Object.keys(definition.argumentSchema.properties));
  const issues: string[] = [];
  for (const key of Object.keys(input)) {
    if (!allowedKeys.has(key)) issues.push(`unknown_argument:${key}`);
  }
  const args: Record<string, ApprovalActionValue> = {};
  for (const [key, rule] of Object.entries(definition.argumentSchema.properties)) {
    const item = input[key];
    if (item === undefined) {
      if (rule.required) issues.push(`missing_argument:${key}`);
      continue;
    }
    if (
      rule.type === "string" &&
      (typeof item !== "string" ||
        (rule.maxLength !== undefined && item.length > rule.maxLength) ||
        (rule.pattern !== undefined && !rule.pattern.test(item)) ||
        (rule.enum !== undefined && !rule.enum.includes(item)))
    ) {
      issues.push(`invalid_argument:${key}`);
      continue;
    }
    if (
      rule.type === "integer" &&
      (typeof item !== "number" ||
        !Number.isSafeInteger(item) ||
        (rule.min !== undefined && item < rule.min) ||
        (rule.max !== undefined && item > rule.max))
    ) {
      issues.push(`invalid_argument:${key}`);
      continue;
    }
    if (rule.type === "boolean" && typeof item !== "boolean") {
      issues.push(`invalid_argument:${key}`);
      continue;
    }
    args[key] = item as ApprovalActionValue;
  }
  return issues.length ? { ok: false, issues } : { ok: true, args };
}

function matchesRuleAtom(
  args: Readonly<Record<string, ApprovalActionValue>>,
  condition: NonNullable<ActionRule["when"]["all"]>[number],
): boolean {
  const actual = args[condition.field];
  if (condition.op === "eq") return actual === condition.value;
  if (typeof actual !== "number" || typeof condition.value !== "number") return false;
  return condition.op === "gt" ? actual > condition.value : actual <= condition.value;
}

export function evaluateApprovalAction(
  actionType: string,
  value: unknown,
): {
  ok: true;
  decision: ApprovalActionDecision;
  reasonCode: string;
  ruleId: string | null;
  definition: ApprovalActionDefinition;
  args: Record<string, ApprovalActionValue>;
} | {
  ok: false;
  decision: "deny";
  reasonCode: "unknown_action" | "arguments_invalid";
  issues: string[];
} {
  const definition = getApprovalActionDefinition(actionType);
  if (!definition) {
    return { ok: false, decision: "deny", reasonCode: "unknown_action", issues: [] };
  }
  const validated = validateApprovalActionArguments(definition, value);
  if (!validated.ok) {
    return {
      ok: false,
      decision: "deny",
      reasonCode: "arguments_invalid",
      issues: validated.issues,
    };
  }
  for (const rule of definition.rules) {
    const allMatch = rule.when.all?.every((condition) =>
      matchesRuleAtom(validated.args, condition),
    ) ?? true;
    const anyMatch = rule.when.any?.some((condition) =>
      matchesRuleAtom(validated.args, condition),
    ) ?? true;
    if (allMatch && anyMatch) {
      return {
        ok: true,
        decision: rule.decision,
        reasonCode: rule.decision === "deny"
          ? "blocked_by_template"
          : rule.decision === "allow"
            ? "allowed_by_template"
            : "human_approval_required",
        ruleId: rule.id,
        definition,
        args: validated.args,
      };
    }
  }
  return {
    ok: true,
    decision: definition.defaultDecision,
    reasonCode: "default_block",
    ruleId: null,
    definition,
    args: validated.args,
  };
}
