import {
  APPROVAL_ACTION_CATALOG,
  type ApprovalActionDecision,
  type ApprovalActionDefinition,
  type ApprovalActionValue,
  evaluateApprovalAction,
  getApprovalActionDefinition,
  validateApprovalActionArguments,
} from "./approval-action-catalog";

export type WorkspaceRuleCondition = {
  field: string;
  op: "eq" | "gt" | "lte";
  value: string | number | boolean;
};

export type WorkspaceActionRule = {
  id: string;
  decision: ApprovalActionDecision;
  when: {
    all?: WorkspaceRuleCondition[];
    any?: WorkspaceRuleCondition[];
  };
};

export type WorkspaceActionRuleDocument = {
  version: 1;
  rules: WorkspaceActionRule[];
};

export const MAX_REFUND_LIMIT_CENTS = 1_000_000;

export type WorkspaceActionRuleProfileId =
  | "prudent-v1"
  | "balanced-v1"
  | "read-only-v1";

export type WorkspaceActionRuleProfile = {
  id: WorkspaceActionRuleProfileId;
  label: string;
  description: string;
  defaultRefundLimitCents: number;
};

const workspaceActionRuleProfiles: readonly WorkspaceActionRuleProfile[] = [
  {
    id: "prudent-v1",
    label: "Prudente",
    description: "El dinero, los correos externos y las respuestas sensibles piden aprobación.",
    defaultRefundLimitCents: 5_000,
  },
  {
    id: "balanced-v1",
    label: "Equilibrada",
    description: "Las respuestas rutinarias pasan; el dinero y las acciones sensibles requieren revisión.",
    defaultRefundLimitCents: 5_000,
  },
  {
    id: "read-only-v1",
    label: "Solo lectura",
    description: "Todas las acciones se bloquean; el agente solo puede proponer.",
    defaultRefundLimitCents: 5_000,
  },
];

export function getWorkspaceActionRuleProfiles(): WorkspaceActionRuleProfile[] {
  return workspaceActionRuleProfiles.map((profile) => ({ ...profile }));
}

export function buildWorkspaceActionRuleProfileDocuments(
  profileId: string,
  refundLimitCents: number,
):
  | {
      ok: true;
      profile: WorkspaceActionRuleProfile;
      documents: Array<{
        actionType: string;
        document: WorkspaceActionRuleDocument;
      }>;
    }
  | { ok: false; issues: string[] } {
  const profile = workspaceActionRuleProfiles.find(
    (candidate) => candidate.id === profileId,
  );
  if (!profile) return { ok: false, issues: ["unknown_rule_profile"] };
  if (
    !Number.isSafeInteger(refundLimitCents) ||
    refundLimitCents < 1 ||
    refundLimitCents > MAX_REFUND_LIMIT_CENTS
  ) {
    return { ok: false, issues: ["refund_limit_out_of_range"] };
  }

  const restrictiveDecision: ApprovalActionDecision =
    profile.id === "read-only-v1" ? "deny" : "require_approval";
  const routineSupportDecision: ApprovalActionDecision =
    profile.id === "balanced-v1" ? "allow" : restrictiveDecision;
  const refundAtOrBelowDecision: ApprovalActionDecision =
    profile.id === "balanced-v1"
      ? "allow"
      : restrictiveDecision;

  const documents = [
    {
      actionType: "guardian.synthetic.support.refund.v1",
      document: {
        version: 1 as const,
        rules: [
          {
            id: "refund-within-threshold",
            decision: refundAtOrBelowDecision,
            when: {
              all: [{
                field: "amount_cents",
                op: "lte" as const,
                value: refundLimitCents,
              }],
            },
          },
          {
            id: "refund-above-threshold",
            decision: restrictiveDecision,
            when: {
              all: [{
                field: "amount_cents",
                op: "gt" as const,
                value: refundLimitCents,
              }],
            },
          },
        ],
      },
    },
    {
      actionType: "guardian.synthetic.finance.bank-change.v1",
      document: {
        version: 1 as const,
        rules: [{
          id: "bank-account-change",
          decision: restrictiveDecision,
          when: {},
        }],
      },
    },
    {
      actionType: "guardian.email.send.external.v1",
      document: {
        version: 1 as const,
        rules: [{
          id: "external-email",
          decision: restrictiveDecision,
          when: {},
        }],
      },
    },
    {
      actionType: "guardian.support.reply.send.v1",
      document: {
        version: 1 as const,
        rules: [
          {
            id: "support-sensitive-external-or-high-compensation",
            decision: restrictiveDecision,
            when: {
              any: [
                {
                  field: "recipient_type",
                  op: "eq" as const,
                  value: "external",
                },
                {
                  field: "compensation_cents",
                  op: "gt" as const,
                  value: refundLimitCents,
                },
              ],
            },
          },
          {
            id: "support-routine-internal",
            decision: routineSupportDecision,
            when: {
              all: [
                {
                  field: "recipient_type",
                  op: "eq" as const,
                  value: "internal",
                },
                {
                  field: "compensation_cents",
                  op: "lte" as const,
                  value: refundLimitCents,
                },
              ],
            },
          },
        ],
      },
    },
  ];

  const invalidDocuments = documents.filter(
    ({ actionType, document }) =>
      !validateWorkspaceActionRuleDocument(actionType, document).ok,
  );
  if (invalidDocuments.length) {
    return { ok: false, issues: ["rule_profile_invalid"] };
  }
  return { ok: true, profile: { ...profile }, documents };
}

export type WorkspaceRuleWarning = {
  code: "unconditional_allow" | "unbounded_recipient" | "contradictory_rules";
  ruleIds: string[];
  message: string;
};

const allowedKeys = (value: unknown, allowed: readonly string[]): value is Record<string, unknown> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).every((key) => allowed.includes(key));

function stableWhen(when: WorkspaceActionRule["when"]): string {
  const normalize = (conditions: WorkspaceRuleCondition[] | undefined) =>
    [...(conditions ?? [])]
      .map((condition) => `${condition.field}:${condition.op}:${JSON.stringify(condition.value)}`)
      .sort();
  return JSON.stringify({ all: normalize(when.all), any: normalize(when.any) });
}

function isPrimitive(value: unknown): value is string | number | boolean {
  return (
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value))
  );
}

function validateCondition(
  definition: ApprovalActionDefinition,
  value: unknown,
): value is WorkspaceRuleCondition {
  if (!allowedKeys(value, ["field", "op", "value"])) return false;
  if (
    typeof value.field !== "string" ||
    !["eq", "gt", "lte"].includes(String(value.op)) ||
    !isPrimitive(value.value)
  ) return false;
  const property = definition.argumentSchema.properties[value.field];
  if (!property) return false;
  if (value.op !== "eq" && property.type !== "integer") return false;
  if (property.type === "integer") {
    if (typeof value.value !== "number" || !Number.isSafeInteger(value.value)) return false;
    if (property.min !== undefined && value.value < property.min) return false;
    if (property.max !== undefined && value.value > property.max) return false;
  } else if (property.type === "boolean") {
    if (typeof value.value !== "boolean") return false;
  } else {
    if (typeof value.value !== "string") return false;
    if (property.enum && !property.enum.includes(value.value)) return false;
  }
  return true;
}

export function validateWorkspaceActionRuleDocument(
  actionType: string,
  input: unknown,
): { ok: true; document: WorkspaceActionRuleDocument } | { ok: false; issues: string[] } {
  const definition = getApprovalActionDefinition(actionType);
  if (!definition) return { ok: false, issues: ["unknown_action"] };
  if (!allowedKeys(input, ["version", "rules"]) || input.version !== 1 || !Array.isArray(input.rules)) {
    return { ok: false, issues: ["invalid_rule_document"] };
  }
  if (input.rules.length > 50) return { ok: false, issues: ["too_many_rules"] };
  const issues: string[] = [];
  const rules: WorkspaceActionRule[] = [];
  const seenIds = new Set<string>();
  input.rules.forEach((candidate, index) => {
    if (!allowedKeys(candidate, ["id", "decision", "when"])) {
      issues.push(`invalid_rule:${index}`);
      return;
    }
    if (
      typeof candidate.id !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/.test(candidate.id) ||
      seenIds.has(candidate.id) ||
      !["allow", "deny", "require_approval"].includes(String(candidate.decision)) ||
      !allowedKeys(candidate.when, ["all", "any"])
    ) {
      issues.push(`invalid_rule:${index}`);
      return;
    }
    seenIds.add(candidate.id);
    const when = candidate.when as Record<string, unknown>;
    if (
      (when.all !== undefined &&
        (!Array.isArray(when.all) ||
          when.all.length > 8 ||
          !when.all.every((condition) => validateCondition(definition, condition)))) ||
      (when.any !== undefined &&
        (!Array.isArray(when.any) ||
          when.any.length > 8 ||
          !when.any.every((condition) => validateCondition(definition, condition))))
    ) {
      issues.push(`invalid_condition:${index}`);
      return;
    }
    rules.push({
      id: candidate.id,
      decision: candidate.decision as ApprovalActionDecision,
      when: {
        ...(when.all ? { all: when.all as WorkspaceRuleCondition[] } : {}),
        ...(when.any ? { any: when.any as WorkspaceRuleCondition[] } : {}),
      },
    });
  });
  return issues.length
    ? { ok: false, issues }
    : { ok: true, document: { version: 1, rules } };
}

export function getWorkspaceRuleWarnings(
  actionType: string,
  document: WorkspaceActionRuleDocument,
): WorkspaceRuleWarning[] {
  const definition = getApprovalActionDefinition(actionType);
  if (!definition) return [];
  const warnings: WorkspaceRuleWarning[] = [];
  const unconditionalAllows = document.rules
    .filter((rule) => rule.decision === "allow" && !rule.when.all?.length && !rule.when.any?.length)
    .map((rule) => rule.id);
  if (unconditionalAllows.length) {
    warnings.push({
      code: "unconditional_allow",
      ruleIds: unconditionalAllows,
      message: "Esta regla permite la acción sin comprobar ningún campo.",
    });
  }
  const recipientField = definition.argumentSchema.properties.to
    ? "to"
    : definition.argumentSchema.properties.recipient_email
      ? "recipient_email"
      : null;
  if (
    recipientField &&
    document.rules.some(
      (rule) =>
        rule.decision === "allow" &&
        !rule.when.all?.some((condition) => condition.field === recipientField) &&
        !rule.when.any?.some((condition) => condition.field === recipientField),
    )
  ) {
    warnings.push({
      code: "unbounded_recipient",
      ruleIds: document.rules
        .filter(
          (rule) =>
            rule.decision === "allow" &&
            !rule.when.all?.some((condition) => condition.field === recipientField) &&
            !rule.when.any?.some((condition) => condition.field === recipientField),
        )
        .map((rule) => rule.id),
      message: "La regla de correo no limita el destinatario.",
    });
  }

  const byCondition = new Map<string, WorkspaceActionRule[]>();
  for (const rule of document.rules) {
    const signature = stableWhen(rule.when);
    const group = byCondition.get(signature) ?? [];
    group.push(rule);
    byCondition.set(signature, group);
  }
  const contradictory = [...byCondition.values()].filter(
    (group) => new Set(group.map((rule) => rule.decision)).size > 1,
  );
  for (const group of contradictory) {
    warnings.push({
      code: "contradictory_rules",
      ruleIds: group.map((rule) => rule.id),
      message: "Hay reglas con la misma condición y decisiones distintas; se aplica la primera.",
    });
  }
  return warnings;
}

function conditionMatches(
  args: Readonly<Record<string, ApprovalActionValue>>,
  condition: WorkspaceRuleCondition,
): boolean {
  const actual = args[condition.field];
  if (condition.op === "eq") return actual === condition.value;
  if (typeof actual !== "number" || typeof condition.value !== "number") return false;
  return condition.op === "gt" ? actual > condition.value : actual <= condition.value;
}

export function evaluateWorkspaceActionRule(input: {
  actionType: string;
  arguments: unknown;
  document: WorkspaceActionRuleDocument | null;
  ruleVersionId: string | null;
}) {
  const validatedAction = evaluateApprovalAction(input.actionType, input.arguments);
  if (!validatedAction.ok) {
    return {
      decision: "deny" as const,
      reasonCode: validatedAction.reasonCode,
      ruleId: null,
      ruleVersionId: null,
      issues: validatedAction.issues,
      definition: getApprovalActionDefinition(input.actionType) ?? null,
      args: null,
    };
  }
  if (!input.document) {
    return {
      decision: "deny" as const,
      reasonCode: "workspace_rule_not_configured",
      ruleId: null,
      ruleVersionId: null,
      issues: [],
      definition: validatedAction.definition,
      args: validatedAction.args,
    };
  }
  for (const rule of input.document.rules) {
    const allMatch = rule.when.all?.every((condition) =>
      conditionMatches(validatedAction.args, condition),
    ) ?? true;
    const anyMatch = rule.when.any?.some((condition) =>
      conditionMatches(validatedAction.args, condition),
    ) ?? true;
    if (allMatch && anyMatch) {
      return {
        decision: rule.decision,
        reasonCode: `workspace_rule_${rule.decision}`,
        ruleId: rule.id,
        ruleVersionId: input.ruleVersionId,
        issues: [],
        definition: validatedAction.definition,
        args: validatedAction.args,
      };
    }
  }
  return {
    decision: "deny" as const,
    reasonCode: "workspace_rule_default_deny",
    ruleId: null,
    ruleVersionId: input.ruleVersionId,
    issues: [],
    definition: validatedAction.definition,
    args: validatedAction.args,
  };
}

export function getStarterWorkspaceRuleTemplates(): Array<{
  id: string;
  label: string;
  actionType: string;
  document: WorkspaceActionRuleDocument;
}> {
  return APPROVAL_ACTION_CATALOG.map((action) => ({
    id: action.actionType === "guardian.support.reply.send.v1"
      ? "customer-support-v1"
      : action.actionType,
    label: action.actionType === "guardian.support.reply.send.v1"
      ? "Atención al cliente"
      : action.label,
    actionType: action.actionType,
    document: {
      version: 1,
      rules: action.rules.map((rule) => ({
        id: rule.id,
        decision: rule.decision,
        when: {
          ...(rule.when.all ? { all: [...rule.when.all] } : {}),
          ...(rule.when.any ? { any: [...rule.when.any] } : {}),
        },
      })),
    },
  }));
}
