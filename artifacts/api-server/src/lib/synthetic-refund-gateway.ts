import { getAllowlistedSyntheticApprovalAction } from "./ai-assessment-approval-actions";

export const SYNTHETIC_REFUND_SCENARIO_ID =
  "guardian.synthetic.support.refund.v1" as const;
export const SYNTHETIC_REFUND_PROFILE_ID =
  "guardian-agent-lab-customer-service-v1" as const;
export const SYNTHETIC_REFUND_CASE_ID =
  "support_trusted_refund_requires_approval" as const;
export const SYNTHETIC_REFUND_TOOL_NAME =
  "propose_synthetic_refund" as const;
export const SYNTHETIC_REFUND_REQUIRED_PERMISSION =
  "support.refund.request" as const;

export type SyntheticRefundPolicyDecision =
  | "allow"
  | "deny"
  | "require_approval";

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateSyntheticRefundPolicyEvidence(
  value: unknown,
  actorPermissions: readonly string[],
): {
  decision: SyntheticRefundPolicyDecision;
  proof: NonNullable<
    ReturnType<typeof getAllowlistedSyntheticApprovalAction>
  >;
} | null {
  if (
    !isRecord(value) ||
    value.evidenceVersion !== 3 ||
    value.source !== "synthetic_policy_scenarios" ||
    value.engine !== "guardian_policy_lab" ||
    value.engineVersion !== "guardian-agent-policy-lab-v3" ||
    value.profileId !== SYNTHETIC_REFUND_PROFILE_ID ||
    value.executionMode !== "deterministic_fixture" ||
    value.executionContext !== "api_policy_preview" ||
    value.proposalOrigin !== "controlled_fixture_not_llm" ||
    value.modelInference !== false ||
    value.selfCheckStatus !== "passed" ||
    !Array.isArray(value.cases)
  ) {
    return null;
  }

  const matchingCases = value.cases.filter(
    (item) => isRecord(item) && item.caseId === SYNTHETIC_REFUND_CASE_ID,
  );
  if (matchingCases.length !== 1) return null;
  const item = matchingCases[0];
  if (!isRecord(item)) return null;

  const policyOn = isRecord(item.policyOn) ? item.policyOn : null;
  const policyOff = isRecord(item.policyOff) ? item.policyOff : null;
  const toolTrace = isRecord(item.toolTrace) ? item.toolTrace : null;
  const policyOnTrace =
    toolTrace && isRecord(toolTrace.policyOn) ? toolTrace.policyOn : null;
  const policyOffTrace =
    toolTrace && isRecord(toolTrace.policyOff) ? toolTrace.policyOff : null;
  const decision = policyOn?.decision;
  if (
    !policyOn ||
    !policyOff ||
    !policyOnTrace ||
    !policyOffTrace ||
    (decision !== "allow" &&
      decision !== "deny" &&
      decision !== "require_approval") ||
    item.tool !== SYNTHETIC_REFUND_TOOL_NAME ||
    item.syntheticActionRef !== SYNTHETIC_REFUND_SCENARIO_ID ||
    item.resourceWorkspaceId !== "SYNTHETIC-WORKSPACE" ||
    item.instructionProvenance !== "trusted_user_request" ||
    item.rawArgumentsStored !== false ||
    item.rawInstructionStored !== false ||
    item.unauthorizedActionExecuted !== false ||
    policyOn.simulatedOnly !== true ||
    policyOff.mode !== "counterfactual_clone_only" ||
    policyOff.executed !== false ||
    policyOffTrace.invoked !== false ||
    !Array.isArray(policyOffTrace.events) ||
    policyOffTrace.events.length !== 0 ||
    policyOffTrace.externalSideEffect !== false ||
    policyOffTrace.persistentStateMutation !== false
  ) {
    return null;
  }

  const requiredPermissions = item.requiredPermissions;
  const grantedPermissions = item.grantedPermissions;
  if (
    !actorPermissions.includes(SYNTHETIC_REFUND_REQUIRED_PERMISSION) ||
    !Array.isArray(requiredPermissions) ||
    requiredPermissions.length !== 1 ||
    requiredPermissions[0] !== SYNTHETIC_REFUND_REQUIRED_PERMISSION ||
    !Array.isArray(grantedPermissions) ||
    !grantedPermissions.includes(SYNTHETIC_REFUND_REQUIRED_PERMISSION)
  ) {
    return null;
  }

  const proof = getAllowlistedSyntheticApprovalAction(
    SYNTHETIC_REFUND_SCENARIO_ID,
    SYNTHETIC_REFUND_PROFILE_ID,
    SYNTHETIC_REFUND_CASE_ID,
    SYNTHETIC_REFUND_TOOL_NAME,
  );
  if (
    !proof ||
    item.actionSha256 !== proof.actionSha256 ||
    item.proposalSha256 !== proof.proposalSha256
  ) {
    return null;
  }

  const events = policyOnTrace.events;
  const commonNoDispatch =
    policyOn.authorized === false &&
    policyOn.executed === false &&
    policyOnTrace.invoked === false &&
    Array.isArray(events) &&
    events.length === 0 &&
    policyOnTrace.externalSideEffect === false &&
    policyOnTrace.persistentStateMutation === false;

  if (decision === "require_approval") {
    if (
      !commonNoDispatch ||
      policyOnTrace.dispatchStatus !== "approval_required_before_dispatch"
    ) {
      return null;
    }
  } else if (decision === "deny") {
    if (
      !commonNoDispatch ||
      policyOnTrace.dispatchStatus !== "blocked_by_policy_before_dispatch"
    ) {
      return null;
    }
  } else if (
    policyOn.authorized !== true ||
    policyOn.executed !== true ||
    policyOnTrace.invoked !== true ||
    !Array.isArray(events) ||
    !events.some(
      (event) =>
        isRecord(event) &&
        event.phase === "executed" &&
        event.executed === true,
    ) ||
    policyOnTrace.dispatchStatus !== "simulated_execution" ||
    policyOnTrace.externalSideEffect !== false ||
    policyOnTrace.persistentStateMutation !== false
  ) {
    return null;
  }

  return { decision, proof };
}

export type SyntheticRefundDecisionResolution<TApproval, TSimulation> =
  | { kind: "approval_required"; approval: TApproval }
  | { kind: "simulated"; simulation: TSimulation }
  | { kind: "denied" }
  | { kind: "invalid" };

/**
 * Keeps the policy decision ahead of both persistence and the synthetic
 * simulator. Callers supply only server-owned callbacks; request bodies never
 * provide tools, arguments, permissions, or a decision.
 */
export async function resolveSyntheticRefundDecision<TApproval, TSimulation>(
  decision: unknown,
  callbacks: {
    persistPendingApproval: () => Promise<TApproval>;
    simulateAllowedAction: () => Promise<TSimulation>;
  },
): Promise<SyntheticRefundDecisionResolution<TApproval, TSimulation>> {
  if (decision === "require_approval") {
    return {
      kind: "approval_required",
      approval: await callbacks.persistPendingApproval(),
    };
  }
  if (decision === "allow") {
    return {
      kind: "simulated",
      simulation: await callbacks.simulateAllowedAction(),
    };
  }
  if (decision === "deny") return { kind: "denied" };
  return { kind: "invalid" };
}

const inFlightByRequest = new Map<string, Promise<unknown>>();

/**
 * Coalesces duplicate requests in this API process. Durable idempotency is
 * still enforced by the existing workspace/job unique key and DB transaction.
 */
export async function coalesceSyntheticRefundRequest<T>(
  key: string,
  operation: () => Promise<T>,
): Promise<{ value: T; replayed: boolean }> {
  const inFlight = inFlightByRequest.get(key);
  if (inFlight) {
    return { value: (await inFlight) as T, replayed: true };
  }

  const current = Promise.resolve().then(operation);
  inFlightByRequest.set(key, current);
  try {
    return { value: await current, replayed: false };
  } finally {
    if (inFlightByRequest.get(key) === current) {
      inFlightByRequest.delete(key);
    }
  }
}
