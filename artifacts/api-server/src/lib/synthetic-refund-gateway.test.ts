import assert from "node:assert/strict";
import test from "node:test";
import { getAllowlistedSyntheticApprovalAction } from "./ai-assessment-approval-actions";
import {
  coalesceSyntheticRefundRequest,
  resolveSyntheticRefundDecision,
  SYNTHETIC_REFUND_CASE_ID,
  SYNTHETIC_REFUND_PROFILE_ID,
  SYNTHETIC_REFUND_REQUIRED_PERMISSION,
  SYNTHETIC_REFUND_SCENARIO_ID,
  SYNTHETIC_REFUND_TOOL_NAME,
  validateSyntheticRefundPolicyEvidence,
} from "./synthetic-refund-gateway";

function refundEvidence(decision: "allow" | "deny" | "require_approval") {
  const proof = getAllowlistedSyntheticApprovalAction(
    SYNTHETIC_REFUND_SCENARIO_ID,
    SYNTHETIC_REFUND_PROFILE_ID,
    SYNTHETIC_REFUND_CASE_ID,
    SYNTHETIC_REFUND_TOOL_NAME,
  );
  assert.ok(proof);
  const approved = decision === "allow";
  const dispatched = decision === "allow";
  return {
    evidenceVersion: 3,
    source: "synthetic_policy_scenarios",
    engine: "guardian_policy_lab",
    engineVersion: "guardian-agent-policy-lab-v3",
    profileId: SYNTHETIC_REFUND_PROFILE_ID,
    executionMode: "deterministic_fixture",
    executionContext: "api_policy_preview",
    proposalOrigin: "controlled_fixture_not_llm",
    modelInference: false,
    selfCheckStatus: "passed",
    cases: [
      {
        caseId: SYNTHETIC_REFUND_CASE_ID,
        tool: SYNTHETIC_REFUND_TOOL_NAME,
        syntheticActionRef: SYNTHETIC_REFUND_SCENARIO_ID,
        resourceWorkspaceId: "SYNTHETIC-WORKSPACE",
        instructionProvenance: "trusted_user_request",
        rawArgumentsStored: false,
        rawInstructionStored: false,
        unauthorizedActionExecuted: false,
        requiredPermissions: [SYNTHETIC_REFUND_REQUIRED_PERMISSION],
        grantedPermissions: [SYNTHETIC_REFUND_REQUIRED_PERMISSION],
        actionSha256: proof.actionSha256,
        proposalSha256: proof.proposalSha256,
        policyOn: {
          decision,
          authorized: approved,
          executed: dispatched,
          simulatedOnly: true,
        },
        policyOff: {
          mode: "counterfactual_clone_only",
          executed: false,
        },
        toolTrace: {
          policyOn: {
            invoked: dispatched,
            dispatchStatus: approved
              ? "simulated_execution"
              : decision === "require_approval"
                ? "approval_required_before_dispatch"
                : "blocked_by_policy_before_dispatch",
            events: dispatched
              ? [{ phase: "executed", executed: true }]
              : [],
            externalSideEffect: false,
            persistentStateMutation: false,
          },
          policyOff: {
            invoked: false,
            events: [],
            externalSideEffect: false,
            persistentStateMutation: false,
          },
        },
      },
    ],
  };
}

test("only the exact synthetic refund policy evidence is accepted", () => {
  const evidence = refundEvidence("require_approval");
  assert.equal(
    validateSyntheticRefundPolicyEvidence(
      evidence,
      [SYNTHETIC_REFUND_REQUIRED_PERMISSION],
    )?.decision,
    "require_approval",
  );

  const wrongScope = JSON.parse(JSON.stringify(evidence)) as {
    cases: Array<Record<string, unknown>>;
  };
  wrongScope.cases[0]!.resourceWorkspaceId = "another-tenant";
  assert.equal(
    validateSyntheticRefundPolicyEvidence(
      wrongScope,
      [SYNTHETIC_REFUND_REQUIRED_PERMISSION],
    ),
    null,
  );

  const wrongAction = JSON.parse(JSON.stringify(evidence)) as {
    cases: Array<Record<string, unknown>>;
  };
  wrongAction.cases[0]!.actionSha256 = "0".repeat(64);
  assert.equal(
    validateSyntheticRefundPolicyEvidence(
      wrongAction,
      [SYNTHETIC_REFUND_REQUIRED_PERMISSION],
    ),
    null,
  );

  const policyOffExecuted = JSON.parse(JSON.stringify(evidence)) as {
    cases: Array<Record<string, unknown>>;
  };
  (
    policyOffExecuted.cases[0]!.policyOff as Record<string, unknown>
  ).executed = true;
  assert.equal(
    validateSyntheticRefundPolicyEvidence(
      policyOffExecuted,
      [SYNTHETIC_REFUND_REQUIRED_PERMISSION],
    ),
    null,
  );

  assert.equal(
    validateSyntheticRefundPolicyEvidence(evidence, []),
    null,
  );
});

test("ALLOW reaches only the synthetic simulator after the decision", async () => {
  const calls: string[] = [];
  const result = await resolveSyntheticRefundDecision("allow", {
    persistPendingApproval: async () => {
      calls.push("persist");
      return "pending";
    },
    simulateAllowedAction: async () => {
      calls.push("simulate");
      return "clone-result";
    },
  });
  assert.deepEqual(result, { kind: "simulated", simulation: "clone-result" });
  assert.deepEqual(calls, ["simulate"]);
});

test("REQUIRE_APPROVAL persists pending and never calls the simulator", async () => {
  const calls: string[] = [];
  const result = await resolveSyntheticRefundDecision("require_approval", {
    persistPendingApproval: async () => {
      calls.push("persist");
      return "pending-record";
    },
    simulateAllowedAction: async () => {
      calls.push("simulate");
      return "unexpected";
    },
  });
  assert.deepEqual(result, {
    kind: "approval_required",
    approval: "pending-record",
  });
  assert.deepEqual(calls, ["persist"]);
});

test("DENY and malformed policy results invoke neither persistence nor simulation", async () => {
  for (const decision of ["deny", "unexpected", null]) {
    const calls: string[] = [];
    const result = await resolveSyntheticRefundDecision(decision, {
      persistPendingApproval: async () => {
        calls.push("persist");
        return "unexpected";
      },
      simulateAllowedAction: async () => {
        calls.push("simulate");
        return "unexpected";
      },
    });
    assert.deepEqual(
      result,
      decision === "deny" ? { kind: "denied" } : { kind: "invalid" },
    );
    assert.deepEqual(calls, []);
  }
});

test("concurrent same-key requests share one operation and later calls can recover", async () => {
  let executions = 0;
  let release!: (value: string) => void;
  const operation = () => {
    executions += 1;
    return new Promise<string>((resolve) => {
      release = resolve;
    });
  };

  const first = coalesceSyntheticRefundRequest("test-workspace:user:key", operation);
  const second = coalesceSyntheticRefundRequest("test-workspace:user:key", operation);
  await Promise.resolve();
  release("same-result");
  const [created, replayed] = await Promise.all([first, second]);
  assert.deepEqual(created, { value: "same-result", replayed: false });
  assert.deepEqual(replayed, { value: "same-result", replayed: true });
  assert.equal(executions, 1);

  const afterCompletion = await coalesceSyntheticRefundRequest(
    "test-workspace:user:key",
    async () => {
      executions += 1;
      return "recovered-result";
    },
  );
  assert.deepEqual(afterCompletion, {
    value: "recovered-result",
    replayed: false,
  });
  assert.equal(executions, 2);
});
