import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createWorkspaceRuleActionEvidence,
  createGenericActionEvidence,
  genericActionDisplay,
  genericActionProposalSha256,
  hashGenericActionArguments,
  verifyGenericActionEvidence,
} from "./generic-action-evidence";

const args = {
  to: "qa@example.test",
  template_id: "guardian-demo-email-v1",
};
const workspaceId = "11111111-1111-4111-8111-111111111111";
const requestedByUserId = "user-synthetic-agent";
const actionType = "guardian.email.send.external.v1";
const evaluatedRuleId =
  "external-email.sandbox.requires-independent-approval.v1";

function evidence() {
  const display = genericActionDisplay(actionType, args);
  assert.ok(display);
  return createGenericActionEvidence({
    workspaceId,
    requestedByUserId,
    actionType,
    args,
    ruleId: evaluatedRuleId,
    ...display,
  });
}

test("generic action evidence binds the exact action, arguments, workspace and requester", () => {
  const value = evidence();
  assert.ok(value);
  assert.equal(value.actionType, actionType);
  assert.equal(value.workspaceId, workspaceId);
  assert.equal(value.synthetic, true);
  assert.equal(value.modelInference, false);
  assert.equal(
    verifyGenericActionEvidence(value, {
      workspaceId,
      requestedByUserId,
      actionType,
      actionSha256: value.actionSha256,
      proposalSha256: value.proposalSha256,
      profileId: value.profileId,
    })?.evidenceSha256,
    value.evidenceSha256,
  );
});

test("an unconfigured synthetic refund can use catalog REQUIRE_APPROVAL evidence with the real agent identity", () => {
  const refundActionType = "guardian.synthetic.support.refund.v1";
  const refundArgs = {
    ticket_id: "TICKET-SYNTH-42",
    amount_cents: 2_500,
  };
  const refundDisplay = genericActionDisplay(refundActionType, refundArgs);
  assert.ok(refundDisplay);
  const value = createGenericActionEvidence({
    workspaceId,
    requestedByUserId,
    actionType: refundActionType,
    args: refundArgs,
    ruleId: "refund.fixture.requires-independent-approval.v1",
    agentId: "11111111-1111-4111-8111-111111111111",
    summary: refundDisplay.summary,
    messagePreview: refundDisplay.messagePreview,
  });
  assert.ok(value);
  assert.equal(value.evidenceVersion, 1);
  assert.equal(value.engineVersion, "guardian-action-catalog-v1");
  assert.equal(value.agentId, "11111111-1111-4111-8111-111111111111");
  assert.equal(
    verifyGenericActionEvidence(value, {
      workspaceId,
      requestedByUserId,
      actionType: refundActionType,
      actionSha256: value.actionSha256,
      proposalSha256: value.proposalSha256,
      profileId: "guardian-agent-lab-customer-service-v1",
      agentId: "11111111-1111-4111-8111-111111111111",
    })?.evidenceSha256,
    value.evidenceSha256,
  );
  assert.equal(
    verifyGenericActionEvidence(value, {
      workspaceId,
      requestedByUserId,
      actionType: refundActionType,
      actionSha256: value.actionSha256,
      proposalSha256: value.proposalSha256,
      profileId: "guardian-agent-lab-customer-service-v1",
      agentId: "22222222-2222-4222-8222-222222222222",
    }),
    null,
    "refund evidence cannot be replayed as a different agent",
  );
});

test("generic evidence rejects changed arguments and mismatched action or workspace", () => {
  const value = evidence();
  assert.ok(value);
  const expected = {
    workspaceId,
    requestedByUserId,
    actionType,
    actionSha256: value.actionSha256,
    proposalSha256: value.proposalSha256,
    profileId: value.profileId,
  };
  assert.equal(
    verifyGenericActionEvidence(
      { ...value, arguments: { ...value.arguments, to: "other@example.test" } },
      expected,
    ),
    null,
  );
  assert.equal(
    verifyGenericActionEvidence(value, { ...expected, actionType: "guardian.support.reply.send.v1" }),
    null,
  );
  assert.equal(
    verifyGenericActionEvidence(value, { ...expected, workspaceId: "22222222-2222-4222-8222-222222222222" }),
    null,
  );
});

test("generic evidence rejects engine versions crossed in either evidence version direction", () => {
  const versionOne = evidence();
  assert.ok(versionOne);
  const expectedV1 = {
    workspaceId,
    requestedByUserId,
    actionType,
    actionSha256: versionOne.actionSha256,
    proposalSha256: versionOne.proposalSha256,
    profileId: versionOne.profileId,
  };
  assert.equal(
    verifyGenericActionEvidence(
      {
        ...versionOne,
        engineVersion: "guardian-workspace-rules-v2",
      },
      expectedV1,
    ),
    null,
    "evidence v1 cannot claim the v2 engine",
  );

  const ruleDocument = {
    version: 1 as const,
    rules: [{
      id: "require-independent-approval",
      decision: "require_approval" as const,
      when: {},
    }],
  };
  const display = genericActionDisplay(actionType, args);
  assert.ok(display);
  const versionTwo = createWorkspaceRuleActionEvidence({
    workspaceId,
    requestedByUserId,
    actionType,
    args,
    ruleId: "require-independent-approval",
    ruleVersionId: "11111111-1111-4111-8111-111111111111",
    ruleDocument,
    ...display,
    agentId: "agent-synthetic-evidence-v2",
  });
  assert.ok(versionTwo);
  assert.equal(versionTwo.evidenceVersion, 2);
  assert.equal(
    verifyGenericActionEvidence(
      {
        ...versionTwo,
        engineVersion: "guardian-action-catalog-v1",
      },
      {
        ...expectedV1,
        actionSha256: versionTwo.actionSha256,
        proposalSha256: versionTwo.proposalSha256,
      },
    ),
    null,
    "evidence v2 cannot claim the v1 engine",
  );
});

test("workspace evidence permits an allow decision only when escalated to human approval", () => {
  const allowRule = {
    version: 1 as const,
    rules: [{
      id: "explicit-allow-rule",
      decision: "allow" as const,
      when: {},
    }],
  };
  const display = genericActionDisplay(actionType, args);
  assert.ok(display);
  const escalated = createWorkspaceRuleActionEvidence({
    workspaceId,
    requestedByUserId,
    actionType,
    args,
    ruleId: "explicit-allow-rule",
    ruleVersionId: "11111111-1111-4111-8111-111111111111",
    ruleDocument: allowRule,
    allowEscalation: true,
    ...display,
    agentId: "agent-synthetic-escalation",
  });
  assert.ok(escalated);
  assert.equal(escalated.decision, "require_approval");
  assert.equal(
    escalated.decisionEscalation,
    "rule_allow_escalated_to_approval",
  );
  assert.equal(
    verifyGenericActionEvidence(escalated, {
      workspaceId,
      requestedByUserId,
      actionType,
      actionSha256: escalated.actionSha256,
      proposalSha256: escalated.proposalSha256,
      profileId: escalated.profileId,
    })?.evidenceSha256,
    escalated.evidenceSha256,
  );
  assert.equal(
    createWorkspaceRuleActionEvidence({
      workspaceId,
      requestedByUserId,
      actionType,
      args,
      ruleId: "explicit-allow-rule",
      ruleVersionId: "11111111-1111-4111-8111-111111111111",
      ruleDocument: allowRule,
      ...display,
      agentId: "agent-synthetic-escalation",
    }),
    null,
    "an allow rule is not presented as a pending approval without escalation",
  );
});

test("workspace evidence v2 binds trusted rule-evaluation context for volume decisions", () => {
  const volumeDocument = {
    version: 1 as const,
    rules: [{
      id: "volume-review",
      decision: "require_approval" as const,
      when: {
        all: [{
          field: "context.action_count",
          op: "gt" as const,
          value: 0,
          windowSeconds: 60,
        }],
      },
    }],
  };
  const display = genericActionDisplay(actionType, args);
  assert.ok(display);
  const evidence = createWorkspaceRuleActionEvidence({
    workspaceId,
    requestedByUserId,
    actionType,
    args,
    ruleId: "volume-review",
    ruleVersionId: "11111111-1111-4111-8111-111111111111",
    ruleDocument: volumeDocument,
    ruleEvaluationContext: {
      dataSensitivity: "normal",
      environment: "test",
      actionCountsByWindow: { 60: 1 },
    },
    ...display,
    agentId: "agent-synthetic-volume",
  });
  assert.ok(evidence);
  assert.equal(evidence.ruleEvaluationContext?.actionCountsByWindow[60], 1);
  assert.equal(
    verifyGenericActionEvidence(evidence, {
      workspaceId,
      requestedByUserId,
      actionType,
      actionSha256: evidence.actionSha256,
      proposalSha256: evidence.proposalSha256,
      profileId: evidence.profileId,
    })?.evidenceSha256,
    evidence.evidenceSha256,
  );
  assert.equal(
    verifyGenericActionEvidence({
      ...evidence,
      ruleEvaluationContext: {
        ...evidence.ruleEvaluationContext!,
        actionCountsByWindow: { 60: 0 },
      },
    }, {
      workspaceId,
      requestedByUserId,
      actionType,
      actionSha256: evidence.actionSha256,
      proposalSha256: evidence.proposalSha256,
      profileId: evidence.profileId,
    }),
    null,
  );
});

test("workspace evidence v2 binds approval-required actions across all eight service profiles", () => {
  const fixtures = [
    {
      actionType: "guardian.email.send.external_sensitive.v1",
      profileId: "guardian-agent-lab-email-v1",
      args: {
        to: "qa@example.test",
        template_id: "guardian-sensitive-email-v1",
        has_attachments: true,
        contains_customer_data: true,
      },
    },
    {
      actionType: "guardian.support.customer_account.close.v1",
      profileId: "guardian-agent-lab-customer-service-v1",
      args: {
        account_id: "LAB-ACCOUNT-42",
        operation: "close",
        case_id: "TICKET-SYNTH-42",
      },
    },
    {
      actionType: "guardian.finance.vendor_payment.known.v1",
      profileId: "guardian-agent-lab-finance-v1",
      args: {
        vendor_id: "VENDOR-SYNTH-42",
        amount_cents: 2500,
        invoice_id: "INVOICE-SYNTH-42",
      },
    },
    {
      actionType: "guardian.data.customer.export.v1",
      profileId: "guardian-agent-lab-database-v1",
      args: { dataset_id: "DATASET-SYNTH-42", record_limit: 25 },
    },
    {
      actionType: "guardian.code.pull_request.merge_main.v1",
      profileId: "guardian-agent-lab-programming-v1",
      args: {
        repository_id: "REPO-SYNTH-42",
        pull_request_id: "PR-SYNTH-42",
        target_branch: "main",
      },
    },
    {
      actionType: "guardian.web.personal_data.submit.v1",
      profileId: "guardian-agent-lab-browser-v1",
      args: { form_id: "FORM-SYNTH-42", host: "example.test", data_class: "personal" },
    },
    {
      actionType: "guardian.cloud.resource.create.v1",
      profileId: "guardian-agent-lab-infrastructure-v1",
      args: {
        resource_type: "compute",
        resource_id: "CLOUD-SYNTH-42",
        estimated_cost_cents: 2500,
      },
    },
    {
      actionType: "guardian.multiagent.delegate_higher_scope.v1",
      profileId: "guardian-agent-lab-multiagent-v1",
      args: { target_agent_id: "AGENT-SYNTH-42", requested_scope: "admin" },
    },
  ] as const;
  for (const fixture of fixtures) {
    const ruleDocument = {
      version: 1 as const,
      rules: [{ id: "service-approval", decision: "require_approval" as const, when: {} }],
    };
    const display = genericActionDisplay(fixture.actionType, fixture.args);
    assert.ok(display, `${fixture.actionType} has a synthetic display`);
    const value = createWorkspaceRuleActionEvidence({
      workspaceId,
      requestedByUserId,
      actionType: fixture.actionType,
      args: fixture.args,
      ruleId: "service-approval",
      ruleVersionId: "11111111-1111-4111-8111-111111111111",
      ruleDocument,
      agentId: display.agentId,
      summary: display.summary,
      messagePreview: display.messagePreview,
    });
    assert.ok(value, `${fixture.actionType} produces v2 approval evidence`);
    assert.equal(value.evidenceVersion, 2);
    assert.equal(value.profileId, fixture.profileId);
    assert.ok(verifyGenericActionEvidence(value, {
      workspaceId,
      requestedByUserId,
      actionType: fixture.actionType,
      actionSha256: value.actionSha256,
      proposalSha256: value.proposalSha256,
      profileId: fixture.profileId,
    }), `${fixture.actionType} evidence verifies`);
  }
});

test("generic action and argument hashes use stable canonical input", () => {
  const first = hashGenericActionArguments(actionType, args);
  const reordered = hashGenericActionArguments(actionType, {
    template_id: "guardian-demo-email-v1",
    to: "qa@example.test",
  });
  assert.deepEqual(reordered, first);
  const proposalSha256 = genericActionProposalSha256({
    workspaceId,
    requestedByUserId,
    actionType,
    actionSha256: first.actionSha256,
    ruleId: evaluatedRuleId,
  });
  assert.match(proposalSha256, /^[a-f0-9]{64}$/);
});
