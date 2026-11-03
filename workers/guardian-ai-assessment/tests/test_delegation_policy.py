import unittest

from guardian_ai_assessment.tool_adapter import evaluate_synthetic_action_policy
from guardian_ai_assessment.qwen_policy_lab import _nearest_rank_percentile


PARENT_PERMISSIONS = {"agent.delegate.read", "database.read.scoped"}
COORDINATOR = "guardian-multiagent-coordinator-v1"
SPECIALIST = "guardian-multiagent-specialist-v1"


def delegation_action(context):
    return {
        "resourceType": "task",
        "resourceId": "TASK-SYNTH-READ-001",
        "resourceWorkspaceId": "SYNTHETIC-WORKSPACE",
        "sensitivity": "internal",
        "operation": "delegate.read_only",
        "instructionProvenance": "trusted_user_request",
        "requiredPermissions": ["agent.delegate.read"],
        "requestedPermissions": ["database.read.scoped"],
        "delegated": True,
        "approvalRequired": False,
        "delegationContext": context,
    }


def valid_context():
    return {
        "tenantId": "SYNTHETIC-WORKSPACE",
        "parentAgentId": COORDINATOR,
        "childAgentId": SPECIALIST,
        "agentChain": [COORDINATOR],
        "expiresAtEpoch": 4_000_000_000,
        "nowEpoch": 1_700_000_000,
        "revokedAgentIds": [],
    }


class DelegationPolicyTests(unittest.TestCase):
    def test_latency_percentiles_use_nearest_rank_without_raw_values(self):
        values = [20, 10, 30, 40]
        self.assertEqual(_nearest_rank_percentile(values, 0.5), 20)
        self.assertEqual(_nearest_rank_percentile(values, 0.95), 40)
        self.assertEqual(_nearest_rank_percentile([], 0.95), 0)

    def test_valid_delegation_preserves_parent_scope(self):
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", delegation_action(valid_context()), PARENT_PERMISSIONS
        )
        self.assertEqual((decision, reason), ("allow", "synthetic_policy_allowlist"))

    def test_cycle_to_any_ancestor_is_denied(self):
        context = valid_context()
        context["agentChain"] = [COORDINATOR, SPECIALIST]
        context["parentAgentId"] = SPECIALIST
        context["childAgentId"] = COORDINATOR
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", delegation_action(context), PARENT_PERMISSIONS
        )
        self.assertEqual((decision, reason), ("deny", "delegation_cycle_detected"))

    def test_expired_delegation_is_denied(self):
        context = valid_context()
        context["expiresAtEpoch"] = 1_600_000_000
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", delegation_action(context), PARENT_PERMISSIONS
        )
        self.assertEqual((decision, reason), ("deny", "delegation_expired"))

    def test_revoked_child_is_denied(self):
        context = valid_context()
        context["revokedAgentIds"] = [SPECIALIST]
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", delegation_action(context), PARENT_PERMISSIONS
        )
        self.assertEqual((decision, reason), ("deny", "delegated_agent_revoked"))

    def test_cross_tenant_delegation_is_denied(self):
        context = valid_context()
        context["tenantId"] = "SYNTHETIC-OTHER-WORKSPACE"
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", delegation_action(context), PARENT_PERMISSIONS
        )
        self.assertEqual((decision, reason), ("deny", "delegation_tenant_mismatch"))

    def test_missing_or_mutated_chain_fails_closed(self):
        context = valid_context()
        context["unexpected"] = "ignored"
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", delegation_action(context), PARENT_PERMISSIONS
        )
        self.assertEqual(
            (decision, reason), ("deny", "delegation_context_missing_or_invalid")
        )

    def test_permission_elevation_is_denied_before_delegation(self):
        action = delegation_action(valid_context())
        action["requestedPermissions"] = ["database.read.scoped", "secret.read"]
        decision, reason = evaluate_synthetic_action_policy(
            "multiagent", action, PARENT_PERMISSIONS
        )
        self.assertEqual(
            (decision, reason), ("deny", "delegated_permissions_exceed_parent")
        )


if __name__ == "__main__":
    unittest.main()
