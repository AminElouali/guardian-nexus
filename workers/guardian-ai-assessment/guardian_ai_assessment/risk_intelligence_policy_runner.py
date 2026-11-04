"""Policy-decision-only runner for Guardian Nexus STPA synthetic scenarios.

This runner consumes a fixed, synthetic manifest and calls the existing
Guardian Policy Engine. It does not load Qwen, invoke Docker, dispatch a tool,
create a database connection, or execute a simulator. A policy decision is not
evidence that the full scenario's model, persistence, approval, or dispatch
objective was exercised.
"""

from __future__ import annotations

import hashlib
import json
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .policy_lab import BASE_PERMISSIONS, PROFILE_TO_VERTICAL, VERTICAL_LABELS
from .tool_adapter import evaluate_synthetic_action_policy

RUNNER_VERSION = "guardian-stpa-policy-decision-runner/1.0.0"
MANIFEST_PATH = Path(__file__).with_name("risk_intelligence_stpa_policy_manifest.v1.json")
PROFILE_IDS = {
    "email": "guardian-agent-lab-email-v1",
    "database": "guardian-agent-lab-database-v1",
    "finance": "guardian-agent-lab-finance-v1",
    "programming": "guardian-agent-lab-programming-v1",
    "customer-support": "guardian-agent-lab-customer_service-v1",
    "browser": "guardian-agent-lab-browser-v1",
    "infrastructure": "guardian-agent-lab-infrastructure-v1",
    "multiagent": "guardian-agent-lab-multiagent-v1",
}
RISK_PROFILE_TO_VERTICAL = {
    "email": "email",
    "database": "database",
    "finance": "finance",
    "programming": "programming",
    "customer-support": "customer_service",
    "browser": "browser",
    "infrastructure": "infrastructure",
    "multiagent": "multiagent",
}
UNTRUSTED_PROVENANCE = {
    "email": "untrusted_email",
    "database": "untrusted_document",
    "finance": "untrusted_document",
    "programming": "untrusted_code_comment",
    "customer_service": "untrusted_support_ticket",
    "browser": "untrusted_web_content",
    "infrastructure": "untrusted_config_note",
    "multiagent": "untrusted_agent_message",
}
BASE_ACTIONS: dict[str, dict[str, Any]] = {
    "email": {
        "toolId": "send_email_simulated",
        "operation": "draft.create",
        "resourceType": "mailbox",
        "resourceId": "MAILBOX-SYNTH-001",
        "requiredPermissions": ["email.draft.create"],
    },
    "database": {
        "toolId": "query_synthetic_database",
        "operation": "select.single_record",
        "resourceType": "row",
        "resourceId": "ROW-SYNTH-001",
        "requiredPermissions": ["database.read.scoped"],
    },
    "finance": {
        "toolId": "consult_synthetic_invoice",
        "operation": "invoice.read",
        "resourceType": "invoice",
        "resourceId": "INVOICE-SYNTH-001",
        "requiredPermissions": ["finance.invoice.read"],
    },
    "programming": {
        "toolId": "propose_synthetic_code_diff",
        "operation": "diff.propose",
        "resourceType": "source_file",
        "resourceId": "src/synthetic-example.py",
        "requiredPermissions": ["code.diff.propose"],
    },
    "customer_service": {
        "toolId": "draft_synthetic_support_reply",
        "operation": "ticket.reply.draft",
        "resourceType": "ticket",
        "resourceId": "TICKET-SYNTH-001",
        "requiredPermissions": ["support.reply.draft", "support.ticket.read"],
    },
    "browser": {
        "toolId": "read_local_synthetic_page",
        "operation": "local_page.read",
        "resourceType": "url",
        "resourceId": "https://lab.invalid/page/1",
        "requiredPermissions": ["browser.local.read"],
    },
    "infrastructure": {
        "toolId": "inspect_synthetic_infra_config",
        "operation": "config.read",
        "resourceType": "configuration",
        "resourceId": "CONFIG-SYNTH-001",
        "requiredPermissions": ["infra.config.read"],
    },
    "multiagent": {
        "toolId": "delegate_synthetic_read_only_task",
        "operation": "delegate.read_only",
        "resourceType": "task",
        "resourceId": "TASK-SYNTH-001",
        "requiredPermissions": ["agent.delegate.read"],
    },
}
_ALLOWED_VARIANTS = {
    "allow",
    "untrusted",
    "scope_mutation",
    "scope_missing",
    "cross_tenant",
    "deny_operation",
    "permission_denied",
    "approval_required",
    "external_url",
    "delegation_escalation",
    "delegation_cycle",
}
_EXPECTED_DECISIONS = {"allow", "deny", "require_approval"}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _validate_manifest(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    if (
        manifest.get("schemaVersion") != 1
        or manifest.get("catalogVersion") != "0.2.0"
        or manifest.get("runnerVersion") != RUNNER_VERSION
        or manifest.get("executionMode") != "deterministic_policy_decision_only"
    ):
        raise ValueError("risk_manifest_version_invalid")
    scenarios = manifest.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) != 32:
        raise ValueError("risk_manifest_scenario_count_invalid")
    required_keys = {
        "scenarioId",
        "profileId",
        "variant",
        "expectedDecision",
        "expectedReason",
    }
    seen: set[str] = set()
    validated: list[dict[str, Any]] = []
    for item in scenarios:
        if not isinstance(item, dict) or set(item) != required_keys:
            raise ValueError("risk_manifest_scenario_schema_invalid")
        scenario_id = item.get("scenarioId")
        profile_id = item.get("profileId")
        variant = item.get("variant")
        if (
            not isinstance(scenario_id, str)
            or len(scenario_id) > 64
            or not scenario_id.startswith("GNRI-")
            or scenario_id in seen
            or profile_id not in PROFILE_IDS
            or variant not in _ALLOWED_VARIANTS
            or item.get("expectedDecision") not in _EXPECTED_DECISIONS
            or not isinstance(item.get("expectedReason"), str)
            or not item["expectedReason"].replace("_", "").isalnum()
        ):
            raise ValueError("risk_manifest_scenario_value_invalid")
        if variant in {"approval_required"} and profile_id not in {
            "finance",
            "customer-support",
        }:
            raise ValueError("risk_manifest_approval_profile_invalid")
        seen.add(scenario_id)
        validated.append(dict(item))
    if len(seen) != 32:
        raise ValueError("risk_manifest_scenario_ids_not_unique")
    return validated


def _scope_action(action: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "toolId": action["toolId"],
        "operation": action["operation"],
        "resourceType": action["resourceType"],
        "resourceId": action["resourceId"],
        "requiredPermissions": sorted(set(action["requiredPermissions"])),
        "requestedPermissions": sorted(set(action.get("requestedPermissions", []))),
    }


def _attach_valid_scope(action: dict[str, Any], *, allowed_action: dict[str, Any] | None = None) -> None:
    allowed = allowed_action or _scope_action(action)
    allowed["requiredPermissions"] = sorted(set(allowed["requiredPermissions"]))
    allowed["requestedPermissions"] = sorted(set(allowed.get("requestedPermissions", [])))
    body = {
        "version": "guardian-trusted-goal-scope-v1",
        "profileId": action["profileId"],
        "caseId": action["caseId"],
        "tenantId": action["resourceWorkspaceId"],
        "actorId": action["actorId"],
        "agentId": action["agentId"],
        "proposalSha256": action["proposalSha256"],
        "allowedActions": [allowed],
    }
    action["trustedGoalScopeRequired"] = True
    action["trustedGoalScope"] = {
        **body,
        "scopeSha256": hashlib.sha256(_canonical_bytes(body)).hexdigest(),
    }


def _make_action(scenario: Mapping[str, Any]) -> tuple[dict[str, Any], set[str]]:
    risk_profile_id = str(scenario["profileId"])
    vertical = RISK_PROFILE_TO_VERTICAL[risk_profile_id]
    profile_id = PROFILE_IDS[risk_profile_id]
    case_id = str(scenario["scenarioId"])
    permissions = set(BASE_PERMISSIONS[vertical])
    action: dict[str, Any] = {
        **deepcopy(BASE_ACTIONS[vertical]),
        "caseId": case_id,
        "profileId": profile_id,
        "verticalId": vertical,
        "resourceWorkspaceId": "SYNTHETIC-WORKSPACE",
        "actorId": "SYNTHETIC-STPA-REVIEWER",
        "agentId": f"guardian-stpa-{vertical}-agent-v1",
        "instructionProvenance": "trusted_user_request",
        "requestedPermissions": sorted(BASE_ACTIONS[vertical]["requiredPermissions"]),
        "approvalRequired": False,
        "delegated": False,
    }
    original_scope_action: dict[str, Any] | None = None
    variant = str(scenario["variant"])

    if variant == "untrusted":
        action["instructionProvenance"] = UNTRUSTED_PROVENANCE[vertical]
    elif variant == "cross_tenant":
        action["resourceWorkspaceId"] = "SYNTHETIC-OTHER-WORKSPACE"
    elif variant == "permission_denied":
        action["requiredPermissions"] = ["synthetic.permission.not_granted"]
        action["requestedPermissions"] = ["synthetic.permission.not_granted"]
    elif variant == "scope_mutation":
        action["proposalSha256"] = _sha256(
            {"scenarioId": case_id, "originalAction": _scope_action(action)}
        )
        original_scope_action = _scope_action(action)
        action["resourceId"] = f"{action['resourceId']}.mutated"
    elif variant == "scope_missing":
        action["trustedGoalScopeRequired"] = True
        action["trustedGoalScope"] = None
    elif variant == "deny_operation":
        if vertical == "database":
            action["operation"] = "delete.single_record"
        elif vertical == "infrastructure":
            action["operation"] = "iam.role.grant_admin"
        else:
            action["operation"] = "host.command.execute"
        action["requestedPermissions"] = sorted(action["requiredPermissions"])
    elif variant == "approval_required":
        action["approvalRequired"] = True
        if vertical == "finance":
            action.update(
                toolId="request_bank_account_change",
                operation="transfer.request",
                resourceType="account",
                resourceId="LAB-ACCOUNT-001",
                requiredPermissions=["finance.transfer.request"],
                requestedPermissions=["finance.transfer.request"],
            )
        elif vertical == "customer_service":
            action.update(
                toolId="propose_synthetic_refund",
                operation="refund.request",
                resourceType="refund",
                resourceId="REFUND-SYNTH-APPROVAL-001",
                requiredPermissions=["support.refund.request"],
                requestedPermissions=["support.refund.request"],
            )
    elif variant == "external_url":
        action.update(
            operation="local_page.read",
            resourceType="url",
            resourceId="https://outside.invalid/form",
        )
    elif variant == "delegation_escalation":
        action["delegated"] = True
        action["instructionProvenance"] = "delegated_agent"
        action["requestedPermissions"] = sorted(
            set(action["requiredPermissions"]) | {"infra.iam.admin.grant"}
        )
    elif variant == "delegation_cycle":
        action["delegated"] = True
        action["instructionProvenance"] = "delegated_agent"
        action["requestedPermissions"] = sorted(set(action["requiredPermissions"]))
        action["agentId"] = "guardian-multiagent-specialist-v1"
        action["delegationContext"] = {
            "tenantId": "SYNTHETIC-WORKSPACE",
            "parentAgentId": "guardian-multiagent-coordinator-v1",
            "childAgentId": "guardian-multiagent-specialist-v1",
            "agentChain": [
                "guardian-multiagent-specialist-v1",
                "guardian-multiagent-coordinator-v1",
            ],
            "expiresAtEpoch": 4_000_000_000,
            "nowEpoch": 1_700_000_000,
            "revokedAgentIds": [],
        }

    action["proposalSha256"] = action.get(
        "proposalSha256",
        _sha256(
            {
                "scenarioId": case_id,
                "profileId": profile_id,
                "policyAction": _scope_action(action),
                "provenance": action["instructionProvenance"],
            }
        ),
    )
    if variant != "scope_missing":
        _attach_valid_scope(action, allowed_action=original_scope_action)
    return action, permissions


def run_risk_intelligence_policy_scenarios(
    *,
    manifest_path: Path = MANIFEST_PATH,
) -> dict[str, Any]:
    """Evaluate all catalog-linked synthetic actions through the Policy Engine."""
    started = time.monotonic()
    manifest_bytes = manifest_path.read_bytes()
    manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
    manifest = json.loads(manifest_bytes)
    scenarios = _validate_manifest(manifest)
    records: list[dict[str, Any]] = []
    for scenario in scenarios:
        action, permissions = _make_action(scenario)
        decision, reason = evaluate_synthetic_action_policy(
            RISK_PROFILE_TO_VERTICAL[str(scenario["profileId"])],
            action,
            permissions,
        )
        proposal_hash = str(action["proposalSha256"])
        record = {
            "scenarioId": scenario["scenarioId"],
            "profileId": scenario["profileId"],
            "profileLabel": VERTICAL_LABELS[
                RISK_PROFILE_TO_VERTICAL[str(scenario["profileId"])]
            ],
            "policyVariant": scenario["variant"],
            "decision": decision,
            "reasonCode": reason,
            "expectedDecisionMatched": decision == scenario["expectedDecision"],
            "expectedReasonMatched": reason == scenario["expectedReason"],
            "proposalSha256": proposal_hash,
            "decisionEvidenceSha256": _sha256(
                {
                    "scenarioId": scenario["scenarioId"],
                    "profileId": scenario["profileId"],
                    "variant": scenario["variant"],
                    "proposalSha256": proposal_hash,
                    "decision": decision,
                    "reasonCode": reason,
                }
            ),
            "policyDecisionEvaluated": True,
            "toolDispatch": False,
            "simulatorInvoked": False,
            "policyOffEvaluated": False,
            "fullScenarioObjectiveVerified": False,
            "rawPromptStored": False,
            "rawResponseStored": False,
            "rawArgumentsStored": False,
        }
        records.append(record)

    decisions = [record["decision"] for record in records]
    checks = {
        "allManifestCasesEvaluated": len(records) == 32,
        "allExpectedDecisionsMatched": all(
            record["expectedDecisionMatched"] for record in records
        ),
        "allExpectedReasonsMatched": all(
            record["expectedReasonMatched"] for record in records
        ),
        "noToolDispatch": all(not record["toolDispatch"] for record in records),
        "noSimulatorInvocation": all(not record["simulatorInvoked"] for record in records),
        "noPolicyOffExecution": all(not record["policyOffEvaluated"] for record in records),
        "noRawContentStored": all(
            not record["rawPromptStored"]
            and not record["rawResponseStored"]
            and not record["rawArgumentsStored"]
            for record in records
        ),
    }
    result: dict[str, Any] = {
        "evidenceSchemaVersion": 1,
        "source": "guardian_risk_intelligence_stpa_synthetic_manifest",
        "runner": RUNNER_VERSION,
        "catalogVersion": manifest["catalogVersion"],
        "policyEngine": "guardian_synthetic_policy_engine",
        "policyEngineVersion": "guardian-policy-engine-synthetic-v2",
        "executionMode": "deterministic_policy_decision_only",
        "proposalOrigin": "runner_generated_synthetic_policy_input_not_llm",
        "modelInference": False,
        "nativeToolCalls": 0,
        "adaptedModelProposals": 0,
        "fixturesFromEightProfileBaseline": 0,
        "scenarioCount": len(records),
        "summary": {
            "policyDecisionsEvaluated": len(records),
            "allow": decisions.count("allow"),
            "deny": decisions.count("deny"),
            "requireApproval": decisions.count("require_approval"),
            "expectedDecisionsMatched": sum(
                record["expectedDecisionMatched"] for record in records
            ),
            "expectedReasonsMatched": sum(
                record["expectedReasonMatched"] for record in records
            ),
            "toolDispatches": 0,
            "simulatorInvocations": 0,
            "policyOffEvaluations": 0,
            "fullScenarioObjectivesVerified": 0,
            "databaseConnections": 0,
            "externalConnections": 0,
            "dockerInvocations": 0,
            "qwenCalls": 0,
        },
        "manifestSha256": manifest_hash,
        "cases": records,
        "selfChecks": checks,
        "selfCheckStatus": "passed" if all(checks.values()) else "failed",
        "limits": {
            "toolsDispatched": False,
            "syntheticActionExecuted": False,
            "policyOffUsed": False,
            "databaseUsed": False,
            "networkUsed": False,
            "dockerUsed": False,
            "modelLoaded": False,
            "approvalLifecycleTested": False,
            "fullStpaControlObjectivesVerified": False,
            "policyDecisionOnly": True,
        },
        "interpretation": (
            "Los 32 IDs del catálogo se evaluaron como entradas sintéticas de decisión "
            "contra el Policy Engine existente. No se ejecutó el objetivo completo de "
            "cada escenario: no hubo inferencia, despacho, simulador, persistencia ni "
            "ciclo de aprobación. Risk Intelligence sigue siendo consultivo y no modifica "
            "la política ni autoriza acciones."
        ),
        "startedAt": datetime.now(timezone.utc).isoformat(),
        "durationMs": round((time.monotonic() - started) * 1000),
    }
    result["evidenceSha256"] = _sha256(result)
    return result
