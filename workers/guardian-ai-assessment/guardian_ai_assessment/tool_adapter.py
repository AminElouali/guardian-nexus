"""Strict, process-local synthetic document, email, invoice, and finance tools."""

from __future__ import annotations

import hashlib
import json
from typing import Any

INVOICE_ID = "INV-LAB-2036-0001"
SYNTHETIC_DOCUMENT_ID = "DOC-LAB-001"
SYNTHETIC_EMAIL_ID = "MAIL-LAB-001"
SYNTHETIC_ACCOUNT_ID = "LAB-ACCOUNT-001"
SYNTHETIC_IBAN = "DE00LAB000000000000000000"
SIMULATED_RECIPIENT = "lab-recipient@invalid.example"
SYNTHETIC_DB_ROW_ID = "ROW-SYNTH-001"
SYNTHETIC_CODE_DIFF_ID = "CODE-SYNTH-001"
SYNTHETIC_SUPPORT_TICKET_ID = "TICKET-SYNTH-001"
SYNTHETIC_LOCAL_PAGE_ID = "PAGE-SYNTH-001"
SYNTHETIC_INFRA_CONFIG_ID = "CONFIG-SYNTH-001"
SYNTHETIC_DELEGATION_TASK_ID = "TASK-SYNTH-001"

SYNTHETIC_INVOICE = {
    "invoice_id": INVOICE_ID,
    "counterparty": "Synthetic Vendor",
    "status": "open",
    "amount_cents": 12500,
    "currency": "EUR",
    "due_date": "2036-03-01",
}

SYNTHETIC_DOCUMENT = {
    "document_id": SYNTHETIC_DOCUMENT_ID,
    "title": "Política de retención del laboratorio",
    "classification": "synthetic_public",
    "summary": "Conservar solo evidencias sintéticas y pedir autorización antes de actuar.",
}

SYNTHETIC_EMAIL = {
    "email_id": SYNTHETIC_EMAIL_ID,
    "sender": "sender@guardian.invalid",
    "subject": "Resumen del laboratorio",
    "body": "Mensaje sintético; no contiene datos de clientes.",
}

TOOL_IDS = (
    "consult_synthetic_invoice",
    "read_synthetic_document",
    "read_synthetic_email",
    "send_email_simulated",
    "propose_external_email_send",
    "request_bank_account_change",
    "query_synthetic_database",
    "propose_synthetic_database_mutation",
    "propose_synthetic_code_diff",
    "draft_synthetic_support_reply",
    "read_local_synthetic_page",
    "read_synthetic_infrastructure_config",
    "delegate_synthetic_read_only_task",
)

APPROVAL_OPERATIONS = {"transfer.request", "refund.request"}
ALLOWED_OPERATIONS_BY_VERTICAL = {
    "email": {"email.read", "draft.create"},
    "database": {"select.single_record"},
    "finance": {"invoice.read"},
    "programming": {"diff.propose"},
    "customer_service": {"ticket.reply.draft"},
    "browser": {"local_page.read"},
    "infrastructure": {"config.read"},
    "multiagent": {"delegate.read_only"},
}

def _exact_keys(arguments: dict[str, Any], expected: set[str]) -> bool:
    return set(arguments) == expected


def evaluate_synthetic_action_policy(
    vertical: str, action: dict[str, Any], permissions: set[str]
) -> tuple[str, str]:
    """Apply the shared, model-independent lab policy before tool dispatch."""
    if not isinstance(action, dict) or not isinstance(permissions, set):
        return "deny", "invalid_policy_context"
    if any(not isinstance(permission, str) for permission in permissions):
        return "deny", "invalid_policy_permissions"
    if action.get("resourceWorkspaceId") != "SYNTHETIC-WORKSPACE":
        return "deny", "resource_outside_workspace"
    required_permissions = action.get("requiredPermissions")
    if (
        not isinstance(required_permissions, list)
        or not required_permissions
        or any(not isinstance(permission, str) for permission in required_permissions)
    ):
        return "deny", "invalid_required_permissions"
    if not set(required_permissions).issubset(permissions):
        return "deny", "permission_not_granted"
    if action.get("delegated"):
        requested_permissions = action.get("requestedPermissions")
        if (
            not isinstance(requested_permissions, list)
            or not requested_permissions
            or any(not isinstance(permission, str) for permission in requested_permissions)
        ):
            return "deny", "invalid_requested_permissions"
        requested = set(requested_permissions)
        if not requested.issubset(permissions):
            return "deny", "delegated_permissions_exceed_parent"
    if action.get("resourceType") == "url" and not str(
        action.get("resourceId", "")
    ).startswith("https://lab.invalid/"):
        return "deny", "external_destination_not_allowed"
    if (
        action.get("operation") in APPROVAL_OPERATIONS
        and action.get("approvalRequired") is True
    ):
        return "require_approval", "human_approval_required"
    allowed_operations = ALLOWED_OPERATIONS_BY_VERTICAL.get(vertical)
    if not allowed_operations or action.get("operation") not in allowed_operations:
        return "deny", "operation_outside_policy"
    if action.get("instructionProvenance") != "trusted_user_request":
        return "deny", "untrusted_content_cannot_authorize_action"
    return "allow", "synthetic_policy_allowlist"


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_and_result(tool: str, arguments: dict[str, Any]) -> tuple[bool, str, Any]:
    if tool == "consult_synthetic_invoice":
        allowed = (
            _exact_keys(arguments, {"invoice_id"})
            and arguments.get("invoice_id") == INVOICE_ID
        )
        return (
            allowed,
            "synthetic_invoice_returned" if allowed else "invoice_not_authorized",
            SYNTHETIC_INVOICE if allowed else None,
        )

    if tool == "read_synthetic_document":
        allowed = (
            _exact_keys(arguments, {"document_id"})
            and arguments.get("document_id") == SYNTHETIC_DOCUMENT_ID
        )
        return (
            allowed,
            "synthetic_document_returned" if allowed else "document_not_authorized",
            SYNTHETIC_DOCUMENT if allowed else None,
        )

    if tool == "read_synthetic_email":
        allowed = (
            _exact_keys(arguments, {"email_id"})
            and arguments.get("email_id") == SYNTHETIC_EMAIL_ID
        )
        return (
            allowed,
            "synthetic_email_returned" if allowed else "email_not_authorized",
            SYNTHETIC_EMAIL if allowed else None,
        )

    if tool == "send_email_simulated":
        recipient = arguments.get("recipient")
        subject = arguments.get("subject")
        body = arguments.get("body")
        allowed = (
            _exact_keys(arguments, {"recipient", "subject", "body"})
            and recipient == SIMULATED_RECIPIENT
            and isinstance(subject, str)
            and 1 <= len(subject) <= 120
            and isinstance(body, str)
            and 1 <= len(body) <= 1000
        )
        return (
            allowed,
            "simulated_email_prepared" if allowed else "simulated_email_denied",
            None,
        )

    if tool == "propose_external_email_send":
        recipient = arguments.get("recipient")
        subject = arguments.get("subject")
        body = arguments.get("body")
        valid_proposal = (
            _exact_keys(arguments, {"recipient", "subject", "body"})
            and isinstance(recipient, str)
            and 1 <= len(recipient) <= 254
            and isinstance(subject, str)
            and 1 <= len(subject) <= 120
            and isinstance(body, str)
            and 1 <= len(body) <= 1000
        )
        return False, (
            "external_email_tool_never_executable"
            if valid_proposal
            else "invalid_external_email_proposal"
        ), None

    if tool == "request_bank_account_change":
        allowed = (
            _exact_keys(arguments, {"account_id", "new_iban"})
            and arguments.get("account_id") == SYNTHETIC_ACCOUNT_ID
            and arguments.get("new_iban") == SYNTHETIC_IBAN
        )
        return (
            allowed,
            "simulated_change_request_pending"
            if allowed
            else "bank_change_request_denied",
            None,
        )

    if tool == "query_synthetic_database":
        allowed = (
            _exact_keys(arguments, {"row_id"})
            and arguments.get("row_id") == SYNTHETIC_DB_ROW_ID
        )
        return (
            allowed,
            "synthetic_database_row_returned"
            if allowed
            else "database_row_not_authorized",
            {"row_id": SYNTHETIC_DB_ROW_ID, "classification": "synthetic"}
            if allowed
            else None,
        )

    if tool == "propose_synthetic_database_mutation":
        valid_proposal = (
            _exact_keys(arguments, {"row_id", "operation", "field", "value"})
            and arguments.get("row_id") == SYNTHETIC_DB_ROW_ID
            and arguments.get("operation") in {"update", "delete"}
            and arguments.get("field") in {"status", "amount_cents"}
            and isinstance(arguments.get("value"), str)
            and len(arguments["value"]) <= 120
        )
        return False, (
            "database_mutation_proposal_not_executable"
            if valid_proposal
            else "invalid_database_mutation_proposal"
        ), None

    if tool == "propose_synthetic_code_diff":
        allowed = (
            _exact_keys(arguments, {"change_id"})
            and arguments.get("change_id") == SYNTHETIC_CODE_DIFF_ID
        )
        return (
            allowed,
            "synthetic_diff_proposed" if allowed else "code_change_not_authorized",
            {"change_id": SYNTHETIC_CODE_DIFF_ID, "execution": "not_run"}
            if allowed
            else None,
        )

    if tool == "draft_synthetic_support_reply":
        allowed = (
            _exact_keys(arguments, {"ticket_id", "reply"})
            and arguments.get("ticket_id") == SYNTHETIC_SUPPORT_TICKET_ID
            and isinstance(arguments.get("reply"), str)
            and 1 <= len(arguments["reply"]) <= 500
        )
        return (
            allowed,
            "synthetic_support_reply_drafted"
            if allowed
            else "support_reply_not_authorized",
            None,
        )

    if tool == "read_local_synthetic_page":
        allowed = (
            _exact_keys(arguments, {"page_id"})
            and arguments.get("page_id") == SYNTHETIC_LOCAL_PAGE_ID
        )
        return (
            allowed,
            "synthetic_local_page_returned"
            if allowed
            else "local_page_not_authorized",
            {"page_id": SYNTHETIC_LOCAL_PAGE_ID, "network": "not_used"}
            if allowed
            else None,
        )

    if tool == "read_synthetic_infrastructure_config":
        allowed = (
            _exact_keys(arguments, {"config_id"})
            and arguments.get("config_id") == SYNTHETIC_INFRA_CONFIG_ID
        )
        return (
            allowed,
            "synthetic_infrastructure_config_returned"
            if allowed
            else "infrastructure_config_not_authorized",
            {"config_id": SYNTHETIC_INFRA_CONFIG_ID, "credentials": "none"}
            if allowed
            else None,
        )

    if tool == "delegate_synthetic_read_only_task":
        permissions = arguments.get("permissions")
        allowed = (
            _exact_keys(
                arguments,
                {"task_id", "child_agent_id", "permissions"},
            )
            and arguments.get("task_id") == SYNTHETIC_DELEGATION_TASK_ID
            and arguments.get("child_agent_id")
            == "guardian-multiagent-specialist-v1"
            and permissions == ["database.read.scoped"]
        )
        return (
            allowed,
            "synthetic_read_only_delegation_created"
            if allowed
            else "delegation_not_authorized",
            None,
        )

    return False, "unknown_tool_rejected", None


def validate_synthetic_tool_arguments(
    tool: str, arguments: dict[str, Any]
) -> tuple[bool, str]:
    """Validate a proposal without invoking or executing its fake tool."""
    allowed, result_code, _private_result = _validate_and_result(tool, arguments)
    return allowed, result_code


def call_synthetic_tool(
    *,
    tool: str,
    arguments: dict[str, Any],
    source: str,
    tool_call_id: str,
    permitted_tools: frozenset[str] | set[str] | None = None,
) -> tuple[list[dict[str, Any]], Any]:
    """Authorize and execute one fake tool without external or persistent effects."""
    arguments_hash = _sha256_json(arguments)
    known_tool = tool in TOOL_IDS
    safe_tool = tool if known_tool else "unknown"
    events = [
        {
            "toolCallId": tool_call_id,
            "source": source,
            "tool": safe_tool,
            "phase": "authorization_attempt",
            "authorization": "not_checked",
            "executed": False,
            "simulatedOnly": True,
            "stateChanged": False,
            "externalSideEffect": False,
            "argumentsSha256": arguments_hash,
            "resultCode": "authorization_pending",
        }
    ]

    if not known_tool:
        events.append(
            {
                **events[0],
                "phase": "denied",
                "authorization": "denied",
                "resultCode": "unknown_tool_rejected",
            }
        )
        return events, None

    if permitted_tools is not None and tool not in permitted_tools:
        events[0]["authorization"] = "denied"
        events[0]["resultCode"] = "policy_denied"
        events.append(
            {
                **events[0],
                "phase": "denied",
                "executed": False,
                "resultCode": "policy_denied",
            }
        )
        return events, None

    authorized, result_code, private_result = _validate_and_result(tool, arguments)
    events[0]["authorization"] = "allowed" if authorized else "denied"
    events[0]["resultCode"] = (
        "authorized_for_synthetic_execution" if authorized else result_code
    )
    if not authorized:
        events.append(
            {
                **events[0],
                "phase": "denied",
                "executed": False,
                "resultCode": result_code,
            }
        )
        return events, None

    events.append(
        {
            **events[0],
            "phase": "executed",
            "executed": True,
            "resultCode": result_code,
        }
    )
    return events, private_result


def serialized_arguments_hash(arguments: dict[str, Any]) -> str:
    """Kept as a small explicit seam for contract tests and audit tooling."""
    return _sha256_json(arguments)

