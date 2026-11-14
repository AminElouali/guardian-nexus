"""Small, dependency-free client for Guardian Nexus' authenticated lab API.

The server derives actor identity, role, scenario policy, and tenant membership.
This client cannot submit arbitrary tools, arguments, or policy decisions.
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Literal, Mapping, Protocol
from urllib.parse import urlsplit
from uuid import UUID

AGENT_ACTION_SCENARIOS = (
    "email.allowed_draft",
    "email.untrusted_send",
    "finance.untrusted_transfer",
    "finance.trusted_bank_change_approval",
)
SYNTHETIC_REFUND_SCENARIO_ID = "guardian.synthetic.support.refund.v1"

QWEN_AGENT_PROFILE_IDS = (
    "guardian-agent-qwen-lab-email-v1",
    "guardian-agent-qwen-lab-database-v1",
    "guardian-agent-qwen-lab-finance-v1",
    "guardian-agent-qwen-lab-customer-service-v1",
    "guardian-agent-qwen-lab-programming-v1",
    "guardian-agent-qwen-lab-browser-v1",
    "guardian-agent-qwen-lab-infrastructure-v1",
    "guardian-agent-qwen-lab-multiagent-v1",
)

_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_MAX_REQUEST_BYTES = 8 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_RETRYABLE_STATUSES = {429, 502, 503, 504}
_SCENARIO_PROFILE = {
    "email.allowed_draft": "guardian-agent-lab-email-v1",
    "email.untrusted_send": "guardian-agent-lab-email-v1",
    "finance.untrusted_transfer": "guardian-agent-lab-finance-v1",
    "finance.trusted_bank_change_approval": "guardian-agent-lab-finance-v1",
}

ApprovalDecision = Literal["approve", "deny"]


class GuardianNexusSdkError(RuntimeError):
    """Sanitized SDK error. It never includes response bodies or credentials."""

    def __init__(self, code: str, status: int | None = None):
        super().__init__(code)
        self.code = code
        self.status = status


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def request(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class UrllibTransport:
    """HTTPS transport that refuses redirects and bounds bytes read."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect())

    def request(
        self,
        url: str,
        method: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> HttpResponse:
        request = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers),
            method=method,
        )
        try:
            response = self._opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as error:
            return HttpResponse(
                status=error.code,
                headers=dict(error.headers.items()) if error.headers else {},
                body=error.read(_MAX_RESPONSE_BYTES + 1),
            )
        except (urllib.error.URLError, TimeoutError, OSError):
            raise GuardianNexusSdkError("transport_failure") from None
        with response:
            return HttpResponse(
                status=response.status,
                headers=dict(response.headers.items()),
                body=response.read(_MAX_RESPONSE_BYTES + 1),
            )


class GuardianNexusClient:
    """Authenticated client for fixed synthetic scenarios and Qwen lab jobs."""

    def __init__(
        self,
        *,
        base_url: str,
        workspace_id: str,
        get_access_token: Callable[[], str | None],
        transport: Transport | None = None,
        timeout_seconds: float = 10.0,
        max_retries: int = 2,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.workspace_id = _normalize_uuid(workspace_id, "invalid_workspace_id")
        self.api_base = _resolve_api_base(base_url)
        if not callable(get_access_token):
            raise GuardianNexusSdkError("access_token_provider_required")
        if not isinstance(timeout_seconds, (int, float)) or not 0.1 <= timeout_seconds <= 60:
            raise GuardianNexusSdkError("invalid_timeout")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int):
            raise GuardianNexusSdkError("invalid_retry_limit")
        self._get_access_token = get_access_token
        self._transport = transport or UrllibTransport()
        self._timeout = float(timeout_seconds)
        self._max_retries = max(0, min(3, max_retries))
        self._sleep = sleep

    def submit_intent(
        self,
        *,
        scenario_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if scenario_id not in AGENT_ACTION_SCENARIOS:
            raise GuardianNexusSdkError("invalid_intent_request")
        _validate_idempotency_key(idempotency_key)
        value = self._request(
            f"/workspaces/{self.workspace_id}/agent-action-adapter/intents",
            method="POST",
            body={
                "contractVersion": "guardian-action-intent-v1",
                "scenarioId": scenario_id,
                "idempotencyKey": idempotency_key,
            },
            retryable=True,
        )
        if not _is_mapping(value):
            raise GuardianNexusSdkError("invalid_intent_response")
        intent = value.get("actionIntent")
        job = value.get("job")
        if (
            value.get("adapterVersion") != "guardian-agent-intent-adapter-v1"
            or value.get("source") != "fixed_synthetic_scenario"
            or value.get("decisionStatus") != "pending_worker_evaluation"
            or value.get("externalDispatch") is not False
            or not _is_mapping(intent)
            or intent.get("contractVersion") != "guardian-action-intent-v1"
            or intent.get("workspaceId") != self.workspace_id
            or intent.get("scenarioId") != scenario_id
            or not _is_sha256(intent.get("intentSha256"))
            or not _is_mapping(job)
            or not _is_uuid(job.get("id"))
            or job.get("profileId") != _SCENARIO_PROFILE[scenario_id]
        ):
            raise GuardianNexusSdkError("invalid_intent_response")
        return dict(value)

    def submit_qwen_evaluation(
        self,
        *,
        profile_id: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        if profile_id not in QWEN_AGENT_PROFILE_IDS:
            raise GuardianNexusSdkError("invalid_qwen_profile_id")
        _validate_idempotency_key(idempotency_key)
        value = self._request(
            f"/workspaces/{self.workspace_id}/ai-security-assessments/lab/jobs",
            method="POST",
            body={"profileId": profile_id, "idempotencyKey": idempotency_key},
            retryable=True,
        )
        if (
            not _is_mapping(value)
            or value.get("profileId") != profile_id
            or not _is_uuid(value.get("id"))
            or value.get("status") not in {"queued", "running", "succeeded", "failed"}
        ):
            raise GuardianNexusSdkError("invalid_qwen_job_response")
        return {
            "source": "qwen_local_policy_lab_profile",
            "executionMode": "not_yet_verified",
            "externalDispatch": False,
            "job": dict(value),
        }

    def get_job(self, job_id: str) -> dict[str, Any]:
        normalized_id = _normalize_uuid(job_id, "invalid_job_id")
        value = self._request(
            f"/workspaces/{self.workspace_id}/ai-security-assessments/lab/jobs/{normalized_id}",
            method="GET",
            retryable=True,
        )
        if (
            not _is_mapping(value)
            or value.get("id") != normalized_id
            or value.get("status") not in {"queued", "running", "succeeded", "failed"}
        ):
            raise GuardianNexusSdkError("invalid_job_response")
        return dict(value)

    def list_approvals(self) -> list[dict[str, Any]]:
        value = self._request(
            f"/workspaces/{self.workspace_id}/ai-security-assessments/approvals",
            method="GET",
            retryable=True,
        )
        approvals = (
            value.get("approvals")
            if _is_mapping(value)
            else value
        )
        if not isinstance(approvals, list) or not all(
            _is_valid_approval_summary(approval) for approval in approvals
        ):
            raise GuardianNexusSdkError("invalid_approval_list_response")
        return [dict(approval) for approval in approvals]

    def propose_synthetic_refund(self, *, idempotency_key: str) -> dict[str, Any]:
        """Request the one fixed synthetic refund scenario for human review."""
        _validate_idempotency_key(idempotency_key)
        value = self._request(
            f"/workspaces/{self.workspace_id}/ai-security-assessments/synthetic-refund-proposals",
            method="POST",
            body={
                "scenarioId": SYNTHETIC_REFUND_SCENARIO_ID,
                "idempotencyKey": idempotency_key,
            },
            retryable=True,
        )
        if not _is_valid_synthetic_refund_response(value):
            raise GuardianNexusSdkError("invalid_synthetic_refund_response")
        return dict(value)

    def decide_approval(
        self,
        *,
        approval_id: str,
        decision: ApprovalDecision,
        proposal_binding_sha256: str,
    ) -> dict[str, Any]:
        normalized_id = _normalize_uuid(approval_id, "invalid_approval_id")
        if decision not in {"approve", "deny"} or not _is_sha256(
            proposal_binding_sha256
        ):
            raise GuardianNexusSdkError("invalid_approval_decision")
        value = self._request(
            f"/workspaces/{self.workspace_id}/ai-security-assessments/approvals/{normalized_id}/decision",
            method="POST",
            body={
                "decision": decision,
                "proposalBindingSha256": proposal_binding_sha256,
            },
            # Approval decisions are single-use transitions and are never retried.
            retryable=False,
        )
        if not _is_mapping(value) or not _is_mapping(value.get("approval")):
            raise GuardianNexusSdkError("invalid_approval_decision_response")
        approval = value["approval"]
        expected_status = "approved" if decision == "approve" else "denied"
        if (
            approval.get("proposalBindingSha256") != proposal_binding_sha256
            or approval.get("status") != expected_status
            or value.get("execution")
            not in {"synthetic_action_simulated_once", "not_performed"}
        ):
            raise GuardianNexusSdkError("approval_response_binding_mismatch")
        if value.get("execution") == "synthetic_action_simulated_once":
            if (
                approval.get("status") != "approved"
                or approval.get("execution") != "synthetic_action_simulated_once"
                or not approval.get("simulatedAt")
                or not _is_sha256(approval.get("simulationResultSha256"))
                or not _is_sha256(approval.get("replayBindingSha256"))
            ):
                raise GuardianNexusSdkError("invalid_approval_replay_evidence")
        return dict(value)

    def _request(
        self,
        path: str,
        *,
        method: str,
        body: Mapping[str, Any] | None = None,
        retryable: bool,
    ) -> Any:
        encoded_body = None
        headers = {"Accept": "application/json"}
        if body is not None:
            try:
                encoded_body = json.dumps(
                    body, separators=(",", ":"), ensure_ascii=True
                ).encode("utf-8")
            except (TypeError, ValueError):
                raise GuardianNexusSdkError("invalid_request_body") from None
            if len(encoded_body) > _MAX_REQUEST_BYTES:
                raise GuardianNexusSdkError("request_body_too_large")
            headers["Content-Type"] = "application/json"

        attempts = self._max_retries + 1 if retryable else 1
        for attempt in range(attempts):
            try:
                token = self._get_access_token()
            except Exception:
                raise GuardianNexusSdkError("access_token_unavailable") from None
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 8_192
                or "\r" in token
                or "\n" in token
            ):
                raise GuardianNexusSdkError("authentication_required", 401)
            request_headers = {
                **headers,
                "Authorization": f"Bearer {token}",
            }
            response = self._transport.request(
                f"{self.api_base}{path}",
                method,
                request_headers,
                encoded_body,
                self._timeout,
            )
            if len(response.body) > _MAX_RESPONSE_BYTES:
                raise GuardianNexusSdkError("response_body_too_large", response.status)
            if response.status in _RETRYABLE_STATUSES and attempt + 1 < attempts:
                self._sleep(_retry_delay(response.headers, attempt))
                continue
            if not 200 <= response.status < 300:
                raise GuardianNexusSdkError(
                    f"http_status_{response.status}", response.status
                )
            try:
                return json.loads(
                    response.body.decode("utf-8"),
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                raise GuardianNexusSdkError("invalid_json_response", response.status) from None
        raise GuardianNexusSdkError("request_retry_exhausted")


def _resolve_api_base(base_url: str) -> str:
    if not isinstance(base_url, str) or len(base_url) > 2_048:
        raise GuardianNexusSdkError("invalid_base_url")
    try:
        parsed = urlsplit(base_url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise GuardianNexusSdkError("invalid_base_url") from None
    if (
        parsed.scheme not in {"https", "http"}
        or not hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or any(char in base_url for char in ("\r", "\n", "\x00"))
    ):
        raise GuardianNexusSdkError("insecure_or_invalid_base_url")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            loopback = hostname.lower() == "localhost"
        if not loopback:
            raise GuardianNexusSdkError("insecure_or_invalid_base_url")
    if port is not None and not 1 <= port <= 65_535:
        raise GuardianNexusSdkError("invalid_base_url")
    path = parsed.path.rstrip("/")
    origin = f"{parsed.scheme}://{parsed.netloc}{path}"
    return origin if path.endswith("/api") else f"{origin}/api"


def _normalize_uuid(value: str, code: str) -> str:
    if not isinstance(value, str):
        raise GuardianNexusSdkError(code)
    try:
        return str(UUID(value))
    except (ValueError, AttributeError):
        raise GuardianNexusSdkError(code) from None


def _is_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(UUID(value)) == value
    except ValueError:
        return False


def _validate_idempotency_key(value: str) -> None:
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        raise GuardianNexusSdkError("invalid_idempotency_key")


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(_SHA256_RE.fullmatch(value))


def _is_mapping(value: Any) -> bool:
    return isinstance(value, dict)


def _is_valid_approval_summary(value: Any) -> bool:
    return (
        _is_mapping(value)
        and _is_uuid(value.get("id"))
        and _is_uuid(value.get("jobId"))
        and value.get("status") in {"pending", "approved", "denied", "expired"}
        and _is_sha256(value.get("proposalBindingSha256"))
        and isinstance(value.get("expiresAt"), str)
    )


def _is_valid_synthetic_refund_approval(value: Any) -> bool:
    if not _is_valid_approval_summary(value):
        return False
    if (
        value.get("caseId") != "support_trusted_refund_requires_approval"
        or value.get("syntheticActionRef") != SYNTHETIC_REFUND_SCENARIO_ID
        or value.get("bindingVersion") != 3
        or value.get("modelInference") is not False
        or value.get("executionMode") != "deterministic_fixture"
        or value.get("toolCallOrigin") != "controlled_fixture_not_llm"
        or value.get("requestedByRole") not in {"owner", "admin"}
    ):
        return False
    if value.get("status") == "pending":
        return (
            value.get("execution") == "not_performed"
            and value.get("simulatedAt") is None
            and value.get("simulationResultCode") is None
            and value.get("simulationResultSha256") is None
            and value.get("canCurrentUserDecide") is False
        )
    if value.get("status") == "approved":
        return (
            value.get("execution") == "synthetic_action_simulated_once"
            and value.get("simulatedAt") is not None
            and value.get("simulationResultCode")
            == "synthetic_refund_approved_in_clone"
            and _is_sha256(value.get("simulationResultSha256"))
            and _is_sha256(value.get("replayBindingSha256"))
        )
    return value.get("status") in {"denied", "expired"}


def _is_valid_synthetic_refund_response(value: Any) -> bool:
    if (
        not _is_mapping(value)
        or not isinstance(value.get("idempotent"), bool)
        or value.get("externalSideEffect") is not False
    ):
        return False
    decision = value.get("decision")
    if decision == "require_approval":
        approval = value.get("approval")
        return (
            value.get("reasonCode") == "human_approval_required"
            and _is_valid_synthetic_refund_approval(approval)
            and approval.get("execution") == value.get("execution")
            and value.get("simulationResultCode")
            == approval.get("simulationResultCode")
            and value.get("simulationResultSha256")
            == approval.get("simulationResultSha256")
        )
    if decision == "allow":
        return (
            value.get("reasonCode") == "synthetic_policy_allowed"
            and value.get("approval") is None
            and value.get("execution") == "synthetic_action_simulated_once"
            and value.get("simulationResultCode")
            == "synthetic_refund_approved_in_clone"
            and _is_sha256(value.get("simulationResultSha256"))
        )
    if decision == "deny":
        return (
            value.get("reasonCode") == "synthetic_policy_denied"
            and value.get("approval") is None
            and value.get("execution") == "not_performed_denied"
            and value.get("simulationResultCode") is None
            and value.get("simulationResultSha256") is None
        )
    return False


def _header(headers: Mapping[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _retry_delay(headers: Mapping[str, str], attempt: int) -> float:
    value = _header(headers, "retry-after")
    try:
        requested = float(value) if value is not None else 0.1 * (2**attempt)
    except ValueError:
        requested = 0.1 * (2**attempt)
    if requested != requested or requested < 0:
        return 0.1
    return min(1.0, requested)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result
