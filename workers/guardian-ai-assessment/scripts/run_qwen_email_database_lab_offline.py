#!/usr/bin/env python3
"""Run a two-profile, process-guarded Qwen lab without API/worker services."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_SAFE_ERROR_CODE = re.compile(
    r"^(?:offline|assessment)_[a-z0-9_]{1,64}$|^BLOCKED_MODEL_UNAVAILABLE$"
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the bounded synthetic Qwen email/database offline lab."
    )
    parser.add_argument(
        "--case-timeout-seconds", type=int, default=120,
    )
    parser.add_argument(
        "--profile-timeout-seconds", type=int, default=300,
    )
    parser.add_argument(
        "--wall-timeout-seconds", type=int, default=660,
    )
    parser.add_argument(
        "--profile-child",
        choices=(
            "guardian-agent-qwen-lab-email-v1",
            "guardian-agent-qwen-lab-database-v1",
        ),
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()
    workspace = Path(__file__).resolve().parents[3]
    worker_root = workspace / "workers/guardian-ai-assessment"
    sys.path.insert(0, str(worker_root))
    from guardian_ai_assessment.offline_qwen_runner import (
        run_offline_email_database_evaluation,
        run_offline_email_database_profile,
    )

    try:
        if args.profile_child:
            bundle, evidence_path = run_offline_email_database_profile(
                workspace,
                args.profile_child,
                case_timeout_seconds=args.case_timeout_seconds,
                profile_timeout_seconds=args.profile_timeout_seconds,
            )
        else:
            bundle, evidence_path = run_offline_email_database_evaluation(
                workspace,
                case_timeout_seconds=args.case_timeout_seconds,
                profile_timeout_seconds=args.profile_timeout_seconds,
                wall_timeout_seconds=args.wall_timeout_seconds,
            )
    except Exception as exc:
        message = str(exc)
        error_code = (
            message
            if _SAFE_ERROR_CODE.fullmatch(message)
            else type(exc).__name__
        )
        print(f"offline_qwen_email_database_failed:{error_code}", file=sys.stderr)
        return 1

    if args.profile_child:
        profile = bundle["profiles"][0] if bundle["profiles"] else {}
        print(
            "offline_qwen_profile_complete "
            f"profile={args.profile_child} "
            f"status={bundle['status']} "
            f"cases={profile.get('summary', {}).get('sampleCount', 0)} "
            f"artifact={evidence_path}",
            flush=True,
        )
        return 0 if bundle["status"] == "completed" else 1

    summary = bundle["summary"]
    print(
        "offline_qwen_email_database "
        f"status={bundle['status']} "
        f"profiles={len(bundle['profiles'])} "
        f"cases={summary['sampleCount']} "
        f"native={summary['runtimeMessageToolCalls']} "
        f"adapted={summary['adaptedQwenMarkupCalls']} "
        f"no_proposal={summary['noToolCalls']} "
        f"host_ready={bundle['integrationReadiness']['hostBoundaryReady']} "
        f"artifact={evidence_path}",
        flush=True,
    )
    return 0 if bundle["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
