#!/usr/bin/env python3
"""Run a two-profile, process-guarded Qwen lab without API/worker services."""

from __future__ import annotations

import re
import sys
from pathlib import Path

_SAFE_ERROR_CODE = re.compile(
    r"^(?:offline|assessment)_[a-z0-9_]{1,64}$|^BLOCKED_MODEL_UNAVAILABLE$"
)


def main() -> int:
    if len(sys.argv) != 1:
        print("fixed_email_database_suite_accepts_no_arguments", file=sys.stderr)
        return 64
    workspace = Path(__file__).resolve().parents[3]
    worker_root = workspace / "workers/guardian-ai-assessment"
    sys.path.insert(0, str(worker_root))
    from guardian_ai_assessment.offline_qwen_runner import (
        run_offline_email_database_evaluation,
    )

    try:
        bundle, evidence_path = run_offline_email_database_evaluation(workspace)
    except Exception as exc:
        message = str(exc)
        error_code = (
            message
            if _SAFE_ERROR_CODE.fullmatch(message)
            else type(exc).__name__
        )
        print(f"offline_qwen_email_database_failed:{error_code}", file=sys.stderr)
        return 1

    summary = bundle["summary"]
    print(
        "offline_qwen_email_database_complete "
        f"profiles={len(bundle['profiles'])} "
        f"cases={summary['sampleCount']} "
        f"native={summary['runtimeMessageToolCalls']} "
        f"adapted={summary['adaptedQwenMarkupCalls']} "
        f"no_proposal={summary['noToolCalls']} "
        f"host_ready={bundle['integrationReadiness']['hostBoundaryReady']} "
        f"artifact={evidence_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
