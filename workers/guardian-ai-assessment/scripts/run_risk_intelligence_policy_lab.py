#!/usr/bin/env python3
"""Run the fixed, no-dispatch STPA Policy Engine evaluation."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 1:
        print("risk_intelligence_runner_accepts_no_arguments", file=sys.stderr)
        return 64
    workspace = Path(__file__).resolve().parents[3]
    worker_root = workspace / "workers/guardian-ai-assessment"
    sys.path.insert(0, str(worker_root))
    from guardian_ai_assessment.risk_intelligence_policy_runner import (
        run_risk_intelligence_policy_scenarios,
    )

    try:
        result = run_risk_intelligence_policy_scenarios()
        if result["selfCheckStatus"] != "passed":
            raise RuntimeError("risk_intelligence_policy_self_check_failed")
        report = worker_root / "reports/risk-intelligence-stpa-policy-run-2026-11-04.json"
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
    except Exception as exc:
        message = str(exc)
        safe_code = (
            message
            if message.startswith("risk_")
            and message.replace("_", "").isalnum()
            else type(exc).__name__
        )
        print(f"risk_intelligence_policy_run_failed:{safe_code}", file=sys.stderr)
        return 1
    summary = result["summary"]
    print(
        "risk_intelligence_policy_run_complete "
        f"cases={result['scenarioCount']} "
        f"allow={summary['allow']} deny={summary['deny']} "
        f"require_approval={summary['requireApproval']} "
        f"full_objectives=0 "
        f"report={report.relative_to(workspace)} "
        f"sha256={result['evidenceSha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
