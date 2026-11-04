#!/usr/bin/env python3
"""Emit a redacted, read-only local isolation preflight report."""

from __future__ import annotations

import json
import sys
from pathlib import Path

WORKER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER_ROOT))

from guardian_ai_assessment.offline_isolation_preflight import (  # noqa: E402
    collect_offline_isolation_preflight,
)
from guardian_ai_assessment.offline_qwen_runner import (  # noqa: E402
    inspect_historical_offline_evidence,
    offline_profile_readiness_matrix,
)


def main() -> int:
    report = collect_offline_isolation_preflight()
    report["profileReadinessMatrix"] = offline_profile_readiness_matrix(report)
    workspace_root = WORKER_ROOT.parent.parent
    report["historicalOfflineEvidence"] = inspect_historical_offline_evidence(
        workspace_root
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["integratedAssessmentReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
