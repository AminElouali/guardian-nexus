#!/usr/bin/env python3
"""Reaggregate one pinned historical artifact; never runs a model or writes input."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from guardian_ai_assessment.qwen_evidence_reconciliation import (
    EvidenceReconciliationError,
    reconcile_historical_artifact,
)


def main() -> int:
    workspace = Path(__file__).resolve().parents[3]
    source = (
        workspace
        / "generated-artifacts"
        / "guardian-qwen-policy-labs-e2e-v1.10.0.json"
    )
    try:
        report = reconcile_historical_artifact(source)
    except EvidenceReconciliationError as error:
        print(
            json.dumps(
                {"status": "blocked", "reasonCode": str(error)},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 1
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
