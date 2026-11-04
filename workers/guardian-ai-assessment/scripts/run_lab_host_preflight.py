#!/usr/bin/env python3
"""Fail-closed lab check; default is metadata-only and never starts Qwen/Docker/DB."""

from __future__ import annotations

import json
import sys
import argparse

from pathlib import Path

workspace = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(workspace / "workers/guardian-ai-assessment"))

from guardian_ai_assessment.lab_host_preflight import collect_local_preflight_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe-database",
        action="store_true",
        help="On the authorized Ubuntu lab only, use local peer-auth psql service profiles.",
    )
    parser.add_argument(
        "--probe-worker-child",
        action="store_true",
        help="On the authorized Ubuntu lab only, run a no-model identity probe as guardian-worker.",
    )
    args = parser.parse_args()
    report = collect_local_preflight_report(
        probe_database=args.probe_database,
        probe_worker_child=args.probe_worker_child,
    )
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["integratedAssessmentReady"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
