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


def main() -> int:
    report = collect_offline_isolation_preflight()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["offlineQwenProcessReady"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
