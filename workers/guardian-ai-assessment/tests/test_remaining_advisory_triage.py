from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from generate_remaining_advisory_triage import (  # noqa: E402
    build_triage,
    critical_high_ids,
    route_assessment,
)


class RemainingAdvisoryTriageTests(unittest.TestCase):
    def test_critical_high_exclusion_is_explicit(self) -> None:
        audit = "\n".join(
            [
                "| Critical 9.8 | `DEBIAN-CVE-2099-0001` |",
                "| High 7.5 | `DEBIAN-CVE-2099-0002` |",
                "| Moderate 5.0 | `DEBIAN-CVE-2099-0003` |",
            ]
        )
        self.assertEqual(
            critical_high_ids(audit),
            {"DEBIAN-CVE-2099-0001", "DEBIAN-CVE-2099-0002"},
        )

    def test_routes_do_not_claim_exploitability(self) -> None:
        route = route_assessment({"util-linux"})
        self.assertEqual(route["priority"], "P2-installed-command-or-service")
        self.assertIn("no encontró una invocación directa", route["route"])
        self.assertIn("no prueba", route["route"])

    def test_runtime_library_route_is_conservative(self) -> None:
        route = route_assessment({"glibc"})
        self.assertEqual(route["priority"], "P1-runtime-library")
        self.assertIn("función concreta", route["route"])

    def test_wrong_review_count_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "Expected 81 reviewed IDs"):
            build_triage({"records": []}, "")


if __name__ == "__main__":
    unittest.main()
