from __future__ import annotations

import os
import re
import subprocess
import unittest
from pathlib import Path


LAB_KIT = (
    Path(__file__).resolve().parents[1]
    / "deployment"
    / "lab-as-code"
)


class LabAsCodeGuardTests(unittest.TestCase):
    def _run_guarded_script(self, script: str, extra_env: dict[str, str] | None = None):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", str(LAB_KIT / "scripts" / script)],
            cwd=LAB_KIT,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

    def test_mutating_or_database_script_requires_explicit_ack(self):
        for script in (
            "provision-worker-login.sh",
            "verify-db-identities.sh",
        ):
            with self.subTest(script=script):
                result = self._run_guarded_script(script)
                self.assertEqual(result.returncode, 64)
                self.assertIn("explicit_lab_ack_required", result.stderr)

    def test_production_database_name_is_rejected_before_psql(self):
        for script, ack in (
            ("provision-worker-login.sh", "provision-worker-login"),
            ("verify-db-identities.sh", "verify-local-lab-db"),
        ):
            with self.subTest(script=script):
                result = self._run_guarded_script(
                    script,
                    {
                        "GUARDIAN_LAB_ACK": ack,
                        "GUARDIAN_LAB_DB": "production",
                    },
                )
                self.assertEqual(result.returncode, 64)
                self.assertIn("database_name_must_start_guardian_lab_", result.stderr)

    def test_shell_templates_parse_without_running_host_checks(self):
        for script in (
            "preflight-host.sh",
            "provision-worker-login.sh",
            "verify-db-identities.sh",
        ):
            with self.subTest(script=script):
                result = subprocess.run(
                    ["bash", "-n", str(LAB_KIT / "scripts" / script)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_role_template_has_no_password_material(self):
        sql = (LAB_KIT / "sql" / "provision-worker-login.sql").read_text()
        env_example = (LAB_KIT / ".env.example").read_text()
        self.assertIsNone(
            re.search(r"\bPASSWORD\s+(?:'[^']*'|\"[^\"]*\")", sql, re.IGNORECASE)
        )
        self.assertIsNone(
            re.search(r"\bPASSWORD\s*=", sql, re.IGNORECASE)
        )
        self.assertIsNone(
            re.search(
                r"(?im)^[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|DATABASE_URL)[A-Z0-9_]*\s*=\s*\S+",
                env_example,
            )
        )


if __name__ == "__main__":
    unittest.main()
