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

    def test_host_preflight_checks_both_sides_without_invoking_docker(self):
        source = (LAB_KIT / "scripts" / "preflight-host.sh").read_text()
        self.assertIn('runuser -u "$api_user" -- test -r', source)
        self.assertIn('runuser -u "$api_user" -- test -w', source)
        self.assertIn('runuser -u "$broker_user" -- test -r "$socket"', source)
        self.assertIn('runuser -u "$broker_user" -- test -w "$socket"', source)
        self.assertIn('fail "shared_uid"', source)
        self.assertIn('fail "api_can_access_docker_socket"', source)
        self.assertIn('fail "broker_rootless_daemon_not_running"', source)
        self.assertNotRegex(source, r"(?m)^\s*(docker|dockerd)\s+")
        self.assertNotRegex(source, r"(?m)^\s*(chmod|chown|useradd|usermod|systemctl|psql)\b")

    def test_database_identity_verifier_is_local_read_only_and_checks_forced_rls(self):
        source = (LAB_KIT / "scripts" / "verify-db-identities.sh").read_text()
        self.assertIn("--no-password", source)
        self.assertIn('--host="$socket_dir"', source)
        self.assertIn("session_user = :'expected_login'", source)
        self.assertIn("rolsuper OR rolbypassrls", source)
        self.assertIn("relrowsecurity AND relforcerowsecurity", source)
        self.assertIn("verify_session \"app_runtime_login\"", source)
        self.assertIn("verify_session \"app_ai_assessment_worker_login\"", source)
        self.assertNotRegex(source, r"(?im)^\s*(INSERT|UPDATE|DELETE|ALTER|CREATE|GRANT|REVOKE)\b")

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
