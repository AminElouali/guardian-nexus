import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

WORKER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER_ROOT))
from guardian_ai_assessment.__main__ import _parse_report, verify_network_isolation


class WorkerContractTests(unittest.TestCase):
    def test_manifest_has_bounded_local_only_profile(self):
        manifest = json.loads((WORKER_ROOT / "manifest.json").read_text())
        self.assertEqual(manifest["target"]["profile"], "guardian-local-agent-v1")
        self.assertFalse(manifest["target"]["publicEndpointsAllowed"])
        self.assertFalse(manifest["target"]["customerDataAllowed"])
        self.assertFalse(manifest["target"]["paidModelsAllowed"])
        self.assertEqual(manifest["limits"]["concurrency"], 1)
        self.assertLessEqual(manifest["limits"]["maxRuntimeSeconds"], 120)
        self.assertEqual(manifest["network"]["runtimeMode"], "docker-network-none")
        self.assertEqual(manifest["network"]["allowedInterfaces"], ["lo"])
        self.assertEqual(manifest["limits"]["probeRequests"], 1)
        self.assertEqual(manifest["engine"]["license"], "Apache-2.0")

    def test_runtime_dependencies_do_not_install_model_providers(self):
        requirements = (
            WORKER_ROOT / "requirements-runtime.txt"
        ).read_text().splitlines()
        forbidden = ("torch", "transformers", "openai", "anthropic", "cohere")
        self.assertFalse(
            [line for line in requirements if line and line.startswith(forbidden)]
        )

    def test_security_sensitive_runtime_packages_are_pinned_to_scanned_fixes(self):
        requirements = (
            WORKER_ROOT / "requirements-runtime.txt"
        ).read_text().splitlines()
        self.assertIn("aiohttp==3.14.5", requirements)
        self.assertIn("nltk==3.10.4", requirements)
        self.assertIn("requests==2.34.2", requirements)

    def test_docker_launcher_enforces_isolation_and_resource_caps(self):
        launcher = (WORKER_ROOT / "scripts/run-local.sh").read_text()
        for option in (
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cpus=0.5",
            "--memory=768m",
            "--memory-swap=768m",
            "--pids-limit=64",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--user=65532:65532",
            "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m",
        ):
            with self.subTest(option=option):
                self.assertIn(option, launcher)
        self.assertIn("caller-supplied Docker flags", launcher)

    def test_report_parser_counts_only_positive_attempt_scores(self):
        report = "\n".join(
            [
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "detector_results": {
                            "detector.one": [0.8, 0.0],
                            "detector.two": [1.0],
                        },
                    }
                ),
                json.dumps(
                    {
                        "entry_type": "eval",
                        "detector_results": {"detector.one": [1.0]},
                    }
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "attempt.report.jsonl"
            report_path.write_text(report, encoding="utf-8")
            evidence = _parse_report(report_path)
        self.assertEqual(evidence["detectorHits"], 2)
        self.assertEqual(
            evidence["findings"],
            [
                {
                    "probeClass": "probes.promptinject.HijackHateHumans",
                    "detector": "detector.one",
                    "positiveScores": 1,
                },
                {
                    "probeClass": "probes.promptinject.HijackHateHumans",
                    "detector": "detector.two",
                    "positiveScores": 1,
                },
            ],
        )

    def test_network_check_fails_closed_on_active_non_loopback_interface(self):
        with (
            patch(
                "guardian_ai_assessment.__main__.os.listdir",
                return_value=["lo", "eth0"],
            ),
            patch.object(Path, "read_text", return_value="0x1"),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "active_non_loopback_interface_present"
            ):
                verify_network_isolation()


if __name__ == "__main__":
    unittest.main()
