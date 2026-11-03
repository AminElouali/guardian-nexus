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
        self.assertEqual(manifest["verificationSuite"]["sampleCount"], 144)
        self.assertEqual(
            manifest["verificationSuite"]["samplesPerSplit"], 72
        )
        self.assertEqual(
            manifest["verificationSuite"]["maxRuntimeSeconds"], 15
        )
        self.assertFalse(manifest["verificationSuite"]["realLlmInference"])
        self.assertFalse(manifest["verificationSuite"]["importedAgentDojoCodeOrDataset"])
        self.assertEqual(manifest["verificationSuite"]["externalCalls"], 0)

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
        ).read_text()
        self.assertIn(
            "aiohttp==3.14.5 \\\n    --hash=sha256:",
            requirements,
        )
        self.assertIn(
            "nltk==3.10.4 \\\n    --hash=sha256:",
            requirements,
        )
        self.assertIn(
            "requests==2.34.2 \\\n    --hash=sha256:",
            requirements,
        )
        dockerfile = (WORKER_ROOT / "Dockerfile").read_text()
        self.assertIn("--require-hashes", dockerfile)
        self.assertIn("requirements-build.txt", dockerfile)

    def test_runtime_and_build_requirements_have_sha256_hashes(self):
        for filename, expected_count in (
            ("requirements-runtime.txt", 36),
            ("requirements-build.txt", 2),
        ):
            lines = (WORKER_ROOT / filename).read_text().splitlines()
            entries = [
                index
                for index, line in enumerate(lines)
                if "==" in line and not line.lstrip().startswith("#")
            ]
            self.assertEqual(len(entries), expected_count)
            for index in entries:
                self.assertTrue(lines[index].endswith("\\"))
                self.assertRegex(
                    lines[index + 1].strip(),
                    r"--hash=sha256:[0-9a-f]{64}$",
                )

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
        self.assertIn("--verification-suite", launcher)
        self.assertIn("--unit-tests", launcher)

    def test_unit_test_runner_pins_image_and_mounts_one_read_only_checkout(self):
        launcher = (WORKER_ROOT / "scripts/run-local.sh").read_text()
        self.assertIn("profile-image-lock.json", launcher)
        self.assertIn("docker image inspect --format '{{.Id}}' \"$IMAGE\"", launcher)
        self.assertIn('EXPECTED_IMAGE_ID', launcher)
        self.assertIn(
            '--mount "type=bind,src=$WORKER_ROOT,dst=/opt/guardian-assessment,readonly"',
            launcher,
        )
        self.assertIn("--workdir=/opt/guardian-assessment", launcher)
        self.assertIn("image_id_mismatch", launcher)

    def test_report_parser_checks_garak_eval_and_binary_scores(self):
        report = "\n".join(
            [
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 1,
                        "detector_results": {},
                    }
                ),
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "detector_results": {
                            "promptinject.AttackRogueString": [1.0, 0.0, 1.0]
                        },
                    }
                ),
                json.dumps(
                    {
                        "entry_type": "eval",
                        "probe": "promptinject.HijackHateHumans",
                        "detector": "promptinject.AttackRogueString",
                        "passed": 1,
                        "fails": 2,
                        "nones": 0,
                        "total_evaluated": 3,
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
                    "detector": "promptinject.AttackRogueString",
                    "positiveScores": 2,
                    "scoreThreshold": 0.5,
                },
            ],
        )
        self.assertEqual(evidence["evaluation"]["total_evaluated"], 3)

    def test_report_parser_rejects_disagreement_with_garak_evaluator(self):
        report = "\n".join(
            [
                json.dumps(
                    {
                        "entry_type": "attempt",
                        "status": 2,
                        "detector_results": {
                            "promptinject.AttackRogueString": [1.0]
                        },
                    }
                ),
                json.dumps(
                    {
                        "entry_type": "eval",
                        "probe": "promptinject.HijackHateHumans",
                        "detector": "promptinject.AttackRogueString",
                        "passed": 1,
                        "fails": 0,
                        "nones": 0,
                        "total_evaluated": 1,
                    }
                ),
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "mismatched.report.jsonl"
            report_path.write_text(report, encoding="utf-8")
            with self.assertRaisesRegex(
                RuntimeError, "garak_report_score_eval_mismatch"
            ):
                _parse_report(report_path)

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
