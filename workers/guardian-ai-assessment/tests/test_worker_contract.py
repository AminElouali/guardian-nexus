import json
import unittest
from pathlib import Path

WORKER_ROOT = Path(__file__).resolve().parents[1]


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

    def test_runtime_dependencies_do_not_install_model_providers(self):
        requirements = (
            WORKER_ROOT / "requirements-runtime.txt"
        ).read_text().splitlines()
        forbidden = ("torch", "transformers", "openai", "anthropic", "cohere")
        self.assertFalse(
            [line for line in requirements if line and line.startswith(forbidden)]
        )

    def test_docker_launcher_enforces_isolation_and_resource_caps(self):
        launcher = (WORKER_ROOT / "scripts/run-local.sh").read_text()
        for option in (
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


if __name__ == "__main__":
    unittest.main()
