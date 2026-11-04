import ast
import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
EXPECTED_QWEN_PROFILES = {
    "guardian-agent-qwen-lab-email-v1",
    "guardian-agent-qwen-lab-database-v1",
    "guardian-agent-qwen-lab-finance-v1",
    "guardian-agent-qwen-lab-customer-service-v1",
    "guardian-agent-qwen-lab-programming-v1",
    "guardian-agent-qwen-lab-browser-v1",
    "guardian-agent-qwen-lab-infrastructure-v1",
    "guardian-agent-qwen-lab-multiagent-v1",
}
EXPECTED_FIXTURE_PROFILES = {
    profile.replace("guardian-agent-qwen-lab-", "guardian-agent-lab-")
    for profile in EXPECTED_QWEN_PROFILES
}


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _ts_string_array(relative_path: str, export_name: str) -> list[str]:
    source = _read(relative_path)
    match = re.search(
        rf"export const {re.escape(export_name)}\s*=\s*\[(.*?)\]\s*as const",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise AssertionError(f"missing TypeScript profile array: {export_name}")
    return re.findall(r'"([^"]+)"', match.group(1))


def _python_assignments(relative_path: str) -> dict[str, ast.AST]:
    tree = ast.parse(_read(relative_path), filename=relative_path)
    assignments: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
    return assignments


def _string_values(node: ast.AST) -> list[str]:
    if not isinstance(node, (ast.Tuple, ast.List)):
        raise AssertionError("profile contract must be a literal tuple or list")
    values = [item.value for item in node.elts if isinstance(item, ast.Constant)]
    if len(values) != len(node.elts) or any(not isinstance(value, str) for value in values):
        raise AssertionError("profile contract contains a non-string value")
    return values


def _literal_string_keys(node: ast.AST) -> set[str]:
    if not isinstance(node, ast.Dict):
        raise AssertionError("profile map must be a literal dictionary")
    keys = {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    if len(keys) != len(node.keys):
        raise AssertionError("profile map contains a non-literal string key")
    return keys


class CrossLayerQwenContractTests(unittest.TestCase):
    def test_eight_qwen_profile_ids_match_api_worker_runner_and_sdks(self):
        sources: dict[str, list[str]] = {
            "API sandbox": _ts_string_array(
                "artifacts/api-server/src/lib/ai-assessment-sandbox.ts",
                "QWEN_POLICY_LAB_PROFILE_IDS",
            ),
            "TypeScript SDK": _ts_string_array(
                "lib/guardian-agent-sdk/src/index.ts",
                "QWEN_AGENT_PROFILE_IDS",
            ),
            "Python SDK": _string_values(
                _python_assignments(
                    "lib/guardian-agent-sdk-python/src/guardian_nexus_sdk/client.py"
                )["QWEN_AGENT_PROFILE_IDS"]
            ),
        }

        worker_source = _read("artifacts/api-server/src/lib/ai-assessment-worker.ts")
        sources["API worker"] = re.findall(
            r'QWEN_[A-Z_]+_POLICY_PROFILE_ID\s*=\s*"([^"]+)"',
            worker_source,
        )

        qwen_assignments = _python_assignments(
            "workers/guardian-ai-assessment/guardian_ai_assessment/qwen_policy_lab.py"
        )
        qwen_profile_names = (
            "EMAIL_PROFILE",
            "DATABASE_PROFILE",
            "FINANCE_PROFILE",
            "SUPPORT_PROFILE",
            "PROGRAMMING_PROFILE",
            "BROWSER_PROFILE",
            "INFRASTRUCTURE_PROFILE",
            "MULTIAGENT_PROFILE",
        )
        sources["Python Qwen worker"] = [
            qwen_assignments[name].value
            for name in qwen_profile_names
            if name in qwen_assignments
            and isinstance(qwen_assignments[name], ast.Constant)
            and isinstance(qwen_assignments[name].value, str)
        ]
        runner_assignments = _python_assignments(
            "workers/guardian-ai-assessment/guardian_ai_assessment/offline_qwen_runner.py"
        )
        sources["offline runner"] = _string_values(
            runner_assignments["_PROFILE_ORDER"]
        )

        for component, profile_ids in sources.items():
            with self.subTest(component=component):
                self.assertEqual(len(profile_ids), 8, component)
                self.assertEqual(len(set(profile_ids)), 8, component)
                self.assertEqual(set(profile_ids), EXPECTED_QWEN_PROFILES, component)

        self.assertEqual(
            _literal_string_keys(runner_assignments["_OFFLINE_CASE_IDS"]),
            EXPECTED_QWEN_PROFILES,
        )
        offline_case_map = runner_assignments["_OFFLINE_CASE_IDS"]
        self.assertIsInstance(offline_case_map, ast.Dict)
        selected_case_ids: set[str] = set()
        for value in offline_case_map.values:
            selected_case_ids.update(_string_values(value))
        qwen_source = ast.parse(
            _read(
                "workers/guardian-ai-assessment/guardian_ai_assessment/qwen_policy_lab.py"
            )
        )
        qwen_string_literals = {
            node.value
            for node in ast.walk(qwen_source)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        self.assertEqual(len(selected_case_ids), 8)
        self.assertTrue(selected_case_ids.issubset(qwen_string_literals))

    def test_eight_fixture_profiles_are_the_matching_verticals(self):
        api_fixture_ids = set(
            _ts_string_array(
                "artifacts/api-server/src/lib/ai-assessment-sandbox.ts",
                "POLICY_LAB_PROFILE_IDS",
            )
        )
        assignments = _python_assignments(
            "workers/guardian-ai-assessment/guardian_ai_assessment/policy_lab.py"
        )
        profile_mapping = assignments["PROFILE_TO_VERTICAL"]
        self.assertIsInstance(profile_mapping, ast.Dict)
        worker_fixture_ids = {
            key.value
            for key in profile_mapping.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        self.assertEqual(len(api_fixture_ids), 8)
        self.assertEqual(api_fixture_ids, EXPECTED_FIXTURE_PROFILES)
        self.assertEqual(worker_fixture_ids, EXPECTED_FIXTURE_PROFILES)


if __name__ == "__main__":
    unittest.main()
