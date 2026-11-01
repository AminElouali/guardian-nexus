import unittest
from unittest.mock import patch

from guardian_ai_assessment.llm_lab import (
    _assert_diskcache_runtime_absent,
    _assert_llama_disk_cache_disabled,
)


class FakeLlama:
    def __init__(self, cache):
        self.cache = cache


class LlamaCachePolicyTests(unittest.TestCase):
    def test_accepts_explicitly_disabled_cache(self):
        _assert_llama_disk_cache_disabled(FakeLlama(None))

    def test_fails_closed_if_any_cache_is_attached(self):
        with self.assertRaisesRegex(
            RuntimeError, "llama_disk_cache_must_remain_disabled"
        ):
            _assert_llama_disk_cache_disabled(FakeLlama(object()))

    def test_fails_closed_if_cache_state_cannot_be_verified(self):
        with self.assertRaisesRegex(RuntimeError, "llama_cache_state_unverifiable"):
            _assert_llama_disk_cache_disabled(object())

    def test_allows_missing_optional_diskcache_runtime(self):
        with patch(
            "guardian_ai_assessment.llm_lab.importlib.util.find_spec",
            return_value=None,
        ):
            _assert_diskcache_runtime_absent()

    def test_fails_closed_if_optional_diskcache_is_present(self):
        with patch(
            "guardian_ai_assessment.llm_lab.importlib.util.find_spec",
            return_value=object(),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "diskcache_runtime_package_must_be_absent"
            ):
                _assert_diskcache_runtime_absent()


if __name__ == "__main__":
    unittest.main()
