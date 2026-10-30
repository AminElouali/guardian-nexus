import unittest
from collections import Counter, defaultdict

from guardian_ai_assessment.corpus_validation import (
    build_corpus,
    run_corpus_validation,
)


class CorpusValidationTests(unittest.TestCase):
    def test_corpus_is_balanced_and_holdout_is_distinct(self):
        corpus = build_corpus()
        self.assertEqual(len(corpus), 128)
        self.assertEqual(len({sample["sampleId"] for sample in corpus}), 128)

        prompts_by_split = defaultdict(set)
        for sample in corpus:
            prompts_by_split[sample["split"]].add(sample["prompt"])
        self.assertTrue(
            prompts_by_split["calibration"].isdisjoint(prompts_by_split["holdout"])
        )

        groups = defaultdict(list)
        for sample in corpus:
            groups[(sample["dataset"], sample["split"])].append(sample)
        self.assertEqual(len(groups), 4)
        for group, samples in groups.items():
            with self.subTest(group=group):
                self.assertEqual(len(samples), 32)
                self.assertEqual(
                    Counter(sample["expectedPositive"] for sample in samples),
                    {True: 16, False: 16},
                )
                self.assertEqual(
                    Counter(sample["language"] for sample in samples),
                    {"en": 16, "es": 16},
                )
                self.assertTrue(all(sample["synthetic"] for sample in samples))
                self.assertTrue(
                    all(
                        sample["targetType"] == "deterministic-local-fixture"
                        for sample in samples
                    )
                )

    def test_garak_detector_metrics_are_split_by_task_not_mixed(self):
        report = run_corpus_validation()

        self.assertEqual(report["corpus"]["sampleCount"], 128)
        self.assertFalse(report["execution"]["fullGarakCliRun"])
        self.assertFalse(report["execution"]["llmInference"])
        self.assertFalse(report["execution"]["networkAccess"])
        self.assertEqual(len(report["metrics"]), 4)

        expected = {
            ("attack_success", "calibration"): (16, 6, 10, 0),
            ("attack_success", "holdout"): (16, 6, 10, 0),
            ("canary_propagation", "calibration"): (6, 8, 8, 10),
            ("canary_propagation", "holdout"): (6, 8, 8, 10),
        }
        for row in report["metrics"]:
            key = (row["dataset"], row["split"])
            with self.subTest(group=key):
                tp, fp, tn, fn = expected[key]
                self.assertEqual(row["sampleCount"], 32)
                self.assertEqual(row["positiveSupport"], 16)
                self.assertEqual(row["negativeSupport"], 16)
                self.assertEqual(row["truePositive"], tp)
                self.assertEqual(row["falsePositive"], fp)
                self.assertEqual(row["trueNegative"], tn)
                self.assertEqual(row["falseNegative"], fn)

    def test_evidence_contains_hashes_but_not_prompt_or_response_text(self):
        report = run_corpus_validation()
        self.assertEqual(len(report["cases"]), 128)
        for row in report["cases"]:
            self.assertIn("inputSha256", row)
            self.assertIn("responseSha256", row)
            self.assertNotIn("prompt", row)
            self.assertNotIn("response", row)


if __name__ == "__main__":
    unittest.main()
