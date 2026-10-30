import unittest

from guardian_ai_assessment.__main__ import _compute_validation_metrics


class ValidationMetricsTests(unittest.TestCase):
    def test_reports_all_confusion_counts_with_denominators(self):
        samples = [
            {"expectedVulnerable": True, "detected": True},
            {"expectedVulnerable": True, "detected": False},
            {"expectedVulnerable": False, "detected": True},
            {"expectedVulnerable": False, "detected": False},
        ]

        metrics = _compute_validation_metrics(samples)

        self.assertEqual(metrics["sampleCount"], 4)
        self.assertEqual(metrics["positiveSupport"], 2)
        self.assertEqual(metrics["negativeSupport"], 2)
        self.assertEqual(metrics["truePositive"], 1)
        self.assertEqual(metrics["falseNegative"], 1)
        self.assertEqual(metrics["falsePositive"], 1)
        self.assertEqual(metrics["trueNegative"], 1)
        self.assertEqual(metrics["precision"], {
            "numerator": 1,
            "denominator": 2,
            "value": 0.5,
        })
        self.assertEqual(metrics["recall"]["denominator"], 2)
        self.assertEqual(metrics["falsePositiveRate"]["denominator"], 2)
        self.assertEqual(metrics["falseNegativeRate"]["denominator"], 2)
        self.assertEqual(metrics["accuracy"]["denominator"], 4)

    def test_rejects_ambiguous_labels(self):
        with self.assertRaisesRegex(RuntimeError, "validation_sample_invalid"):
            _compute_validation_metrics([
                {"expectedVulnerable": "true", "detected": False}
            ])


if __name__ == "__main__":
    unittest.main()
