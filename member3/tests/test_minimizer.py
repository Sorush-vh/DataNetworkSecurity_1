
import unittest

from modules.minimizer.delta_debugging import (
    delta_debug,
    delta_debug_with_report
)


class TestDeltaDebugging(unittest.TestCase):

    def test_minimizes_input(self):
        original = b"AAAA_CRASH_BBBBB"

        def test_function(data):
            return b"CRASH" in data

        minimized = delta_debug(original, test_function)

        self.assertIn(b"CRASH", minimized)
        self.assertEqual(minimized, b"CRASH")

    def test_preserves_input_when_no_failure(self):
        original = b"SAFE_INPUT"

        def test_function(data):
            return False

        minimized = delta_debug(original, test_function)

        self.assertEqual(minimized, original)

    def test_report_contains_minimization_statistics(self):
        original = b"AAAA_CRASH_BBBBB"

        def test_function(data):
            return b"CRASH" in data

        report = delta_debug_with_report(original, test_function)

        self.assertEqual(report["status"], "MINIMIZED")
        self.assertEqual(report["original"], original)
        self.assertEqual(report["minimized"], b"CRASH")
        self.assertTrue(report["validated"])
        self.assertGreater(report["test_count"], 0)
        self.assertEqual(report["original_size"], len(original))
        self.assertEqual(report["minimized_size"], 5)
        self.assertGreater(report["reduction_ratio"], 0)

    def test_rejects_input_without_reproducible_failure(self):
        original = b"SAFE_INPUT"

        def test_function(data):
            return False

        report = delta_debug_with_report(original, test_function)

        self.assertEqual(
            report["status"],
            "FAILURE_NOT_REPRODUCED"
        )
        self.assertEqual(report["minimized"], original)
        self.assertFalse(report["validated"])

    def test_empty_input(self):
        report = delta_debug_with_report(
            b"",
            lambda data: True
        )

        self.assertEqual(report["status"], "EMPTY_INPUT")
        self.assertEqual(report["minimized"], b"")
        self.assertFalse(report["validated"])

    def test_minimized_input_is_revalidated(self):
        calls = []

        def test_function(data):
            calls.append(data)

            # The first execution succeeds, but subsequent
            # executions simulate a failure disappearing.
            return len(calls) == 1

        report = delta_debug_with_report(
            b"ORIGINAL_INPUT",
            test_function
        )

        self.assertEqual(report["status"], "VALIDATION_FAILED")
        self.assertFalse(report["validated"])
        self.assertGreaterEqual(report["test_count"], 2)


if __name__ == "__main__":
    unittest.main()
