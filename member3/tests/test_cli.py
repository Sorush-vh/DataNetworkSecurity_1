
import json
import tempfile
import unittest
from modules.cli.cli import evaluate_regression_result
from pathlib import Path

from modules.cli.cli import (
    create_report,
    save_report,
    EXIT_CODES
)


class TestCLI(unittest.TestCase):

    def test_pass_status(self):
        report = create_report("PASS", "PASS", "PASS")

        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["exit_code"], 0)

    def test_vulnerability_priority(self):
        report = create_report(
            "VULN_REMAINS",
            "FUNC_REGRESSION",
            "PASS"
        )

        self.assertEqual(report["status"], "VULN_REMAINS")
        self.assertEqual(report["exit_code"], 10)

    def test_build_error_priority(self):
        report = create_report(
            "VULN_REMAINS",
            "FUNC_REGRESSION",
            "BUILD_OR_CONFIG_ERROR"
        )

        self.assertEqual(report["status"], "BUILD_OR_CONFIG_ERROR")
        self.assertEqual(report["exit_code"], 30)

    def test_inconclusive_status(self):
        report = create_report(
            "INCONCLUSIVE",
            "PASS",
            "INCONCLUSIVE"
        )

        self.assertEqual(report["status"], "INCONCLUSIVE")
        self.assertEqual(report["exit_code"], 40)

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "report.json"

            report = create_report("PASS", "PASS", "PASS")
            save_report(report, output)

            self.assertTrue(output.exists())

            with open(output, encoding="utf-8") as file:
                loaded = json.load(file)

            self.assertEqual(loaded["status"], "PASS")
            self.assertEqual(loaded["exit_code"], EXIT_CODES["PASS"])
    def test_rejects_invalid_status(self):
        with self.assertRaises(ValueError):
            create_report(
                "UNKNOWN",
                "PASS",
                "PASS"
            )

    def test_rejects_non_dictionary_details(self):
        with self.assertRaises(ValueError):
            create_report(
                "PASS",
                "PASS",
                "PASS",
                details="invalid"
            )



    def test_regression_pass_result(self):
        result = {
            "status": "PASS",
            "stability": {
                "overall": "STABLE"
            },
            "base": {
                "matches_expected_error": True
            },
            "patched": {
                "same_error_absent": True,
                "expected_behavior": True
            }
        }

        security, functional = evaluate_regression_result(result)

        self.assertEqual(security, "PASS")
        self.assertEqual(functional, "PASS")

    def test_regression_flaky_result(self):
        result = {
            "status": "INCONCLUSIVE",
            "stability": {
                "overall": "FLAKY"
            }
        }

        security, functional = evaluate_regression_result(result)

        self.assertEqual(security, "INCONCLUSIVE")
        self.assertEqual(functional, "INCONCLUSIVE")


    def test_regression_vulnerability_remains(self):
        result = {
            "status": "FAIL",
            "stability": {
                "overall": "STABLE"
            },
            "base": {"matches_expected_error": True},
            "patched": {
                "same_error_absent": False,
                "expected_behavior": False
            }
        }

        security, functional = evaluate_regression_result(result)

        self.assertEqual(security, "VULN_REMAINS")
        self.assertEqual(functional, "PASS")

    def test_regression_functional_failure(self):
        result = {
            "status": "FAIL",
            "stability": {
                "overall": "STABLE"
            },
            "base": {"matches_expected_error": True},
            "patched": {
                "same_error_absent": True,
                "expected_behavior": False
            }
        }

        security, functional = evaluate_regression_result(result)

        self.assertEqual(security, "PASS")
        self.assertEqual(functional, "FUNC_REGRESSION")


if __name__ == "__main__":
    unittest.main()
