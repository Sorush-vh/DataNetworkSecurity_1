
import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
import sys
from modules.regression.regression import validate_regression_test
from modules.regression.regression import generate_regression_test


class TestRegression(unittest.TestCase):

    def test_generates_regression_test(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            minimized_input = root / "minimized.input"
            minimized_input.write_bytes(b"CRASH")

            output_dir = root / "regression"

            result = generate_regression_test(
                minimized_input=minimized_input,
                test_name="crash_test",
                error_type="AddressSanitizer",
                output_dir=output_dir
            )

            self.assertTrue(result.exists())
            self.assertEqual(result.read_bytes(), b"CRASH")

            manifest_path = output_dir / "regression_tests.json"

            with open(manifest_path, encoding="utf-8") as file:
                manifest = json.load(file)

            self.assertEqual(len(manifest["tests"]), 1)
            self.assertEqual(manifest["tests"][0]["name"], "crash_test")
            self.assertEqual(
                manifest["tests"][0]["error_type"],
                "AddressSanitizer"
            )
            self.assertTrue(manifest["tests"][0]["expected_on_base"])
            self.assertFalse(manifest["tests"][0]["expected_on_patched"])

    def test_rejects_duplicate_test(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            minimized_input = root / "minimized.input"
            minimized_input.write_bytes(b"CRASH")

            output_dir = root / "regression"

            generate_regression_test(
                minimized_input,
                "crash_test",
                "AddressSanitizer",
                output_dir
            )

            with self.assertRaises(ValueError):
                generate_regression_test(
                    minimized_input,
                    "crash_test",
                    "AddressSanitizer",
                    output_dir
                )

    def test_validates_base_and_patched_versions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "test.input"
            input_file.write_text("test input")

            result = validate_regression_test(
                input_file=input_file,
                base_command=[
                    sys.executable,
                    "-c",
                    "import sys; print('AddressSanitizer: heap-buffer-overflow', file=sys.stderr); sys.exit(1)"
                ],
                patched_command=[
                    sys.executable,
                    "-c",
                    "print('OK')"
                ],
                expected_error_type="ADDRESS_SANITIZER"
            )

            self.assertEqual(result["status"], "PASS")
            self.assertTrue(result["base"]["matches_expected_error"])
            self.assertTrue(result["patched"]["expected_behavior"])


    @patch("modules.regression.regression.replay")
    def test_flaky_base_returns_inconclusive(self, mock_replay):
        base_results = [
            {
                "error_type": "ADDRESS_SANITIZER",
                "stderr": "AddressSanitizer: heap-buffer-overflow",
                "returncode": 1,
                "timed_out": False
            },
            {
                "error_type": "ADDRESS_SANITIZER",
                "stderr": "AddressSanitizer: heap-buffer-overflow",
                "returncode": 1,
                "timed_out": False
            },
            {
                "error_type": None,
                "stderr": "",
                "returncode": 0,
                "timed_out": False
            }
        ]

        patched_results = [
            {
                "error_type": None,
                "stderr": "",
                "returncode": 0,
                "timed_out": False
            }
            for _ in range(3)
        ]

        mock_replay.side_effect = [
            {"status": "FLAKY", "repetitions": 3, "results": base_results},
            {"status": "STABLE", "repetitions": 3, "results": patched_results}
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "test.input"
            input_file.write_text("test input")

            result = validate_regression_test(
                input_file=input_file,
                base_command=["base"],
                patched_command=["patched"],
                expected_error_type="ADDRESS_SANITIZER"
            )

        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["stability"]["base"], "FLAKY")
        self.assertEqual(result["stability"]["patched"], "STABLE")

    @patch("modules.regression.regression.replay")
    def test_stable_replays_return_pass(self, mock_replay):
        base_results = [
            {
                "error_type": "ADDRESS_SANITIZER",
                "stderr": "AddressSanitizer: heap-buffer-overflow",
                "returncode": 1,
                "timed_out": False
            }
            for _ in range(3)
        ]

        patched_results = [
            {
                "error_type": None,
                "stderr": "",
                "returncode": 0,
                "timed_out": False
            }
            for _ in range(3)
        ]

        mock_replay.side_effect = [
            {"status": "STABLE", "repetitions": 3, "results": base_results},
            {"status": "STABLE", "repetitions": 3, "results": patched_results}
        ]

        with tempfile.TemporaryDirectory() as temp_dir:
            input_file = Path(temp_dir) / "test.input"
            input_file.write_text("test input")

            result = validate_regression_test(
                input_file=input_file,
                base_command=["base"],
                patched_command=["patched"],
                expected_error_type="ADDRESS_SANITIZER"
            )

        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["repetitions"], 3)
        self.assertEqual(result["stability"]["overall"], "STABLE")



if __name__ == "__main__":
    unittest.main()
