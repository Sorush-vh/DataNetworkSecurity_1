
import json
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
