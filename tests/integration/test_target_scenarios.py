"""End-to-end target scenario test (Linux x86_64, opt-in).

Set ``SPV_TARGET_SCENARIOS=1`` to run the three tlvparse scenarios.  The test
builds release and sanitized binaries, runs 3 repetitions, minimizes both
security inputs, and writes regression tests.  It intentionally stays opt-in so
the normal unit test run stays fast.
"""

from __future__ import annotations

import os
import platform
import tempfile
import unittest
from pathlib import Path

from security_patch_validator.targets import run_scenario

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(
    platform.system() == "Linux" and platform.machine() == "x86_64",
    "dynamic target execution requires Linux x86_64",
)
@unittest.skipUnless(
    os.environ.get("SPV_TARGET_SCENARIOS") == "1",
    "set SPV_TARGET_SCENARIOS=1 to run the slow target scenarios",
)
class TargetScenarioTests(unittest.TestCase):
    def test_tlvparse_three_scenarios(self):
        target = ROOT / "targets" / "tlvparse" / "target.json"
        results = {}
        with tempfile.TemporaryDirectory() as directory:
            for scenario, expected_code in (
                ("correct", 0),
                ("incomplete", 10),
                ("regression", 20),
            ):
                with self.subTest(scenario=scenario):
                    result = run_scenario(
                        target, scenario,
                        artifacts_dir=Path(directory) / scenario,
                        repetitions=3,
                    )
                    results[scenario] = result
                    self.assertTrue(result["matches_expected_exit_code"], result["classification"])
                    self.assertEqual(result["observed_exit_code"], expected_code)
                    self.assertTrue(result["reproducers"]["bundles"])

        self.assertEqual(results["correct"]["classification"]["statuses"], ["FIXED"])
        self.assertIn("INCOMPLETE_FIX", results["incomplete"]["classification"]["statuses"])
        self.assertIn("FUNCTIONAL_REGRESSION", results["regression"]["classification"]["statuses"])

        # The correct scenario's regression test must pass on both versions.
        for bundle in results["correct"]["reproducers"]["bundles"]:
            self.assertEqual(bundle["regression_validation"], "PASS")
        # The incomplete scenario's alternate input must remain exploitable.
        alternate = next(
            bundle for bundle in results["incomplete"]["reproducers"]["bundles"]
            if bundle["test_id"] == "SEC-ALTERNATE"
        )
        self.assertEqual(alternate["regression_validation"], "VULN_REMAINS")


if __name__ == "__main__":
    unittest.main()
