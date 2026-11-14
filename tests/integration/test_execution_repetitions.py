"""Integration test for the backward-compatible execution repetitions."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from security_patch_validator.execution import load_config, run_suite


@unittest.skipUnless(
    shutil.which("gcc") and shutil.which("readelf"),
    "requires GCC and GNU readelf on Linux x86_64",
)
class RepetitionTests(unittest.TestCase):
    def test_repetitions_multiply_observations_without_rebuilding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = '#include <stdio.h>\nint main(void){puts("ok");return 0;}\n'
            for label in ("base", "patched"):
                folder = root / label
                folder.mkdir()
                (folder / "main.c").write_text(source, encoding="utf-8")
            config = {
                "target_id": "repetition-fixture",
                "versions": {
                    "base": {"source_dir": "base"},
                    "patched": {"source_dir": "patched"},
                },
                "build": {"binary": "app", "commands": [
                    ["gcc", "{flags}", "main.c", "-o", "{binary}"],
                ]},
                "limits": {"timeout": 3, "build_timeout": 20, "max_output_bytes": 65536},
                "tests": [{
                    "id": "valid",
                    "category": "valid",
                    "input": {"mode": "argv"},
                    "args": [],
                    "expected": {"exit_code": 0, "stdout": "ok\n", "stderr": ""},
                    "reference": "docs/execution.md",
                }],
            }
            path = root / "config.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            report = run_suite(load_config(path), repetitions=3)

        self.assertEqual(report["repetitions"], 3)
        self.assertEqual(report["status"], "completed")
        # One test x two versions x two build types x three repetitions.
        self.assertEqual(len(report["executions"]), 12)
        counts = Counter(
            (run["test_id"], run["version"], run["build_type"])
            for run in report["executions"]
        )
        self.assertEqual(set(counts.values()), {3})
        self.assertTrue(all(run["expectation"]["status"] == "pass" for run in report["executions"]))


if __name__ == "__main__":
    unittest.main()
