"""Unit tests for target manifests, config materialization and Git snapshots."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from security_patch_validator.execution import load_config
from security_patch_validator.patch_analysis.diff_analyzer import analyze_diff
from security_patch_validator.targets import (
    TargetError,
    load_target,
    materialize_execution_config,
    prepare_git_repo,
    reference_test_map,
)

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("bzip2", "tlvparse")


class ManifestTests(unittest.TestCase):
    def test_all_targets_load(self):
        for name in TARGETS:
            target = load_target(ROOT / "targets" / name / "target.json")
            self.assertEqual(target.target_id, name)
            self.assertEqual(set(target.versions), {"base", "correct", "incomplete", "regression"})
            self.assertEqual(set(target.scenarios), {"correct", "incomplete", "regression"})
            self.assertTrue(target.reference_tests.is_file())

    def test_real_world_target_exists(self):
        targets = [load_target(ROOT / "targets" / name / "target.json") for name in TARGETS]
        self.assertTrue(any(target.real_world for target in targets))

    def test_materialized_config_is_valid(self):
        for name in TARGETS:
            target = load_target(ROOT / "targets" / name / "target.json")
            for scenario in ("correct", "incomplete", "regression"):
                with tempfile.TemporaryDirectory() as directory:
                    path = materialize_execution_config(
                        target, scenario, Path(directory) / "config.json",
                    )
                    config = load_config(path)
                    self.assertEqual(config.target_id, name)
                    self.assertEqual(config.versions["patched"].source_dir,
                                     target.versions[target.scenarios[scenario]["patched_version"]].source_dir)

    def test_checked_in_configs_match_manifests(self):
        for name in TARGETS:
            target = load_target(ROOT / "targets" / name / "target.json")
            for scenario in ("correct", "incomplete", "regression"):
                path = ROOT / "configs" / name / f"{scenario}.json"
                self.assertTrue(path.is_file(), path)
                config = load_config(path)
                self.assertEqual(config.target_id, target.target_id)
                self.assertEqual(
                    config.versions["patched"].source_dir,
                    target.versions[target.scenarios[scenario]["patched_version"]].source_dir,
                )
                expected_ids = [test["id"] for test in target.execution["tests"]]
                self.assertEqual([test.test_id for test in config.tests], expected_ids)

    def test_reference_test_map(self):
        for name in TARGETS:
            target = load_target(ROOT / "targets" / name / "target.json")
            mapping = reference_test_map(target)
            execution_ids = {test["id"] for test in target.execution["tests"]}
            self.assertEqual(set(mapping), execution_ids)

    def test_missing_version_is_rejected(self):
        target_path = ROOT / "targets" / "tlvparse" / "target.json"
        raw = json.loads(target_path.read_text())
        del raw["versions"]["regression"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.json"
            path.write_text(json.dumps(raw))
            with self.assertRaises(TargetError):
                load_target(path)


class GitSnapshotTests(unittest.TestCase):
    def test_snapshot_hashes_are_deterministic_and_diff_is_standalone(self):
        target = load_target(ROOT / "targets" / "tlvparse" / "target.json")
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            hashes_a = prepare_git_repo(target, first)
            hashes_b = prepare_git_repo(target, second)
            self.assertEqual(hashes_a, hashes_b)
            diff = analyze_diff(Path(first) / "repo", hashes_a["base"], hashes_a["correct"])
            changed = [entry["new_path"] for entry in diff["files"]]
            self.assertIn("tlvparse.c", changed)
            # Each patched commit is a direct child of base, so the incomplete
            # diff must not contain the correct patch as well.
            incomplete = analyze_diff(Path(first) / "repo", hashes_a["base"], hashes_a["incomplete"])
            self.assertIn("tlvparse.c", [entry["new_path"] for entry in incomplete["files"]])


if __name__ == "__main__":
    unittest.main()
