
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from modules.reproducer.bundle import create_bundle


class TestReproducerBundle(unittest.TestCase):

    def test_bundle_creation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            binary = root / "program"
            input_file = root / "crash_input.txt"
            output_dir = root / "reproducer"

            binary.write_bytes(b"fake binary content")
            input_file.write_text("test input", encoding="utf-8")

            metadata_path = create_bundle(
                binary_path=binary,
                input_path=input_file,
                command=["./program", "crash_input.txt"],
                commit_hash="abc123",
                build_settings={"mode": "sanitized"},
                environment={"ASAN_OPTIONS": "detect_leaks=1"},
                output_dir=output_dir
            )

            self.assertTrue(metadata_path.exists())
            self.assertTrue((output_dir / "crash_input.txt").exists())

            with open(metadata_path, encoding="utf-8") as file:
                metadata = json.load(file)

            self.assertEqual(metadata["commit_hash"], "abc123")
            self.assertEqual(
                metadata["command"],
                ["./program", "crash_input.txt"]
            )
            self.assertEqual(
                metadata["build_settings"]["mode"],
                "sanitized"
            )
            self.assertEqual(
                metadata["environment"]["ASAN_OPTIONS"],
                "detect_leaks=1"
            )
            self.assertEqual(len(metadata["binary_sha256"]), 64)
            self.assertEqual(len(metadata["input_sha256"]), 64)

    def test_missing_binary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_file = root / "input.txt"
            input_file.write_text("test", encoding="utf-8")

            with self.assertRaises(FileNotFoundError):
                create_bundle(
                    binary_path=root / "missing",
                    input_path=input_file,
                    command=[],
                    commit_hash="abc123",
                    build_settings={},
                    environment={},
                    output_dir=root / "output"
                )

    def test_binary_is_copied_and_hash_matches(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            binary = root / "program"
            input_file = root / "input.txt"
            output_dir = root / "bundle"

            binary.write_bytes(b"ELF test binary")
            input_file.write_text("test input", encoding="utf-8")

            metadata_path = create_bundle(
                binary_path=binary,
                input_path=input_file,
                command=["./program"],
                commit_hash="abc123",
                build_settings={},
                environment={},
                output_dir=output_dir
            )

            with open(metadata_path, encoding="utf-8") as file:
                metadata = json.load(file)

            saved_binary = output_dir / metadata["binary_file"]

            self.assertTrue(saved_binary.is_file())
            self.assertEqual(
                saved_binary.read_bytes(),
                binary.read_bytes()
            )

            expected_hash = hashlib.sha256(
                binary.read_bytes()
            ).hexdigest()

            self.assertEqual(
                metadata["binary_sha256"],
                expected_hash
            )

    def test_sensitive_environment_values_are_redacted(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            binary = root / "program"
            input_file = root / "input.txt"
            output_dir = root / "bundle"

            binary.write_bytes(b"test binary")
            input_file.write_text("test input", encoding="utf-8")

            metadata_path = create_bundle(
                binary_path=binary,
                input_path=input_file,
                command=["./program"],
                commit_hash="abc123",
                build_settings={},
                environment={
                    "API_KEY": "my-secret-key",
                    "NORMAL_SETTING": "enabled"
                },
                output_dir=output_dir
            )

            with open(metadata_path, encoding="utf-8") as file:
                metadata = json.load(file)

            self.assertEqual(
                metadata["environment"]["API_KEY"],
                "<REDACTED>"
            )
            self.assertEqual(
                metadata["environment"]["NORMAL_SETTING"],
                "enabled"
            )


if __name__ == "__main__":
    unittest.main()
