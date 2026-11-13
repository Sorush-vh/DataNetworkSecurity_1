
import sys
import tempfile
import unittest
from pathlib import Path

from modules.reproducer.runner import replay


class TestRunner(unittest.TestCase):

    def test_stable_replay(self):
        result = replay(
            command=["/bin/sh", "-c", "echo error >&2; exit 1"],
            repetitions=3
        )

        self.assertEqual(result["status"], "STABLE")
        self.assertEqual(result["repetitions"], 3)

        for run in result["results"]:
            self.assertEqual(run["returncode"], 1)
            self.assertEqual(run["error_type"], "EXIT_CODE_1")

    def test_flaky_replay(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            counter_file = Path(temp_dir) / "counter.txt"

            script = """
import sys
from pathlib import Path

counter = Path(sys.argv[1])

if counter.exists():
    count = int(counter.read_text()) + 1
else:
    count = 1

counter.write_text(str(count))
print(f"error {count}", file=sys.stderr)
sys.exit(1)
"""

            result = replay(
                command=[
                    sys.executable,
                    "-c",
                    script,
                    str(counter_file)
                ],
                repetitions=3
            )

            self.assertEqual(result["status"], "FLAKY")
            self.assertEqual(result["repetitions"], 3)

            errors = [
                run["stderr"].strip()
                for run in result["results"]
            ]

            self.assertEqual(
                errors,
                ["error 1", "error 2", "error 3"]
            )

    def test_flaky_stdout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            counter_file = Path(temp_dir) / "counter.txt"

            script = """
import sys
from pathlib import Path

counter = Path(sys.argv[1])

if counter.exists():
    count = int(counter.read_text()) + 1
else:
    count = 1

counter.write_text(str(count))
print(f"output {count}")
"""

            result = replay(
                command=[
                    sys.executable,
                    "-c",
                    script,
                    str(counter_file)
                ],
                repetitions=3
            )

            self.assertEqual(result["status"], "FLAKY")

    def test_rejects_less_than_three_replays(self):
        with self.assertRaises(ValueError):
            replay(
                command=["/bin/true"],
                repetitions=2
            )


if __name__ == "__main__":
    unittest.main()
