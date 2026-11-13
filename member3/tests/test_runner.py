import unittest

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

    def test_rejects_less_than_three_replays(self):
        with self.assertRaises(ValueError):
            replay(
                command=["/bin/true"],
                repetitions=2
            )


if __name__ == "__main__":
    unittest.main()
