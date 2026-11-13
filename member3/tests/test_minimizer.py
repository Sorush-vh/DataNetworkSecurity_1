
import unittest

from modules.minimizer.delta_debugging import delta_debug


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


if __name__ == "__main__":
    unittest.main()
