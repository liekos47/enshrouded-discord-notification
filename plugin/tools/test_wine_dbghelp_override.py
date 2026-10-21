"""Tests for wine_dbghelp_override.py.  Run: python -m unittest test_wine_dbghelp_override (in tools/)."""
import os
import tempfile
import unittest

import wine_dbghelp_override as w

GOOD = "[Software\\\\Wine\\\\DllOverrides]"  # as user.reg writes it: two backslashes
BAD = "[Software\\Wine\\DllOverrides]"       # one backslash: what the first attempt wrote

REG = (
    "WINE REGISTRY Version 2\n\n"
    f"{GOOD} 1789520095\n#time=1dd4575fd9281c2\n\"atl\"=\"native,builtin\"\n\n"
    "[Other] 1\n\"x\"=\"y\"\n\n"
    f"{BAD} 1792065925\n\"dbghelp\"=\"native,builtin\"\n"
)


class OverrideTest(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".reg")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(REG)

    def tearDown(self):
        os.remove(self.path)

    def read(self):
        with open(self.path, encoding="utf-8") as f:
            return f.read()

    def test_set_into_existing_section_and_clean_bad_one(self):
        w.main(self.path)
        text = self.read()
        self.assertNotIn(BAD + " ", text)
        self.assertIn(f"{GOOD} 1789520095\n#time=1dd4575fd9281c2\n\"dbghelp\"=\"native,builtin\"\n\"atl\"", text)
        self.assertIn("[Other] 1\n\"x\"=\"y\"", text)
        self.assertEqual(text.count("\"dbghelp\"="), 1)

    def test_idempotent_and_remove(self):
        w.main(self.path)
        w.main(self.path)
        self.assertEqual(self.read().count("\"dbghelp\"="), 1)
        w.main(self.path, remove=True)
        text = self.read()
        self.assertNotIn("dbghelp", text)
        self.assertIn("\"atl\"=\"native,builtin\"", text)

    def test_creates_section_when_missing(self):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write("WINE REGISTRY Version 2\n\n[Other] 1\n\"x\"=\"y\"\n")
        w.main(self.path)
        self.assertRegex(self.read(), r"\[Software\\\\Wine\\\\DllOverrides\] \d+\n\"dbghelp\"=\"native,builtin\"")


if __name__ == "__main__":
    unittest.main()
