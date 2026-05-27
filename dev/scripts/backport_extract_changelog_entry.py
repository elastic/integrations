#!/usr/bin/env python3
"""
Extract the newly added version entry from a git diff of a changelog.yml file.

Usage:
    backport_extract_changelog_entry.py <diff_file> --entry-file <path>
    backport_extract_changelog_entry.py -            --entry-file <path>  # stdin

Output:
    Prints the new version string to stdout (single line).
    Writes the full entry block to --entry-file.

Exit codes:
    0  success
    1  no new version entry found in the diff
    2  usage error
"""
import argparse
import re
import sys
import unittest


def extract_from_diff(diff_text):
    """Return (version_str, entry_block) or (None, None) if no new entry is found."""
    added = [
        line[1:]
        for line in diff_text.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    ]
    if not added:
        return None, None

    entry_block = "\n".join(added)

    m = re.search(
        r'^- version: ["\']?([0-9]+\.[0-9]+\.[0-9][^\s"\']*)["\']?\s*$',
        entry_block,
        re.MULTILINE,
    )
    if not m:
        return None, None

    return m.group(1).strip(), entry_block


def main():
    parser = argparse.ArgumentParser(
        description="Extract the new version entry from a changelog.yml git diff."
    )
    parser.add_argument(
        "diff_file",
        metavar="DIFF_FILE",
        nargs="?",
        help="Path to the git diff file, or '-' for stdin",
    )
    parser.add_argument("--entry-file", metavar="PATH", help="File to write the new entry block to")
    parser.add_argument("--test",       action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    if not args.diff_file:
        parser.error("DIFF_FILE is required")
    if not args.entry_file:
        parser.error("--entry-file is required")

    if args.diff_file == "-":
        diff_text = sys.stdin.read()
    else:
        with open(args.diff_file) as f:
            diff_text = f.read()

    version, entry = extract_from_diff(diff_text)

    if version is None:
        print("No new version entry found in the changelog diff", file=sys.stderr)
        sys.exit(1)

    with open(args.entry_file, "w") as f:
        f.write(entry)

    print(version)


# ── tests ─────────────────────────────────────────────────────────────────────

_DIFF_VALID = """\
diff --git a/packages/aws/changelog.yml b/packages/aws/changelog.yml
index abc..def 100644
--- a/packages/aws/changelog.yml
+++ b/packages/aws/changelog.yml
@@ -1,4 +1,9 @@
 # newer versions go on top
+- version: "6.14.3"
+  changes:
+    - description: Fix CEL handling
+      type: bugfix
+      link: https://github.com/elastic/integrations/pull/19147
 - version: "6.15.0"
"""


class TestExtractFromDiff(unittest.TestCase):

    def test_extracts_version(self):
        version, _ = extract_from_diff(_DIFF_VALID)
        self.assertEqual(version, "6.14.3")

    def test_extracts_entry_block(self):
        _, entry = extract_from_diff(_DIFF_VALID)
        self.assertIn('- version: "6.14.3"', entry)
        self.assertIn("Fix CEL handling", entry)

    def test_no_added_lines_returns_none(self):
        diff = "--- a/changelog.yml\n+++ b/changelog.yml\n context line\n"
        version, entry = extract_from_diff(diff)
        self.assertIsNone(version)
        self.assertIsNone(entry)

    def test_added_lines_without_version_returns_none(self):
        diff = _DIFF_VALID.replace("- version:", "  something:")
        version, entry = extract_from_diff(diff)
        self.assertIsNone(version)
        self.assertIsNone(entry)

    def test_entry_file_is_written(self):
        import pathlib
        import tempfile
        import unittest.mock
        with tempfile.TemporaryDirectory() as tmp:
            diff_file  = str(pathlib.Path(tmp) / "changelog.diff")
            entry_file = str(pathlib.Path(tmp) / "entry.txt")
            pathlib.Path(diff_file).write_text(_DIFF_VALID)
            with unittest.mock.patch("sys.argv", [
                "backport_extract_changelog_entry.py",
                diff_file, "--entry-file", entry_file,
            ]):
                main()
            content = pathlib.Path(entry_file).read_text()
            self.assertIn("6.14.3", content)
            self.assertIn("Fix CEL handling", content)


if __name__ == "__main__":
    main()
