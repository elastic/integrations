#!/usr/bin/env python3
"""
Insert a version entry at the correct semver-descending position in a changelog.yml.

The file is modified in place.

Usage:
    backport_insert_changelog_entry.py \
        --changelog <path> \
        --version   <version> \
        --entry-file <path>

Exit codes:
    0  success
    1  error (file not found, etc.)
    2  usage error
"""
import argparse
import re
import sys
import unittest


def parse_ver(v):
    try:
        return tuple(int(p) for p in v.strip().strip("'\"").split("."))
    except ValueError:
        return (0, 0, 0)


def insert_entry(changelog_path, new_ver_str, entry_block):
    with open(changelog_path) as f:
        content = f.read()

    lines     = content.split("\n")
    new_ver   = parse_ver(new_ver_str)
    insert_at = len(lines)

    for i, line in enumerate(lines):
        m = re.match(r'^- version: ["\']?([^\s"\']+)["\']?\s*$', line)
        if m:
            if m.group(1).strip().strip("'\"") == new_ver_str.strip().strip("'\""):
                print(f"Version {new_ver_str} already present in {changelog_path} — skipping", file=sys.stderr)
                return
            if parse_ver(m.group(1)) < new_ver:
                insert_at = i
                break

    entry_lines  = entry_block.rstrip("\n").split("\n")
    result_lines = lines[:insert_at] + entry_lines + lines[insert_at:]

    with open(changelog_path, "w") as f:
        f.write("\n".join(result_lines))

    print(f"Inserted {new_ver_str} at line {insert_at} in {changelog_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Insert a version entry at the correct position in a changelog.yml."
    )
    parser.add_argument("--changelog",  metavar="PATH",    help="Path to the changelog.yml to modify in place")
    parser.add_argument("--version",    metavar="VERSION", help="Version string of the entry being inserted (e.g. 6.14.3)")
    parser.add_argument("--entry-file", metavar="PATH",    help="File containing the changelog entry block to insert")
    parser.add_argument("--test",       action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    if not args.changelog:
        parser.error("--changelog is required")
    if not args.version:
        parser.error("--version is required")
    if not args.entry_file:
        parser.error("--entry-file is required")

    try:
        with open(args.entry_file) as f:
            entry_block = f.read()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        insert_entry(args.changelog, args.version, entry_block)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


# ── tests ─────────────────────────────────────────────────────────────────────

_CHANGELOG = """\
# newer versions go on top
- version: "6.15.0"
  changes:
    - description: Some enhancement
      type: enhancement
      link: https://github.com/elastic/integrations/pull/19000
- version: "6.14.2"
  changes:
    - description: Old fix
      type: bugfix
      link: https://github.com/elastic/integrations/pull/18900
"""

_NEW_ENTRY = """\
- version: "6.14.3"
  changes:
    - description: Fix CEL handling
      type: bugfix
      link: https://github.com/elastic/integrations/pull/19147"""


class TestInsertEntry(unittest.TestCase):

    def setUp(self):
        import pathlib
        import tempfile
        self._tmp  = pathlib.Path(tempfile.mkdtemp())
        self._path = str(self._tmp / "changelog.yml")
        pathlib.Path(self._path).write_text(_CHANGELOG)

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp)

    def _versions(self):
        import pathlib
        lines = pathlib.Path(self._path).read_text().splitlines()
        return [line.split('"')[1] for line in lines if line.startswith("- version:")]

    def test_insert_between_versions(self):
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        self.assertEqual(self._versions(), ["6.15.0", "6.14.3", "6.14.2"])

    def test_insert_at_top_when_highest(self):
        entry = '- version: "7.0.0"\n  changes:\n    - description: Major\n      type: enhancement\n      link: https://...'
        insert_entry(self._path, "7.0.0", entry)
        self.assertEqual(self._versions()[0], "7.0.0")

    def test_insert_at_bottom_when_lowest(self):
        entry = '- version: "6.0.0"\n  changes:\n    - description: Old\n      type: bugfix\n      link: https://...'
        insert_entry(self._path, "6.0.0", entry)
        self.assertEqual(self._versions()[-1], "6.0.0")

    def test_preserves_header_comment(self):
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        import pathlib
        content = pathlib.Path(self._path).read_text()
        self.assertTrue(content.startswith("# newer versions go on top"))

    def test_entry_content_is_present(self):
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        import pathlib
        content = pathlib.Path(self._path).read_text()
        self.assertIn("Fix CEL handling", content)

    def test_missing_changelog_raises(self):
        with self.assertRaises(FileNotFoundError):
            insert_entry("/nonexistent/changelog.yml", "6.14.3", _NEW_ENTRY)

    def test_duplicate_version_is_skipped(self):
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        self.assertEqual(self._versions().count("6.14.3"), 1)

    def test_duplicate_version_does_not_modify_file(self):
        import pathlib
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        content_after_first = pathlib.Path(self._path).read_text()
        insert_entry(self._path, "6.14.3", _NEW_ENTRY)
        content_after_second = pathlib.Path(self._path).read_text()
        self.assertEqual(content_after_first, content_after_second)


if __name__ == "__main__":
    main()
