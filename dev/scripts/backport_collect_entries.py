#!/usr/bin/env python3
"""
Collect changelog entries introduced by a backport push.

Resolves the associated backport PR, checks for an existing sync PR (dedup),
then walks every changed changelog.yml to extract new version entries that are
not yet on main.  Writes results to $GITHUB_OUTPUT and a TSV file.

Usage:
    backport_collect_entries.py \
        --before <sha> \
        --after  <sha> \
        --repository <owner/repo>

Writes to $GITHUB_OUTPUT:
    has_changes        true | false
    entries_tsv        path to pipe-delimited file (name|version|entry_file)
    working_branch     changelog/pr-<N>
    backport_pr_number <N>

Exit codes:
    0  success (has_changes may be false)
    1  unexpected error
    2  usage error
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest

from backport_extract_changelog_entry import extract_from_diff


def _run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def _backport_pr_number(repository, after):
    result = _run(["gh", "api", f"repos/{repository}/commits/{after}/pulls",
                   "--jq", ".[0].number // empty"])
    return result.stdout.strip()


def _sync_pr_exists(working_branch):
    result = _run(["gh", "pr", "list", "--head", working_branch,
                   "--state", "all", "--json", "number"], check=True)
    return len(json.loads(result.stdout)) > 0


def _changed_changelogs(before, after):
    result = _run(["git", "diff", "--name-only", f"{before}..{after}",
                   "--", "**/changelog.yml"], check=True)
    return [p for p in result.stdout.splitlines() if p]


def _manifest_name(package_dir):
    try:
        import yaml
        with open(os.path.join(package_dir, "manifest.yml")) as f:
            data = yaml.safe_load(f) or {}
        return data.get("name", "")
    except Exception:
        return ""


def _git_diff(before, after, path):
    return _run(["git", "diff", f"{before}..{after}", "--", path], check=True).stdout


def _version_in_main(changelog_path, version):
    result = _run(["git", "show", f"origin/main:{changelog_path}"])
    if result.returncode != 0:
        return False
    content = result.stdout
    return any(
        f"- version: {v}" in content
        for v in [version, f'"{version}"', f"'{version}'"]
    )


def _write_output(key, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{key}={value}\n")


def collect(before, after, repository):
    backport_pr_number = _backport_pr_number(repository, after)
    if not backport_pr_number:
        print(f"No PR associated with commit {after} — skipping")
        _write_output("has_changes", "false")
        return

    working_branch = f"changelog/pr-{backport_pr_number}"

    if _sync_pr_exists(working_branch):
        print(f"Sync PR already exists for {working_branch} — skipping")
        _write_output("has_changes", "false")
        return

    changed = _changed_changelogs(before, after)
    entries = []

    for changelog_path in changed:
        package_dir = os.path.dirname(changelog_path)
        manifest_name = _manifest_name(package_dir)
        if not manifest_name:
            print(f"Could not read manifest for {package_dir} — skipping")
            continue

        diff_text = _git_diff(before, after, changelog_path)
        version, entry_block = extract_from_diff(diff_text)
        if version is None:
            print(f"No new version entry in {changelog_path} — skipping")
            continue

        if _version_in_main(changelog_path, version):
            print(f"Version {version} of {manifest_name} already in main — skipping")
            continue

        entry_file = tempfile.mktemp(prefix="entry_", suffix=".txt")
        with open(entry_file, "w") as f:
            f.write(entry_block)

        entries.append(f"{manifest_name}|{version}|{entry_file}")
        print(f"Queued {manifest_name} {version}")

    if not entries:
        print("No new changelog entries to sync")
        _write_output("has_changes", "false")
        return

    entries_tsv = tempfile.mktemp(prefix="entries_", suffix=".tsv")
    with open(entries_tsv, "w") as f:
        f.write("\n".join(entries) + "\n")

    _write_output("has_changes", "true")
    _write_output("entries_tsv", entries_tsv)
    _write_output("working_branch", working_branch)
    _write_output("backport_pr_number", backport_pr_number)
    print(f"Queued {len(entries)} entr(ies) for sync under {working_branch}")


def main():
    parser = argparse.ArgumentParser(
        description="Collect changelog entries from a backport push."
    )
    parser.add_argument("--before",     metavar="SHA",  required=False)
    parser.add_argument("--after",      metavar="SHA",  required=False)
    parser.add_argument("--repository", metavar="REPO", required=False)
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    for flag in ("before", "after", "repository"):
        if not getattr(args, flag):
            parser.error(f"--{flag} is required")

    collect(args.before, args.after, args.repository)


# ── tests ─────────────────────────────────────────────────────────────────────

# Patches must use the name under which this module is loaded: '__main__' when
# run directly, the module name when imported by a test runner.
_MODULE = __name__


class TestCollect(unittest.TestCase):

    def setUp(self):
        import pathlib
        import tempfile
        self._tmp = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp)

    def test_no_pr_number_writes_false(self):
        import unittest.mock
        outputs = {}

        def fake_write(key, value):
            outputs[key] = value

        with unittest.mock.patch(f"{_MODULE}._backport_pr_number", return_value=""), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write):
            collect("aaa", "bbb", "org/repo")

        self.assertEqual(outputs.get("has_changes"), "false")

    def test_existing_sync_pr_writes_false(self):
        import unittest.mock
        outputs = {}

        def fake_write(key, value):
            outputs[key] = value

        with unittest.mock.patch(f"{_MODULE}._backport_pr_number", return_value="42"), \
             unittest.mock.patch(f"{_MODULE}._sync_pr_exists", return_value=True), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write):
            collect("aaa", "bbb", "org/repo")

        self.assertEqual(outputs.get("has_changes"), "false")

    def test_no_changed_changelogs_writes_false(self):
        import unittest.mock
        outputs = {}

        def fake_write(key, value):
            outputs[key] = value

        with unittest.mock.patch(f"{_MODULE}._backport_pr_number", return_value="42"), \
             unittest.mock.patch(f"{_MODULE}._sync_pr_exists", return_value=False), \
             unittest.mock.patch(f"{_MODULE}._changed_changelogs", return_value=[]), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write):
            collect("aaa", "bbb", "org/repo")

        self.assertEqual(outputs.get("has_changes"), "false")

    def test_version_already_in_main_is_skipped(self):
        import unittest.mock
        outputs = {}

        _DIFF = """\
+- version: "1.2.3"
+  changes:
+    - description: Fix
+      type: bugfix
+      link: https://github.com/elastic/integrations/pull/1
"""

        def fake_write(key, value):
            outputs[key] = value

        with unittest.mock.patch(f"{_MODULE}._backport_pr_number", return_value="42"), \
             unittest.mock.patch(f"{_MODULE}._sync_pr_exists", return_value=False), \
             unittest.mock.patch(f"{_MODULE}._changed_changelogs", return_value=["packages/aws/changelog.yml"]), \
             unittest.mock.patch(f"{_MODULE}._manifest_name", return_value="aws"), \
             unittest.mock.patch(f"{_MODULE}._git_diff", return_value=_DIFF), \
             unittest.mock.patch(f"{_MODULE}._version_in_main", return_value=True), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write):
            collect("aaa", "bbb", "org/repo")

        self.assertEqual(outputs.get("has_changes"), "false")

    def test_valid_entry_queued(self):
        import unittest.mock
        outputs = {}

        _DIFF = """\
+- version: "1.2.3"
+  changes:
+    - description: Fix
+      type: bugfix
+      link: https://github.com/elastic/integrations/pull/1
"""

        def fake_write(key, value):
            outputs[key] = value

        with unittest.mock.patch(f"{_MODULE}._backport_pr_number", return_value="42"), \
             unittest.mock.patch(f"{_MODULE}._sync_pr_exists", return_value=False), \
             unittest.mock.patch(f"{_MODULE}._changed_changelogs", return_value=["packages/aws/changelog.yml"]), \
             unittest.mock.patch(f"{_MODULE}._manifest_name", return_value="aws"), \
             unittest.mock.patch(f"{_MODULE}._git_diff", return_value=_DIFF), \
             unittest.mock.patch(f"{_MODULE}._version_in_main", return_value=False), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write):
            collect("aaa", "bbb", "org/repo")

        self.assertEqual(outputs.get("has_changes"), "true")
        self.assertEqual(outputs.get("working_branch"), "changelog/pr-42")
        self.assertEqual(outputs.get("backport_pr_number"), "42")
        self.assertIn("entries_tsv", outputs)

    def test_manifest_name_reads_yaml(self):
        import pathlib
        pkg_dir = self._tmp / "packages" / "aws"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "manifest.yml").write_text("name: aws\nversion: 1.0.0\n")
        self.assertEqual(_manifest_name(str(pkg_dir)), "aws")

    def test_manifest_name_missing_file_returns_empty(self):
        self.assertEqual(_manifest_name("/nonexistent/dir"), "")


if __name__ == "__main__":
    main()
