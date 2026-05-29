#!/usr/bin/env python3
"""
Apply changelog entries from a TSV file and open a sync PR against main.

Reads the pipe-delimited entries TSV produced by backport_collect_entries.py,
resolves each package directory via mage listPackages, inserts the changelog
entry at the correct semver position, commits, pushes, and opens a GitHub PR.

Usage:
    backport_create_sync_pr.py \
        --entries-tsv        <path>   \
        --working-branch     <branch> \
        --backport-pr-number <N>      \
        --backport-branch    <branch> \
        --after              <sha>    \
        --repository         <owner/repo>

Writes to $GITHUB_OUTPUT:
    not_found_packages  comma-separated list of packages not found on main

Exit codes:
    0  success
    1  error
    2  usage error
"""
import argparse
import os
import subprocess
import sys
import tempfile
import unittest

from backport_insert_changelog_entry import insert_entry
from backport_resolve_package_dir import find_package_dir


def _git(*args, check=True):
    subprocess.run(["git"] + list(args), check=check)


def _write_output(key, value):
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"{key}={value}\n")


def create_sync_pr(entries_tsv, working_branch, backport_pr_number,
                   backport_branch, after, repository):
    _git("config", "user.name", "github-actions[bot]")
    _git("config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
    _git("checkout", "-b", working_branch, "origin/main")

    with open(entries_tsv) as f:
        entries = [line.strip() for line in f if line.strip()]

    summary = []
    not_found = []

    for row in entries:
        pkg, ver, entry_file = row.split("|", 2)
        pkg_dir = find_package_dir(pkg)
        if pkg_dir is None:
            print(f"Package '{pkg}' not found on main — skipping", file=sys.stderr)
            not_found.append(f"`{pkg}`")
            continue

        with open(entry_file) as f:
            entry_block = f.read()

        insert_entry(os.path.join(pkg_dir, "changelog.yml"), ver, entry_block)
        _git("add", os.path.join(pkg_dir, "changelog.yml"))
        summary.append(f"- `{pkg}` {ver}")
        print(f"Prepared {pkg} {ver}")

    _write_output("not_found_packages", ", ".join(not_found))

    if not summary:
        print("No changelogs applied — all packages missing on main. Skipping commit.")
        sys.exit(0)

    after_short = after[:8]
    backport_pr_url = f"https://github.com/{repository}/pull/{backport_pr_number}"
    trigger_line = (
        f"_Triggered by commit [`{after_short}`]"
        f"(https://github.com/{repository}/commit/{after})"
        f" on `{backport_branch}`._"
    )

    if len(entries) == 1:
        pkg, ver, _ = entries[0].split("|", 2)
        pr_title = f"changelog: {pkg} {ver} (backport sync from PR #{backport_pr_number})"
        commit_msg = f"changelog: {pkg} {ver} (backport sync from PR #{backport_pr_number}, {after_short})"
    else:
        pr_title = f"changelog: backport sync from PR #{backport_pr_number}"
        commit_msg = f"changelog: backport sync from PR #{backport_pr_number} ({after_short})"

    _git("commit", "-m", commit_msg)
    _git("push", "origin", working_branch)

    summary_text = "\n".join(summary)
    pr_body = (
        f"Automated changelog sync from [PR #{backport_pr_number}]({backport_pr_url}).\n\n"
        f"**Packages synced:**\n{summary_text}\n{trigger_line}\n"
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(pr_body)
        pr_body_file = f.name

    try:
        subprocess.run([
            "gh", "pr", "create",
            "--base", "main",
            "--head", working_branch,
            "--title", pr_title,
            "--label", "automation",
            "--reviewer", "elastic/ecosystem",
            "--body-file", pr_body_file,
        ], check=True)
    finally:
        os.unlink(pr_body_file)


def main():
    parser = argparse.ArgumentParser(
        description="Apply changelog entries and open a sync PR against main."
    )
    parser.add_argument("--entries-tsv",        metavar="PATH",   required=False)
    parser.add_argument("--working-branch",      metavar="BRANCH", required=False)
    parser.add_argument("--backport-pr-number",  metavar="N",      required=False)
    parser.add_argument("--backport-branch",     metavar="BRANCH", required=False)
    parser.add_argument("--after",               metavar="SHA",    required=False)
    parser.add_argument("--repository",          metavar="REPO",   required=False)
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    required = ("entries_tsv", "working_branch", "backport_pr_number",
                "backport_branch", "after", "repository")
    for flag in required:
        if not getattr(args, flag):
            parser.error(f"--{flag.replace('_', '-')} is required")

    create_sync_pr(
        args.entries_tsv,
        args.working_branch,
        args.backport_pr_number,
        args.backport_branch,
        args.after,
        args.repository,
    )


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

_ENTRY = """\
- version: "6.14.3"
  changes:
    - description: Fix CEL handling
      type: bugfix
      link: https://github.com/elastic/integrations/pull/19147"""


# Patches must use the name under which this module is loaded: '__main__' when
# run directly, the module name when imported by a test runner.
_MODULE = __name__


class TestCreateSyncPr(unittest.TestCase):

    def setUp(self):
        import pathlib
        import tempfile
        self._tmp = pathlib.Path(tempfile.mkdtemp())

    def tearDown(self):
        import shutil
        shutil.rmtree(self._tmp)

    def _make_tsv(self, rows):
        tsv = self._tmp / "entries.tsv"
        tsv.write_text("\n".join(rows) + "\n")
        return str(tsv)

    def _make_entry_file(self, content):
        ef = self._tmp / "entry.txt"
        ef.write_text(content)
        return str(ef)

    def _make_changelog(self, pkg):
        pkg_dir = self._tmp / "packages" / pkg
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "changelog.yml").write_text(_CHANGELOG)
        return str(pkg_dir)

    def test_not_found_package_is_recorded(self):
        import unittest.mock
        outputs = {}

        entry_file = self._make_entry_file(_ENTRY)
        tsv = self._make_tsv([f"missing_pkg|6.14.3|{entry_file}"])

        def fake_write(key, value):
            outputs[key] = value

        def fake_git(*args, check=True):
            pass

        with unittest.mock.patch(f"{_MODULE}._git", side_effect=fake_git), \
             unittest.mock.patch(f"{_MODULE}.find_package_dir", return_value=None), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write):
            with self.assertRaises(SystemExit) as cm:
                create_sync_pr(tsv, "changelog/pr-42", "42", "backport-8.x", "abc12345", "org/repo")

        self.assertEqual(cm.exception.code, 0)
        self.assertIn("`missing_pkg`", outputs.get("not_found_packages", ""))

    def test_single_entry_pr_title_format(self):
        import unittest.mock
        outputs = {}
        pr_calls = []

        pkg_dir = self._make_changelog("aws")
        entry_file = self._make_entry_file(_ENTRY)
        tsv = self._make_tsv([f"aws|6.14.3|{entry_file}"])

        def fake_write(key, value):
            outputs[key] = value

        def fake_git(*args, check=True):
            pass

        def fake_subprocess_run(cmd, **kwargs):
            if cmd[0] == "gh":
                pr_calls.append(cmd)
            import subprocess as sp
            return sp.CompletedProcess(cmd, 0, stdout="")

        with unittest.mock.patch(f"{_MODULE}._git", side_effect=fake_git), \
             unittest.mock.patch(f"{_MODULE}.find_package_dir", return_value=pkg_dir), \
             unittest.mock.patch(f"{_MODULE}._write_output", side_effect=fake_write), \
             unittest.mock.patch("subprocess.run", side_effect=fake_subprocess_run):
            create_sync_pr(tsv, "changelog/pr-42", "42", "backport-8.x", "abc12345ff", "org/repo")

        gh_create = next(c for c in pr_calls if "create" in c)
        title_idx = gh_create.index("--title") + 1
        self.assertIn("aws", gh_create[title_idx])
        self.assertIn("6.14.3", gh_create[title_idx])

    def test_multi_entry_pr_title_format(self):
        import unittest.mock
        pr_calls = []

        pkg_dir_aws = self._make_changelog("aws")
        entry_file1 = self._make_entry_file(_ENTRY)
        nginx_dir = self._tmp / "packages" / "nginx"
        nginx_dir.mkdir(parents=True)
        (nginx_dir / "changelog.yml").write_text(_CHANGELOG)
        entry_file2 = self._make_entry_file(_ENTRY)
        tsv = self._make_tsv([
            f"aws|6.14.3|{entry_file1}",
            f"nginx|6.14.3|{entry_file2}",
        ])

        def fake_find(pkg, **kwargs):
            return {"aws": pkg_dir_aws, "nginx": str(nginx_dir)}.get(pkg)

        def fake_git(*args, check=True):
            pass

        def fake_subprocess_run(cmd, **kwargs):
            if cmd[0] == "gh":
                pr_calls.append(cmd)
            import subprocess as sp
            return sp.CompletedProcess(cmd, 0, stdout="")

        with unittest.mock.patch(f"{_MODULE}._git", side_effect=fake_git), \
             unittest.mock.patch(f"{_MODULE}.find_package_dir", side_effect=fake_find), \
             unittest.mock.patch(f"{_MODULE}._write_output"), \
             unittest.mock.patch("subprocess.run", side_effect=fake_subprocess_run):
            create_sync_pr(tsv, "changelog/pr-42", "42", "backport-8.x", "abc12345ff", "org/repo")

        gh_create = next(c for c in pr_calls if "create" in c)
        title_idx = gh_create.index("--title") + 1
        self.assertNotIn("aws", gh_create[title_idx])
        self.assertIn("backport sync from PR #42", gh_create[title_idx])


if __name__ == "__main__":
    main()
