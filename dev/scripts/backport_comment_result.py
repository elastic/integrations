#!/usr/bin/env python3
"""
Post a comment on the originating backport PR with the sync result.

Usage:
    backport_comment_result.py \
        --backport-pr-number <N>             \
        --working-branch     <branch>        \
        --not-found-packages <csv>           \
        --create-outcome     success|skipped|failure \
        --run-id             <id>            \
        --repository         <owner/repo>

Exit codes:
    0  success or nothing to do
    1  error
    2  usage error
"""
import argparse
import subprocess
import sys
import unittest


def _sync_pr_url(working_branch):
    result = subprocess.run(
        ["gh", "pr", "list", "--head", working_branch, "--state", "open",
         "--json", "url", "--jq", ".[0].url"],
        capture_output=True, text=True,
    )
    return result.stdout.strip()


def _branch_exists_on_remote(working_branch, repository):
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/branches/{working_branch}",
         "--jq", ".name"],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == working_branch


def post_comment(backport_pr_number, working_branch, not_found_packages,
                 create_outcome, run_id, repository):
    if not backport_pr_number:
        print("No backport PR number — skipping comment")
        return

    if not working_branch:
        return

    run_url = f"https://github.com/{repository}/actions/runs/{run_id}"
    skipped_warn = (
        f"\n\n⚠️ The following packages were not found on `main` and were skipped: "
        f"{not_found_packages}"
    ) if not_found_packages else ""

    if create_outcome == "skipped":
        body = "Changelog sync skipped: all versions already present in `main` or a sync PR already exists."
    elif create_outcome == "success":
        sync_pr_url = _sync_pr_url(working_branch)
        if sync_pr_url:
            body = f"Changelog sync PR created successfully: {sync_pr_url}"
            if not_found_packages:
                body += skipped_warn
        else:
            body = (
                f"Changelog sync could not be completed: the following packages were not "
                f"found on `main`: {not_found_packages}"
            )
    else:
        body = f"Changelog sync PR creation failed. See the [workflow run]({run_url}) for details."
        if working_branch and _branch_exists_on_remote(working_branch, repository):
            compare_url = (
                f"https://github.com/{repository}/compare/main...{working_branch}?expand=1"
            )
            body += (
                f"\n\nThe changelog entries were committed to `{working_branch}`. "
                f"You can [create the sync PR manually]({compare_url}) from that branch."
            )

    subprocess.run(["gh", "pr", "comment", backport_pr_number, "--body", body], check=True)


def main():
    parser = argparse.ArgumentParser(
        description="Post a sync result comment on the originating backport PR."
    )
    parser.add_argument("--backport-pr-number",  metavar="N",      required=False, default="")
    parser.add_argument("--working-branch",       metavar="BRANCH", required=False, default="")
    parser.add_argument("--not-found-packages",   metavar="CSV",    required=False, default="")
    parser.add_argument("--create-outcome",       metavar="RESULT", required=False, default="")
    parser.add_argument("--run-id",               metavar="ID",     required=False, default="")
    parser.add_argument("--repository",           metavar="REPO",   required=False, default="")
    parser.add_argument("--test", action="store_true", help="Run unit tests")
    args = parser.parse_args()

    if args.test:
        unittest.main(argv=[sys.argv[0]], verbosity=2)
        return

    if not args.repository:
        parser.error("--repository is required")

    post_comment(
        args.backport_pr_number,
        args.working_branch,
        args.not_found_packages,
        args.create_outcome,
        args.run_id,
        args.repository,
    )


# ── tests ─────────────────────────────────────────────────────────────────────

_MODULE = __name__


class TestPostComment(unittest.TestCase):

    def setUp(self):
        import unittest.mock
        self._mock = unittest.mock

    def test_no_pr_number_is_noop(self):
        import unittest.mock
        with unittest.mock.patch("subprocess.run") as mock_run:
            post_comment("", "changelog/pr-42", "", "success", "123", "org/repo")
            mock_run.assert_not_called()

    def test_no_working_branch_is_noop(self):
        import unittest.mock
        with unittest.mock.patch("subprocess.run") as mock_run:
            post_comment("42", "", "", "success", "123", "org/repo")
            mock_run.assert_not_called()

    def test_skipped_outcome(self):
        import unittest.mock
        comment_calls = []

        def fake_run(cmd, **kwargs):
            comment_calls.append(cmd)
            import subprocess as sp
            return sp.CompletedProcess(cmd, 0)

        with unittest.mock.patch("subprocess.run", side_effect=fake_run):
            post_comment("42", "changelog/pr-42", "", "skipped", "123", "org/repo")

        gh_comment = next(c for c in comment_calls if "comment" in c)
        body_idx = gh_comment.index("--body") + 1
        self.assertIn("skipped", gh_comment[body_idx])

    def test_success_with_sync_pr_url(self):
        import unittest.mock
        comment_calls = []

        def fake_run(cmd, **kwargs):
            import subprocess as sp
            comment_calls.append(cmd)
            if "--jq" in cmd:
                return sp.CompletedProcess(cmd, 0, stdout="https://github.com/org/repo/pull/99\n")
            return sp.CompletedProcess(cmd, 0, stdout="")

        with unittest.mock.patch("subprocess.run", side_effect=fake_run):
            post_comment("42", "changelog/pr-42", "", "success", "123", "org/repo")

        gh_comment = next(c for c in comment_calls if "comment" in c)
        body_idx = gh_comment.index("--body") + 1
        self.assertIn("https://github.com/org/repo/pull/99", gh_comment[body_idx])

    def test_success_with_not_found_packages_appends_warning(self):
        import unittest.mock
        comment_calls = []

        def fake_run(cmd, **kwargs):
            import subprocess as sp
            comment_calls.append(cmd)
            if "--jq" in cmd:
                return sp.CompletedProcess(cmd, 0, stdout="https://github.com/org/repo/pull/99\n")
            return sp.CompletedProcess(cmd, 0, stdout="")

        with unittest.mock.patch("subprocess.run", side_effect=fake_run):
            post_comment("42", "changelog/pr-42", "`missing_pkg`", "success", "123", "org/repo")

        gh_comment = next(c for c in comment_calls if "comment" in c)
        body_idx = gh_comment.index("--body") + 1
        self.assertIn("missing_pkg", gh_comment[body_idx])
        self.assertIn("⚠️", gh_comment[body_idx])

    def test_failure_outcome_includes_run_url(self):
        import unittest.mock
        comment_calls = []

        def fake_run(cmd, **kwargs):
            import subprocess as sp
            comment_calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="")

        with unittest.mock.patch("subprocess.run", side_effect=fake_run), \
             unittest.mock.patch(f"{_MODULE}._branch_exists_on_remote", return_value=False):
            post_comment("42", "changelog/pr-42", "", "failure", "99999", "org/repo")

        gh_comment = next(c for c in comment_calls if "comment" in c)
        body_idx = gh_comment.index("--body") + 1
        self.assertIn("99999", gh_comment[body_idx])

    def test_failure_outcome_with_pushed_branch_includes_manual_creation_link(self):
        import unittest.mock
        comment_calls = []

        def fake_run(cmd, **kwargs):
            import subprocess as sp
            comment_calls.append(cmd)
            return sp.CompletedProcess(cmd, 0, stdout="")

        with unittest.mock.patch("subprocess.run", side_effect=fake_run), \
             unittest.mock.patch(f"{_MODULE}._branch_exists_on_remote", return_value=True):
            post_comment("42", "changelog/pr-42", "", "failure", "99999", "org/repo")

        gh_comment = next(c for c in comment_calls if "comment" in c)
        body_idx = gh_comment.index("--body") + 1
        body = gh_comment[body_idx]
        self.assertIn("changelog/pr-42", body)
        self.assertIn("manually", body)
        self.assertIn("compare/main...changelog/pr-42", body)


if __name__ == "__main__":
    main()
