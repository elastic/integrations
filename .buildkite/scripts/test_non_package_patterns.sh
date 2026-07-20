#!/usr/bin/env bash
# Unit tests for pr_has_package_related_files() in common.sh.
# Run directly (from repo root) or via run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=.buildkite/scripts/common.sh
source "${REPO_ROOT}/.buildkite/scripts/common.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Wraps pr_has_package_related_files for a single path.
# Returns 0 if the path would trigger package tests, 1 if it would not.
path_triggers_tests() {
    printf '%s\n' "$1" | pr_has_package_related_files
}

# ---------------------------------------------------------------------------
# Paths covered by non_package_patterns: must NOT trigger tests
# ---------------------------------------------------------------------------
echo "--- pr_has_package_related_files: non-package paths do NOT trigger tests"

NON_PACKAGE_PATHS=(
    "packages/aws/manifest.yml"
    "packages/nginx/changelog.yml"
    ".agents/skills/some_skill.yml"
    ".backports.yml"
    ".buildkite/pipeline.backport.yml"
    ".buildkite/pipeline.publish.yml"
    ".buildkite/pipeline.schedule-daily.yml"
    ".buildkite/pipeline.schedule-weekly.yml"
    ".buildkite/pipeline.serverless.yml"
    ".buildkite/pull-requests.json"
    ".buildkite/scripts/backport_branch.sh"
    ".buildkite/scripts/backport_branch_lib.sh"
    ".buildkite/scripts/check_backports_inventory.sh"
    ".buildkite/scripts/notify_backport_pr.sh"
    ".buildkite/scripts/trigger_backport.sh"
    ".buildkite/scripts/trigger_backport_lib.sh"
    ".buildkite/scripts/build_packages.sh"
    ".buildkite/scripts/check_backport_owners.sh"
    ".buildkite/scripts/check_changelog_entries.sh"
    ".buildkite/scripts/packages/aws.sh"
    ".buildkite/scripts/packages/nginx.sh"
    ".buildkite/scripts/requirements-ci-python-scripts.txt"
    ".buildkite/scripts/run_buildkite_scripts_tests.sh"
    ".buildkite/scripts/run_dev_scripts_tests.sh"
    ".buildkite/scripts/test_backport_branch.sh"
    ".buildkite/scripts/test_check_backport_owners.sh"
    ".buildkite/scripts/test_check_changelog_entries.sh"
    ".buildkite/scripts/test_helpers.sh"
    ".buildkite/scripts/test_non_package_patterns.sh"
    ".buildkite/scripts/test_trigger_backport.sh"
    ".github/dependabot.yml"
    ".github/stale.yml"
    ".github/workflows/test.yml"
    ".github/CODEOWNERS"
    ".github/ISSUE_TEMPLATE/bug_report.md"
    ".github/PULL_REQUEST_TEMPLATE.md"
    ".gitignore"
    ".mergify.yml"
    "catalog-info.yaml"
    "dev/backports/some_script.sh"
    "dev/codeowners/codeowners.go"
    "dev/gitutil/git.go"
    "dev/requiresupdate/requiresupdate.go"
    "dev/scripts/foo.sh"
    "docs/extend/developer-workflow.md"
    "docs/some/nested/page.md"
    "CODE_OF_CONDUCT.md"
    "CONTRIBUTING.md"
    "README.md"
)

for path in "${NON_PACKAGE_PATHS[@]}"; do
    exit_code=0
    path_triggers_tests "${path}" && exit_code=0 || exit_code=$?
    assert_exit_code "only '${path}' changed → tests NOT triggered" "1" "${exit_code}"
done

# ---------------------------------------------------------------------------
# Paths NOT covered by non_package_patterns: must trigger tests
# ---------------------------------------------------------------------------
echo ""
echo "--- pr_has_package_related_files: infra-file changes DO trigger tests"

TRIGGERING_PATHS=(
    ".buildkite/scripts/common.sh"
    ".buildkite/pipeline.yml"
    "Makefile"
    ".buildkite/scripts/build_packages_serverless.sh"
)

for path in "${TRIGGERING_PATHS[@]}"; do
    exit_code=0
    path_triggers_tests "${path}" || exit_code=$?
    assert_exit_code "change to '${path}' → tests triggered" "0" "${exit_code}"
done

# ---------------------------------------------------------------------------
# Mixed changeset: one triggering file among non-package files → still triggers
# ---------------------------------------------------------------------------
echo ""
echo "--- pr_has_package_related_files: mixed changesets are classified correctly"

exit_code=0
printf '%s\n' "README.md" ".buildkite/pipeline.yml" "docs/foo.md" \
    | pr_has_package_related_files || exit_code=$?
assert_exit_code "non-package + pipeline.yml → tests triggered" "0" "${exit_code}"

exit_code=0
printf '%s\n' "README.md" "docs/foo.md" ".github/workflows/ci.yml" \
    | pr_has_package_related_files && exit_code=0 || exit_code=$?
assert_exit_code "only non-package files → tests NOT triggered" "1" "${exit_code}"

# ---------------------------------------------------------------------------
# Anchoring: patterns are anchored at ^ so a prefix must not cause false matches
# ---------------------------------------------------------------------------
echo ""
echo "--- pr_has_package_related_files: ^ anchoring prevents false positives"

ANCHORING_CASES=(
    "vendor/docs/foo.md"           # must not match 'docs/'
    "my_packages/aws/manifest.yml" # must not match 'packages/'
    "not_readme/README.md"         # must not match 'README\.md' mid-path
)

for path in "${ANCHORING_CASES[@]}"; do
    exit_code=0
    path_triggers_tests "${path}" || exit_code=$?
    assert_exit_code "'^'-anchored pattern does not match '${path}'" "0" "${exit_code}"
done

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
