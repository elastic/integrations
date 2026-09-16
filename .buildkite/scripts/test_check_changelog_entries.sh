#!/usr/bin/env bash
# Unit tests for check_changelog_entries.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

# Source the script without executing main so its functions are available.
source "${REPO_ROOT}/.buildkite/scripts/check_changelog_entries.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Helpers: set up / tear down a minimal git repo that mimics a PR diff.
#
# The repo has a base commit followed by a second commit that adds a new
# changelog entry — the second commit is what tests diff against.
# ---------------------------------------------------------------------------

DUMMY_REPO=""

cleanup() {
    [[ -n "${DUMMY_REPO}" ]] && rm -rf "${DUMMY_REPO}"
}
trap cleanup EXIT

setup_dummy_repo() {
    local tmpdir
    tmpdir="$(mktemp -d)"
    git -C "${tmpdir}" init -q
    git -C "${tmpdir}" config user.email "test@test.com"
    git -C "${tmpdir}" config user.name "Test"

    # Base commit: existing changelog entry
    mkdir -p "${tmpdir}/packages/test_pkg"
    cat > "${tmpdir}/packages/test_pkg/changelog.yml" << 'EOF'
# newer versions go on top
- version: "1.0.0"
  changes:
    - description: Initial release.
      type: enhancement
      link: https://github.com/elastic/integrations/pull/100
EOF
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Initial release"

    echo "${tmpdir}"
}

add_changelog_entry() {
    local repo="$1"
    local changelog_file="$2"
    local link="$3"

    # Prepend the new entry on top of the existing file
    local tmp
    tmp="$(mktemp)"
    cat > "${tmp}" << EOF
# newer versions go on top
- version: "1.1.0"
  changes:
    - description: New feature.
      type: enhancement
      link: ${link}
EOF
    # Keep existing entries below
    grep -v '^# newer' "${repo}/${changelog_file}" >> "${tmp}" || true
    mv "${tmp}" "${repo}/${changelog_file}"

    git -C "${repo}" add "${changelog_file}"
    git -C "${repo}" commit -q -m "Add changelog entry"
}

# ---------------------------------------------------------------------------
# Tests: github_repo_path
# ---------------------------------------------------------------------------
echo "--- github_repo_path tests"

assert_equals "parses SSH remote URL" \
    "elastic/integrations" \
    "$(github_repo_path "git@github.com:elastic/integrations.git")"

assert_equals "parses HTTPS remote URL with .git suffix" \
    "elastic/integrations" \
    "$(github_repo_path "https://github.com/elastic/integrations.git")"

assert_equals "parses HTTPS remote URL without .git suffix" \
    "elastic/integrations" \
    "$(github_repo_path "https://github.com/elastic/integrations")"

assert_equals "preserves org name" \
    "my-org/my-repo" \
    "$(github_repo_path "git@github.com:my-org/my-repo.git")"

# ---------------------------------------------------------------------------
# Tests: check_changelog_file
# ---------------------------------------------------------------------------
echo ""
echo "--- check_changelog_file tests"

DUMMY_REPO="$(setup_dummy_repo)"
CHANGELOG="packages/test_pkg/changelog.yml"
EXPECTED_LINK="https://github.com/elastic/integrations/pull/999"

# Correct PR link
add_changelog_entry "${DUMMY_REPO}" "${CHANGELOG}" "${EXPECTED_LINK}"
BASE_REF="HEAD~1"
exit_code=0
(cd "${DUMMY_REPO}" && check_changelog_file "${BASE_REF}" "${CHANGELOG}" "${EXPECTED_LINK}") || exit_code=$?
assert_exit_code "correct PR link returns 0" "0" "${exit_code}"

# Wrong PR link
add_changelog_entry "${DUMMY_REPO}" "${CHANGELOG}" "https://github.com/elastic/integrations/pull/000"
BASE_REF="HEAD~1"
exit_code=0
(cd "${DUMMY_REPO}" && check_changelog_file "${BASE_REF}" "${CHANGELOG}" "${EXPECTED_LINK}") || exit_code=$?
assert_exit_code "wrong PR link returns non-zero" "1" "${exit_code}"

# Issue link is accepted
add_changelog_entry "${DUMMY_REPO}" "${CHANGELOG}" "https://github.com/elastic/integrations/issues/42"
BASE_REF="HEAD~1"
exit_code=0
(cd "${DUMMY_REPO}" && check_changelog_file "${BASE_REF}" "${CHANGELOG}" "${EXPECTED_LINK}") || exit_code=$?
assert_exit_code "issue link returns 0" "0" "${exit_code}"

# No new link entries (changelog unchanged since base)
exit_code=0
(cd "${DUMMY_REPO}" && check_changelog_file "HEAD" "${CHANGELOG}" "${EXPECTED_LINK}") || exit_code=$?
assert_exit_code "no added links returns 0" "0" "${exit_code}"

# Deleted file is skipped
exit_code=0
(cd "${DUMMY_REPO}" && check_changelog_file "HEAD~1" "packages/nonexistent/changelog.yml" "${EXPECTED_LINK}") || exit_code=$?
assert_exit_code "deleted/missing file returns 0" "0" "${exit_code}"

# Multiple wrong links accumulate errors
add_changelog_entry "${DUMMY_REPO}" "${CHANGELOG}" "https://github.com/elastic/integrations/pull/111"
add_changelog_entry "${DUMMY_REPO}" "${CHANGELOG}" "https://github.com/elastic/integrations/pull/222"
BASE_REF="HEAD~2"
exit_code=0
(cd "${DUMMY_REPO}" && check_changelog_file "${BASE_REF}" "${CHANGELOG}" "${EXPECTED_LINK}") || exit_code=$?
assert_exit_code "two wrong links returns 2" "2" "${exit_code}"

# ---------------------------------------------------------------------------
# Tests: get_pr_mention
# ---------------------------------------------------------------------------
echo ""
echo "--- get_pr_mention tests"

assert_equals "empty user returns empty string" \
    "" \
    "$(get_pr_mention "")"

assert_equals "regular user returns mention" \
    $'\n'"@johndoe" \
    "$(get_pr_mention "johndoe")"

assert_equals "github-actions[bot] returns elastic/ecosystem mention" \
    $'\n'"@elastic/ecosystem" \
    "$(get_pr_mention "github-actions[bot]")"

assert_equals "no argument returns empty string" \
    "" \
    "$(get_pr_mention)"

# ---------------------------------------------------------------------------
# Tests: should_skip_changelog_check
# ---------------------------------------------------------------------------
echo ""
echo "--- should_skip_changelog_check tests"

exit_code=0
should_skip_changelog_check "changelog-link-check:skip" || exit_code=$?
assert_exit_code "exact label returns 0" "0" "${exit_code}"

exit_code=0
should_skip_changelog_check "foo,changelog-link-check:skip,bar" || exit_code=$?
assert_exit_code "label in comma-separated list returns 0" "0" "${exit_code}"

exit_code=0
should_skip_changelog_check "skip-changelog" && exit_code=0 || exit_code=$?
assert_exit_code "wrong label 'skip-changelog' returns non-zero" "1" "${exit_code}"

exit_code=0
should_skip_changelog_check "" && exit_code=0 || exit_code=$?
assert_exit_code "empty labels returns non-zero" "1" "${exit_code}"

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
