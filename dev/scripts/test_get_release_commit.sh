#!/usr/bin/env bash
# Unit tests for get_release_commit.sh.
# Run directly or via .buildkite/scripts/run_dev_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="${REPO_ROOT}/dev/scripts/get_release_commit.sh"

source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Helpers: set up / tear down a minimal git repo with two package layouts.
#
# Creates:
#   packages/flat_pkg/manifest.yml            (flat:   packages/<pkg>/, unquoted version)
#   packages/group/nested_pkg/manifest.yml    (nested: packages/<group>/<pkg>/)
#   packages/quoted_pkg/manifest.yml          (flat, version string in quotes)
#   packages/beta_pkg/manifest.yml            (flat, version promoted from beta)
# Each package gets multiple commits so tests can verify the script finds the
# right commit, not just the latest. Commit hashes are stored in .state/.
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

    mkdir -p "${tmpdir}/packages/flat_pkg"
    printf 'name: flat_pkg\nversion: 1.0.0\n' > "${tmpdir}/packages/flat_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release flat_pkg 1.0.0"
    mkdir -p "${tmpdir}/.state"
    git -C "${tmpdir}" rev-parse --short HEAD > "${tmpdir}/.state/flat_pkg_1.0.0"

    printf 'name: flat_pkg\nversion: 1.1.0\n' > "${tmpdir}/packages/flat_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release flat_pkg 1.1.0"

    mkdir -p "${tmpdir}/packages/group/nested_pkg"
    printf 'name: nested_pkg\nversion: 2.0.0\n' > "${tmpdir}/packages/group/nested_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release nested_pkg 2.0.0"
    git -C "${tmpdir}" rev-parse --short HEAD > "${tmpdir}/.state/nested_pkg_2.0.0"

    printf 'name: nested_pkg\nversion: 2.1.0\n' > "${tmpdir}/packages/group/nested_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release nested_pkg 2.1.0"

    mkdir -p "${tmpdir}/packages/quoted_pkg"
    printf 'name: quoted_pkg\nversion: "1.0.0"\n' > "${tmpdir}/packages/quoted_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release quoted_pkg 1.0.0"
    git -C "${tmpdir}" rev-parse --short HEAD > "${tmpdir}/.state/quoted_pkg_1.0.0"

    printf 'name: quoted_pkg\nversion: "1.1.0"\n' > "${tmpdir}/packages/quoted_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release quoted_pkg 1.1.0"

    mkdir -p "${tmpdir}/packages/beta_pkg"
    printf 'name: beta_pkg\nversion: 3.0.0-beta.1\n' > "${tmpdir}/packages/beta_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release beta_pkg 3.0.0-beta.1"

    printf 'name: beta_pkg\nversion: 3.0.0\n' > "${tmpdir}/packages/beta_pkg/manifest.yml"
    git -C "${tmpdir}" add .
    git -C "${tmpdir}" commit -q -m "Release beta_pkg 3.0.0"
    git -C "${tmpdir}" rev-parse --short HEAD > "${tmpdir}/.state/beta_pkg_3.0.0"

    echo "${tmpdir}"
}

# ---------------------------------------------------------------------------
# Tests: flag validation (no package lookup; agnostic of packages on disk)
# ---------------------------------------------------------------------------
echo "--- get_release_commit.sh tests"

# Missing -p flag
exit_code=0
"${SCRIPT}" -v 1.0.0 > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero when -p is missing" "1" "${exit_code}"

# Missing -v flag
exit_code=0
"${SCRIPT}" -p any_pkg > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero when -v is missing" "1" "${exit_code}"

# Invalid flag
exit_code=0
"${SCRIPT}" -z > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero for invalid flag" "1" "${exit_code}"

# ---------------------------------------------------------------------------
# Tests: against dummy repo (isolated from real history)
# ---------------------------------------------------------------------------
echo ""
echo "--- get_release_commit.sh tests (dummy repo)"

DUMMY_REPO="$(setup_dummy_repo)"
DUMMY_FLAT_COMMIT="$(cat "${DUMMY_REPO}/.state/flat_pkg_1.0.0")"
DUMMY_NESTED_COMMIT="$(cat "${DUMMY_REPO}/.state/nested_pkg_2.0.0")"
DUMMY_QUOTED_COMMIT="$(cat "${DUMMY_REPO}/.state/quoted_pkg_1.0.0")"
DUMMY_BETA_COMMIT="$(cat "${DUMMY_REPO}/.state/beta_pkg_3.0.0")"

# Flat layout: packages/<pkg>/ — queries v1.0.0, not the latest v1.1.0
result="$(cd "${DUMMY_REPO}" && "${SCRIPT}" -p flat_pkg -v 1.0.0)"
assert_equals "finds correct commit for packages/<p>/ (not the latest)" "${DUMMY_FLAT_COMMIT}" "${result}"

# Nested layout: packages/<group>/<pkg>/ — queries v2.0.0, not the latest v2.1.0
result="$(cd "${DUMMY_REPO}" && "${SCRIPT}" -p nested_pkg -v 2.0.0)"
assert_equals "finds correct commit for packages/<group>/<p>/ (not the latest)" "${DUMMY_NESTED_COMMIT}" "${result}"

# Quoted version in manifest (version: "1.0.0") — queries v1.0.0, not the latest v1.1.0
result="$(cd "${DUMMY_REPO}" && "${SCRIPT}" -p quoted_pkg -v 1.0.0)"
assert_equals "finds correct commit for package with quoted version in manifest" "${DUMMY_QUOTED_COMMIT}" "${result}"

# Version promoted from beta (3.0.0-beta.1 → 3.0.0)
result="$(cd "${DUMMY_REPO}" && "${SCRIPT}" -p beta_pkg -v 3.0.0)"
assert_equals "finds commit for version promoted from beta" "${DUMMY_BETA_COMMIT}" "${result}"

# Unknown package
exit_code=0
(cd "${DUMMY_REPO}" && "${SCRIPT}" -p no_such_package -v 1.0.0) > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero for unknown package" "1" "${exit_code}"

# Unknown version
exit_code=0
(cd "${DUMMY_REPO}" && "${SCRIPT}" -p flat_pkg -v 9.99.99) > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero for unknown version" "1" "${exit_code}"

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
