#!/usr/bin/env bash
# Runs unit tests for scripts in dev/scripts/.
# TODO: migrate to the bats framework (https://github.com/bats-core/bats-core)
#       for better test isolation, TAP output, and native setup/teardown support.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="${REPO_ROOT}/dev/scripts/get_release_commit.sh"

pass=0
fail=0

DUMMY_REPO=""
cleanup() {
    [[ -n "$DUMMY_REPO" ]] && teardown_dummy_repo "$DUMMY_REPO"
}
trap cleanup EXIT

assert_equals() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        echo "PASS: ${description}"
        (( pass++ )) || true
    else
        echo "FAIL: ${description} — expected '${expected}', got '${actual}'"
        (( fail++ )) || true
    fi
}

assert_exit_code() {
    local description="$1"
    local expected="$2"
    local actual="$3"
    if [[ "${actual}" == "${expected}" ]]; then
        echo "PASS: ${description}"
        (( pass++ )) || true
    else
        echo "FAIL: ${description} — expected exit code '${expected}', got '${actual}'"
        (( fail++ )) || true
    fi
}

setup_dummy_repo() {
    # Creates a minimal git repo with two package layouts and two versions each:
    #   packages/flat_pkg/manifest.yml            (flat:   packages/<pkg>/)
    #   packages/group/nested_pkg/manifest.yml    (nested: packages/<group>/<pkg>/)
    # Each package gets two commits (1.0.0 then 1.1.0 / 2.0.0 then 2.1.0) so tests
    # can verify the script finds the right commit rather than just the latest one.
    # Commit hashes for the first versions are stored in .state/ inside the repo.
    local tmpdir
    tmpdir="$(mktemp -d)"
    git -C "$tmpdir" init -q
    git -C "$tmpdir" config user.email "test@test.com"
    git -C "$tmpdir" config user.name "Test"

    mkdir -p "${tmpdir}/packages/flat_pkg"
    printf 'name: flat_pkg\nversion: 1.0.0\n' > "${tmpdir}/packages/flat_pkg/manifest.yml"
    git -C "$tmpdir" add .
    git -C "$tmpdir" commit -q -m "Release flat_pkg 1.0.0"
    mkdir -p "${tmpdir}/.state"
    git -C "$tmpdir" rev-parse --short HEAD > "${tmpdir}/.state/flat_pkg_1.0.0"

    printf 'name: flat_pkg\nversion: 1.1.0\n' > "${tmpdir}/packages/flat_pkg/manifest.yml"
    git -C "$tmpdir" add .
    git -C "$tmpdir" commit -q -m "Release flat_pkg 1.1.0"

    mkdir -p "${tmpdir}/packages/group/nested_pkg"
    printf 'name: nested_pkg\nversion: 2.0.0\n' > "${tmpdir}/packages/group/nested_pkg/manifest.yml"
    git -C "$tmpdir" add .
    git -C "$tmpdir" commit -q -m "Release nested_pkg 2.0.0"
    git -C "$tmpdir" rev-parse --short HEAD > "${tmpdir}/.state/nested_pkg_2.0.0"

    printf 'name: nested_pkg\nversion: 2.1.0\n' > "${tmpdir}/packages/group/nested_pkg/manifest.yml"
    git -C "$tmpdir" add .
    git -C "$tmpdir" commit -q -m "Release nested_pkg 2.1.0"

    echo "$tmpdir"
}

teardown_dummy_repo() {
    rm -rf "$1"
}

echo "--- Running get_release_commit.sh tests"

# Package at packages/<p>/ with unquoted version
result="$("${SCRIPT}" -p prometheus -v 1.24.2)"
assert_equals "finds commit for package at packages/<p>/ (unquoted version)" "43bb655db0" "${result}"

# Package at packages/<p>/ with quoted version
result="$("${SCRIPT}" -p zscaler_zpa -v 1.23.3)"
assert_equals "finds commit for package at packages/<p>/ (quoted version)" "8b024204a8" "${result}"

# Version previously released as beta (9.3.8-beta.2 -> 9.3.8)
result="$("${SCRIPT}" -p security_detection_engine -v 9.3.8)"
assert_equals "finds commit for version promoted from beta" "fd04de398f" "${result}"

# Unknown package
exit_code=0
"${SCRIPT}" -p no_such_package -v 1.0.0 > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero for unknown package" "1" "${exit_code}"

# Unknown version
exit_code=0
"${SCRIPT}" -p prometheus -v 9.99.99 > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero for unknown version" "1" "${exit_code}"

# Missing -p flag
exit_code=0
"${SCRIPT}" -v 1.0.0 > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero when -p is missing" "1" "${exit_code}"

# Missing -v flag
exit_code=0
"${SCRIPT}" -p prometheus > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero when -v is missing" "1" "${exit_code}"

# Invalid flag
exit_code=0
"${SCRIPT}" -z > /dev/null 2>&1 || exit_code=$?
assert_exit_code "exits non-zero for invalid flag" "1" "${exit_code}"

echo "--- Running get_release_commit.sh tests (dummy repo)"
DUMMY_REPO="$(setup_dummy_repo)"
DUMMY_FLAT_COMMIT="$(cat "${DUMMY_REPO}/.state/flat_pkg_1.0.0")"
DUMMY_NESTED_COMMIT="$(cat "${DUMMY_REPO}/.state/nested_pkg_2.0.0")"

# Flat layout: packages/<pkg>/ — queries v1.0.0, not the latest v1.1.0
result="$(cd "$DUMMY_REPO" && "${SCRIPT}" -p flat_pkg -v 1.0.0)"
assert_equals "finds correct commit for packages/<p>/ (not the latest)" "${DUMMY_FLAT_COMMIT}" "${result}"

# Nested layout: packages/<group>/<pkg>/ — queries v2.0.0, not the latest v2.1.0
result="$(cd "$DUMMY_REPO" && "${SCRIPT}" -p nested_pkg -v 2.0.0)"
assert_equals "finds correct commit for packages/<group>/<p>/ (not the latest)" "${DUMMY_NESTED_COMMIT}" "${result}"

teardown_dummy_repo "$DUMMY_REPO"

echo "--- Running backport Python script tests"
for script in backport_check_active backport_resolve_package_dir \
              backport_extract_changelog_entry backport_insert_changelog_entry; do
    echo "  Testing ${script}.py"
    if python3 "${REPO_ROOT}/dev/scripts/${script}.py" --test 2>&1; then
        (( pass++ )) || true
    else
        (( fail++ )) || true
    fi
done

echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
