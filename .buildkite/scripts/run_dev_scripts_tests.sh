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
DUMMY_INVENTORY=""
cleanup() {
    [[ -n "${DUMMY_REPO}" ]] && teardown_dummy_repo "${DUMMY_REPO}"
    [[ -n "${DUMMY_INVENTORY}" ]] && rm -f "${DUMMY_INVENTORY}"
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

echo "--- Running backport_check_active.sh tests"

ACTIVE_SCRIPT="${REPO_ROOT}/dev/scripts/backport_check_active.sh"

# Create a temporary inventory file with known entries for all test cases.
# DUMMY_INVENTORY is declared at the top so the shared EXIT trap cleans it up.
DUMMY_INVENTORY="$(mktemp)"
cat > "${DUMMY_INVENTORY}" <<'YAML'
backports:
  - package: mypkg
    branch: backport-mypkg-1.0
    base_version: "1.0.0"
    base_commit: "aabbccddee"
    maintained_until: null
    archived: false

  - package: mypkg
    branch: backport-mypkg-2.0
    base_version: "2.0.0"
    base_commit: "11223344ff"
    maintained_until: null
    archived: true

  - package: mypkg
    branch: backport-mypkg-3.0
    base_version: "3.0.0"
    base_commit: "aabbccddee"
    maintained_until: "2020-01-01"
    archived: false

  - package: mypkg
    branch: backport-mypkg-4.0
    base_version: "4.0.0"
    base_commit: "aabbccddee"
    maintained_until: "2099-12-31"
    archived: false

  - package: mypkg
    branch: backport-mypkg-5.0
    base_version: "5.0.0"
    base_commit: "aabbccddee"
    maintained_until: "2099-12-31"
    archived: true
YAML

# Exit code helpers (BACKPORTS_INVENTORY override avoids touching the real file).
run_check() { BACKPORTS_INVENTORY="${DUMMY_INVENTORY}" "${ACTIVE_SCRIPT}" "$@"; }

# active branch: archived=false, maintained_until=null → exit 0, "active"
exit_code=0
result="$(run_check --branch backport-mypkg-1.0)" || exit_code=$?
assert_exit_code "active branch exits 0" "0" "${exit_code}"
assert_equals  "active branch prints 'active'" "backport-mypkg-1.0: active" "${result}"

# inactive: archived=true → exit 1
exit_code=0
run_check --branch backport-mypkg-2.0 > /dev/null || exit_code=$?
assert_exit_code "archived branch exits 1" "1" "${exit_code}"
result="$(run_check --branch backport-mypkg-2.0 || true)"
assert_equals "archived branch prints 'inactive (archived)'" \
    "backport-mypkg-2.0: inactive (archived)" "${result}"

# inactive: maintained_until in the past → exit 1
exit_code=0
run_check --branch backport-mypkg-3.0 > /dev/null || exit_code=$?
assert_exit_code "expired maintained_until exits 1" "1" "${exit_code}"

# active: maintained_until far in the future → exit 0
exit_code=0
run_check --branch backport-mypkg-4.0 > /dev/null || exit_code=$?
assert_exit_code "future maintained_until exits 0" "0" "${exit_code}"

# archived takes precedence over future maintained_until → exit 1
exit_code=0
run_check --branch backport-mypkg-5.0 > /dev/null || exit_code=$?
assert_exit_code "archived beats future maintained_until: exits 1" "1" "${exit_code}"

# --json: active branch
result="$(run_check --branch backport-mypkg-1.0 --json)"
assert_equals "--json active branch: correct shape" \
    '{"branch":"backport-mypkg-1.0","active":true,"archived":false,"maintained_until":null}' \
    "${result}"

# --json: archived branch
result="$(run_check --branch backport-mypkg-2.0 --json || true)"
assert_equals "--json archived branch: active=false" \
    '{"branch":"backport-mypkg-2.0","active":false,"archived":true,"maintained_until":null}' \
    "${result}"

# --json: branch with a date maintained_until
result="$(run_check --branch backport-mypkg-4.0 --json)"
assert_equals "--json future maintained_until: quoted date" \
    '{"branch":"backport-mypkg-4.0","active":true,"archived":false,"maintained_until":"2099-12-31"}' \
    "${result}"

# unknown branch → exit 2
exit_code=0
run_check --branch backport-no-such-branch > /dev/null 2>&1 || exit_code=$?
assert_exit_code "unknown branch exits 2" "2" "${exit_code}"

# missing --branch → exit 2
exit_code=0
run_check > /dev/null 2>&1 || exit_code=$?
assert_exit_code "missing --branch exits 2" "2" "${exit_code}"

# unknown flag → exit 2
exit_code=0
run_check --unknown-flag > /dev/null 2>&1 || exit_code=$?
assert_exit_code "unknown flag exits 2" "2" "${exit_code}"

echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
