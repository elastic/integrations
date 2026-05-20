#!/usr/bin/env bash
# Runs unit tests for scripts in dev/scripts/.
# TODO: migrate to the bats framework (https://github.com/bats-core/bats-core)
#       for better test isolation, TAP output, and native setup/teardown support.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="${REPO_ROOT}/dev/scripts/get_release_commit.sh"

pass=0
fail=0

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

echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
