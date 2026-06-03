#!/usr/bin/env bash
# Unit tests for backport_check_active.sh.
# Run directly or via .buildkite/scripts/run_dev_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
SCRIPT="${REPO_ROOT}/dev/scripts/backport_check_active.sh"

source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Helpers: set up / tear down a temporary inventory file.
# ---------------------------------------------------------------------------

DUMMY_INVENTORY=""

cleanup() {
    [[ -n "${DUMMY_INVENTORY}" ]] && rm -f "${DUMMY_INVENTORY}"
}
trap cleanup EXIT

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

# BACKPORTS_INVENTORY override avoids touching the real file.
run_check() { BACKPORTS_INVENTORY="${DUMMY_INVENTORY}" "${SCRIPT}" "$@"; }

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
echo "--- backport_check_active.sh tests"

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

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
