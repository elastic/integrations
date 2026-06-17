#!/usr/bin/env bash
# Unit tests for generate_trigger_pipeline() from trigger_backport_lib.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.
#
# Requires: yq (installed via with_yq in CI; must be available locally too).

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

source "${REPO_ROOT}/.buildkite/scripts/trigger_backport_lib.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Mock: mage — set MOCK_MAGE_EXIT to control CheckBackportBranchActive result.
#   0 = active (default)
#   1 = inactive
#   2 = error
# ---------------------------------------------------------------------------
mage() {
    return "${MOCK_MAGE_EXIT:-0}"
}
MOCK_MAGE_EXIT=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

WORK_DIR=""
cleanup() {
    [[ -n "${WORK_DIR}" ]] && rm -rf "${WORK_DIR}"
}
trap cleanup EXIT
WORK_DIR="$(mktemp -d)"

# Write a .backports.yml with one or more entries.
# Each entry requires exactly 5 args: branch pkg base_version base_commit archived
# Usage: write_inventory <file> <branch> <pkg> <base_version> <base_commit> <archived> ...
write_inventory() {
    local file="$1"; shift
    printf 'backports:\n' > "${file}"
    while [[ $# -ge 5 ]]; do
        local branch="$1" pkg="$2" base_version="$3" base_commit="$4" archived="$5"
        cat >> "${file}" <<EOF
  - package: ${pkg}
    branch: ${branch}
    base_version: "${base_version}"
    base_commit: "${base_commit}"
    maintained_until: null
    archived: ${archived}
EOF
        shift 5
    done
}

# Run generate_trigger_pipeline into a fresh output file.
# Usage: run_generate <old> <new> <dry_run> <pr_number> <out_file>
run_generate() {
    local old="$1" new="$2" dry_run="$3" pr_number="$4" out="$5"
    : > "${out}"
    generate_trigger_pipeline "${old}" "${new}" "${dry_run}" "${pr_number}" "${out}" || true
}

OLD="${WORK_DIR}/old.yml"
NEW="${WORK_DIR}/new.yml"
OUT="${WORK_DIR}/pipeline.yml"

# ---------------------------------------------------------------------------
# Test: new entry in dry-run mode
# ---------------------------------------------------------------------------
echo "--- new entry — dry-run mode"

write_inventory "${OLD}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false"
write_inventory "${NEW}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false" \
    "backport-aws-2.0"  "aws" "2.0.0"  "def456" "false"

run_generate "${OLD}" "${NEW}" "true" "" "${OUT}"

assert_file_contains     "dry-run: step header present"           "steps:"                                   "${OUT}"
assert_file_contains     "dry-run: label is Backport dry-run"    'Backport dry-run: backport-aws-2.0'       "${OUT}"
assert_file_contains     "dry-run: DRY_RUN is true"              'DRY_RUN: "true"'                          "${OUT}"
assert_file_contains     "dry-run: PACKAGE_NAME correct"         'PACKAGE_NAME: "aws"'                      "${OUT}"
assert_file_contains     "dry-run: PACKAGE_VERSION correct"      'PACKAGE_VERSION: "2.0.0"'                 "${OUT}"
assert_file_contains     "dry-run: BASE_COMMIT correct"          'BASE_COMMIT: "def456"'                    "${OUT}"
assert_file_contains     "dry-run: BACKPORT_BRANCH_NAME correct" 'BACKPORT_BRANCH_NAME: "backport-aws-2.0"' "${OUT}"
assert_file_not_contains "dry-run: PR_NUMBER absent when empty"  "PR_NUMBER"                                "${OUT}"

# ---------------------------------------------------------------------------
# Test: new entry in create mode
# ---------------------------------------------------------------------------
echo "--- new entry — create mode"

run_generate "${OLD}" "${NEW}" "false" "" "${OUT}"

assert_file_contains "create: label is Backport create" 'Backport create: backport-aws-2.0' "${OUT}"
assert_file_contains "create: DRY_RUN is false"         'DRY_RUN: "false"'                  "${OUT}"

# ---------------------------------------------------------------------------
# Test: PR_NUMBER included when provided, omitted when empty
# ---------------------------------------------------------------------------
echo "--- PR_NUMBER"

run_generate "${OLD}" "${NEW}" "false" "9999" "${OUT}"
assert_file_contains     "PR_NUMBER included when set"  'PR_NUMBER: "9999"' "${OUT}"

run_generate "${OLD}" "${NEW}" "false" "" "${OUT}"
assert_file_not_contains "PR_NUMBER omitted when empty" "PR_NUMBER"         "${OUT}"

# ---------------------------------------------------------------------------
# Test: existing entry is skipped
# ---------------------------------------------------------------------------
echo "--- existing entry skipped"

write_inventory "${OLD}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false"
write_inventory "${NEW}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false"

run_generate "${OLD}" "${NEW}" "true" "" "${OUT}"
assert_equals "existing entry: no steps generated" "" "$(cat "${OUT}")"

# ---------------------------------------------------------------------------
# Test: inactive entry (mage returns 1) is skipped
# ---------------------------------------------------------------------------
echo "--- inactive entry skipped"

write_inventory "${OLD}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false"
write_inventory "${NEW}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false" \
    "backport-aws-2.0"  "aws" "2.0.0"  "def456" "true"

MOCK_MAGE_EXIT=1
run_generate "${OLD}" "${NEW}" "true" "" "${OUT}"
MOCK_MAGE_EXIT=0

assert_equals "inactive entry: no steps generated" "" "$(cat "${OUT}")"

# ---------------------------------------------------------------------------
# Test: mage error (exit code 2) causes function to return non-zero
# ---------------------------------------------------------------------------
echo "--- mage error propagated"

write_inventory "${OLD}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false"
write_inventory "${NEW}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false" \
    "backport-aws-2.0"  "aws" "2.0.0"  "def456" "false"

MOCK_MAGE_EXIT=2
err_exit=0
: > "${OUT}"
generate_trigger_pipeline "${OLD}" "${NEW}" "true" "" "${OUT}" || err_exit=$?
MOCK_MAGE_EXIT=0

assert_exit_code "mage error: non-zero exit returned" "1" "${err_exit}"

# ---------------------------------------------------------------------------
# Test: multiple new entries all appear in pipeline
# ---------------------------------------------------------------------------
echo "--- multiple new entries"

write_inventory "${OLD}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false"
write_inventory "${NEW}" \
    "backport-aws-1.19" "aws" "1.19.5" "abc123" "false" \
    "backport-aws-2.0"  "aws" "2.0.0"  "def456" "false" \
    "backport-gcp-1.5"  "gcp" "1.5.0"  "ghi789" "false"

run_generate "${OLD}" "${NEW}" "true" "" "${OUT}"

assert_file_contains "multiple: aws step present" "backport-aws-2.0" "${OUT}"
assert_file_contains "multiple: gcp step present" "backport-gcp-1.5" "${OUT}"

# ---------------------------------------------------------------------------
# Test: invalid old inventory returns non-zero
# ---------------------------------------------------------------------------
echo "--- invalid inventory"

echo "not: yaml: backports" > "${OLD}"
write_inventory "${NEW}" \
    "backport-aws-2.0" "aws" "2.0.0" "def456" "false"

inv_exit=0
: > "${OUT}"
generate_trigger_pipeline "${OLD}" "${NEW}" "true" "" "${OUT}" || inv_exit=$?

assert_exit_code "invalid old inventory: non-zero exit" "1" "${inv_exit}"

# ---------------------------------------------------------------------------
# Test: validate_backport_branch_name
# ---------------------------------------------------------------------------
echo "--- validate_backport_branch_name"

# Valid names
assert_exit_code "valid: numeric minor"       "0" "$(validate_backport_branch_name "backport-aws-1.19"      2>/dev/null; echo $?)"
assert_exit_code "valid: x minor"             "0" "$(validate_backport_branch_name "backport-aws-6.x"       2>/dev/null; echo $?)"
assert_exit_code "valid: underscore in pkg"   "0" "$(validate_backport_branch_name "backport-my_pkg-2.0"    2>/dev/null; echo $?)"
assert_exit_code "valid: single-digit minor"  "0" "$(validate_backport_branch_name "backport-gcp-1.5"       2>/dev/null; echo $?)"

# Invalid names
assert_exit_code "invalid: hyphen in pkg"     "1" "$(validate_backport_branch_name "backport-my-pkg-2.0"    2>/dev/null; echo $?)"
assert_exit_code "invalid: missing minor"     "1" "$(validate_backport_branch_name "backport-aws-1"         2>/dev/null; echo $?)"
assert_exit_code "invalid: mixed minor"       "1" "$(validate_backport_branch_name "backport-aws-6.1x"      2>/dev/null; echo $?)"
assert_exit_code "invalid: wrong prefix"      "1" "$(validate_backport_branch_name "not-backport-1.0"       2>/dev/null; echo $?)"
assert_exit_code "invalid: double-quote"      "1" "$(validate_backport_branch_name 'backport-foo"bar-1.0'   2>/dev/null; echo $?)"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
