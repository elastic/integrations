#!/usr/bin/env bash
# Unit tests for backport_branch_lib.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

TMPDIR_PKGS=""
TMPDIR_REPO=""

cleanup() {
    [[ -n "${TMPDIR_PKGS}" ]] && rm -rf "${TMPDIR_PKGS}"
    [[ -n "${TMPDIR_REPO}" ]] && rm -rf "${TMPDIR_REPO}"
}
trap cleanup EXIT

TMPDIR_PKGS="$(mktemp -d)"

# Override list_all_directories so lib functions use our fixture packages.
list_all_directories() {
    find "${TMPDIR_PKGS}" -mindepth 1 -maxdepth 1 -type d | sort
}

source "${REPO_ROOT}/.buildkite/scripts/backport_branch_lib.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

make_package() {
    local dir="${TMPDIR_PKGS}/${1}"
    mkdir -p "${dir}"
    printf '%s\n' "${2}" > "${dir}/manifest.yml"
}

# ---------------------------------------------------------------------------
# Tests: get_required_package_names
# ---------------------------------------------------------------------------
echo "--- get_required_package_names tests"

# 1. No requires key at all
make_package "pkg_plain" "name: pkg_plain"
assert_equals "no requires key → empty output" \
    "" \
    "$(get_required_package_names "${TMPDIR_PKGS}/pkg_plain")"

# 2. requires.input only
make_package "pkg_input_only" "$(cat <<'EOF'
name: pkg_input_only
requires:
  input:
    - package: filelog_otel
      version: "0.2.0"
    - package: nginx_otel_input
      version: 0.1.0
EOF
)"
assert_equals "requires.input only → two names" \
    $'filelog_otel\nnginx_otel_input' \
    "$(get_required_package_names "${TMPDIR_PKGS}/pkg_input_only")"

# 3. requires.content only
make_package "pkg_content_only" "$(cat <<'EOF'
name: pkg_content_only
requires:
  content:
    - package: nginx_otel
      version: 0.3.0
EOF
)"
assert_equals "requires.content only → one name" \
    "nginx_otel" \
    "$(get_required_package_names "${TMPDIR_PKGS}/pkg_content_only")"

# 4. Both requires.input and requires.content
make_package "pkg_composable" "$(cat <<'EOF'
name: pkg_composable
requires:
  input:
    - package: filelog_otel
      version: "0.2.0"
    - package: nginx_otel_input
      version: 0.1.0
  content:
    - package: nginx_otel
      version: 0.3.0
EOF
)"
assert_equals "both input+content → three names" \
    $'filelog_otel\nnginx_otel_input\nnginx_otel' \
    "$(get_required_package_names "${TMPDIR_PKGS}/pkg_composable")"

# 5. Missing manifest file
assert_equals "missing manifest → empty output" \
    "" \
    "$(get_required_package_names "${TMPDIR_PKGS}/nonexistent")"

# ---------------------------------------------------------------------------
# Tests: get_package_path
# ---------------------------------------------------------------------------
echo ""
echo "--- get_package_path tests"

assert_equals "finds pkg_plain by name" \
    "${TMPDIR_PKGS}/pkg_plain" \
    "$(get_package_path "pkg_plain")"

assert_equals "finds pkg_composable by name" \
    "${TMPDIR_PKGS}/pkg_composable" \
    "$(get_package_path "pkg_composable")"

exit_code=0
get_package_path "nonexistent_package" || exit_code=$?
assert_exit_code "unknown package name returns non-zero" "1" "${exit_code}"

# ---------------------------------------------------------------------------
# Tests: remove_other_packages
# ---------------------------------------------------------------------------
echo ""
echo "--- remove_other_packages tests"

TMPDIR_REPO="$(mktemp -d)"
mkdir -p "${TMPDIR_REPO}/.github"
mkdir -p "${TMPDIR_REPO}/packages/"{pkg_a,pkg_b,pkg_c}
printf '/packages/pkg_a/ @team-a\n/packages/pkg_b/ @team-b\n/packages/pkg_c/ @team-c\n' \
    > "${TMPDIR_REPO}/.github/CODEOWNERS"

# Override list_all_directories for this block to use TMPDIR_REPO/packages
list_all_directories() {
    find "${TMPDIR_REPO}/packages" -mindepth 1 -maxdepth 1 -type d | sort
}

(cd "${TMPDIR_REPO}" && remove_other_packages "packages/pkg_a" "packages/pkg_b")

assert_equals "pkg_a is kept" \
    "true" "$([[ -d "${TMPDIR_REPO}/packages/pkg_a" ]] && echo true || echo false)"

assert_equals "pkg_b is kept" \
    "true" "$([[ -d "${TMPDIR_REPO}/packages/pkg_b" ]] && echo true || echo false)"

assert_equals "pkg_c is removed" \
    "true" "$([[ ! -d "${TMPDIR_REPO}/packages/pkg_c" ]] && echo true || echo false)"

assert_equals "pkg_c entry removed from CODEOWNERS" \
    "false" "$(grep -q 'pkg_c' "${TMPDIR_REPO}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "pkg_a entry kept in CODEOWNERS" \
    "true" "$(grep -q 'pkg_a' "${TMPDIR_REPO}/.github/CODEOWNERS" && echo true || echo false)"

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
