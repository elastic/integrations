#!/usr/bin/env bash
# Unit tests for backport_branch_lib.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

TMPDIR_PKGS=""
TMPDIR_REPO=""
TMPDIR_REPO2=""

cleanup() {
    [[ -n "${TMPDIR_PKGS}" ]] && rm -rf "${TMPDIR_PKGS}"
    [[ -n "${TMPDIR_REPO}" ]] && rm -rf "${TMPDIR_REPO}"
    [[ -n "${TMPDIR_REPO2}" ]] && rm -rf "${TMPDIR_REPO2}"
}
trap cleanup EXIT

TMPDIR_PKGS="$(mktemp -d)"

# Single mock controlled by MOCK_REPO_DIR. Strips the absolute prefix so the
# output is always relative (e.g. packages/nginx_otel), matching what the real
# list_all_directories returns in production.
MOCK_REPO_DIR="${TMPDIR_PKGS}"
list_all_directories() {
    find "${MOCK_REPO_DIR}/packages" -mindepth 1 -maxdepth 1 -type d | sort | sed "s|${MOCK_REPO_DIR}/||"
}

source "${REPO_ROOT}/.buildkite/scripts/backport_branch_lib.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

make_package() {
    local dir="${TMPDIR_PKGS}/packages/${1}"
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
    "$(get_required_package_names "${TMPDIR_PKGS}/packages/pkg_plain")"

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
    "$(get_required_package_names "${TMPDIR_PKGS}/packages/pkg_input_only")"

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
    "$(get_required_package_names "${TMPDIR_PKGS}/packages/pkg_content_only")"

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
    "$(get_required_package_names "${TMPDIR_PKGS}/packages/pkg_composable")"

# 5. Missing manifest file
assert_equals "missing manifest → empty output" \
    "" \
    "$(get_required_package_names "${TMPDIR_PKGS}/packages/nonexistent")"

# ---------------------------------------------------------------------------
# Tests: get_package_path
# ---------------------------------------------------------------------------
echo ""
echo "--- get_package_path tests"

assert_equals "finds pkg_plain by name" \
    "packages/pkg_plain" \
    "$(cd "${TMPDIR_PKGS}" && get_package_path "pkg_plain")"

assert_equals "finds pkg_composable by name" \
    "packages/pkg_composable" \
    "$(cd "${TMPDIR_PKGS}" && get_package_path "pkg_composable")"

exit_code=0
(cd "${TMPDIR_PKGS}" && get_package_path "nonexistent_package") || exit_code=$?
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

MOCK_REPO_DIR="${TMPDIR_REPO}"

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
# Tests: remove_other_packages with composable package dependencies
# ---------------------------------------------------------------------------
echo ""
echo "--- remove_other_packages with requires-based dependencies tests"

# Set up a fresh repo with a composable package and its dependencies
TMPDIR_REPO2="$(mktemp -d)"
mkdir -p "${TMPDIR_REPO2}/.github"
mkdir -p "${TMPDIR_REPO2}/packages/"{nginx_integration_otel,filelog_otel,nginx_otel_input,nginx_otel,unrelated_pkg}

cat > "${TMPDIR_REPO2}/packages/nginx_integration_otel/manifest.yml" <<'EOF'
name: nginx_integration_otel
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
printf 'name: filelog_otel\n'     > "${TMPDIR_REPO2}/packages/filelog_otel/manifest.yml"
printf 'name: nginx_otel_input\n' > "${TMPDIR_REPO2}/packages/nginx_otel_input/manifest.yml"
printf 'name: nginx_otel\n'       > "${TMPDIR_REPO2}/packages/nginx_otel/manifest.yml"
printf 'name: unrelated_pkg\n'    > "${TMPDIR_REPO2}/packages/unrelated_pkg/manifest.yml"

printf '/packages/nginx_integration_otel/ @team\n/packages/filelog_otel/ @team\n/packages/nginx_otel_input/ @team\n/packages/nginx_otel/ @team\n/packages/unrelated_pkg/ @team\n' \
    > "${TMPDIR_REPO2}/.github/CODEOWNERS"

MOCK_REPO_DIR="${TMPDIR_REPO2}"

# Replicate the logic from updateBackportBranchContents: resolve required package paths
# then call remove_other_packages with the full keep list. Everything runs from
# TMPDIR_REPO2 so relative paths (packages/<name>) resolve correctly.
(
    cd "${TMPDIR_REPO2}"
    target_path="packages/nginx_integration_otel"
    packages_to_keep=("${target_path}")
    while IFS= read -r req_name; do
        req_path="$(get_package_path "${req_name}" || true)"
        [[ -n "${req_path}" ]] && packages_to_keep+=("${req_path}")
    done < <(get_required_package_names "${target_path}")
    remove_other_packages "${packages_to_keep[@]}"
)

assert_equals "target package nginx_integration_otel is kept" \
    "true" "$([[ -d "${TMPDIR_REPO2}/packages/nginx_integration_otel" ]] && echo true || echo false)"

assert_equals "required input package filelog_otel is kept" \
    "true" "$([[ -d "${TMPDIR_REPO2}/packages/filelog_otel" ]] && echo true || echo false)"

assert_equals "required input package nginx_otel_input is kept" \
    "true" "$([[ -d "${TMPDIR_REPO2}/packages/nginx_otel_input" ]] && echo true || echo false)"

assert_equals "required content package nginx_otel is kept" \
    "true" "$([[ -d "${TMPDIR_REPO2}/packages/nginx_otel" ]] && echo true || echo false)"

assert_equals "unrelated package is removed" \
    "true" "$([[ ! -d "${TMPDIR_REPO2}/packages/unrelated_pkg" ]] && echo true || echo false)"

assert_equals "unrelated_pkg entry removed from CODEOWNERS" \
    "false" "$(grep -q 'unrelated_pkg' "${TMPDIR_REPO2}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "nginx_integration_otel entry kept in CODEOWNERS" \
    "true" "$(grep -q 'nginx_integration_otel' "${TMPDIR_REPO2}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "filelog_otel entry kept in CODEOWNERS" \
    "true" "$(grep -q 'filelog_otel' "${TMPDIR_REPO2}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "nginx_otel_input entry kept in CODEOWNERS" \
    "true" "$(grep -q 'nginx_otel_input' "${TMPDIR_REPO2}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "nginx_otel entry kept in CODEOWNERS" \
    "true" "$(grep -q 'nginx_otel' "${TMPDIR_REPO2}/.github/CODEOWNERS" && echo true || echo false)"

rm -rf "${TMPDIR_REPO2}"

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
