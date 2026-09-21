#!/usr/bin/env bash
# Unit tests for backport_branch_lib.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

TMPDIR_PKGS=""
TMPDIR_REPO=""
TMPDIR_REPO2=""
TMPDIR_LINK=""   # unit tests for collect_linked_packages_from_roots (single-hop cases)
TMPDIR_REPO3=""
TMPDIR_TRANS=""  # unit tests for collect_linked_packages_from_roots (transitive cases)
TMPDIR_REPO4=""
TMPDIR_REPO5=""
TMPDIR_REPO6=""

cleanup() {
    [[ -n "${TMPDIR_PKGS}" ]] && rm -rf "${TMPDIR_PKGS}"
    [[ -n "${TMPDIR_REPO}" ]] && rm -rf "${TMPDIR_REPO}"
    [[ -n "${TMPDIR_REPO2}" ]] && rm -rf "${TMPDIR_REPO2}"
    [[ -n "${TMPDIR_LINK}" ]] && rm -rf "${TMPDIR_LINK}"
    [[ -n "${TMPDIR_REPO3}" ]] && rm -rf "${TMPDIR_REPO3}"
    [[ -n "${TMPDIR_TRANS}" ]] && rm -rf "${TMPDIR_TRANS}"
    [[ -n "${TMPDIR_REPO4}" ]] && rm -rf "${TMPDIR_REPO4}"
    [[ -n "${TMPDIR_REPO5}" ]] && rm -rf "${TMPDIR_REPO5}"
    [[ -n "${TMPDIR_REPO6}" ]] && rm -rf "${TMPDIR_REPO6}"
}
trap cleanup EXIT

TMPDIR_PKGS="$(mktemp -d)"

# Single mock controlled by MOCK_REPO_DIR. Discovers packages by finding
# manifest.yml at depth 2 (packages/pkg) and depth 3 (packages/technology/pkg),
# mirroring what mage listPackages does in production. Using bounded depths
# avoids picking up manifest.yml files that live deeper inside packages (e.g.
# data stream manifests at depth 4+). Strips the absolute prefix so the output
# is always relative (e.g. packages/nginx_otel), matching production output.
MOCK_REPO_DIR="${TMPDIR_PKGS}"
list_all_directories() {
    {
        find "${MOCK_REPO_DIR}/packages" -mindepth 2 -maxdepth 2 -name "manifest.yml" -exec dirname {} \;
        find "${MOCK_REPO_DIR}/packages" -mindepth 3 -maxdepth 3 -name "manifest.yml" -exec dirname {} \;
    } | sort -u | sed "s|${MOCK_REPO_DIR}/||"
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
printf 'name: pkg_a\n' > "${TMPDIR_REPO}/packages/pkg_a/manifest.yml"
printf 'name: pkg_b\n' > "${TMPDIR_REPO}/packages/pkg_b/manifest.yml"
printf 'name: pkg_c\n' > "${TMPDIR_REPO}/packages/pkg_c/manifest.yml"
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
    packages_to_keep=()
    while IFS= read -r pkg; do packages_to_keep+=("${pkg}"); done \
        < <(collect_packages_to_keep "packages/nginx_integration_otel")
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
# Tests: collect_linked_packages_from_roots (single-package, edge cases)
# ---------------------------------------------------------------------------
echo ""
echo "--- collect_linked_packages_from_roots unit tests"

TMPDIR_LINK="$(mktemp -d)"
mkdir -p "${TMPDIR_LINK}/packages"
MOCK_REPO_DIR="${TMPDIR_LINK}"

# 1. No .link files → empty output
mkdir -p "${TMPDIR_LINK}/packages/pkg_no_links"
printf 'name: pkg_no_links\n' > "${TMPDIR_LINK}/packages/pkg_no_links/manifest.yml"
assert_equals "no .link files → empty output" \
    "" \
    "$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/pkg_no_links")"

# 2. .link file pointing to _dev/shared inside the same package → empty (filtered)
# Layout mirrors the real pattern: link file is in data_stream/*/fields/ and source
# is in the package's own _dev/shared/fields/.
mkdir -p "${TMPDIR_LINK}/packages/pkg_self_link/data_stream/ds1/fields"
mkdir -p "${TMPDIR_LINK}/packages/pkg_self_link/_dev/shared/fields"
printf 'name: pkg_self_link\n' > "${TMPDIR_LINK}/packages/pkg_self_link/manifest.yml"
touch "${TMPDIR_LINK}/packages/pkg_self_link/_dev/shared/fields/ecs.yml"
# ../../../ from data_stream/ds1/fields/ goes up to the package root
printf '../../../_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/pkg_self_link/data_stream/ds1/fields/ecs.yml.link"
assert_equals ".link pointing to same package _dev/shared → empty (filtered)" \
    "" \
    "$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/pkg_self_link")"

# 3. .link file with ../ traversal pointing to _dev/shared in a different package
mkdir -p "${TMPDIR_LINK}/packages/pkg_target/data_stream/ds1/fields"
printf 'name: pkg_target\n' > "${TMPDIR_LINK}/packages/pkg_target/manifest.yml"
mkdir -p "${TMPDIR_LINK}/packages/pkg_source/_dev/shared/fields"
printf 'name: pkg_source\n' > "${TMPDIR_LINK}/packages/pkg_source/manifest.yml"
touch "${TMPDIR_LINK}/packages/pkg_source/_dev/shared/fields/beats.yml"
# ../../../../ from data_stream/ds1/fields/ reaches packages/, then into pkg_source
printf '../../../../pkg_source/_dev/shared/fields/beats.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/pkg_target/data_stream/ds1/fields/beats.yml.link"
assert_equals ".link with ../ traversal pointing to different package _dev/shared → that package path" \
    "packages/pkg_source" \
    "$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/pkg_target")"

# 4. .link file pointing to _dev/shared at repo root (outside all packages) → empty + warning
# Layout: link is 5 levels deep; ../../../../../ reaches repo root where _dev/shared lives.
mkdir -p "${TMPDIR_LINK}/packages/pkg_outside_link/data_stream/ds1/fields"
printf 'name: pkg_outside_link\n' > "${TMPDIR_LINK}/packages/pkg_outside_link/manifest.yml"
printf '../../../../../_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/pkg_outside_link/data_stream/ds1/fields/ecs.yml.link"
WARN_FILE="$(mktemp)"
actual_outside="$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/pkg_outside_link" 2>"${WARN_FILE}")"
assert_equals ".link pointing to repo-root _dev/shared → empty stdout" \
    "" \
    "${actual_outside}"
assert_file_contains ".link pointing to repo-root _dev/shared → warning on stderr" \
    "Warning:" \
    "${WARN_FILE}"
rm -f "${WARN_FILE}"

# 5. Packages nested under a technology sub-folder (packages/technology/pkg1 etc.)
# The updated mock finds manifest.yml at depth 2 and depth 3, so these packages
# are discovered automatically via MOCK_REPO_DIR without any subshell override.
mkdir -p "${TMPDIR_LINK}/packages/technology/pkg1/data_stream/ds1/fields"
mkdir -p "${TMPDIR_LINK}/packages/technology/pkg1/_dev/shared/fields"
mkdir -p "${TMPDIR_LINK}/packages/technology/pkg2/_dev/shared/fields"
mkdir -p "${TMPDIR_LINK}/packages/pkg3/data_stream/ds1/fields"
printf 'name: pkg1\n' > "${TMPDIR_LINK}/packages/technology/pkg1/manifest.yml"
printf 'name: pkg2\n' > "${TMPDIR_LINK}/packages/technology/pkg2/manifest.yml"
printf 'name: pkg3\n' > "${TMPDIR_LINK}/packages/pkg3/manifest.yml"
touch "${TMPDIR_LINK}/packages/technology/pkg2/_dev/shared/fields/ecs.yml"
touch "${TMPDIR_LINK}/packages/technology/pkg1/_dev/shared/fields/beats.yml"

# 5a. Link from depth-3 package (technology/pkg1) → sibling depth-3 package (technology/pkg2)
# ../../../../ from data_stream/ds1/fields/ reaches packages/technology/
printf '../../../../pkg2/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/technology/pkg1/data_stream/ds1/fields/ecs.yml.link"
assert_equals "link from depth-3 pkg to sibling depth-3 pkg → sibling path returned" \
    "packages/technology/pkg2" \
    "$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/technology/pkg1")"

# 5b. Link from depth-2 package (pkg3) → depth-3 package (technology/pkg1),
# which itself links to technology/pkg2 (set up explicitly here so this test
# does not implicitly depend on the .link file written in 5a).
# ../../../../ from data_stream/ds1/fields/ reaches packages/technology/
printf '../../../../pkg2/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/technology/pkg1/data_stream/ds1/fields/ecs.yml.link"
# ../../../../ from data_stream/ds1/fields/ reaches packages/
printf '../../../../technology/pkg1/_dev/shared/fields/beats.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/pkg3/data_stream/ds1/fields/beats.yml.link"
assert_equals "link from depth-2 pkg to depth-3 pkg → depth-3 pkg and its transitive links returned" \
    $'packages/technology/pkg1\npackages/technology/pkg2' \
    "$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/pkg3")"

# 5c. .link inside a depth-3 package points to the same depth-3 package → empty (filtered)
mkdir -p "${TMPDIR_LINK}/packages/technology/pkg_self/data_stream/ds1/fields"
mkdir -p "${TMPDIR_LINK}/packages/technology/pkg_self/_dev/shared/fields"
printf 'name: pkg_self\n' > "${TMPDIR_LINK}/packages/technology/pkg_self/manifest.yml"
touch "${TMPDIR_LINK}/packages/technology/pkg_self/_dev/shared/fields/ecs.yml"
# ../../../ from data_stream/ds1/fields/ reaches the package root, then into _dev/shared
printf '../../../_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_LINK}/packages/technology/pkg_self/data_stream/ds1/fields/ecs.yml.link"
assert_equals ".link in depth-3 pkg pointing to same pkg _dev/shared → empty (filtered)" \
    "" \
    "$(cd "${TMPDIR_LINK}" && collect_linked_packages_from_roots "packages/technology/pkg_self")"

rm -rf "${TMPDIR_LINK}"

# ---------------------------------------------------------------------------
# Integration test: collect_linked_packages_from_roots + remove_other_packages
# ---------------------------------------------------------------------------
echo ""
echo "--- integration: linked source packages kept by remove_other_packages"

# Repo layout:
#   packages/nginx_target   — target package; has a .link file pointing into
#                             nginx_shared's _dev/shared/fields/
#   packages/nginx_shared   — source package that owns the linked file
#   packages/unrelated_pkg  — should be removed
TMPDIR_REPO3="$(mktemp -d)"
mkdir -p "${TMPDIR_REPO3}/.github"
mkdir -p "${TMPDIR_REPO3}/packages/nginx_target/data_stream/ds1/fields"
mkdir -p "${TMPDIR_REPO3}/packages/nginx_shared/_dev/shared/fields"
mkdir -p "${TMPDIR_REPO3}/packages/unrelated_pkg"

printf 'name: nginx_target\n'   > "${TMPDIR_REPO3}/packages/nginx_target/manifest.yml"
printf 'name: nginx_shared\n'   > "${TMPDIR_REPO3}/packages/nginx_shared/manifest.yml"
printf 'name: unrelated_pkg\n'  > "${TMPDIR_REPO3}/packages/unrelated_pkg/manifest.yml"

touch "${TMPDIR_REPO3}/packages/nginx_shared/_dev/shared/fields/ecs.yml"
# ../../../../ from data_stream/ds1/fields/ reaches packages/, then into nginx_shared
printf '../../../../nginx_shared/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_REPO3}/packages/nginx_target/data_stream/ds1/fields/ecs.yml.link"

printf '/packages/nginx_target/ @team\n/packages/nginx_shared/ @team\n/packages/unrelated_pkg/ @team\n' \
    > "${TMPDIR_REPO3}/.github/CODEOWNERS"

MOCK_REPO_DIR="${TMPDIR_REPO3}"

(
    cd "${TMPDIR_REPO3}"
    packages_to_keep=()
    while IFS= read -r pkg; do packages_to_keep+=("${pkg}"); done \
        < <(collect_packages_to_keep "packages/nginx_target")
    remove_other_packages "${packages_to_keep[@]}"
)

assert_equals "target package nginx_target is kept" \
    "true" "$([[ -d "${TMPDIR_REPO3}/packages/nginx_target" ]] && echo true || echo false)"

assert_equals "linked source package nginx_shared is kept" \
    "true" "$([[ -d "${TMPDIR_REPO3}/packages/nginx_shared" ]] && echo true || echo false)"

assert_equals "unrelated package is removed" \
    "true" "$([[ ! -d "${TMPDIR_REPO3}/packages/unrelated_pkg" ]] && echo true || echo false)"

assert_equals "nginx_target entry kept in CODEOWNERS" \
    "true" "$(grep -q 'nginx_target' "${TMPDIR_REPO3}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "nginx_shared entry kept in CODEOWNERS" \
    "true" "$(grep -q 'nginx_shared' "${TMPDIR_REPO3}/.github/CODEOWNERS" && echo true || echo false)"

assert_equals "unrelated_pkg entry removed from CODEOWNERS" \
    "false" "$(grep -q 'unrelated_pkg' "${TMPDIR_REPO3}/.github/CODEOWNERS" && echo true || echo false)"

rm -rf "${TMPDIR_REPO3}"

# ---------------------------------------------------------------------------
# Tests: collect_linked_packages_from_roots (transitive chain)
# ---------------------------------------------------------------------------
echo ""
echo "--- collect_linked_packages_from_roots transitive tests"

# Set up a chain: pkg_chain_a → pkg_chain_b → pkg_chain_c (no further links)
# ../../../../ from data_stream/ds1/fields/ reaches packages/
TMPDIR_TRANS="$(mktemp -d)"
mkdir -p "${TMPDIR_TRANS}/packages/pkg_chain_a/data_stream/ds1/fields"
mkdir -p "${TMPDIR_TRANS}/packages/pkg_chain_b/data_stream/ds1/fields"
mkdir -p "${TMPDIR_TRANS}/packages/pkg_chain_b/_dev/shared/fields"
mkdir -p "${TMPDIR_TRANS}/packages/pkg_chain_c/_dev/shared/fields"
printf 'name: pkg_chain_a\n' > "${TMPDIR_TRANS}/packages/pkg_chain_a/manifest.yml"
printf 'name: pkg_chain_b\n' > "${TMPDIR_TRANS}/packages/pkg_chain_b/manifest.yml"
printf 'name: pkg_chain_c\n' > "${TMPDIR_TRANS}/packages/pkg_chain_c/manifest.yml"
touch "${TMPDIR_TRANS}/packages/pkg_chain_b/_dev/shared/fields/ecs.yml"
touch "${TMPDIR_TRANS}/packages/pkg_chain_c/_dev/shared/fields/ecs.yml"
printf '../../../../pkg_chain_b/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_TRANS}/packages/pkg_chain_a/data_stream/ds1/fields/b.yml.link"
printf '../../../../pkg_chain_c/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_TRANS}/packages/pkg_chain_b/data_stream/ds1/fields/c.yml.link"
MOCK_REPO_DIR="${TMPDIR_TRANS}"

assert_equals "collect: package with no .link files → empty" \
    "" \
    "$(cd "${TMPDIR_TRANS}" && collect_linked_packages_from_roots "packages/pkg_chain_c")"

assert_equals "collect: two-hop chain A→B→C returns B then C (BFS order)" \
    $'packages/pkg_chain_b\npackages/pkg_chain_c' \
    "$(cd "${TMPDIR_TRANS}" && collect_linked_packages_from_roots "packages/pkg_chain_a")"

rm -rf "${TMPDIR_TRANS}"

# ---------------------------------------------------------------------------
# Integration test: transitive chain + remove_other_packages
# ---------------------------------------------------------------------------
echo ""
echo "--- integration: transitive linked packages kept by remove_other_packages"

# Repo layout:
#   packages/pkg_chain_a  — target; links into pkg_chain_b
#   packages/pkg_chain_b  — direct link from a; links into pkg_chain_c
#   packages/pkg_chain_c  — transitive link (b→c); no further links
#   packages/pkg_unrelated — should be removed
TMPDIR_REPO4="$(mktemp -d)"
mkdir -p "${TMPDIR_REPO4}/.github"
mkdir -p "${TMPDIR_REPO4}/packages/pkg_chain_a/data_stream/ds1/fields"
mkdir -p "${TMPDIR_REPO4}/packages/pkg_chain_b/data_stream/ds1/fields"
mkdir -p "${TMPDIR_REPO4}/packages/pkg_chain_b/_dev/shared/fields"
mkdir -p "${TMPDIR_REPO4}/packages/pkg_chain_c/_dev/shared/fields"
mkdir -p "${TMPDIR_REPO4}/packages/pkg_unrelated"
printf 'name: pkg_chain_a\n'  > "${TMPDIR_REPO4}/packages/pkg_chain_a/manifest.yml"
printf 'name: pkg_chain_b\n'  > "${TMPDIR_REPO4}/packages/pkg_chain_b/manifest.yml"
printf 'name: pkg_chain_c\n'  > "${TMPDIR_REPO4}/packages/pkg_chain_c/manifest.yml"
printf 'name: pkg_unrelated\n' > "${TMPDIR_REPO4}/packages/pkg_unrelated/manifest.yml"
touch "${TMPDIR_REPO4}/packages/pkg_chain_b/_dev/shared/fields/ecs.yml"
touch "${TMPDIR_REPO4}/packages/pkg_chain_c/_dev/shared/fields/ecs.yml"
printf '../../../../pkg_chain_b/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_REPO4}/packages/pkg_chain_a/data_stream/ds1/fields/b.yml.link"
printf '../../../../pkg_chain_c/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_REPO4}/packages/pkg_chain_b/data_stream/ds1/fields/c.yml.link"
printf '/packages/pkg_chain_a/ @team\n/packages/pkg_chain_b/ @team\n/packages/pkg_chain_c/ @team\n/packages/pkg_unrelated/ @team\n' \
    > "${TMPDIR_REPO4}/.github/CODEOWNERS"
MOCK_REPO_DIR="${TMPDIR_REPO4}"

(
    cd "${TMPDIR_REPO4}"
    packages_to_keep=()
    while IFS= read -r pkg; do packages_to_keep+=("${pkg}"); done \
        < <(collect_packages_to_keep "packages/pkg_chain_a")
    remove_other_packages "${packages_to_keep[@]}"
)

assert_equals "transitive: pkg_chain_a (target) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO4}/packages/pkg_chain_a" ]] && echo true || echo false)"
assert_equals "transitive: pkg_chain_b (direct link) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO4}/packages/pkg_chain_b" ]] && echo true || echo false)"
assert_equals "transitive: pkg_chain_c (transitive link) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO4}/packages/pkg_chain_c" ]] && echo true || echo false)"
assert_equals "transitive: pkg_unrelated is removed" \
    "true" "$([[ ! -d "${TMPDIR_REPO4}/packages/pkg_unrelated" ]] && echo true || echo false)"
assert_equals "transitive: pkg_chain_c CODEOWNERS entry kept" \
    "true" "$(grep -q 'pkg_chain_c' "${TMPDIR_REPO4}/.github/CODEOWNERS" && echo true || echo false)"
assert_equals "transitive: pkg_unrelated CODEOWNERS entry removed" \
    "false" "$(grep -q 'pkg_unrelated' "${TMPDIR_REPO4}/.github/CODEOWNERS" && echo true || echo false)"

rm -rf "${TMPDIR_REPO4}"

# ---------------------------------------------------------------------------
# Integration test: required package's .link files are also walked
# ---------------------------------------------------------------------------
echo ""
echo "--- integration: linked packages from required package kept by remove_other_packages"

# Repo layout:
#   packages/pkg_target        — target; requires pkg_required (no .link files of its own)
#   packages/pkg_required      — required by target; has a .link pointing into pkg_linked_shared
#   packages/pkg_linked_shared — owns the source file linked by pkg_required; must be kept
#   packages/pkg_unrelated     — should be removed
#
# This exercises the fix where collect_linked_packages_from_roots receives all
# packages_to_keep (target + required) so required packages' .link files are
# also walked, not only those of the target package.
TMPDIR_REPO5="$(mktemp -d)"
mkdir -p "${TMPDIR_REPO5}/.github"
mkdir -p "${TMPDIR_REPO5}/packages/pkg_target"
mkdir -p "${TMPDIR_REPO5}/packages/pkg_required/data_stream/ds1/fields"
mkdir -p "${TMPDIR_REPO5}/packages/pkg_linked_shared/_dev/shared/fields"
mkdir -p "${TMPDIR_REPO5}/packages/pkg_unrelated"

cat > "${TMPDIR_REPO5}/packages/pkg_target/manifest.yml" <<'EOF'
name: pkg_target
requires:
  input:
    - package: pkg_required
EOF
printf 'name: pkg_required\n'      > "${TMPDIR_REPO5}/packages/pkg_required/manifest.yml"
printf 'name: pkg_linked_shared\n' > "${TMPDIR_REPO5}/packages/pkg_linked_shared/manifest.yml"
printf 'name: pkg_unrelated\n'     > "${TMPDIR_REPO5}/packages/pkg_unrelated/manifest.yml"

touch "${TMPDIR_REPO5}/packages/pkg_linked_shared/_dev/shared/fields/ecs.yml"
# ../../../../ from data_stream/ds1/fields/ reaches packages/, then into pkg_linked_shared
printf '../../../../pkg_linked_shared/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_REPO5}/packages/pkg_required/data_stream/ds1/fields/ecs.yml.link"

printf '/packages/pkg_target/ @team\n/packages/pkg_required/ @team\n/packages/pkg_linked_shared/ @team\n/packages/pkg_unrelated/ @team\n' \
    > "${TMPDIR_REPO5}/.github/CODEOWNERS"

MOCK_REPO_DIR="${TMPDIR_REPO5}"

(
    cd "${TMPDIR_REPO5}"
    packages_to_keep=()
    while IFS= read -r pkg; do packages_to_keep+=("${pkg}"); done \
        < <(collect_packages_to_keep "packages/pkg_target")
    remove_other_packages "${packages_to_keep[@]}"
)

assert_equals "req-link: pkg_target (target) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO5}/packages/pkg_target" ]] && echo true || echo false)"
assert_equals "req-link: pkg_required (required) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO5}/packages/pkg_required" ]] && echo true || echo false)"
assert_equals "req-link: pkg_linked_shared (linked by required) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO5}/packages/pkg_linked_shared" ]] && echo true || echo false)"
assert_equals "req-link: pkg_unrelated is removed" \
    "true" "$([[ ! -d "${TMPDIR_REPO5}/packages/pkg_unrelated" ]] && echo true || echo false)"
assert_equals "req-link: pkg_linked_shared entry kept in CODEOWNERS" \
    "true" "$(grep -q 'pkg_linked_shared' "${TMPDIR_REPO5}/.github/CODEOWNERS" && echo true || echo false)"
assert_equals "req-link: pkg_unrelated entry removed from CODEOWNERS" \
    "false" "$(grep -q 'pkg_unrelated' "${TMPDIR_REPO5}/.github/CODEOWNERS" && echo true || echo false)"

rm -rf "${TMPDIR_REPO5}"

# ---------------------------------------------------------------------------
# Integration test: link-discovered package has its own requires.* dependency
# ---------------------------------------------------------------------------
echo ""
echo "--- integration: requires.* deps of link-discovered packages kept"

# Repo layout:
#   packages/pkg_target       — target; has a .link pointing into pkg_linked
#   packages/pkg_linked       — discovered via .link; declares requires.input: [pkg_utils]
#   packages/pkg_utils        — required by pkg_linked; must also be kept
#   packages/pkg_unrelated    — should be removed
#
# This exercises the iterative expansion: the first pass discovers pkg_linked
# via .link, the second pass discovers pkg_utils via pkg_linked's requires.
TMPDIR_REPO6="$(mktemp -d)"
mkdir -p "${TMPDIR_REPO6}/.github"
mkdir -p "${TMPDIR_REPO6}/packages/pkg_target/data_stream/ds1/fields"
mkdir -p "${TMPDIR_REPO6}/packages/pkg_linked/_dev/shared/fields"
mkdir -p "${TMPDIR_REPO6}/packages/pkg_utils"
mkdir -p "${TMPDIR_REPO6}/packages/pkg_unrelated"

printf 'name: pkg_target\n' > "${TMPDIR_REPO6}/packages/pkg_target/manifest.yml"
cat > "${TMPDIR_REPO6}/packages/pkg_linked/manifest.yml" <<'EOF'
name: pkg_linked
requires:
  input:
    - package: pkg_utils
EOF
printf 'name: pkg_utils\n'     > "${TMPDIR_REPO6}/packages/pkg_utils/manifest.yml"
printf 'name: pkg_unrelated\n' > "${TMPDIR_REPO6}/packages/pkg_unrelated/manifest.yml"

touch "${TMPDIR_REPO6}/packages/pkg_linked/_dev/shared/fields/ecs.yml"
# ../../../../ from data_stream/ds1/fields/ reaches packages/, then into pkg_linked
printf '../../../../pkg_linked/_dev/shared/fields/ecs.yml abc123\n' \
    > "${TMPDIR_REPO6}/packages/pkg_target/data_stream/ds1/fields/ecs.yml.link"

printf '/packages/pkg_target/ @team\n/packages/pkg_linked/ @team\n/packages/pkg_utils/ @team\n/packages/pkg_unrelated/ @team\n' \
    > "${TMPDIR_REPO6}/.github/CODEOWNERS"

MOCK_REPO_DIR="${TMPDIR_REPO6}"

(
    cd "${TMPDIR_REPO6}"
    packages_to_keep=()
    while IFS= read -r pkg; do packages_to_keep+=("${pkg}"); done \
        < <(collect_packages_to_keep "packages/pkg_target")
    remove_other_packages "${packages_to_keep[@]}"
)

assert_equals "link-req: pkg_target (target) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO6}/packages/pkg_target" ]] && echo true || echo false)"
assert_equals "link-req: pkg_linked (discovered via .link) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO6}/packages/pkg_linked" ]] && echo true || echo false)"
assert_equals "link-req: pkg_utils (required by pkg_linked) is kept" \
    "true" "$([[ -d "${TMPDIR_REPO6}/packages/pkg_utils" ]] && echo true || echo false)"
assert_equals "link-req: pkg_unrelated is removed" \
    "true" "$([[ ! -d "${TMPDIR_REPO6}/packages/pkg_unrelated" ]] && echo true || echo false)"
assert_equals "link-req: pkg_utils entry kept in CODEOWNERS" \
    "true" "$(grep -q 'pkg_utils' "${TMPDIR_REPO6}/.github/CODEOWNERS" && echo true || echo false)"
assert_equals "link-req: pkg_unrelated entry removed from CODEOWNERS" \
    "false" "$(grep -q 'pkg_unrelated' "${TMPDIR_REPO6}/.github/CODEOWNERS" && echo true || echo false)"

rm -rf "${TMPDIR_REPO6}"

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
