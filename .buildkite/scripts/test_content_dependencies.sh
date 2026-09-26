#!/usr/bin/env bash
# Unit tests for content_dependencies.sh.
# Run directly or via .buildkite/scripts/run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

if ! command -v yq >/dev/null 2>&1; then
    echo "yq is required to run content dependency tests" >&2
    exit 1
fi

source "${REPO_ROOT}/.buildkite/scripts/content_dependencies.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

TMPDIR_REPO=""
BUILD_LOG=""

cleanup() {
    [[ -n "${TMPDIR_REPO}" ]] && rm -rf "${TMPDIR_REPO}"
    [[ -n "${BUILD_LOG}" ]] && rm -f "${BUILD_LOG}"
}
trap cleanup EXIT

setup_repo() {
    [[ -n "${TMPDIR_REPO}" ]] && rm -rf "${TMPDIR_REPO}"
    TMPDIR_REPO="$(mktemp -d)"
    WORKSPACE="${TMPDIR_REPO}"
    BUILD_LOG="${TMPDIR_REPO}/builds.log"
    : > "${BUILD_LOG}"
    export WORKSPACE
    export BUILD_LOG
    export ELASTIC_PACKAGE_BIN="${TMPDIR_REPO}/elastic-package"
    cat > "${ELASTIC_PACKAGE_BIN}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "build" ]]; then
    if [[ "${STUB_BUILD_FAIL:-}" == "1" ]]; then
        echo "stub build failed" >&2
        exit 1
    fi
    printf '%s\n' "$(pwd)" >> "${BUILD_LOG}"
    exit 0
fi
echo "unexpected elastic-package args: $*" >&2
exit 1
EOF
    chmod +x "${ELASTIC_PACKAGE_BIN}"
}

make_package() {
    local dir="${WORKSPACE}/packages/${1}"
    mkdir -p "${dir}"
    printf '%s\n' "${2}" > "${dir}/manifest.yml"
}

# ---------------------------------------------------------------------------
echo "--- build_local_content_dependencies tests"

# 1. No requires.content
setup_repo
make_package "input_pkg" "$(cat <<'EOF'
name: input_pkg
version: 1.0.0
EOF
)"
(
    cd "${WORKSPACE}/packages/input_pkg"
    build_local_content_dependencies
)
assert_equals "no requires.content → nothing built" "" "$(cat "${BUILD_LOG}")"

# 2. Content package is not in this checkout
setup_repo
make_package "input_pkg" "$(cat <<'EOF'
name: input_pkg
version: 1.0.0
requires:
  content:
    - package: missing_otel
      version: "0.2.0"
EOF
)"
(
    cd "${WORKSPACE}/packages/input_pkg"
    build_local_content_dependencies
)
assert_equals "missing checkout package → nothing built" "" "$(cat "${BUILD_LOG}")"

# 3. Local version does not match the pin
setup_repo
make_package "input_pkg" "$(cat <<'EOF'
name: input_pkg
version: 1.0.0
requires:
  content:
    - package: content_otel
      version: "0.2.0"
EOF
)"
make_package "content_otel" "$(cat <<'EOF'
name: content_otel
version: 0.1.0
EOF
)"
(
    cd "${WORKSPACE}/packages/input_pkg"
    build_local_content_dependencies
)
assert_equals "version mismatch → nothing built" "" "$(cat "${BUILD_LOG}")"

# 4. Local version matches the pin
setup_repo
make_package "input_pkg" "$(cat <<'EOF'
name: input_pkg
version: 1.0.0
requires:
  content:
    - package: content_otel
      version: "0.2.0"
EOF
)"
make_package "content_otel" "$(cat <<'EOF'
name: content_otel
version: 0.2.0
EOF
)"
(
    cd "${WORKSPACE}/packages/input_pkg"
    build_local_content_dependencies
)
assert_equals "matching content package is built" \
    "$(cd "${WORKSPACE}/packages/content_otel" && pwd)" \
    "$(cat "${BUILD_LOG}")"

# 5. Nested technology/package path
setup_repo
make_package "input_pkg" "$(cat <<'EOF'
name: input_pkg
version: 1.0.0
requires:
  content:
    - package: nested_otel
      version: "1.2.3"
EOF
)"
make_package "technology/nested_otel" "$(cat <<'EOF'
name: nested_otel
version: 1.2.3
EOF
)"
(
    cd "${WORKSPACE}/packages/input_pkg"
    build_local_content_dependencies
)
assert_equals "nested content package is built" \
    "$(cd "${WORKSPACE}/packages/technology/nested_otel" && pwd)" \
    "$(cat "${BUILD_LOG}")"

# 6. A package does not rebuild itself
setup_repo
make_package "content_otel" "$(cat <<'EOF'
name: content_otel
version: 0.2.0
requires:
  content:
    - package: content_otel
      version: "0.2.0"
EOF
)"
(
    cd "${WORKSPACE}/packages/content_otel"
    build_local_content_dependencies
)
assert_equals "package does not rebuild itself" "" "$(cat "${BUILD_LOG}")"

# 7. Build failure is returned to the caller
setup_repo
make_package "input_pkg" "$(cat <<'EOF'
name: input_pkg
version: 1.0.0
requires:
  content:
    - package: content_otel
      version: "0.2.0"
EOF
)"
make_package "content_otel" "$(cat <<'EOF'
name: content_otel
version: 0.2.0
EOF
)"
set +e
(
    cd "${WORKSPACE}/packages/input_pkg"
    STUB_BUILD_FAIL=1 build_local_content_dependencies
)
build_status=$?
set -e
assert_exit_code "failed content build fails the step" "1" "${build_status}"

echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
