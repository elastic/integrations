#!/bin/bash
# Local test for the PACKAGE_LIST derivation logic.
# Mocks list_all_directories with a fixed set of packages (flat and nested).

set -euo pipefail

PASS=0
FAIL=0

# Mock package list: flat and nested
list_all_directories() {
    cat <<'EOF'
packages/crowdstrike
packages/security_detection_engine
packages/technology/elastic_package_registry
packages/technology/another_pkg
EOF
}

# Core logic extracted from the scripts (identical in both .sh files)
compute_package_list() {
    local changed_files="$1"
    {
        all_pkgs=$(list_all_directories)
        while IFS= read -r pkg_path; do
            if echo "${changed_files}" | grep -q "^${pkg_path}/"; then
                echo "${pkg_path}"
            elif echo "${changed_files}" | grep -q "^\.buildkite/scripts/${pkg_path}\.sh$"; then
                echo "${pkg_path}"
            fi
        done <<< "${all_pkgs}"
    } | sort -u | grep -v '^$' || true
}

check() {
    local desc="$1"
    local changed_files="$2"
    local expected="$3"

    result=$(compute_package_list "${changed_files}")
    if [[ "${result}" == "${expected}" ]]; then
        echo "PASS: ${desc}"
        PASS=$((PASS + 1))
    else
        echo "FAIL: ${desc}"
        echo "      expected: $(echo "${expected}" | tr '\n' ' ')"
        echo "      got:      $(echo "${result}" | tr '\n' ' ')"
        FAIL=$((FAIL + 1))
    fi
}

# 1. Flat package file changed
check "flat package file" \
    "packages/crowdstrike/data_stream/fdr/manifest.yml" \
    "packages/crowdstrike"

# 2. Nested package file changed
check "nested package file" \
    "packages/technology/elastic_package_registry/data_stream/metrics/manifest.yml" \
    "packages/technology/elastic_package_registry"

# 3. Intermediate directory (no manifest.yml) — should match nothing
check "intermediate non-package dir" \
    "packages/technology/README.md" \
    ""

# 4. Buildkite script for flat package
check "buildkite script flat package" \
    ".buildkite/scripts/packages/crowdstrike.sh" \
    "packages/crowdstrike"

# 5. Buildkite script for nested package
check "buildkite script nested package" \
    ".buildkite/scripts/packages/technology/elastic_package_registry.sh" \
    "packages/technology/elastic_package_registry"

# 6. Multiple packages changed at once
check "multiple packages" \
    "packages/crowdstrike/foo.yml
packages/technology/another_pkg/bar.yml" \
    "packages/crowdstrike
packages/technology/another_pkg"

# 7. Unrelated file — should match nothing
check "unrelated file" \
    ".github/CODEOWNERS" \
    ""

# 8. Both package file and buildkite script for the same package — deduplicated
check "package file + buildkite script (same package)" \
    "packages/crowdstrike/foo.yml
.buildkite/scripts/packages/crowdstrike.sh" \
    "packages/crowdstrike"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"
[[ ${FAIL} -eq 0 ]]
