#!/usr/bin/env bash
# Unit tests for select_shard_packages() in common.sh.
# Run directly (from repo root) or via run_buildkite_scripts_tests.sh.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
# shellcheck source=.buildkite/scripts/common.sh
source "${REPO_ROOT}/.buildkite/scripts/common.sh"
source "${REPO_ROOT}/.buildkite/scripts/test_helpers.sh"

pass=0
fail=0

PACKAGES=$'packages/nginx\npackages/aws\npackages/aws_bedrock\npackages/aws-logs\npackages/Zeek\npackages/apache\npackages/system'

# Prints the selected packages as a single space-separated line.
shard() {
    printf '%s\n' "$1" | select_shard_packages "$2" "$3" | tr '\n' ' ' | sed 's/ $//'
}

# ---------------------------------------------------------------------------
echo "--- select_shard_packages: round-robin over the C-locale sorted list"

assert_equals "single shard gets every package, sorted" \
    "packages/Zeek packages/apache packages/aws packages/aws-logs packages/aws_bedrock packages/nginx packages/system" \
    "$(shard "${PACKAGES}" 0 1)"
assert_equals "shard 1/3" "packages/Zeek packages/aws-logs packages/system" "$(shard "${PACKAGES}" 0 3)"
assert_equals "shard 2/3" "packages/apache packages/aws_bedrock" "$(shard "${PACKAGES}" 1 3)"
assert_equals "shard 3/3" "packages/aws packages/nginx" "$(shard "${PACKAGES}" 2 3)"

# ---------------------------------------------------------------------------
echo "--- select_shard_packages: order is independent of the caller's locale"

for locale in C en_US.UTF-8 es_ES.UTF-8; do
    assert_equals "shard 1/3 with LC_ALL=${locale}" \
        "packages/Zeek packages/aws-logs packages/system" \
        "$(LC_ALL="${locale}" shard "${PACKAGES}" 0 3 2>/dev/null)"
done

# ---------------------------------------------------------------------------
echo "--- select_shard_packages: every package lands in exactly one shard"

for total in 1 2 3 4 7 10; do
    all_shards=$(
        for (( i = 0; i < total; i++ )); do
            printf '%s\n' "${PACKAGES}" | select_shard_packages "${i}" "${total}"
        done | LC_ALL=C sort
    )
    assert_equals "union of ${total} shards equals the input, without duplicates" \
        "$(printf '%s\n' "${PACKAGES}" | LC_ALL=C sort)" \
        "${all_shards}"
done

# ---------------------------------------------------------------------------
echo "--- select_shard_packages: edge cases"

assert_equals "empty input gives an empty shard" "" "$(shard "" 0 4)"
assert_equals "blank lines are ignored" "packages/aws packages/nginx" \
    "$(shard $'\npackages/nginx\n\npackages/aws\n' 0 1)"
assert_equals "more shards than packages: shard 2/4 gets one package" "packages/nginx" \
    "$(shard $'packages/aws\npackages/nginx' 1 4)"
assert_equals "more shards than packages: shard 4/4 is empty" "" \
    "$(shard $'packages/aws\npackages/nginx' 3 4)"

# ---------------------------------------------------------------------------
echo ""
echo "--- Results: ${pass} passed, ${fail} failed"
if [[ "${fail}" -gt 0 ]]; then
    exit 1
fi
