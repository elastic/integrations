#!/usr/bin/env bash
# Orchestrates unit tests for dev and CI scripts.
# TODO: migrate to the bats framework (https://github.com/bats-core/bats-core)
#       for better test isolation, TAP output, and native setup/teardown support.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

echo "=== Running get_release_commit.sh tests ==="
"${REPO_ROOT}/dev/scripts/test_get_release_commit.sh"

echo ""
echo "=== Running check_changelog_entries.sh tests ==="
"${REPO_ROOT}/.buildkite/scripts/test_check_changelog_entries.sh"
