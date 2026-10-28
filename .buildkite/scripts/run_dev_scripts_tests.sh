#!/usr/bin/env bash
# Runs tests for scripts in dev/scripts/.
# TODO: migrate to the bats framework (https://github.com/bats-core/bats-core)
#       for better test isolation, TAP output, and native setup/teardown support.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

echo "=== Running get_release_commit.sh tests ==="
bash "${REPO_ROOT}/dev/scripts/test_get_release_commit.sh"
