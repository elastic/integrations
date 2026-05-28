#!/usr/bin/env bash
# Runs tests for scripts in dev/scripts/.
# TODO: migrate to the bats framework (https://github.com/bats-core/bats-core)
#       for better test isolation, TAP output, and native setup/teardown support.
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"

run_tests_if_exists() {
    local script="$1"
    if [[ ! -f "${script}" ]]; then
        echo "Skipping ${script} (file not found)"
        return 0
    fi
    "${script}"
}

run_tests_if_exists "${REPO_ROOT}/dev/scripts/test_get_release_commit.sh"
