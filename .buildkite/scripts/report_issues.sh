#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

junit_folder="test-results"
test_results_folder="build/${junit_folder}"
buildkite_pattern="${test_results_folder}/*.xml"

download_test_results() {
    mkdir -p "${test_results_folder}"

    if ! buildkite-agent artifact download "${buildkite_pattern}" . ; then
      echo "[report] No test results generated"
      return 1
    fi
    return 0
}

if running_on_buildkite ; then
    echo "--- Installing tools"
    add_bin_path
    with_go
    with_github_cli # to post comments in Pull Requests

    echo "--- Download Test Results"
    if ! download_test_results ; then
        exit 0
    fi
fi

echo "--- Report Issues"
mage -v ReportIssues build/test-results

