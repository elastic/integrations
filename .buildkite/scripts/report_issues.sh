#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

junit_folder="test-results"
test_results_folder="build/${junit_folder}"
buildkite_pattern="${test_results_folder}/*.xml"

download_test_results() {
    mkdir -p "${test_results_folder}"

    if ! buildkite-agent artifact download "${buildkite_pattern}" . ; then
        message="Could not download XML artifacts. Skip creating issues."
        echo "--- :boom: ${message}"
        buildkite-agent annotate \
            "[Report Failed Tests] ${message}" \
            --context "ctx-report-failed-tests-no-files" \
            --style "warning"
        return 1
    fi
    return 0
}

if running_on_buildkite ; then
    echo "--- Installing tools"
    add_bin_path
    with_mage
    with_github_cli # to list, create and update issues

    echo "--- Download Test Results"
    if ! download_test_results ; then
        exit 0
    fi
fi

echo "--- Create GitHub Issues for failed tests"
mage -v ReportFailedTests build/test-results

