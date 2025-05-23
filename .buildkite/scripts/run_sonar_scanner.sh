#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_mage

run_sonar_scanner() {
    local message=""
    echo "--- Download coverage reports and merge them"
    if ! buildkite-agent artifact download build/test-coverage/coverage-*.xml . ; then
        message="Could not download XML artifacts. Skip coverage."
        echo "--- :boom: ${message}"
        buildkite-agent annotate \
            "[Code inspection] ${message}" \
            --context "ctx-sonarqube-no-files" \
            --style "warning"
        exit 0
    fi

    echo "Merge all coverage reports"
    mage mergeCoverage

    echo "--- Execute sonar scanner CLI"
    /scan-source-code.sh
}

if [[ "${PUBLISH_COVERAGE_REPORTS:-"false"}" == "true" ]]; then
    echo "Enabled sonnar scanner by PUBLISH_COVERAGE_REPORTS variable (Pipeline ${BUILDKITE_PIPELINE_SLUG})"
    run_sonar_scanner
    exit 0
fi

if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
    echo "Run sonar scanner from Pull Request (Pipeline ${BUILDKITE_PIPELINE_SLUG})"
    run_sonar_scanner
    exit 0
fi

echo "Skip coverage report"
