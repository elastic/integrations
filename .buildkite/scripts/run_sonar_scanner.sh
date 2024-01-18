#!/bin/bash
set -euo pipefail

run_sonar_scanner() {
    echo "--- Download coverage reports and merge them"
    buildkite-agent artifact download build/test-coverage/coverage-*.xml .

    echo "Merge all coverage reports"
    .buildkite/scripts/merge_xml.sh

    echo "--- Execute sonar scanner CLI"
    /scan-source-code.sh
}

if [[ "${PUBLISH_COVERAGE_REPORTS:-"false"}" == "true" ]]; then
    run_sonar_scanner
    exit 0
fi

if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
    echo "Run from Pull Request"
    run_sonar_scanner
    exit 0
fi

echo "Skip coverage report"
