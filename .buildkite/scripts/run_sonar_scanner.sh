#!/bin/bash
set -euo pipefail

run_sonar_scanner() {
    echo "--- Download coverage reports and merge them"
    buildkite-agent artifact download build/test-coverage/coverage-*.xml .
    # buildkite-agent artifact download build/test-results/*.xml .

    echo "Merge all coverage reports"
    .buildkite/scripts/merge_xml.sh

    echo "--- Execute sonar scanner CLI"
    /scan-source-code.sh
}

if [[ ${FORCE_CHECK_ALL:-"false"} == "true" && ${STACK_VERSION:-"false"} =~ 8\..*\-SNAPSHOT ]]; then
    echo "Run from schedule daily job"
    run_sonar_scanner
    exit 0
fi

if [[ "${BUILDKITE_PULL_REQUEST}" != "false" ]]; then
    echo "Run from Pull Request"
    run_sonar_scanner
    exit 0
fi

echo "Skip coverage report"
