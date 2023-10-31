#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

pushd packages > /dev/null
PACKAGE_LIST=$(list_all_directories)
popd > /dev/null

echo "steps:"
echo "  - group: \":terminal: Test integrations\""
echo "    key: \"integration-tests\""
echo "    steps:"

for package in ${PACKAGE_LIST}; do
    echo "    - label: \"Check integrations ${package}\""
    echo "      key: \"test-integrations-${package}\""
    echo "      command: \".buildkite/scripts/test_one_package.sh ${package}\""
    echo "      agents:"
    echo "        provider: gcp"
    echo "      env:"
    echo "        UPLOAD_SAFE_LOGS: 1"
    echo "      artifact_paths:"
    echo "        - build/test-results/*.xml"
    echo "        - build/benchmark-results/*.xml"
done
