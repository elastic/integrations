#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

pushd packages > /dev/null
PACKAGE_LIST=$(list_all_directories | head -n 10)
popd > /dev/null

echo "steps:"
echo "  - group: \":terminal: Test integrations\""
echo "    key: \"integration-tests\""
echo "    steps:"

for package in ${PACKAGE_LIST}; do
    echo "    - label: \"Check integrations ${package}\""
    echo "      key: \"test-integrations-${package}\""
    echo "      command: \".buildkite/scripts/test_one_package.sh\""
    echo "      agents:"
    echo "        provider: gcp"
    echo "      artifact_paths:"
    echo "        - build/results/*.xml"
done

