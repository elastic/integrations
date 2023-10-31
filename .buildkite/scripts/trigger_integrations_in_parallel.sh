#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
# echoerr "Some some envs"
# env |egrep 'STACK_VERSION|SERVERLESS|FORCE_CHECK_ALL' || true 1>&2
#
# STACK_VERSION=${STACK_VERSION:-""}
# SERVERLESS="false"
# FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}

pushd packages > /dev/null
PACKAGE_LIST=$(list_all_directories)
popd > /dev/null

echo "steps:"
echo "  - group: \":terminal: Test integrations\""
echo "    key: \"integration-tests\""
echo "    steps:"

for package in ${PACKAGE_LIST}; do
    # check if needed to create an step for this package
    pushd packages/${package} > /dev/null
    skip_package="false"
    if ! reason=$(is_pr_affected ${package}) ; then
        skip_package="true"
    fi
    echoerr "${reason}"
    popd > /dev/null

    if [[ $skip_package == "true" ]] ; then
        continue
    fi

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
