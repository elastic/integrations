#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

pushd packages > /dev/null
PACKAGE_LIST=$(list_all_directories)
popd > /dev/null

PIPELINE_FILE="packages_pipeline.yml"
touch packages_pipeline.yml

echo "steps:" > ${PIPELINE_FILE}
echo "  - group: \":terminal: Test integrations\"" >> ${PIPELINE_FILE}
echo "    key: \"integration-tests\"" >> ${PIPELINE_FILE}
echo "    steps:" >> ${PIPELINE_FILE}

packages_to_test=0

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

    packages_to_test=$((packages_to_test+1))
    echo "    - label: \"Check integrations ${package}\"" >> ${PIPELINE_FILE}
    echo "      key: \"test-integrations-${package}\"" >> ${PIPELINE_FILE}
    echo "      command: \".buildkite/scripts/test_one_package.sh ${package}\"" >> ${PIPELINE_FILE}
    echo "      agents:" >> ${PIPELINE_FILE}
    echo "        provider: gcp" >> ${PIPELINE_FILE}
    echo "      env:" >> ${PIPELINE_FILE}
    echo "        UPLOAD_SAFE_LOGS: 1" >> ${PIPELINE_FILE}
    echo "      artifact_paths:" >> ${PIPELINE_FILE}
    echo "        - build/test-results/*.xml" >> ${PIPELINE_FILE}
    echo "        - build/benchmark-results/*.xml" >> ${PIPELINE_FILE}
done

if [ ${packages_to_test} -eq 0 ]; then
    buildkite-agent annotate "No packages to be tested" --context "ctx-no-packages" --style "warning"
    exit 0
fi

cat ${PIPELINE_FILE} | buildkite-agent pipeline upload
