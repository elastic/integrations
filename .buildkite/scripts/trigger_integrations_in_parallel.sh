#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_yq

pushd packages > /dev/null
PACKAGE_LIST=$(list_all_directories)
popd > /dev/null

PIPELINE_FILE="packages_pipeline.yml"
touch packages_pipeline.yml

cat <<EOF > ${PIPELINE_FILE}
steps:
  - group: ":terminal: Test integrations"
    key: "integration-tests"
    steps:
EOF

# Get from and to changesets to avoid repeating the same queries for each package

# setting range of changesets to check differences
from="$(get_from_changeset)"
to="$(get_to_changeset)"

echo "[DEBUG] Checking with commits: from: '${from}' to: '${to}'"

packages_to_test=0

for package in ${PACKAGE_LIST}; do
    # check if needed to create an step for this package
    pushd "packages/${package}" > /dev/null
    skip_package="false"
    if ! reason=$(is_pr_affected "${package}" "${from}" "${to}") ; then
        skip_package="true"
    fi
    echoerr "${reason}"
    popd > /dev/null

    if [[ "$skip_package" == "true" ]] ; then
        continue
    fi

    packages_to_test=$((packages_to_test+1))
    cat << EOF >> ${PIPELINE_FILE}
    - label: "Check integrations ${package}"
      key: "test-integrations-${package}"
      command: ".buildkite/scripts/test_one_package.sh ${package} ${from} ${to}"
      agents:
        provider: gcp
      env:
        STACK_VERSION: "${STACK_VERSION}"
        FORCE_CHECK_ALL: "${FORCE_CHECK_ALL}"
        SERVERLESS: "false"
        UPLOAD_SAFE_LOGS: ${UPLOAD_SAFE_LOGS}
      artifact_paths:
        - build/test-results/*.xml
        - build/benchmark-results/*.xml
EOF
done

if [ ${packages_to_test} -eq 0 ]; then
    buildkite-agent annotate "No packages to be tested" --context "ctx-no-packages" --style "warning"
    exit 0
fi

cat ${PIPELINE_FILE} | buildkite-agent pipeline upload
