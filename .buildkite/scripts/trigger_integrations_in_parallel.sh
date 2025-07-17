#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

echo "--- Install requirements"
add_bin_path
with_yq
with_mage

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
echo "--- Get from and to changesets"
from="$(get_from_changeset)"
if [[ "${from}" == "" ]]; then
    echo "Missing \"from\" changset".
    exit 1
fi
to="$(get_to_changeset)"
if [[ "${to}" == "" ]]; then
    echo "Missing \"to\" changset".
    exit 1
fi

echo "Checking with commits: from: '${from}' to: '${to}'"

# This variable does not exist in builds triggered automatically
GITHUB_PR_TRIGGER_COMMENT="${GITHUB_PR_TRIGGER_COMMENT:-""}"

if [[ "${BUILDKITE_PIPELINE_SLUG}" == "integrations-test-stack" && "${GITHUB_PR_TRIGGER_COMMENT}" =~ ^/test\ stack ]]; then
    echo "--- Stack version set from Github comment"
    STACK_VERSION=$(echo "$GITHUB_PR_TRIGGER_COMMENT" | cut -d " " -f 3)
    export STACK_VERSION
    echo "Use Elastic stack version from Github comment: ${STACK_VERSION}"
fi

packages_to_test=0

pushd packages > /dev/null
if ! affected_packages=$(get_all_pr_affected_packages "${from}" "${to}"); then
    echo "Error getting affected packages"
    exit 1
fi
popd > /dev/null

for package in ${affected_packages}; do

    packages_to_test=$((packages_to_test+1))
    cat << EOF >> ${PIPELINE_FILE}
    - label: "Check integrations ${package}"
      key: "test-integrations-${package}"
      command: ".buildkite/scripts/test_one_package.sh ${package} ${from} ${to}"
      timeout_in_minutes: 240
      agents:
        provider: gcp
        image: ${IMAGE_UBUNTU_X86_64}
      env:
        STACK_VERSION: "${STACK_VERSION}"
        FORCE_CHECK_ALL: "${FORCE_CHECK_ALL}"
        SERVERLESS: "false"
        UPLOAD_SAFE_LOGS: ${UPLOAD_SAFE_LOGS}
      plugins:
        # See https://github.com/elastic/oblt-infra/blob/main/conf/resources/repos/integrations/01-aws-buildkite-oidc.tf
        # This plugin creates the environment variables required by the service deployer (AWS_SECRET_ACCESS_KEY and AWS_SECRET_KEY_ID)
        - elastic/oblt-aws-auth#v0.1.0:
            duration: 10800 # seconds
        # See https://github.com/elastic/oblt-infra/blob/main/conf/resources/repos/integrations/01-gcp-buildkite-oidc.tf
        # This plugin authenticates to Google Cloud using the OIDC token.
        - elastic/oblt-google-auth#v1.3.0:
            lifetime: 10800 # seconds
            project-id: "elastic-observability-ci"
            project-number: "911195782929"
      artifact_paths:
        - build/test-results/*.xml
        - build/test-coverage/*.xml
        - build/benchmark-results/*.json
        - build/elastic-stack-dump/*/logs/*.log
        - build/elastic-stack-dump/*/logs/fleet-server-internal/**/*
EOF
done

if [ ${packages_to_test} -eq 0 ]; then
    echo "--- Create Buildkite annotation no packages to be tested"
    buildkite-agent annotate "No packages to be tested" --context "ctx-no-packages" --style "warning"
    exit 0
fi

echo "--- Upload Buildkite pipeline"
cat ${PIPELINE_FILE} | buildkite-agent pipeline upload
