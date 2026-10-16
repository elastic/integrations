#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

echo "--- Install requirements"
add_bin_path
with_yq
with_mage

PIPELINE_FILE="packages_pipeline.yml"

# Buildkite rejects pipeline uploads with more than 500 jobs (organization limit),
# so steps are uploaded in batches. Keep some margin below the limit (the group also counts as a job).
MAX_STEPS_PER_UPLOAD="${MAX_STEPS_PER_UPLOAD:-400}"
if ! [[ "${MAX_STEPS_PER_UPLOAD}" =~ ^[1-9][0-9]*$ ]]; then
    echo "MAX_STEPS_PER_UPLOAD must be a positive integer, got: '${MAX_STEPS_PER_UPLOAD}'"
    exit 1
fi
steps_in_batch=0

start_batch() {
    local batch_number=$1
    # ">" truncates the file, so each batch starts from a clean pipeline file
    cat <<EOF > ${PIPELINE_FILE}
steps:
  - group: ":terminal: Test integrations (batch ${batch_number})"
    key: "integration-tests-${batch_number}"
    steps:
EOF
}

upload_batch() {
    local batch_number=$1
    local steps_in_batch=$2
    echo "--- Upload Buildkite pipeline (batch ${batch_number}, ${steps_in_batch} steps)"
    buildkite-agent pipeline upload < ${PIPELINE_FILE}
}

batch_number=1
start_batch "${batch_number}"

# Get from and to changesets to avoid repeating the same queries for each package
# setting range of changesets to check differences
echo "--- Get from and to changesets"
from="$(get_from_changeset)"
if [[ "${from}" == "" ]]; then
    echo "Missing \"from\" changeset".
    exit 1
fi
to="$(get_to_changeset)"
if [[ "${to}" == "" ]]; then
    echo "Missing \"to\" changeset".
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

echo "--- Compute affected packages from git diff"
COMMIT_MERGE=$(git merge-base "${from}" "${to}")
export COMMIT_MERGE
changed_files=$(git diff --name-only "${COMMIT_MERGE}" "${to}")
echo "Commit merge: ${COMMIT_MERGE}"
echo "Commit to: ${to}"

if [[ "${FORCE_CHECK_ALL}" == "true" ]] || echo "${changed_files}" | pr_has_package_related_files; then
    echo "Non-package files changed or FORCE_CHECK_ALL set: scanning all packages"
    PACKAGE_LIST=$(list_all_directories)
else
    PACKAGE_LIST=$(
        {
            # Use list_all_directories (mage listPackages) instead of grepping ^packages/[^/]+
            # directly from the diff output: the regex would only capture the first path segment
            # and break for nested packages (e.g. packages/technology/foo → packages/technology,
            # which has no manifest.yml). mage listPackages discovers valid package roots at any
            # depth via WalkDir, so we cross-reference its output against the changed files.
            all_pkgs=$(list_all_directories)
            # Avoid using "grep -q" in these pipes. With "set -o pipefail", grep -q exits on the
            # first match while "echo" may still be writing (changed_files can exceed the pipe
            # buffer on large PRs), so "echo" fails with SIGPIPE (141) and the match is lost.
            # Example: https://buildkite.com/elastic/integrations/builds/50152
            while IFS= read -r pkg_path; do
                if echo "${changed_files}" | grep "^${pkg_path}/" > /dev/null; then
                    echo "${pkg_path}"
                elif echo "${changed_files}" | grep "^\.buildkite/scripts/${pkg_path}\.sh$" > /dev/null; then
                    echo "${pkg_path}"
                fi
            done <<< "${all_pkgs}"
        } | sort -u | grep -v '^$' || true
    )
    echo "Packages affected by diff: $(echo "${PACKAGE_LIST}" | tr '\n' ' ')"
fi

packages_to_test=0

for package_path in ${PACKAGE_LIST}; do
    # check if needed to create an step for this package
    echo "--- [$package_path] check if it is required to be tested"
    if ! should_test_package "${package_path}" "${from}" "${to}"; then
        continue
    fi

    # package names (manifest.yml) are unique, so it can be used as key for the step
    pushd "${package_path}" > /dev/null
    package_name=$(package_name_manifest)
    popd > /dev/null

    if [ ${steps_in_batch} -ge "${MAX_STEPS_PER_UPLOAD}" ]; then
        upload_batch "${batch_number}" "${steps_in_batch}"
        batch_number=$((batch_number+1))
        steps_in_batch=0
        start_batch "${batch_number}"
    fi

    packages_to_test=$((packages_to_test+1))
    steps_in_batch=$((steps_in_batch+1))
    cat << EOF >> ${PIPELINE_FILE}
    - label: "Check integrations ${package_name}"
      key: "test-integrations-${package_name}"
      command: ".buildkite/scripts/test_one_package.sh ${package_path} ${from} ${to}"
      timeout_in_minutes: 300
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
            duration: 18000 # seconds
        # See https://github.com/elastic/oblt-infra/blob/main/conf/resources/repos/integrations/01-gcp-buildkite-oidc.tf
        # This plugin authenticates to Google Cloud using the OIDC token.
        - elastic/oblt-google-auth#v1.3.0:
            lifetime: 18000 # seconds
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

upload_batch "${batch_number}" "${steps_in_batch}"
