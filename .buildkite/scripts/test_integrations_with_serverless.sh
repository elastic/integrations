#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
SERVERLESS=${SERVERLESS:-"false"}
STACK_VERSION=${STACK_VERSION:-""}
UPLOAD_SAFE_LOGS=${UPLOAD_SAFE_LOGS:-"0"}
# used in common.sh
FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}

SKIPPED_PACKAGES_FILE_PATH="${WORKSPACE}/skipped_packages.txt"
FAILED_PACKAGES_FILE_PATH="${WORKSPACE}/failed_packages.txt"

if running_on_buildkite; then
    # just get the value from meta-data if it is running on Buildkite
    if buildkite-agent meta-data exists SERVERLESS_PROJECT; then
        SERVERLESS_PROJECT="$(buildkite-agent meta-data get SERVERLESS_PROJECT)"
    fi
fi

SERVERLESS_PROJECT=${SERVERLESS_PROJECT:-"observability"}
echo "Running packages on Serverles project type: ${SERVERLESS_PROJECT}"
if running_on_buildkite; then
    buildkite-agent annotate "Serverless Project: ${SERVERLESS_PROJECT}" --context "ctx-info-${SERVERLESS_PROJECT}" --style "info"
fi

# Download config files from kibana
kibana_url="https://raw.githubusercontent.com/elastic/kibana/main/config/serverless.oblt.yml"
if [[ "$SERVERLESS_PROJECT" == "security" ]]; then
    kibana_url="https://raw.githubusercontent.com/elastic/kibana/main/config/serverless.security.yml"
fi
export KIBANA_CONFIG_FILE_PATH="${WORKSPACE}/kibana.serverless.config.yml"
curl -sSL -o "${KIBANA_CONFIG_FILE_PATH}" "${kibana_url}"

if [ ! -d packages ]; then
    echo "Missing packages folder"
    if running_on_buildkite ; then
        buildkite-agent annotate "Missing packages folder" --style "error"
    fi
    exit 1
fi

add_bin_path

with_yq
with_mage
with_docker
with_docker_compose_plugin
with_kubernetes

use_elastic_package

prepare_serverless_stack

echo "Waiting time to avoid getaddrinfo ENOTFOUND errors..."
sleep 120
echo "Done."

# setting range of changesets to check differences
from="$(get_from_changeset)"
to="$(get_to_changeset)"

any_package_failing=0

pushd packages > /dev/null
for package in $(list_all_directories); do
    if ! process_package "${package}" "${from}" "${to}"; then
        any_package_failing=1
    fi
done
popd > /dev/null

if running_on_buildkite ; then
    if [ -f "${SKIPPED_PACKAGES_FILE_PATH}" ]; then
        create_collapsed_annotation "Skipped packages in ${SERVERLESS_PROJECT}" "${SKIPPED_PACKAGES_FILE_PATH}" "info" "ctx-skipped-packages-${SERVERLESS_PROJECT}"
    fi

    if [ -f "${FAILED_PACKAGES_FILE_PATH}" ]; then
        create_collapsed_annotation "Failed packages in ${SERVERLESS_PROJECT}" "${FAILED_PACKAGES_FILE_PATH}" "error" "ctx-failed-packages-${SERVERLESS_PROJECT}"
    fi
fi

if [ $any_package_failing -eq 1 ] ; then
    echo "These packages have failed:"
    cat "${FAILED_PACKAGES_FILE_PATH}"
    exit 1
fi
