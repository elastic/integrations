#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail


# used in common.sh
SKIPPED_PACKAGES_FILE_PATH="${WORKSPACE}/skipped_packages.txt"
FAILED_PACKAGES_FILE_PATH="${WORKSPACE}/failed_packages.txt"

# package name
package="$1"
# changesets
from=${2:-""}
to=${3:-""}


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
#
# This variable does not exist in builds triggered automatically
GITHUB_PR_TRIGGER_COMMENT="${GITHUB_PR_TRIGGER_COMMENT:-""}"

# Test purposes - to be removed
GITHUB_PR_TRIGGER_COMMENT="/test stack 9.0.0-SNAPSHOT"

if [[ "${GITHUB_PR_TRIGGER_COMMENT}" =~ ^/test\ stack ]]; then
    STACK_VERSION=$(echo "$GITHUB_PR_TRIGGER_COMMENT" | cut -d " " -f 3)
    export STACK_VERSION
    echo "Use Elastic stack version: ${STACK_VERSION}"
fi

pushd packages > /dev/null
if ! process_package "${package}" "${from}" "${to}"; then
    echo "[${package}] failed"
    exit 1
fi
popd > /dev/null
