#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
STACK_VERSION=${STACK_VERSION:-""}
UPLOAD_SAFE_LOGS=${UPLOAD_SAFE_LOGS:-"0"}
BENCHMARK_THRESHOLD=${BENCHMARK_THRESHOLD:-'15'}


# used in common.sh
FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}
SKIPPED_PACKAGES_FILE_PATH="${WORKSPACE}/skipped_packages.txt"
FAILED_PACKAGES_FILE_PATH="${WORKSPACE}/failed_packages.txt"

package="$1"

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
with_docker_compose
with_kubernetes

use_elastic_package

pushd packages > /dev/null
if ! process_package ${package}; then
    echo "[${package}] failed"
    exit 1
fi
popd > /dev/null
