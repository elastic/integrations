#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
STACK_VERSION=${STACK_VERSION:-""}
UPLOAD_SAFE_LOGS=${UPLOAD_SAFE_LOGS:-"0"}
SERVERLESS=false

# used in common.sh
FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}

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

prepare_stack

pushd packages > /dev/null
process_package ${package}
popd > /dev/null