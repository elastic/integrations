#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# default values
SERVERLESS=false

# used in common.sh
FORCE_CHECK_ALL=${FORCE_CHECK_ALL:-"false"}

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

process_package ${package}