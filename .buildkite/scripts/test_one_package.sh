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
with_docker_compose
with_kubernetes

use_elastic_package

pushd packages > /dev/null
if ! process_package "${package}" "${from}" "${to}"; then
    echo "[${package}] failed"
    exit 1
fi
popd > /dev/null
