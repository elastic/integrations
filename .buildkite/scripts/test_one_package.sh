#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

show_error_logs() {
    local r=$?
    if [ "${r}" -ne 0 ]; then
        # Ensure that the group where the failure happened is opened.
        echo "^^^ +++"
    fi
    exit $r
}

trap show_error_logs EXIT


# package name
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
with_docker
with_docker_compose_plugin
with_kubernetes

use_elastic_package

pushd packages > /dev/null
exit_code=0
if ! process_package "${package}" ; then
    echo "[${package}] failed"
    exit_code=1
fi
popd > /dev/null

exit "${exit_code}"
