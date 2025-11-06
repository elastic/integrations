#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

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
    # keep this message as a collapsed group in Buildkite, so it
    # is not hidden by the previous collapsed group.
    echo "--- [${package}] failed"
    exit_code=1
fi
popd > /dev/null

exit "${exit_code}"
