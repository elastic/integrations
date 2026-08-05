#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

# package path
package_path="$1"
package_name="$(basename "${package_path}")"

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

exit_code=0
if ! process_package "${package_path}" ; then
    # keep this message as a collapsed group in Buildkite, so it
    # is not hidden by the previous collapsed group.
    echo "--- [${package_name}] failed"
    exit_code=1
fi

if [ "${exit_code}" -ne 0 ] ; then
  exit "${exit_code}"
fi

custom_package_checker_script_path="${SCRIPTS_BUILDKITE_PATH}/${package_path}.sh"

if [ -x "$custom_package_checker_script_path" ]; then
  echo "--- [${package_name}] Run individual package checker"
  "$custom_package_checker_script_path"
fi
