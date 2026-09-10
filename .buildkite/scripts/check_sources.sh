#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_mage

echo "--- Run mage check"
mage -v check

echo "--- Check if any files modified"
check_git_diff

echo "--- Run elastic-package links"
run_links_command=false
if less_than=$(mage isElasticPackageDependencyLessThan 0.113.0) ; then
    # links command require at least v0.113.0
    if [[ "$less_than" == "false" ]] ; then
        run_links_command=true
    fi
else
    echo "Failed to check elastic-package version in go.mod"
    exit 1
fi


if [[ "$run_links_command" == "true" ]] ; then
    # links command require at least v0.113.0
    use_elastic_package
    ${ELASTIC_PACKAGE_BIN} links check
else
    echo "Skip elastic-package links. Unsupported for this elastic-package version."
fi
