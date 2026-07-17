#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_mage

echo "--- Check changelog versions are not already in main"
mage -d "${WORKSPACE}" -v checkChangelogVersionsInMain "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
