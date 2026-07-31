#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_mage
with_yq

echo "--- Validate .backports.yml inventory schema"
mage -d "${WORKSPACE}" -v validateBackportsInventory

echo "--- Check if any files modified"
check_git_diff
