#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_backport
with_yq

echo "--- Validate .backports.yml inventory schema"
backport validate-inventory

echo "--- Check if any files modified"
check_git_diff
