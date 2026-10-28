#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_backport

echo "--- Check changelog versions are not already in main"
backport check-changelog-versions "${BUILDKITE_PULL_REQUEST_BASE_BRANCH}"
