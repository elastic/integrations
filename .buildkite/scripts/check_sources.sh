#!/bin/bash

source .buildkite/scripts/common.sh

set -euo pipefail

add_bin_path
with_mage

echo "-- Show value ${FOO}"

mage -debug check

check_git_diff
